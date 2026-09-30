from __future__ import annotations

import base64
import csv
import hashlib
import importlib.util
import io
import json
import marshal
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "packaging" / "python-runtime" / "runtime_install.py"
SOURCE_TOOL = ROOT / "packaging" / "python-runtime" / "runtime_source.py"
PRIVATE_ROOT = "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages"
EPOCH = 1_700_000_000


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def record_hash(payload: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
    return "sha256=" + encoded.decode("ascii")


def wheel_component(
    wheel: Path,
    *,
    distribution: str,
    version: str = "1.0",
    filename_tags: str = "py3-none-any",
    wheel_tags: tuple[str, ...] | None = None,
    root_is_purelib: bool = True,
    architecture: str = "noarch",
) -> dict[str, Any]:
    python_tag, abi_tag, platform_tag = filename_tags.split("-")
    escaped = distribution.replace("-", "_")
    return {
        "abi_tags": abi_tag.split("."),
        "architecture": architecture,
        "dependencies": [],
        "filename": wheel.name,
        "license_expression": "MIT",
        "license_members": [f"{escaped}-{version}.dist-info/licenses/LICENSE"],
        "name": distribution,
        "normalized_name": distribution.replace("_", "-").lower(),
        "platform_tags": platform_tag.split("."),
        "python_tags": python_tag.split("."),
        "root_is_purelib": root_is_purelib,
        "version": version,
        "wheel_tags": list(wheel_tags or (filename_tags,)),
    }


def make_wheel(
    directory: Path,
    *,
    distribution: str = "example",
    version: str = "1.0",
    filename_tags: str = "py3-none-any",
    wheel_tags: tuple[str, ...] | None = None,
    root_is_purelib: bool = True,
    files: dict[str, bytes] | None = None,
    malformed_record: bytes | None = None,
) -> Path:
    escaped = distribution.replace("-", "_")
    wheel = directory / f"{escaped}-{version}-{filename_tags}.whl"
    dist_info = f"{escaped}-{version}.dist-info"
    payloads = {
        f"{escaped}/__init__.py": b"VALUE = 1\n",
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.4\n"
            f"Name: {distribution}\n"
            f"Version: {version}\n"
            "License-Expression: MIT\n"
            "License-File: LICENSE\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: runtime-install-test\n"
            f"Root-Is-Purelib: {str(root_is_purelib).lower()}\n"
            + "".join(f"Tag: {tag}\n" for tag in wheel_tags or (filename_tags,))
            + "\n"
        ).encode(),
        f"{dist_info}/licenses/LICENSE": b"Example license\n",
    }
    payloads.update(files or {})
    record_name = f"{dist_info}/RECORD"
    if malformed_record is None:
        rows = [
            (name, record_hash(payload), str(len(payload)))
            for name, payload in sorted(payloads.items())
        ]
        rows.append((record_name, "", ""))
        stream = io.StringIO(newline="")
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerows(rows)
        record = stream.getvalue().encode("utf-8")
    else:
        record = malformed_record
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, payload in payloads.items():
            archive.writestr(name, payload)
        archive.writestr(record_name, record)
    return wheel


def append_raw_member(wheel: Path, member: str | zipfile.ZipInfo) -> None:
    replacement: tuple[bytes, bytes] | None = None
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(wheel, "a") as archive:
            if isinstance(member, str) and "\0" in member:
                placeholder = member.replace("\0", "X")
                archive.writestr(placeholder, b"untrusted\n")
                replacement = (placeholder.encode(), member.encode())
            else:
                archive.writestr(member, b"untrusted\n")
    if replacement:
        wheel.write_bytes(wheel.read_bytes().replace(*replacement))


def load_installer():
    specification = importlib.util.spec_from_file_location("runtime_install", INSTALLER)
    assert specification is not None and specification.loader is not None
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def seal_source(
    temporary: Path, wheel_options: tuple[dict[str, Any], ...]
) -> tuple[Path, Path]:
    wheelhouse = temporary / "wheelhouse"
    wheelhouse.mkdir()
    components = []
    lock_lines = []
    for options in wheel_options:
        wheel = make_wheel(wheelhouse, **options)
        component = wheel_component(
            wheel,
            distribution=options.get("distribution", "example"),
            version=options.get("version", "1.0"),
            filename_tags=options.get("filename_tags", "py3-none-any"),
            wheel_tags=options.get("wheel_tags"),
            root_is_purelib=options.get("root_is_purelib", True),
            architecture=options.get("architecture", "noarch"),
        )
        components.append(component)
        lock_lines.append(
            f"{component['normalized_name']}=={component['version']} "
            f"--hash=sha256:{sha256_bytes(wheel.read_bytes())}\n"
        )
    authorized_lock = temporary / "requirements-runtime.lock"
    authorized_lock.write_text("".join(lock_lines), encoding="utf-8")
    authority_file = temporary / "runtime-components.json"
    authority_file.write_text(
        json.dumps(
            {
                "components": sorted(components, key=lambda item: item["filename"]),
                "runtime": {
                    "aggregate_license": (
                        "BSD-3-Clause AND MIT AND MIT-0 AND MPL-2.0 AND PSF-2.0"
                    ),
                    "architecture": "x86_64",
                    "authorized_lock_sha256": sha256_bytes(
                        authorized_lock.read_bytes()
                    ),
                    "expected_wheel_count": len(components),
                    "name": "lto-archiver-python-runtime",
                    "python_version": "3.11",
                    "version": "0.11.27",
                },
                "schema_version": 1,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    source = temporary / "source"
    sealed = subprocess.run(
        [
            sys.executable,
            str(SOURCE_TOOL),
            "seal",
            "--authority",
            str(authority_file),
            "--authorized-lock",
            str(authorized_lock),
            "--wheelhouse",
            str(wheelhouse),
            "--output",
            str(source),
            "--source-date-epoch",
            str(EPOCH),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if sealed.returncode:
        raise AssertionError(sealed.stderr)
    authority = temporary / "authority"
    authority.mkdir()
    shutil.copyfile(authority_file, authority / "runtime-components.json")
    shutil.copyfile(SOURCE_TOOL, authority / "runtime_source.py")
    (authority / "authorized-lock.sha256").write_text(
        f"{sha256_bytes(authorized_lock.read_bytes())}  requirements-runtime.lock\n",
        encoding="ascii",
    )
    for relative in (
        "THIRD_PARTY_NOTICES.md",
        "requirements-runtime.lock",
        "runtime.spdx.json",
        "wheel-inventory.json",
        "wheel-inventory.schema.json",
    ):
        shutil.copyfile(source / relative, authority / relative)
    shutil.copytree(source / "licenses", authority / "licenses")
    return source, authority


def run_install(
    source: Path,
    authority: Path,
    output: Path,
    *,
    payload_authority: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    arguments = [
        sys.executable,
        str(INSTALLER),
        "install",
        "--source",
        str(source),
        "--authority-root",
        str(authority),
        "--output",
        str(output),
        "--installed-root",
        PRIVATE_ROOT,
        "--source-date-epoch",
        str(EPOCH),
        "--expected-python",
        f"{sys.version_info.major}.{sys.version_info.minor}",
    ]
    if payload_authority is not None:
        arguments.extend(("--payload-authority", str(payload_authority)))
    return subprocess.run(
        arguments,
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


class RuntimeWheelValidationTests(unittest.TestCase):
    def test_rejects_unsafe_archive_member_types_and_names(self) -> None:
        cases: list[tuple[str, str | zipfile.ZipInfo]] = [
            ("parent traversal", "../outside.py"),
            ("absolute", "/outside.py"),
            ("Windows absolute", "C:/outside.py"),
            ("backslash", "package\\outside.py"),
            ("noncanonical separator", "package//outside.py"),
            ("NUL", "package/nul\0.py"),
            ("control", "package/control\x01.py"),
            ("casefold", "EXAMPLE/__init__.py"),
            ("duplicate", "example/__init__.py"),
        ]
        symlink = zipfile.ZipInfo("example/link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        cases.append(("symlink", symlink))
        fifo = zipfile.ZipInfo("example/fifo")
        fifo.create_system = 3
        fifo.external_attr = (stat.S_IFIFO | 0o644) << 16
        cases.append(("special", fifo))
        installer = load_installer()
        for label, member in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                wheel = make_wheel(root)
                append_raw_member(wheel, member)
                component = wheel_component(wheel, distribution="example")
                with self.assertRaisesRegex(
                    installer.RuntimeInstallError, "unsafe|collision|duplicate"
                ):
                    installer.validate_wheel(wheel, component)

    def test_rejects_malformed_or_mismatched_record(self) -> None:
        installer = load_installer()
        records = (
            b"not,enough\n",
            b"example/__init__.py,sha256=AAAA,1\n",
            b"example/__init__.py,,\nexample-1.0.dist-info/RECORD,bad,1\n",
        )
        for record in records:
            with self.subTest(record=record), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                wheel = make_wheel(root, malformed_record=record)
                component = wheel_component(wheel, distribution="example")
                with self.assertRaisesRegex(installer.RuntimeInstallError, "RECORD"):
                    installer.validate_wheel(wheel, component)

    def test_rejects_unexpected_data_scheme_and_tag_mismatch(self) -> None:
        installer = load_installer()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wheel = make_wheel(
                root,
                files={"example-1.0.data/scripts/example": b"#!/bin/sh\n"},
            )
            component = wheel_component(wheel, distribution="example")
            with self.assertRaisesRegex(installer.RuntimeInstallError, "data layout"):
                installer.validate_wheel(wheel, component)

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            wheel = make_wheel(root)
            component = wheel_component(wheel, distribution="example")
            component["wheel_tags"] = ["cp311-none-any"]
            with self.assertRaisesRegex(installer.RuntimeInstallError, "tag"):
                installer.validate_wheel(wheel, component)


class RuntimeInstallIntegrationTests(unittest.TestCase):
    def test_installs_atomically_with_checked_hash_normalized_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, authority = seal_source(root, ({"distribution": "example"},))
            output = root / "site-packages"
            result = run_install(source, authority, output)
            self.assertEqual(0, result.returncode, result.stderr)
            source_file = output / "example" / "__init__.py"
            pyc_files = list((output / "example" / "__pycache__").glob("*.pyc"))
            self.assertTrue(source_file.is_file())
            self.assertEqual(1, len(pyc_files))
            pyc = pyc_files[0].read_bytes()
            self.assertEqual(3, struct.unpack("<I", pyc[4:8])[0])
            code = marshal.loads(pyc[16:])
            self.assertEqual(f"{PRIVATE_ROOT}/example/__init__.py", code.co_filename)
            self.assertEqual(0o644, stat.S_IMODE(source_file.stat().st_mode))
            self.assertEqual(EPOCH, int(source_file.stat().st_mtime))
            self.assertTrue(
                (output / "example-1.0.dist-info" / "licenses" / "LICENSE").is_file()
            )
            self.assertEqual([], list(authority.rglob("__pycache__")))

    def test_installs_authenticated_source0_without_mutating_the_sealed_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, authority = seal_source(root, ({"distribution": "example"},))
            archive = root / "lto-archiver-python-runtime-0.11.27.tar.gz"
            built = subprocess.run(
                [
                    sys.executable,
                    str(SOURCE_TOOL),
                    "build-source0",
                    "--source",
                    str(source),
                    "--output",
                    str(archive),
                    "--source-date-epoch",
                    str(EPOCH),
                    "--authority-root",
                    str(authority),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, built.returncode, built.stderr)
            digest = root / "source0.sha256"
            digest.write_text(
                f"{sha256_bytes(archive.read_bytes())}  {archive.name}\n",
                encoding="ascii",
            )
            output = root / "site-packages"
            result = subprocess.run(
                [
                    sys.executable,
                    str(INSTALLER),
                    "install-source0",
                    "--archive",
                    str(archive),
                    "--expected-sha256",
                    str(digest),
                    "--output",
                    str(output),
                    "--installed-root",
                    PRIVATE_ROOT,
                    "--source-date-epoch",
                    str(EPOCH),
                    "--expected-python",
                    f"{sys.version_info.major}.{sys.version_info.minor}",
                    "--expected-wheel-count",
                    "1",
                ],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertTrue((output / "example" / "__init__.py").is_file())

    def test_rejects_lock_inventory_and_embedded_tool_mismatch_without_output(
        self,
    ) -> None:
        mutations = {
            "lock": lambda source: (source / "requirements-runtime.lock").write_text(
                "example==1.0 --hash=sha256:" + "0" * 64 + "\n"
            ),
            "inventory": lambda source: (source / "wheel-inventory.json").write_text(
                "{}\n"
            ),
            "tool": lambda source: (source / "tools" / "runtime_source.py").write_text(
                "# substituted\n"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                source, authority = seal_source(root, ({"distribution": "example"},))
                mutate(source)
                output = root / "site-packages"
                result = run_install(source, authority, output)
                self.assertNotEqual(0, result.returncode)
                self.assertFalse(output.exists())

    def test_rejects_cross_wheel_file_collision_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, authority = seal_source(
                root,
                (
                    {"distribution": "alpha", "files": {"shared.py": b"A = 1\n"}},
                    {"distribution": "beta", "files": {"shared.py": b"B = 2\n"}},
                ),
            )
            output = root / "site-packages"
            result = run_install(source, authority, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("collision", result.stderr)
            self.assertFalse(output.exists())

    def test_rejects_cross_wheel_casefolded_directory_collision(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, authority = seal_source(
                root,
                (
                    {
                        "distribution": "alpha",
                        "files": {"Shared/alpha.py": b"A = 1\n"},
                    },
                    {
                        "distribution": "beta",
                        "files": {"shared/beta.py": b"B = 2\n"},
                    },
                ),
            )
            output = root / "site-packages"
            result = run_install(source, authority, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("casefold", result.stderr)
            self.assertFalse(output.exists())

    def test_compile_failure_rolls_back_partial_staging(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, authority = seal_source(
                root,
                (
                    {
                        "distribution": "example",
                        "files": {"example/broken.py": b"def broken(:\n"},
                    },
                ),
            )
            output = root / "site-packages"
            result = run_install(source, authority, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("bytecode", result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual([], list(root.glob(".site-packages.staging.*")))

    def test_payload_filelist_authority_mismatch_rolls_back_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source, authority = seal_source(root, ({"distribution": "example"},))
            payload_authority = root / "runtime-payload-authority.json"
            payload_authority.write_text(
                json.dumps(
                    {
                        "file_count": 1,
                        "filelist_sha256": "0" * 64,
                        "installed_root": PRIVATE_ROOT,
                        "native_extension_paths": [],
                        "pyc_count": 0,
                        "python_cache_tag": (
                            f"cpython-{sys.version_info.major}{sys.version_info.minor}"
                        ),
                        "schema_version": 1,
                        "wheel_count": 1,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n"
            )
            output = root / "site-packages"
            result = run_install(
                source,
                authority,
                output,
                payload_authority=payload_authority,
            )
            self.assertNotEqual(0, result.returncode)
            self.assertIn("payload filelist", result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual([], list(root.glob(".site-packages.staging.*")))


if __name__ == "__main__":
    unittest.main()
