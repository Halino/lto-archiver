from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from typing import ClassVar

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "packaging" / "python-runtime" / "runtime_source.py"
REAL_AUTHORITY = ROOT / "packaging" / "python-runtime"
SOURCE0_DIGEST = (
    ROOT
    / "packaging"
    / "python-runtime"
    / "lto-archiver-python-runtime-0.11.27.tar.gz.sha256"
)
EPOCH = 1_700_000_000
REAL_EPOCH = 1_787_523_964


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_wheel(
    directory: Path,
    *,
    distribution: str = "example",
    version: str = "1.0",
    filename_tags: str = "py3-none-any",
    wheel_tags: tuple[str, ...] | None = None,
    root_is_purelib: bool = True,
    license_member: str | None = None,
    license_text: bytes = b"Example license\n",
) -> Path:
    escaped = distribution.replace("-", "_")
    filename = f"{escaped}-{version}-{filename_tags}.whl"
    wheel = directory / filename
    dist_info = f"{escaped}-{version}.dist-info"
    if license_member is None:
        license_member = f"{dist_info}/licenses/LICENSE"
    tags = wheel_tags or (filename_tags,)
    metadata = (
        "Metadata-Version: 2.4\n"
        f"Name: {distribution}\n"
        f"Version: {version}\n"
        "License-Expression: MIT\n"
        "License-File: LICENSE\n"
        "\n"
    ).encode()
    wheel_metadata = (
        "Wheel-Version: 1.0\n"
        "Generator: test fixture\n"
        f"Root-Is-Purelib: {str(root_is_purelib).lower()}\n"
        + "".join(f"Tag: {tag}\n" for tag in tags)
        + "\n"
    ).encode()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(f"{dist_info}/METADATA", metadata)
        archive.writestr(f"{dist_info}/WHEEL", wheel_metadata)
        archive.writestr(license_member, license_text)
    return wheel


def make_authority(
    path: Path,
    wheel: Path,
    *,
    name: str = "example",
    version: str = "1.0",
    filename_tags: str = "py3-none-any",
    wheel_tags: tuple[str, ...] | None = None,
    root_is_purelib: bool = True,
    architecture: str = "noarch",
    license_member: str | None = None,
    authorized_lock_sha256: str = "0" * 64,
) -> None:
    escaped = name.replace("-", "_")
    if license_member is None:
        license_member = f"{escaped}-{version}.dist-info/licenses/LICENSE"
    python_tag, abi_tag, platform_tag = filename_tags.split("-")
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "runtime": {
                    "name": "lto-archiver-python-runtime",
                    "version": "0.11.27",
                    "python_version": "3.11",
                    "architecture": "x86_64",
                    "aggregate_license": (
                        "BSD-3-Clause AND MIT AND MIT-0 AND MPL-2.0 AND PSF-2.0"
                    ),
                    "expected_wheel_count": 1,
                    "authorized_lock_sha256": authorized_lock_sha256,
                },
                "components": [
                    {
                        "filename": wheel.name,
                        "name": name,
                        "normalized_name": name.replace("_", "-").lower(),
                        "version": version,
                        "python_tags": python_tag.split("."),
                        "abi_tags": abi_tag.split("."),
                        "platform_tags": platform_tag.split("."),
                        "wheel_tags": list(wheel_tags or (filename_tags,)),
                        "root_is_purelib": root_is_purelib,
                        "architecture": architecture,
                        "license_expression": "MIT",
                        "license_members": [license_member],
                        "dependencies": [],
                    }
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def run_tool(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def materialize_trusted_authority(
    source: Path,
    component_authority: Path,
    authorized_lock: Path,
    output: Path,
) -> None:
    output.mkdir()
    shutil.copyfile(component_authority, output / "runtime-components.json")
    shutil.copyfile(TOOL, output / "runtime_source.py")
    (output / "authorized-lock.sha256").write_text(
        f"{sha256(authorized_lock)}  requirements-runtime.lock\n", encoding="ascii"
    )
    for relative in (
        "THIRD_PARTY_NOTICES.md",
        "runtime.spdx.json",
        "wheel-inventory.json",
        "wheel-inventory.schema.json",
    ):
        shutil.copyfile(source / relative, output / relative)
    shutil.copyfile(authorized_lock, output / "requirements-runtime.lock")
    shutil.copytree(source / "licenses", output / "licenses")


class PythonRuntimeSourceTests(unittest.TestCase):
    def assert_seal_rejects_zip_members(
        self, members: tuple[str | zipfile.ZipInfo, ...]
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary = Path(raw_directory)
            wheelhouse = temporary / "wheelhouse"
            wheelhouse.mkdir()
            wheel = make_wheel(wheelhouse)
            raw_name_replacements: list[tuple[bytes, bytes]] = []
            with zipfile.ZipFile(wheel, "a") as archive:
                for member in members:
                    if isinstance(member, str) and "\x00" in member:
                        placeholder = member.replace("\x00", "X")
                        archive.writestr(placeholder, b"untrusted\n")
                        raw_name_replacements.append(
                            (placeholder.encode("utf-8"), member.encode("utf-8"))
                        )
                    else:
                        archive.writestr(member, b"untrusted\n")
            if raw_name_replacements:
                payload = wheel.read_bytes()
                for before, after in raw_name_replacements:
                    payload = payload.replace(before, after)
                wheel.write_bytes(payload)
            authorized_lock = temporary / "requirements-runtime.lock"
            authorized_lock.write_text(
                f"example==1.0 --hash=sha256:{sha256(wheel)}\n",
                encoding="utf-8",
            )
            authority = temporary / "runtime-components.json"
            make_authority(
                authority, wheel, authorized_lock_sha256=sha256(authorized_lock)
            )
            result = run_tool(
                "seal",
                "--authority",
                str(authority),
                "--authorized-lock",
                str(authorized_lock),
                "--wheelhouse",
                str(wheelhouse),
                "--output",
                str(temporary / "source"),
                "--source-date-epoch",
                str(EPOCH),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe wheel member", result.stderr)

    def seal_fixture(self, temporary: Path, **wheel_options: object) -> Path:
        wheelhouse = temporary / "wheelhouse"
        wheelhouse.mkdir()
        wheel = make_wheel(wheelhouse, **wheel_options)
        authorized_lock = temporary / "requirements-runtime.lock"
        authorized_lock.write_text(
            f"example==1.0 \\\n    --hash=sha256:{sha256(wheel)}\n",
            encoding="utf-8",
        )
        authority = temporary / "runtime-components.json"
        make_authority(
            authority,
            wheel,
            name=str(wheel_options.get("distribution", "example")),
            version=str(wheel_options.get("version", "1.0")),
            filename_tags=str(wheel_options.get("filename_tags", "py3-none-any")),
            wheel_tags=wheel_options.get("wheel_tags"),  # type: ignore[arg-type]
            root_is_purelib=bool(wheel_options.get("root_is_purelib", True)),
            architecture=str(wheel_options.get("architecture", "noarch")),
            license_member=wheel_options.get("license_member"),  # type: ignore[arg-type]
            authorized_lock_sha256=sha256(authorized_lock),
        )
        source = temporary / "source"
        sealed = run_tool(
            "seal",
            "--authority",
            str(authority),
            "--authorized-lock",
            str(authorized_lock),
            "--wheelhouse",
            str(wheelhouse),
            "--output",
            str(source),
            "--source-date-epoch",
            str(EPOCH),
        )
        self.assertEqual(sealed.returncode, 0, sealed.stderr)
        materialize_trusted_authority(
            source,
            authority,
            authorized_lock,
            temporary / "trusted-authority",
        )
        return source

    def verify_source(self, source: Path) -> subprocess.CompletedProcess[str]:
        return run_tool(
            "verify-source",
            "--source",
            str(source),
            "--authority-root",
            str(source.parent / "trusted-authority"),
        )

    def rewrite_inventory(self, source: Path, inventory: dict[str, object]) -> None:
        (source / "wheel-inventory.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def test_seal_generates_a_closed_deterministic_runtime_source(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary = Path(raw_directory)
            wheelhouse = temporary / "wheelhouse"
            wheelhouse.mkdir()
            wheel = make_wheel(wheelhouse)
            authorized_lock = temporary / "requirements-runtime.lock"
            authorized_lock.write_text(
                f"example==1.0 \\\n    --hash=sha256:{sha256(wheel)}\n",
                encoding="utf-8",
            )
            authority = temporary / "runtime-components.json"
            make_authority(
                authority, wheel, authorized_lock_sha256=sha256(authorized_lock)
            )
            source = temporary / "source"

            sealed = run_tool(
                "seal",
                "--authority",
                str(authority),
                "--authorized-lock",
                str(authorized_lock),
                "--wheelhouse",
                str(wheelhouse),
                "--output",
                str(source),
                "--source-date-epoch",
                str(EPOCH),
            )

            self.assertEqual(sealed.returncode, 0, sealed.stderr)
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            self.assertEqual(inventory["runtime"]["wheel_count"], 1)
            self.assertEqual(inventory["wheels"][0]["sha256"], sha256(wheel))
            self.assertEqual(
                (source / "requirements-runtime.lock").read_text(),
                f"example==1.0 --hash=sha256:{sha256(wheel)}\n",
            )
            self.assertEqual(
                json.loads((source / "runtime.spdx.json").read_text())["packages"][0][
                    "downloadLocation"
                ],
                "NOASSERTION",
            )
            self.assertTrue((source / "licenses" / "example" / "LICENSE").is_file())
            materialize_trusted_authority(
                source,
                authority,
                authorized_lock,
                temporary / "trusted-authority",
            )
            verified = self.verify_source(source)
            self.assertEqual(verified.returncode, 0, verified.stderr)

    def test_verify_rejects_an_extra_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            shutil.copyfile(
                source / "wheels" / "example-1.0-py3-none-any.whl",
                source / "wheels" / "extra-1.0-py3-none-any.whl",
            )
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("extra=['extra-1.0-py3-none-any.whl']", result.stderr)

    def test_verify_rejects_an_extra_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            (source / "unsealed-empty-directory").mkdir()
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("source directory closure mismatch", result.stderr)

    def test_seal_rejects_parent_traversal_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("../outside",))

    def test_seal_rejects_absolute_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("/absolute",))

    def test_seal_rejects_backslash_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("package\\escape.py",))

    def test_seal_rejects_casefolded_wheel_member_collision(self) -> None:
        self.assert_seal_rejects_zip_members(("package/Foo.py", "package/foo.py"))

    def test_seal_rejects_exact_duplicate_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("package/module.py", "package/module.py"))

    def test_seal_rejects_control_character_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("package/control\x01.py",))

    def test_seal_rejects_c1_control_character_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("package/control\x85.py",))

    def test_seal_rejects_nul_wheel_member(self) -> None:
        self.assert_seal_rejects_zip_members(("package/nul\x00.py",))

    def test_seal_rejects_symlink_wheel_member(self) -> None:
        member = zipfile.ZipInfo("package/link")
        member.create_system = 3
        member.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assert_seal_rejects_zip_members((member,))

    def test_verify_source_requires_a_trusted_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            result = run_tool("verify-source", "--source", str(source))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--authority-root", result.stderr)

    def test_verify_rejects_embedded_tool_substitution(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            (source / "tools" / "runtime_source.py").write_text(
                "# coordinated attacker verifier\n", encoding="utf-8"
            )
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("embedded runtime source tool mismatch", result.stderr)

    def test_verify_rejects_coordinated_wheel_source_and_tool_substitution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            wheel = source / "wheels" / "example-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "a") as archive:
                archive.writestr("example/attacker.py", b"controlled payload\n")
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            inventory["wheels"][0]["sha256"] = sha256(wheel)
            self.rewrite_inventory(source, inventory)
            (source / "requirements-runtime.lock").write_text(
                f"example==1.0 --hash=sha256:{sha256(wheel)}\n", encoding="utf-8"
            )
            sbom = json.loads((source / "runtime.spdx.json").read_text())
            sbom["packages"][0]["checksums"][0]["checksumValue"] = sha256(wheel)
            (source / "runtime.spdx.json").write_text(
                json.dumps(sbom, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            (source / "tools" / "runtime_source.py").write_text(
                "# coordinated attacker verifier\n", encoding="utf-8"
            )
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_verify_rejects_a_missing_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            (source / "wheels" / "example-1.0-py3-none-any.whl").unlink()
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing=['example-1.0-py3-none-any.whl']", result.stderr)

    def test_verify_rejects_a_duplicate_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            duplicate = dict(inventory["wheels"][0])
            duplicate["filename"] = "z-example-1.0-py3-none-any.whl"
            inventory["wheels"].append(duplicate)
            inventory["runtime"]["wheel_count"] = 2
            shutil.copyfile(
                source / "wheels" / "example-1.0-py3-none-any.whl",
                source / "wheels" / duplicate["filename"],
            )
            self.rewrite_inventory(source, inventory)
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_verify_rejects_a_substituted_wheel(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            wheel = source / "wheels" / "example-1.0-py3-none-any.whl"
            wheel.write_bytes(wheel.read_bytes() + b"substitution")
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SHA-256 mismatch", result.stderr)

    def test_verify_rejects_wrong_wheel_name(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            inventory["wheels"][0]["name"] = "attacker"
            self.rewrite_inventory(source, inventory)
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_verify_rejects_wrong_wheel_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            inventory["wheels"][0]["version"] = "2.0"
            self.rewrite_inventory(source, inventory)
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_verify_rejects_wrong_wheel_tag(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            inventory["wheels"][0]["wheel_tags"] = ["cp311-none-any"]
            self.rewrite_inventory(source, inventory)
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_verify_rejects_wrong_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            inventory["wheels"][0]["architecture"] = "x86_64"
            self.rewrite_inventory(source, inventory)
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_verify_rejects_a_missing_license(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            (source / "licenses" / "example" / "LICENSE").unlink()
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing license file", result.stderr)

    def test_verify_rejects_unknown_inventory_fields(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            source = self.seal_fixture(Path(raw_directory))
            inventory = json.loads((source / "wheel-inventory.json").read_text())
            inventory["wheels"][0]["unsealed_field"] = "not allowed"
            self.rewrite_inventory(source, inventory)
            result = self.verify_source(source)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "sealed inventory does not match trusted authority", result.stderr
            )

    def test_source0_is_byte_reproducible_and_has_canonical_headers(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary = Path(raw_directory)
            source = self.seal_fixture(temporary)
            first = temporary / "first.tar.gz"
            second = temporary / "second.tar.gz"
            for output in (first, second):
                result = run_tool(
                    "build-source0",
                    "--source",
                    str(source),
                    "--output",
                    str(output),
                    "--source-date-epoch",
                    str(EPOCH),
                    "--authority-root",
                    str(temporary / "trusted-authority"),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with tarfile.open(first, "r:gz") as archive:
                members = archive.getmembers()
            names = [member.name for member in members]
            self.assertEqual(names, sorted(names))
            self.assertEqual(len(names), len(set(names)))
            self.assertTrue(
                all(member.uid == 0 and member.gid == 0 for member in members)
            )
            self.assertTrue(
                all(member.uname == "" and member.gname == "" for member in members)
            )
            self.assertTrue(all(member.mtime == EPOCH for member in members))
            self.assertTrue(
                all(
                    member.mode == (0o755 if member.isdir() else 0o644)
                    for member in members
                )
            )

    def test_verify_rejects_noncanonical_source0(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary = Path(raw_directory)
            source = self.seal_fixture(temporary)
            canonical = temporary / "canonical.tar.gz"
            built = run_tool(
                "build-source0",
                "--source",
                str(source),
                "--output",
                str(canonical),
                "--source-date-epoch",
                str(EPOCH),
                "--authority-root",
                str(temporary / "trusted-authority"),
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            canonical_digest = temporary / "canonical.sha256"
            canonical_digest.write_text(
                f"{sha256(canonical)}  {canonical.name}\n", encoding="ascii"
            )
            verified = run_tool(
                "verify-source0",
                "--source",
                str(source),
                "--archive",
                str(canonical),
                "--source-date-epoch",
                str(EPOCH),
                "--expected-sha256",
                str(canonical_digest),
                "--authority-root",
                str(temporary / "trusted-authority"),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)

            noncanonical = temporary / "noncanonical.tar.gz"
            with tarfile.open(noncanonical, "w:gz") as archive:
                archive.add(source, arcname="lto-archiver-python-runtime-0.11.27")
            noncanonical_digest = temporary / "noncanonical.sha256"
            noncanonical_digest.write_text(
                f"{sha256(noncanonical)}  {noncanonical.name}\n", encoding="ascii"
            )
            rejected = run_tool(
                "verify-source0",
                "--source",
                str(source),
                "--archive",
                str(noncanonical),
                "--source-date-epoch",
                str(EPOCH),
                "--expected-sha256",
                str(noncanonical_digest),
                "--authority-root",
                str(temporary / "trusted-authority"),
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("noncanonical Source0", rejected.stderr)

    def test_verify_source0_requires_expected_digest(self) -> None:
        result = run_tool(
            "verify-source0",
            "--source",
            "/does/not/matter",
            "--archive",
            "/does/not/matter.tar.gz",
            "--source-date-epoch",
            str(EPOCH),
            "--authority-root",
            "/does/not/matter",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--expected-sha256", result.stderr)

    def test_verify_source0_rejects_epoch_outside_trusted_authority(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary = Path(raw_directory)
            source = self.seal_fixture(temporary)
            archive = temporary / "runtime.tar.gz"
            built = run_tool(
                "build-source0",
                "--source",
                str(source),
                "--output",
                str(archive),
                "--source-date-epoch",
                str(EPOCH),
                "--authority-root",
                str(temporary / "trusted-authority"),
            )
            self.assertEqual(built.returncode, 0, built.stderr)
            digest = temporary / "runtime.sha256"
            digest.write_text(f"{sha256(archive)}  {archive.name}\n", encoding="ascii")
            result = run_tool(
                "verify-source0",
                "--source",
                str(source),
                "--archive",
                str(archive),
                "--source-date-epoch",
                str(EPOCH + 1),
                "--expected-sha256",
                str(digest),
                "--authority-root",
                str(temporary / "trusted-authority"),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "SOURCE_DATE_EPOCH does not match trusted authority", result.stderr
            )


class SealedRuntimeIntegrationTests(unittest.TestCase):
    EXPECTED_DISTRIBUTIONS: ClassVar[frozenset[str]] = frozenset(
        {
            "annotated-doc",
            "annotated-types",
            "anyio",
            "argon2-cffi",
            "argon2-cffi-bindings",
            "certifi",
            "cffi",
            "click",
            "fastapi",
            "h11",
            "httpcore",
            "httpx",
            "idna",
            "jinja2",
            "markupsafe",
            "pycparser",
            "pydantic",
            "pydantic-core",
            "starlette",
            "typing-extensions",
            "typing-inspection",
            "uvicorn",
        }
    )

    def test_repository_tracks_no_runtime_wheel_or_source0_binary(self) -> None:
        if os.path.lexists(ROOT / ".git"):
            tracked = subprocess.run(
                ["git", "ls-files", "-z"],
                cwd=ROOT,
                check=True,
                capture_output=True,
            ).stdout.split(b"\0")
        else:
            # In Source0 all shipped files, not a nonexistent Git index, are
            # the inventory. A broken checkout still fails the Git branch.
            self.assertTrue((ROOT / ".gitattributes").is_file())
            self.assertTrue(TOOL.is_file())
            tracked = [
                os.fsencode(path.relative_to(ROOT))
                for path in ROOT.rglob("*") if path.is_file()
            ]
        runtime_binaries = [
            path.decode() for path in tracked if path.endswith((b".whl", b".tar.gz"))
        ]
        self.assertEqual(runtime_binaries, [])

    def test_real_source_is_the_exact_22_distribution_runtime_closure(self) -> None:
        result = run_tool("verify-authority", "--authority-root", str(REAL_AUTHORITY))
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads((REAL_AUTHORITY / "wheel-inventory.json").read_text())
        names = {wheel["normalized_name"] for wheel in inventory["wheels"]}
        self.assertEqual(inventory["runtime"]["wheel_count"], 22)
        self.assertEqual(
            inventory["runtime"]["authorized_lock_sha256"],
            "b61ac9dbdb373fb7f0665d2f6d7fcfeb16f5f4ec141d9d66f3271c9e0d3adaac",
        )
        self.assertEqual(
            inventory["runtime"]["aggregate_license"],
            "BSD-3-Clause AND MIT AND MIT-0 AND MPL-2.0 AND PSF-2.0",
        )
        self.assertEqual(names, self.EXPECTED_DISTRIBUTIONS)
        self.assertTrue(names.isdisjoint({"packaging", "setuptools", "wheel"}))
        native = {
            wheel["normalized_name"]
            for wheel in inventory["wheels"]
            if wheel["architecture"] == "x86_64"
        }
        self.assertEqual(
            native,
            {"argon2-cffi-bindings", "cffi", "markupsafe", "pydantic-core"},
        )
        sbom = json.loads((REAL_AUTHORITY / "runtime.spdx.json").read_text())
        self.assertEqual(len(sbom["packages"]), 22)
        self.assertEqual(
            sum(len(wheel["license_files"]) for wheel in inventory["wheels"]), 22
        )
        self.assertTrue(
            all(
                package["downloadLocation"] == "NOASSERTION"
                for package in sbom["packages"]
            )
        )
        self.assertEqual(
            {package.get("copyrightText") for package in sbom["packages"]},
            {"NOASSERTION"},
        )

    def test_committed_digest_verifies_two_identical_source0_builds(self) -> None:
        authorized_lock = os.environ.get("LTO_RUNTIME_AUTHORIZED_LOCK")
        wheelhouse = os.environ.get("LTO_RUNTIME_WHEELHOUSE")
        if not authorized_lock or not wheelhouse:
            self.skipTest("set external authorized runtime inputs for Source0 gate")
        with tempfile.TemporaryDirectory() as raw_directory:
            temporary = Path(raw_directory)
            first_source = temporary / "first-source"
            second_source = temporary / "second-source"
            for source in (first_source, second_source):
                sealed = run_tool(
                    "seal",
                    "--authority",
                    str(REAL_AUTHORITY / "runtime-components.json"),
                    "--authorized-lock",
                    authorized_lock,
                    "--wheelhouse",
                    wheelhouse,
                    "--output",
                    str(source),
                    "--source-date-epoch",
                    str(REAL_EPOCH),
                )
                self.assertEqual(sealed.returncode, 0, sealed.stderr)
            for relative in (
                "THIRD_PARTY_NOTICES.md",
                "requirements-runtime.lock",
                "runtime.spdx.json",
                "wheel-inventory.json",
                "wheel-inventory.schema.json",
            ):
                self.assertEqual(
                    (first_source / relative).read_bytes(),
                    (REAL_AUTHORITY / relative).read_bytes(),
                )
                self.assertEqual(
                    (first_source / relative).read_bytes(),
                    (second_source / relative).read_bytes(),
                )
            self.assertEqual(
                (first_source / "tools" / "runtime_source.py").read_bytes(),
                TOOL.read_bytes(),
            )
            first = temporary / "lto-archiver-python-runtime-0.11.27.tar.gz"
            second = temporary / "second" / first.name
            for source, output in ((first_source, first), (second_source, second)):
                result = run_tool(
                    "build-source0",
                    "--source",
                    str(source),
                    "--output",
                    str(output),
                    "--source-date-epoch",
                    str(REAL_EPOCH),
                    "--authority-root",
                    str(REAL_AUTHORITY),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertTrue(
                SOURCE0_DIGEST.is_file(), "committed Source0 digest missing"
            )
            expected = SOURCE0_DIGEST.read_text(encoding="ascii")
            self.assertEqual(expected, f"{sha256(first)}  {first.name}\n")
            verified = run_tool(
                "verify-source0",
                "--source",
                str(first_source),
                "--archive",
                str(first),
                "--source-date-epoch",
                str(REAL_EPOCH),
                "--expected-sha256",
                str(SOURCE0_DIGEST),
                "--authority-root",
                str(REAL_AUTHORITY),
            )
            self.assertEqual(verified.returncode, 0, verified.stderr)



class PublicRuntimeLockTests(unittest.TestCase):
    def test_committed_public_lock_is_the_complete_runtime_authority(self) -> None:
        public_lock = REAL_AUTHORITY / "requirements-runtime.lock"
        inventory = json.loads((REAL_AUTHORITY / "wheel-inventory.json").read_text())
        components = json.loads((REAL_AUTHORITY / "runtime-components.json").read_text())
        expected_rows = [
            f"{wheel['normalized_name']}=={wheel['version']} "
            f"--hash=sha256:{wheel['sha256']}"
            for wheel in sorted(inventory["wheels"], key=lambda item: item["filename"])
        ]
        self.assertEqual(public_lock.read_text(encoding="utf-8").splitlines(), expected_rows)
        self.assertEqual(
            {wheel["filename"] for wheel in inventory["wheels"]},
            {component["filename"] for component in components["components"]},
        )
        digest = sha256(public_lock)
        self.assertEqual(inventory["runtime"]["authorized_lock_sha256"], digest)
        self.assertEqual(components["runtime"]["authorized_lock_sha256"], digest)
        self.assertEqual(
            (REAL_AUTHORITY / "authorized-lock.sha256").read_text(encoding="ascii"),
            f"{digest}  requirements-runtime.lock\n",
        )
        sbom = json.loads((REAL_AUTHORITY / "runtime.spdx.json").read_text())
        self.assertTrue(sbom["documentNamespace"].endswith(f"/{digest}"))

    def test_authority_rejects_public_lock_byte_change(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            authority = Path(raw) / "authority"
            shutil.copytree(REAL_AUTHORITY, authority)
            public_lock = authority / "requirements-runtime.lock"
            public_lock.write_bytes(public_lock.read_bytes() + b"\n")
            result = run_tool(
                "verify-authority", "--authority-root", str(authority)
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("authorized lock", result.stderr)

    def test_seal_rejects_renamed_changed_or_extra_public_wheel(self) -> None:
        for mutation in ("renamed", "changed", "extra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as raw:
                temporary = Path(raw)
                wheelhouse = temporary / "wheelhouse"
                wheelhouse.mkdir()
                wheel = make_wheel(wheelhouse)
                public_lock = temporary / "requirements-runtime.lock"
                public_lock.write_text(
                    f"example==1.0 --hash=sha256:{sha256(wheel)}\n",
                    encoding="utf-8",
                )
                authority = temporary / "runtime-components.json"
                make_authority(
                    authority, wheel, authorized_lock_sha256=sha256(public_lock)
                )
                if mutation == "renamed":
                    wheel.rename(wheelhouse / "renamed-1.0-py3-none-any.whl")
                elif mutation == "changed":
                    wheel.write_bytes(wheel.read_bytes() + b"changed")
                else:
                    shutil.copyfile(
                        wheel, wheelhouse / "extra-1.0-py3-none-any.whl"
                    )
                output = temporary / "sealed"
                result = run_tool(
                    "seal", "--authority", str(authority),
                    "--authorized-lock", str(public_lock),
                    "--wheelhouse", str(wheelhouse),
                    "--output", str(output),
                    "--source-date-epoch", str(EPOCH),
                )
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse(output.exists())

if __name__ == "__main__":
    unittest.main()
