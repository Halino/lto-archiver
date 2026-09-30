from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "packaging" / "rpm" / "lto-archiver-python-runtime.spec"
BUILDER = ROOT / "packaging" / "rpm" / "build-python-runtime-rpm.sh"
INVENTORY = ROOT / "packaging" / "python-runtime" / "wheel-inventory.json"
PAYLOAD_AUTHORITY = (
    ROOT / "packaging" / "python-runtime" / "runtime-payload-authority.json"
)
SOURCE0_DIGEST = (
    ROOT
    / "packaging"
    / "python-runtime"
    / "lto-archiver-python-runtime-0.11.27.tar.gz.sha256"
)
PRIVATE_ROOT = "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages"


def make_builder_fixture(directory: Path) -> tuple[Path, Path, Path, Path]:
    repository = directory / "repository"
    (repository / "packaging" / "rpm").mkdir(parents=True)
    (repository / "packaging" / "python-runtime").mkdir(parents=True)
    for source, destination in (
        (SPEC, repository / "packaging/rpm" / SPEC.name),
        (
            ROOT / "packaging/python-runtime/runtime_install.py",
            repository / "packaging/python-runtime/runtime_install.py",
        ),
        (
            ROOT / "packaging/python-runtime/runtime-payload-authority.json",
            repository / "packaging/python-runtime/runtime-payload-authority.json",
        ),
        (
            ROOT / "packaging/python-runtime/wheel-inventory.json",
            repository / "packaging/python-runtime/wheel-inventory.json",
        ),
        (
            ROOT
            / "packaging/python-runtime"
            / "lto-archiver-python-runtime-0.11.27.tar.gz.sha256",
            repository
            / "packaging/python-runtime"
            / "lto-archiver-python-runtime-0.11.27.tar.gz.sha256",
        ),
    ):
        shutil.copyfile(source, destination)
    signer = repository / "packaging/rpm/sign-rpm-tree.py"
    signer.write_text(
        r"""#!/usr/bin/python3
import os
import shutil
from pathlib import Path
import sys

source = Path(sys.argv[sys.argv.index("--unsigned-tree") + 1])
output = Path(sys.argv[sys.argv.index("--output") + 1])
if os.environ.get("FAKE_SIGN_FAIL") == "1":
    raise SystemExit(2)
shutil.copytree(source, output)
(output / "SHA256SUMS.asc").write_text("fixture detached signature\n")
"""
    )
    signer.chmod(0o755)
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_NAME": "Runtime RPM Test",
            "GIT_AUTHOR_EMAIL": "rpm@example.invalid",
            "GIT_COMMITTER_NAME": "Runtime RPM Test",
            "GIT_COMMITTER_EMAIL": "rpm@example.invalid",
            "GIT_AUTHOR_DATE": "2026-08-23T22:26:04+00:00",
            "GIT_COMMITTER_DATE": "2026-08-23T22:26:04+00:00",
        }
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "fixture"],
        check=True,
        env=environment,
    )
    source0 = directory / "lto-archiver-python-runtime-0.11.27.tar.gz"
    source0.write_bytes(b"authenticated source0 fixture\n")
    digest = hashlib_sha256(source0.read_bytes())
    (
        repository
        / "packaging/python-runtime"
        / "lto-archiver-python-runtime-0.11.27.tar.gz.sha256"
    ).write_text(f"{digest}  {source0.name}\n", encoding="ascii")
    subprocess.run(
        ["git", "-C", str(repository), "add", "packaging/python-runtime"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(repository), "commit", "-q", "-m", "fixture digest"],
        check=True,
        env=environment,
    )

    fake_bin = directory / "bin"
    fake_bin.mkdir()
    record = directory / "rpmbuild-record"
    fake_rpmbuild = fake_bin / "rpmbuild"
    fake_rpmbuild.write_text(
        r"""#!/usr/bin/python3
import os
from pathlib import Path
import sys

definition = sys.argv[sys.argv.index("--define") + 1]
topdir = Path(definition.split(" ", 1)[1])
record = Path(os.environ["FAKE_RPM_RECORD"])
counter = Path(os.environ["FAKE_RPM_COUNTER"])
invocation = int(counter.read_text()) + 1 if counter.exists() else 1
counter.write_text(str(invocation))
with record.open("a") as output:
    sources = sorted(path.name for path in (topdir / "SOURCES").iterdir())
    output.write(
        f"{topdir}\t{os.environ.get('SOURCE_DATE_EPOCH', '')}\t{','.join(sources)}\n"
    )
for relative, kind in (
    ("RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.x86_64.rpm", "binary"),
    ("SRPMS/lto-archiver-python-runtime-0.11.27-3.src.rpm", "source"),
):
    artifact = topdir / relative
    artifact.parent.mkdir(parents=True, exist_ok=True)
    varying = f"root={topdir}\n" if os.environ.get("FAKE_RPM_VARY") == kind else ""
    artifact.write_text(f"{kind}\nepoch={os.environ.get('SOURCE_DATE_EPOCH', '')}\n{varying}")
""",
        encoding="utf-8",
    )
    fake_rpmbuild.chmod(0o755)
    return repository, source0, fake_bin, record


def hashlib_sha256(payload: bytes) -> str:
    import hashlib

    return hashlib.sha256(payload).hexdigest()


def host_compatible_builder(directory: Path) -> Path:
    script_dir = directory / "builder"
    script_dir.mkdir()
    builder = script_dir / BUILDER.name
    source = BUILDER.read_text(encoding="utf-8")
    if source.count("publish_python=/usr/bin/python3.11") != 1:
        raise AssertionError("publisher Python seam changed")
    source = source.replace(
        "publish_python=/usr/bin/python3.11",
        f"publish_python={sys.executable}",
    ).replace(
        "sys.version_info[:2] != (3, 11)",
        f"sys.version_info[:2] != {sys.version_info[:2]!r}",
    ).replace(
        "/usr/bin/rpmbuild",
        shlex.quote(str(directory / "bin" / "rpmbuild")),
    )
    argument_seam = 'if [ "$#" -ne 5 ]; then'
    if source.count(argument_seam) != 1:
        raise AssertionError("runtime builder signing argument seam changed")
    test_gnupg = script_dir / "test-gnupg"
    test_gnupg.mkdir(mode=0o700)
    source = source.replace(
        argument_seam,
        'if [ "$#" -eq 2 ]; then\n'
        f"    set -- \"$1\" \"$2\" {shlex.quote(str(test_gnupg))} "
        "720A3739260F7F170F6775D671BFB166903560F7 "
        "B89E149F0793DA2E3C7C5D3C442162C8A68E868D\n"
        "fi\n"
        + argument_seam,
    )
    builder.write_text(source, encoding="utf-8")
    builder.chmod(0o755)
    shutil.copyfile(
        ROOT / "packaging/rpm/publish-rpm-tree.py",
        script_dir / "publish-rpm-tree.py",
    )
    return builder


class PythonRuntimeSpecTests(unittest.TestCase):
    def test_spec_disables_empty_debugsource_subpackages(self) -> None:
        spec = SPEC.read_text(encoding="utf-8")

        self.assertEqual(
            1,
            len(re.findall(r"(?m)^%global debug_package %\{nil\}$", spec)),
            "the sealed wheel runtime must not emit an empty EL9 debugsource package",
        )

    def test_spec_declares_exact_private_x86_64_runtime_contract(self) -> None:
        spec = SPEC.read_text(encoding="utf-8")
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
        self.assertRegex(spec, r"(?m)^Name:\s+lto-archiver-python-runtime$")
        self.assertRegex(spec, r"(?m)^Version:\s+0\.11\.27$")
        self.assertRegex(spec, r"(?m)^Release:\s+3%\{\?dist\}$")
        self.assertRegex(
            spec,
            r"(?m)^URL:\s+https://lto-archiver\.invalid/private$",
        )
        self.assertRegex(spec, r"(?m)^BuildArch:\s+x86_64$")
        self.assertRegex(spec, r"(?m)^ExclusiveArch:\s+x86_64$")
        self.assertIn(PRIVATE_ROOT, spec)
        self.assertNotIn("/usr/lib/python3.11/site-packages", spec)
        self.assertNotIn("/usr/local/lib", spec)
        self.assertNotIn("pip install", spec)
        self.assertNotIn("AutoReqProv: no", spec)
        self.assertIn("Requires:       python3.11", spec)
        self.assertIn("%global __python_provides %{nil}", spec)
        self.assertIn("%global __python_requires %{nil}", spec)
        self.assertIn("%global __brp_python_bytecompile %{nil}", spec)
        provides = {
            (match.group("name"), match.group("version"))
            for match in re.finditer(
                r"(?m)^Provides:\s+bundled\(python3\.11dist\((?P<name>[^)]+)\)\)"
                r"\s+=\s+(?P<version>\S+)$",
                spec,
            )
        }
        expected = {
            (wheel["normalized_name"], wheel["version"])
            for wheel in inventory["wheels"]
        }
        self.assertEqual(expected, provides)
        self.assertEqual(22, len(provides))
        self.assertIsNone(
            re.search(r"(?m)^Provides:\s+python3\.11dist\(", spec),
            "private runtime must not publish global Python capabilities",
        )

    def test_runtime_builder_has_exact_absolute_tool_and_package_closure(self) -> None:
        builder = BUILDER.read_text(encoding="utf-8")
        spec = SPEC.read_text(encoding="utf-8")
        tools = (
            "cmp",
            "find",
            "git",
            "install",
            "mkdir",
            "mktemp",
            "rm",
            "rpmbuild",
            "sed",
            "sha256sum",
            "sort",
            "wc",
        )
        for tool in tools:
            with self.subTest(tool=tool):
                self.assertIn(f"/usr/bin/{tool}", builder)
                self.assertIn(f"BuildRequires:  /usr/bin/{tool}", spec)
                self.assertNotRegex(
                    builder,
                    rf"(?m)(?<![/A-Za-z0-9_.-]){re.escape(tool)}(?=[ \t])",
                )
        self.assertEqual(1, builder.count("=/usr/bin/python3.11"))

    def test_spec_installs_authenticated_source_with_licenses_and_sbom(self) -> None:
        spec = SPEC.read_text(encoding="utf-8")
        self.assertIn("install-source0", spec)
        self.assertIn("--expected-wheel-count 22", spec)
        self.assertIn("runtime-payload-authority.json", spec)
        self.assertIn("--payload-authority", spec)
        self.assertIn("THIRD_PARTY_NOTICES.md", spec)
        self.assertIn("runtime.spdx.json", spec)
        self.assertIn("wheel-inventory.json", spec)
        self.assertIn("%license", spec)
        self.assertNotIn("http://", spec)
        self.assertNotIn("https://", spec.split("%prep", 1)[-1])

    def test_payload_authority_is_the_exact_311_filelist_contract(self) -> None:
        authority = json.loads(PAYLOAD_AUTHORITY.read_text(encoding="utf-8"))
        self.assertEqual(1, authority["schema_version"])
        self.assertEqual(PRIVATE_ROOT, authority["installed_root"])
        self.assertEqual("cpython-311", authority["python_cache_tag"])
        self.assertEqual(22, authority["wheel_count"])
        self.assertEqual(1031, authority["file_count"])
        self.assertEqual(443, authority["pyc_count"])
        self.assertEqual(4, len(authority["native_extension_paths"]))
        self.assertTrue(
            all(path.endswith(".so") for path in authority["native_extension_paths"])
        )


class PythonRuntimeBuilderTests(unittest.TestCase):
    def run_builder(
        self,
        repository: Path,
        source0: Path,
        fake_bin: Path,
        record: Path,
        output: Path,
        *,
        vary: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{fake_bin}:{environment['PATH']}",
                "FAKE_RPM_RECORD": str(record),
                "FAKE_RPM_COUNTER": str(record.with_name("rpmbuild-counter")),
            }
        )
        if vary:
            environment["FAKE_RPM_VARY"] = vary
        return subprocess.run(
            [str(host_compatible_builder(output.parent)), str(source0), str(output)],
            cwd=repository,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_builder_uses_two_distinct_roots_and_publishes_identical_rpm_and_srpm(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository, source0, fake_bin, record = make_builder_fixture(root)
            output = root / "published"
            result = self.run_builder(repository, source0, fake_bin, record, output)
            self.assertEqual(0, result.returncode, result.stderr)
            rows = [line.split("\t") for line in record.read_text().splitlines()]
            self.assertEqual(2, len(rows))
            self.assertNotEqual(rows[0][0], rows[1][0])
            self.assertEqual({"1787523964"}, {row[1] for row in rows})
            expected_sources = {
                "lto-archiver-python-runtime-0.11.27.tar.gz",
                "lto-archiver-python-runtime-0.11.27.tar.gz.sha256",
                "runtime-payload-authority.json",
                "runtime_install.py",
            }
            self.assertEqual(expected_sources, set(rows[0][2].split(",")))
            self.assertEqual(expected_sources, set(rows[1][2].split(",")))
            self.assertTrue(
                (
                    output
                    / "RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.x86_64.rpm"
                ).is_file()
            )
            self.assertTrue(
                (
                    output / "SRPMS/lto-archiver-python-runtime-0.11.27-3.src.rpm"
                ).is_file()
            )
            self.assertEqual(
                "fixture detached signature\n",
                (output / "SHA256SUMS.asc").read_text(),
            )

    def test_runtime_publisher_emits_a_self_verified_sha256_manifest_without_deploy_tree(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository, source0, fake_bin, record = make_builder_fixture(root)
            output = root / "published"

            result = self.run_builder(repository, source0, fake_bin, record, output)

            self.assertEqual(0, result.returncode, result.stderr)
            manifest = output / "SHA256SUMS"
            self.assertTrue(manifest.is_file())
            entries = [line.split("  ", 1)[1] for line in manifest.read_text().splitlines()]
            self.assertEqual(sorted(entries), entries)
            self.assertNotIn("SHA256SUMS", entries)
            self.assertFalse((output / "DEPLOY").exists())
            for line in manifest.read_text(encoding="ascii").splitlines():
                digest, relative = line.split("  ", 1)
                self.assertEqual(64, len(digest))
                self.assertEqual(
                    digest,
                    hashlib_sha256((output / relative).read_bytes()),
                )

    def test_builder_rejects_nonreproducible_artifacts_without_publication(
        self,
    ) -> None:
        for vary in ("binary", "source"):
            with self.subTest(vary=vary), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                repository, source0, fake_bin, record = make_builder_fixture(root)
                output = root / "published"
                result = self.run_builder(
                    repository, source0, fake_bin, record, output, vary=vary
                )
                self.assertNotEqual(0, result.returncode)
                self.assertIn("reproducibility check failed", result.stderr)
                self.assertFalse(output.exists())

    def test_builder_rejects_signer_failure_without_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository, source0, fake_bin, record = make_builder_fixture(root)
            output = root / "published"
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{fake_bin}:{environment['PATH']}",
                    "FAKE_RPM_RECORD": str(record),
                    "FAKE_RPM_COUNTER": str(record.with_name("rpmbuild-counter")),
                    "FAKE_SIGN_FAIL": "1",
                }
            )

            result = subprocess.run(
                [
                    str(host_compatible_builder(output.parent)),
                    str(source0),
                    str(output),
                ],
                cwd=repository,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )

            self.assertEqual(2, result.returncode, result.stderr)
            self.assertFalse(output.exists())

    def test_builder_rejects_source0_digest_mismatch_before_rpmbuild(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository, source0, fake_bin, record = make_builder_fixture(root)
            source0.write_bytes(b"substituted source0\n")
            output = root / "published"
            result = self.run_builder(repository, source0, fake_bin, record, output)
            self.assertNotEqual(0, result.returncode)
            self.assertIn("Source0 SHA-256 mismatch", result.stderr)
            self.assertFalse(record.exists())
            self.assertFalse(output.exists())


class SealedRuntimePayloadIntegrationTests(unittest.TestCase):
    def test_real_source0_produces_the_exact_reproducible_payload(self) -> None:
        source0_value = os.environ.get("LTO_RUNTIME_SOURCE0")
        if not source0_value:
            self.skipTest("set LTO_RUNTIME_SOURCE0 for the sealed payload gate")
        source0 = Path(source0_value)
        authority = json.loads(PAYLOAD_AUTHORITY.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            outputs = (root / "first", root / "second")
            for output in outputs:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "packaging/python-runtime/runtime_install.py"),
                        "install-source0",
                        "--archive",
                        str(source0),
                        "--expected-sha256",
                        str(SOURCE0_DIGEST),
                        "--output",
                        str(output),
                        "--installed-root",
                        PRIVATE_ROOT,
                        "--source-date-epoch",
                        "1787523964",
                        "--expected-python",
                        f"{sys.version_info.major}.{sys.version_info.minor}",
                        "--expected-wheel-count",
                        "22",
                    ],
                    cwd=ROOT,
                    check=False,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)

            def snapshot(output: Path) -> list[tuple[str, int, int, str]]:
                return [
                    (
                        path.relative_to(output).as_posix(),
                        path.stat().st_mode & 0o777,
                        int(path.stat().st_mtime),
                        hashlib_sha256(path.read_bytes()),
                    )
                    for path in sorted(output.rglob("*"))
                    if path.is_file()
                ]

            first = snapshot(outputs[0])
            self.assertEqual(first, snapshot(outputs[1]))
            self.assertEqual(1031, len(first))
            self.assertTrue(all(mode == 0o644 for _, mode, _, _ in first))
            self.assertTrue(all(mtime == 1787523964 for _, _, mtime, _ in first))
            self.assertFalse(any(path.endswith(".pth") for path, *_ in first))
            actual_tag = f"cpython-{sys.version_info.major}{sys.version_info.minor}"
            normalized = sorted(
                path.replace(actual_tag, "cpython-311") for path, *_ in first
            )
            filelist = "".join(f"{path}\n" for path in normalized).encode()
            self.assertEqual(authority["filelist_sha256"], hashlib_sha256(filelist))
            self.assertEqual(
                authority["native_extension_paths"],
                sorted(path for path in normalized if path.endswith(".so")),
            )
            self.assertEqual(443, sum(path.endswith(".pyc") for path in normalized))
            self.assertEqual(
                22,
                sum(".dist-info/licenses/" in path for path in normalized),
            )


if __name__ == "__main__":
    unittest.main()
