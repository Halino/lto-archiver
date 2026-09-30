"""Refusal tests for the public, keyless RPM build boundary."""

from __future__ import annotations

import os
import re
import runpy
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace

TOOL = Path(__file__).resolve().parents[1] / "packaging/rpm/build-public-unsigned.py"
RUNTIME_SOURCE = TOOL.parents[2] / "packaging/python-runtime"


def runtime_license_snapshot(root: Path) -> SimpleNamespace:
    extracted = root / "rpm-payload"
    metadata: dict[str, tuple[str, str, str]] = {}
    sources = [path for path in (RUNTIME_SOURCE / "licenses").rglob("*") if path.is_file()]
    if len(sources) != 22:
        raise AssertionError("the reviewed runtime must have 22 component licenses")
    prefix = "/usr/share/licenses/lto-archiver-python-runtime"
    pairs = {
        f"{prefix}/components/{path.relative_to(RUNTIME_SOURCE / 'licenses').as_posix()}": path
        for path in sources
    }
    pairs[f"{prefix}/THIRD_PARTY_NOTICES.md"] = RUNTIME_SOURCE / "THIRD_PARTY_NOTICES.md"
    for name in ("runtime.spdx.json", "wheel-inventory.json"):
        pairs[f"/usr/share/doc/lto-archiver-python-runtime/{name}"] = RUNTIME_SOURCE / name
    for installed, source in pairs.items():
        target = extracted / installed.removeprefix("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        metadata[installed] = ("-rw-r--r--", "root", "root")
    return SimpleNamespace(
        name="lto-archiver-python-runtime",
        architecture="x86_64",
        version_release="0.11.27-3.el9",
        extracted_root=extracted,
        payload_metadata=metadata,
    )


def git(repo: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments], check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def committed_repo(root: Path) -> tuple[Path, str]:
    repo = root / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "tracked.txt").write_text("reviewed\n", encoding="utf-8")
    (repo / "packaging/rpm").mkdir(parents=True)
    (repo / "packaging/rpm/lto-archiver.spec").write_text(
        "Name: lto-archiver\nVersion: 0.11.27\nRelease: 155%{?dist}\n"
    )
    git(repo, "add", "tracked.txt", "packaging")
    git(
        repo,
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "Reviewed source",
    )
    git(repo, "tag", "v0.11.27")
    return repo, git(repo, "rev-parse", "HEAD")


class PublicUnsignedBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = runpy.run_path(str(TOOL))

    def test_build_bootstrap_makes_git_available_before_checkout(self) -> None:
        """A minimal runner must use Git checkout, not archive fallback."""
        source = (TOOL.parents[2] / ".github/workflows/build-release.yml").read_text()
        blocks = re.split(r"(?m)^  ([\w-]+):\s*\n", source.split("\njobs:\n", 1)[1])
        jobs = dict(zip(blocks[1::2], blocks[2::2], strict=True))
        real_git, bash = shutil.which("git"), shutil.which("bash")
        self.assertIsNotNone(real_git)
        self.assertIsNotNone(bash)
        for job in ("build-a", "build-b"):
            before_checkout = jobs[job].split("      - uses: actions/checkout@", 1)[0]
            scripts = re.findall(
                r"(?m)^        run: \|\n((?:^          .*\n)+)", before_checkout
            )
            with self.subTest(job=job), tempfile.TemporaryDirectory() as raw:
                binary_dir = Path(raw)
                # DNF is the external package boundary. Its double installs the
                # real Git executable only when git-core is actually requested.
                dnf = binary_dir / "dnf"
                dnf.write_text(
                    f"#!{sys.executable}\n"
                    "import os, pathlib, sys\n"
                    "if sys.argv[1:] != ['-y', 'install', 'git-core']: sys.exit(2)\n"
                    "pathlib.Path(__file__).with_name('git').symlink_to(os.environ['REAL_GIT'])\n"
                )
                dnf.chmod(0o755)
                environment = {**os.environ, "PATH": raw, "REAL_GIT": real_git}
                self.assertIsNone(shutil.which("git", path=raw))
                result = subprocess.run(
                    [bash, "-euo", "pipefail", "-c",
                     "\n".join(textwrap.dedent(script) for script in scripts)
                     + "\ncommand -v git\ngit --version\n"],
                    env=environment, cwd=raw, capture_output=True, text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("git version ", result.stdout)

    def test_release_tag_must_match_app_version_not_runtime_version(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            repo, _ = committed_repo(Path(raw))
            specs = repo / "packaging/rpm"
            specs.mkdir(parents=True, exist_ok=True)
            (specs / "lto-archiver.spec").write_text(
                "Name: lto-archiver\nVersion: 0.11.29\nRelease: 155%{?dist}\n"
            )
            (specs / "lto-archiver-python-runtime.spec").write_text(
                "Name: lto-archiver-python-runtime\nVersion: 0.11.27\nRelease: 3%{?dist}\n"
            )
            git(repo, "add", "packaging")
            git(repo, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                "commit", "-qm", "Independent component versions")
            commit = git(repo, "rev-parse", "HEAD")
            git(repo, "tag", "-f", "v0.11.27")
            git(repo, "tag", "v0.11.29")
            validate = self.builder["validate_source"]
            with self.assertRaises(self.builder["PublicBuildError"]):
                validate(repo, "v0.11.27", commit)
            validate(repo, "v0.11.29", commit)

    def test_runtime_installed_license_payload_matches_tagged_source(self) -> None:
        verify = self.builder.get("verify_runtime_license_payload")
        self.assertTrue(callable(verify), "runtime RPM payload verifier is missing")
        with tempfile.TemporaryDirectory() as raw:
            snapshot = runtime_license_snapshot(Path(raw))
            verify(snapshot, RUNTIME_SOURCE)

    def test_runtime_changed_or_missing_component_license_is_rejected(self) -> None:
        verify = self.builder.get("verify_runtime_license_payload")
        self.assertTrue(callable(verify), "runtime RPM payload verifier is missing")
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            snapshot = runtime_license_snapshot(Path(raw))
            component = next(
                name for name in snapshot.payload_metadata if "/components/" in name
            )
            installed = snapshot.extracted_root / component.removeprefix("/")
            installed.write_bytes(installed.read_bytes() + b"changed")
            with self.assertRaises(error):
                verify(snapshot, RUNTIME_SOURCE)
            installed.unlink()
            with self.assertRaises(error):
                verify(snapshot, RUNTIME_SOURCE)

    def test_runtime_missing_inventory_or_sbom_is_rejected(self) -> None:
        verify = self.builder.get("verify_runtime_license_payload")
        self.assertTrue(callable(verify), "runtime RPM payload verifier is missing")
        error = self.builder["PublicBuildError"]
        for name in ("wheel-inventory.json", "runtime.spdx.json"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                snapshot = runtime_license_snapshot(Path(raw))
                installed = snapshot.extracted_root / (
                    "usr/share/doc/lto-archiver-python-runtime/" + name
                )
                installed.unlink()
                with self.assertRaises(error):
                    verify(snapshot, RUNTIME_SOURCE)

    def test_runtime_notice_is_required_and_source_identical(self) -> None:
        verify = self.builder["verify_runtime_license_payload"]
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            snapshot = runtime_license_snapshot(Path(raw))
            notice = snapshot.extracted_root / (
                "usr/share/licenses/lto-archiver-python-runtime/THIRD_PARTY_NOTICES.md"
            )
            original = notice.read_bytes()
            notice.write_bytes(original + b"changed")
            with self.assertRaises(error):
                verify(snapshot, RUNTIME_SOURCE)
            notice.unlink()
            with self.assertRaises(error):
                verify(snapshot, RUNTIME_SOURCE)

    def test_rpm_inspection_accepts_large_payload_without_memory_capture(self) -> None:
        verifier = runpy.run_path(
            str(TOOL.parents[2] / "packaging/rpm/verify-main-rpm.py")
        )
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            member = root / "usr/share/doc/runtime/payload.bin"
            member.parent.mkdir(parents=True)
            member.write_bytes(b"x" * (16 * 1024 * 1024 + 1))
            archive = root / "payload.cpio"
            result = subprocess.run(
                ["cpio", "-o", "-H", "newc", "--quiet"],
                cwd=root,
                input=b"usr/share/doc/runtime/payload.bin\n",
                capture_output=True,
                check=True,
            )
            archive.write_bytes(result.stdout)
            fake_rpm = root / "fake-rpm"
            fake_rpm.write_text(
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "if '--requires' in sys.argv: print('libicu')\n"
                "elif '--provides' in sys.argv: print('lto-archiver-python-runtime')\n"
                "elif '%{FILENAMES}' in sys.argv[sys.argv.index('--qf') + 1]:\n"
                "    print('/usr/share/doc/runtime/payload.bin\\t-rw-r--r--\\troot\\troot')\n"
                "else: print('lto-archiver-python-runtime\\nx86_64\\n0.11.27-3.el9\\nhttps://example.invalid')\n",
                encoding="utf-8",
            )
            fake_rpm2cpio = root / "fake-rpm2cpio"
            fake_rpm2cpio.write_text(
                f'#!/bin/sh\nexec /bin/cat "{archive}"\n', encoding="utf-8"
            )
            for path in (fake_rpm, fake_rpm2cpio):
                path.chmod(0o755)
            package = root / "runtime.rpm"
            package.write_bytes(b"fake rpm input")
            tools = verifier["RpmTools"](
                rpm=fake_rpm,
                rpm2cpio=fake_rpm2cpio,
                cpio=Path("/usr/bin/cpio"),
                semodule_unpackage=fake_rpm,
                matchpathcon=fake_rpm,
            )
            snapshot = verifier["inspect_rpm"](package, tools=tools)
            try:
                self.assertEqual(
                    member.read_bytes(),
                    (snapshot.extracted_root / "usr/share/doc/runtime/payload.bin").read_bytes(),
                )
            finally:
                shutil.rmtree(snapshot.extracted_root)

    def test_accepts_only_clean_exact_tag_commit(self) -> None:
        validate = self.builder["validate_source"]
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            repo, commit = committed_repo(Path(raw))
            validate(repo, "v0.11.27", commit)
            with self.assertRaises(error):
                validate(repo, "v0.11.27", "0" * 40)
            with self.assertRaises(error):
                validate(repo, "v0.11.26", commit)
            (repo / "tracked.txt").write_text("changed\n", encoding="utf-8")
            with self.assertRaises(error):
                validate(repo, "v0.11.27", commit)
            (repo / "tracked.txt").write_text("reviewed\n", encoding="utf-8")
            (repo / "untracked.txt").write_text("not reviewed\n", encoding="utf-8")
            with self.assertRaises(error):
                validate(repo, "v0.11.27", commit)

    def test_fake_rpmbuild_extra_rpm_breaks_closed_artifact_set(self) -> None:
        build_once = self.builder["build_rpm_once"]
        validate = self.builder["validate_rpm_closure"]
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repo = root / "repo"
            (repo / "packaging/rpm").mkdir(parents=True)
            (repo / "packaging/rpm/lto-archiver.spec").write_text(
                "Name: lto-archiver\nVersion: 0.11.27\nRelease: 155%{?dist}\n",
                encoding="utf-8",
            )
            source = root / "lto-archiver-0.11.27.tar.gz"
            source.write_bytes(b"reviewed source archive")
            fake = root / "fake-rpmbuild"
            fake.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "top = pathlib.Path(sys.argv[sys.argv.index('--define')+1].split(' ', 1)[1])\n"
                "(top/'RPMS/noarch').mkdir(parents=True, exist_ok=True)\n"
                "(top/'SRPMS').mkdir(parents=True, exist_ok=True)\n"
                "(top/'RPMS/noarch/lto-archiver-0.11.27-155.el9.noarch.rpm').write_bytes(b'rpm')\n"
                "(top/'SRPMS/lto-archiver-0.11.27-155.el9.src.rpm').write_bytes(b'srpm')\n",
                encoding="utf-8",
            )
            fake.chmod(0o755)
            topdir = root / "build"
            build_once(repo, "app", source, topdir, 1_787_523_964, rpmbuild=str(fake))
            validate(topdir, "lto-archiver", "0.11.27", "155", "noarch")
            (topdir / "RPMS/noarch/extra.rpm").write_bytes(b"injected")
            with self.assertRaises(error):
                validate(topdir, "lto-archiver", "0.11.27", "155", "noarch")
            (topdir / "RPMS/noarch/extra.rpm").unlink()
            binary = topdir / "RPMS/noarch/lto-archiver-0.11.27-155.el9.noarch.rpm"
            misplaced = topdir / "RPMS/x86_64"
            misplaced.mkdir()
            binary.rename(misplaced / binary.name)
            with self.assertRaises(error):
                validate(topdir, "lto-archiver", "0.11.27", "155", "noarch")

    def test_changed_srpm_source_member_is_rejected(self) -> None:
        verify = self.builder["verify_srpm_sources"]
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            expected = root / "expected"
            expected.mkdir()
            source = expected / "lto-archiver-0.11.27.tar.gz"
            source.write_bytes(b"reviewed archive")
            spec = expected / "lto-archiver.spec"
            spec.write_text("Name: lto-archiver\n", encoding="utf-8")
            members = root / "members"
            members.mkdir()
            (members / source.name).write_bytes(b"changed archive")
            (members / spec.name).write_bytes(spec.read_bytes())
            archive = root / "fake.src.rpm"
            result = subprocess.run(
                ["cpio", "-o", "-H", "newc", "--quiet"],
                cwd=members,
                input=f"{source.name}\n{spec.name}\n".encode(),
                capture_output=True,
                check=True,
            )
            archive.write_bytes(result.stdout)
            fake = root / "fake-rpm2cpio"
            fake.write_text('#!/bin/sh\nexec /bin/cat "$1"\n', encoding="utf-8")
            fake.chmod(0o755)
            with self.assertRaises(error):
                verify(
                    archive, {source.name: source, spec.name: spec}, rpm2cpio=str(fake)
                )

    def test_existing_or_symlinked_output_is_refused(self) -> None:
        normalize = self.builder["normalize_output"]
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            ordinary = root / "out"
            self.assertEqual(normalize(ordinary), ordinary)
            ordinary.mkdir()
            with self.assertRaises(error):
                normalize(ordinary)
            link = root / "link"
            link.symlink_to(root / "uncreated", target_is_directory=True)
            with self.assertRaises(error):
                normalize(link)
            with self.assertRaises(error):
                normalize(link / "nested")

    def test_runtime_pair_must_match_before_container_install(self) -> None:
        compare = self.builder["compare_rpm_pair"]
        error = self.builder["PublicBuildError"]
        with tempfile.TemporaryDirectory() as raw:
            roots = [Path(raw) / name for name in ("first", "second")]
            for root in roots:
                binary = (
                    root
                    / "RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm"
                )
                source = (
                    root / "SRPMS/lto-archiver-python-runtime-0.11.27-3.el9.src.rpm"
                )
                binary.parent.mkdir(parents=True)
                source.parent.mkdir()
                binary.write_bytes(b"identical binary")
                source.write_bytes(b"identical source")
            compare(*roots, "lto-archiver-python-runtime", "0.11.27", "3", "x86_64")
            binary = next((roots[1] / "RPMS/x86_64").glob("*.rpm"))
            binary.write_bytes(b"changed binary")
            with self.assertRaises(error):
                compare(*roots, "lto-archiver-python-runtime", "0.11.27", "3", "x86_64")


if __name__ == "__main__":
    unittest.main()
