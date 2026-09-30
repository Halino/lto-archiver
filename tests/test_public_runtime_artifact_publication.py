"""Runtime publication must preserve the exact public comparison inputs."""

from __future__ import annotations

import hashlib
import os
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path

from tests.test_public_release_gate import COMMIT, EXPECTED_RPMS, TAG, fixture


ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    "lto-archiver-python-runtime-0.11.27.tar.gz.sha256",
    "runtime_install.py",
    "runtime-payload-authority.json",
)


class PublicRuntimeArtifactPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.builder = runpy.run_path(str(ROOT / "packaging/rpm/build-public-unsigned.py"))
        cls.gate = runpy.run_path(str(ROOT / "packaging/rpm/verify-public-artifacts.py"))

    def inputs(self, root: Path) -> tuple[Path, Path]:
        first, second = root / "first-input", root / "second-input"
        first.mkdir()
        second.mkdir()
        fixture(first)
        fixture(second)
        return first, second

    def publish(self, first: Path, second: Path, output: Path) -> None:
        self.builder["_publish_pair"](
            ROOT, first, second, "lto-archiver-python-runtime-0.11.27.tar.gz",
            "lto-archiver-python-runtime.spec", output,
        )

    def test_real_publication_preserves_sources_through_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first, second = self.inputs(root)
            # An unrelated source must not be admitted merely by existing in SOURCES.
            for source in (first, second):
                (source / "runtime/SOURCES/arbitrary.txt").write_bytes(b"not approved\n")
            outputs = (root / "build-a", root / "build-b")
            for output in outputs:
                output.mkdir()
                self.publish(first / "runtime", second / "runtime", output / "runtime")
                self.builder["_publish_pair"](
                    ROOT, first / "app", second / "app", "lto-archiver-0.11.31.tar.gz",
                    "lto-archiver.spec", output / "app",
                )
                for name in ("EVIDENCE.json", "MAIN-RPM.json"):
                    shutil.copyfile(first / name, output / name)
                paths = sorted(path for path in output.rglob("*") if path.is_file())
                (output / "SHA256SUMS").write_text("".join(
                    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                    f"{path.relative_to(output).as_posix()}\n" for path in paths
                ), encoding="ascii")
                self.assertFalse((output / "runtime/SOURCES/arbitrary.txt").exists())
            report = self.gate["compare_unsigned"](
                *outputs, EXPECTED_RPMS, TAG, COMMIT,
            )
            self.assertEqual(report["status"], "identical_unsigned")
            self.assertEqual(set(report["rpm_sha256"]), EXPECTED_RPMS)
            for output in outputs:
                for name in SOURCES:
                    self.assertEqual(
                        (first / "runtime/SOURCES" / name).read_bytes(),
                        (output / "runtime/SOURCES" / name).read_bytes(),
                    )
            (outputs[0] / "runtime/SOURCES/arbitrary.txt").write_bytes(b"not approved\n")
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](*outputs, EXPECTED_RPMS, TAG, COMMIT)

    def test_missing_runtime_source_refuses_publication(self) -> None:
        for name in SOURCES:
            with self.subTest(source=name), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                first, second = self.inputs(root)
                (second / "runtime/SOURCES" / name).unlink()
                output = root / "published"
                with self.assertRaises(self.builder["PublicBuildError"]):
                    self.publish(first / "runtime", second / "runtime", output)
                self.assertFalse(output.exists())

    def test_unsafe_runtime_source_refuses_publication(self) -> None:
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                first, second = self.inputs(root)
                source = second / "runtime/SOURCES/runtime_install.py"
                target = root / "outside"
                target.write_bytes(source.read_bytes())
                source.unlink()
                if kind == "symlink":
                    source.symlink_to(target)
                else:
                    os.link(target, source)
                output = root / "published"
                with self.assertRaises(self.builder["PublicBuildError"]):
                    self.publish(first / "runtime", second / "runtime", output)
                self.assertFalse(output.exists())

    def test_different_runtime_source_bytes_refuse_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            first, second = self.inputs(root)
            (second / "runtime/SOURCES/runtime-payload-authority.json").write_bytes(b"changed\n")
            output = root / "published"
            with self.assertRaises(self.builder["PublicBuildError"]):
                self.publish(first / "runtime", second / "runtime", output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
