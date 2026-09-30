"""Fail-closed tests for the independently built public unsigned artifact trees."""

from __future__ import annotations

import hashlib
import json
import runpy
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "packaging/rpm/verify-public-artifacts.py"
TAG = "v0.11.28"
COMMIT = "a" * 40
EXPECTED_RPMS = {
    "app/RPMS/noarch/lto-archiver-0.11.28-155.el9.noarch.rpm",
    "app/SRPMS/lto-archiver-0.11.28-155.el9.src.rpm",
    "runtime/RPMS/x86_64/lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm",
    "runtime/SRPMS/lto-archiver-python-runtime-0.11.27-3.el9.src.rpm",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(root: Path) -> None:
    for subtree in ("app", "runtime"):
        base = root / subtree
        paths = sorted(
            path
            for path in base.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        )
        (base / "SHA256SUMS").write_text(
            "".join(
                f"{sha(path)}  {path.relative_to(base).as_posix()}\n" for path in paths
            ),
            encoding="ascii",
        )
    paths = sorted(
        path
        for path in root.rglob("*")
        if path.is_file() and path != root / "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{sha(path)}  {path.relative_to(root).as_posix()}\n" for path in paths
        ),
        encoding="ascii",
    )


def fixture(root: Path, *, commit: str = COMMIT) -> None:
    for relative in EXPECTED_RPMS:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"unsigned {relative}".encode())
    for package in ("app", "runtime"):
        (root / package / "SOURCES").mkdir()
        (root / package / "SPECS").mkdir()
        rpm_name = "lto-archiver" if package == "app" else "lto-archiver-python-runtime"
        version = "0.11.28" if package == "app" else "0.11.27"
        archive = f"{rpm_name}-{version}.tar.gz"
        (root / package / "SOURCES" / archive).write_bytes(b"source")
        (root / package / "SPECS" / f"{rpm_name}.spec").write_bytes(b"spec")
        if package == "runtime":
            (root / package / "SOURCES" / f"{archive}.sha256").write_bytes(b"digest")
            (root / package / "SOURCES" / "runtime_install.py").write_bytes(b"script")
            (root / package / "SOURCES" / "runtime-payload-authority.json").write_bytes(
                b"{}"
            )
    app_binary = root / "app/RPMS/noarch/lto-archiver-0.11.28-155.el9.noarch.rpm"
    (root / "MAIN-RPM.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "status": "verified",
                "name": "lto-archiver",
                "architecture": "noarch",
                "version_release": "0.11.28-155.el9",
                "rpm_sha256": sha(app_binary),
            }
        )
        + "\n",
        encoding="ascii",
    )
    (root / "EVIDENCE.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "tag": TAG,
                "commit": commit,
                "app_source0_sha256": sha(
                    root / "app/SOURCES/lto-archiver-0.11.28.tar.gz"
                ),
                "runtime_source0_sha256": sha(
                    root / "runtime/SOURCES/lto-archiver-python-runtime-0.11.27.tar.gz"
                ),
            },
            sort_keys=True,
        )
        + "\n",
        encoding="ascii",
    )
    seal(root)


class PublicReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.gate = runpy.run_path(str(TOOL))

    def test_exact_identical_trees_pass(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second)
            report = self.gate["compare_unsigned"](
                first, second, EXPECTED_RPMS, TAG, COMMIT
            )
            self.assertEqual(report["status"], "identical_unsigned")
            self.assertEqual(set(report["rpm_sha256"]), EXPECTED_RPMS)

    def test_changed_byte_fails_even_with_resealed_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second)
            (second / min(EXPECTED_RPMS)).write_bytes(b"different RPM")
            seal(second)
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)

    def test_extra_rpm_fails_even_when_manifest_includes_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second)
            (second / "app/RPMS/noarch/extra.rpm").write_bytes(b"unreviewed")
            seal(second)
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)

    def test_wrong_commit_or_unlisted_file_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second, commit="d" * 40)
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)
            evidence = json.loads((second / "EVIDENCE.json").read_text())
            evidence["commit"] = COMMIT
            (second / "EVIDENCE.json").write_text(json.dumps(evidence) + "\n")
            seal(second)
            (first / "unlisted.txt").write_text("bad", encoding="ascii")
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)

    def test_symlink_in_download_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second)
            (second / "link").symlink_to(second / "EVIDENCE.json")
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)

    def test_two_identical_trees_cannot_lie_about_source0_digest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second)
            for root in (first, second):
                (root / "app/SOURCES/lto-archiver-0.11.27.tar.gz").write_bytes(
                    b"other source"
                )
                seal(root)
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)

    def test_false_main_rpm_verification_report_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            first, second = Path(raw) / "first", Path(raw) / "second"
            first.mkdir()
            second.mkdir()
            fixture(first)
            fixture(second)
            for root in (first, second):
                report = json.loads((root / "MAIN-RPM.json").read_text())
                report["status"] = "not_verified"
                (root / "MAIN-RPM.json").write_text(json.dumps(report) + "\n")
                seal(root)
            with self.assertRaises(self.gate["PublicArtifactError"]):
                self.gate["compare_unsigned"](first, second, EXPECTED_RPMS, TAG, COMMIT)


if __name__ == "__main__":
    unittest.main()
