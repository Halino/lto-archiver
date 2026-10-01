"""Artifact admission must fail before exposing unverified RPM bytes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/run-github-el9-smoke.py"


class GitHubEL9SmokeTests(unittest.TestCase):
    def report_fixture(self):
        names = ["fresh_host", "hardware_absent", "hash_pinned_unsigned_tuple", "install_order",
                 "installed_nevras", "rpm_verify", "unit_syntax", "service_accounts", "selinux",
                 "live_web_login", "preflight_refuses_unsupported_host", "uninstall_residue_recorded",
                 "uninstall_no_owned_executables", "uninstall_no_active_units"]
        return {"schema_version": 1, "profile": "github-almalinux9-unsigned-compatibility",
                "qualified": False, "compatibility_passed": True, "errors": [],
                "app_commit": "4507cd23e96fef48dd3099d0da69bb7cda3a9a27",
                "driver_commit": "61f8b6acb547e715624856e85786e7676fa28c37",
                "rpm_sha256": {
                    "lto-ltfs-0.1.2-22.el9.x86_64.rpm": "a2f234284c96c3f35f358f46d8977e7fbba53f8d292d04eb5d909f7dd5f46a44",
                    "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm": "59c9694981bcbff8583b4d16b0fe7ea3137cb2b102e506a4af897193fe895bb3",
                    "lto-archiver-0.11.31-155.el9.noarch.rpm": "bfc77147a6b98623eb74cb8c19d4fe477bd9af71abcea7dd693b8e6488b916c9"},
                "unverified_features": ["backup_restore", "daemon_import", "physical_ltfs", "rhel9",
                                        "rpm_signatures", "snapshot_restoration"],
                "checks": dict.fromkeys(names, True)}

    def invoke(self, *arguments):
        return subprocess.run([sys.executable, str(SCRIPT), *map(str, arguments)],
                              capture_output=True, text=True)

    def test_admits_only_the_hash_pinned_member(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, output = root / "input.zip", root / "selected.rpm"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("unsigned/package.rpm", b"reviewed package bytes")
                stream.writestr("../../must-not-extract", b"unrelated")
            result = self.invoke("validate-archive", archive,
                                 hashlib.sha256(archive.read_bytes()).hexdigest(),
                                 "unsigned/package.rpm",
                                 "9074a406093263d77bf04f19cc0bd22fe1d11aa475a3c88a2613edc1482d9f7f",
                                 output)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output.read_bytes(), b"reviewed package bytes")
            self.assertEqual(sorted(p.name for p in root.iterdir()), ["input.zip", "selected.rpm"])

    def test_rejects_archive_or_rpm_drift_without_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "input.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("unsigned/package.rpm", b"changed")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            for archive_digest, rpm_digest in (("0" * 64, "0" * 64), (digest, "0" * 64)):
                output = root / "selected.rpm"
                result = self.invoke("validate-archive", archive, archive_digest,
                                     "unsigned/package.rpm", rpm_digest, output)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(output.exists())

    def test_does_not_turn_compatibility_evidence_into_release_qualification(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            value = self.report_fixture()
            value["qualified"] = True
            report.write_text(json.dumps(value))
            result = self.invoke("check-report", report)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_admits_complete_unqualified_report_but_rejects_one_failed_observation(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            value = self.report_fixture()
            report.write_text(json.dumps(value))
            result = self.invoke("check-report", report)
            self.assertEqual(result.returncode, 0, result.stderr)
            value["checks"]["live_web_login"] = False
            report.write_text(json.dumps(value))
            result = self.invoke("check-report", report)
            self.assertEqual(result.returncode, 2, result.stderr)


if __name__ == "__main__":
    unittest.main()
