"""The publication gate must read and reject unqualified VM evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "packaging/rpm/verify-public-fresh-smoke.py"
APP = "lto-archiver-0.11.30-155.el9.noarch.rpm"
RUNTIME = "lto-archiver-python-runtime-0.11.27-3.el9.x86_64.rpm"
DRIVER = "lto-ltfs-0.1.2-22.el9.x86_64.rpm"
CHECKS = (
    "disposable_marker", "snapshot_created", "fresh_host", "signed_tuple",
    "install_order", "installed_nevras", "rpm_verify", "unit_syntax",
    "service_accounts", "selinux", "live_web_login", "hardware_absence_refused",
    "uninstall_residue_recorded", "uninstall_no_owned_executables",
    "uninstall_no_active_units", "snapshot_restored",
)


class FreshSmokeGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.app = self.root / APP
        self.runtime = self.root / RUNTIME
        self.app.write_bytes(b"signed app fixture")
        self.runtime.write_bytes(b"signed runtime fixture")
        digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
        self.report = {
            "schema_version": 2,
            "profile": "fresh-rhel9-webui-hardware-absent",
            "unverified_features": ["backup_restore", "daemon_import", "physical_ltfs"],
            "qualified": True,
            "app_commit": "a" * 40,
            "driver_commit": "b" * 40,
            "rpm_sha256": {APP: digest(self.app), RUNTIME: digest(self.runtime), DRIVER: "c" * 64},
            "baseline_sha256": "d" * 64,
            "restored_sha256": "d" * 64,
            "checks": {name: True for name in CHECKS},
            "uninstall_generated_state_count": 2,
        }

    def run_gate(self, report: dict | bytes, *, approved: str | None = None) -> subprocess.CompletedProcess[str]:
        raw = report if isinstance(report, bytes) else json.dumps(report, sort_keys=True).encode()
        path = self.root / "report.json"
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest() if approved is None else approved
        return subprocess.run(
            [sys.executable, str(GATE), "--report", str(path),
             "--approved-sha256", digest, "--app-commit", "a" * 40,
             "--app-rpm", str(self.app), "--runtime-rpm", str(self.runtime)],
            capture_output=True, text=True, check=False,
        )

    def test_exact_qualified_report_passes(self) -> None:
        result = self.run_gate(self.report)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_report_hash_substitution_fails(self) -> None:
        result = self.run_gate(self.report, approved="0" * 64)
        self.assertNotEqual(result.returncode, 0)

    def test_static_only_or_failed_live_login_is_not_qualified(self) -> None:
        for field in ("live_web_login", "hardware_absence_refused", "snapshot_restored"):
            with self.subTest(field=field):
                report = {**self.report, "checks": {**self.report["checks"], field: False}}
                self.assertNotEqual(self.run_gate(report).returncode, 0)

    def test_missing_check_and_false_qualified_fail(self) -> None:
        report = {**self.report, "checks": dict(self.report["checks"])}
        del report["checks"]["uninstall_no_active_units"]
        self.assertNotEqual(self.run_gate(report).returncode, 0)
        self.assertNotEqual(self.run_gate({**self.report, "qualified": False}).returncode, 0)

    def test_changed_snapshot_or_package_or_source_fails(self) -> None:
        for changed in (
            {**self.report, "restored_sha256": "e" * 64},
            {**self.report, "app_commit": "e" * 40},
            {**self.report, "rpm_sha256": {**self.report["rpm_sha256"], APP: "e" * 64}},
        ):
            with self.subTest(changed=changed):
                self.assertNotEqual(self.run_gate(changed).returncode, 0)

    def test_unknown_fields_and_trailing_json_fail(self) -> None:
        self.assertNotEqual(self.run_gate({**self.report, "unexpected": "value"}).returncode, 0)
        raw = json.dumps(self.report).encode() + b'\n{"extra":"value"}'
        self.assertNotEqual(self.run_gate(raw).returncode, 0)

    def test_hardware_free_report_cannot_claim_import_or_physical_qualification(self) -> None:
        for value in ([], ["physical_ltfs"], ["backup_restore", "physical_ltfs"]):
            with self.subTest(unverified=value):
                self.assertNotEqual(self.run_gate({
                    **self.report, "unverified_features": value,
                }).returncode, 0)

    def test_old_smoke_profile_cannot_be_relabelled_as_new_acceptance(self) -> None:
        self.assertNotEqual(self.run_gate({
            **self.report, "schema_version": 1, "profile": "fresh-rhel9-no-tape",
        }).returncode, 0)


if __name__ == "__main__":
    unittest.main()
