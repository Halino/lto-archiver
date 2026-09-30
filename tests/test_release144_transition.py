"""Focused application144/runtime3/driver21 transition contract."""

from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests import test_rhel9_deployment as deployment_tests
from tests import test_rhel9_rollback as rollback_tests
from tests import test_rhel9_rollback_predecessor_profile as profile_tests
from tests.test_release135_transition import nevras

ROOT = Path(__file__).resolve().parents[1]
DRIVER21_VERIFY_POLICY_SHA256 = (
    "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
)


class Release144PackagingTests(unittest.TestCase):
    def test_current_release_pins_are_exact155_runtime3_driver22(self):
        spec = (ROOT / "packaging/rpm/lto-archiver.spec").read_text()
        contract = json.loads(
            (ROOT / "packaging/rpm/main-rpm-contract.json").read_text()
        )

        release = re.search(r"(?m)^Release:\s+(\S+)$", spec)
        self.assertIsNotNone(release)
        self.assertEqual("155%{?dist}", release.group(1))
        self.assertEqual("155.el9", contract["release"])
        self.assertEqual(
            "lto-archiver-python-runtime = 0.11.27-3.el9",
            contract["runtime_requirement"],
        )
        self.assertEqual("lto-ltfs = 0.1.0-22.el9", contract["driver_requirement"])
        self.assertRegex(
            spec, r"(?m)^Requires:\s+lto-ltfs = 0\.1\.0-22%\{\?dist\}$"
        )

    def test_driver21_verification_policy_bytes_are_unchanged(self):
        raw = (ROOT / "packaging/rpm/driver-rpm-verify-policy.json").read_bytes()

        self.assertEqual(DRIVER21_VERIFY_POLICY_SHA256, hashlib.sha256(raw).hexdigest())


class Release144DeploymentTests(unittest.TestCase):
    setUp = deployment_tests.Rhel9DeploymentTests.setUp
    tearDown = deployment_tests.Rhel9DeploymentTests.tearDown

    def predecessor_host(self, installed):
        host = object.__new__(self.module.SystemDeploymentHost)
        host._rollback = rollback_tests._load_module()
        check = mock.Mock(return_value=True)
        host._rollback_host = SimpleNamespace(
            installed_nevras=lambda: installed,
            _sqlite_check=check,
        )
        return host, check

    def test_exact144_candidate_and141_predecessor_are_not_swappable(self):
        rollback = rollback_tests._load_module()
        self.assertEqual(nevras(141, 21), rollback._PREDECESSOR_NEVRAS)
        self.assertEqual(nevras(144, 21), rollback._DEPLOYED_NEVRAS)

        predecessor, sqlite_check = self.predecessor_host(nevras(141, 21))
        self.assertTrue(
            predecessor.validate_predecessor_source(self.request.rollback_request)
        )
        sqlite_check.assert_called_once_with(
            Path("/var/lib/lto-archiver/catalog.db"),
            catalog=True,
            catalog_schema="40",
            deployment_quiescent=True,
        )
        for application, driver in ((144, 21), (143, 21), (142, 21), (141, 20), (140, 21)):
            with self.subTest(predecessor_application=application, driver=driver):
                rejected, rejected_check = self.predecessor_host(
                    nevras(application, driver)
                )
                self.assertFalse(
                    rejected.validate_predecessor_source(
                        self.request.rollback_request
                    )
                )
                rejected_check.assert_not_called()

        candidate = object.__new__(self.module.SystemDeploymentHost)
        candidate._rollback_host = SimpleNamespace(
            installed_nevras=lambda: nevras(144, 21)
        )
        candidate.authenticated_preflight()
        for application, driver in ((141, 21), (142, 21), (143, 21), (144, 20), (140, 21)):
            with self.subTest(candidate_application=application, driver=driver):
                rejected = object.__new__(self.module.SystemDeploymentHost)
                rejected._rollback_host = SimpleNamespace(
                    installed_nevras=lambda application=application, driver=driver: nevras(
                        application, driver
                    )
                )
                with self.assertRaises(self.module.DeploymentError):
                    rejected.authenticated_preflight()

    def test_driver_and_live_requests_use_current144_identity(self):
        host = object.__new__(self.module.SystemDeploymentHost)
        captured = []
        host._live = SimpleNamespace(
            VerifyDeploymentRequest=lambda **fields: captured.append(
                SimpleNamespace(**fields)
            )
            or captured[-1],
            verify_deployment=lambda *_args: SimpleNamespace(
                status="green", to_json=lambda: "{}\n"
            ),
            _publish_report=lambda *_args: None,
        )
        host._config = SimpleNamespace(
            rpm_verify_policy=self.root / "rpm-policy",
            journal_policy=self.root / "journal-policy",
            live_report_output=self.root / "live-report.json",
        )
        host._live_host = SimpleNamespace(
            _driver_artifact_ok=lambda _request: True,
            _config=SimpleNamespace(driver_rpm=self.request.driver_rpm),
        )

        host._driver_request(self.request)
        self.request.rollback_request.bundle_dir.mkdir()
        (
            self.request.rollback_request.bundle_dir / "bundle-manifest.json"
        ).write_bytes(b"rollback\n")
        self.assertTrue(host.verify_driver_input(self.request))
        self.assertEqual("verified", host.verify_live(self.request).status)

        self.assertEqual(3, len(captured))
        for request in captured:
            self.assertEqual(nevras(144, 21), request.expected_nevras)


class Release144HistoricalHealthTests(unittest.TestCase):
    setUp = profile_tests.RollbackPredecessorProfileTests.setUp
    source_contract = profile_tests.RollbackPredecessorProfileTests.source_contract
    full_gate = profile_tests.RollbackPredecessorProfileTests.full_gate

    def test_release141_schema40_driver21_is_a_valid_historical_profile(self):
        self.assertTrue(
            self.full_gate(141, 40, driver_release=21, reader="inactive")
        )


if __name__ == "__main__":
    unittest.main()
