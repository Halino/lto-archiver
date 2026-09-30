"""A restored release gets a durable, separate health observation interval."""

import hashlib
import json
import stat
import subprocess
import unittest
from pathlib import Path
from unittest import mock

from tests import test_rhel9_rollback as rollback_fixture


class RollbackHealthWindowTests(unittest.TestCase):
    def setUp(self):
        self.fixture = rollback_fixture.Rhel9RollbackTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.temporary.cleanup)

    def test_health_window_is_recorded_before_restored_services_activate(self):
        fixture = self.fixture
        fixture._create()
        fixture.host.begin_restore_health_window = lambda recovery: (
            fixture.host.calls.append("health-window-durable")
        )
        result = fixture.module.restore_bundle(fixture.root / "rollback", fixture.host)
        self.assertEqual("restored", result.status)
        self.assertIn("health-window-durable", fixture.host.calls)
        self.assertLess(
            fixture.host.calls.index("health-window-durable"),
            fixture.host.calls.index("activate-old"),
        )

    def test_failed_window_publication_blocks_without_activation(self):
        fixture = self.fixture
        fixture._create()

        def refuse(recovery):
            raise OSError("cannot durably record health interval")

        fixture.host.begin_restore_health_window = refuse
        result = fixture.module.restore_bundle(fixture.root / "rollback", fixture.host)
        self.assertEqual("blocked", result.status)
        self.assertNotIn("activate-old", fixture.host.calls)
        self.assertTrue(fixture.host.masked)

    def test_real_window_is_new_private_and_bound_to_the_sealed_bundle(self):
        fixture = self.fixture
        fixture._create()
        recovery = fixture.root / "health-window"
        recovery.mkdir(mode=0o700)
        system = fixture.module.SystemRollbackHost()
        system._verified_bundle = fixture.root / "rollback"
        # Root-owned directory admission is independently covered by rollback tests.
        system.parent_is_secure = lambda path: path == recovery
        self.assertTrue(callable(getattr(system, "begin_restore_health_window", None)))
        system.begin_restore_health_window(recovery)
        path = recovery / "restore-health-window.json"
        payload = json.loads(path.read_text())
        self.assertEqual(
            {"schema", "bundle_manifest_sha256", "restoration_started_at"}, set(payload)
        )
        self.assertEqual(1, payload["schema"])
        self.assertEqual(
            hashlib.sha256(
                (system._verified_bundle / "bundle-manifest.json").read_bytes()
            ).hexdigest(),
            payload["bundle_manifest_sha256"],
        )
        self.assertRegex(
            payload["restoration_started_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"
        )
        self.assertEqual(0o600, stat.S_IMODE(path.stat().st_mode))
        original = path.read_bytes()
        with self.assertRaises((OSError, fixture.module.RollbackError)):
            system.begin_restore_health_window(recovery)
        self.assertEqual(original, path.read_bytes())

    def _health_consumer(self):
        fixture = self.fixture
        manifest = fixture._create()
        system = fixture.module.SystemRollbackHost()
        bundle = fixture.root / "rollback"
        system._verified_bundle = bundle
        contract = json.loads((bundle / "contracts/old-live-contract.json").read_text())
        system._basic_old_health = lambda manifest, probe: True
        system._require_tool = lambda path: None
        system.captured_installed_package_state = lambda: contract[
            "installed_package_state"
        ]
        commands = []

        def run(argv, accepted=(0,)):
            command = tuple(str(part) for part in argv)
            commands.append(command)
            output = Path(command[command.index("--json-output") + 1])
            output.write_text('{"schema":1,"status":"green"}\n')
            return subprocess.CompletedProcess(command, 0, "", "")

        system._run = run
        recovery = fixture.root / "health-observation"
        recovery.mkdir(mode=0o700)
        system.parent_is_secure = lambda path: path == recovery
        return system, manifest, recovery, commands

    def test_current_health_refuses_missing_durable_window(self):
        system, manifest, _recovery, commands = self._health_consumer()
        self.assertFalse(system.verify_old_health(manifest))
        self.assertEqual([], commands)

    def test_current_health_passes_persisted_activation_timestamp_to_verifier(self):
        system, manifest, recovery, commands = self._health_consumer()
        system.begin_restore_health_window(recovery)
        expected = json.loads((recovery / "restore-health-window.json").read_text())[
            "restoration_started_at"
        ]
        self.assertTrue(system.verify_old_health(manifest))
        self.assertIn("--restoration-started-at", commands[0])
        self.assertEqual(
            expected, commands[0][commands[0].index("--restoration-started-at") + 1]
        )

    def test_current_health_rejects_tampered_window_without_verifier_execution(self):
        system, manifest, recovery, commands = self._health_consumer()
        system.begin_restore_health_window(recovery)
        (recovery / "restore-health-window.json").write_text("{}\n")
        self.assertFalse(system.verify_old_health(manifest))
        self.assertEqual([], commands)

    def test_failed_fsync_cannot_authorize_health_verification(self):
        system, manifest, recovery, commands = self._health_consumer()
        with (
            mock.patch.object(
                self.fixture.module.os, "fsync", side_effect=OSError("disk full")
            ),
            self.assertRaises(OSError),
        ):
            system.begin_restore_health_window(recovery)
        self.assertFalse(system.verify_old_health(manifest))
        self.assertEqual([], commands)

    def test_failed_new_window_invalidates_previous_activation_authority(self):
        system, manifest, recovery, commands = self._health_consumer()
        system.begin_restore_health_window(recovery)
        with self.assertRaises(OSError):
            system.begin_restore_health_window(recovery)
        self.assertFalse(system.verify_old_health(manifest))
        self.assertEqual([], commands)


if __name__ == "__main__":
    unittest.main()
