from __future__ import annotations

import unittest
from contextlib import ExitStack
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup.daemon import archive_runtime, restore_coordinator
from ltobackup.daemon.models import RecoveryCommandFence, ProcessIdentity
from ltobackup.tape.command_supervisor import (
    CommandFailed,
    ProcessObservation,
    SnapshotProcessProbe,
)
from tests.test_archive_recovery import _command, _operation, _target


class _ProcessSource:
    def __init__(self, observations=()):
        self.observations = observations
        self.snapshots = 0
        self.boot_reads = 0
        self.failure = None

    def snapshot(self):
        self.snapshots += 1
        if self.failure is not None:
            raise self.failure
        return self.observations

    def boot_id(self):
        self.boot_reads += 1
        return "boot-a"


class RecoveryProcessSnapshotTests(unittest.TestCase):
    def _inspect(self, module, identities, source):
        """Keep real process correlation; replace only catalog/media boundaries."""
        native = module is archive_runtime
        kind = "archive.native" if native else "restore.cassette"
        operation = _operation(None, kind=kind)
        fence = RecoveryCommandFence(operation.operation_id, 7)
        commands = tuple(
            _command(command_id=f"command-{index}", process=identity)
            for index, identity in enumerate(identities)
        )
        cassette = SimpleNamespace(
            sequence=4, physical_label="RECOVERY-4", tape_serial="SERIAL-4",
            operation="format", expected_media=object(),
        )
        catalog = SimpleNamespace(
            assert_command_fence=lambda selected: self.assertEqual(fence, selected),
            get_operation=lambda selected: {
                "job_id": "job", "cassette_sequence": 4,
            },
            current_daemon_fence=lambda: SimpleNamespace(generation=7),
            hardware_commands_for_operation=lambda selected: commands,
            restore_run=lambda selected: {"cassettes": [vars(cassette)]},
        )
        runtime_type = (
            module.ProductionRecoveryRuntime if native
            else module.ProductionRestoreRuntime
        )
        runtime = object.__new__(runtime_type)
        runtime._archive = SimpleNamespace(
            _settings=SimpleNamespace(mount_path=Path("/synthetic/mount")),
            _ltfs_info_binary=Path("/synthetic/ltfs-info"),
            _device_identities=object(),
        )
        probe = SnapshotProcessProbe(snapshot=source.snapshot, boot_id=source.boot_id)
        with ExitStack() as stack:
            stack.enter_context(patch.object(module, "LinuxProcessProbe", return_value=probe))
            mount = stack.enter_context(patch.object(module, "ProcMountInfoProbe"))
            mount.return_value.is_mounted.return_value = False
            mount.return_value.has_fuse_mount.return_value = False
            media = stack.enter_context(patch.object(module, "BrokeredLtfsInfoMediaIdentityProbe"))
            media.return_value.identify_preformat.side_effect = CommandFailed("identify", 3)
            media.return_value.identify_unmounted.side_effect = CommandFailed("probe_media", 3)
            stack.enter_context(patch.object(runtime, "_recovery_supervisor", return_value=object()))
            if native:
                stack.enter_context(patch.object(module.FrozenNativeCassettePlan, "load", return_value=cassette))
                stack.enter_context(patch.object(module.LinuxLtfsBackend, "target_binding_from", return_value=_target()))
            else:
                stack.enter_context(patch.object(runtime, "hardware_target", return_value=_target()))
            return runtime.inspect(operation, fence, catalog)

    def test_long_command_history_uses_one_fresh_snapshot_per_assessment(self):
        identities = tuple(ProcessIdentity("boot-a", index, index, index) for index in range(100, 228))
        for module in (archive_runtime, restore_coordinator):
            with self.subTest(runtime=module.__name__):
                source = _ProcessSource()
                result = self._inspect(module, identities, source)
                self.assertFalse(result.drive_busy)
                self.assertEqual((), result.correlated_processes)
                self.assertEqual(1, source.snapshots)
                self.assertEqual(1, source.boot_reads)

                source.observations = (ProcessObservation(identities[-1], 1),)
                result = self._inspect(module, identities, source)
                self.assertTrue(result.drive_busy)
                self.assertEqual((identities[-1],), result.correlated_processes)
                self.assertEqual(2, source.snapshots)
                self.assertEqual(2, source.boot_reads)

    def test_exact_identity_and_group_survivors_keep_order(self):
        exact = ProcessIdentity("boot-a", 101, 10, 101)
        group_root = ProcessIdentity("boot-a", 201, 20, 201)
        reused = ProcessIdentity("boot-a", 301, 30, 301)
        old_boot = ProcessIdentity("previous-boot", 401, 40, 401)
        identities = (None, reused, group_root, old_boot, exact)
        observations = (
            ProcessObservation(exact, 1),
            ProcessObservation(ProcessIdentity("boot-a", 202, 21, 201), 1),
            ProcessObservation(ProcessIdentity("boot-a", 301, 31, 302), 1),
            ProcessObservation(ProcessIdentity("boot-a", 401, 40, 401), 1),
        )
        for module in (archive_runtime, restore_coordinator):
            with self.subTest(runtime=module.__name__):
                result = self._inspect(module, identities, _ProcessSource(observations))
                self.assertTrue(result.drive_busy)
                self.assertEqual((group_root, exact), result.correlated_processes)
                self.assertFalse(result.media_loaded)
                self.assertFalse(result.mounted)

    def test_duplicate_survivor_identities_remain_invalid(self):
        identity = ProcessIdentity("boot-a", 101, 10, 101)
        for module in (archive_runtime, restore_coordinator):
            with self.subTest(runtime=module.__name__):
                source = _ProcessSource((ProcessObservation(identity, 1),))
                with self.assertRaisesRegex(ValueError, "must be unique"):
                    self._inspect(module, (identity, identity), source)

    def test_snapshot_failure_does_not_report_false_quiescence(self):
        identity = ProcessIdentity("boot-a", 101, 10, 101)
        for module in (archive_runtime, restore_coordinator):
            with self.subTest(runtime=module.__name__):
                source = _ProcessSource()
                source.failure = PermissionError("synthetic procfs unavailable")
                with self.assertRaises(PermissionError):
                    self._inspect(module, (identity,), source)

    def test_commands_without_process_identity_need_no_process_snapshot(self):
        for module in (archive_runtime, restore_coordinator):
            with self.subTest(runtime=module.__name__):
                source = _ProcessSource()
                result = self._inspect(module, (None,), source)
                self.assertFalse(result.drive_busy)
                self.assertEqual((), result.correlated_processes)
                self.assertEqual(0, source.snapshots)


if __name__ == "__main__":
    unittest.main()
