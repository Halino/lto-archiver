"""Restart must not issue tape probes for an ambiguous pre-media release."""
from datetime import UTC, datetime
from pathlib import Path
import tempfile
import unittest

from ltobackup.catalog import Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.models import (
    HardwareTargetBinding, OperationFence, OperationRecord, ProcessIdentity,
)
from ltobackup.daemon.recovery_coordinator import RecoveryCoordinatorResult
from ltobackup.daemon.service import DaemonService
from ltobackup.linux_settings import LinuxPaths, LinuxSettings


class _RecordingCoordinator:
    def __init__(self):
        self.assessed = []

    def set_transition_callback(self, callback):
        self.callback = callback

    def reconcile_startup(self, blockers):
        self.assessed.extend(item.id for item in blockers)
        return RecoveryCoordinatorResult(())

    def start(self):
        pass

    def shutdown(self):
        pass


class PreMediaStartupDeferralTests(unittest.TestCase):
    def _restart(self, *, ambiguous, phase=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = LinuxSettings(state_dir=root / "state", socket_path=root / "daemon.sock")
            paths = LinuxPaths.from_settings(settings)
            backups = BackupManager(paths.catalog_file, paths.backup_dir)
            backups.prepare_and_initialize()
            with Catalog(paths.catalog_file) as catalog:
                catalog.add_library("LIB", "Library", str(root))
                catalog.create_automatic_job("JOB", "LIB", "drive", str(root / "tape"),
                                             [("TAPE16", "SERIAL", 1, 1)], force_format=True)
                owner = catalog.claim_daemon_owner("old-daemon")
                target = HardwareTargetBinding.from_verified_inputs(
                    root / "tape", "tape-by-id", "scsi-by-id",
                    ("archive.native", "JOB", "1", "TAPE16", "", ""),
                )
                record = OperationRecord("blocked", "archive.native", "running", None,
                                         "key", "admin", "JOB", 1,
                                         datetime.now(UTC).isoformat(), None)
                catalog.admit_operation(record, owner, admission_open=True, hardware_target=target)
                fence = OperationFence("blocked", owner.generation)
                catalog.reserve_hardware_command(fence, "probe", "probe_media", "a" * 64)
                if ambiguous:
                    catalog.record_blocked_process("probe", fence, ProcessIdentity("boot", 1234, 99, 1234))
                    catalog.authorize_hardware_command_release("probe", fence, "b" * 64)
                    catalog.mark_hardware_command_release_ambiguous("probe", owner, "b" * 64)
                else:
                    catalog.finish_operation(fence, "recovery_required", error_code="recovery_required")
                if phase is not None:
                    with catalog.transaction() as db:
                        db.execute("UPDATE daemon_operations SET phase=? WHERE id='blocked'", (phase,))
                original = catalog.hardware_commands_for_operation("blocked")
            coordinator = _RecordingCoordinator()
            service = DaemonService(paths, settings, backups, None,
                                    EventBus(lambda: Catalog(paths.catalog_file)),
                                    recovery_coordinator_factory=lambda operations: coordinator)
            try:
                result = service.startup()
                self.assertFalse(result.safe_for_admission)
                with Catalog(paths.catalog_file) as catalog:
                    self.assertEqual(original, catalog.hardware_commands_for_operation("blocked"))
                    self.assertEqual("recovery_required", catalog.get_operation("blocked")["state"])
                return coordinator.assessed
            finally:
                service.shutdown(0)

    def test_ambiguous_pre_media_release_is_left_for_authenticated_reset(self):
        self.assertEqual([], self._restart(ambiguous=True))

    def test_unreleased_reservation_keeps_existing_automatic_recovery(self):
        self.assertEqual(["blocked"], self._restart(ambiguous=False))

    def test_writing_recovery_keeps_existing_automatic_recovery(self):
        self.assertEqual(["blocked"], self._restart(ambiguous=True, phase="writing"))
