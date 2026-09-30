from __future__ import annotations

import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

from ltobackup.catalog import Catalog
from ltobackup.daemon.models import (
    CommandExitEvidence,
    HardwareTargetBinding,
    OperationRecord,
    ProcessIdentity,
    RecoveryCommandFence,
    critical_command_ledger_sha256,
)
from ltobackup.daemon.recovery import AggregateRecoveryProbe, RecoveryAction, RecoveryReason
from ltobackup.daemon.recovery_coordinator import ProductionRecoveryDecisionSource


class UnboundRecoveryObservationTests(unittest.TestCase):
    def _assess(self, *, phase=None, kind="archive.native", command_state=None, **probe_changes):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        database = Path(temporary.name) / "catalog.db"
        target = HardwareTargetBinding("1" * 64, "2" * 64, "3" * 64, "4" * 64)
        with Catalog(database) as catalog:
            catalog.initialize()
            catalog.add_library("LIB", "Library", temporary.name)
            catalog.create_automatic_job(
                "JOB", "LIB", "drive", "/synthetic/mount",
                [("MEDIA-1", "SERIAL-1", 1, 1)], force_format=True,
            )
            original = catalog.claim_daemon_owner("original")
            catalog.admit_operation(
                OperationRecord(
                    "operation", kind, "running", phase, "admission",
                    "admin", "JOB", 1, "2026-08-28T09:00:00+00:00", None,
                ),
                original, admission_open=True, hardware_target=target,
            )
            daemon = catalog.claim_daemon_owner("recovery")
            catalog.recover_interrupted_operations(daemon)
            if command_state is not None:
                catalog.reserve_hardware_command(
                    RecoveryCommandFence("operation", daemon.generation),
                    "probe", "identify", "5" * 64,
                )
                if command_state == "quiesced":
                    catalog.acknowledge_command_quiescence(
                        "probe", daemon,
                        CommandExitEvidence(
                            "probe", None, "launch_aborted", datetime.now(UTC).isoformat(),
                        ),
                    )
            before = catalog.get_operation("operation")
            before_commands = catalog.hardware_commands_for_operation("operation")
        probe = AggregateRecoveryProbe(**{
            "target": target,
            "observed_media_identity_sha256": None,
            "configured_mount_source_identity_sha256": target.tape_device_identity_sha256,
            "configured_mount_fstype": "fuse.ltfs",
            "mounted": False,
            "mounted_source_identity_sha256": None,
            "mounted_fstype": None,
            "media_loaded": False,
            "drive_busy": False,
            "correlated_processes": (),
            **probe_changes,
        })
        source = ProductionRecoveryDecisionSource(
            lambda: Catalog(database), daemon,
            SimpleNamespace(inspect=lambda operation, fence, catalog: probe),
        )
        assessment = source.assess("operation")
        with Catalog(database) as catalog:
            self.assertEqual(before, catalog.get_operation("operation"))
            self.assertEqual(before_commands, catalog.hardware_commands_for_operation("operation"))
            self.assertEqual(1, catalog.connection.execute("SELECT COUNT(*) FROM daemon_operations").fetchone()[0])
            for table in ("command_quiescence_receipts", "physical_reconciliation_receipts"):
                self.assertEqual(0, catalog.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            if assessment.observation is not None:
                self.assertEqual(
                    critical_command_ledger_sha256(before_commands),
                    assessment.observation.command_ledger_sha256,
                )
        self.assertFalse(assessment.decision.admission_open)
        self.assertNotIn(RecoveryAction.RETRY_CURRENT_CASSETTE, assessment.decision.actions)
        self.assertNotIn(RecoveryAction.RETRY_IDENTIFICATION, assessment.decision.actions)
        return assessment, database

    def test_unbound_preadmission_empty_observation_waits_without_auto_resume(self):
        assessment, _ = self._assess()
        self.assertIsNotNone(assessment.observation)
        self.assertIsNone(assessment.observation.bound_media_identity_sha256)
        self.assertIsNone(assessment.observation.observed_media_identity_sha256)
        self.assertFalse(assessment.observation.media_loaded)
        self.assertFalse(assessment.observation.commands_quiescent)
        self.assertEqual(RecoveryReason.WAITING_MEDIA_RETRY_SAFE, assessment.decision.reason)
        self.assertEqual((RecoveryAction.WAIT_FOR_MEDIA, RecoveryAction.HOLD_ADMISSION), assessment.decision.actions)

    def test_unbound_observation_preserves_target_mismatch_quarantine(self):
        assessment, database = self._assess(
            target=HardwareTargetBinding("9" * 64, "2" * 64, "3" * 64, "4" * 64),
        )
        self.assertIsNotNone(assessment.observation)
        self.assertEqual(RecoveryReason.TARGET_MISMATCH, assessment.decision.reason)
        self.assertEqual((RecoveryAction.ENTER_CRITICAL_QUARANTINE, RecoveryAction.HOLD_ADMISSION), assessment.decision.actions)
        with Catalog(database) as catalog:
            self.assertFalse(catalog._critical_observation_matches_current_tx(
                catalog.connection, assessment.observation,
                datetime.now(UTC).isoformat(), physical_policy="empty",
            ))

    def test_unquiesced_command_is_not_promoted_to_empty_drive_authority(self):
        assessment, database = self._assess(command_state="launch_reserved")
        self.assertIsNotNone(assessment.observation)
        self.assertFalse(assessment.observation.commands_quiescent)
        with Catalog(database) as catalog:
            self.assertFalse(catalog._critical_observation_matches_current_tx(
                catalog.connection, assessment.observation,
                datetime.now(UTC).isoformat(), physical_policy="empty",
            ))

    def test_only_catalog_empty_policy_accepts_complete_unbound_observation(self):
        assessment, database = self._assess(command_state="quiesced")
        self.assertIsNotNone(assessment.observation)
        self.assertTrue(assessment.observation.commands_quiescent)
        with Catalog(database) as catalog:
            for policy, expected in (("empty", True), ("observe", False), ("exact_loaded", False)):
                with self.subTest(policy=policy):
                    self.assertEqual(expected, catalog._critical_observation_matches_current_tx(
                        catalog.connection, assessment.observation,
                        datetime.now(UTC).isoformat(), physical_policy=policy,
                    ))

    def test_loaded_unknown_or_dangerous_phase_keeps_missing_binding_rejection(self):
        variants = (
            {"media_loaded": True, "observed_media_identity_sha256": "8" * 64},
            {"media_loaded": True},
            {"media_loaded": None},
            {"observed_media_identity_sha256": "8" * 64},
            {"phase": "identifying_media"},
            {"phase": "writing"},
            {"kind": "archive.resume"},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                assessment, _ = self._assess(**variant)
                self.assertIsNone(assessment.observation)
                self.assertEqual(RecoveryReason.DURABLE_EVIDENCE_MISSING, assessment.decision.reason)

    def test_mounted_busy_or_related_process_evidence_is_not_cleared(self):
        variants = (
            {"mounted": True, "mounted_fstype": "fuse.ltfs", "mounted_source_identity_sha256": "2" * 64},
            {"drive_busy": True},
            {"correlated_processes": (ProcessIdentity("boot", 100, 10, 100),)},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                assessment, database = self._assess(command_state="quiesced", **variant)
                self.assertIsNotNone(assessment.observation)
                for name, value in variant.items():
                    if name in {"mounted", "drive_busy"}:
                        self.assertEqual(value, getattr(assessment.observation, name))
                self.assertEqual(len(variant.get("correlated_processes", ())), assessment.observation.related_process_count)
                with Catalog(database) as catalog:
                    self.assertFalse(catalog._critical_observation_matches_current_tx(
                        catalog.connection, assessment.observation,
                        datetime.now(UTC).isoformat(), physical_policy="empty",
                    ))


if __name__ == "__main__":
    unittest.main()
