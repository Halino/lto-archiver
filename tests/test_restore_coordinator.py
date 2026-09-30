from __future__ import annotations

import hashlib
import tempfile
import time
import unittest
from concurrent.futures import Future
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon.models import (
    DaemonFence,
    HardwareTargetBinding,
    OperationFence,
    OperationRecord,
    RecoveryCommandFence,
    RecoveryEffectReceipt,
    SafeRecoveryResolution,
    VerifiedPhysicalQuiescence,
)
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.recovery import (
    AggregateRecoveryProbe,
    RecoveryAction,
    RestoreRecoveryCheckpoint,
    decide_restore_recovery,
)
from ltobackup.daemon.recovery_coordinator import ProductionRecoveryExecutor
from ltobackup.daemon.restore_coordinator import (
    ProductionRestoreRuntime,
    RestoreSequenceCoordinator,
)
from ltobackup.daemon.restore_runner import RestoreCassetteOutcome
from ltobackup.errors import CatalogError
from ltobackup.settings import Settings
from tests.test_catalog import (
    insert_quiesced_restore_no_media_probe,
    insert_quiesced_restore_unload,
    restore_release_fixture,
    seed_one_tape_two_item_restore_plan,
    seed_two_tape_restore_plan,
)


class _InlineExecutor:
    def submit(self, callback, *arguments):
        future = Future()
        try:
            future.set_result(callback(*arguments))
        except BaseException as error:  # noqa: BLE001 - preserve worker semantics.
            future.set_exception(error)
        return future


class _CheckpointRunner:
    def __init__(self, database: Path) -> None:
        self.database = database
        self.sequences: list[int] = []
        self.items_seen: list[tuple[int, int]] = []
        self.items_restored: list[tuple[int, int]] = []

    def run(self, run_id, context, stop_requested):
        sequence = context.record.cassette_sequence
        assert sequence is not None
        self.sequences.append(sequence)
        restored = 0
        restored_bytes = 0
        with Catalog(self.database) as catalog:
            run = catalog.restore_run(run_id)
            cassette = next(row for row in run["cassettes"] if row["sequence"] == sequence)
            if cassette["state"] == "waiting_media":
                catalog.transition_restore_cassette(
                    context.fence, run_id, sequence,
                    expected_state="waiting_media", new_state="restoring",
                )
            run = catalog.restore_run(run_id)
            for item in run["items"]:
                if item["cassette_sequence"] != sequence:
                    continue
                self.items_seen.append((sequence, item["sequence"]))
                if item["state"] in {"restored", "skipped_verified"}:
                    continue
                self.items_restored.append((sequence, item["sequence"]))
                if stop_requested():
                    return RestoreCassetteOutcome(
                        "recovery_required", "recovery_required", run_id,
                        sequence, restored, 0, restored_bytes,
                    )
                if item["state"] == "pending":
                    catalog.transition_restore_item(
                        context.fence, run_id, item["sequence"],
                        expected_state="pending", new_state="restoring",
                        bytes_copied=0, observed_sha256=None,
                    )
                catalog.transition_restore_item(
                    context.fence, run_id, item["sequence"],
                    expected_state="restoring", new_state="restored",
                    bytes_copied=item["plan_item"]["size"],
                    observed_sha256=item["plan_item"]["sha256"],
                )
                restored += 1
                restored_bytes += item["plan_item"]["size"]
            catalog.transition_restore_cassette(
                context.fence, run_id, sequence,
                expected_state="restoring", new_state="completed",
            )
            after = catalog.restore_run(run_id)
        return RestoreCassetteOutcome(
            "succeeded",
            "completed" if after["state"] == "completed" else "waiting_media",
            run_id, sequence, restored, 0, restored_bytes,
        )


class ProductionRestoreIdentityTests(unittest.TestCase):
    def test_legacy_ltfs_uuid_stored_as_volume_serial_is_normalized(self) -> None:
        legacy_uuid = "bea8bf77-bbce-45f0-84ef-87ca286ceb50"

        expected = ProductionRestoreRuntime._expected(
            {"id": "RESTORE-RUN-1"},
            {
                "sequence": 1,
                "physical_label": "TAPE01",
                "volume_serial": legacy_uuid,
                "volume_uuid": None,
            },
        )

        self.assertIsNone(expected.volume_serial)
        self.assertEqual(legacy_uuid, expected.volume_uuid)
        self.assertEqual("TAPE01", expected.volume_label)

    def test_distinct_mam_serial_and_ltfs_uuid_are_preserved(self) -> None:
        expected = ProductionRestoreRuntime._expected(
            {"id": "RESTORE-RUN-1"},
            {
                "sequence": 1,
                "physical_label": "TAPE01",
                "volume_serial": "MAM-SERIAL-001",
                "volume_uuid": "bea8bf77-bbce-45f0-84ef-87ca286ceb50",
            },
        )

        self.assertEqual("MAM-SERIAL-001", expected.volume_serial)
        self.assertEqual(
            "bea8bf77-bbce-45f0-84ef-87ca286ceb50", expected.volume_uuid
        )

    def test_non_uuid_oversized_legacy_serial_still_fails_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected tape serial is invalid"):
            ProductionRestoreRuntime._expected(
                {"id": "RESTORE-RUN-1"},
                {
                    "sequence": 1,
                    "physical_label": "TAPE01",
                    "volume_serial": "X" * 36,
                    "volume_uuid": None,
                },
            )


class RestoreSequenceCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "catalog.db"
        with Catalog(self.database) as catalog:
            catalog.initialize()
            catalog.import_application_settings_once(Settings(), legacy_source_sha256=None)
            plan = seed_two_tape_restore_plan(catalog)
            self.run = catalog.create_restore_run(
                str(plan["id"]), actor="operator-1",
                idempotency_key="restore-run", request_sha256="a" * 64,
            )
            self.owner = catalog.claim_daemon_owner("restore-daemon")
        self.runner = _CheckpointRunner(self.database)
        self.operations = OperationManager(
            lambda: Catalog(self.database), self.owner, executor=_InlineExecutor()
        )
        self.coordinator = RestoreSequenceCoordinator(
            lambda: Catalog(self.database),
            operations=self.operations,
            runner=self.runner,
            hardware_target=self._target,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(lambda: self.coordinator.stop(1.0))

    def _target(self, run, cassette):
        return HardwareTargetBinding.from_verified_inputs(
            self.root / "mount", "tape", "scsi",
            (
                "restore.cassette", run["id"], str(cassette["sequence"]),
                cassette["physical_label"], cassette["volume_serial"],
                cassette["volume_uuid"] or "",
            ),
        )

    def _wait_for_state(self, expected: str) -> dict[str, object]:
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with Catalog(self.database) as catalog:
                run = catalog.restore_run(str(self.run["id"]))
            if run["state"] == expected:
                return run
            time.sleep(0.01)
        self.fail(f"restore run did not reach {expected}")

    def test_success_automatically_admits_the_next_cassette_once(self) -> None:
        self.coordinator.start()

        completed = self._wait_for_state("completed")

        self.assertEqual([1, 2], self.runner.sequences)
        self.assertEqual("TAPE02", completed["cassettes"][1]["physical_label"])
        with Catalog(self.database) as catalog:
            rows = catalog.connection.execute(
                "SELECT cassette_sequence,idempotency_key FROM daemon_operations "
                "WHERE kind='restore.cassette' ORDER BY cassette_sequence"
            ).fetchall()
        self.assertEqual([1, 2], [row["cassette_sequence"] for row in rows])
        self.assertEqual(
            hashlib.sha256(
                f"restore.cassette\0{self.run['id']}\0{1}\0{1}".encode()
            ).hexdigest(),
            rows[0]["idempotency_key"],
        )

    def test_duplicate_wakes_replay_no_second_attempt(self) -> None:
        self.coordinator.start()
        self._wait_for_state("completed")

        self.coordinator.wake()
        self.coordinator.wake()
        time.sleep(0.05)

        with Catalog(self.database) as catalog:
            count = catalog.connection.execute(
                "SELECT COUNT(*) FROM daemon_operations WHERE kind='restore.cassette'"
            ).fetchone()[0]
        self.assertEqual(2, count)

    def test_cancel_waiting_run_is_durable_and_preserves_item_evidence(self) -> None:
        cancelled = self.coordinator.request_cancel(str(self.run["id"]), "operator-2")

        self.assertEqual("cancelled", cancelled["state"])
        self.assertEqual(["pending", "pending"], [item["state"] for item in cancelled["items"]])
        with Catalog(self.database) as catalog:
            audit = catalog.connection.execute(
                "SELECT principal FROM audit_entries WHERE action='restore.run.cancel'"
            ).fetchone()
        self.assertEqual("operator-2", audit["principal"])

    def test_restore_controls_replay_the_durable_response_for_one_key(self) -> None:
        paused = self.coordinator.request_pause(
            str(self.run["id"]), "operator-2", "pause-response-loss"
        )
        replay = self.coordinator.request_pause(
            str(self.run["id"]), "operator-2", "pause-response-loss"
        )

        self.assertEqual(paused, replay)
        self.assertEqual("paused", replay["state"])

    def test_restore_control_response_loss_replay_and_collision(self) -> None:
        paused = self.coordinator.request_pause(str(self.run["id"]), "operator-2", "control-key")
        self.assertEqual(paused, self.coordinator.request_pause(str(self.run["id"]), "operator-2", "control-key"))
        with self.assertRaises(CatalogError):
            self.coordinator.resume(str(self.run["id"]), "operator-2", "control-key")

    def test_pause_noop_with_new_key_reserves_that_key_for_pause(self) -> None:
        """An accepted no-op pause is still an idempotent control receipt."""

        paused = self.coordinator.request_pause(
            str(self.run["id"]), "operator-2", "pause-key-a"
        )
        repeated_pause = self.coordinator.request_pause(
            str(self.run["id"]), "operator-2", "pause-key-b"
        )

        self.assertEqual(paused, repeated_pause)
        with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
            self.coordinator.resume(
                str(self.run["id"]), "operator-2", "pause-key-b"
            )

    def test_failed_worker_callback_cannot_terminalize_pending_cancel(self) -> None:
        record = OperationRecord(
            "restore-failed-operation", "restore.cassette", "running", None,
            "restore-failed-key", "restore-coordinator", str(self.run["id"]), 1,
            "2026-09-01T07:00:00+00:00", None,
        )
        with Catalog(self.database) as catalog:
            catalog.admit_operation(
                record,
                self.owner,
                admission_open=True,
                hardware_target=self._target(self.run, self.run["cassettes"][0]),
            )
            fence = OperationFence(record.id, self.owner.generation)
            catalog.transition_restore_cassette(
                fence,
                str(self.run["id"]),
                1,
                expected_state="waiting_media",
                new_state="restoring",
            )
            catalog.request_restore_run_cancel(
                str(self.run["id"]), actor="operator-2"
            )
            catalog.finish_operation(
                fence,
                "failed",
                error_class="terminal_safety_failure",
                error_code="operation_failed",
            )

        self.coordinator._operation_complete(record)

        with Catalog(self.database) as catalog:
            after = catalog.restore_run(str(self.run["id"]))
        self.assertNotEqual("cancelled", after["state"])

    def test_repeated_cancel_after_failed_admission_needs_release_evidence(self) -> None:
        record = OperationRecord(
            "restore-failed-operation", "restore.cassette", "running", None,
            "restore-failed-key", "restore-coordinator", str(self.run["id"]), 1,
            "2026-09-01T07:00:00+00:00", None,
        )
        with Catalog(self.database) as catalog:
            catalog.admit_operation(
                record,
                self.owner,
                admission_open=True,
                hardware_target=self._target(self.run, self.run["cassettes"][0]),
            )
            fence = OperationFence(record.id, self.owner.generation)
            catalog.transition_restore_cassette(
                fence,
                str(self.run["id"]),
                1,
                expected_state="waiting_media",
                new_state="restoring",
            )

            first = catalog.request_restore_run_cancel(
                str(self.run["id"]), actor="operator-2"
            )
            catalog.finish_operation(
                fence,
                "failed",
                error_class="terminal_safety_failure",
                error_code="operation_failed",
            )
            second = catalog.request_restore_run_cancel(
                str(self.run["id"]), actor="operator-2"
            )

            operation = catalog.get_operation(record.id)
            release_count = catalog.connection.execute(
                "SELECT COUNT(*) FROM restore_release_receipts "
                "WHERE operation_id=?",
                (record.id,),
            ).fetchone()[0]
            audit_count = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries "
                "WHERE action='restore.run.cancel' "
                "AND json_extract(payload_json,'$.run_id')=?",
                (str(self.run["id"]),),
            ).fetchone()[0]

        self.assertNotEqual("cancelled", first["state"])
        self.assertNotEqual("cancelled", second["state"])
        self.assertEqual("failed", operation["state"])
        self.assertEqual(0, release_count)
        self.assertEqual(1, audit_count)

    def test_cancel_checkpoint_is_exact_and_preserves_completed_file_evidence(self) -> None:
        record = OperationRecord(
            "restore-cancel-operation", "restore.cassette", "running", None,
            "restore-cancel-key", "restore-coordinator", str(self.run["id"]), 1,
            "2026-09-01T07:00:00+00:00", None,
        )
        with Catalog(self.database) as catalog:
            catalog.admit_operation(
                record, self.owner, admission_open=True,
                hardware_target=self._target(self.run, self.run["cassettes"][0]),
            )
            fence = OperationFence(record.id, self.owner.generation)
            catalog.transition_restore_cassette(
                fence, str(self.run["id"]), 1,
                expected_state="waiting_media", new_state="restoring",
            )
            item = catalog.restore_run(str(self.run["id"]))["items"][0]
            catalog.transition_restore_item(
                fence, str(self.run["id"]), 1,
                expected_state="pending", new_state="restoring",
                bytes_copied=0, observed_sha256=None,
            )
            catalog.transition_restore_item(
                fence, str(self.run["id"]), 1,
                expected_state="restoring", new_state="restored",
                bytes_copied=item["plan_item"]["size"],
                observed_sha256=item["plan_item"]["sha256"],
            )
            before = catalog.restore_run(str(self.run["id"]))
            catalog.request_restore_run_cancel(
                str(self.run["id"]), actor="operator-2"
            )

            with self.assertRaises(CatalogError):
                catalog.checkpoint_restore_run_control(
                    fence, str(self.run["id"]), 1
                )
            after = catalog.restore_run(str(self.run["id"]))
            operation = catalog.get_operation(record.id)

        self.assertNotEqual("cancelled", after["state"])
        self.assertEqual("restored", after["items"][0]["state"])
        self.assertEqual("pending", after["items"][1]["state"])
        self.assertEqual(before["plan_fingerprint_sha256"], after["plan_fingerprint_sha256"])
        self.assertEqual("running", operation["state"])

    def test_pause_waiting_run_blocks_admission_until_exact_resume(self) -> None:
        paused = self.coordinator.request_pause(str(self.run["id"]), "operator-2")

        self.assertEqual("paused", paused["state"])
        self.assertIsNone(self.coordinator.reconcile_once())
        with Catalog(self.database) as catalog:
            audit = catalog.connection.execute(
                "SELECT principal FROM audit_entries "
                "WHERE action='restore.run.pause' ORDER BY id DESC LIMIT 1"
            ).fetchone()
        self.assertEqual("operator-2", audit["principal"])

        resumed = self.coordinator.resume(str(self.run["id"]), "operator-3")

        self.assertEqual("waiting_media", resumed["state"])
        self.coordinator.start()
        self._wait_for_state("completed")

    def test_resumed_active_pause_is_not_reported_as_recovery_replacement(self) -> None:
        replacement_admissions: list[tuple[str, int, str]] = []
        with Catalog(self.database) as catalog:
            record = OperationRecord(
                "restore-paused-operation", "restore.cassette", "running", None,
                "restore-paused-key", "restore-coordinator", str(self.run["id"]), 1,
                "2026-09-01T07:00:00+00:00", None,
            )
            catalog.admit_operation(
                record,
                self.owner,
                admission_open=True,
                hardware_target=self._target(self.run, self.run["cassettes"][0]),
            )
            fence = OperationFence(record.id, self.owner.generation)
            catalog.request_restore_run_pause(
                str(self.run["id"]), actor="operator-2"
            )
            catalog.checkpoint_restore_control_before_mount(
                fence, str(self.run["id"]), 1
            )
            catalog.resume_restore_run(str(self.run["id"]), actor="operator-3")
            candidate = catalog.next_restore_sequence_candidate()
        assert candidate is not None
        self.assertEqual(2, candidate["attempt_number"])
        self.assertEqual("paused_resume", candidate["continuation_kind"])

        def prepare_replacement(run_id, cassette_sequence):
            return lambda admitted: replacement_admissions.append(
                (run_id, cassette_sequence, admitted.id)
            )

        coordinator = RestoreSequenceCoordinator(
            lambda: Catalog(self.database),
            operations=self.operations,
            runner=self.runner,
            hardware_target=self._target,
            prepare_replacement_admission=prepare_replacement,
            poll_interval_seconds=0.01,
        )

        admitted = coordinator.reconcile_once()

        self.assertIsNotNone(admitted)
        self.assertEqual([], replacement_admissions)

    def test_ordinary_resume_cannot_bypass_recovery_required(self) -> None:
        with Catalog(self.database) as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE restore_runs SET state='recovery_required',"
                "last_error_code='destination_conflict' WHERE id=?",
                (self.run["id"],),
            )
            db.execute(
                "UPDATE restore_run_cassettes SET state='recovery_required',"
                "last_error_code='destination_conflict' "
                "WHERE run_id=? AND sequence=1",
                (self.run["id"],),
            )

        with self.assertRaisesRegex(CatalogError, "restore resume state conflict"):
            self.coordinator.resume(str(self.run["id"]), "operator-2")

        with Catalog(self.database) as catalog:
            blocked = catalog.restore_run(str(self.run["id"]))
        self.assertEqual("recovery_required", blocked["state"])

    def test_restart_retries_only_first_incomplete_item_and_keeps_plan_fingerprint(self) -> None:
        database = self.root / "restart.db"
        with Catalog(database) as catalog:
            catalog.initialize()
            catalog.import_application_settings_once(Settings(), legacy_source_sha256=None)
            plan = seed_one_tape_two_item_restore_plan(catalog)
            run = catalog.create_restore_run(
                str(plan["id"]), actor="operator-1",
                idempotency_key="restart-run", request_sha256="b" * 64,
            )
            original_fingerprint = run["plan_fingerprint_sha256"]
            original = catalog.claim_daemon_owner("restore-before-crash")
            record = OperationRecord(
                "restore-before-crash-operation", "restore.cassette", "running",
                None, "restore-before-crash-key", "restore-coordinator",
                str(run["id"]), 1, "2026-09-01T07:00:00+00:00", None,
            )
            catalog.admit_operation(
                record, original, admission_open=True,
                hardware_target=self._target(run, run["cassettes"][0]),
            )
            fence = OperationFence(record.id, original.generation)
            catalog.transition_restore_cassette(
                fence, str(run["id"]), 1,
                expected_state="waiting_media", new_state="restoring",
            )
            for item_sequence in (1, 2):
                catalog.transition_restore_item(
                    fence, str(run["id"]), item_sequence,
                    expected_state="pending", new_state="restoring",
                    bytes_copied=0, observed_sha256=None,
                )
                if item_sequence == 1:
                    item = catalog.restore_run(str(run["id"]))["items"][0]
                    catalog.transition_restore_item(
                        fence, str(run["id"]), 1,
                        expected_state="restoring", new_state="restored",
                        bytes_copied=item["plan_item"]["size"],
                        observed_sha256=item["plan_item"]["sha256"],
                    )
            target = self._target(run, run["cassettes"][0])
            insert_quiesced_restore_unload(
                catalog, record.id, original.generation, target
            )
            insert_quiesced_restore_no_media_probe(
                catalog, record.id, original.generation, target
            )
            mounted, unmount = restore_release_fixture(
                record.id,
                original.generation,
                mount_path=self.root / "mount",
                volume_label=str(run["cassettes"][0]["volume_label"]),
            )
            catalog.record_restore_post_eject_receipt(
                fence,
                str(run["id"]),
                1,
                mounted,
                unmount,
                no_media_proven=True,
            )
            recovered_owner = catalog.claim_daemon_owner("restore-after-crash")
            blockers = catalog.recover_interrupted_operations(recovered_owner)
            self.assertEqual((record.id,), tuple(item.id for item in blockers))
            commands = catalog.create_command_quiescence_receipt(
                record.id, recovered_owner
            )
            physical = catalog.create_physical_reconciliation_receipt(
                record.id,
                recovered_owner,
                commands.id,
                VerifiedPhysicalQuiescence(
                    target=self._target(run, run["cassettes"][0]),
                    observed_media_identity_sha256=None,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
            catalog.resolve_restore_recovery_boundary(
                record.id,
                str(run["id"]),
                1,
                str(original_fingerprint),
                recovered_owner,
                SafeRecoveryResolution(
                    "restore_restart_safe", commands.id, physical.id
                ),
                action="retry",
            )

        runner = _CheckpointRunner(database)
        operations = OperationManager(
            lambda: Catalog(database), recovered_owner, executor=_InlineExecutor()
        )
        replacement_admissions: list[tuple[str, int, str]] = []

        def prepare_replacement(run_id, cassette_sequence):
            return lambda record: replacement_admissions.append(
                (run_id, cassette_sequence, record.id)
            )

        coordinator = RestoreSequenceCoordinator(
            lambda: Catalog(database), operations=operations, runner=runner,
            hardware_target=self._target,
            prepare_replacement_admission=prepare_replacement,
            poll_interval_seconds=0.01,
        )
        self.addCleanup(lambda: coordinator.stop(1.0))
        coordinator.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            with Catalog(database) as catalog:
                after = catalog.restore_run(str(run["id"]))
            if after["state"] == "completed":
                break
            time.sleep(0.01)
        else:
            self.fail("restarted restore did not complete")

        self.assertEqual([(1, 2)], runner.items_restored)
        self.assertEqual(original_fingerprint, after["plan_fingerprint_sha256"])
        self.assertEqual(1, len(replacement_admissions))
        self.assertEqual(
            (str(run["id"]), 1), replacement_admissions[0][:2]
        )


class RestoreRecoveryDecisionTests(unittest.TestCase):
    @staticmethod
    def probe(*, mounted: bool, loaded: bool) -> AggregateRecoveryProbe:
        target = HardwareTargetBinding("1" * 64, "2" * 64, "3" * 64, "4" * 64)
        return AggregateRecoveryProbe(
            target=target,
            observed_media_identity_sha256=None,
            configured_mount_source_identity_sha256="2" * 64,
            configured_mount_fstype="fuse.ltfs",
            mounted=mounted,
            mounted_source_identity_sha256="2" * 64 if mounted else None,
            mounted_fstype="fuse.ltfs" if mounted else None,
            media_loaded=loaded,
            drive_busy=False,
            correlated_processes=(),
        )

    def test_ambiguous_mount_or_unload_blocks_but_proven_eject_prepares_retry(self) -> None:
        checkpoint = RestoreRecoveryCheckpoint(
            run_id="RESTORE-RUN-1", cassette_sequence=1,
            plan_fingerprint_sha256="a" * 64,
            first_incomplete_item_sequence=2,
            conflict_state=None,
            release_boundary="post_eject",
        )

        mounted = decide_restore_recovery(checkpoint, self.probe(mounted=True, loaded=True))
        loaded = decide_restore_recovery(checkpoint, self.probe(mounted=False, loaded=True))
        safe = decide_restore_recovery(checkpoint, self.probe(mounted=False, loaded=False))

        self.assertEqual(RecoveryAction.ENTER_CRITICAL_QUARANTINE, mounted.actions[0])
        self.assertEqual(RecoveryAction.ENTER_CRITICAL_QUARANTINE, loaded.actions[0])
        self.assertEqual(RecoveryAction.PREPARE_RESTORE_RETRY, safe.actions[0])

    def test_destination_conflict_needs_exact_authority_before_replacement_prepare(self) -> None:
        blocked = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, 2, "recorded",
            release_boundary="post_eject",
        )
        authorized = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, 2, "authorized",
            release_boundary="post_eject",
        )

        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            decide_restore_recovery(blocked, self.probe(mounted=False, loaded=False)).actions[0],
        )
        self.assertEqual(
            RecoveryAction.PREPARE_RESTORE_RETRY,
            decide_restore_recovery(authorized, self.probe(mounted=False, loaded=False)).actions[0],
        )

    def test_restore_receipt_chain_controls_retry_commit_and_pending_control(self) -> None:
        missing = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, 2, None,
            release_boundary="missing", pending_control=None,
        )
        incomplete = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, 2, None,
            release_boundary="post_eject", pending_control=None,
        )
        complete = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, None, None,
            release_boundary="post_eject", pending_control=None,
        )
        cancelled = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, 2, None,
            release_boundary="post_eject", pending_control="cancelled",
        )
        clean = self.probe(mounted=False, loaded=False)

        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            decide_restore_recovery(missing, clean).actions[0],
        )
        self.assertEqual(
            RecoveryAction.PREPARE_RESTORE_RETRY,
            decide_restore_recovery(incomplete, clean).actions[0],
        )
        self.assertEqual(
            RecoveryAction.RECONCILE_RESTORE_COMMIT,
            decide_restore_recovery(complete, clean).actions[0],
        )
        self.assertEqual(
            RecoveryAction.FINALIZE_RESTORE_CONTROL,
            decide_restore_recovery(cancelled, clean).actions[0],
        )

    def test_proven_pre_mount_failure_prepares_retry_only_after_eject(self) -> None:
        checkpoint = RestoreRecoveryCheckpoint(
            "RESTORE-RUN-1", 1, "a" * 64, 1, None,
            release_boundary="missing", pending_control=None,
            pre_mount_recoverable=True,
        )

        loaded = decide_restore_recovery(
            checkpoint, self.probe(mounted=False, loaded=True)
        )
        ejected = decide_restore_recovery(
            checkpoint, self.probe(mounted=False, loaded=False)
        )

        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE, loaded.actions[0]
        )
        self.assertEqual(RecoveryAction.PREPARE_RESTORE_RETRY, ejected.actions[0])

    def test_recovery_executor_dispatches_only_the_restore_prepare_effect(self) -> None:
        calls = []

        class FenceCatalog:
            def __enter__(catalog_self):
                return catalog_self

            def __exit__(catalog_self, *_args):
                return None

            def current_daemon_fence(catalog_self):
                return DaemonFence("restore-daemon", 4)

            def assert_command_fence(catalog_self, received):
                self.assertEqual(fence, received)

        blocker = OperationRecord(
            "restore-operation-1", "restore.cassette", "recovery_required",
            None, "restore-key-1", "restore-coordinator", "RESTORE-RUN-1", 1,
            "2026-09-01T07:00:00+00:00", None,
        )
        fence = RecoveryCommandFence(blocker.id, 4)

        def prepare(received, received_fence):
            calls.append((received.id, received_fence.owner_generation))
            return RecoveryEffectReceipt(
                "prepare_restore_retry", received.id,
                received_fence.owner_generation, "resolved-restore-boundary",
            )

        executor = ProductionRecoveryExecutor(
            FenceCatalog,
            observe_command=lambda *_args: None,
            reconcile_commit=lambda *_args: None,
            retry_identification=lambda *_args: None,
            retry_unload=lambda *_args: None,
            safe_release=lambda *_args: None,
            prepare_restore_retry=prepare,
        )

        receipt = executor.prepare_restore_retry(blocker, fence)

        self.assertEqual([("restore-operation-1", 4)], calls)
        self.assertEqual("resolved-restore-boundary", receipt.proof)

    def test_pre_mount_control_rebuilds_missing_receipt_before_resolution(self) -> None:
        target = HardwareTargetBinding("1" * 64, "2" * 64, "3" * 64, "4" * 64)
        observed_media = "5" * 64
        daemon = DaemonFence("restore-daemon", 4)
        calls: list[str] = []

        class FakeCatalog:
            def __enter__(catalog_self):
                return catalog_self

            def __exit__(catalog_self, *_args):
                return None

            def hardware_target_binding(catalog_self, _operation_id):
                return target

            def get_operation(catalog_self, _operation_id):
                return {
                    "id": "restore-operation-1",
                    "state": "recovery_required",
                    "phase": None,
                    "owner_generation": 3,
                    "cassette_sequence": 1,
                    "error_code": "media_identity_mismatch",
                    "started_at": "2026-09-01T07:00:00+00:00",
                    "kind": "restore.cassette",
                }

            def media_identity_binding_evidence(catalog_self, _operation_id):
                return {
                    "observed_media_identity_sha256": observed_media,
                    "bound_by_command_id": "identify-1",
                    "bound_at": "2026-09-01T07:01:00+00:00",
                }

            def current_daemon_fence(catalog_self):
                return daemon

            def restore_run(catalog_self, _run_id):
                return {"plan_fingerprint_sha256": "a" * 64}

            def restore_release_boundary(catalog_self, *_args):
                return "missing"

            def record_restore_pre_mount_recovery_receipt(catalog_self, *_args):
                calls.append("pre_mount_receipt")

            def create_physical_reconciliation_receipt(
                catalog_self, _operation_id, _daemon, _command, evidence
            ):
                self.assertEqual(
                    observed_media, evidence.observed_media_identity_sha256
                )
                calls.append("physical_receipt")
                return SimpleNamespace(id="physical-1")

            def resolve_restore_recovery_boundary(catalog_self, *_args, **kwargs):
                self.assertEqual("control", kwargs["action"])
                calls.append("resolve_control")

        class Supervisor:
            @staticmethod
            def reconcile(_operation_id, _daemon):
                calls.append("command_receipt")
                return SimpleNamespace(id="command-1")

        runtime = object.__new__(ProductionRestoreRuntime)
        runtime._catalog_factory = FakeCatalog  # type: ignore[attr-defined]
        runtime._operations = SimpleNamespace(daemon_fence=daemon)  # type: ignore[attr-defined]
        runtime._archive = SimpleNamespace(  # type: ignore[attr-defined]
            _scope_manager=None, _privilege_boundary=None
        )
        runtime.inspect = lambda *_args: self.probe(  # type: ignore[method-assign]
            mounted=False, loaded=False
        )
        blocker = OperationRecord(
            "restore-operation-1", "restore.cassette", "recovery_required",
            None, "restore-key-1", "restore-coordinator", "RESTORE-RUN-1", 1,
            "2026-09-01T07:00:00+00:00", None,
        )

        with patch(
            "ltobackup.daemon.restore_coordinator._production_supervisor",
            return_value=Supervisor(),
        ):
            receipt = runtime._resolve_restore_boundary(
                blocker,
                RecoveryCommandFence(blocker.id, 4),
                "control",
                RecoveryAction.FINALIZE_RESTORE_CONTROL,
            )

        self.assertEqual(
            [
                "pre_mount_receipt", "command_receipt", "physical_receipt",
                "resolve_control",
            ],
            calls,
        )
        self.assertEqual("physical-1", receipt.proof)


if __name__ == "__main__":
    unittest.main()
