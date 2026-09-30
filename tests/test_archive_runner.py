from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import threading
import unittest
from concurrent.futures import Future
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import call as mock_call
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon.archive_runner import (
    ArchiveRunner,
    prepare_automatic_cassette_retry,
)
from ltobackup.daemon.archive_runtime import (
    BrokeredLtfsInfoMediaIdentityProbe,
    ProductionArchiveResume,
    ProductionRecoveryRuntime,
    load_broker_capability,
)
from ltobackup.daemon.frozen_job import FrozenCassette, FrozenItem, FrozenJobPlan
from ltobackup.daemon.models import (
    CriticalRecoveryObservation,
    DaemonFence,
    HardwareTargetBinding,
    OperationConflict,
    OperationFence,
    OperationRecord,
    RecoveryCommandFence,
    StaleOperationFence,
    VerifiedPhysicalQuiescence,
    critical_command_ledger_sha256,
)
from ltobackup.daemon.operations import OperationContext, OperationManager
from ltobackup.daemon.recovery import RecoveryAction
from ltobackup.daemon.recovery_coordinator import (
    CriticalRecoveryError,
    ProductionRecoveryDecisionSource,
    ProductionRecoveryExecutor,
)
from ltobackup.daemon.service import DaemonService
from ltobackup.errors import CatalogError, ValidationError
from ltobackup.linux_settings import LinuxSettings
from ltobackup.operational_log import OperationalEvent
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupExecutionScopeManager,
    CommandFailed,
    CompletedCommand,
    ForkExecCommandLauncher,
    LinuxProcessProbe,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsStandaloneReceipt,
    PosixProcessTerminator,
    ReadOnlyCgroupPrivilegeBoundary,
    TrackedCommandSupervisor,
)
from ltobackup.tape.copier import CopyResult
from ltobackup.tape.linux_ltfs import MediaProbeUnavailable
from ltobackup.tape.models import (
    ExpectedMedia,
    MountedTape,
    UnmountResult,
)


class _Fault(RuntimeError):
    pass


class RestoreReplacementTelemetryBoundaryTests(unittest.TestCase):
    def test_restore_replacement_baseline_precedes_published_operation_id(self):
        service = DaemonService.__new__(DaemonService)
        service._diagnostics = SimpleNamespace(
            committed_checkpoint=lambda: (7, 1234, 9)
        )
        service._current_progress_baseline = None
        service._current_operation_id = None
        callback = service.prepare_restore_replacement_admission(
            "RESTORE-RUN-1", 2
        )
        record = OperationRecord(
            "restore-operation-2", "restore.cassette", "running", None,
            "restore-key-2", "restore-coordinator", "RESTORE-RUN-1", 2,
            "2026-09-01T08:00:00+00:00", None,
        )

        callback(record)

        self.assertEqual(
            ("restore-operation-2", 7, 1234, 9),
            service._current_progress_baseline,
        )
        self.assertEqual("restore-operation-2", service._current_operation_id)

    def test_restore_replacement_callback_rejects_mismatched_binding(self):
        service = DaemonService.__new__(DaemonService)
        service._diagnostics = SimpleNamespace(
            committed_checkpoint=lambda: (0, 0, 0)
        )
        callback = service.prepare_restore_replacement_admission(
            "RESTORE-RUN-1", 2
        )
        mismatch = OperationRecord(
            "restore-operation-2", "restore.cassette", "running", None,
            "restore-key-2", "restore-coordinator", "RESTORE-RUN-OTHER", 2,
            "2026-09-01T08:00:00+00:00", None,
        )

        with self.assertRaisesRegex(RuntimeError, "binding"):
            callback(mismatch)


class _InlineOperationExecutor:
    def submit(self, callback, *arguments):
        future = Future()
        try:
            future.set_result(callback(*arguments))
        except BaseException as error:  # noqa: BLE001 - preserve worker semantics.
            future.set_exception(error)
        return future


class AutomaticCassetteRetryBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "catalog.db"

    @staticmethod
    def target(root: Path) -> HardwareTargetBinding:
        return HardwareTargetBinding.from_verified_inputs(
            root / "mount",
            "tape-by-id",
            "scsi-by-id",
            ("archive.native", "JOB-1", "1", "TAPE01", "", ""),
        )

    @staticmethod
    def snapshot_current_restore_plan(
        catalog: Catalog, key: str
    ) -> dict[str, object]:
        version_id = int(
            catalog.connection.execute(
                "SELECT id FROM file_versions WHERE block_id='block-current'"
            ).fetchone()[0]
        )
        return catalog.create_restore_plan(
            (version_id,),
            "/srv/restore",
            actor="admin",
            idempotency_key=key,
            request_sha256=hashlib.sha256(key.encode("ascii")).hexdigest(),
        )

    @staticmethod
    def convert_restore_plan_to_legacy_coalesced_schema(
        catalog: Catalog, plan_id: str, key: str
    ) -> None:
        catalog.connection.executescript(
            """
            DROP TRIGGER restore_plan_cassettes_immutable_update;
            DROP TRIGGER restore_plan_items_immutable_update;
            DROP TRIGGER restore_plan_items_immutable_delete;
            UPDATE restore_plan_cassettes SET physical_label=cassette_number;
            UPDATE restore_plan_items SET physical_label=cassette_number;
            ALTER TABLE restore_plan_items RENAME TO restore_plan_items_snapshot;
            CREATE TABLE restore_plan_items (
                plan_id TEXT NOT NULL
                    REFERENCES restore_plans(id) ON DELETE RESTRICT,
                sequence INTEGER NOT NULL CHECK(sequence BETWEEN 1 AND 200),
                file_version_id INTEGER NOT NULL REFERENCES file_versions(id),
                library_id TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                tape_relative_path TEXT NOT NULL,
                tape_id TEXT NOT NULL,
                cassette_number TEXT NOT NULL,
                physical_label TEXT,
                size INTEGER NOT NULL CHECK(size>=0),
                sha256 TEXT NOT NULL CHECK(length(sha256)=64),
                copied_at TEXT NOT NULL,
                PRIMARY KEY(plan_id,sequence),
                UNIQUE(plan_id,file_version_id)
            );
            INSERT INTO restore_plan_items(
                plan_id,sequence,file_version_id,library_id,relative_path,
                tape_relative_path,tape_id,cassette_number,physical_label,
                size,sha256,copied_at
            )
            SELECT plan_id,sequence,file_version_id,library_id,relative_path,
                tape_relative_path,tape_id,cassette_number,physical_label,
                size,sha256,copied_at
            FROM restore_plan_items_snapshot;
            DROP TABLE restore_plan_items_snapshot;
            """
        )
        coalesced = catalog.get_restore_plan(plan_id)
        catalog.connection.execute(
            "UPDATE management_idempotency SET response_json=? "
            "WHERE actor='admin' AND idempotency_key=?",
            (
                json.dumps(
                    coalesced,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                key,
            ),
        )
        catalog.connection.commit()

    def prepare(
        self,
        operation: str,
        *,
        format_confirmation: bool,
        old_completed_block: bool = False,
        current_provisional_block: bool = False,
        current_provisional_file: bool = False,
        current_completed_block: bool = False,
        unlinked_provisional_block: bool = False,
        extension_layout: bool = False,
        sequence_authorization: bool = False,
    ) -> tuple[RecoveryCommandFence, tuple[tuple[object, ...], ...]]:
        target = self.target(Path(self.temporary.name))
        payload = Path(self.temporary.name) / "payload.bin"
        payload.write_bytes(b"x")
        with Catalog(self.database) as catalog:
            catalog.initialize()
            catalog.add_library("LIB-1", "Library", self.temporary.name)
            catalog.create_automatic_job(
                "JOB-1",
                "LIB-1",
                "drive",
                str(Path(self.temporary.name) / "mount"),
                [("TAPE01", "SERIAL-1", 1, 1)],
                force_format=True,
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB-1",
                1,
                [("LIB-1", payload.name, 1, payload.stat().st_mtime_ns)],
            )
            authorization_id = None
            if sequence_authorization:
                epoch = catalog.latest_layout_epoch("JOB-1")
                authorization_id = "a" * 64
                catalog.connection.execute(
                    "INSERT INTO automatic_sequence_state("
                    "job_id,state,layout_epoch,layout_fingerprint_sha256,revision,"
                    "enabled_by,enabled_at,updated_at) "
                    "VALUES(?,'disabled',?,?,1,NULL,NULL,?)",
                    (
                        "JOB-1",
                        epoch["epoch_number"],
                        epoch["layout_fingerprint_sha256"],
                        "2026-08-30T10:00:00+00:00",
                    ),
                )
                catalog.connection.execute(
                    "INSERT INTO automatic_format_authorizations("
                    "authorization_id,job_id,cassette_sequence,layout_epoch,"
                    "layout_fingerprint_sha256,expected_label,expected_operation,"
                    "reuse_registered,authorized_by,authorized_at,request_sha256) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        authorization_id,
                        "JOB-1",
                        1,
                        epoch["epoch_number"],
                        epoch["layout_fingerprint_sha256"],
                        "TAPE01",
                        "format",
                        0,
                        "authorizer",
                        "2026-08-30T10:00:00+00:00",
                        "b" * 64,
                    ),
                )
            if any(
                (
                    old_completed_block,
                    current_provisional_block,
                    current_provisional_file,
                    current_completed_block,
                    unlinked_provisional_block,
                )
            ):
                catalog.register_tape(
                    "TAPE01", "SERIAL-1", "TAPE01", "LTFS", "/tape"
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET tape_id='TAPE01' "
                    "WHERE job_id='JOB-1' AND sequence=1"
                )
            if old_completed_block:
                catalog.create_block(
                    "block-completed",
                    "LIB-1",
                    "TAPE01",
                    "blocks/completed",
                    1,
                    1,
                )
                catalog.complete_block("block-completed")
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET block_id='block-completed' "
                    "WHERE job_id='JOB-1' AND sequence=1"
                )
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET operation=?,status='writing' "
                "WHERE job_id='JOB-1' AND sequence=1",
                (operation,),
            )
            if extension_layout:
                catalog._insert_layout_epoch_tx(
                    catalog.connection,
                    "JOB-1",
                    kind="extension",
                    plan_id="PLAN-APPEND",
                    plan_digest_sha256="e" * 64,
                    created_at="2026-08-28T08:59:59+00:00",
                    target_sequences=(1,),
                    target_operations=(operation,),
                )
            catalog.connection.commit()
            original = catalog.claim_daemon_owner("daemon-original")
            catalog.admit_operation(
                OperationRecord(
                    "operation-1",
                    "archive.native",
                    "running",
                    "writing",
                    "native-recovery",
                    "admin",
                    "JOB-1",
                    1,
                    "2026-08-28T09:00:00+00:00",
                    None,
                ),
                original,
                admission_open=True,
                hardware_target=target,
                format_confirmation_label=(
                    "TAPE01"
                    if format_confirmation and not sequence_authorization
                    else None
                ),
                sequence_authorization_id=authorization_id,
            )
            catalog.connection.execute(
                "UPDATE daemon_operations SET copy_buffer_bytes=? WHERE id=?",
                (4 * 1024 * 1024, "operation-1"),
            )
            if current_provisional_block or current_completed_block:
                catalog.create_block(
                    "block-current",
                    "LIB-1",
                    "TAPE01",
                    "blocks/current",
                    1,
                    1,
                    automatic_operation_id="operation-1",
                    automatic_job_id="JOB-1",
                    automatic_cassette_sequence=1,
                )
                if current_provisional_file:
                    catalog.record_file_version(
                        "LIB-1",
                        "block-current",
                        "TAPE01",
                        payload.name,
                        "blocks/current/files/payload.bin",
                        1,
                        payload.stat().st_mtime_ns,
                        "a" * 64,
                    )
                if current_completed_block:
                    catalog.complete_block("block-current")
            if unlinked_provisional_block:
                catalog.create_block(
                    "block-unlinked",
                    "LIB-1",
                    "TAPE01",
                    "blocks/unlinked",
                    1,
                    1,
                )
            recovery = catalog.claim_daemon_owner("daemon-recovery")
            catalog.recover_interrupted_operations(recovery)
            media = "d" * 64
            lineage_at = catalog.connection.execute(
                "SELECT recorded_at FROM operation_recovery_lineages "
                "WHERE operation_id='operation-1'"
            ).fetchone()[0]
            now = (
                datetime.fromisoformat(lineage_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.connection.execute(
                "INSERT INTO hardware_command_executions("
                "id,operation_id,issued_generation,command_kind,argv_sha256,"
                "mount_path_sha256,tape_device_identity_sha256,"
                "scsi_device_identity_sha256,expected_media_scope_sha256,"
                "observed_media_identity_sha256,state,exit_outcome,created_at,"
                "exit_observed_at,quiesced_at) VALUES(?,?,?,?,?,?,?,?,?,?,"
                "'quiesced','completed',?,?,?)",
                (
                    "recovery-probe",
                    "operation-1",
                    recovery.generation,
                    "probe_media",
                    "e" * 64,
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    media,
                    now,
                    now,
                    now,
                ),
            )
            catalog.connection.execute(
                "INSERT INTO operation_media_identity_bindings("
                "operation_id,observed_media_identity_sha256,bound_by_command_id,"
                "bound_at) VALUES('operation-1',?,'recovery-probe',?)",
                (media, now),
            )
            catalog.connection.commit()
            before = tuple(
                tuple(row)
                for table in (
                    "automatic_cassette_items",
                    "job_plan_drafts",
                    "job_plan_cassettes",
                    "job_plan_items",
                )
                for row in catalog.connection.execute(
                    f"SELECT * FROM {table} ORDER BY rowid"
                )
            )
        return RecoveryCommandFence("operation-1", recovery.generation), before

    def frozen_layout(self) -> tuple[tuple[object, ...], ...]:
        with Catalog(self.database) as catalog:
            return tuple(
                tuple(row)
                for table in (
                    "automatic_cassette_items",
                    "job_plan_drafts",
                    "job_plan_cassettes",
                    "job_plan_items",
                )
                for row in catalog.connection.execute(
                    f"SELECT * FROM {table} ORDER BY rowid"
                )
            )

    def prepare_critical_replacement(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]
            catalog.begin_recovery_attempt(
                blocker.id,
                1,
                catalog.current_daemon_fence(),
                trigger="daemon_restart",
                evidence_sha256="a" * 64,
                decision="enter_critical_quarantine",
                recorded_at="2026-08-28T09:30:00+00:00",
            )
            catalog.finish_recovery_attempt(
                blocker.id,
                1,
                catalog.current_daemon_fence(),
                state="critical_quarantine",
                evidence_sha256="b" * 64,
                decision="enter_critical_quarantine",
                recorded_at="2026-08-28T09:30:01+00:00",
            )
            target = catalog.hardware_target_binding(blocker.id)
            media = catalog.media_identity_binding_evidence(blocker.id)
            assert target is not None and media is not None
            command_receipt = catalog.create_command_quiescence_receipt(
                blocker.id, catalog.current_daemon_fence()
            )
            catalog.create_physical_reconciliation_receipt(
                blocker.id,
                catalog.current_daemon_fence(),
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=target,
                    observed_media_identity_sha256=media[
                        "observed_media_identity_sha256"
                    ],
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
        return fence, before, blocker, target, media

    def critical_action_proof(self, blocker, target, media):
        observed_at = datetime.now(UTC)
        with Catalog(self.database) as catalog:
            daemon = catalog.current_daemon_fence()
            ledger = critical_command_ledger_sha256(
                catalog.hardware_commands_for_operation(blocker.id)
            )
        assert daemon is not None
        return {
            "observation": CriticalRecoveryObservation(
                operation_id=blocker.id,
                daemon_generation=daemon.generation,
                target=target,
                bound_media_identity_sha256=media[
                    "observed_media_identity_sha256"
                ],
                observed_media_identity_sha256=media[
                    "observed_media_identity_sha256"
                ],
                command_ledger_sha256=ledger,
                commands_quiescent=True,
                mounted=False,
                media_loaded=True,
                drive_busy=False,
                related_process_count=0,
                evidence_category="identification_retry_safe",
                evidence_sha256="d" * 64,
                observed_at=observed_at.isoformat(),
            ),
            "consumed_at": observed_at.isoformat(),
        }

    def prepare_registered_reuse_reset(
        self,
        *,
        for_recovery: bool,
    ) -> tuple[RecoveryCommandFence | None, int]:
        append_fence, _before = self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_file=True,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            prepare_automatic_cassette_retry(catalog, append_fence)
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='completed' "
                "WHERE job_id='JOB-1' AND sequence=1"
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
            )
            catalog.connection.commit()
            catalog.create_automatic_job(
                "REUSE",
                "LIB-1",
                "drive",
                str(Path(self.temporary.name) / "mount"),
                [("TAPE01", "SERIAL-NEW", 1, 1)],
                force_format=True,
                allow_registered_reuse=True,
            )
            owner_generation = int(
                catalog.connection.execute(
                    "SELECT owner_generation FROM daemon_operations "
                    "WHERE id='operation-1'"
                ).fetchone()[0]
            )
            if not for_recovery:
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='failed',error='format failed' "
                    "WHERE job_id='REUSE' AND sequence=1"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='failed',last_error='format failed' "
                    "WHERE id='REUSE'"
                )
                catalog.connection.commit()
                return None, owner_generation

            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='writing' "
                "WHERE job_id='REUSE' AND sequence=1"
            )
            catalog.connection.commit()
            daemon = catalog.current_daemon_fence()
            target = HardwareTargetBinding.from_verified_inputs(
                Path(self.temporary.name) / "mount",
                "tape-by-id",
                "scsi-by-id",
                ("archive.native", "REUSE", "1", "TAPE01", "", ""),
            )
            catalog.admit_operation(
                OperationRecord(
                    "operation-format",
                    "archive.native",
                    "running",
                    "formatting_media",
                    "registered-reuse-format",
                    "admin",
                    "REUSE",
                    1,
                    "2026-08-28T10:00:00+00:00",
                    None,
                ),
                daemon,
                admission_open=True,
                hardware_target=target,
                format_confirmation_label="TAPE01",
            )
            recovery = catalog.claim_daemon_owner("daemon-format-recovery")
            catalog.recover_interrupted_operations(recovery)
            media = "f" * 64
            lineage_at = catalog.connection.execute(
                "SELECT recorded_at FROM operation_recovery_lineages "
                "WHERE operation_id='operation-format'"
            ).fetchone()[0]
            now = (
                datetime.fromisoformat(lineage_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.connection.execute(
                "INSERT INTO hardware_command_executions("
                "id,operation_id,issued_generation,command_kind,argv_sha256,"
                "mount_path_sha256,tape_device_identity_sha256,"
                "scsi_device_identity_sha256,expected_media_scope_sha256,"
                "observed_media_identity_sha256,state,exit_outcome,created_at,"
                "exit_observed_at,quiesced_at) VALUES(?,?,?,?,?,?,?,?,?,?,"
                "'quiesced','completed',?,?,?)",
                (
                    "registered-reuse-probe",
                    "operation-format",
                    recovery.generation,
                    "probe_media",
                    "e" * 64,
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    media,
                    now,
                    now,
                    now,
                ),
            )
            catalog.connection.execute(
                "INSERT INTO operation_media_identity_bindings("
                "operation_id,observed_media_identity_sha256,bound_by_command_id,"
                "bound_at) VALUES('operation-format',?,'registered-reuse-probe',?)",
                (media, now),
            )
            catalog.connection.commit()
        return RecoveryCommandFence("operation-format", recovery.generation), owner_generation

    def test_nuova_requires_exact_identity_and_retained_format_authorization(self):
        fence, before = self.prepare("format", format_confirmation=False)
        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            prepare_automatic_cassette_retry(catalog, fence)
        self.assertEqual(before, self.frozen_layout())

        self.temporary.cleanup()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "catalog.db"
        fence, before = self.prepare("format", format_confirmation=True)
        with Catalog(self.database) as catalog:
            checkpoint = prepare_automatic_cassette_retry(catalog, fence)
        self.assertEqual("format", checkpoint.operation)
        self.assertTrue(checkpoint.format_allowed)
        self.assertEqual(before, self.frozen_layout())

    def test_stale_recovery_generation_rolls_back_checkpoint_reset(self):
        fence, before = self.prepare("format", format_confirmation=True)
        with Catalog(self.database) as catalog:
            catalog.claim_daemon_owner("daemon-newer")
            with self.assertRaises(StaleOperationFence):
                prepare_automatic_cassette_retry(catalog, fence)
            cassette = catalog.list_automatic_cassettes("JOB-1")[0]
        self.assertEqual("writing", cassette["status"])
        self.assertEqual(before, self.frozen_layout())

    def test_wrong_recovery_operation_rolls_back_checkpoint_reset(self):
        fence, before = self.prepare("format", format_confirmation=True)
        wrong = RecoveryCommandFence("operation-wrong", fence.owner_generation)
        with Catalog(self.database) as catalog:
            with self.assertRaises(StaleOperationFence):
                prepare_automatic_cassette_retry(catalog, wrong)
            cassette = catalog.list_automatic_cassettes("JOB-1")[0]
        self.assertEqual("writing", cassette["status"])
        self.assertEqual(before, self.frozen_layout())

    def test_append_invalidates_provisional_attempt_without_formatter_access(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            checkpoint = prepare_automatic_cassette_retry(catalog, fence)

        self.assertEqual("append", checkpoint.operation)
        self.assertFalse(checkpoint.format_allowed)
        self.assertEqual(before, self.frozen_layout())

    def test_append_invalidates_only_current_operation_provisional_block(self):
        fence, before = self.prepare(
            "append",
            format_confirmation=False,
            old_completed_block=True,
            current_provisional_block=True,
        )
        with Catalog(self.database) as catalog:
            checkpoint = prepare_automatic_cassette_retry(catalog, fence)
            blocks = {
                row["id"]: (row["status"], row["visible"])
                for row in catalog.connection.execute(
                    "SELECT id,status,visible FROM blocks ORDER BY id"
                )
            }

        self.assertEqual(1, checkpoint.invalidated_blocks)
        self.assertEqual(("completed", 1), blocks["block-completed"])
        self.assertEqual(("failed", 0), blocks["block-current"])
        self.assertEqual(before, self.frozen_layout())

    def test_append_operation_block_mapping_is_immutable(self):
        self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_block=True,
            extension_layout=True,
        )
        with Catalog(self.database) as catalog:
            self.assertIsNotNone(
                catalog.connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='job_layout_target_blocks'"
                ).fetchone()
            )
            binding = catalog.connection.execute(
                "SELECT target_sequence,segment_id,operation_id,block_id "
                "FROM job_layout_target_blocks WHERE job_id='JOB-1' AND epoch_number=2"
            ).fetchone()
            self.assertEqual(
                (1, catalog.connection.execute(
                    "SELECT segment_id FROM job_layout_targets WHERE job_id='JOB-1' "
                    "AND epoch_number=2 AND plan_sequence=1"
                ).fetchone()[0], "operation-1", "block-current"),
                tuple(binding),
            )
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable_layout_target_block"
            ):
                catalog.connection.execute(
                    "UPDATE job_layout_target_blocks SET block_id='different' "
                    "WHERE block_id='block-current'"
                )
            catalog.connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable_automatic_operation_block"
            ):
                catalog.connection.execute(
                    "UPDATE automatic_operation_blocks SET operation_id=? "
                    "WHERE block_id='block-current'",
                    ("operation-other",),
                )
            catalog.connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable_automatic_operation_block"
            ):
                catalog.connection.execute(
                    "DELETE FROM automatic_operation_blocks "
                    "WHERE block_id='block-current'"
                )

    def test_format_extension_block_maps_to_its_immutable_layout_segment(self):
        self.prepare(
            "format",
            format_confirmation=True,
            current_provisional_block=True,
            extension_layout=True,
        )
        with Catalog(self.database) as catalog:
            target = catalog.connection.execute(
                "SELECT target_sequence,segment_id FROM job_layout_targets "
                "WHERE job_id='JOB-1' AND epoch_number=2 AND operation='format'"
            ).fetchone()
            binding = catalog.connection.execute(
                "SELECT target_sequence,segment_id,operation_id,block_id "
                "FROM job_layout_target_blocks WHERE job_id='JOB-1' AND epoch_number=2"
            ).fetchone()
            self.assertEqual(
                (target["target_sequence"], target["segment_id"], "operation-1", "block-current"),
                tuple(binding) if binding is not None else None,
            )

    def test_append_ownership_is_archived_before_automatic_job_deletion(self):
        self.prepare(
            "append",
            format_confirmation=False,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            owner_generation = catalog.connection.execute(
                "SELECT owner_generation FROM daemon_operations "
                "WHERE id='operation-1'"
            ).fetchone()[0]

            result = catalog.delete_automatic_job("JOB-1")

            live = catalog.connection.execute(
                "SELECT * FROM automatic_operation_blocks "
                "WHERE block_id='block-current'"
            ).fetchone()
            archived = catalog.connection.execute(
                "SELECT block_id,operation_id,job_id,cassette_sequence,"
                "daemon_generation,disposition FROM "
                "automatic_operation_block_tombstones "
                "WHERE block_id='block-current'"
            ).fetchone()
            block = catalog.connection.execute(
                "SELECT id,status,visible FROM blocks WHERE id='block-current'"
            ).fetchone()
            violations = list(catalog.connection.execute("PRAGMA foreign_key_check"))
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable_automatic_operation_block_tombstone",
            ):
                catalog.connection.execute(
                    "UPDATE automatic_operation_block_tombstones "
                    "SET operation_id='operation-other' "
                    "WHERE block_id='block-current'"
                )
            catalog.connection.rollback()
            with self.assertRaisesRegex(
                sqlite3.IntegrityError,
                "immutable_automatic_operation_block_tombstone",
            ):
                catalog.connection.execute(
                    "DELETE FROM automatic_operation_block_tombstones "
                    "WHERE block_id='block-current'"
                )

        self.assertEqual("JOB-1", result["id"])
        self.assertIsNone(live)
        self.assertEqual(
            (
                "block-current",
                "operation-1",
                "JOB-1",
                1,
                owner_generation,
                "job_deleted",
            ),
            tuple(archived),
        )
        self.assertEqual(("block-current", "completed", 1), tuple(block))
        self.assertEqual([], violations)

    def test_deleted_job_provenance_invalidates_ambiguous_legacy_restore_plan(
        self,
    ):
        self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_file=True,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET block_id='block-current' "
                "WHERE job_id='JOB-1' AND sequence=1"
            )
            catalog.connection.commit()
            original = self.snapshot_current_restore_plan(
                catalog, "restore-before-job-delete"
            )
            self.assertEqual("TAPE01", original["items"][0]["physical_label"])
            self.convert_restore_plan_to_legacy_coalesced_schema(
                catalog, original["id"], "restore-before-job-delete"
            )

            deleted = catalog.delete_automatic_job("JOB-1")
            catalog.initialize()

            detail = catalog.get_restore_plan(original["id"])
            replay = catalog.create_restore_plan(
                (original["items"][0]["file_version_id"],),
                "/srv/restore",
                actor="admin",
                idempotency_key="restore-before-job-delete",
                request_sha256=hashlib.sha256(
                    b"restore-before-job-delete"
                ).hexdigest(),
            )
            foreign_keys = {
                str(row["table"])
                for row in catalog.connection.execute(
                    "PRAGMA foreign_key_list(restore_plan_items)"
                )
            }
            file_row = catalog.connection.execute(
                "SELECT 1 FROM file_versions WHERE id=?",
                (original["items"][0]["file_version_id"],),
            ).fetchone()
            violations = list(catalog.connection.execute("PRAGMA foreign_key_check"))

            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                catalog.connection.execute(
                    "UPDATE restore_plans SET state='planned' WHERE id=?",
                    (original["id"],),
                )

        self.assertEqual(1, deleted["deleted_cassettes"])
        self.assertEqual("legacy_invalid", detail.get("identity_state"))
        self.assertEqual(
            "legacy_physical_identity_ambiguous",
            detail["invalidation_reason"],
        )
        self.assertIsNone(detail["cassettes"][0]["physical_label"])
        self.assertIsNone(detail["items"][0]["physical_label"])
        self.assertEqual(detail, replay)
        self.assertNotIn("file_versions", foreign_keys)
        self.assertIsNotNone(file_row)
        self.assertEqual([], violations)

    def test_legacy_restore_invalidation_migration_rolls_back_atomically(self):
        self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_file=True,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET block_id='block-current' "
                "WHERE job_id='JOB-1' AND sequence=1"
            )
            catalog.connection.commit()
            original = self.snapshot_current_restore_plan(
                catalog, "restore-migration-rollback"
            )
            self.assertEqual("TAPE01", original["items"][0]["physical_label"])
            self.convert_restore_plan_to_legacy_coalesced_schema(
                catalog, original["id"], "restore-migration-rollback"
            )
            catalog.delete_automatic_job("JOB-1")
            receipt_before = catalog.connection.execute(
                "SELECT response_json FROM management_idempotency "
                "WHERE actor='admin' AND idempotency_key='restore-migration-rollback'"
            ).fetchone()[0]
            catalog.connection.execute(
                "CREATE TRIGGER force_restore_identity_migration_failure "
                "BEFORE UPDATE ON restore_plan_cassettes "
                "BEGIN SELECT RAISE(ABORT,'forced_restore_identity_failure'); END"
            )
            catalog.connection.commit()

        with Catalog(self.database) as catalog:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "forced_restore_identity_failure"
            ):
                catalog.initialize()
            foreign_keys = {
                str(row["table"])
                for row in catalog.connection.execute(
                    "PRAGMA foreign_key_list(restore_plan_items)"
                )
            }
            item_label = catalog.connection.execute(
                "SELECT physical_label FROM restore_plan_items WHERE plan_id=?",
                (original["id"],),
            ).fetchone()[0]
            plan_state = tuple(
                catalog.connection.execute(
                    "SELECT identity_state,invalidation_reason FROM restore_plans "
                    "WHERE id=?",
                    (original["id"],),
                ).fetchone()
            )
            receipt_after = catalog.connection.execute(
                "SELECT response_json FROM management_idempotency "
                "WHERE actor='admin' AND idempotency_key='restore-migration-rollback'"
            ).fetchone()[0]

        self.assertIn("file_versions", foreign_keys)
        self.assertEqual("TAPE01", item_label)
        self.assertEqual(("exact", None), plan_state)
        self.assertEqual(receipt_before, receipt_after)

    def test_append_ownership_is_archived_before_registered_tape_reformat_commit(
        self,
    ):
        self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_file=True,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='completed',"
                "block_id='block-current' "
                "WHERE job_id='JOB-1' AND sequence=1"
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
            )
            catalog.connection.commit()
            owner_generation = catalog.connection.execute(
                "SELECT owner_generation FROM daemon_operations "
                "WHERE id='operation-1'"
            ).fetchone()[0]
            restore_plan = self.snapshot_current_restore_plan(
                catalog, "restore-before-reformat"
            )
            self.convert_restore_plan_to_legacy_coalesced_schema(
                catalog, restore_plan["id"], "restore-before-reformat"
            )
            catalog.initialize()
            catalog.create_automatic_job(
                "REUSE",
                "LIB-1",
                "drive",
                str(Path(self.temporary.name) / "mount"),
                [("TAPE01", "SERIAL-NEW", 1, 1)],
                force_format=True,
                allow_registered_reuse=True,
            )

            result = catalog.commit_registered_tape_reformat("REUSE", 1)

            archived = catalog.connection.execute(
                "SELECT block_id,operation_id,job_id,cassette_sequence,"
                "daemon_generation,disposition FROM "
                "automatic_operation_block_tombstones "
                "WHERE block_id='block-current'"
            ).fetchone()
            queued = catalog.list_automatic_cassettes("REUSE")[0]
            old_tape = catalog.connection.execute(
                "SELECT 1 FROM tapes WHERE id='TAPE01'"
            ).fetchone()
            old_block = catalog.connection.execute(
                "SELECT 1 FROM blocks WHERE id='block-current'"
            ).fetchone()
            old_file = catalog.connection.execute(
                "SELECT 1 FROM file_versions WHERE block_id='block-current'"
            ).fetchone()
            retained_restore_plan = catalog.get_restore_plan(restore_plan["id"])
            invalidated_job = catalog.get_automatic_job("JOB-1")
            violations = list(catalog.connection.execute("PRAGMA foreign_key_check"))

        self.assertEqual(
            {"tapes": 1, "blocks": 1, "files": 1, "jobs": 1}, result
        )
        self.assertEqual(
            (
                "block-current",
                "operation-1",
                "JOB-1",
                1,
                owner_generation,
                "registered_tape_reformatted",
            ),
            tuple(archived),
        )
        self.assertEqual("TAPE01", queued["physical_label"])
        self.assertEqual("SERIAL-NEW", queued["tape_serial"])
        self.assertIsNone(queued["tape_id"])
        self.assertIsNone(queued["block_id"])
        self.assertIsNone(old_tape)
        self.assertIsNone(old_block)
        self.assertIsNone(old_file)
        self.assertEqual(
            "Dati invalidati: cassetta TAPE01 riformattata dal job REUSE",
            invalidated_job["last_error"],
        )
        expected_legacy_plan = {
            **restore_plan,
            "items": [
                {**item, "is_current": None} for item in restore_plan["items"]
            ],
        }
        self.assertEqual(expected_legacy_plan, retained_restore_plan)
        self.assertEqual([], violations)

    def test_registered_tape_reformat_rolls_back_when_ownership_archive_fails(self):
        self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_file=True,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='completed' "
                "WHERE job_id='JOB-1' AND sequence=1"
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
            )
            catalog.connection.commit()
            catalog.create_automatic_job(
                "REUSE",
                "LIB-1",
                "drive",
                str(Path(self.temporary.name) / "mount"),
                [("TAPE01", "SERIAL-NEW", 1, 1)],
                force_format=True,
                allow_registered_reuse=True,
            )
            catalog.connection.execute(
                "CREATE TRIGGER force_operation_block_archive_failure "
                "BEFORE INSERT ON automatic_operation_block_tombstones "
                "BEGIN SELECT RAISE(ABORT,'forced_ownership_archive_failure'); END"
            )
            catalog.connection.commit()

            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "forced_ownership_archive_failure"
            ):
                catalog.commit_registered_tape_reformat("REUSE", 1)

            live = catalog.connection.execute(
                "SELECT operation_id,job_id,cassette_sequence "
                "FROM automatic_operation_blocks WHERE block_id='block-current'"
            ).fetchone()
            archived = catalog.connection.execute(
                "SELECT 1 FROM automatic_operation_block_tombstones "
                "WHERE block_id='block-current'"
            ).fetchone()
            tape = catalog.connection.execute(
                "SELECT 1 FROM tapes WHERE id='TAPE01'"
            ).fetchone()
            block = catalog.connection.execute(
                "SELECT status FROM blocks WHERE id='block-current'"
            ).fetchone()
            version = catalog.connection.execute(
                "SELECT visible FROM file_versions WHERE block_id='block-current'"
            ).fetchone()
            old_cassette = catalog.list_automatic_cassettes("JOB-1")[0]

        self.assertEqual(("operation-1", "JOB-1", 1), tuple(live))
        self.assertIsNone(archived)
        self.assertIsNotNone(tape)
        self.assertEqual(("completed",), tuple(block))
        self.assertEqual((1,), tuple(version))
        self.assertEqual("completed", old_cassette["status"])

    def test_registered_reuse_administrative_reset_archives_append_ownership(self):
        _fence, owner_generation = self.prepare_registered_reuse_reset(
            for_recovery=False
        )
        with Catalog(self.database) as catalog:
            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "immutable_automatic_operation_block"
            ):
                catalog.connection.execute(
                    "DELETE FROM automatic_operation_blocks "
                    "WHERE block_id='block-current'"
                )
            catalog.connection.rollback()
            restore_plan = self.snapshot_current_restore_plan(
                catalog, "restore-before-administrative-reset"
            )

            result = catalog.reset_automatic_cassette(
                "REUSE", 1, "retry registered format"
            )

            archived = catalog.connection.execute(
                "SELECT block_id,operation_id,job_id,cassette_sequence,"
                "daemon_generation,disposition FROM "
                "automatic_operation_block_tombstones "
                "WHERE block_id='block-current'"
            ).fetchone()
            live = catalog.connection.execute(
                "SELECT 1 FROM automatic_operation_blocks "
                "WHERE block_id='block-current'"
            ).fetchone()
            cassette = catalog.list_automatic_cassettes("REUSE")[0]
            old_rows = tuple(
                catalog.connection.execute(
                    "SELECT 'tape' FROM tapes WHERE id='TAPE01' "
                    "UNION ALL SELECT 'block' FROM blocks "
                    "WHERE id='block-current' "
                    "UNION ALL SELECT 'file' FROM file_versions "
                    "WHERE block_id='block-current'"
                )
            )
            retained_restore_plan = catalog.get_restore_plan(restore_plan["id"])

        self.assertEqual({"blocks": 1, "files": 1, "tapes": 1}, result)
        self.assertEqual(
            (
                "block-current",
                "operation-1",
                "JOB-1",
                1,
                owner_generation,
                "registered_tape_reset",
            ),
            tuple(archived),
        )
        self.assertIsNone(live)
        self.assertEqual("pending", cassette["status"])
        self.assertIsNone(cassette["tape_id"])
        self.assertEqual((), old_rows)
        self.assertEqual(restore_plan, retained_restore_plan)

    def test_registered_reuse_format_recovery_archives_append_ownership(self):
        fence, owner_generation = self.prepare_registered_reuse_reset(
            for_recovery=True
        )
        assert fence is not None
        with Catalog(self.database) as catalog:
            restore_plan = self.snapshot_current_restore_plan(
                catalog, "restore-before-recovery-reset"
            )
            checkpoint = prepare_automatic_cassette_retry(catalog, fence)
            archived = catalog.connection.execute(
                "SELECT block_id,operation_id,job_id,cassette_sequence,"
                "daemon_generation,disposition FROM "
                "automatic_operation_block_tombstones "
                "WHERE block_id='block-current'"
            ).fetchone()
            live = catalog.connection.execute(
                "SELECT 1 FROM automatic_operation_blocks "
                "WHERE block_id='block-current'"
            ).fetchone()
            cassette = catalog.list_automatic_cassettes("REUSE")[0]
            old_rows = tuple(
                catalog.connection.execute(
                    "SELECT 'tape' FROM tapes WHERE id='TAPE01' "
                    "UNION ALL SELECT 'block' FROM blocks "
                    "WHERE id='block-current' "
                    "UNION ALL SELECT 'file' FROM file_versions "
                    "WHERE block_id='block-current'"
                )
            )
            retained_restore_plan = catalog.get_restore_plan(restore_plan["id"])

        self.assertEqual("format", checkpoint.operation)
        self.assertTrue(checkpoint.format_allowed)
        self.assertEqual(1, checkpoint.invalidated_blocks)
        self.assertEqual(1, checkpoint.invalidated_files)
        self.assertEqual(1, checkpoint.invalidated_tapes)
        self.assertEqual(
            (
                "block-current",
                "operation-1",
                "JOB-1",
                1,
                owner_generation,
                "registered_tape_recovery_reset",
            ),
            tuple(archived),
        )
        self.assertIsNone(live)
        self.assertEqual("pending", cassette["status"])
        self.assertIsNone(cassette["tape_id"])
        self.assertEqual((), old_rows)
        self.assertEqual(restore_plan, retained_restore_plan)

    def test_registered_reuse_recovery_reset_rolls_back_on_archive_failure(self):
        fence, _owner_generation = self.prepare_registered_reuse_reset(
            for_recovery=True
        )
        assert fence is not None
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "CREATE TRIGGER force_recovery_reset_archive_failure "
                "BEFORE INSERT ON automatic_operation_block_tombstones "
                "BEGIN SELECT RAISE(ABORT,'forced_recovery_reset_archive_failure'); END"
            )
            catalog.connection.commit()

            with self.assertRaisesRegex(
                sqlite3.IntegrityError, "forced_recovery_reset_archive_failure"
            ):
                prepare_automatic_cassette_retry(catalog, fence)

            live = catalog.connection.execute(
                "SELECT operation_id,job_id,cassette_sequence "
                "FROM automatic_operation_blocks WHERE block_id='block-current'"
            ).fetchone()
            archived = catalog.connection.execute(
                "SELECT 1 FROM automatic_operation_block_tombstones "
                "WHERE block_id='block-current'"
            ).fetchone()
            tape = catalog.connection.execute(
                "SELECT 1 FROM tapes WHERE id='TAPE01'"
            ).fetchone()
            block = catalog.connection.execute(
                "SELECT status,visible FROM blocks WHERE id='block-current'"
            ).fetchone()
            version = catalog.connection.execute(
                "SELECT visible FROM file_versions WHERE block_id='block-current'"
            ).fetchone()
            cassette = catalog.list_automatic_cassettes("REUSE")[0]
            operation = catalog.get_operation("operation-format")

        self.assertEqual(("operation-1", "JOB-1", 1), tuple(live))
        self.assertIsNone(archived)
        self.assertIsNotNone(tape)
        self.assertEqual(("completed", 1), tuple(block))
        self.assertEqual((1,), tuple(version))
        self.assertEqual("writing", cassette["status"])
        self.assertEqual("recovery_required", operation["state"])

    def test_append_fails_closed_on_unmapped_provisional_block(self):
        fence, before = self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_block=True,
            unlinked_provisional_block=True,
        )
        with Catalog(self.database) as catalog:
            with self.assertRaisesRegex(ValidationError, "provisional block"):
                prepare_automatic_cassette_retry(catalog, fence)
            states = tuple(
                (row["id"], row["status"])
                for row in catalog.connection.execute(
                    "SELECT id,status FROM blocks ORDER BY id"
                )
            )
        self.assertEqual(
            (("block-current", "copying"), ("block-unlinked", "copying")),
            states,
        )
        self.assertEqual(before, self.frozen_layout())

    def test_append_invalidates_file_checkpointed_before_backup_return(self):
        fence, before = self.prepare(
            "append",
            format_confirmation=False,
            current_provisional_block=True,
            current_provisional_file=True,
        )
        with Catalog(self.database) as catalog:
            checkpoint = prepare_automatic_cassette_retry(catalog, fence)
            block = catalog.connection.execute(
                "SELECT status,visible FROM blocks WHERE id='block-current'"
            ).fetchone()
            version = catalog.connection.execute(
                "SELECT visible FROM file_versions WHERE block_id='block-current'"
            ).fetchone()

        self.assertEqual(1, checkpoint.invalidated_blocks)
        self.assertEqual(("failed", 0), tuple(block))
        self.assertEqual((0,), tuple(version))
        self.assertEqual(before, self.frozen_layout())

    def test_append_preserves_current_attempt_block_completed_before_crash(self):
        fence, before = self.prepare(
            "append",
            format_confirmation=False,
            old_completed_block=True,
            current_completed_block=True,
        )
        with Catalog(self.database) as catalog:
            checkpoint = prepare_automatic_cassette_retry(catalog, fence)
            states = tuple(
                (row["id"], row["status"], row["visible"])
                for row in catalog.connection.execute(
                    "SELECT id,status,visible FROM blocks ORDER BY id"
                )
            )
        self.assertEqual(0, checkpoint.invalidated_blocks)
        self.assertEqual(
            (
                ("block-completed", "completed", 1),
                ("block-current", "completed", 1),
            ),
            states,
        )
        self.assertEqual(before, self.frozen_layout())

    def test_production_executor_fails_closed_without_frozen_retry_seam(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]
        unavailable = lambda _blocker, _fence: None
        executor = ProductionRecoveryExecutor(
            lambda: Catalog(self.database),
            observe_command=unavailable,
            reconcile_commit=unavailable,
            retry_identification=unavailable,
            retry_unload=unavailable,
            safe_release=unavailable,
        )

        with (
            patch("ltobackup.application.analyze_library") as application_scan,
            patch("ltobackup.scanner.analyze_library") as scanner_scan,
            patch("ltobackup.engine.BackupEngine.scan") as engine_scan,
            patch(
                "ltobackup.daemon.native_runtime._native_backup_callback"
            ) as native_scan_callback,
        ):
            with self.assertRaises(CriticalRecoveryError):
                executor.retry_current_cassette(blocker, fence)

        application_scan.assert_not_called()
        scanner_scan.assert_not_called()
        engine_scan.assert_not_called()
        native_scan_callback.assert_not_called()
        self.assertEqual(before, self.frozen_layout())
        with Catalog(self.database) as catalog:
            self.assertEqual(
                "recovery_required", catalog.get_operation(blocker.id)["state"]
            )

    def test_native_recovery_atomically_admits_non_scanning_replacement(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]

        class DeferredExecutor:
            def __init__(self) -> None:
                self.submissions = []

            def submit(self, callback, *arguments):
                self.submissions.append((callback, arguments))
                return Future()

        submitted = DeferredExecutor()
        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=submitted,
            accepting=False,
        )
        frozen_calls = []

        class NativeArchive:
            def run_frozen_recovery(self, context):
                frozen_calls.append(context.record.id)

        native = NativeArchive()
        runtime = ProductionRecoveryRuntime(
            SimpleNamespace(), operations, native
        )

        with (
            patch("ltobackup.application.analyze_library") as application_scan,
            patch("ltobackup.scanner.analyze_library") as scanner_scan,
            patch("ltobackup.engine.BackupEngine.scan") as engine_scan,
            patch(
                "ltobackup.daemon.native_runtime._native_backup_callback"
            ) as scan_capable_callback,
        ):
            replacement = runtime.retry_current_cassette(blocker, fence)

        self.assertEqual(1, len(submitted.submissions))
        self.assertEqual(
            operations._run_native_recovery_once,
            submitted.submissions[0][0],
        )
        submitted_context, submitted_callback = submitted.submissions[0][1]
        self.assertEqual(replacement.proof, submitted_context.record.id)
        self.assertEqual(native.run_frozen_recovery, submitted_callback)
        application_scan.assert_not_called()
        scanner_scan.assert_not_called()
        engine_scan.assert_not_called()
        scan_capable_callback.assert_not_called()
        self.assertEqual(before, self.frozen_layout())
        with Catalog(self.database) as catalog:
            self.assertEqual("cancelled", catalog.get_operation(blocker.id)["state"])
            current = catalog.active_operation()
            self.assertEqual(replacement.proof, current["id"])
            self.assertEqual("archive.native", current["kind"])
            self.assertEqual("JOB-1", current["job_id"])
            self.assertEqual(1, current["cassette_sequence"])
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT 1 FROM format_confirmations WHERE operation_id=?",
                    (current["id"],),
                ).fetchone()
            )

    def test_native_recovery_hands_off_progress_before_inline_worker(self):
        fence, _before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]
        events: list[tuple[str, str]] = []
        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=_InlineOperationExecutor(),
            accepting=False,
        )
        native = SimpleNamespace(
            run_frozen_recovery=lambda context: events.append(
                ("worker", context.record.id)
            )
        )
        runtime = ProductionRecoveryRuntime(
            SimpleNamespace(),
            operations,
            native,
            replacement_admission_factory=lambda: (
                lambda admitted: events.append(("admitted", admitted.id))
            ),
        )

        receipt = runtime.retry_current_cassette(blocker, fence)

        self.assertEqual(
            [("admitted", receipt.proof), ("worker", receipt.proof)], events
        )

    def test_critical_replacement_hands_off_progress_before_inline_worker(self):
        fence, _before, blocker, target, media = self.prepare_critical_replacement()
        events: list[tuple[str, str]] = []
        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=_InlineOperationExecutor(),
            accepting=False,
        )
        proof = self.critical_action_proof(blocker, target, media)

        replacement = operations.authorize_critical_replacement(
            blocker,
            fence,
            lambda context: events.append(("worker", context.record.id)),
            principal="web-user-1",
            idempotency_key="critical-progress-handoff",
            job_id="JOB-1",
            cassette_sequence=1,
            expected_label="TAPE01",
            attempt_number=1,
            evidence_sha256="b" * 64,
            target=target,
            observed_media_identity_sha256=media[
                "observed_media_identity_sha256"
            ],
            on_admitted=lambda admitted: events.append(("admitted", admitted.id)),
            **proof,
        )

        self.assertEqual(
            [("admitted", replacement.id), ("worker", replacement.id)], events
        )

    def test_protected_replacement_is_atomic_one_shot_and_non_scanning(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]
            catalog.begin_recovery_attempt(
                blocker.id,
                1,
                catalog.current_daemon_fence(),
                trigger="daemon_restart",
                evidence_sha256="a" * 64,
                decision="enter_critical_quarantine",
                recorded_at="2026-08-28T09:30:00+00:00",
            )
            catalog.finish_recovery_attempt(
                blocker.id,
                1,
                catalog.current_daemon_fence(),
                state="critical_quarantine",
                evidence_sha256="b" * 64,
                decision="enter_critical_quarantine",
                recorded_at="2026-08-28T09:30:01+00:00",
            )
            target = catalog.hardware_target_binding(blocker.id)
            media = catalog.media_identity_binding_evidence(blocker.id)
            command_receipt = catalog.create_command_quiescence_receipt(
                blocker.id, catalog.current_daemon_fence()
            )
            catalog.create_physical_reconciliation_receipt(
                blocker.id,
                catalog.current_daemon_fence(),
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=target,
                    observed_media_identity_sha256=media[
                        "observed_media_identity_sha256"
                    ],
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
        assert target is not None and media is not None

        class DeferredExecutor:
            def __init__(self) -> None:
                self.submissions = []

            def submit(self, callback, *arguments):
                self.submissions.append((callback, arguments))
                return Future()

        submitted = DeferredExecutor()
        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=submitted,
            accepting=False,
        )
        frozen = SimpleNamespace(run_frozen_recovery=lambda _context: None)
        kwargs = {
            "principal": "web-user-1",
            "idempotency_key": "critical-replacement-once",
            "job_id": "JOB-1",
            "cassette_sequence": 1,
            "expected_label": "TAPE01",
            "attempt_number": 1,
            "evidence_sha256": "b" * 64,
            "target": target,
            "observed_media_identity_sha256": media[
                "observed_media_identity_sha256"
            ],
            **self.critical_action_proof(blocker, target, media),
        }

        with (
            patch("ltobackup.application.analyze_library") as application_scan,
            patch("ltobackup.scanner.analyze_library") as scanner_scan,
            patch("ltobackup.engine.BackupEngine.scan") as engine_scan,
            patch(
                "ltobackup.daemon.native_runtime._native_backup_callback"
            ) as scan_callback,
        ):
            replacement = operations.authorize_critical_replacement(
                blocker, fence, frozen.run_frozen_recovery, **kwargs
            )

        self.assertEqual(1, len(submitted.submissions))
        application_scan.assert_not_called()
        scanner_scan.assert_not_called()
        engine_scan.assert_not_called()
        scan_callback.assert_not_called()
        self.assertEqual(before, self.frozen_layout())
        with Catalog(self.database) as catalog:
            self.assertEqual("failed", catalog.get_operation(blocker.id)["state"])
            self.assertEqual(
                "accepted",
                catalog.connection.execute(
                    "SELECT result FROM audit_entries "
                    "WHERE request_id='critical-replacement-once'"
                ).fetchone()[0],
            )
        with self.assertRaisesRegex(CatalogError, "one-shot"):
            operations.authorize_critical_replacement(
                blocker, fence, frozen.run_frozen_recovery, **kwargs
            )
        self.assertEqual("archive.native", replacement.kind)
        self.assertEqual(1, len(submitted.submissions))

    def test_protected_replacement_rejects_mismatch_and_live_physical_state(self):
        fence, _before, blocker, target, media = self.prepare_critical_replacement()

        class DeferredExecutor:
            def submit(self, callback, *arguments):
                return Future()

        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=DeferredExecutor(),
            accepting=False,
        )
        kwargs = {
            "principal": "web-user-1",
            "job_id": "JOB-1",
            "cassette_sequence": 1,
            "attempt_number": 1,
            "evidence_sha256": "b" * 64,
            "target": target,
            "observed_media_identity_sha256": media[
                "observed_media_identity_sha256"
            ],
            **self.critical_action_proof(blocker, target, media),
        }
        with self.assertRaisesRegex(CatalogError, "mismatched"):
            operations.authorize_critical_replacement(
                blocker,
                fence,
                lambda _context: None,
                idempotency_key="critical-wrong-label",
                expected_label="WRONG1",
                **kwargs,
            )
        wrong_target = HardwareTargetBinding(
            "f" * 64,
            target.tape_device_identity_sha256,
            target.scsi_device_identity_sha256,
            target.expected_media_scope_sha256,
        )
        with self.assertRaisesRegex(CatalogError, "mismatched"):
            operations.authorize_critical_replacement(
                blocker,
                fence,
                lambda _context: None,
                idempotency_key="critical-wrong-target",
                expected_label="TAPE01",
                **{**kwargs, "target": wrong_target},
            )
        with self.assertRaisesRegex(CatalogError, "mismatched"):
            operations.authorize_critical_replacement(
                blocker,
                fence,
                lambda _context: None,
                idempotency_key="critical-wrong-media",
                expected_label="TAPE01",
                **{
                    **kwargs,
                    "observed_media_identity_sha256": "e" * 64,
                },
            )
        with Catalog(self.database) as catalog:
            self.assertEqual("recovery_required", catalog.get_operation(blocker.id)["state"])
            self.assertEqual(
                "rejected",
                catalog.connection.execute(
                    "SELECT result FROM audit_entries "
                    "WHERE request_id='critical-wrong-label'"
                ).fetchone()[0],
            )
        with self.assertRaisesRegex(CatalogError, "mismatched"):
            operations.authorize_critical_replacement(
                blocker,
                RecoveryCommandFence(blocker.id, fence.owner_generation - 1),
                lambda _context: None,
                idempotency_key="critical-stale-generation",
                expected_label="TAPE01",
                **kwargs,
            )
        with Catalog(self.database) as catalog:
            self.assertEqual(
                "rejected",
                catalog.connection.execute(
                    "SELECT result FROM audit_entries "
                    "WHERE request_id='critical-stale-generation'"
                ).fetchone()[0],
            )
            catalog.connection.execute(
                "DELETE FROM physical_reconciliation_receipts WHERE operation_id=?",
                (blocker.id,),
            )
            catalog.connection.commit()
        with self.assertRaisesRegex(CatalogError, "not quiescent"):
            operations.authorize_critical_replacement(
                blocker,
                fence,
                lambda _context: None,
                idempotency_key="critical-mounted",
                expected_label="TAPE01",
                **{
                    **kwargs,
                    "observation": replace(kwargs["observation"], mounted=True),
                },
            )
        with Catalog(self.database) as catalog:
            self.assertEqual("recovery_required", catalog.get_operation(blocker.id)["state"])
            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations"
                ).fetchone()[0],
            )

    def test_protected_replacement_audit_failure_rolls_back_action_and_key(self):
        fence, _before, blocker, target, media = self.prepare_critical_replacement()

        class DeferredExecutor:
            def submit(self, callback, *arguments):
                return Future()

        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=DeferredExecutor(),
            accepting=False,
        )
        kwargs = {
            "principal": "web-user-1",
            "idempotency_key": "critical-audit-rollback",
            "job_id": "JOB-1",
            "cassette_sequence": 1,
            "expected_label": "TAPE01",
            "attempt_number": 1,
            "evidence_sha256": "b" * 64,
            "target": target,
            "observed_media_identity_sha256": media[
                "observed_media_identity_sha256"
            ],
            **self.critical_action_proof(blocker, target, media),
        }
        with patch.object(
            Catalog,
            "reset_automatic_cassette_for_recovery",
            side_effect=ValidationError("replacement admission failed"),
        ):
            with self.assertRaisesRegex(CatalogError, "proof is incomplete"):
                operations.authorize_critical_replacement(
                    blocker,
                    fence,
                    lambda _context: None,
                    **{**kwargs, "idempotency_key": "critical-admission-rejected"},
                )
        with Catalog(self.database) as catalog:
            self.assertEqual("recovery_required", catalog.get_operation(blocker.id)["state"])
            self.assertEqual(
                "rejected",
                catalog.connection.execute(
                    "SELECT result FROM audit_entries "
                    "WHERE request_id='critical-admission-rejected'"
                ).fetchone()[0],
            )
        with patch.object(
            Catalog, "_record_audit_tx", side_effect=RuntimeError("audit failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "audit failed"):
                operations.authorize_critical_replacement(
                    blocker, fence, lambda _context: None, **kwargs
                )
        with Catalog(self.database) as catalog:
            self.assertEqual("recovery_required", catalog.get_operation(blocker.id)["state"])
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT 1 FROM audit_entries "
                    "WHERE request_id='critical-audit-rollback'"
                ).fetchone()
            )
        replacement = operations.authorize_critical_replacement(
            blocker, fence, lambda _context: None, **kwargs
        )
        self.assertEqual("archive.native", replacement.kind)

    def test_nuova_replacement_clones_only_retained_format_authorization(self):
        fence, before = self.prepare("format", format_confirmation=True)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]

        class DeferredExecutor:
            def submit(self, callback, *arguments):
                return Future()

        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=DeferredExecutor(),
            accepting=False,
        )
        native = SimpleNamespace(run_frozen_recovery=lambda _context: None)
        receipt = ProductionRecoveryRuntime(
            SimpleNamespace(), operations, native
        ).retry_current_cassette(blocker, fence)

        self.assertEqual(before, self.frozen_layout())
        with Catalog(self.database) as catalog:
            confirmation = catalog.connection.execute(
                "SELECT operation.owner_generation,confirmation.job_id,"
                "confirmation.cassette_sequence,confirmation.expected_label "
                "FROM format_confirmations confirmation JOIN daemon_operations operation "
                "ON operation.id=confirmation.operation_id WHERE confirmation.operation_id=?",
                (receipt.proof,),
            ).fetchone()
            provenance = catalog.connection.execute(
                "SELECT 1 FROM operation_format_authorizations WHERE operation_id=?",
                (receipt.proof,),
            ).fetchone()
            self.assertEqual(
                (fence.owner_generation, "JOB-1", 1, "TAPE01"),
                tuple(confirmation),
            )
            self.assertIsNone(provenance)

    def test_nuova_replacement_preserves_sequence_authority_provenance(self):
        fence, before = self.prepare(
            "format", format_confirmation=False, sequence_authorization=True
        )
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]

        class DeferredExecutor:
            def submit(self, callback, *arguments):
                return Future()

        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=DeferredExecutor(),
            accepting=False,
        )
        receipt = ProductionRecoveryRuntime(
            SimpleNamespace(),
            operations,
            SimpleNamespace(run_frozen_recovery=lambda _context: None),
        ).retry_current_cassette(blocker, fence)

        self.assertEqual(before, self.frozen_layout())
        with Catalog(self.database) as catalog:
            confirmation = catalog.connection.execute(
                "SELECT confirmed_by FROM format_confirmations WHERE operation_id=?",
                (receipt.proof,),
            ).fetchone()
            provenance = catalog.connection.execute(
                "SELECT authorization_id FROM operation_format_authorizations "
                "WHERE operation_id=?",
                (receipt.proof,),
            ).fetchone()

        self.assertEqual("authorizer", confirmation["confirmed_by"])
        self.assertIsNotNone(provenance)
        if provenance is not None:
            self.assertEqual("a" * 64, provenance["authorization_id"])

    def test_nuova_replacement_rejects_changed_sequence_authority_binding(self):
        for field, value in (
            ("physical_label", "TAPE02"),
            ("operation", "append"),
            ("reuse_registered", 1),
        ):
            with self.subTest(field=field):
                original_database = self.database
                self.database = Path(self.temporary.name) / f"{field}.db"
                try:
                    fence, _before = self.prepare(
                        "format", format_confirmation=False, sequence_authorization=True
                    )
                    with Catalog(self.database) as catalog:
                        blocker = catalog.recover_interrupted_operations(
                            catalog.current_daemon_fence()
                        )[0]
                        catalog.connection.execute(
                            f"UPDATE automatic_cassettes SET {field}=? "
                            "WHERE job_id='JOB-1' AND sequence=1",
                            (value,),
                        )
                        catalog.connection.commit()

                    class DeferredExecutor:
                        def submit(self, callback, *arguments):
                            return Future()

                    operations = OperationManager(
                        lambda: Catalog(self.database),
                        DaemonFence("daemon-recovery", fence.owner_generation),
                        executor=DeferredExecutor(),
                        accepting=False,
                    )
                    runtime = ProductionRecoveryRuntime(
                        SimpleNamespace(),
                        operations,
                        SimpleNamespace(run_frozen_recovery=lambda _context: None),
                    )
                    with self.assertRaises(ValidationError):
                        runtime.retry_current_cassette(blocker, fence)
                    with Catalog(self.database) as catalog:
                        self.assertIsNone(
                            catalog.connection.execute(
                                "SELECT 1 FROM daemon_operations "
                                "WHERE id<>? AND job_id='JOB-1'",
                                (fence.operation_id,),
                            ).fetchone()
                        )
                        self.assertEqual(
                            1,
                            catalog.connection.execute(
                                "SELECT COUNT(*) FROM format_confirmations"
                            ).fetchone()[0],
                        )
                        self.assertEqual(
                            1,
                            catalog.connection.execute(
                                "SELECT COUNT(*) FROM operation_format_authorizations"
                            ).fetchone()[0],
                        )
                finally:
                    self.database = original_database

    def test_nuova_replacement_rejects_stale_sequence_authority_layout(self):
        fence, _before = self.prepare(
            "format", format_confirmation=False, sequence_authorization=True
        )
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]
            with catalog.transaction() as db:
                catalog._insert_layout_epoch_tx(  # noqa: SLF001 - stale-layout fixture
                    db,
                    "JOB-1",
                    kind="extension",
                    plan_id=None,
                    plan_digest_sha256="e" * 64,
                    created_at="2026-08-30T10:00:01+00:00",
                    target_sequences=(1,),
                    target_operations=("format",),
                )

        class DeferredExecutor:
            def submit(self, callback, *arguments):
                return Future()

        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=DeferredExecutor(),
            accepting=False,
        )
        with self.assertRaises(ValidationError):
            ProductionRecoveryRuntime(
                SimpleNamespace(),
                operations,
                SimpleNamespace(run_frozen_recovery=lambda _context: None),
            ).retry_current_cassette(blocker, fence)
        with Catalog(self.database) as catalog:
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT 1 FROM daemon_operations "
                    "WHERE id<>? AND job_id='JOB-1'",
                    (fence.operation_id,),
                ).fetchone()
            )
            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM format_confirmations"
                ).fetchone()[0],
            )
            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM operation_format_authorizations"
                ).fetchone()[0],
            )

    def test_native_replacement_submit_failure_replays_one_worker_submission(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]

        class RejectingExecutor:
            def __init__(self):
                self.calls = 0

            def submit(self, _callback, *_arguments):
                self.calls += 1
                if self.calls == 1:
                    raise OSError("worker unavailable")
                return Future()

        worker = RejectingExecutor()
        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=worker,
            accepting=False,
        )
        native = SimpleNamespace(run_frozen_recovery=lambda _context: None)
        runtime = ProductionRecoveryRuntime(SimpleNamespace(), operations, native)
        with self.assertRaisesRegex(OSError, "worker unavailable"):
            runtime.retry_current_cassette(blocker, fence)

        replayed = runtime.retry_current_cassette(blocker, fence)
        replayed_again = runtime.retry_current_cassette(blocker, fence)

        self.assertEqual(replayed.proof, replayed_again.proof)
        self.assertEqual(2, worker.calls)
        with Catalog(self.database) as catalog:
            replacement = catalog.get_operation(replayed.proof)
            self.assertEqual("running", replacement["state"])
            dispatch = catalog.native_recovery_dispatch(replayed.proof)
            self.assertEqual("admitted", dispatch["state"])

    def test_native_submit_response_loss_never_runs_callback_twice(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]
        callback_calls = []

        class ResponseLostExecutor:
            def __init__(self):
                self.calls = 0

            def submit(self, callback, *arguments):
                self.calls += 1
                callback(*arguments)
                raise OSError("submit response lost")

        worker = ResponseLostExecutor()
        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=worker,
            accepting=False,
        )
        native = SimpleNamespace(
            run_frozen_recovery=lambda context: callback_calls.append(
                context.record.id
            )
        )
        runtime = ProductionRecoveryRuntime(SimpleNamespace(), operations, native)
        first = runtime.retry_current_cassette(blocker, fence)
        second = runtime.retry_current_cassette(blocker, fence)

        self.assertEqual(first.proof, second.proof)
        self.assertEqual(1, worker.calls)
        self.assertEqual([first.proof], callback_calls)
        self.assertEqual(before, self.frozen_layout())

    def test_concurrent_native_submission_wrappers_have_one_durable_callback_owner(self):
        fence, _before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]

        class CapturingExecutor:
            def __init__(self):
                self.submissions = []

            def submit(self, callback, *arguments):
                self.submissions.append((callback, arguments))
                return Future()

        first_worker = CapturingExecutor()
        second_worker = CapturingExecutor()
        daemon = DaemonFence("daemon-recovery", fence.owner_generation)
        first_operations = OperationManager(
            lambda: Catalog(self.database),
            daemon,
            executor=first_worker,
            accepting=False,
        )
        second_operations = OperationManager(
            lambda: Catalog(self.database),
            daemon,
            executor=second_worker,
            accepting=False,
        )
        callback_calls = []
        native = SimpleNamespace(
            run_frozen_recovery=lambda context: callback_calls.append(
                context.record.id
            )
        )
        first = ProductionRecoveryRuntime(
            SimpleNamespace(), first_operations, native
        ).retry_current_cassette(blocker, fence)
        second = ProductionRecoveryRuntime(
            SimpleNamespace(), second_operations, native
        ).retry_current_cassette(blocker, fence)

        self.assertEqual(first.proof, second.proof)
        self.assertEqual(1, len(first_worker.submissions))
        self.assertEqual(1, len(second_worker.submissions))
        for callback, arguments in (
            first_worker.submissions[0],
            second_worker.submissions[0],
        ):
            callback(*arguments)

        self.assertEqual([first.proof], callback_calls)
        with Catalog(self.database) as catalog:
            self.assertEqual(
                "finished",
                catalog.native_recovery_dispatch(first.proof)["state"],
            )

    def test_native_replacement_submit_failure_is_durable_before_replay(self):
        fence, before = self.prepare("append", format_confirmation=False)
        with Catalog(self.database) as catalog:
            blocker = catalog.recover_interrupted_operations(
                catalog.current_daemon_fence()
            )[0]

        class RejectingExecutor:
            def submit(self, _callback, *_arguments):
                raise OSError("worker unavailable")

        operations = OperationManager(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            executor=RejectingExecutor(),
            accepting=False,
        )
        native = SimpleNamespace(run_frozen_recovery=lambda _context: None)
        with self.assertRaisesRegex(OSError, "worker unavailable"):
            ProductionRecoveryRuntime(
                SimpleNamespace(), operations, native
            ).retry_current_cassette(blocker, fence)

        self.assertEqual(before, self.frozen_layout())
        with Catalog(self.database) as catalog:
            self.assertEqual("cancelled", catalog.get_operation(blocker.id)["state"])
            replacement = catalog.active_operation()
            self.assertEqual("running", replacement["state"])
            self.assertEqual("archive.native", replacement["kind"])
            self.assertEqual(
                "admitted",
                catalog.native_recovery_dispatch(replacement["id"])["state"],
            )
        assessment = ProductionRecoveryDecisionSource(
            lambda: Catalog(self.database),
            DaemonFence("daemon-recovery", fence.owner_generation),
            SimpleNamespace(),
        ).assess(blocker.id)
        self.assertEqual(
            RecoveryAction.RETRY_CURRENT_CASSETTE,
            assessment.decision.actions[0],
        )


class _FakeCatalog:
    def __init__(self, calls: list[str], fail_at: str | None = None) -> None:
        self.calls = calls
        self.fail_at = fail_at
        self.commit_fences: list[OperationFence] = []
        self.recovery: tuple[str, str] | None = None
        self.phase: str | None = None
        self.recovered_terminal: object | None = None
        self.staged_files: list[dict[str, object]] = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise _Fault(name)

    def assert_operation_fence(self, _fence) -> None:
        self._call("catalog.assert")

    def transition_imported_cassette_phase(self, _fence, phase: str) -> None:
        self._call(f"phase.{phase}")
        self.phase = phase

    def get_operation(self, _operation_id: str):
        return {"phase": self.phase}

    def record_imported_unmount_timings(self, _fence, **_kwargs) -> None:
        self._call("catalog.unmount_timings")

    def record_imported_unmount_boundary(self, _fence, **_kwargs) -> None:
        return None

    def record_imported_ltfs_terminal(self, _fence, **_kwargs) -> None:
        result = _kwargs["unmount_result"]
        if result.observed_volume_label != self.expected_label:
            raise _Fault("catalog.ltfs_terminal")
        self._call("catalog.unmount_timings")

    def require_consumed_format_confirmation(
        self, _fence, _job_id, _sequence, _label
    ) -> None:
        self._call("catalog.format_confirmation")

    def get_library(self, library_id: str):
        return {"source_root": str(Path(self.source_root) / library_id)}

    def stage_imported_cassette(self, _fence, **_kwargs) -> str:
        self._call("catalog.stage_cassette")
        return "catalog-tape-test"

    def stage_imported_file(self, _fence, **_kwargs) -> int:
        self._call("catalog.stage_file")
        self.staged_files.append(dict(_kwargs))
        return 1

    def commit_imported_cassette_authority(
        self, fence: OperationFence, _tape_id: str, _block_ids: tuple[str, ...]
    ) -> None:
        self.commit_fences.append(fence)
        self._call("catalog.commit_authority")

    def commit_imported_cassette(
        self, fence: OperationFence, _tape_id: str, _block_ids: tuple[str, ...]
    ) -> str:
        self.commit_fences.append(fence)
        self._call("catalog.commit_regular")
        return "completed" if fence.operation_id.endswith("-20") else "waiting_media"

    def attest_imported_postcommit_unload(
        self, _fence, *, no_media_proven=None
    ) -> None:
        if no_media_proven is not True:
            raise AssertionError("exact no-media proof was not supplied")
        self._call("catalog.attest_unload")

    def finish_operation(
        self, _fence, state: str, *, error_class: str, error_code: str
    ) -> None:
        self.calls.append(f"catalog.finish.{state}")
        self.recovery = (error_class, error_code)

    def recover_imported_ltfs_terminal_and_commit(self, fence, terminal) -> str:
        self.calls.append("catalog.recover_terminal_commit")
        self.recovered_terminal = terminal
        self.phase = "unloading"
        return "waiting_media"


class _FakeBackupManager:
    def __init__(self, calls: list[str], fail_at: str | None) -> None:
        self.calls = calls
        self.fail_at = fail_at

    def create_for_operation(self, _fence, reason: str):
        name = "backup.pre" if reason.startswith("before-") else "backup.post"
        self.calls.append(name)
        if self.fail_at == name:
            raise _Fault(name)
        return Path(f"/{name}")


class _FakeBackend:
    def __init__(self, calls: list[str], fail_at: str | None) -> None:
        self.calls = calls
        self.fail_at = fail_at
        self.expected = None
        self.durable_terminal = None

        class NoMediaProbe:
            @staticmethod
            def identify_unmounted():
                calls.append("backend.probe_no_media")
                raise CommandFailed("probe_media", 3)

        self.media_identity_probe = NoMediaProbe()

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if self.fail_at == name:
            raise _Fault(name)

    def wait_for_media(self, expected, _stop) -> bool:
        self.expected = expected
        self._call("backend.wait")
        self._call("backend.identify_bind")
        return True

    def wait_for_preformat_media(self, expected, _stop) -> bool:
        return self.wait_for_media(expected, _stop)

    def format(self, _expected) -> None:
        self._call("backend.format")

    def mount(self, *, read_only: bool) -> MountedTape:
        self._call("backend.mount")
        if read_only:
            raise AssertionError("archive mount must be writable")
        return MountedTape(
            Path(self.mount_root),
            False,
            LtfsSessionReceipt(
                1,
                "operation-4",
                "11111111-1111-5111-8111-111111111111",
                "22222222-2222-4222-8222-222222222222",
                7,
                False,
                1,
                b"a" * 32,
                "session-a",
                "1" * 64,
                4711,
                8123,
                "2" * 64,
                b"b" * 32,
                b"c" * 32,
                True,
                self.expected.volume_label,
                "9" * 64,
            ),
        )

    def unmount(self, mounted, observer) -> UnmountResult:
        observer.finalization_started()
        if self.fail_at == "backend.unmount":
            self._call("backend.unmount")
        else:
            self.calls.append("backend.unmount")
        observer.mount_release_started()
        session = mounted.session_receipt
        terminal_fields = {
            "schema": 1,
            "stage": "terminal",
            "operation_id": session.receipt_operation_uuid,
            "volume_uuid": session.observed_volume_uuid,
            "prior_generation": session.observed_prior_generation,
            "new_generation": session.observed_prior_generation + 1,
            "bytes_valid": True,
            "bytes": 4,
            "files_valid": True,
            "files": 1,
            "phase_duration_ns": [0] * 11,
            "capture_duration_ns": 0,
            "device_close_duration_ns": 0,
            "device_close_result_valid": True,
            "device_close_result": 0,
            "catalog_ack_duration_ns": 0,
            "media_committed": True,
            "catalog_acknowledged": True,
            "cleanup_failed": False,
            "result": 0,
        }
        terminal_sha256 = hashlib.sha256(
            (json.dumps(terminal_fields, separators=(",", ":")) + "\n").encode("ascii")
        ).hexdigest()
        standalone = LtfsStandaloneReceipt(
            **{
                **terminal_fields,
                "phase_duration_ns": tuple(terminal_fields["phase_duration_ns"]),
            },
            terminal_sha256=terminal_sha256,
        )
        finalization = LtfsFinalizationReceipt(
            1,
            session,
            standalone,
            b"d" * 32,
            b"e" * 32,
            b"f" * 32,
            True,
            True,
        )
        if self.fail_at == "backend.unmount_response_lost":
            self.durable_terminal = finalization
            raise _Fault("backend.unmount_response_lost")
        return UnmountResult(
            0.1,
            0.2,
            finalization,
        )

    def recover_pending_ltfs_session(self):
        self.calls.append("backend.recover_terminal")
        return self.durable_terminal

    def unload(self) -> None:
        self._call("backend.unload")


class _FakeWriter:
    def __init__(self, calls: list[str], fail_at: str | None) -> None:
        self.calls = calls
        self.fail_at = fail_at

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def append(self, _record) -> None:
        self.calls.append("manifest.append")
        if self.fail_at == "manifest.append":
            raise _Fault("manifest.append")

    def finalize(self, _block) -> None:
        self.calls.append("manifest.finalize")
        if self.fail_at == "manifest.finalize":
            raise _Fault("manifest.finalize")


class _TelemetrySink:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def begin_window(self) -> None:
        self.calls.append("telemetry.begin")

    def record_file(self, byte_count: int) -> None:
        self.calls.append(f"telemetry.file.{byte_count}")

    def add_duration(self, phase: str, seconds: float) -> None:
        self.calls.append(f"telemetry.duration.{phase}.{seconds}")

    def start_phase(self, phase: str) -> None:
        self.calls.append(f"telemetry.start.{phase}")

    def finish_phase(self, phase: str) -> None:
        self.calls.append(f"telemetry.finish.{phase}")


class ArchiveRunnerTests(unittest.TestCase):
    def test_retry_unload_proves_no_media_before_durable_attestation(self) -> None:
        calls: list[str] = []

        class CatalogProbe:
            state = "recovery_required"

            def attest_imported_postcommit_unload(
                self,
                _fence,
                *,
                no_media_proven=None,
                require_durable_no_media=False,
            ):
                calls.append(
                    f"attest.{no_media_proven}.{require_durable_no_media}"
                )
                if require_durable_no_media:
                    raise ValidationError("no durable exact proof")
                return "eject-proof"

            def get_operation(self, _operation_id):
                return {"state": self.state}

        class NoMediaProbe:
            def identify_unmounted(self):
                calls.append("probe.no_media")
                raise CommandFailed("probe_media", 3)

        catalog = CatalogProbe()
        backend = SimpleNamespace(
            unload=lambda: calls.append("unload"),
            media_identity_probe=NoMediaProbe(),
        )
        runtime = ProductionRecoveryRuntime.__new__(ProductionRecoveryRuntime)
        runtime._archive = SimpleNamespace(
            _catalog_factory=lambda: nullcontext(catalog)
        )
        runtime._recovery_backend = lambda *_args: backend

        def safe_release(_blocker, _fence):
            calls.append("safe_release")
            catalog.state = "cancelled"

        runtime.safe_release = safe_release
        blocker = SimpleNamespace(id="operation-4")
        fence = RecoveryCommandFence("operation-4", 7)

        result = runtime.retry_unload(blocker, fence)

        self.assertEqual("eject-proof", result.proof)
        self.assertEqual(
            [
                "attest.None.True",
                "unload",
                "probe.no_media",
                "attest.True.False",
                "safe_release",
            ],
            calls,
        )

    def test_retry_unload_replays_durable_proof_without_touching_drive(self) -> None:
        calls: list[str] = []

        class CatalogProbe:
            state = "recovery_required"

            def attest_imported_postcommit_unload(
                self,
                _fence,
                *,
                no_media_proven=None,
                require_durable_no_media=False,
            ):
                calls.append(
                    f"attest.{no_media_proven}.{require_durable_no_media}"
                )
                return "durable-eject-proof"

            def get_operation(self, _operation_id):
                return {"state": self.state}

        catalog = CatalogProbe()
        runtime = ProductionRecoveryRuntime.__new__(ProductionRecoveryRuntime)
        runtime._archive = SimpleNamespace(
            _catalog_factory=lambda: nullcontext(catalog)
        )
        runtime._recovery_backend = lambda *_args: self.fail(
            "durably attested unload must not touch the drive"
        )

        def safe_release(_blocker, _fence):
            calls.append("safe_release")
            catalog.state = "cancelled"

        runtime.safe_release = safe_release

        result = runtime.retry_unload(
            SimpleNamespace(id="operation-4"),
            RecoveryCommandFence("operation-4", 7),
        )

        self.assertEqual("durable-eject-proof", result.proof)
        self.assertEqual(["attest.None.True", "safe_release"], calls)

    def test_recovery_selects_preformat_probe_for_unmounted_format_media(self) -> None:
        calls: list[str] = []

        class Probe:
            def identify_mounted(self, _path: Path):
                calls.append("mounted")
                return "mounted-fields"

            def identify_preformat(self):
                calls.append("pre-format")
                return "pre-format-fields"

            def identify_unmounted(self):
                calls.append("unmounted")
                return "unmounted-fields"

        probe = Probe()
        mount_path = Path("/mnt/tape")

        self.assertEqual(
            "pre-format-fields",
            ProductionRecoveryRuntime._identify_recovery_media(
                probe,
                mounted=False,
                mount_path=mount_path,
                cassette_operation="format",
            ),
        )
        self.assertEqual(
            "unmounted-fields",
            ProductionRecoveryRuntime._identify_recovery_media(
                probe,
                mounted=False,
                mount_path=mount_path,
                cassette_operation="append",
            ),
        )
        self.assertEqual(
            "mounted-fields",
            ProductionRecoveryRuntime._identify_recovery_media(
                probe,
                mounted=True,
                mount_path=mount_path,
                cassette_operation="format",
            ),
        )
        self.assertEqual(["pre-format", "unmounted", "mounted"], calls)

    @unittest.skipUnless(
        os.environ.get("LTO_TEST_ROOT_OWNED_LTFS_INFO"),
        "requires authorized root-owned ltfs-info fixture",
    )
    def test_authorized_root_owned_ltfs_info_fixture_contract(self) -> None:
        fixture = Path(os.environ["LTO_TEST_ROOT_OWNED_LTFS_INFO"])
        status = fixture.stat(follow_symlinks=False)
        self.assertTrue(fixture.is_absolute())
        self.assertFalse(fixture.is_symlink())
        self.assertEqual(0, status.st_uid)
        self.assertEqual(0o755, status.st_mode & 0o777)

    @unittest.skipUnless(
        all(
            os.environ.get(name)
            for name in (
                "LTO_TEST_ROOT_OWNED_LTFS_INFO",
                "LTO_TEST_BROKER_SOCKET",
                "LTO_TEST_BROKER_CAPABILITY",
                "LTO_TEST_TAPE_BY_ID",
                "LTO_TEST_SCSI_BY_ID",
                "LTO_TEST_MOUNT_PATH",
            )
        ),
        "requires authorized broker and root-owned ltfs-info fixture",
    )
    def test_authorized_brokered_ltfs_info_e2e(self) -> None:
        """No mocks: catalog fence → broker release → subprocess → typed provider."""
        from ltobackup.broker.client import UnixBrokeredCgroupScopeApi

        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        catalog_path = root / "catalog.db"
        fixture = Path(os.environ["LTO_TEST_ROOT_OWNED_LTFS_INFO"])
        settings = LinuxSettings(
            tape_device_path=Path(os.environ["LTO_TEST_TAPE_BY_ID"]),
            scsi_device_path=Path(os.environ["LTO_TEST_SCSI_BY_ID"]),
            mount_path=Path(os.environ["LTO_TEST_MOUNT_PATH"]),
        )
        with Catalog(catalog_path) as catalog:
            catalog.initialize()
            daemon_fence = catalog.claim_daemon_owner("e2e-daemon")
            candidate = OperationRecord(
                "e2e-operation",
                "archive.resume",
                "running",
                None,
                "e2e-key",
                "admin",
                "job",
                4,
                "2026-08-22T00:00:00+00:00",
                None,
            )
            target = HardwareTargetBinding.from_verified_inputs(
                settings.mount_path,
                "e2e-tape-identity",
                "e2e-scsi-identity",
                ("archive.resume", "job", "4", "TAPE04", "", ""),
            )
            record = catalog.admit_operation(
                candidate,
                daemon_fence,
                admission_open=True,
                hardware_target=target,
            ).record
        context = OperationContext(
            record,
            OperationFence(record.id, daemon_fence.generation),
            lambda: Catalog(catalog_path),
        )
        capability = load_broker_capability(os.environ["LTO_TEST_BROKER_CAPABILITY"])
        api = UnixBrokeredCgroupScopeApi(
            Path(os.environ["LTO_TEST_BROKER_SOCKET"]), capability
        )
        api.assert_ready()
        probe = LinuxProcessProbe()
        with Catalog(catalog_path) as catalog:
            supervisor = TrackedCommandSupervisor(
                catalog=catalog,
                daemon_fence=daemon_fence,
                launcher=ForkExecCommandLauncher(
                    BrokeredCgroupExecutionScopeManager(api, capability),
                    ReadOnlyCgroupPrivilegeBoundary(),
                ),
                process_probe=probe,
                process_terminator=PosixProcessTerminator(probe),
            )
            fields = BrokeredLtfsInfoMediaIdentityProbe(
                supervisor, context, settings, fixture
            ).identify_unmounted()
            commands = catalog.active_hardware_commands()
        self.assertEqual("TAPE04", fields.mam_barcode)
        self.assertEqual((), commands)

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.mount_root = self.root / "mount"
        self.mount_root.mkdir()
        self.source_root = self.root / "sources"
        source = self.source_root / "LIB1" / "folder" / "clip.bin"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"data")
        self.calls: list[str] = []
        item = FrozenItem(4, 1, "LIB1", "folder/clip.bin", 4, source.stat().st_mtime_ns)
        cassette = FrozenCassette(
            4,
            "TAPE04",
            "SERIAL-TEST-04",
            "format",
            "waiting_media",
            1,
            4,
            None,
            None,
            0,
            0,
            None,
            None,
            None,
            False,
            (item,),
        )
        self.plan = FrozenJobPlan(
            "JOB-MIGRATION",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            "pre_cutover",
            (cassette,),
            (("LIB1", source.parent.parent),),
            False,
        )
        record = OperationRecord(
            "operation-4",
            "archive.resume",
            "running",
            None,
            "resume-4",
            "admin",
            "JOB-MIGRATION",
            4,
            "2026-08-22T00:00:00+00:00",
            None,
        )
        self.fence = OperationFence("operation-4", 7)
        self.context = OperationContext(record, self.fence, lambda: self.catalog)

    def runner(
        self,
        fail_at: str | None = None,
        *,
        sequence: int = 4,
        telemetry_sink=None,
        event_sink=None,
    ):
        if sequence != 4:
            original = self.plan.cassettes[0]
            cassette = FrozenCassette(
                sequence,
                f"TAPE{sequence:02d}",
                f"SERIAL-TEST-{sequence:02d}",
                "append",
                "waiting_media",
                original.planned_files,
                original.planned_bytes,
                None,
                None,
                0,
                0,
                None,
                None,
                None,
                False,
                tuple(
                    FrozenItem(
                        sequence,
                        item.item_sequence,
                        item.library_id,
                        item.relative_path,
                        item.size,
                        item.mtime_ns,
                    )
                    for item in original.items
                ),
            )
            self.plan = FrozenJobPlan(
                self.plan.job_id,
                self.plan.assignment_sha256,
                self.plan.cassette_plan_sha256,
                self.plan.completed_evidence_sha256,
                self.plan.bundle_sha256,
                "active_linux",
                (cassette,),
                self.plan._library_roots,
                False,
            )
            self.context = OperationContext(
                OperationRecord(
                    f"operation-{sequence}",
                    "archive.resume",
                    "running",
                    None,
                    f"resume-{sequence}",
                    "admin",
                    "JOB-MIGRATION",
                    sequence,
                    "2026-08-22T00:00:00+00:00",
                    None,
                ),
                OperationFence(f"operation-{sequence}", 7),
                lambda: self.catalog,
            )
        self.catalog = _FakeCatalog(self.calls, fail_at)
        self.catalog.source_root = self.source_root
        self.catalog.expected_label = self.plan.cassettes[0].physical_label
        backend = _FakeBackend(self.calls, fail_at)
        backend.mount_root = self.mount_root
        backend.fence = self.context.fence
        cassette = self.plan.cassettes[0]
        backend.expected = ExpectedMedia(
            "archive.resume",
            self.plan.job_id,
            cassette.sequence,
            cassette.physical_label,
            None,
            None,
        )

        def copy_file(request):
            self.calls.append("copy.file")
            if fail_at == "copy.file":
                raise _Fault("copy.file")
            request.destination.parent.mkdir(parents=True, exist_ok=True)
            request.destination.write_bytes(b"data")
            return CopyResult("e" * 64, 4, 0.1, 0.2, 0.3)

        return ArchiveRunner(
            catalog_factory=lambda: nullcontext(self.catalog),
            backups=_FakeBackupManager(self.calls, fail_at),
            backend=backend,
            host_staging_root=self.root / "staging",
            buffer_bytes=1024,
            plan_loader=lambda _catalog, _job_id: self.plan,
            copy_file=copy_file,
            manifest_writer_factory=lambda **_kwargs: _FakeWriter(self.calls, fail_at),
            telemetry_sink=telemetry_sink,
            event_sink=event_sink,
        )

    def test_archive_operational_events_follow_durable_write_and_eject_boundaries(self):
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        outcome = self.runner(event_sink=sink).resume(
            "JOB-MIGRATION", self.context, lambda: False
        )

        self.assertEqual("succeeded", outcome.state)
        phase_results = [(event.phase, event.code) for event in sink.events]
        for expected in (
            ("identify", "ltfs.phase.succeeded"),
            ("format", "ltfs.phase.succeeded"),
            ("mount", "ltfs.phase.succeeded"),
            ("copy", "ltfs.phase.succeeded"),
            ("finalizing_index", "ltfs.phase.succeeded"),
            ("unmount", "ltfs.phase.succeeded"),
            ("commit", "ltfs.phase.succeeded"),
            ("eject", "ltfs.phase.succeeded"),
        ):
            self.assertIn(expected, phase_results)
        eject_success = next(
            event for event in sink.events
            if event.phase == "eject" and event.code == "ltfs.phase.succeeded"
        )
        self.assertEqual("operation-4", eject_success.operation_id)
        self.assertEqual("TAPE04", eject_success.cassette_label)

    def test_automatic_recovery_supervisor_keeps_sink_and_closed_correlation(self) -> None:
        sink = object()
        runtime = ProductionRecoveryRuntime.__new__(ProductionRecoveryRuntime)
        runtime._archive = SimpleNamespace(
            _scope_manager="scope",
            _privilege_boundary="boundary",
            _event_sink=sink,
        )
        fence = RecoveryCommandFence("operation-4", 7)

        with patch(
            "ltobackup.daemon.archive_runtime._production_supervisor",
            return_value="supervisor",
        ) as supervisor_type:
            result = runtime._recovery_supervisor(
                "catalog",
                DaemonFence("daemon-7", 7),
                fence,
                job_id="JOB-MIGRATION",
                cassette_label="TAPE04",
                cassette_sequence=4,
            )

        self.assertEqual("supervisor", result)
        self.assertIs(supervisor_type.call_args.kwargs["event_sink"], sink)
        correlation = supervisor_type.call_args.kwargs["operation_context"]
        self.assertEqual("operation-4", correlation.operation_id)
        self.assertEqual("JOB-MIGRATION", correlation.job_id)
        self.assertEqual("TAPE04", correlation.cassette_label)
        self.assertEqual(4, correlation.cassette_sequence)
        self.assertEqual(7, correlation.daemon_generation)

    def test_archive_operational_events_close_every_started_phase_on_failure(self):
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        outcome = self.runner(
            "backend.unmount", event_sink=sink
        ).resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual("recovery_required", outcome.state)
        for phase in {
            event.phase
            for event in sink.events
            if event.code == "ltfs.phase.started"
        }:
            terminal = [
                event.code
                for event in sink.events
                if event.phase == phase and event.code != "ltfs.phase.started"
            ]
            self.assertTrue(terminal, f"started phase {phase} has no terminal event")

    def test_archive_eject_success_requires_exact_no_media_proof(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        class LoadedMediaProbe:
            @staticmethod
            def identify_unmounted():
                return object()

        sink = Sink()
        runner = self.runner(event_sink=sink)
        runner.backend.media_identity_probe = LoadedMediaProbe()

        outcome = runner.resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual("recovery_required", outcome.state)
        self.assertEqual("postcommit_eject_unproven", outcome.error_code)
        self.assertEqual(
            ["ltfs.phase.started", "ltfs.phase.failed"],
            [event.code for event in sink.events if event.phase == "eject"],
        )

    def test_archive_never_reclassifies_succeeded_mount_after_staging_failure(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        outcome = self.runner(
            "catalog.stage_cassette", event_sink=sink
        ).resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual("recovery_required", outcome.state)
        self.assertEqual(
            ["ltfs.phase.started", "ltfs.phase.succeeded"],
            [event.code for event in sink.events if event.phase == "mount"],
        )

    def test_archive_ltfs_terminal_persistence_failure_has_one_terminal_per_phase(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        outcome = self.runner(
            "catalog.unmount_timings", event_sink=sink
        ).resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual("recovery_required", outcome.state)
        for phase in ("sync", "finalizing_index", "unmount"):
            self.assertEqual(
                ["ltfs.phase.started", "ltfs.phase.failed"],
                [event.code for event in sink.events if event.phase == phase],
            )

    def test_managed_source_mismatch_blocks_before_plan_or_hardware_reads(self):
        runner = self.runner()

        def reject(_job_id, _operation_id, _generation):
            self.calls.append("managed_source.admit")
            raise RuntimeError("share_identity_changed")

        runner.managed_source_admission = reject
        with self.assertRaisesRegex(RuntimeError, "share_identity_changed"):
            runner.resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual(["managed_source.admit"], self.calls)

    def test_success_orders_every_durable_boundary_and_uses_exact_four_fence(self):
        outcome = self.runner().resume("JOB-MIGRATION", self.context, lambda: False)

        ordered = (
            "backup.pre",
            "phase.identifying_media",
            "catalog.format_confirmation",
            "backend.wait",
            "backend.identify_bind",
            "phase.formatting_media",
            "backend.format",
            "phase.mounting",
            "backend.mount",
            "catalog.stage_cassette",
            "phase.writing",
            "copy.file",
            "catalog.stage_file",
            "manifest.append",
            "phase.writing_manifest",
            "manifest.finalize",
            "phase.finalizing_index",
            "backend.unmount",
            "phase.unmounting",
            "catalog.unmount_timings",
            "phase.committing",
            "catalog.commit_authority",
            "backup.post",
            "phase.unloading",
            "backend.unload",
            "backend.probe_no_media",
            "catalog.attest_unload",
        )
        positions = [self.calls.index(name) for name in ordered]
        self.assertEqual(sorted(positions), positions)
        self.assertEqual((self.fence,), tuple(self.catalog.commit_fences))
        self.assertEqual(1, self.calls.count("backend.identify_bind"))
        self.assertEqual("waiting_media", outcome.next_state)

    def test_physical_qualification_contract_uses_real_runner_eject_boundary(self):
        runner = self.runner()

        outcome = runner.resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertIsInstance(runner, ArchiveRunner)
        self.assertEqual("succeeded", outcome.state)
        self.assertLess(
            self.calls.index("backend.unload"),
            self.calls.index("backend.probe_no_media"),
        )
        self.assertLess(
            self.calls.index("backend.probe_no_media"),
            self.calls.index("catalog.attest_unload"),
        )

    def test_archive_maps_nonportable_source_name_only_on_ltfs(self) -> None:
        """The production Linux runner must never create a trailing-space LTFS name."""
        source = self.source_root / "LIB1" / "I Flintstones " / "episode.mkv"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"data")
        original = self.plan.cassettes[0]
        cassette = FrozenCassette(
            original.sequence,
            original.physical_label,
            original.tape_serial,
            original.operation,
            original.status,
            original.planned_files,
            original.planned_bytes,
            original.tape_id,
            original.block_id,
            original.copied_files,
            original.copied_bytes,
            original.started_at,
            original.completed_at,
            original.error,
            original.reuse_registered,
            (
                FrozenItem(
                    4,
                    1,
                    "LIB1",
                    "I Flintstones /episode.mkv",
                    4,
                    source.stat().st_mtime_ns,
                ),
            ),
        )
        self.plan = FrozenJobPlan(
            self.plan.job_id,
            self.plan.assignment_sha256,
            self.plan.cassette_plan_sha256,
            self.plan.completed_evidence_sha256,
            self.plan.bundle_sha256,
            self.plan.authority_state,
            (cassette,),
            self.plan._library_roots,
            False,
        )
        records = []
        runner = self.runner()

        class CapturingWriter(_FakeWriter):
            def append(writer_self, record) -> None:
                records.append(record)
                super().append(record)

        runner.manifest_writer_factory = lambda **_kwargs: CapturingWriter(
            self.calls, None
        )

        runner.resume("JOB-MIGRATION", self.context, lambda: False)

        mapped_suffix = Path("files/~lto1~I Flintstones%20/episode.mkv")
        copied = tuple(self.mount_root.glob("libraries/LIB1/blocks/*"))[0]
        self.assertEqual(b"data", (copied / mapped_suffix).read_bytes())
        self.assertFalse((copied / "files" / "I Flintstones ").exists())
        self.assertTrue(self.catalog.staged_files[0]["tape_relative_path"].endswith(
            mapped_suffix.as_posix()
        ))
        self.assertEqual(
            "I Flintstones /episode.mkv", records[0].relative_path
        )
        self.assertTrue(records[0].tape_relative_path.endswith(mapped_suffix.as_posix()))

    def test_archive_runner_never_treats_legacy_serial_as_expected_mam(self) -> None:
        runner = self.runner()
        cassette = self.plan.cassettes[0]
        runner.backend.expected = ExpectedMedia(
            "archive.resume",
            self.plan.job_id,
            cassette.sequence,
            cassette.physical_label,
            None,
            None,
        )

        outcome = runner.resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual("waiting_media", outcome.next_state)

    def test_production_resume_threads_exact_authenticated_ltfs_client_to_backend(
        self,
    ) -> None:
        target = HardwareTargetBinding.from_verified_inputs(
            self.mount_root,
            "stable-tape",
            "stable-scsi",
            ("archive.resume", "JOB-MIGRATION", "4", "TAPE04", "", ""),
        )

        class RuntimeCatalog:
            def __enter__(catalog_self):
                return catalog_self

            def __exit__(catalog_self, *_args):
                return None

            def hardware_target_binding(catalog_self, _operation_id):
                return target

            def current_daemon_fence(catalog_self):
                return DaemonFence("daemon-a", self.context.fence.owner_generation)

            def get_operation(catalog_self, operation_id):
                self.assertEqual(self.context.record.id, operation_id)
                return {"copy_buffer_bytes": 2 * 1024**2}

        ltfs_sessions = object()
        self.catalog = RuntimeCatalog()
        resume = ProductionArchiveResume.__new__(ProductionArchiveResume)
        resume._paths = SimpleNamespace(state_dir=self.root)
        resume._settings = SimpleNamespace(buffer_bytes=4096)
        resume._backups = object()
        resume._telemetry_sink = lambda: object()
        resume._stop_requested = lambda: False
        resume._scope_manager = object()
        resume._privilege_boundary = object()
        resume._ltfs_info_binary = Path("/usr/libexec/lto-archiver/ltfs-info")
        resume._catalog_factory = lambda: self.catalog
        resume._device_identities = object()
        resume._ltfs_sessions = ltfs_sessions

        with (
            patch(
                "ltobackup.daemon.archive_runtime.FrozenJobPlan.load",
                return_value=self.plan,
            ),
            patch(
                "ltobackup.daemon.archive_runtime._production_supervisor",
                return_value="daemon-supervisor",
            ),
            patch(
                "ltobackup.daemon.archive_runtime.BrokeredLtfsInfoMediaIdentityProbe",
                return_value="media-probe",
            ),
            patch("ltobackup.daemon.archive_runtime.LinuxLtfsBackend") as backend_class,
            patch("ltobackup.daemon.archive_runtime.ArchiveRunner") as runner_class,
        ):
            backend_class.target_binding_from.return_value = target
            runner_class.return_value.resume.return_value = SimpleNamespace(
                state="recovery_required"
            )
            resume(self.context)
            resume(self.context)

        self.assertEqual(2, backend_class.call_count)
        self.assertTrue(
            all(
                call.kwargs["buffer_bytes"] == 2 * 1024**2
                for call in runner_class.call_args_list
            )
        )
        self.assertTrue(
            all(
                call.kwargs["ltfs_sessions"] is ltfs_sessions
                and call.kwargs["supervisor"] == "daemon-supervisor"
                and call.kwargs["expected"].volume_label
                == self.plan.cassettes[0].physical_label
                and call.kwargs["expected"].volume_serial is None
                for call in backend_class.call_args_list
            )
        )
        self.assertEqual(
            [
                mock_call("JOB-MIGRATION", self.context, resume._stop_requested),
                mock_call("JOB-MIGRATION", self.context, resume._stop_requested),
            ],
            runner_class.return_value.resume.call_args_list,
        )

    def test_production_startup_reconciler_retries_only_exact_archive_blocker(
        self,
    ) -> None:
        resume = ProductionArchiveResume.__new__(ProductionArchiveResume)
        daemon_fence = DaemonFence("daemon-recovery", 12)
        archive = SimpleNamespace(
            id="operation-archive",
            kind="archive.resume",
            state="recovery_required",
        )
        unrelated = SimpleNamespace(
            id="operation-other",
            kind="diagnostic",
            state="recovery_required",
        )
        operations = SimpleNamespace(
            daemon_fence=daemon_fence,
            reconcile_admission_blockers=lambda: (archive, unrelated),
        )

        with patch.object(
            resume, "reconcile_pending_ltfs_operation", return_value=None
        ) as recover_pending:
            resume.reconcile_pending_ltfs_startup(operations)

        recover_pending.assert_called_once_with(
            "operation-archive",
            RecoveryCommandFence("operation-archive", daemon_fence.generation),
        )

    def test_production_recovery_imports_commit_and_never_unloads_or_finishes(self):
        calls: list[object] = []
        target = HardwareTargetBinding.from_verified_inputs(
            self.mount_root,
            "stable-tape",
            "stable-scsi",
            ("archive.resume", "JOB-MIGRATION", "4", "TAPE04", "", ""),
        )
        fence = RecoveryCommandFence("operation-4", 8)
        terminal = object()

        class RecoveryCatalog:
            def __enter__(catalog_self):
                return catalog_self

            def __exit__(catalog_self, *_args):
                return None

            def assert_command_fence(catalog_self, observed_fence):
                calls.append(("assert", observed_fence))

            def get_operation(catalog_self, _operation_id):
                return {
                    "state": "recovery_required",
                    "kind": "archive.resume",
                    "job_id": "JOB-MIGRATION",
                    "cassette_sequence": 4,
                }

            def hardware_target_binding(catalog_self, _operation_id):
                return target

            def current_daemon_fence(catalog_self):
                return DaemonFence("daemon-restarted", fence.owner_generation)

            def recover_imported_ltfs_terminal_and_commit(
                catalog_self, observed_fence, observed_terminal
            ):
                calls.append(("import_commit", observed_fence, observed_terminal))
                return "waiting_media"

        resume = ProductionArchiveResume.__new__(ProductionArchiveResume)
        resume._settings = SimpleNamespace()
        resume._scope_manager = object()
        resume._privilege_boundary = object()
        resume._ltfs_sessions = object()
        resume._device_identities = object()
        resume._catalog_factory = RecoveryCatalog

        with (
            patch(
                "ltobackup.daemon.archive_runtime.FrozenJobPlan.load",
                return_value=self.plan,
            ),
            patch(
                "ltobackup.daemon.archive_runtime._production_supervisor",
                return_value="recovery-supervisor",
            ),
            patch("ltobackup.daemon.archive_runtime.LinuxLtfsBackend") as backend_class,
        ):
            backend_class.target_binding_from.return_value = target
            backend_class.return_value.recover_pending_ltfs_session.return_value = (
                terminal
            )
            recovered = resume.reconcile_pending_ltfs_operation(
                fence.operation_id, fence
            )

        self.assertIs(terminal, recovered)
        self.assertIn(("assert", fence), calls)
        self.assertIn(("import_commit", fence, terminal), calls)
        backend_class.return_value.unload.assert_not_called()
        self.assertFalse(
            any(call[0] in {"unload", "eject", "finish"} for call in calls)
        )

    def test_copy_finalization_unmount_and_unload_feed_the_runtime_telemetry_sink(self):
        runner = self.runner(telemetry_sink=_TelemetrySink(self.calls))

        runner.resume("JOB-MIGRATION", self.context, lambda: False)

        for call in (
            "telemetry.begin",
            "telemetry.file.4",
            "telemetry.duration.smb_read.0.1",
            "telemetry.duration.copy.0.2",
            "telemetry.duration.close.0.3",
            "telemetry.duration.finalization.0.1",
            "telemetry.duration.unmount.0.2",
            "telemetry.start.unload",
            "telemetry.finish.unload",
        ):
            self.assertIn(call, self.calls)
        self.assertEqual(1, self.calls.count("telemetry.begin"))
        self.assertLess(
            self.calls.index("telemetry.begin"), self.calls.index("copy.file")
        )

    def test_sequence_five_uses_only_the_new_fenced_regular_commit(self):
        runner = self.runner(sequence=5)
        runner.resume("JOB-MIGRATION", self.context, lambda: False)
        self.assertIn("catalog.commit_regular", self.calls)
        self.assertNotIn("catalog.commit_authority", self.calls)
        self.assertNotIn("catalog.format_confirmation", self.calls)
        self.assertNotIn("backend.format", self.calls)

    def test_sequence_twenty_commits_completed_and_attests_exact_unload(self):
        runner = self.runner(sequence=20)
        outcome = runner.resume("JOB-MIGRATION", self.context, lambda: False)
        self.assertEqual("completed", outcome.next_state)
        self.assertEqual(1, self.calls.count("backend.identify_bind"))
        self.assertEqual(1, self.calls.count("backend.unload"))
        self.assertEqual(1, self.calls.count("catalog.attest_unload"))

    def test_prehardware_failures_raise_without_persisting_recovery(self):
        for boundary in ("backup.pre", "phase.identifying_media"):
            with self.subTest(boundary=boundary):
                self.calls.clear()
                with self.assertRaises(_Fault):
                    self.runner(boundary).resume(
                        "JOB-MIGRATION", self.context, lambda: False
                    )
                self.assertNotIn("backend.unload", self.calls)
                self.assertIsNone(self.catalog.recovery)

    def test_each_precommit_hardware_failure_blocks_replacement_without_unload(self):
        boundaries = (
            "backend.wait",
            "backend.identify_bind",
            "catalog.format_confirmation",
            "phase.formatting_media",
            "backend.format",
            "phase.mounting",
            "backend.mount",
            "catalog.stage_cassette",
            "phase.writing",
            "copy.file",
            "catalog.stage_file",
            "phase.writing_manifest",
            "manifest.append",
            "manifest.finalize",
            "backend.unmount",
            "phase.unmounting",
            "catalog.unmount_timings",
            "phase.committing",
            "catalog.commit_authority",
            "phase.finalizing_index",
        )
        for boundary in boundaries:
            with self.subTest(boundary=boundary):
                self.calls.clear()
                outcome = self.runner(boundary).resume(
                    "JOB-MIGRATION", self.context, lambda: False
                )
                self.assertEqual("recovery_required", outcome.state)
                self.assertEqual("operator_required", outcome.error_class)
                self.assertIsNotNone(self.catalog.recovery)
                self.assertNotIn("backend.unload", self.calls)

    def test_response_loss_recovers_terminal_before_marking_recovery_required(self):
        runner = self.runner("backend.unmount_response_lost")
        outcome = runner.resume("JOB-MIGRATION", self.context, lambda: False)

        self.assertEqual("recovery_required", outcome.state)
        self.assertEqual("unloading", outcome.phase)
        self.assertIs(runner.backend.durable_terminal, self.catalog.recovered_terminal)
        self.assertIn("backend.recover_terminal", self.calls)
        self.assertIn("catalog.recover_terminal_commit", self.calls)
        self.assertNotIn("backend.unload", self.calls)

    def test_finalizing_index_persistence_failure_sends_no_unmount_request(self):
        outcome = self.runner("phase.finalizing_index").resume(
            "JOB-MIGRATION", self.context, lambda: False
        )

        self.assertEqual("recovery_required", outcome.state)
        self.assertNotIn("backend.unmount", self.calls)
        self.assertNotIn("backend.unload", self.calls)

    def test_postcommit_backup_and_unload_failures_require_recovery(self):
        for boundary, code in (
            ("backup.post", "postcommit_backup_failed"),
            ("backend.unload", "unload_failed"),
            ("catalog.attest_unload", "postcommit_attestation_failed"),
        ):
            with self.subTest(boundary=boundary):
                self.calls.clear()
                outcome = self.runner(boundary).resume(
                    "JOB-MIGRATION", self.context, lambda: False
                )
                self.assertEqual("recovery_required", outcome.state)
                self.assertEqual(code, outcome.error_code)
                self.assertEqual(("operator_required", code), self.catalog.recovery)

    def test_manifest_append_fault_persists_copy_recovery_without_unload(self):
        outcome = self.runner("manifest.append").resume(
            "JOB-MIGRATION", self.context, lambda: False
        )
        self.assertEqual("recovery_required", outcome.state)
        self.assertEqual("operator_required", outcome.error_class)
        self.assertEqual("copy_or_manifest_failed", outcome.error_code)
        self.assertEqual(
            ("operator_required", "copy_or_manifest_failed"), self.catalog.recovery
        )
        self.assertNotIn("backend.unload", self.calls)

    def test_cassette_one_through_three_are_rejected_before_any_boundary(self):
        runner = self.runner(sequence=3)
        with self.assertRaises(ValidationError):
            runner.resume("JOB-MIGRATION", self.context, lambda: False)
        self.assertEqual([], self.calls)

    def test_backend_must_be_bound_to_the_exact_operation_fence(self):
        runner = self.runner()
        runner.backend.fence = OperationFence("different-operation", 7)
        with self.assertRaises(ValidationError):
            runner.resume("JOB-MIGRATION", self.context, lambda: False)
        self.assertEqual([], self.calls)

    def test_operation_manager_rejects_replacement_after_recovery_is_persisted(self):
        database = self.root / "operation-manager.db"
        with Catalog(database) as catalog:
            catalog.initialize()
            source = self.root / "operation-manager-source"
            source.mkdir()
            catalog.add_library("LIB-RECOVERY", "Recovery library", str(source))
            catalog.create_automatic_job(
                "JOB-MIGRATION",
                "LIB-RECOVERY",
                "TAPE0",
                "AUTO",
                [
                    (f"TAPE{sequence:02d}", f"TAPE{sequence:02d}", 0, 0)
                    for sequence in range(1, 6)
                ],
            )
            daemon = catalog.claim_daemon_owner("daemon-recovery-test")
        manager = OperationManager(lambda: Catalog(database), daemon)
        persisted = threading.Event()

        def require_recovery(context: OperationContext) -> None:
            with Catalog(database) as catalog:
                catalog.finish_operation(
                    context.fence,
                    "recovery_required",
                    error_class="operator_required",
                    error_code="recovery_required",
                )
            persisted.set()

        target = HardwareTargetBinding.from_verified_inputs(
            self.root / "manager-mount",
            "manager-tape",
            "manager-scsi",
            ("archive.resume", "JOB-MIGRATION", "5", "TAPE05", "", ""),
        )
        manager.start(
            "archive.resume",
            "recovery-operation",
            "admin",
            require_recovery,
            job_id="JOB-MIGRATION",
            cassette_sequence=5,
            hardware_target=target,
        )
        self.assertTrue(persisted.wait(1))
        with self.assertRaises(OperationConflict):
            manager.start("catalog.test", "replacement", "admin", lambda _ctx: None)
        manager.shutdown(0.1)

    def test_brokered_ltfs_info_requires_exact_admitted_targets_and_closed_json(
        self,
    ) -> None:
        class Supervisor:
            def __init__(self, stdout: str) -> None:
                self.stdout = stdout
                self.calls: list[tuple] = []

            def run(self, *args, **kwargs):
                self.calls.append((*args, kwargs))
                return CompletedCommand(0, self.stdout, "")

        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/drive-a-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-drive-a"),
            mount_path=self.mount_root,
        )
        valid = {
            "schema": 2,
            "media_state": "ltfs",
            "tape_by_id": str(settings.tape_device_path),
            "scsi_by_id": str(settings.scsi_device_path),
            "drive_serial": "stable-drive",
            "mam_barcode": "TAPE04",
            "mam_volume_serial": "serial",
            "ltfs_volume_label": "TAPE04",
            "ltfs_volume_uuid": "uuid",
            "index_generation": 7,
        }
        supervisor = Supervisor(json.dumps(valid))
        status = list(Path("/usr/bin/bash").stat())
        status[4] = 0
        status[0] = 0o100755
        with patch(
            "ltobackup.daemon.archive_runtime.os.fstat",
            return_value=os.stat_result(status),
        ):
            probe = BrokeredLtfsInfoMediaIdentityProbe(
                supervisor, self.context, settings, Path("/usr/bin/bash")
            )
            fields = probe.identify_unmounted()

        self.assertEqual("TAPE04", fields.mam_barcode)
        self.assertEqual(self.context.fence, supervisor.calls[0][0])
        self.assertEqual("probe_media", supervisor.calls[0][1])
        self.assertNotIn(str(settings.tape_device_path), supervisor.calls[0][2])
        self.assertNotIn(str(settings.scsi_device_path), supervisor.calls[0][2])
        self.assertEqual("--mode", supervisor.calls[0][2][2])
        self.assertEqual("unmounted", supervisor.calls[0][2][3])
        pass_fds = supervisor.calls[0][-1]["pass_fds"]
        self.assertEqual(1, len(pass_fds))
        self.assertEqual(f"/proc/self/fd/{pass_fds[0]}", supervisor.calls[0][2][0])
        self.assertNotEqual(str(probe._binary), supervisor.calls[0][2][0])

        unidentified = {
            **valid,
            "media_state": "unidentified",
            "mam_barcode": None,
            "ltfs_volume_label": None,
            "ltfs_volume_uuid": None,
            "index_generation": None,
        }
        with patch(
            "ltobackup.daemon.archive_runtime.os.fstat",
            return_value=os.stat_result(status),
        ):
            preformat_supervisor = Supervisor(json.dumps(unidentified))
            fields = BrokeredLtfsInfoMediaIdentityProbe(
                preformat_supervisor,
                self.context,
                settings,
                Path("/usr/bin/bash"),
            ).identify_preformat()
        self.assertIsNone(fields.mam_barcode)
        self.assertEqual("serial", fields.mam_volume_serial)
        self.assertEqual("pre-format", preformat_supervisor.calls[0][2][3])

        invalid_envelopes = (
            {**valid, "schema": 1},
            {**valid, "media_state": "unidentified"},
            {**valid, "media_state": "unknown"},
        )
        for payload in invalid_envelopes:
            with (
                self.subTest(payload=payload),
                patch(
                    "ltobackup.daemon.archive_runtime.os.fstat",
                    return_value=os.stat_result(status),
                ),
                self.assertRaisesRegex(Exception, "ltfs-info"),
            ):
                BrokeredLtfsInfoMediaIdentityProbe(
                    Supervisor(json.dumps(payload)),
                    self.context,
                    settings,
                    Path("/usr/bin/bash"),
                ).identify_unmounted()

        valid["tape_by_id"] = "/dev/tape/by-id/other"
        with (
            patch(
                "ltobackup.daemon.archive_runtime.os.fstat",
                return_value=os.stat_result(status),
            ),
            self.assertRaisesRegex(Exception, "ltfs-info"),
        ):
            BrokeredLtfsInfoMediaIdentityProbe(
                Supervisor(json.dumps(valid)),
                self.context,
                settings,
                Path("/usr/bin/bash"),
            ).identify_unmounted()

    def test_brokered_ltfs_info_repin_failures_are_typed_and_redacted(self) -> None:
        class Supervisor:
            def run(self, *_args, **_kwargs):
                raise AssertionError("a failed pin must not execute ltfs-info")

        binary = Path("/usr/bin/bash")
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/drive-a-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-drive-a"),
            mount_path=self.mount_root,
        )
        real_fstat = os.fstat
        status = list(binary.stat())
        status[4] = 0
        status[0] = stat.S_IFREG | 0o755

        with (
            patch(
                "ltobackup.daemon.archive_runtime.os.open",
                side_effect=OSError("raw-open"),
            ),
            self.assertRaises(MediaProbeUnavailable) as raised,
        ):
            BrokeredLtfsInfoMediaIdentityProbe(
                Supervisor(), self.context, settings, binary
            )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn("raw-open", str(raised.exception))

        with (
            patch(
                "ltobackup.daemon.archive_runtime.os.fstat",
                side_effect=TypeError("raw-stat"),
            ),
            self.assertRaises(MediaProbeUnavailable) as raised,
        ):
            BrokeredLtfsInfoMediaIdentityProbe(
                Supervisor(), self.context, settings, binary
            )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn("raw-stat", str(raised.exception))

        real_close = os.close

        def close_then_fail(descriptor: int) -> None:
            real_close(descriptor)
            raise OSError("raw-close")

        with (
            patch(
                "ltobackup.daemon.archive_runtime.os.fstat",
                return_value=os.stat_result(status),
            ),
            patch(
                "ltobackup.daemon.archive_runtime.os.close",
                side_effect=close_then_fail,
            ),
            self.assertRaises(MediaProbeUnavailable) as raised,
        ):
            BrokeredLtfsInfoMediaIdentityProbe(
                Supervisor(), self.context, settings, binary
            )
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn("raw-close", str(raised.exception))

        with patch(
            "ltobackup.daemon.archive_runtime.os.fstat",
            return_value=os.stat_result(status),
        ):
            probe = BrokeredLtfsInfoMediaIdentityProbe(
                Supervisor(), self.context, settings, binary
            )
        with (
            patch(
                "ltobackup.daemon.archive_runtime.os.fstat",
                side_effect=OSError("raw-repin"),
            ),
            self.assertRaises(MediaProbeUnavailable) as raised,
        ):
            probe.identify_unmounted()
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)
        self.assertNotIn("raw-repin", str(raised.exception))
        self.assertIs(real_fstat, os.fstat)

    def test_brokered_ltfs_info_uses_pinned_fd_and_rejects_path_swaps(self) -> None:
        class Supervisor:
            def __init__(self) -> None:
                self.calls: list[tuple[tuple[str, ...], tuple[int, ...]]] = []

            def run(self, _fence, _kind, argv, _timeout, *, pass_fds):
                self.calls.append((argv, pass_fds))
                return CompletedCommand(
                    0,
                    json.dumps(
                        {
                            "schema": 2,
                            "media_state": "ltfs",
                            "tape_by_id": "/dev/tape/by-id/drive-a-nst",
                            "scsi_by_id": "/dev/lto-archiver-scsi-drive-a",
                            "drive_serial": "stable-drive",
                            "mam_barcode": "TAPE04",
                            "mam_volume_serial": "serial",
                            "ltfs_volume_label": "TAPE04",
                            "ltfs_volume_uuid": "uuid",
                            "index_generation": 7,
                        }
                    ),
                    "",
                )

        binary = self.root / "ltfs-info"
        replacement = self.root / "replacement"
        binary.write_text("original", encoding="ascii")
        replacement.write_text("replacement", encoding="ascii")
        settings = LinuxSettings(
            tape_device_path=Path("/dev/tape/by-id/drive-a-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-drive-a"),
            mount_path=self.mount_root,
        )
        real_fstat = os.fstat

        def root_owned_fstat(fd: int) -> os.stat_result:
            fields = list(real_fstat(fd))
            fields[4] = 0
            fields[0] = stat.S_IFREG | 0o755
            return os.stat_result(fields)

        supervisor = Supervisor()
        with patch(
            "ltobackup.daemon.archive_runtime.os.fstat", side_effect=root_owned_fstat
        ):
            probe = BrokeredLtfsInfoMediaIdentityProbe(
                supervisor, self.context, settings, binary
            )
            probe.identify_unmounted()
            argv, pass_fds = supervisor.calls[-1]
            self.assertEqual(1, len(pass_fds))
            self.assertEqual(f"/proc/self/fd/{pass_fds[0]}", argv[0])
            self.assertNotEqual(str(probe._binary), argv[0])

            os.replace(replacement, binary)
            with self.assertRaises(MediaProbeUnavailable):
                probe.identify_unmounted()
            self.assertEqual(1, len(supervisor.calls))

            binary.unlink()
            binary.symlink_to("/usr/bin/bash")
            with self.assertRaises(MediaProbeUnavailable):
                probe.identify_unmounted()
            self.assertEqual(1, len(supervisor.calls))

            probe._binary = Path("/usr/bin/bash")
            with self.assertRaises(MediaProbeUnavailable):
                probe.identify_unmounted()
            self.assertEqual(1, len(supervisor.calls))


if __name__ == "__main__":
    unittest.main()
