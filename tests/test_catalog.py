from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.frozen_job import (
    FrozenJobAssignmentChanged,
    FrozenJobPlan,
    FrozenJobStateInvalid,
)
from ltobackup.daemon.models import (
    CommandExitEvidence,
    CommandQuiescenceRequired,
    CriticalRecoveryObservation,
    HardwareTargetBinding,
    MediaTargetMismatch,
    MutationAdmissionClosed,
    OperationConflict,
    OperationFence,
    OperationRecord,
    PhysicalTargetMismatch,
    ProcessIdentity,
    SafeRecoveryResolution,
    StaleDaemonFence,
    StaleOperationFence,
    VerifiedPhysicalQuiescence,
    critical_command_ledger_sha256,
)
from ltobackup.daemon.native_runtime import ProductionNativeArchive
from ltobackup.errors import CatalogError, ValidationError
from ltobackup.migration.validator import (
    MigrationValidator,
    canonical_cassette_plan_sha256,
    validate_catalog_contract,
)
from ltobackup.settings import Settings
from ltobackup.tape.command_supervisor import (
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsStandaloneReceipt,
)
from ltobackup.tape.models import MountedTape, UnmountResult
from tests.fixtures import build_frozen_job_fixture

POPULATED_TABLES = (
    "libraries",
    "tapes",
    "blocks",
    "file_versions",
    "events",
    "automatic_jobs",
    "automatic_cassettes",
    "automatic_job_libraries",
    "automatic_cassette_items",
)


def read_schema_version(database_path: Path) -> str:
    with closing(sqlite3.connect(database_path)) as connection:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key='schema_version'"
        ).fetchone()
    return row[0]


def initialize_current_with_protected_backup(catalog: Catalog, root: Path) -> None:
    source_version = int(read_schema_version(catalog.path))
    backup = root / (
        f"20260830T180000000000Z-abcdef123456-p-v{source_version}-"
        "0123456789abcdef.sqlite3"
    )
    shutil.copy2(catalog.path, backup)
    catalog._initialize_after_protected_backup(SCHEMA_VERSION, backup)


def prepare_and_initialize(database_path: Path) -> None:
    BackupManager(
        database_path,
        database_path.parent / "backups",
        retention=5,
    ).prepare_and_initialize()


def integrity_check(database_path: Path) -> list[str]:
    with closing(sqlite3.connect(database_path)) as connection:
        return [row[0] for row in connection.execute("PRAGMA integrity_check")]


def foreign_key_violations(database_path: Path) -> list[tuple]:
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        return list(connection.execute("PRAGMA foreign_key_check"))


def make_schema_17_format_rebinding_catalog(
    database_path: Path,
    *,
    column_layout: str,
    populated: bool,
) -> Path:
    """Build the two schema-17 layouts emitted by 947bf84 and a4e55ab."""

    with Catalog(database_path) as catalog:
        catalog.initialize(target_version=17)
        columns = {
            row[1]
            for row in catalog.connection.execute(
                "PRAGMA table_info(format_media_rebindings)"
            )
        }
        has_identify = "pre_identify_command_id" in columns
        if column_layout == "identify" and not has_identify:
            catalog.connection.execute(
                "ALTER TABLE format_media_rebindings RENAME COLUMN "
                "pre_probe_media_command_id TO pre_identify_command_id"
            )
            catalog.connection.execute(
                "ALTER TABLE format_media_rebindings RENAME COLUMN "
                "post_probe_media_command_id TO post_identify_command_id"
            )
        elif column_layout == "probe_media" and has_identify:
            catalog.connection.execute(
                "ALTER TABLE format_media_rebindings RENAME COLUMN "
                "pre_identify_command_id TO pre_probe_media_command_id"
            )
            catalog.connection.execute(
                "ALTER TABLE format_media_rebindings RENAME COLUMN "
                "post_identify_command_id TO post_probe_media_command_id"
            )
        if populated:
            catalog.connection.execute(
                "INSERT INTO daemon_operations("
                "id,kind,state,phase,idempotency_key,principal,owner_generation,"
                "started_at) VALUES(?,?,?,?,?,?,?,?)",
                (
                    "operation-schema17",
                    "archive.resume",
                    "running",
                    "formatting_media",
                    "schema17-rebinding",
                    "synthetic-admin",
                    1,
                    "2026-08-23T00:00:00+00:00",
                ),
            )
            for command_id, kind in (
                ("pre-command", "identify"),
                ("format-command", "format"),
                ("post-command", "identify"),
            ):
                catalog.connection.execute(
                    "INSERT INTO hardware_command_executions("
                    "id,operation_id,issued_generation,command_kind,argv_sha256,"
                    "mount_path_sha256,tape_device_identity_sha256,"
                    "scsi_device_identity_sha256,expected_media_scope_sha256,"
                    "state,exit_outcome,created_at,released_at,exit_observed_at,"
                    "quiesced_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        command_id,
                        "operation-schema17",
                        1,
                        kind,
                        "a" * 64,
                        "b" * 64,
                        "c" * 64,
                        "d" * 64,
                        "e" * 64,
                        "quiesced",
                        "completed",
                        "2026-08-23T00:00:01+00:00",
                        "2026-08-23T00:00:02+00:00",
                        "2026-08-23T00:00:03+00:00",
                        "2026-08-23T00:00:04+00:00",
                    ),
                )
            prefix = "identify" if column_layout == "identify" else "probe_media"
            catalog.connection.execute(
                "INSERT INTO format_media_rebindings("
                "operation_id,owner_generation,confirmation_confirmed_at,"
                f"pre_{prefix}_command_id,format_command_id,"
                f"post_{prefix}_command_id,expected_label,observed_label,"
                "expected_serial,observed_serial,post_volume_uuid,"
                "post_index_generation,pre_media_identity_sha256,"
                "post_media_identity_sha256,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "operation-schema17",
                    1,
                    "2026-08-23T00:00:00+00:00",
                    "pre-command",
                    "format-command",
                    "post-command",
                    "SYNTHETIC LABEL",
                    "SYNTHETIC LABEL",
                    "SERIAL-SYNTHETIC",
                    "SERIAL-SYNTHETIC",
                    "33333333-3333-4333-8333-333333333333",
                    7,
                    "1" * 64,
                    "2" * 64,
                    "2026-08-23T00:00:05+00:00",
                ),
            )
        catalog.connection.commit()
    return database_path


def canonical_row_snapshot(database_path: Path, tables: tuple[str, ...]) -> dict:
    snapshot = {}
    with closing(sqlite3.connect(database_path)) as connection:
        connection.row_factory = sqlite3.Row
        for table in tables:
            columns = list(connection.execute(f'PRAGMA table_info("{table}")'))
            names = [row[1] for row in columns]
            primary_key = [
                row[1] for row in sorted(columns, key=lambda item: item[5]) if row[5]
            ]
            order = primary_key or names
            order_sql = ", ".join(f'"{name}"' for name in order)
            rows = connection.execute(
                f'SELECT * FROM "{table}" ORDER BY {order_sql}'
            ).fetchall()
            snapshot[table] = [
                {name: json.loads(json.dumps(row[name])) for name in names}
                for row in rows
            ]
    return snapshot


def normalize_snapshot_value(
    snapshot: dict, *, table: str, column: str, old: object, new: object
) -> dict:
    normalized = json.loads(json.dumps(snapshot))
    for row in normalized[table]:
        if row[column] == old:
            row[column] = new
    return normalized


def make_populated_schema_13_catalog(database_path: Path) -> Path:
    source = database_path.parent / "source"
    source.mkdir(parents=True, exist_ok=True)
    with Catalog(database_path) as catalog:
        catalog.initialize(target_version=13)
        catalog.add_library("LIB1", "Library", str(source))
        catalog.register_tape(
            "TAPE1",
            "SERIAL-DIAGNOSTIC",
            "TAPE1",
            "LTFS",
            "/synthetic/mount",
            cassette_number="CASSETTE-1",
        )
        catalog.create_block("BLOCK1", "LIB1", "TAPE1", "archive", 1, 11)
        catalog.record_file_version(
            "LIB1",
            "BLOCK1",
            "TAPE1",
            "clip.mxf",
            "archive/clip.mxf",
            11,
            123,
            "a" * 64,
        )
        catalog.complete_block("BLOCK1")
        catalog.create_automatic_job(
            "JOB1",
            "LIB1",
            "synthetic-drive",
            "/synthetic/mount",
            [("LABEL4", "SERIAL4", 1, 11)],
            force_format=True,
        )
        catalog.replace_automatic_cassette_manifest(
            "JOB1", 1, [("LIB1", "clip.mxf", 11, 123)]
        )
        catalog.update_automatic_job("JOB1", "formatting", current_sequence=1)
        catalog.update_automatic_cassette("JOB1", 1, "formatting")
        catalog.event("fixture.populated", {"order": [1], "safe": True})
    return database_path


def synthetic_target(
    mount: str = "mount-a",
    tape: str = "tape-a",
    scsi: str = "scsi-a",
    media: str = "media-a",
) -> HardwareTargetBinding:
    return HardwareTargetBinding.from_verified_inputs(
        Path(f"/synthetic/{mount}"),
        f"synthetic-{tape}",
        f"synthetic-{scsi}",
        ("archive.resume", "JOB-SYNTHETIC", "4", media, "", ""),
    )


def sha256_fixture(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def confirm_command_release(catalog: Catalog, command_id: str, fence) -> None:
    permit = sha256_fixture(f"release:{command_id}")
    catalog.authorize_hardware_command_release(command_id, fence, permit)
    catalog.confirm_hardware_command_released(command_id, fence, permit)


def command_exit_after_release(catalog: Catalog, command_id: str) -> str:
    command = catalog.command(command_id)
    boundary = command.released_at or command.created_at
    return (datetime.fromisoformat(boundary) + timedelta(microseconds=1)).isoformat()


def operation_candidate(
    operation_id: str,
    key: str,
    *,
    kind: str = "catalog.test",
    principal: str = "synthetic-admin",
    job_id: str | None = None,
    cassette_sequence: int | None = None,
) -> OperationRecord:
    return OperationRecord(
        id=operation_id,
        kind=kind,
        state="running",
        phase=None,
        idempotency_key=key,
        principal=principal,
        job_id=job_id,
        cassette_sequence=cassette_sequence,
        started_at="2026-08-21T12:00:00+00:00",
        finished_at=None,
    )


def restore_release_fixture(
    operation_id: str,
    owner_generation: int,
    *,
    mount_path: Path = Path("/synthetic/mount-a"),
    volume_label: str = "RESTORE-VOLUME-1",
) -> tuple[MountedTape, UnmountResult]:
    session = LtfsSessionReceipt(
        1,
        operation_id,
        "receipt-operation",
        "11111111-1111-4111-8111-111111111111",
        owner_generation,
        True,
        1,
        b"a" * 32,
        "restore-session",
        "b" * 64,
        1,
        1,
        "c" * 64,
        b"d" * 32,
        b"e" * 32,
        True,
        volume_label,
        "f" * 64,
    )
    standalone = LtfsStandaloneReceipt(
        1,
        "terminal",
        session.receipt_operation_uuid,
        session.observed_volume_uuid,
        1,
        1,
        True,
        0,
        True,
        0,
        (),
        0,
        0,
        True,
        0,
        0,
        True,
        True,
        False,
        0,
        "a" * 64,
    )
    finalization = LtfsFinalizationReceipt(
        1,
        session,
        standalone,
        b"b" * 32,
        b"c" * 32,
        b"d" * 32,
        True,
        True,
    )
    mounted = MountedTape(mount_path, True, session)
    return mounted, UnmountResult(0.1, 0.2, finalization)


def insert_quiesced_restore_unload(
    catalog: Catalog,
    operation_id: str,
    owner_generation: int,
    target: HardwareTargetBinding,
) -> None:
    now = "2026-09-01T08:00:00.000001+00:00"
    with catalog.transaction() as db:
        db.execute(
            "INSERT INTO hardware_command_executions("
            "id,operation_id,issued_generation,command_kind,argv_sha256,"
            "mount_path_sha256,tape_device_identity_sha256,"
            "scsi_device_identity_sha256,expected_media_scope_sha256,"
            "state,exit_outcome,created_at,exit_observed_at,quiesced_at,"
            "terminal_exit_code) "
            "VALUES('restore-unload',?,?, 'unload',?,?,?,?,?,"
            "'quiesced','completed',?,?,?,0)",
            (
                operation_id,
                owner_generation,
                "a" * 64,
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                now,
                now,
                now,
            ),
        )


def insert_quiesced_restore_no_media_probe(
    catalog: Catalog,
    operation_id: str,
    owner_generation: int,
    target: HardwareTargetBinding,
) -> None:
    now = "2026-09-01T08:00:00.000002+00:00"
    with catalog.transaction() as db:
        db.execute(
            "INSERT INTO hardware_command_executions("
            "id,operation_id,issued_generation,command_kind,argv_sha256,"
            "mount_path_sha256,tape_device_identity_sha256,"
            "scsi_device_identity_sha256,expected_media_scope_sha256,"
            "state,exit_outcome,created_at,exit_observed_at,quiesced_at,"
            "terminal_exit_code) "
            "VALUES('restore-probe-no-media',?,?, 'probe_media',?,?,?,?,?,"
            "'quiesced','completed',?,?,?,3)",
            (
                operation_id,
                owner_generation,
                "b" * 64,
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                now,
                now,
                now,
            ),
        )


def seed_post_eject_restore_recovery_boundary(
    catalog: Catalog, *, complete: bool, pending_control: str | None = None
) -> dict[str, object]:
    plan = seed_one_tape_two_item_restore_plan(catalog)
    run = catalog.create_restore_run(
        str(plan["id"]), actor="operator-1",
        idempotency_key="restore-run-1", request_sha256="a" * 64,
    )
    target = synthetic_target()
    original = catalog.claim_daemon_owner("restore-original")
    admitted = catalog.admit_operation(
        operation_candidate(
            "restore-operation-1", "restore-operation-key-1",
            kind="restore.cassette", job_id=str(run["id"]),
            cassette_sequence=1,
        ),
        original,
        admission_open=True,
        hardware_target=target,
    )
    fence = OperationFence(admitted.record.id, original.generation)
    catalog.transition_restore_cassette(
        fence, str(run["id"]), 1,
        expected_state="waiting_media", new_state="restoring",
    )
    if complete:
        for item in catalog.restore_run(str(run["id"]))["items"]:
            sequence = int(item["sequence"])
            catalog.transition_restore_item(
                fence, str(run["id"]), sequence,
                expected_state="pending", new_state="restoring",
                bytes_copied=0, observed_sha256=None,
            )
            catalog.transition_restore_item(
                fence, str(run["id"]), sequence,
                expected_state="restoring", new_state="restored",
                bytes_copied=int(item["plan_item"]["size"]),
                observed_sha256=str(item["plan_item"]["sha256"]),
            )
    insert_quiesced_restore_unload(
        catalog, admitted.record.id, original.generation, target
    )
    insert_quiesced_restore_no_media_probe(
        catalog, admitted.record.id, original.generation, target
    )
    mounted, unmount = restore_release_fixture(
        admitted.record.id, original.generation
    )
    catalog.record_restore_post_eject_receipt(
        fence,
        str(run["id"]),
        1,
        mounted,
        unmount,
        no_media_proven=True,
    )
    if pending_control == "pause":
        catalog.request_restore_run_pause(str(run["id"]), actor="operator-2")
    elif pending_control == "cancel":
        catalog.request_restore_run_cancel(str(run["id"]), actor="operator-2")
    catalog.finish_operation(
        fence, "recovery_required", error_class="operator_required",
        error_code="recovery_required",
    )
    recovered = catalog.claim_daemon_owner("restore-recovered")
    command = catalog.create_command_quiescence_receipt(
        admitted.record.id, recovered
    )
    physical = catalog.create_physical_reconciliation_receipt(
        admitted.record.id,
        recovered,
        command.id,
        VerifiedPhysicalQuiescence(target, None, False, False, False, ()),
    )
    return {
        "run": run,
        "operation_id": admitted.record.id,
        "recovered": recovered,
        "resolution": SafeRecoveryResolution(
            "restore_restart_safe", command.id, physical.id
        ),
    }


def seed_two_tape_restore_plan(catalog: Catalog) -> dict[str, object]:
    """Create a hand-derived two-cassette immutable restore plan fixture."""

    source_root = catalog.path.parent / "restore-source"
    source_root.mkdir(exist_ok=True)
    catalog.add_library("RESTORELIB", "Restore library", str(source_root))
    catalog.register_tape(
        "RESTORE-TAPE-1",
        "RESTORE-SERIAL-1",
        "RESTORE-VOLUME-1",
        "LTFS",
        "/synthetic/tape-1",
        "RESTORE-NUMBER-1",
    )
    catalog.register_tape(
        "RESTORE-TAPE-2",
        "RESTORE-SERIAL-2",
        "RESTORE-VOLUME-2",
        "LTFS",
        "/synthetic/tape-2",
        "RESTORE-NUMBER-2",
    )
    catalog.create_automatic_job(
        "RESTORE-JOB",
        "RESTORELIB",
        "/dev/never-opened",
        "/never-mounted",
        [
            ("TAPE01", "RESTORE-SERIAL-1", 1, 11),
            ("TAPE02", "RESTORE-SERIAL-2", 1, 22),
        ],
    )
    version_ids: list[int] = []
    for sequence, (tape_id, block_id, relative_path, size) in enumerate(
        (
            ("RESTORE-TAPE-1", "RESTORE-BLOCK-1", "one.bin", 11),
            ("RESTORE-TAPE-2", "RESTORE-BLOCK-2", "two.bin", 22),
        ),
        1,
    ):
        catalog.create_block(
            block_id,
            "RESTORELIB",
            tape_id,
            f".lto-backup/{block_id}",
            1,
            size,
        )
        version_ids.append(
            catalog.record_file_version(
                "RESTORELIB",
                block_id,
                tape_id,
                relative_path,
                f".lto-backup/{block_id}/files/{relative_path}",
                size,
                sequence,
                f"{sequence:064x}",
            )
        )
        catalog.complete_block(block_id)
        catalog.update_automatic_cassette(
            "RESTORE-JOB",
            sequence,
            "completed",
            tape_id=tape_id,
            block_id=block_id,
            copied_files=1,
            copied_bytes=size,
        )
    return catalog.create_restore_plan(
        version_ids,
        "/srv/restores/selection",
        actor="operator-1",
        idempotency_key="restore-plan-1",
        request_sha256="f" * 64,
        destination_kind="local",
        destination_anchor="/srv/restores",
    )


def seed_completed_tape_receipt(
    catalog: Catalog,
    *,
    job_id: str,
    tape_id: str,
    volume_uuid: str,
    ordinal: int,
) -> None:
    """Attach one terminal receipt to a completed fourth cassette."""

    cassettes = [
        (f"R{ordinal:02d}{sequence:03d}", f"SERIAL-{ordinal}-{sequence}", 0, 0)
        for sequence in range(1, 5)
    ]
    library_id = f"RECEIPTLIB-{ordinal}"
    source_root = catalog.path.parent / library_id
    source_root.mkdir(exist_ok=True)
    catalog.add_library(library_id, f"Receipt library {ordinal}", str(source_root))
    catalog.create_automatic_job(
        job_id,
        library_id,
        "/dev/never-opened",
        "/never-mounted",
        cassettes,
    )
    catalog.update_automatic_cassette(
        job_id,
        4,
        "completed",
        tape_id=tape_id,
        block_id=f"RECEIPT-BLOCK-{ordinal}",
        copied_files=0,
        copied_bytes=0,
    )
    operation_id = f"receipt-operation-{ordinal}"
    catalog.connection.execute(
        "INSERT INTO daemon_operations("
        "id,kind,state,phase,idempotency_key,principal,owner_generation,started_at) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (
            operation_id,
            "archive.resume",
            "succeeded",
            None,
            f"receipt-{ordinal}",
            "migration-test",
            1,
            f"2026-08-31T00:00:{ordinal:02d}+00:00",
        ),
    )
    catalog.connection.execute(
        "INSERT INTO ltfs_terminal_receipts("
        "operation_id,owner_generation,job_id,sequence,receipt_operation_uuid,"
        "session_id,request_sha256,volume_uuid,prior_generation,new_generation,"
        "bytes_valid,byte_count,files_valid,file_count,media_committed,"
        "catalog_acknowledged,device_close_result_valid,device_close_result,"
        "cleanup_failed,result,terminal_sha256,request_nonce,finalization_nonce,"
        "broker_proof,observed_volume_label,observed_media_identity_sha256,"
        "standalone_receipt_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,"
        "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            operation_id,
            1,
            job_id,
            4,
            f"00000000-0000-4000-8000-{ordinal:012d}",
            f"receipt-session-{ordinal}",
            f"{ordinal:064x}",
            volume_uuid,
            1,
            2,
            1,
            0,
            1,
            0,
            1,
            1,
            1,
            0,
            0,
            0,
            f"{ordinal + 100:064x}",
            bytes([ordinal]) * 32,
            bytes([ordinal + 20]) * 32,
            bytes([ordinal + 40]) * 32,
            cassettes[3][0],
            f"{ordinal + 200:064x}",
            "{}",
            f"2026-08-31T00:01:{ordinal:02d}+00:00",
        ),
    )


def seed_one_tape_two_item_restore_plan(catalog: Catalog) -> dict[str, object]:
    """Create two independently restorable items on one cassette."""

    source_root = catalog.path.parent / "restore-source"
    source_root.mkdir(exist_ok=True)
    catalog.add_library("RESTORELIB", "Restore library", str(source_root))
    catalog.register_tape(
        "RESTORE-TAPE-1",
        "RESTORE-SERIAL-1",
        "RESTORE-VOLUME-1",
        "LTFS",
        "/synthetic/tape-1",
        "RESTORE-NUMBER-1",
    )
    catalog.create_automatic_job(
        "RESTORE-JOB",
        "RESTORELIB",
        "/dev/never-opened",
        "/never-mounted",
        [("TAPE01", "RESTORE-SERIAL-1", 2, 33)],
    )
    catalog.create_block(
        "RESTORE-BLOCK-1",
        "RESTORELIB",
        "RESTORE-TAPE-1",
        ".lto-backup/RESTORE-BLOCK-1",
        2,
        33,
    )
    version_ids = [
        catalog.record_file_version(
            "RESTORELIB",
            "RESTORE-BLOCK-1",
            "RESTORE-TAPE-1",
            relative_path,
            f".lto-backup/RESTORE-BLOCK-1/files/{relative_path}",
            size,
            sequence,
            f"{sequence:064x}",
        )
        for sequence, (relative_path, size) in enumerate(
            (("one.bin", 11), ("two.bin", 22)), 1
        )
    ]
    catalog.complete_block("RESTORE-BLOCK-1")
    catalog.update_automatic_cassette(
        "RESTORE-JOB",
        1,
        "completed",
        tape_id="RESTORE-TAPE-1",
        block_id="RESTORE-BLOCK-1",
        copied_files=2,
        copied_bytes=33,
    )
    return catalog.create_restore_plan(
        version_ids,
        "/srv/restores/selection",
        actor="operator-1",
        idempotency_key="restore-plan-1",
        request_sha256="f" * 64,
        destination_kind="local",
        destination_anchor="/srv/restores",
    )


class _MissExistingOperationLookupCatalog(Catalog):
    """Expose a committed winner only after one operation-insert collision."""

    def __init__(self, path: Path):
        super().__init__(path)
        self.operation_lookup_count = 0
        self._missed_existing = False

    def _find_operation_by_key_tx(self, db, idempotency_key):
        self.operation_lookup_count += 1
        row = super()._find_operation_by_key_tx(db, idempotency_key)
        if row is not None and not self._missed_existing:
            self._missed_existing = True
            return None
        return row


class CatalogMigrationTests(unittest.TestCase):
    def test_schema_39_to_40_is_additive_and_backup_restores_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            backup = root / "catalog-v39.sqlite3"
            restored = root / "restored.sqlite3"
            (root / "source").mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=39)
                catalog.add_library("KEEP", "Keep", str(root / "source"))
                catalog.backup_to(backup)
                catalog.initialize(target_version=40)
                columns = {
                    row["name"]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(hardware_command_executions)"
                    )
                }
                self.assertIn("terminal_exit_code", columns)
                self.assertIsNotNone(
                    catalog.connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND "
                        "name='qualification_readback_release_receipts'"
                    ).fetchone()
                )
                self.assertIsNotNone(catalog.get_library("KEEP"))
                validation = validate_catalog_contract(catalog.connection, 40)
                self.assertTrue(validation.valid, validation.error_codes)

            shutil.copy2(backup, restored)
            with Catalog(restored) as recovered:
                recovered.initialize(target_version=40)
                self.assertIsNotNone(recovered.get_library("KEEP"))
                self.assertEqual(
                    "40",
                    recovered.connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0],
                )
                validation = validate_catalog_contract(recovered.connection, 40)
                self.assertTrue(validation.valid, validation.error_codes)
            self.assertEqual(["ok"], integrity_check(restored))
            self.assertEqual([], foreign_key_violations(restored))

    def test_new_restore_plan_persists_closed_destination_snapshot(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            plan = seed_one_tape_two_item_restore_plan(catalog)

            expected_destination = {
                "kind": "local",
                "root": "/srv/restores/selection",
                "anchor": "/srv/restores",
            }
            self.assertEqual(expected_destination, plan["destination"])
            self.assertEqual("exact", plan["destination_state"])
            self.assertIsNone(plan["destination_invalidation_reason"])
            self.assertEqual(
                expected_destination,
                catalog.get_restore_plan(plan["id"])["destination"],
            )
            self.assertEqual(
                (
                    "exact",
                    "local",
                    "/srv/restores/selection",
                    "/srv/restores",
                    None,
                ),
                tuple(
                    catalog.connection.execute(
                        "SELECT destination_state,kind,root,anchor,"
                        "invalidation_reason FROM restore_plan_destinations "
                        "WHERE plan_id=?",
                        (plan["id"],),
                    ).fetchone()
                ),
            )

    def test_schema_39_destination_snapshot_rejects_nul_paths(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.connection.execute("PRAGMA foreign_keys=OFF")
            for field, root, anchor in (
                ("root", "/safe\x00", "/"),
                ("anchor", "/safe\x00", "/safe\x00"),
            ):
                with self.subTest(field=field), self.assertRaisesRegex(
                    sqlite3.IntegrityError, "CHECK"
                ):
                    catalog.connection.execute(
                        "INSERT INTO restore_plan_destinations("
                        "plan_id,destination_state,kind,root,anchor,"
                        "invalidation_reason) VALUES(?,'exact','local',?,?,NULL)",
                        (f"NUL-{field}", root, anchor),
                    )

    def test_schema_39_restore_run_freezes_plan_and_cassette_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=38)
                plan = seed_two_tape_restore_plan(catalog)
                plan_before = catalog.get_restore_plan(str(plan["id"]))
                migration_statements: list[str] = []
                catalog.connection.set_trace_callback(migration_statements.append)
                catalog.initialize(target_version=39)
                catalog.connection.set_trace_callback(None)
                volume_backfill = next(
                    statement
                    for statement in migration_statements
                    if statement.startswith(
                        "UPDATE restore_plan_cassettes SET volume_uuid="
                    )
                )
                self.assertIn(
                    "GROUP BY cassette.tape_id HAVING",
                    " ".join(volume_backfill.split()),
                )
                migrated_plan = catalog.get_restore_plan(str(plan["id"]))
                self.assertIsNone(migrated_plan["destination"])
                self.assertEqual("legacy_invalid", migrated_plan["destination_state"])
                self.assertEqual(
                    "legacy_destination_snapshot_missing",
                    migrated_plan["destination_invalidation_reason"],
                )
                with self.assertRaisesRegex(CatalogError, "destination"):
                    catalog.create_restore_run(
                        str(plan["id"]),
                        actor="operator-1",
                        idempotency_key="restore-run-1",
                        request_sha256="a" * 64,
                    )
                self.assertEqual(
                    {key: value for key, value in plan_before.items() if key != "cassettes"},
                    {key: value for key, value in migrated_plan.items() if key != "cassettes"},
                )
                for old, migrated in zip(
                    plan_before["cassettes"], migrated_plan["cassettes"], strict=True
                ):
                    self.assertEqual(
                        {
                            key: value
                            for key, value in old.items()
                            if key not in {"volume_serial", "volume_uuid"}
                        },
                        {
                            key: migrated[key]
                            for key in old
                            if key not in {"volume_serial", "volume_uuid"}
                        },
                    )

    def test_schema_39_backfills_only_unambiguous_terminal_volume_uuid(self) -> None:
        cases = (
            ("without-receipt", (), None),
            (
                "one-uuid",
                ("11111111-1111-4111-8111-111111111111",),
                "11111111-1111-4111-8111-111111111111",
            ),
            (
                "same-uuid-across-jobs",
                (
                    "22222222-2222-4222-8222-222222222222",
                    "22222222-2222-4222-8222-222222222222",
                ),
                "22222222-2222-4222-8222-222222222222",
            ),
            (
                "conflicting-uuids",
                (
                    "33333333-3333-4333-8333-333333333333",
                    "44444444-4444-4444-8444-444444444444",
                ),
                None,
            ),
        )
        for name, receipt_uuids, expected in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                with Catalog(Path(temporary) / "catalog.db") as catalog:
                    catalog.initialize(target_version=38)
                    plan = seed_two_tape_restore_plan(catalog)
                    for ordinal, volume_uuid in enumerate(receipt_uuids, 1):
                        seed_completed_tape_receipt(
                            catalog,
                            job_id=f"RECEIPT-JOB-{ordinal}",
                            tape_id="RESTORE-TAPE-1",
                            volume_uuid=volume_uuid,
                            ordinal=ordinal,
                        )

                    catalog.initialize(target_version=39)

                    migrated = catalog.get_restore_plan(str(plan["id"]))
                    by_tape = {
                        cassette["tape_id"]: cassette["volume_uuid"]
                        for cassette in migrated["cassettes"]
                    }
                    self.assertEqual(expected, by_tape["RESTORE-TAPE-1"])
                    self.assertIsNone(by_tape["RESTORE-TAPE-2"])

    def test_schema_39_restore_run_is_idempotent_and_one_active_per_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_two_tape_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]),
                    actor="operator-1",
                    idempotency_key="restore-run-1",
                    request_sha256="a" * 64,
                )
                self.assertEqual(
                    run,
                    catalog.create_restore_run(
                        str(plan["id"]),
                        actor="operator-1",
                        idempotency_key="restore-run-1",
                        request_sha256="a" * 64,
                    ),
                )
                with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                    catalog.create_restore_run(
                        str(plan["id"]),
                        actor="operator-1",
                        idempotency_key="restore-run-1",
                        request_sha256="b" * 64,
                    )
                with self.assertRaisesRegex(CatalogError, "active"):
                    catalog.create_restore_run(
                        str(plan["id"]),
                        actor="operator-1",
                        idempotency_key="restore-run-2",
                        request_sha256="c" * 64,
                    )

    def test_schema_39_rejects_legacy_invalid_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_two_tape_restore_plan(catalog)
                catalog.connection.execute("DROP TRIGGER restore_plans_immutable_update")
                catalog.connection.execute(
                    "UPDATE restore_plans SET identity_state='legacy_invalid',"
                    "invalidation_reason='legacy_physical_identity_ambiguous' WHERE id=?",
                    (plan["id"],),
                )
                catalog.connection.commit()

                with self.assertRaisesRegex(CatalogError, "identity"):
                    catalog.create_restore_run(
                        str(plan["id"]),
                        actor="operator-1",
                        idempotency_key="legacy-run",
                        request_sha256="a" * 64,
                    )

    def test_restore_conflict_and_replacement_authorization_are_exact_one_shot(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_two_tape_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]),
                    actor="operator-1",
                    idempotency_key="restore-run-1",
                    request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1",
                        "restore-operation-key-1",
                        kind="restore.cassette",
                        job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                self.assertEqual(
                    1,
                    catalog.next_restore_cassette(str(run["id"]))["sequence"],
                )
                conflict = catalog.record_restore_item_conflict(
                    fence,
                    str(run["id"]),
                    1,
                    canonical_destination="/srv/restores/selection/RESTORELIB/one.bin",
                    observed_size=9,
                    observed_sha256="9" * 64,
                )

                blocked = catalog.restore_run(str(run["id"]))
                self.assertEqual("recovery_required", blocked["state"])
                self.assertEqual("recovery_required", blocked["items"][0]["state"])
                self.assertEqual(conflict, blocked["items"][0]["conflict"])
                authorization = catalog.authorize_restore_item_replacement(
                    str(run["id"]),
                    1,
                    administrator="admin-1",
                    fresh_reauthentication="d" * 64,
                    idempotency_key="replacement-authorization-1",
                )
                self.assertEqual(
                    authorization,
                    catalog.authorize_restore_item_replacement(
                        str(run["id"]),
                        1,
                        administrator="admin-1",
                        fresh_reauthentication="d" * 64,
                        idempotency_key="replacement-authorization-1",
                    ),
                )
                with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                    catalog.authorize_restore_item_replacement(
                        str(run["id"]),
                        1,
                        administrator="admin-1",
                        fresh_reauthentication="e" * 64,
                        idempotency_key="replacement-authorization-1",
                    )
                with self.assertRaises(ValidationError):
                    catalog.authorize_restore_item_replacement(
                        str(run["id"]),
                        1,
                        administrator="admin-1",
                        fresh_reauthentication="raw-session-secret",
                        idempotency_key="replacement-malformed-proof",
                    )
                with self.assertRaisesRegex(CatalogError, "reauthentication"):
                    catalog.authorize_restore_item_replacement(
                        str(run["id"]),
                        1,
                        administrator="admin-1",
                        fresh_reauthentication="d" * 64,
                        idempotency_key="replacement-stale-proof",
                    )
                for column, changed in (
                    ("item_sequence", 2),
                    ("file_version_id", conflict["file_version_id"] + 1),
                    (
                        "canonical_destination",
                        "/srv/restores/selection/RESTORELIB/changed.bin",
                    ),
                    ("observed_size", conflict["observed_size"] + 1),
                    ("observed_sha256", "8" * 64),
                ):
                    with self.subTest(column=column), self.assertRaises(
                        sqlite3.IntegrityError
                    ):
                        catalog.connection.execute(
                            f"UPDATE restore_item_conflicts SET {column}=? WHERE id=?",
                            (changed, conflict["id"]),
                        )

                consumed = catalog.consume_restore_item_replacement_authorization(
                    fence,
                    str(run["id"]),
                    1,
                    str(authorization["id"]),
                )
                self.assertEqual("consumed", consumed["state"])
                self.assertEqual(conflict["file_version_id"], consumed["file_version_id"])
                self.assertEqual(
                    conflict["canonical_destination"], consumed["canonical_destination"]
                )
                with self.assertRaisesRegex(CatalogError, "consumed"):
                    catalog.consume_restore_item_replacement_authorization(
                        fence,
                        str(run["id"]),
                        1,
                        str(authorization["id"]),
                    )
                catalog.transition_restore_cassette(
                    fence,
                    str(run["id"]),
                    1,
                    expected_state="recovery_required",
                    new_state="restoring",
                )
                catalog.transition_restore_item(
                    fence,
                    str(run["id"]),
                    1,
                    expected_state="recovery_required",
                    new_state="restoring",
                    bytes_copied=0,
                    observed_sha256=None,
                )
                with self.assertRaisesRegex(CatalogError, "state changed"):
                    catalog.transition_restore_item(
                        fence,
                        str(run["id"]),
                        1,
                        expected_state="recovery_required",
                        new_state="restoring",
                        bytes_copied=0,
                        observed_sha256=None,
                    )

    def test_restore_cassette_recovery_exit_requires_consumed_authorization(
        self,
    ) -> None:
        for resumed_state in ("waiting_media", "restoring"):
            with (
                self.subTest(resumed_state=resumed_state),
                tempfile.TemporaryDirectory() as temporary,
                Catalog(Path(temporary) / "catalog.db") as catalog,
            ):
                catalog.initialize()
                plan = seed_two_tape_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]),
                    actor="operator-1",
                    idempotency_key="restore-run-1",
                    request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1",
                        "restore-operation-key-1",
                        kind="restore.cassette",
                        job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.record_restore_item_conflict(
                    fence,
                    str(run["id"]),
                    1,
                    canonical_destination=(
                        "/srv/restores/selection/RESTORELIB/one.bin"
                    ),
                    observed_size=9,
                    observed_sha256="9" * 64,
                )

                with self.assertRaisesRegex(CatalogError, "authorization"):
                    catalog.transition_restore_cassette(
                        fence,
                        str(run["id"]),
                        1,
                        expected_state="recovery_required",
                        new_state=resumed_state,
                    )
                blocked = catalog.restore_run(str(run["id"]))
                self.assertEqual("recovery_required", blocked["state"])
                self.assertEqual(
                    "recovery_required", blocked["cassettes"][0]["state"]
                )

                authorization = catalog.authorize_restore_item_replacement(
                    str(run["id"]),
                    1,
                    administrator="admin-1",
                    fresh_reauthentication="d" * 64,
                    idempotency_key="replacement-authorization-1",
                )
                catalog.consume_restore_item_replacement_authorization(
                    fence,
                    str(run["id"]),
                    1,
                    str(authorization["id"]),
                )
                catalog.transition_restore_cassette(
                    fence,
                    str(run["id"]),
                    1,
                    expected_state="recovery_required",
                    new_state=resumed_state,
                )
                resumed = catalog.restore_run(str(run["id"]))
                self.assertEqual(resumed_state, resumed["state"])
                self.assertEqual(
                    resumed_state, resumed["cassettes"][0]["state"]
                )

    def test_pending_item_cannot_clear_parent_recovery_with_open_conflict(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]),
                    actor="operator-1",
                    idempotency_key="restore-run-1",
                    request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1",
                        "restore-operation-key-1",
                        kind="restore.cassette",
                        job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.record_restore_item_conflict(
                    fence,
                    str(run["id"]),
                    1,
                    canonical_destination=(
                        "/srv/restores/selection/RESTORELIB/one.bin"
                    ),
                    observed_size=9,
                    observed_sha256="9" * 64,
                )

                with self.assertRaisesRegex(CatalogError, "recovery"):
                    catalog.transition_restore_item(
                        fence,
                        str(run["id"]),
                        2,
                        expected_state="pending",
                        new_state="restoring",
                        bytes_copied=0,
                        observed_sha256=None,
                    )

                blocked = catalog.restore_run(str(run["id"]))
                self.assertEqual("recovery_required", blocked["state"])
                self.assertEqual(
                    "recovery_required", blocked["cassettes"][0]["state"]
                )
                self.assertEqual("pending", blocked["items"][1]["state"])

    def test_authorized_conflict_keeps_recovery_gate_closed_until_consumed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]),
                    actor="operator-1",
                    idempotency_key="restore-run-1",
                    request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1",
                        "restore-operation-key-1",
                        kind="restore.cassette",
                        job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.record_restore_item_conflict(
                    fence,
                    str(run["id"]),
                    1,
                    canonical_destination=(
                        "/srv/restores/selection/RESTORELIB/one.bin"
                    ),
                    observed_size=9,
                    observed_sha256="9" * 64,
                )
                authorization = catalog.authorize_restore_item_replacement(
                    str(run["id"]),
                    1,
                    administrator="admin-1",
                    fresh_reauthentication="d" * 64,
                    idempotency_key="replacement-authorization-1",
                )

                for resumed_state in ("waiting_media", "restoring"):
                    with self.subTest(resumed_state=resumed_state):
                        with self.assertRaisesRegex(CatalogError, "authorization"):
                            catalog.transition_restore_cassette(
                                fence,
                                str(run["id"]),
                                1,
                                expected_state="recovery_required",
                                new_state=resumed_state,
                            )
                with self.assertRaisesRegex(CatalogError, "recovery"):
                    catalog.transition_restore_item(
                        fence,
                        str(run["id"]),
                        2,
                        expected_state="pending",
                        new_state="restoring",
                        bytes_copied=0,
                        observed_sha256=None,
                    )

                blocked = catalog.restore_run(str(run["id"]))
                self.assertEqual("recovery_required", blocked["state"])
                self.assertEqual(
                    ["recovery_required"],
                    [cassette["state"] for cassette in blocked["cassettes"]],
                )
                self.assertEqual(
                    ["recovery_required", "pending"],
                    [item["state"] for item in blocked["items"]],
                )
                self.assertEqual(
                    "authorized", blocked["items"][0]["conflict"]["state"]
                )
                self.assertEqual(
                    authorization["id"],
                    blocked["items"][0]["conflict"]["authorization_id"],
                )
                durable_authorization = catalog.connection.execute(
                    "SELECT state,consumed_at,consumed_by_operation_id "
                    "FROM restore_replacement_authorizations WHERE id=?",
                    (authorization["id"],),
                ).fetchone()
                self.assertEqual(
                    ("authorized", None, None), tuple(durable_authorization)
                )

                consumed = catalog.consume_restore_item_replacement_authorization(
                    fence,
                    str(run["id"]),
                    1,
                    str(authorization["id"]),
                )
                self.assertEqual("consumed", consumed["state"])
                catalog.transition_restore_cassette(
                    fence,
                    str(run["id"]),
                    1,
                    expected_state="recovery_required",
                    new_state="restoring",
                )
                released = catalog.restore_run(str(run["id"]))
                self.assertEqual("restoring", released["state"])
                self.assertEqual("restoring", released["cassettes"][0]["state"])

    def test_authorized_conflict_is_not_replacement_admission_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-1", request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1", "restore-operation-key-1",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.record_restore_item_conflict(
                    fence, str(run["id"]), 1,
                    canonical_destination=(
                        "/srv/restores/selection/RESTORELIB/one.bin"
                    ),
                    observed_size=9, observed_sha256="9" * 64,
                )
                catalog.authorize_restore_item_replacement(
                    str(run["id"]), 1, administrator="admin-1",
                    fresh_reauthentication="d" * 64,
                    idempotency_key="replacement-authorization-1",
                )
                catalog.finish_operation(fence, "cancelled")

                candidate = catalog.next_restore_sequence_candidate()

                self.assertIsNone(candidate)

    def test_live_pause_marker_excludes_waiting_restore_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-1", request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1", "restore-operation-key-1",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.request_restore_run_pause(
                    str(run["id"]), actor="operator-2"
                )
                catalog.finish_operation(fence, "cancelled")

                candidate = catalog.next_restore_sequence_candidate()

                self.assertIsNone(candidate)

    def test_exact_pre_mount_pause_checkpoint_can_resume_without_recovery_prep(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-pause-resume",
                    request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-paused", "restore-operation-paused-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.request_restore_run_pause(
                    str(run["id"]), actor="operator-2"
                )

                control = catalog.checkpoint_restore_control_before_mount(
                    fence, str(run["id"]), 1
                )

                self.assertEqual("paused", control)
                self.assertIsNone(catalog.next_restore_sequence_candidate())
                self.assertEqual(
                    0,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM restore_retry_preparations "
                        "WHERE run_id=?",
                        (run["id"],),
                    ).fetchone()[0],
                )
                resumed = catalog.resume_restore_run(
                    str(run["id"]), actor="operator-3",
                    idempotency_key="resume-exact-pause",
                )

                self.assertEqual("waiting_media", resumed["state"])
                candidate = catalog.next_restore_sequence_candidate()
                self.assertIsNotNone(candidate)
                assert candidate is not None
                self.assertEqual(str(run["id"]), candidate["run_id"])
                self.assertEqual(2, candidate["attempt_number"])
                self.assertEqual("paused_resume", candidate["continuation_kind"])

            with Catalog(database) as reopened:
                replay = reopened.resume_restore_run(
                    str(run["id"]), actor="operator-3",
                    idempotency_key="resume-exact-pause",
                )
                candidate = reopened.next_restore_sequence_candidate()

            self.assertEqual(resumed, replay)
            self.assertIsNotNone(candidate)
            assert candidate is not None
            self.assertEqual("paused_resume", candidate["continuation_kind"])

    def test_waiting_media_pause_can_resume_without_a_new_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-waiting-pause",
                    request_sha256="c" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-waiting-pause",
                        "restore-operation-waiting-pause-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.request_restore_run_pause(
                    str(run["id"]), actor="operator-2"
                )
                self.assertEqual(
                    "paused",
                    catalog.checkpoint_restore_control_before_mount(
                        fence, str(run["id"]), 1
                    ),
                )
                catalog.resume_restore_run(
                    str(run["id"]), actor="operator-3",
                    idempotency_key="resume-to-waiting-media",
                )
                catalog.request_restore_run_pause(
                    str(run["id"]), actor="operator-4",
                    idempotency_key="pause-while-waiting-media",
                )

                resumed = catalog.resume_restore_run(
                    str(run["id"]), actor="operator-5",
                    idempotency_key="resume-after-waiting-pause",
                )

                self.assertEqual("waiting_media", resumed["state"])
                candidate = catalog.next_restore_sequence_candidate()
                self.assertIsNotNone(candidate)
                assert candidate is not None
                self.assertEqual("paused_resume", candidate["continuation_kind"])
                self.assertEqual(admitted.record.id, candidate["source_operation_id"])

    def test_old_pause_proof_cannot_authorize_a_newer_unproven_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-stale-pause-proof",
                    request_sha256="b" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                proven_record = replace(
                    operation_candidate(
                        "restore-operation-z-proven", "restore-operation-1-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    started_at="2030-01-01T00:00:00+00:00",
                )
                proven = catalog.admit_operation(
                    proven_record,
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                proven_fence = OperationFence(proven.record.id, owner.generation)
                catalog.request_restore_run_pause(
                    str(run["id"]), actor="operator-2"
                )
                catalog.checkpoint_restore_control_before_mount(
                    proven_fence, str(run["id"]), 1
                )
                catalog.resume_restore_run(str(run["id"]), actor="operator-3")
                unproven_record = replace(
                    operation_candidate(
                        "restore-operation-a-unproven", "restore-operation-2-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    started_at="2020-01-01T00:00:00+00:00",
                )
                unproven = catalog.admit_operation(
                    unproven_record,
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                catalog.finish_operation(
                    OperationFence(unproven.record.id, owner.generation),
                    "cancelled",
                    error_class="operator_required",
                    error_code="operation_cancelled",
                )

                latest = catalog.connection.execute(
                    "SELECT id FROM daemon_operations WHERE kind='restore.cassette' "
                    "AND job_id=? AND cassette_sequence=1 "
                    "ORDER BY rowid DESC LIMIT 1",
                    (run["id"],),
                ).fetchone()
                self.assertEqual(unproven.record.id, latest["id"])
                self.assertIsNotNone(catalog.connection.execute(
                    "SELECT 1 FROM restore_release_receipts WHERE operation_id=?",
                    (proven.record.id,),
                ).fetchone())
                self.assertIsNone(catalog.connection.execute(
                    "SELECT 1 FROM restore_release_receipts WHERE operation_id=?",
                    (unproven.record.id,),
                ).fetchone())
                self.assertIsNone(catalog.next_restore_sequence_candidate())

    def test_restore_sequence_admission_revalidates_terminal_control_atomically(self) -> None:
        for control in ("pause", "cancel"):
            with self.subTest(control=control), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "catalog.db"
                with Catalog(database) as catalog:
                    catalog.initialize()
                    plan = seed_one_tape_two_item_restore_plan(catalog)
                    run = catalog.create_restore_run(
                        str(plan["id"]), actor="operator-1",
                        idempotency_key=f"restore-run-race-{control}",
                        request_sha256="c" * 64,
                    )
                    owner = catalog.claim_daemon_owner("restore-daemon")
                    expected = catalog.next_restore_sequence_candidate()
                assert expected is not None
                key = hashlib.sha256(
                    f"restore.cassette\0{run['id']}\0{1}\0{1}".encode()
                ).hexdigest()
                candidate = operation_candidate(
                    f"restore-race-{control}", key,
                    kind="restore.cassette", job_id=str(run["id"]),
                    cassette_sequence=1,
                )
                with Catalog(database) as concurrent:
                    if control == "pause":
                        concurrent.request_restore_run_pause(
                            str(run["id"]), actor="operator-2"
                        )
                    else:
                        concurrent.request_restore_run_cancel(
                            str(run["id"]), actor="operator-2"
                        )
                with Catalog(database) as catalog:
                    with self.assertRaises(MutationAdmissionClosed):
                        catalog.admit_restore_sequence_operation(
                            candidate,
                            owner,
                            admission_open=True,
                            hardware_target=synthetic_target(),
                            expected_candidate=expected,
                        )
                    self.assertIsNone(catalog.connection.execute(
                        "SELECT 1 FROM daemon_operations WHERE id=?",
                        (candidate.id,),
                    ).fetchone())

    def test_replacement_begin_rolls_back_consumption_when_item_cas_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-1", request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1", "restore-operation-key-1",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.record_restore_item_conflict(
                    fence, str(run["id"]), 1,
                    canonical_destination=(
                        "/srv/restores/selection/RESTORELIB/one.bin"
                    ),
                    observed_size=9, observed_sha256="9" * 64,
                )
                authorization = catalog.authorize_restore_item_replacement(
                    str(run["id"]), 1, administrator="admin-1",
                    fresh_reauthentication="d" * 64,
                    idempotency_key="replacement-authorization-1",
                )
                catalog.connection.execute(
                    "CREATE TRIGGER fail_restore_replacement_begin "
                    "BEFORE UPDATE ON restore_run_items "
                    "WHEN NEW.state='restoring' BEGIN "
                    "SELECT RAISE(ABORT,'injected item CAS failure'); END"
                )

                with self.assertRaises(sqlite3.DatabaseError):
                    catalog.consume_restore_item_replacement_and_begin(
                        fence, str(run["id"]), 1, str(authorization["id"])
                    )

                durable = catalog.restore_run(str(run["id"]))
                row = catalog.connection.execute(
                    "SELECT state,consumed_at,consumed_by_operation_id "
                    "FROM restore_replacement_authorizations WHERE id=?",
                    (authorization["id"],),
                ).fetchone()
                self.assertEqual("recovery_required", durable["items"][0]["state"])
                self.assertEqual("authorized", durable["items"][0]["conflict"]["state"])
                self.assertEqual(("authorized", None, None), tuple(row))

    def test_restore_recovery_resolution_and_retry_readiness_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-1", request_sha256="a" * 64,
                )
                target = synthetic_target()
                original = catalog.claim_daemon_owner("restore-original")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1", "restore-operation-key-1",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    original,
                    admission_open=True,
                    hardware_target=target,
                )
                fence = OperationFence(admitted.record.id, original.generation)
                catalog.transition_restore_cassette(
                    fence, str(run["id"]), 1,
                    expected_state="waiting_media", new_state="restoring",
                )
                insert_quiesced_restore_unload(
                    catalog, admitted.record.id, original.generation, target
                )
                insert_quiesced_restore_no_media_probe(
                    catalog, admitted.record.id, original.generation, target
                )
                mounted, unmount = restore_release_fixture(
                    admitted.record.id, original.generation
                )
                mismatched = replace(
                    mounted,
                    session_receipt=replace(
                        mounted.session_receipt, operation_id="other-operation"
                    ),
                )
                with self.assertRaises((CatalogError, ValidationError)):
                    catalog.record_restore_post_eject_receipt(
                        fence,
                        str(run["id"]),
                        1,
                        mismatched,
                        unmount,
                        no_media_proven=True,
                    )
                with self.assertRaises(ValidationError):
                    catalog.record_restore_post_eject_receipt(
                        fence,
                        str(run["id"]),
                        1,
                        mounted,
                        unmount,
                        no_media_proven=False,
                    )
                catalog.connection.execute(
                    "UPDATE hardware_command_executions "
                    "SET terminal_exit_code=1 WHERE id='restore-unload'"
                )
                with self.assertRaises(CatalogError):
                    catalog.record_restore_post_eject_receipt(
                        fence,
                        str(run["id"]),
                        1,
                        mounted,
                        unmount,
                        no_media_proven=True,
                    )
                catalog.connection.execute(
                    "UPDATE hardware_command_executions "
                    "SET terminal_exit_code=0 WHERE id='restore-unload'"
                )
                catalog.connection.execute(
                    "UPDATE hardware_command_executions "
                    "SET terminal_exit_code=0 WHERE id='restore-probe-no-media'"
                )
                with self.assertRaises(CatalogError):
                    catalog.record_restore_post_eject_receipt(
                        fence,
                        str(run["id"]),
                        1,
                        mounted,
                        unmount,
                        no_media_proven=True,
                    )
                catalog.connection.execute(
                    "UPDATE hardware_command_executions "
                    "SET terminal_exit_code=3 WHERE id='restore-probe-no-media'"
                )
                catalog.record_restore_post_eject_receipt(
                    fence,
                    str(run["id"]),
                    1,
                    mounted,
                    unmount,
                    no_media_proven=True,
                )
                catalog.transition_restore_cassette(
                    fence, str(run["id"]), 1,
                    expected_state="restoring", new_state="recovery_required",
                    error_code="restore_copy_failed",
                )
                catalog.finish_operation(
                    fence, "recovery_required", error_class="operator_required",
                    error_code="recovery_required",
                )
                recovered = catalog.claim_daemon_owner("restore-recovered")
                command = catalog.create_command_quiescence_receipt(
                    admitted.record.id, recovered
                )
                physical = catalog.create_physical_reconciliation_receipt(
                    admitted.record.id,
                    recovered,
                    command.id,
                    VerifiedPhysicalQuiescence(
                        target, None, False, False, False, (),
                    ),
                )
                resolution = SafeRecoveryResolution(
                    "restore_restart_safe", command.id, physical.id
                )
                catalog.connection.execute(
                    "CREATE TRIGGER fail_restore_retry_readiness "
                    "BEFORE UPDATE ON restore_runs "
                    "WHEN NEW.state='waiting_media' BEGIN "
                    "SELECT RAISE(ABORT,'injected retry readiness failure'); END"
                )

                with self.assertRaises(sqlite3.DatabaseError):
                    catalog.resolve_restore_recovery_boundary(
                        admitted.record.id,
                        str(run["id"]),
                        1,
                        str(run["plan_fingerprint_sha256"]),
                        recovered,
                        resolution,
                        action="retry",
                    )

                self.assertIsNone(
                    catalog.connection.execute(
                        "SELECT 1 FROM recovery_resolutions WHERE operation_id=?",
                        (admitted.record.id,),
                    ).fetchone()
                )
                self.assertEqual(
                    "recovery_required",
                    catalog.get_operation(admitted.record.id)["state"],
                )
                self.assertEqual(
                    "recovery_required", catalog.restore_run(str(run["id"]))["state"]
                )
                catalog.connection.execute(
                    "DROP TRIGGER fail_restore_retry_readiness"
                )

                prepared = catalog.resolve_restore_recovery_boundary(
                    admitted.record.id,
                    str(run["id"]),
                    1,
                    str(run["plan_fingerprint_sha256"]),
                    recovered,
                    resolution,
                    action="retry",
                )

                self.assertEqual("waiting_media", prepared["state"])
                self.assertEqual(
                    admitted.record.id,
                    catalog.connection.execute(
                        "SELECT source_operation_id FROM restore_retry_preparations "
                        "WHERE run_id=? AND cassette_sequence=1",
                        (run["id"],),
                    ).fetchone()["source_operation_id"],
                )
                self.assertEqual(
                    str(run["id"]),
                    catalog.next_restore_sequence_candidate()["run_id"],
                )
                self.assertEqual(
                    "recovery_retry",
                    catalog.next_restore_sequence_candidate()["continuation_kind"],
                )
                unprepared = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-2-unprepared", "restore-operation-2-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    recovered,
                    admission_open=True,
                    hardware_target=target,
                )
                catalog.finish_operation(
                    OperationFence(unprepared.record.id, recovered.generation),
                    "cancelled",
                    error_class="operator_required",
                    error_code="operation_cancelled",
                )
                self.assertIsNone(catalog.next_restore_sequence_candidate())

    def test_restore_recovery_stale_retry_yields_to_pending_pause(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                fixture = seed_post_eject_restore_recovery_boundary(
                    catalog, complete=False, pending_control="pause"
                )
                run = fixture["run"]

                resolved = catalog.resolve_restore_recovery_boundary(
                    str(fixture["operation_id"]),
                    str(run["id"]),
                    1,
                    str(run["plan_fingerprint_sha256"]),
                    fixture["recovered"],
                    fixture["resolution"],
                    action="retry",
                )

                self.assertEqual("paused", resolved["state"])
                self.assertEqual("waiting_media", resolved["cassettes"][0]["state"])
                self.assertEqual(
                    "cancelled",
                    catalog.get_operation(str(fixture["operation_id"]))["state"],
                )
                self.assertEqual(
                    0,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM restore_retry_preparations "
                        "WHERE run_id=?",
                        (run["id"],),
                    ).fetchone()[0],
                )
                self.assertIsNone(catalog.next_restore_sequence_candidate())

    def test_restore_recovery_stale_commit_yields_to_pending_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                fixture = seed_post_eject_restore_recovery_boundary(
                    catalog, complete=True, pending_control="cancel"
                )
                run = fixture["run"]

                resolved = catalog.resolve_restore_recovery_boundary(
                    str(fixture["operation_id"]),
                    str(run["id"]),
                    1,
                    str(run["plan_fingerprint_sha256"]),
                    fixture["recovered"],
                    fixture["resolution"],
                    action="commit",
                )

                self.assertEqual("cancelled", resolved["state"])
                self.assertNotEqual("completed", resolved["cassettes"][0]["state"])
                self.assertEqual(
                    "cancelled",
                    catalog.get_operation(str(fixture["operation_id"]))["state"],
                )
                self.assertEqual(
                    0,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM restore_retry_preparations "
                        "WHERE run_id=?",
                        (run["id"],),
                    ).fetchone()[0],
                )
                self.assertIsNone(catalog.next_restore_sequence_candidate())

    def test_restore_pre_mount_cancel_requires_and_records_exact_safe_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-1", request_sha256="a" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1", "restore-operation-key-1",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admitted.record.id, owner.generation)
                catalog.request_restore_run_cancel(
                    str(run["id"]), actor="operator-2"
                )

                control = catalog.checkpoint_restore_control_before_mount(
                    fence, str(run["id"]), 1
                )

                after = catalog.restore_run(str(run["id"]))
                receipt = catalog.connection.execute(
                    "SELECT boundary,operation_id,plan_fingerprint_sha256 "
                    "FROM restore_release_receipts WHERE operation_id=?",
                    (admitted.record.id,),
                ).fetchone()
                self.assertEqual("cancelled", control)
                self.assertEqual("cancelled", after["state"])
                self.assertEqual("pre_mount", receipt["boundary"])
                self.assertEqual(admitted.record.id, receipt["operation_id"])
                self.assertEqual(
                    run["plan_fingerprint_sha256"],
                    receipt["plan_fingerprint_sha256"],
                )
                self.assertEqual(
                    0,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM hardware_command_executions "
                        "WHERE operation_id=? AND command_kind IN "
                        "('mount','unmount','load','unload','format')",
                        (admitted.record.id,),
                    ).fetchone()[0],
                )

    def test_restore_pre_mount_failure_repairs_receipt_and_prepares_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-pre-mount-recovery",
                    request_sha256="d" * 64,
                )
                target = synthetic_target()
                original = catalog.claim_daemon_owner("restore-original")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-pre-mount-failure", "restore-pre-mount-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    original,
                    admission_open=True,
                    hardware_target=target,
                )
                fence = OperationFence(admitted.record.id, original.generation)
                catalog.transition_restore_cassette(
                    fence, str(run["id"]), 1,
                    expected_state="waiting_media", new_state="recovery_required",
                    error_code="destination_unavailable",
                )
                catalog.finish_operation(
                    fence, "recovery_required", error_class="operator_required",
                    error_code="recovery_required",
                )
                recovered = catalog.claim_daemon_owner("restore-recovered")

                self.assertTrue(
                    catalog.restore_pre_mount_recovery_candidate(
                        admitted.record.id, str(run["id"]), 1,
                        str(run["plan_fingerprint_sha256"]),
                    )
                )
                catalog.record_restore_pre_mount_recovery_receipt(
                    recovered, admitted.record.id, str(run["id"]), 1,
                    str(run["plan_fingerprint_sha256"]),
                )
                command = catalog.create_command_quiescence_receipt(
                    admitted.record.id, recovered
                )
                physical = catalog.create_physical_reconciliation_receipt(
                    admitted.record.id,
                    recovered,
                    command.id,
                    VerifiedPhysicalQuiescence(
                        target, None, False, False, False, ()
                    ),
                )
                prepared = catalog.resolve_restore_recovery_boundary(
                    admitted.record.id,
                    str(run["id"]),
                    1,
                    str(run["plan_fingerprint_sha256"]),
                    recovered,
                    SafeRecoveryResolution(
                        "restore_restart_safe", command.id, physical.id
                    ),
                    action="retry",
                )

                self.assertEqual("pre_mount", catalog.restore_release_boundary(
                    admitted.record.id, str(run["id"]), 1,
                    str(run["plan_fingerprint_sha256"]),
                ))
                self.assertEqual("waiting_media", prepared["state"])
                self.assertEqual("cancelled", catalog.get_operation(
                    admitted.record.id
                )["state"])
                self.assertEqual(
                    str(run["id"]), catalog.next_restore_sequence_candidate()["run_id"]
                )

    def test_restore_recovery_reconciles_completed_items_after_exact_eject(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:  # noqa: SIM117
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                plan = seed_two_tape_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-run-1", request_sha256="a" * 64,
                )
                target = synthetic_target()
                original = catalog.claim_daemon_owner("restore-original")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-operation-1", "restore-operation-key-1",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    original,
                    admission_open=True,
                    hardware_target=target,
                )
                fence = OperationFence(admitted.record.id, original.generation)
                catalog.transition_restore_cassette(
                    fence, str(run["id"]), 1,
                    expected_state="waiting_media", new_state="restoring",
                )
                first = catalog.restore_run(str(run["id"]))["items"][0]
                catalog.transition_restore_item(
                    fence, str(run["id"]), 1,
                    expected_state="pending", new_state="restoring",
                    bytes_copied=0, observed_sha256=None,
                )
                catalog.transition_restore_item(
                    fence, str(run["id"]), 1,
                    expected_state="restoring", new_state="restored",
                    bytes_copied=first["plan_item"]["size"],
                    observed_sha256=first["plan_item"]["sha256"],
                )
                insert_quiesced_restore_unload(
                    catalog, admitted.record.id, original.generation, target
                )
                insert_quiesced_restore_no_media_probe(
                    catalog, admitted.record.id, original.generation, target
                )
                mounted, unmount = restore_release_fixture(
                    admitted.record.id, original.generation
                )
                catalog.record_restore_post_eject_receipt(
                    fence,
                    str(run["id"]),
                    1,
                    mounted,
                    unmount,
                    no_media_proven=True,
                )
                catalog.finish_operation(
                    fence, "recovery_required", error_class="operator_required",
                    error_code="recovery_required",
                )
                with catalog.transaction() as db:
                    db.execute(
                        "UPDATE restore_run_cassettes SET state='recovery_required',"
                        "last_error_code='restore_copy_failed' WHERE run_id=? AND sequence=1",
                        (run["id"],),
                    )
                    db.execute(
                        "UPDATE restore_runs SET state='recovery_required',"
                        "last_error_code='restore_copy_failed' WHERE id=?",
                        (run["id"],),
                    )
                recovered = catalog.claim_daemon_owner("restore-recovered")
                command = catalog.create_command_quiescence_receipt(
                    admitted.record.id, recovered
                )
                physical = catalog.create_physical_reconciliation_receipt(
                    admitted.record.id, recovered, command.id,
                    VerifiedPhysicalQuiescence(target, None, False, False, False, ()),
                )

                reconciled = catalog.resolve_restore_recovery_boundary(
                    admitted.record.id,
                    str(run["id"]),
                    1,
                    str(run["plan_fingerprint_sha256"]),
                    recovered,
                    SafeRecoveryResolution(
                        "restore_commit_safe", command.id, physical.id
                    ),
                    action="commit",
                )

                self.assertEqual("waiting_media", reconciled["state"])
                self.assertEqual("completed", reconciled["cassettes"][0]["state"])
                self.assertEqual("waiting_media", reconciled["cassettes"][1]["state"])
                self.assertEqual(
                    2,
                    catalog.next_restore_sequence_candidate()["cassette_sequence"],
                )

    def test_schema_38_frozen_fixture_augments_an_existing_current_catalog(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            backup = root / (
                "20260831T180000000000Z-abcdef123456-p-v37-"
                "0123456789abcdef.sqlite3"
            )
            existing_source = root / "existing-source"
            existing_source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=38)
                catalog.add_library(
                    "EXISTING",
                    "Existing current-schema library",
                    str(existing_source),
                )

            try:
                build_frozen_job_fixture(database, schema_version=38)
            except CatalogError as exc:
                self.fail(f"current-schema fixture augmentation failed: {exc}")

            with Catalog(database) as catalog:
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                libraries = {
                    row[0]
                    for row in catalog.connection.execute(
                        "SELECT id FROM libraries"
                    )
                }
                job = catalog.connection.execute(
                    "SELECT id FROM automatic_jobs WHERE id='JOB-MIGRATION'"
                ).fetchone()

            self.assertEqual("38", version)
            self.assertEqual({"EXISTING", "LIB1"}, libraries)
            self.assertIsNotNone(job)
            self.assertFalse(backup.exists())

    def test_schema_38_frozen_fixture_snapshots_the_live_schema_37_source(
        self,
    ) -> None:
        for existing_schema_37 in (False, True):
            with (
                self.subTest(existing_schema_37=existing_schema_37),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                database = root / "catalog.db"
                backup = root / (
                    "20260831T180000000000Z-abcdef123456-p-v37-"
                    "0123456789abcdef.sqlite3"
                )
                if existing_schema_37:
                    existing_source = root / "existing-schema-37-source"
                    existing_source.mkdir()
                    with Catalog(database) as catalog:
                        catalog.initialize(target_version=37)
                        catalog.add_library(
                            "EXISTING37",
                            "Existing schema-37 library",
                            str(existing_source),
                        )

                build_frozen_job_fixture(database, schema_version=38)

                with sqlite3.connect(backup) as connection:
                    backed_up_libraries = {
                        row[0]
                        for row in connection.execute("SELECT id FROM libraries")
                    }
                self.assertNotEqual(database.resolve(), backup.resolve())
                self.assertEqual("38", read_schema_version(database))
                self.assertEqual("37", read_schema_version(backup))
                self.assertEqual(
                    {"EXISTING37"} if existing_schema_37 else set(),
                    backed_up_libraries,
                )
                self.assertEqual(["ok"], integrity_check(backup))
                self.assertEqual([], foreign_key_violations(backup))

    def test_empty_schema_37_requires_source_backup_for_schema_38(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=37)
            backup = root / (
                "20260831T075900000000Z-abcdef123456-p-v37-"
                "0123456789abcdef.sqlite3"
            )
            shutil.copy2(database, backup)

            with Catalog(database) as catalog:
                catalog._initialize_after_protected_backup(38, backup)
                count = catalog.connection.execute(
                    "SELECT COUNT(*) FROM operation_sequence_continuations"
                ).fetchone()[0]

            self.assertEqual("38", read_schema_version(database))
            self.assertEqual(0, count)
            self.assertEqual(["ok"], integrity_check(database))
            self.assertEqual([], foreign_key_violations(database))

    def test_schema_38_adds_empty_immutable_sequence_continuation_bindings(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            build_frozen_job_fixture(
                database, completed=3, total=20, schema_version=37
            )
            with sqlite3.connect(database) as connection:
                epoch = connection.execute(
                    "SELECT epoch_number,layout_fingerprint_sha256 "
                    "FROM job_layout_epochs WHERE job_id='JOB-MIGRATION' "
                    "ORDER BY epoch_number DESC LIMIT 1"
                ).fetchone()
                connection.execute(
                    "INSERT INTO automatic_format_authorizations("
                    "authorization_id,job_id,cassette_sequence,layout_epoch,"
                    "layout_fingerprint_sha256,expected_label,expected_operation,"
                    "reuse_registered,authorized_by,authorized_at,request_sha256) "
                    "VALUES(?,?,?,?,?,?,'format',0,'admin-1',?,?)",
                    (
                        "AUTH-PRESERVED",
                        "JOB-MIGRATION",
                        4,
                        epoch[0],
                        epoch[1],
                        "TAPE04",
                        "2026-08-31T08:00:00+00:00",
                        "a" * 64,
                    ),
                )
            before = canonical_row_snapshot(
                database,
                (
                    "automatic_format_authorizations",
                    "automatic_sequence_state",
                    "operation_format_authorizations",
                ),
            )

            with Catalog(database) as catalog:
                with self.assertRaisesRegex(CatalogError, "protected backup"):
                    catalog.initialize(target_version=38)
                wrong_source = root / (
                    "20260831T080000000000Z-abcdef123456-p-v36-"
                    "0123456789abcdef.sqlite3"
                )
                shutil.copy2(database, wrong_source)
                with self.assertRaisesRegex(CatalogError, "protected backup"):
                    catalog._initialize_after_protected_backup(38, wrong_source)
                backup = root / (
                    "20260831T080000000000Z-abcdef123456-p-v37-"
                    "0123456789abcdef.sqlite3"
                )
                shutil.copy2(database, backup)
                catalog._initialize_after_protected_backup(38, backup)
                table_info = tuple(
                    catalog.connection.execute(
                        "PRAGMA table_info(operation_sequence_continuations)"
                    )
                )
                indexes = tuple(
                    catalog.connection.execute(
                        "PRAGMA index_list(operation_sequence_continuations)"
                    )
                )
                foreign_keys = tuple(
                    catalog.connection.execute(
                        "PRAGMA foreign_key_list(operation_sequence_continuations)"
                    )
                )
                trigger_names = {
                    str(row[0])
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger' "
                        "AND tbl_name='operation_sequence_continuations'"
                    )
                }
                catalog.initialize(target_version=38)

            self.assertEqual(41, SCHEMA_VERSION)
            self.assertEqual("38", read_schema_version(database))
            self.assertEqual(
                (
                    "operation_id",
                    "job_id",
                    "cassette_sequence",
                    "layout_epoch",
                    "layout_fingerprint_sha256",
                    "continuation_idempotency_key",
                    "linked_at",
                ),
                tuple(str(row[1]) for row in table_info),
            )
            self.assertEqual(
                ("operation_id",),
                tuple(str(row[1]) for row in table_info if int(row[5]) > 0),
            )
            with sqlite3.connect(database) as connection:
                unique_keys = {
                    tuple(
                        str(column[2])
                        for column in connection.execute(
                            f"PRAGMA index_info({index[1]})"
                        )
                    )
                    for index in indexes
                    if int(index[2]) and str(index[3]).casefold() == "u"
                }
            self.assertEqual({("continuation_idempotency_key",)}, unique_keys)
            self.assertEqual(
                {
                    (("operation_id",), "daemon_operations", ("id",)),
                    (
                        ("job_id", "cassette_sequence"),
                        "automatic_cassettes",
                        ("job_id", "sequence"),
                    ),
                    (
                        ("job_id", "layout_epoch"),
                        "job_layout_epochs",
                        ("job_id", "epoch_number"),
                    ),
                },
                {
                    (
                        tuple(str(part[3]) for part in sorted(group, key=lambda part: part[1])),
                        str(group[0][2]),
                        tuple(str(part[4]) for part in sorted(group, key=lambda part: part[1])),
                    )
                    for group in (
                        [row for row in foreign_keys if row[0] == identifier]
                        for identifier in {row[0] for row in foreign_keys}
                    )
                },
            )
            self.assertEqual(
                {
                    "trg_operation_sequence_continuations_no_update",
                    "trg_operation_sequence_continuations_no_delete",
                },
                trigger_names,
            )
            after = canonical_row_snapshot(database, tuple(before))
            for table, rows in before.items():
                with self.subTest(table=table):
                    self.assertTrue(all(row in after[table] for row in rows))
            with sqlite3.connect(database) as connection:
                self.assertEqual(
                    0,
                    connection.execute(
                        "SELECT COUNT(*) FROM operation_sequence_continuations"
                    ).fetchone()[0],
                )
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute(
                    "INSERT INTO daemon_operations("
                    "id,kind,state,idempotency_key,principal,owner_generation,"
                    "job_id,cassette_sequence,started_at) "
                    "VALUES('CONTINUATION-1','archive.native','succeeded',"
                    "'continuation-key-1','sequence-coordinator',1,"
                    "'JOB-MIGRATION',4,'2026-08-31T08:01:00+00:00')"
                )
                connection.execute(
                    "INSERT INTO operation_sequence_continuations("
                    "operation_id,job_id,cassette_sequence,layout_epoch,"
                    "layout_fingerprint_sha256,continuation_idempotency_key,linked_at) "
                    "VALUES('CONTINUATION-1','JOB-MIGRATION',4,?,?,?,?)",
                    (
                        epoch[0],
                        epoch[1],
                        "continuation-key-1",
                        "2026-08-31T08:01:00+00:00",
                    ),
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "immutable_operation_sequence_continuation",
                ):
                    connection.execute(
                        "UPDATE operation_sequence_continuations "
                        "SET linked_at='2026-08-31T08:02:00+00:00' "
                        "WHERE operation_id='CONTINUATION-1'"
                    )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError,
                    "immutable_operation_sequence_continuation",
                ):
                    connection.execute(
                        "DELETE FROM operation_sequence_continuations "
                        "WHERE operation_id='CONTINUATION-1'"
                    )
                self.assertEqual(
                    1,
                    connection.execute(
                        "SELECT COUNT(*) FROM operation_sequence_continuations"
                    ).fetchone()[0],
                )
            self.assertEqual(["ok"], integrity_check(database))
            self.assertEqual([], foreign_key_violations(database))

    def test_schema_38_migration_failure_rolls_back_source_and_keeps_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            build_frozen_job_fixture(
                database, completed=3, total=20, schema_version=37
            )
            before = canonical_row_snapshot(
                database,
                (
                    "automatic_format_authorizations",
                    "automatic_sequence_state",
                    "operation_format_authorizations",
                ),
            )
            backup = root / (
                "20260831T080000000000Z-abcdef123456-p-v37-"
                "0123456789abcdef.sqlite3"
            )
            shutil.copy2(database, backup)
            migrate = Catalog._migrate_v37_to_v38

            def fail_after_transactional_ddl(catalog, connection):
                migrate(catalog, connection)
                raise CatalogError("injected schema 38 failure")

            with (
                patch.object(
                    Catalog,
                    "_migrate_v37_to_v38",
                    autospec=True,
                    side_effect=fail_after_transactional_ddl,
                ),
                Catalog(database) as catalog,
                self.assertRaisesRegex(CatalogError, "injected schema 38 failure"),
            ):
                catalog._initialize_after_protected_backup(38, backup)

            self.assertEqual("37", read_schema_version(database))
            self.assertEqual(before, canonical_row_snapshot(database, tuple(before)))
            with sqlite3.connect(database) as connection:
                self.assertIsNone(
                    connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name='operation_sequence_continuations'"
                    ).fetchone()
                )
            self.assertEqual("37", read_schema_version(backup))
            self.assertEqual(["ok"], integrity_check(database))
            self.assertEqual([], foreign_key_violations(database))

    def test_schema_36_does_not_infer_legacy_format_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=35)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "AUTO-LEGACY",
                    "LIB1",
                    "synthetic-drive",
                    "/synthetic/mount",
                    [("AL0001", "SERIAL-1", 1, 7)],
                    force_format=True,
                )

            with Catalog(database) as catalog:
                backup = root / (
                    "20260830T180000000000Z-abcdef123456-p-v35-"
                    "0123456789abcdef.sqlite3"
                )
                shutil.copy2(database, backup)
                catalog._initialize_after_protected_backup(37, backup)
                self.assertEqual(41, SCHEMA_VERSION)
                self.assertIsNone(
                    catalog.format_sequence_authorization("AUTO-LEGACY", 1)
                )
                state = catalog.automatic_sequence_state("AUTO-LEGACY")

            self.assertEqual("disabled", state["state"])

    def test_reserve_layout_requires_fresh_exact_authority_and_keeps_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "AUTO-RESERVE", "LIB1", "drive", "/mnt",
                    [("AR0001", "AR0001", 1, 7)], force_format=True,
                )
                epoch = catalog.latest_layout_epoch("AUTO-RESERVE")
                catalog.authorize_automatic_format_sequence(
                    "AUTO-RESERVE", expected_revision=0,
                    layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                    actor="admin-1", idempotency_key="initial-authority",
                    authorized_at="2026-08-30T18:00:00+00:00",
                )
                with self.assertRaises(CatalogError):
                    catalog.reserve_job_labels(
                        "AUTO-RESERVE", ("AR0002",), expected_revision=0,
                        actor="admin-1", authorize_automatic_formatting=False,
                        request_sha256="1" * 64,
                    )
                self.assertEqual(1, len(catalog.list_automatic_cassettes("AUTO-RESERVE")))
                catalog.reserve_job_labels(
                    "AUTO-RESERVE", ("AR0002",), expected_revision=0,
                    actor="admin-1", authorize_automatic_formatting=True,
                    request_sha256="2" * 64,
                )
                state = catalog.automatic_sequence_state("AUTO-RESERVE")
                current = catalog.latest_layout_epoch("AUTO-RESERVE")
                rows = list(catalog.connection.execute(
                    "SELECT layout_epoch,cassette_sequence FROM automatic_format_authorizations "
                    "WHERE job_id='AUTO-RESERVE' ORDER BY layout_epoch,cassette_sequence"
                ))
            self.assertEqual(current["epoch_number"], state["layout_epoch"])
            self.assertEqual("disabled", state["state"])
            self.assertEqual([(1, 1), (2, 1), (2, 2)], [tuple(row) for row in rows])

    def test_sequence_transition_audits_are_atomic_and_redact_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "AUTO-AUDIT", "LIB1", "drive", "/mnt",
                    [("AU0001", "AU0001", 1, 7)], force_format=True,
                )
                epoch = catalog.latest_layout_epoch("AUTO-AUDIT")
                catalog.authorize_automatic_format_sequence(
                    "AUTO-AUDIT", expected_revision=0,
                    layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                    actor="admin-1", idempotency_key="audit-authority",
                    authorized_at="2026-08-30T18:00:00+00:00",
                )
                with (
                    patch.object(Catalog, "_record_audit_tx", side_effect=RuntimeError("audit failed")),
                    self.assertRaisesRegex(RuntimeError, "audit failed"),
                ):
                    catalog.enable_automatic_sequence_for_start(
                        "AUTO-AUDIT", actor="admin-1",
                        enabled_at="2026-08-30T18:00:30+00:00",
                    )
                self.assertEqual(
                    "disabled", catalog.automatic_sequence_state("AUTO-AUDIT")["state"]
                )
                catalog.enable_automatic_sequence_for_start(
                    "AUTO-AUDIT", actor="admin-1",
                    enabled_at="2026-08-30T18:01:00+00:00",
                )
                catalog.update_automatic_job(
                    "AUTO-AUDIT", "waiting_media", current_sequence=1
                )
                catalog.update_automatic_cassette(
                    "AUTO-AUDIT", 1, "waiting_media"
                )
                authority = catalog.format_sequence_authorization("AUTO-AUDIT", 1)
                self.assertIsNotNone(authority)
                fence = catalog.claim_daemon_owner("daemon-a")
                continuation_key = hashlib.sha256(
                    f"AUTO-AUDIT\0{epoch['layout_fingerprint_sha256']}\0{1}\0"
                    f"{fence.generation}".encode("utf-8")
                ).hexdigest()
                candidate = operation_candidate(
                    "sequence-audit-operation",
                    continuation_key,
                    kind="archive.native",
                    principal="sequence-coordinator",
                    job_id="AUTO-AUDIT",
                    cassette_sequence=1,
                )
                target = HardwareTargetBinding.from_verified_inputs(
                    root / "mount", "tape-a", "scsi-a",
                    ("archive.native", "AUTO-AUDIT", "1", "AU0001", "", ""),
                )
                admitted = catalog.admit_operation(
                    candidate, fence, admission_open=True, hardware_target=target,
                    sequence_authorization_id=authority["authorization_id"],
                    sequence_layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                )
                replayed = catalog.admit_operation(
                    candidate, fence, admission_open=True, hardware_target=target,
                    sequence_authorization_id=authority["authorization_id"],
                    sequence_layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                )
                audits = list(catalog.connection.execute(
                    "SELECT action,payload_json FROM audit_entries WHERE action LIKE "
                    "'automatic.sequence.%' ORDER BY id"
                ))
            self.assertFalse(admitted.replayed)
            self.assertTrue(replayed.replayed)
            self.assertEqual(
                ["automatic.sequence.enabled", "automatic.sequence.continuation.admitted",
                 "automatic.sequence.continuation.replayed"],
                [row["action"] for row in audits],
            )
            self.assertNotIn("AU0001", "".join(row["payload_json"] for row in audits))
            payload = json.loads(audits[0]["payload_json"])
            self.assertEqual("AUTO-AUDIT", payload["job_id"])
            self.assertEqual(epoch["epoch_number"], payload.get("layout_epoch"))

    def test_sequence_terminal_completion_is_durably_audited_without_label(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "AUTO-DONE", "LIB1", "drive", "/mnt",
                    [("DN0001", "DN0001", 1, 7)], force_format=True,
                )
                epoch = catalog.latest_layout_epoch("AUTO-DONE")
                catalog.authorize_automatic_format_sequence(
                    "AUTO-DONE", expected_revision=0,
                    layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                    actor="admin-1", idempotency_key="done-authority",
                    authorized_at="2026-08-30T18:00:00+00:00",
                )
                catalog.update_automatic_job("AUTO-DONE", "waiting_media", current_sequence=1)
                catalog.update_automatic_cassette("AUTO-DONE", 1, "completed")
                self.assertIsNone(catalog.advance_automatic_job_after_eject("AUTO-DONE", 1))
                row = catalog.connection.execute(
                    "SELECT payload_json FROM audit_entries WHERE "
                    "action='automatic.sequence.terminal_stopped'"
                ).fetchone()
            self.assertIsNotNone(row)
            self.assertNotIn("DN0001", row["payload_json"])
            self.assertEqual("completed", json.loads(row["payload_json"])["reason"])

    def test_schema_thirty_two_makes_current_binding_refreshable_without_rewriting_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with Catalog(database_path) as catalog:
                catalog.initialize(target_version=30)
                catalog.add_named_library(
                    "LOCAL",
                    "Local library",
                    str(source),
                    str(source),
                    "a" * 64,
                )
                before = dict(catalog.get_named_library("LOCAL"))

            with Catalog(database_path) as catalog:
                initialize_current_with_protected_backup(catalog, root)
                after = {key: catalog.get_named_library("LOCAL")[key] for key in before}
                tables = {
                    row[0]
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                lease_columns = {
                    row[1]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(managed_source_leases)"
                    )
                }
                immutable_triggers = {
                    row[0]
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger'"
                    )
                }

            self.assertEqual(41, SCHEMA_VERSION)
            self.assertEqual("41", read_schema_version(database_path))
            self.assertEqual(before, after)
            self.assertTrue(
                {
                    "library_share_scan_evidence",
                    "library_share_binding_evidence",
                    "operation_share_evidence",
                    "managed_source_leases",
                }.issubset(tables)
            )
            self.assertTrue({"owner_id", "daemon_generation"}.issubset(lease_columns))
            self.assertNotIn(
                "trg_library_share_binding_evidence_no_update", immutable_triggers
            )
            self.assertNotIn(
                "trg_library_share_binding_evidence_no_delete", immutable_triggers
            )
            self.assertTrue(
                {
                    "trg_operation_share_evidence_no_update",
                    "trg_operation_share_evidence_no_delete",
                }.issubset(immutable_triggers)
            )
            self.assertEqual(["ok"], integrity_check(database_path))
            self.assertEqual([], foreign_key_violations(database_path))

    def test_schema_thirty_two_fences_real_v30_network_job_without_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = root / "catalog.db"
            source = root / "network-source"
            source.mkdir()
            with Catalog(database_path) as catalog:
                catalog.initialize(target_version=30)
                share = catalog.create_managed_share(
                    "archive",
                    "Archive NAS",
                    "nfs",
                    json.dumps(
                        {
                            "kind": "nfs",
                            "server": "nas.example.test",
                            "export": "/archive",
                            "version": "4.2",
                            "timeout_seconds": 60,
                            "retransmissions": 2,
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    actor="admin-1",
                    idempotency_key="create-v30-share",
                    request_fingerprint_sha256="a" * 64,
                )
                catalog.add_named_library(
                    "NETWORK",
                    "Network library",
                    str(source),
                    str(source),
                    "b" * 64,
                )
                catalog.bind_library_to_share(
                    "NETWORK",
                    "archive",
                    "media",
                    expected_share_revision=int(share["revision"]),
                    actor="admin-1",
                    idempotency_key="bind-v30-network",
                    request_fingerprint_sha256="c" * 64,
                )
                catalog.create_automatic_job(
                    "V30-NETWORK-JOB",
                    "NETWORK",
                    "TAPE0",
                    "AUTO",
                    [("VN0001", "VN0001", 1, 7)],
                )
                catalog.update_automatic_job("V30-NETWORK-JOB", "paused")

            with Catalog(database_path) as catalog:
                initialize_current_with_protected_backup(catalog, root)
                table_exists = catalog.connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='managed_source_job_fences'"
                ).fetchone()
                self.assertIsNotNone(table_exists)
                fence = catalog.connection.execute(
                    "SELECT reason FROM managed_source_job_fences WHERE job_id=?",
                    ("V30-NETWORK-JOB",),
                ).fetchone()

            self.assertIsNotNone(fence)
            self.assertEqual("legacy_managed_source_evidence_missing", fence["reason"])

    def test_schema_twenty_five_upgrade_preserves_every_local_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = root / "catalog.db"
            sources = tuple(root / name for name in ("active", "disabled", "retired"))
            for source in sources:
                source.mkdir()

            with Catalog(database_path) as catalog:
                catalog.initialize(target_version=25)
                for index, (library_id, state) in enumerate(
                    (
                        ("ACTIVE", "active"),
                        ("DISABLED", "disabled"),
                        ("RETIRED", "retired"),
                    )
                ):
                    source = str(sources[index])
                    catalog.add_named_library(
                        library_id,
                        f"{state.title()} library",
                        source,
                        source,
                        hashlib.sha256(source.encode("utf-8")).hexdigest(),
                    )
                catalog.update_named_library("DISABLED", requested_state="disabled")
                catalog.retire_named_library("RETIRED")
                legacy_columns = tuple(
                    row[1]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(libraries)"
                    )
                )
                before = tuple(
                    tuple(row[column] for column in legacy_columns)
                    for row in catalog.list_named_libraries()
                )

            with Catalog(database_path) as catalog:
                initialize_current_with_protected_backup(catalog, root)
                after = tuple(
                    tuple(row[column] for column in legacy_columns)
                    for row in catalog.list_named_libraries()
                )
                migrated = [dict(row) for row in catalog.list_named_libraries()]

            self.assertEqual(str(SCHEMA_VERSION), read_schema_version(database_path))
            self.assertEqual(before, after)
            self.assertEqual(
                ["active", "active", "retired"],
                [row["status"] for row in migrated],
            )
            self.assertEqual([1, 0, 0], [row["enabled"] for row in migrated])
            self.assertEqual(
                ["local", "local", "local"],
                [row["source_kind"] for row in migrated],
            )
            self.assertEqual(["ok"], integrity_check(database_path))
            self.assertEqual([], foreign_key_violations(database_path))


class ManagedShareCatalogTests(unittest.TestCase):
    _SAFE_ERROR_SENTINEL = "SENTINEL-SAFE-ERROR-SECRET-DO-NOT-PERSIST"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database_path = self.root / "catalog.db"
        self.catalog = Catalog(self.database_path)
        self.catalog.initialize()

    def tearDown(self) -> None:
        self.catalog.close()
        self.temporary.cleanup()

    @staticmethod
    def _fingerprint(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _nfs_config(*, forbidden_value: str | None = None) -> str:
        config: dict[str, object] = {
            "export": "/archive/media",
            "kind": "nfs",
            "retransmissions": 2,
            "server": "nas.example.test",
            "timeout_seconds": 60,
            "version": "4.2",
        }
        if forbidden_value is not None:
            config["password"] = forbidden_value
        return json.dumps(
            config, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        )

    def _create_share(
        self,
        share_id: str = "archive",
        *,
        idempotency_key: str = "create-archive",
        fingerprint: str | None = None,
    ) -> dict:
        return self.catalog.create_managed_share(
            share_id,
            "Archive NAS",
            "nfs",
            self._nfs_config(),
            actor="admin-1",
            idempotency_key=idempotency_key,
            request_fingerprint_sha256=fingerprint
            or self._fingerprint(idempotency_key),
        )

    def _every_catalog_value(self) -> tuple[str, ...]:
        table_names = tuple(
            str(row[0])
            for row in self.catalog.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        )
        values = []
        for table_name in table_names:
            quoted = table_name.replace('"', '""')
            values.extend(
                str(value)
                for row in self.catalog.connection.execute(f'SELECT * FROM "{quoted}"')
                for value in row
            )
        return tuple(values)

    def test_share_ids_are_case_insensitive_and_results_are_detached(self) -> None:
        created = self._create_share("Archive")

        self.assertIs(type(created), dict)
        self.assertEqual("archive", created["share_id"])
        self.assertEqual(created, self.catalog.get_managed_share("ARCHIVE"))
        self.assertEqual([created], self.catalog.list_managed_shares())
        with self.assertRaisesRegex(CatalogError, "share_already_exists"):
            self._create_share("ARCHIVE", idempotency_key="duplicate-archive")

    def test_managed_source_lease_blocks_disconnect_and_startup_recovers_stale_owner(
        self,
    ) -> None:
        share = self._create_share()
        connected = self.catalog.update_managed_share(
            "archive",
            expected_revision=share["revision"],
            actor="admin-1",
            idempotency_key="desire-connected",
            request_fingerprint_sha256=self._fingerprint("desire-connected"),
            desired_state="connected",
        )
        self.catalog.record_managed_share_observation(
            "archive",
            actor="daemon-1",
            observed_state="connected",
            safe_error_code=None,
            mount_identity_sha256="b" * 64,
            mounted_config_revision=1,
            mounted_credential_generation=0,
            checked_at="2026-08-26T12:00:00+00:00",
        )
        lease_id = self.catalog.acquire_managed_source_lease(
            "archive",
            consumer_kind="scan",
            consumer_id="LIBRARY",
            owner_id="daemon-1",
            daemon_generation=7,
        )

        with self.assertRaisesRegex(CatalogError, "share_in_use"):
            self.catalog.queue_share_operation(
                "disconnect-blocked",
                "archive",
                "disconnect",
                actor="admin-1",
                idempotency_key="disconnect-blocked",
                request_fingerprint_sha256=self._fingerprint("disconnect-blocked"),
                expected_share_revision=connected["revision"],
                require_no_consumers=True,
            )
        self.assertEqual(
            1,
            self.catalog.recover_stale_managed_source_leases(
                owner_id="daemon-2", daemon_generation=8
            ),
        )
        self.assertIsNone(
            self.catalog.connection.execute(
                "SELECT 1 FROM managed_source_leases WHERE lease_id=?", (lease_id,)
            ).fetchone()
        )

    def test_revision_and_idempotency_checks_are_case_insensitive(self) -> None:
        self._create_share("Archive")
        fingerprint = self._fingerprint("rename")
        updated = self.catalog.update_managed_share(
            "ARCHIVE",
            expected_revision=1,
            actor="admin-1",
            idempotency_key="rename-archive",
            request_fingerprint_sha256=fingerprint,
            display_name="Primary archive",
        )
        replay = self.catalog.update_managed_share(
            "archive",
            expected_revision=1,
            actor="admin-1",
            idempotency_key="rename-archive",
            request_fingerprint_sha256=fingerprint,
            display_name="Primary archive",
        )

        self.assertEqual(2, updated["revision"])
        self.assertEqual(updated, replay)
        with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
            self.catalog.update_managed_share(
                "archive",
                expected_revision=1,
                actor="admin-1",
                idempotency_key="rename-archive",
                request_fingerprint_sha256=self._fingerprint("changed payload"),
                display_name="Changed payload",
            )
        with self.assertRaisesRegex(CatalogError, "share_revision_conflict"):
            self.catalog.update_managed_share(
                "ARCHIVE",
                expected_revision=1,
                actor="admin-1",
                idempotency_key="stale-rename",
                request_fingerprint_sha256=self._fingerprint("stale"),
                display_name="Stale rename",
            )

        receipts = self.catalog.connection.execute(
            "SELECT action,target_id FROM management_idempotency ORDER BY created_at"
        ).fetchall()
        audits = self.catalog.connection.execute(
            "SELECT action FROM audit_entries WHERE action LIKE 'share.%' ORDER BY id"
        ).fetchall()
        self.assertEqual(
            [("share.create", "archive"), ("share.update", "archive")],
            [tuple(row) for row in receipts],
        )
        self.assertEqual(
            ["share.create", "share.update"],
            [row["action"] for row in audits],
        )

    def test_binding_and_live_operation_block_retirement_across_id_case(self) -> None:
        bound_share = self._create_share("BOUND")
        source = self.root / "local-source"
        source.mkdir()
        source_text = str(source)
        self.catalog.add_named_library(
            "LIBRARY",
            "Library",
            source_text,
            source_text,
            self._fingerprint(source_text),
        )
        binding = self.catalog.bind_library_to_share(
            "library",
            "bound",
            "photos/2026",
            expected_share_revision=bound_share["revision"],
            actor="admin-1",
            idempotency_key="bind-library",
            request_fingerprint_sha256=self._fingerprint("bind-library"),
        )

        self.assertEqual("LIBRARY", binding["library_id"])
        self.assertEqual("bound", binding["share_id"])
        self.assertEqual(
            "network", self.catalog.get_named_library("library")["source_kind"]
        )
        self.assertEqual(
            source_text, self.catalog.get_named_library("LIBRARY")["source_root"]
        )
        with self.assertRaisesRegex(CatalogError, "share_in_use"):
            self.catalog.retire_managed_share(
                "bOuNd",
                expected_revision=1,
                actor="admin-1",
                idempotency_key="retire-bound",
                request_fingerprint_sha256=self._fingerprint("retire-bound"),
            )

        live_share = self._create_share("LIVE", idempotency_key="create-live")
        operation = self.catalog.begin_share_operation(
            "OPERATION-1",
            "live",
            "connect",
            actor="admin-1",
            idempotency_key="connect-live",
            request_fingerprint_sha256=self._fingerprint("connect-live"),
            expected_share_revision=live_share["revision"],
        )
        self.assertEqual(operation, self.catalog.get_share_operation("operation-1"))
        with self.assertRaisesRegex(CatalogError, "share_busy"):
            self.catalog.retire_managed_share(
                "LIVE",
                expected_revision=1,
                actor="admin-1",
                idempotency_key="retire-live",
                request_fingerprint_sha256=self._fingerprint("retire-live"),
            )

        finished = self.catalog.finish_share_operation(
            "operation-1",
            state="succeeded",
            receipt_sha256=self._fingerprint("connect receipt"),
        )
        retired = self.catalog.retire_managed_share(
            "live",
            expected_revision=1,
            actor="admin-1",
            idempotency_key="retire-live-after-finish",
            request_fingerprint_sha256=self._fingerprint("retire-live-after-finish"),
        )
        self.assertEqual("succeeded", finished["state"])
        self.assertEqual("retired", retired["lifecycle"])

    def test_operation_replay_rejects_conflicts_and_finish_is_idempotent(self) -> None:
        share = self._create_share()
        fingerprint = self._fingerprint("test connection")
        begun = self.catalog.begin_share_operation(
            "TEST-OP",
            "ARCHIVE",
            "test",
            actor="admin-1",
            idempotency_key="test-archive",
            request_fingerprint_sha256=fingerprint,
            expected_share_revision=share["revision"],
        )
        replay = self.catalog.begin_share_operation(
            "test-op",
            "archive",
            "test",
            actor="admin-1",
            idempotency_key="test-archive",
            request_fingerprint_sha256=fingerprint,
            expected_share_revision=share["revision"],
        )
        self.assertEqual(begun, replay)
        with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
            self.catalog.begin_share_operation(
                "OTHER-OP",
                "archive",
                "test",
                actor="admin-1",
                idempotency_key="test-archive",
                request_fingerprint_sha256=self._fingerprint("different test"),
                expected_share_revision=share["revision"],
            )

        receipt = self._fingerprint("test receipt")
        finished = self.catalog.finish_share_operation(
            "TEST-OP", state="succeeded", receipt_sha256=receipt
        )
        finished_replay = self.catalog.finish_share_operation(
            "test-op", state="succeeded", receipt_sha256=receipt
        )
        self.assertEqual(finished, finished_replay)
        with self.assertRaisesRegex(CatalogError, "share_operation_conflict"):
            self.catalog.finish_share_operation(
                "test-op",
                state="failed",
                safe_error_code="share_unreachable",
                receipt_sha256=self._fingerprint("different receipt"),
            )

    def test_share_update_rejects_unknown_safe_error_before_persistence(self) -> None:
        self._create_share()

        with self.assertRaises(ValidationError):
            self.catalog.update_managed_share(
                "archive",
                expected_revision=1,
                actor="admin-1",
                idempotency_key="unsafe-share-error",
                request_fingerprint_sha256=self._fingerprint("unsafe-share-error"),
                safe_error_code=self._SAFE_ERROR_SENTINEL,
            )

        self.assertEqual(1, self.catalog.get_managed_share("archive")["revision"])
        self.assertNotIn(self._SAFE_ERROR_SENTINEL, self._every_catalog_value())

    def test_operation_finish_rejects_unknown_safe_error_before_persistence(
        self,
    ) -> None:
        share = self._create_share()
        operation = self.catalog.begin_share_operation(
            "UNSAFE-ERROR-OP",
            "archive",
            "connect",
            actor="admin-1",
            idempotency_key="unsafe-operation-error",
            request_fingerprint_sha256=self._fingerprint("unsafe-operation-error"),
            expected_share_revision=share["revision"],
        )

        with self.assertRaises(ValidationError):
            self.catalog.finish_share_operation(
                operation["operation_id"],
                state="failed",
                safe_error_code=self._SAFE_ERROR_SENTINEL,
                receipt_sha256=self._fingerprint("unsafe operation receipt"),
            )

        self.assertEqual(
            "running",
            self.catalog.get_share_operation(operation["operation_id"])["state"],
        )
        self.assertNotIn(self._SAFE_ERROR_SENTINEL, self._every_catalog_value())

    def test_binding_receipt_target_handles_maximum_length_ids(self) -> None:
        library_id = "L" * 64
        share_id = "s" * 63
        share = self._create_share(share_id, idempotency_key="create-maximum-share")
        source = self.root / "maximum-source"
        source.mkdir()
        source_text = str(source)
        self.catalog.add_named_library(
            library_id,
            "Maximum library",
            source_text,
            source_text,
            self._fingerprint(source_text),
        )

        binding = self.catalog.bind_library_to_share(
            library_id,
            share_id,
            "",
            expected_share_revision=share["revision"],
            actor="admin-1",
            idempotency_key="bind-maximum-identifiers",
            request_fingerprint_sha256=self._fingerprint("bind-maximum-identifiers"),
        )
        receipt = self.catalog.connection.execute(
            "SELECT target_id FROM management_idempotency "
            "WHERE actor=? AND idempotency_key=?",
            ("admin-1", "bind-maximum-identifiers"),
        ).fetchone()

        self.assertEqual(library_id, binding["library_id"])
        self.assertRegex(receipt["target_id"], r"^library-share-[0-9a-f]{64}$")
        self.assertLessEqual(len(receipt["target_id"]), 128)

    def test_binding_receipt_target_cannot_alias_delimiter_collisions(self) -> None:
        first_share = self._create_share("gamma", idempotency_key="create-gamma")
        second_share = self._create_share(
            "beta--gamma", idempotency_key="create-beta-gamma"
        )
        source = self.root / "collision-source"
        source.mkdir()
        source_text = str(source)
        for library_id in ("alpha--beta", "alpha"):
            self.catalog.add_named_library(
                library_id,
                library_id,
                source_text,
                source_text,
                self._fingerprint(f"{source_text}:{library_id}"),
            )
        fingerprint = self._fingerprint("binding collision request")
        self.catalog.bind_library_to_share(
            "alpha--beta",
            "gamma",
            "",
            expected_share_revision=first_share["revision"],
            actor="admin-1",
            idempotency_key="binding-collision",
            request_fingerprint_sha256=fingerprint,
        )

        with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
            self.catalog.bind_library_to_share(
                "alpha",
                "beta--gamma",
                "",
                expected_share_revision=second_share["revision"],
                actor="admin-1",
                idempotency_key="binding-collision",
                request_fingerprint_sha256=fingerprint,
            )

    def test_new_retirement_request_rejects_already_retired_share(self) -> None:
        self._create_share()
        retired = self.catalog.retire_managed_share(
            "archive",
            expected_revision=1,
            actor="admin-1",
            idempotency_key="retire-once",
            request_fingerprint_sha256=self._fingerprint("retire-once"),
        )

        with self.assertRaisesRegex(CatalogError, "share_state_conflict"):
            self.catalog.retire_managed_share(
                "ARCHIVE",
                expected_revision=retired["revision"],
                actor="admin-1",
                idempotency_key="retire-twice",
                request_fingerprint_sha256=self._fingerprint("retire-twice"),
            )

        stored = self.catalog.get_managed_share("archive")
        retire_audits = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM audit_entries WHERE action='share.retire'"
        ).fetchone()[0]
        retire_receipts = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM management_idempotency WHERE action='share.retire'"
        ).fetchone()[0]
        self.assertEqual(2, stored["revision"])
        self.assertEqual(1, retire_audits)
        self.assertEqual(1, retire_receipts)

    def test_final_share_remove_is_logical_and_preserves_operation_history(
        self,
    ) -> None:
        share = self._create_share()
        operation = self.catalog.begin_share_operation(
            "TEST-BEFORE-REMOVE",
            "archive",
            "test",
            actor="admin-1",
            idempotency_key="test-before-remove",
            request_fingerprint_sha256=self._fingerprint("test-before-remove"),
            expected_share_revision=share["revision"],
        )
        self.catalog.finish_share_operation(
            operation["operation_id"],
            state="succeeded",
            receipt_sha256=self._fingerprint("test-before-remove-receipt"),
        )
        retired = self.catalog.retire_managed_share(
            "archive",
            expected_revision=share["revision"],
            actor="admin-1",
            idempotency_key="retire-before-remove",
            request_fingerprint_sha256=self._fingerprint("retire-before-remove"),
        )

        removed = self.catalog.finalize_managed_share_removal(
            "archive",
            expected_revision=retired["revision"],
            actor="admin-1",
            idempotency_key="remove-archive",
            request_fingerprint_sha256=self._fingerprint("remove-archive"),
        )

        self.assertIsNotNone(removed["removed_at"])
        with self.assertRaisesRegex(CatalogError, "share_not_found"):
            self.catalog.get_managed_share("archive")
        self.assertEqual([], self.catalog.list_managed_shares())
        self.assertEqual(
            removed,
            self.catalog.get_managed_share("archive", include_removed=True),
        )
        self.assertEqual(
            "succeeded",
            self.catalog.get_share_operation("test-before-remove")["state"],
        )

    def test_failed_audit_rolls_back_share_receipt_and_domain_mutation(self) -> None:
        self.catalog.connection.execute(
            "CREATE TEMP TRIGGER fail_share_audit BEFORE INSERT ON audit_entries "
            "WHEN NEW.action='share.create' BEGIN "
            "SELECT RAISE(ABORT,'forced share audit failure'); END"
        )
        with self.assertRaisesRegex(
            sqlite3.IntegrityError, "forced share audit failure"
        ):
            self._create_share()

        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM managed_shares"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM management_idempotency"
            ).fetchone()[0],
        )
        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries WHERE action='share.create'"
            ).fetchone()[0],
        )

    def test_password_payload_is_rejected_before_any_catalog_value_can_retain_it(
        self,
    ) -> None:
        sentinel = "SENTINEL-NETWORK-PASSWORD-DO-NOT-PERSIST"
        with self.assertRaises(ValidationError):
            self.catalog.create_managed_share(
                "unsafe",
                "Unsafe",
                "nfs",
                self._nfs_config(forbidden_value=sentinel),
                actor="admin-1",
                idempotency_key="unsafe-password",
                request_fingerprint_sha256=self._fingerprint("opaque keyed request"),
            )

        schema = "\n".join(
            str(row[0] or "")
            for row in self.catalog.connection.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            )
        )
        self.assertNotIn(sentinel, schema)
        self.assertNotIn(sentinel, self._every_catalog_value())
        for forbidden_column in (
            "password",
            "credential_path",
            "secret_path",
            "raw_helper_output",
            "endpoint_helper_output",
        ):
            self.assertNotIn(forbidden_column, schema.casefold())

    def test_schema_thirty_migrates_share_operations_without_losing_history(
        self,
    ) -> None:
        database = self.root / "schema-29.db"
        with Catalog(database) as catalog:
            catalog.initialize(target_version=29)
            share = catalog.create_managed_share(
                "legacy-share",
                "Legacy share",
                "nfs",
                self._nfs_config(),
                actor="admin-1",
                idempotency_key="create-legacy-share",
                request_fingerprint_sha256=self._fingerprint("create-legacy-share"),
            )
            catalog.connection.execute(
                "INSERT INTO share_operations("
                "operation_id,share_id,actor,action,idempotency_key,"
                "keyed_request_fingerprint_sha256,expected_share_revision,"
                "state,started_at) VALUES(?,?,?,?,?,?,?,'running',?)",
                (
                    "legacy-operation",
                    share["share_id"],
                    "admin-1",
                    "connect",
                    "connect-legacy-share",
                    self._fingerprint("connect-legacy-share"),
                    share["revision"],
                    "2026-08-26T10:00:00+00:00",
                ),
            )
            catalog.connection.commit()

        with Catalog(database) as catalog:
            initialize_current_with_protected_backup(catalog, database.parent)
            migrated_share = catalog.get_managed_share("legacy-share")
            migrated_operation = catalog.get_share_operation("legacy-operation")
            columns = {
                row["name"]
                for row in catalog.connection.execute(
                    "PRAGMA table_info(share_operations)"
                )
            }

        self.assertEqual(41, SCHEMA_VERSION)
        self.assertEqual("41", read_schema_version(database))
        self.assertEqual(1, migrated_share["config_revision"])
        self.assertIsNone(migrated_share["mounted_config_revision"])
        self.assertIsNone(migrated_share["mounted_credential_generation"])
        self.assertEqual("running", migrated_operation["state"])
        self.assertTrue({"owner_id", "claimed_at", "queued_at"} <= columns)
        self.assertEqual(["ok"], integrity_check(database))
        self.assertEqual([], foreign_key_violations(database))

    def test_schema_thirty_maintenance_preserves_pre_recovery_operations(
        self,
    ) -> None:
        share = self._create_share()
        queued = self.catalog.queue_share_operation(
            "pre-recovery-operation",
            "archive",
            "connect",
            actor="admin-1",
            idempotency_key="pre-recovery-connect",
            request_fingerprint_sha256=self._fingerprint("pre-recovery-connect"),
            expected_share_revision=share["revision"],
        )
        self.catalog.close()
        with sqlite3.connect(self.database_path) as connection:
            connection.executescript(
                """
                DROP INDEX ux_share_one_live_operation;
                DROP INDEX ix_share_operations_latest;
                CREATE TABLE share_operations_pre_recovery (
                    operation_id TEXT PRIMARY KEY COLLATE NOCASE,
                    share_id TEXT NOT NULL COLLATE NOCASE
                        REFERENCES managed_shares(share_id),
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    keyed_request_fingerprint_sha256 TEXT NOT NULL,
                    expected_share_revision INTEGER NOT NULL,
                    frozen_config_json TEXT NOT NULL,
                    frozen_config_revision INTEGER NOT NULL,
                    frozen_credential_generation INTEGER NOT NULL,
                    frozen_observed_state TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN (
                        'queued','running','succeeded','failed'
                    )),
                    owner_id TEXT,
                    safe_error_code TEXT,
                    receipt_sha256 TEXT,
                    queued_at TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    claimed_at TEXT,
                    finished_at TEXT,
                    recovered_at TEXT,
                    UNIQUE(actor,idempotency_key)
                );
                INSERT INTO share_operations_pre_recovery(
                    operation_id,share_id,actor,action,idempotency_key,
                    keyed_request_fingerprint_sha256,expected_share_revision,
                    frozen_config_json,frozen_config_revision,
                    frozen_credential_generation,frozen_observed_state,state,
                    owner_id,safe_error_code,receipt_sha256,queued_at,started_at,
                    claimed_at,finished_at,recovered_at
                )
                SELECT operation_id,share_id,actor,action,idempotency_key,
                    keyed_request_fingerprint_sha256,expected_share_revision,
                    frozen_config_json,frozen_config_revision,
                    frozen_credential_generation,frozen_observed_state,state,
                    owner_id,safe_error_code,receipt_sha256,queued_at,started_at,
                    claimed_at,finished_at,recovered_at
                FROM share_operations;
                DROP TABLE share_operations;
                ALTER TABLE share_operations_pre_recovery
                    RENAME TO share_operations;
                CREATE UNIQUE INDEX ux_share_one_live_operation
                    ON share_operations(share_id COLLATE NOCASE)
                    WHERE state IN ('queued','running');
                CREATE INDEX ix_share_operations_latest
                    ON share_operations(
                        share_id COLLATE NOCASE,queued_at DESC,operation_id
                    );
                """
            )

        self.catalog = Catalog(self.database_path)
        self.catalog.initialize()
        preserved = self.catalog.get_share_operation(queued["operation_id"])
        columns = {
            str(row["name"])
            for row in self.catalog.connection.execute(
                "PRAGMA table_info(share_operations)"
            )
        }
        claimed = self.catalog.claim_share_operation(
            queued["operation_id"], owner_id="daemon-test-owner"
        )
        recovering = self.catalog.mark_share_operation_recovering(
            queued["operation_id"],
            owner_id="daemon-test-owner",
            recovery_deadline="2026-08-26T12:00:00+00:00",
        )

        self.assertEqual("queued", preserved["state"])
        self.assertEqual("running", claimed["state"])
        self.assertEqual("recovering", recovering["state"])
        self.assertIn("recovery_deadline", columns)
        self.assertEqual(["ok"], integrity_check(self.database_path))
        self.assertEqual([], foreign_key_violations(self.database_path))

    def test_queued_operation_replay_claim_recovery_and_projection_are_durable(
        self,
    ) -> None:
        share = self._create_share()
        fingerprint = self._fingerprint("connect archive")
        queued = self.catalog.queue_share_operation(
            "operation-first",
            "archive",
            "connect",
            actor="admin-1",
            idempotency_key="connect-archive",
            request_fingerprint_sha256=fingerprint,
            expected_share_revision=share["revision"],
        )
        replay = self.catalog.queue_share_operation(
            "operation-new-caller-id",
            "ARCHIVE",
            "connect",
            actor="admin-1",
            idempotency_key="connect-archive",
            request_fingerprint_sha256=fingerprint,
            expected_share_revision=share["revision"],
        )

        self.assertEqual("queued", queued["state"])
        self.assertEqual("operation-first", replay["operation_id"])
        self.assertEqual(
            queued,
            self.catalog.get_current_share_operation("archive"),
        )
        claimed = self.catalog.claim_share_operation(
            "operation-first", owner_id="daemon-owner-1"
        )
        self.assertEqual("running", claimed["state"])
        self.assertEqual("daemon-owner-1", claimed["owner_id"])
        self.assertEqual(
            claimed,
            self.catalog.claim_share_operation(
                "operation-first", owner_id="daemon-owner-1"
            ),
        )
        with self.assertRaisesRegex(CatalogError, "share_operation_conflict"):
            self.catalog.claim_share_operation(
                "operation-first", owner_id="daemon-owner-2"
            )

        recovered = self.catalog.recover_interrupted_share_operations(
            owner_id="daemon-owner-recovery"
        )
        self.assertEqual(
            ("operation-first",), tuple(row["operation_id"] for row in recovered)
        )
        recovering = self.catalog.get_share_operation("operation-first")
        self.assertEqual("recovering", recovering["state"])
        self.assertEqual("share_recovery_required", recovering["safe_error_code"])
        self.assertIsNone(recovering["receipt_sha256"])
        self.assertEqual(
            recovering,
            self.catalog.get_latest_share_operation("archive"),
        )
        self.assertEqual(
            recovering, self.catalog.get_current_share_operation("archive")
        )

    def test_queued_operation_freezes_mount_inputs_and_blocks_config_mutation(
        self,
    ) -> None:
        share = self._create_share()
        queued = self.catalog.queue_share_operation(
            "frozen-connect",
            "archive",
            "connect",
            actor="admin-1",
            idempotency_key="frozen-connect",
            request_fingerprint_sha256=self._fingerprint("frozen-connect"),
            expected_share_revision=share["revision"],
        )

        self.assertEqual(share["config_json"], queued["frozen_config_json"])
        self.assertEqual(share["config_revision"], queued["frozen_config_revision"])
        self.assertEqual(
            share["credential_generation"],
            queued["frozen_credential_generation"],
        )
        with self.assertRaisesRegex(CatalogError, "share_busy"):
            self.catalog.update_managed_share(
                "archive",
                expected_revision=share["revision"],
                actor="admin-1",
                idempotency_key="mutate-during-connect",
                request_fingerprint_sha256=self._fingerprint("mutate-during-connect"),
                config_json=json.dumps(
                    {
                        "kind": "nfs",
                        "server": "other.example.test",
                        "export": "/changed",
                        "version": "4.2",
                        "timeout_seconds": 60,
                        "retransmissions": 2,
                    }
                ),
            )

    def test_disconnect_consumer_guard_blocks_only_live_consumption_states(
        self,
    ) -> None:
        share = self._create_share()
        source = self.root / "consumer-library"
        source.mkdir()
        source_text = str(source)
        self.catalog.add_named_library(
            "CONSUMER",
            "Consumer",
            source_text,
            source_text,
            self._fingerprint(source_text),
        )
        self.catalog.bind_library_to_share(
            "CONSUMER",
            share["share_id"],
            "",
            expected_share_revision=share["revision"],
            actor="admin-1",
            idempotency_key="bind-consumer-matrix",
            request_fingerprint_sha256=self._fingerprint("bind-consumer-matrix"),
        )

        self.assertFalse(self.catalog.share_has_active_library_consumer("archive"))
        self.catalog.start_named_library_scan("CONSUMER")
        self.assertTrue(self.catalog.share_has_active_library_consumer("archive"))
        self.catalog.connection.execute(
            "UPDATE libraries SET scan_state='ready' WHERE id='CONSUMER'"
        )
        self.catalog.connection.commit()

        self.catalog.create_job_plan_draft(
            plan_id="CONSUMER-PLAN",
            kind="create",
            creator="operator-1",
            created_at="2026-08-26T10:00:00+00:00",
            expires_at="2026-08-27T10:00:00+00:00",
            media_key="LTO-6",
            library_ids=("CONSUMER",),
        )
        self.assertTrue(self.catalog.share_has_active_library_consumer("archive"))
        self.catalog.connection.execute(
            "INSERT INTO job_plan_libraries("
            "plan_id,sequence,library_id,source_root,scan_revision,"
            "scan_fingerprint_sha256) VALUES(?,?,?,?,?,?)",
            (
                "CONSUMER-PLAN",
                1,
                "CONSUMER",
                source_text,
                0,
                self._fingerprint("consumer-ready-plan"),
            ),
        )
        self.catalog.connection.execute(
            "UPDATE job_plan_drafts SET state='ready' WHERE id='CONSUMER-PLAN'"
        )
        self.catalog.connection.commit()
        self.assertFalse(self.catalog.share_has_active_library_consumer("archive"))

        self.catalog.create_automatic_job(
            "CONSUMER-JOB",
            "CONSUMER",
            "TAPE0",
            "AUTO",
            [("AB1234", "AB1234", 1, 7)],
            force_format=True,
        )
        for status in ("planned", "waiting_media", "paused"):
            self.catalog.connection.execute(
                "UPDATE automatic_jobs SET status=? WHERE id='CONSUMER-JOB'",
                (status,),
            )
            self.catalog.connection.commit()
            with self.subTest(status=status):
                self.assertFalse(
                    self.catalog.share_has_active_library_consumer("archive")
                )

        self.catalog.connection.execute(
            "INSERT INTO daemon_operations("
            "id,kind,state,phase,idempotency_key,principal,owner_generation,"
            "job_id,cassette_sequence,started_at) "
            "VALUES('CONSUMER-OP','archive.native','running','writing',"
            "'consumer-operation','operator-1',1,'CONSUMER-JOB',1,"
            "'2026-08-26T10:30:00+00:00')"
        )
        self.catalog.connection.commit()
        self.assertTrue(self.catalog.share_has_active_library_consumer("archive"))

    def test_operation_finish_atomically_persists_verified_mount_evidence_without_revision_churn(
        self,
    ) -> None:
        share = self._create_share()
        queued = self.catalog.queue_share_operation(
            "connect-operation",
            "archive",
            "connect",
            actor="admin-1",
            idempotency_key="connect-operation",
            request_fingerprint_sha256=self._fingerprint("connect-operation"),
            expected_share_revision=share["revision"],
        )
        self.catalog.claim_share_operation(
            queued["operation_id"], owner_id="daemon-owner"
        )
        receipt = self._fingerprint("verified broker receipt")
        mount_identity = self._fingerprint("verified mount identity")
        finished = self.catalog.finish_share_operation(
            queued["operation_id"],
            state="succeeded",
            receipt_sha256=receipt,
            desired_state="connected",
            observed_state="connected",
            mount_identity_sha256=mount_identity,
            mounted_config_revision=share["config_revision"],
            mounted_credential_generation=share["credential_generation"],
            last_checked_at="2026-08-26T12:00:00+00:00",
        )
        stored = self.catalog.get_managed_share("archive")

        self.assertEqual("succeeded", finished["state"])
        self.assertEqual(receipt, finished["receipt_sha256"])
        self.assertEqual(share["revision"], stored["revision"])
        self.assertEqual("connected", stored["desired_state"])
        self.assertEqual("connected", stored["observed_state"])
        self.assertEqual(mount_identity, stored["mount_identity_sha256"])
        self.assertEqual(1, stored["mounted_config_revision"])
        self.assertEqual(0, stored["mounted_credential_generation"])

    def test_operation_and_share_observation_roll_back_together(self) -> None:
        share = self._create_share()
        operation = self.catalog.queue_share_operation(
            "atomic-finish",
            "archive",
            "connect",
            actor="admin-1",
            idempotency_key="atomic-finish",
            request_fingerprint_sha256=self._fingerprint("atomic-finish"),
            expected_share_revision=share["revision"],
        )
        self.catalog.claim_share_operation(operation["operation_id"], owner_id="owner")
        self.catalog.connection.execute(
            "CREATE TEMP TRIGGER fail_share_operation_finish "
            "BEFORE INSERT ON audit_entries "
            "WHEN NEW.action='share.operation.finish' BEGIN "
            "SELECT RAISE(ABORT,'forced operation finish audit failure'); END"
        )

        with self.assertRaisesRegex(sqlite3.IntegrityError, "forced operation finish"):
            self.catalog.finish_share_operation(
                operation["operation_id"],
                state="succeeded",
                receipt_sha256=self._fingerprint("receipt"),
                desired_state="connected",
                observed_state="connected",
                mount_identity_sha256=self._fingerprint("mount"),
                mounted_config_revision=1,
                mounted_credential_generation=0,
            )

        self.assertEqual(
            "running", self.catalog.get_share_operation("atomic-finish")["state"]
        )
        stored = self.catalog.get_managed_share("archive")
        self.assertEqual("disconnected", stored["desired_state"])
        self.assertEqual("disconnected", stored["observed_state"])
        self.assertIsNone(stored["mount_identity_sha256"])

    def test_resource_and_broker_config_revisions_are_independent(self) -> None:
        share = self._create_share()
        renamed = self.catalog.update_managed_share(
            "archive",
            expected_revision=share["revision"],
            actor="admin-1",
            idempotency_key="rename-only",
            request_fingerprint_sha256=self._fingerprint("rename-only"),
            display_name="Renamed archive",
        )
        changed_config = json.loads(self._nfs_config())
        changed_config["export"] = "/archive/changed"
        endpoint_changed = self.catalog.update_managed_share(
            "archive",
            expected_revision=renamed["revision"],
            actor="admin-1",
            idempotency_key="change-config",
            request_fingerprint_sha256=self._fingerprint("change-config"),
            config_json=json.dumps(changed_config),
        )

        self.assertEqual(2, renamed["revision"])
        self.assertEqual(1, renamed["config_revision"])
        self.assertEqual(3, endpoint_changed["revision"])
        self.assertEqual(2, endpoint_changed["config_revision"])


class CatalogTests(unittest.TestCase):
    @staticmethod
    def _sequence_catalog(
        root: Path,
        *,
        job_id: str,
        cassettes: list[tuple[str, str, int, int]],
        allow_registered_reuse: bool = False,
        library_id: str = "LIB1",
    ) -> Catalog:
        source = root / library_id
        source.mkdir()
        catalog = Catalog(root / f"{job_id}.db")
        catalog.initialize()
        catalog.add_library(library_id, library_id, str(source))
        catalog.create_automatic_job(
            job_id,
            library_id,
            "synthetic-drive",
            "/synthetic/mount",
            cassettes,
            force_format=True,
            allow_registered_reuse=allow_registered_reuse,
        )
        return catalog

    @staticmethod
    def _authorize_and_enable_sequence(catalog: Catalog, job_id: str) -> tuple[str, ...]:
        fingerprint = catalog.latest_layout_epoch(job_id)["layout_fingerprint_sha256"]
        authorization_ids = catalog.authorize_automatic_format_sequence(
            job_id,
            expected_revision=0,
            layout_fingerprint_sha256=fingerprint,
            actor="admin-1",
            idempotency_key=f"authorize-{job_id}",
            authorized_at="2026-08-30T18:00:00+00:00",
        )
        state = catalog.set_automatic_sequence_enabled(
            job_id,
            expected_revision=1,
            layout_fingerprint_sha256=fingerprint,
            actor="admin-1",
            enabled_at="2026-08-30T18:01:00+00:00",
        )
        assert state["state"] == "enabled"
        assert state["revision"] == 2
        catalog.update_automatic_job(job_id, "waiting_media", current_sequence=1)
        return authorization_ids

    def _continuation_fixture(
        self,
        root: Path,
        *,
        operation: str = "format",
        job_id: str = "AUTO-CONTINUATION",
        label: str = "CT0001",
    ) -> tuple[
        Catalog,
        object,
        OperationRecord,
        HardwareTargetBinding,
        str | None,
        dict,
    ]:
        source = root / f"source-{job_id}"
        source.mkdir()
        database = root / "continuations.db"
        catalog = Catalog(database)
        catalog.initialize()
        catalog.add_library(f"LIB-{job_id}", job_id, str(source))
        catalog.create_automatic_job(
            job_id,
            f"LIB-{job_id}",
            f"drive-{job_id}",
            f"/synthetic/{job_id}",
            [(label, f"SERIAL-{job_id}", 1, 7)],
            force_format=True,
        )
        if operation == "append":
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET operation='append' "
                "WHERE job_id=? AND sequence=1",
                (job_id,),
            )
            catalog.connection.commit()
            with catalog.transaction() as db:
                catalog._insert_layout_epoch_tx(
                    db,
                    job_id,
                    kind="extension",
                    plan_id=None,
                    plan_digest_sha256="a" * 64,
                    created_at="2026-08-31T11:59:00+00:00",
                    target_sequences=(1,),
                    target_operations=("append",),
                )
        authority_ids = self._authorize_and_enable_sequence(catalog, job_id)
        catalog.update_automatic_cassette(job_id, 1, "waiting_media")
        epoch = catalog.latest_layout_epoch(job_id)
        owner = catalog.claim_daemon_owner(f"daemon-{job_id}")
        key = hashlib.sha256(
            f"{job_id}\0{epoch['layout_fingerprint_sha256']}\0{1}\0"
            f"{owner.generation}".encode("utf-8")
        ).hexdigest()
        candidate = operation_candidate(
            f"operation-{job_id}",
            key,
            kind="archive.native",
            principal="sequence-coordinator",
            job_id=job_id,
            cassette_sequence=1,
        )
        target = HardwareTargetBinding.from_verified_inputs(
            root / f"mount-{job_id}",
            f"tape-{job_id}",
            f"scsi-{job_id}",
            ("archive.native", job_id, "1", label, "", ""),
        )
        authority_id = None if not authority_ids else authority_ids[0]
        return catalog, owner, candidate, target, authority_id, epoch

    @staticmethod
    def _continuation_audits(catalog: Catalog) -> list[tuple[str, dict]]:
        return [
            (str(row["action"]), json.loads(str(row["payload_json"])))
            for row in catalog.connection.execute(
                "SELECT action,payload_json FROM audit_entries "
                "WHERE action IN ('automatic.sequence.continuation.admitted',"
                "'automatic.sequence.continuation.replayed') ORDER BY id"
            )
        ]

    def _admit_continuation(
        self,
        catalog: Catalog,
        owner,
        candidate: OperationRecord,
        target: HardwareTargetBinding,
        authority_id: str | None,
        fingerprint: str,
    ):
        return catalog.admit_operation(
            candidate,
            owner,
            admission_open=True,
            hardware_target=target,
            sequence_authorization_id=authority_id,
            sequence_layout_fingerprint_sha256=fingerprint,
        )

    def test_exact_format_and_append_continuations_replay_from_immutable_binding(
        self,
    ) -> None:
        audit_keys = {
            "authority_id",
            "continuation_idempotency_key",
            "job_id",
            "layout_epoch",
            "layout_fingerprint_sha256",
            "operation_id",
            "outcome",
            "sequence",
        }
        for operation in ("format", "append"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as temporary,
            ):
                root = Path(temporary)
                catalog, owner, candidate, target, authority_id, epoch = (
                    self._continuation_fixture(root, operation=operation)
                )
                database = catalog.path
                admitted = self._admit_continuation(
                    catalog,
                    owner,
                    candidate,
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
                first_replay = self._admit_continuation(
                    catalog,
                    owner,
                    replace(candidate, id=f"replay-one-{operation}"),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
                catalog.close()
                catalog = Catalog(database)
                restarted_owner = catalog.claim_daemon_owner(f"restarted-{operation}")
                second_replay = self._admit_continuation(
                    catalog,
                    restarted_owner,
                    replace(candidate, id=f"replay-two-{operation}"),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
                audits = self._continuation_audits(catalog)
                binding = catalog.connection.execute(
                    "SELECT * FROM operation_sequence_continuations"
                ).fetchall()
                operation_count = catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations WHERE idempotency_key=?",
                    (candidate.idempotency_key,),
                ).fetchone()[0]
                catalog.close()

                self.assertFalse(admitted.replayed)
                self.assertTrue(first_replay.replayed)
                self.assertTrue(second_replay.replayed)
                self.assertEqual(candidate.id, first_replay.record.id)
                self.assertEqual(candidate.id, second_replay.record.id)
                self.assertEqual(1, operation_count)
                self.assertEqual(1, len(binding))
                self.assertEqual(
                    [
                        "automatic.sequence.continuation.admitted",
                        "automatic.sequence.continuation.replayed",
                        "automatic.sequence.continuation.replayed",
                    ],
                    [action for action, _payload in audits],
                )
                expected = {
                    "authority_id": authority_id,
                    "continuation_idempotency_key": candidate.idempotency_key,
                    "job_id": candidate.job_id,
                    "layout_epoch": int(epoch["epoch_number"]),
                    "layout_fingerprint_sha256": epoch[
                        "layout_fingerprint_sha256"
                    ],
                    "operation_id": candidate.id,
                    "sequence": 1,
                }
                for index, (_action, payload) in enumerate(audits):
                    with self.subTest(operation=operation, audit=index):
                        self.assertEqual(audit_keys, set(payload))
                        self.assertEqual(
                            {**expected, "outcome": "admitted" if index == 0 else "replayed"},
                            payload,
                        )
                        encoded = json.dumps(payload, sort_keys=True)
                        self.assertNotIn("CT0001", encoded)
                        self.assertNotIn("admin-1", encoded)
                        for digest in Catalog._target_values(target):
                            self.assertNotIn(digest, encoded)

    def test_exact_replay_survives_current_layout_advance(self) -> None:
        for operation in ("format", "append"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                catalog, owner, candidate, target, authority_id, epoch = (
                    self._continuation_fixture(
                        Path(temporary), operation=operation
                    )
                )
                try:
                    admitted = self._admit_continuation(
                        catalog,
                        owner,
                        candidate,
                        target,
                        authority_id,
                        str(epoch["layout_fingerprint_sha256"]),
                    )
                    catalog.finish_operation(
                        OperationFence(admitted.record.id, owner.generation),
                        "succeeded",
                    )
                    with catalog.transaction() as db:
                        advanced = catalog._insert_layout_epoch_tx(
                            db,
                            str(candidate.job_id),
                            kind="extension",
                            plan_id=None,
                            plan_digest_sha256="f" * 64,
                            created_at="2026-08-31T12:10:00+00:00",
                            target_sequences=(1,),
                            target_operations=(operation,),
                        )
                        db.execute(
                            "UPDATE automatic_sequence_state SET layout_epoch=?,"
                            "layout_fingerprint_sha256=? WHERE job_id=?",
                            (
                                advanced["epoch_number"],
                                advanced["layout_fingerprint_sha256"],
                                candidate.job_id,
                            ),
                        )
                    replayed = self._admit_continuation(
                        catalog,
                        owner,
                        replace(
                            candidate,
                            id=f"replay-after-layout-advance-{operation}",
                        ),
                        target,
                        authority_id,
                        str(epoch["layout_fingerprint_sha256"]),
                    )
                    payload = self._continuation_audits(catalog)[-1][1]

                    self.assertTrue(replayed.replayed)
                    self.assertEqual(candidate.id, replayed.record.id)
                    self.assertEqual(
                        epoch["epoch_number"], payload.get("layout_epoch")
                    )
                    self.assertEqual(
                        epoch["layout_fingerprint_sha256"],
                        payload["layout_fingerprint_sha256"],
                    )
                    if operation == "append":
                        self.assertIsNone(payload["authority_id"])
                finally:
                    catalog.close()

    def test_continuation_key_hits_require_exact_candidate_and_target(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(root)
            )
            self.addCleanup(catalog.close)
            self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            before_binding = tuple(
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT * FROM operation_sequence_continuations"
                )
            )
            different_target = HardwareTargetBinding.from_verified_inputs(
                root / "different-mount",
                "different-tape",
                "different-scsi",
                ("archive.native", str(candidate.job_id), "1", "CT0001", "", ""),
            )
            attempts = (
                (
                    replace(candidate, id="different-job", job_id="DIFFERENT-JOB"),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                ),
                (
                    replace(candidate, id="different-sequence", cassette_sequence=2),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                ),
                (
                    replace(candidate, id="different-fingerprint"),
                    target,
                    authority_id,
                    "e" * 64,
                ),
                (
                    replace(candidate, id="different-target"),
                    different_target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                ),
                (
                    replace(candidate, id="missing-authority"),
                    target,
                    None,
                    str(epoch["layout_fingerprint_sha256"]),
                ),
                (
                    replace(candidate, id="swapped-authority"),
                    target,
                    "e" * 64,
                    str(epoch["layout_fingerprint_sha256"]),
                ),
            )
            for altered, supplied_target, supplied_authority, supplied_fingerprint in attempts:
                before_audits = len(self._continuation_audits(catalog))
                with (
                    self.subTest(operation_id=altered.id),
                    self.assertRaisesRegex(CatalogError, "idempotency_conflict"),
                ):
                    self._admit_continuation(
                        catalog,
                        owner,
                        altered,
                        supplied_target,
                        supplied_authority,
                        supplied_fingerprint,
                    )
                self.assertEqual(before_audits, len(self._continuation_audits(catalog)))
                self.assertEqual(
                    before_binding,
                    tuple(
                        tuple(row)
                        for row in catalog.connection.execute(
                            "SELECT * FROM operation_sequence_continuations"
                        )
                    ),
                )
                self.assertEqual(
                    1,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM daemon_operations"
                    ).fetchone()[0],
                )

    def test_new_continuation_rejects_nondeterministic_key_and_append_authority(
        self,
    ) -> None:
        for operation in ("format", "append"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temporary:
                catalog, owner, candidate, target, authority_id, epoch = (
                    self._continuation_fixture(Path(temporary), operation=operation)
                )
                try:
                    if operation == "append":
                        authority_id = "e" * 64
                    with self.assertRaises(Exception) as caught:
                        self._admit_continuation(
                            catalog,
                            owner,
                            replace(candidate, id=f"invalid-{operation}", idempotency_key="d" * 64),
                            target,
                            authority_id,
                            str(epoch["layout_fingerprint_sha256"]),
                        )
                    self.assertIsInstance(caught.exception, CatalogError)
                    self.assertIn("idempotency_conflict", str(caught.exception))
                    self.assertEqual(
                        0,
                        catalog.connection.execute(
                            "SELECT COUNT(*) FROM daemon_operations"
                        ).fetchone()[0],
                    )
                    self.assertEqual([], self._continuation_audits(catalog))
                finally:
                    catalog.close()

    def test_legacy_or_unrelated_key_cannot_alias_a_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(Path(temporary))
            )
            self.addCleanup(catalog.close)
            legacy = operation_candidate("legacy-operation", "legacy-key")
            catalog.admit_operation(legacy, owner, admission_open=True)
            with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                self._admit_continuation(
                    catalog,
                    owner,
                    replace(candidate, id="legacy-key-reuse", idempotency_key="legacy-key"),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
            self.assertEqual([], self._continuation_audits(catalog))

    def test_admission_rejects_a_direct_continuation_key_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(Path(temporary))
            )
            self.addCleanup(catalog.close)
            admitted = self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            catalog.finish_operation(
                OperationFence(admitted.record.id, owner.generation), "succeeded"
            )
            reserved_key = "malformed-continuation-reservation"
            catalog.connection.execute(
                "DROP TRIGGER trg_operation_sequence_continuations_no_update"
            )
            catalog.connection.execute(
                "UPDATE operation_sequence_continuations SET "
                "continuation_idempotency_key=? WHERE operation_id=?",
                (reserved_key, candidate.id),
            )
            catalog.connection.commit()
            before_operations = catalog.connection.execute(
                "SELECT COUNT(*) FROM daemon_operations"
            ).fetchone()[0]
            before_audit_entries = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries"
            ).fetchone()[0]
            before_audits = len(self._continuation_audits(catalog))

            with self.assertRaisesRegex(CatalogError, "^idempotency_conflict$"):
                catalog.admit_operation(
                    operation_candidate("public-operation", reserved_key),
                    owner,
                    admission_open=True,
                )

            self.assertEqual(
                before_operations,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations"
                ).fetchone()[0],
            )
            audit_entries = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries"
            ).fetchone()[0]
            self.assertEqual(before_audit_entries, audit_entries)
            self.assertEqual(before_audits, len(self._continuation_audits(catalog)))

    def test_admission_rejects_an_orphan_continuation_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(Path(temporary))
            )
            self.addCleanup(catalog.close)
            admitted = self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            catalog.finish_operation(
                OperationFence(admitted.record.id, owner.generation), "succeeded"
            )
            catalog.connection.execute("PRAGMA foreign_keys=OFF")
            catalog.connection.execute(
                "DELETE FROM daemon_operations WHERE id=?", (candidate.id,)
            )
            catalog.connection.commit()
            catalog.connection.execute("PRAGMA foreign_keys=ON")
            before_audits = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries"
            ).fetchone()[0]

            with self.assertRaisesRegex(CatalogError, "^idempotency_conflict$"):
                catalog.admit_operation(
                    operation_candidate("public-operation", candidate.idempotency_key),
                    owner,
                    admission_open=True,
                )

            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM operation_sequence_continuations"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations"
                ).fetchone()[0],
            )
            audit_entries = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries"
            ).fetchone()[0]
            self.assertEqual(before_audits, audit_entries)

    def test_one_continuation_key_cannot_alias_another_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, first_owner, first_candidate, first_target, first_authority, first_epoch = (
                self._continuation_fixture(
                    root, job_id="AUTO-FIRST", label="CF0001"
                )
            )
            first_admission = self._admit_continuation(
                first,
                first_owner,
                first_candidate,
                first_target,
                first_authority,
                str(first_epoch["layout_fingerprint_sha256"]),
            )
            first.finish_operation(
                OperationFence(first_admission.record.id, first_owner.generation),
                "succeeded",
            )
            first.close()

            second, second_owner, second_candidate, second_target, second_authority, second_epoch = (
                self._continuation_fixture(
                    root, job_id="AUTO-SECOND", label="CS0002"
                )
            )
            self.addCleanup(second.close)
            self._admit_continuation(
                second,
                second_owner,
                second_candidate,
                second_target,
                second_authority,
                str(second_epoch["layout_fingerprint_sha256"]),
            )
            before_audits = len(self._continuation_audits(second))
            with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                self._admit_continuation(
                    second,
                    second_owner,
                    replace(
                        first_candidate,
                        id="cross-continuation-key",
                        idempotency_key=second_candidate.idempotency_key,
                    ),
                    first_target,
                    first_authority,
                    str(first_epoch["layout_fingerprint_sha256"]),
                )
            self.assertEqual(before_audits, len(self._continuation_audits(second)))

    def test_corrupt_persisted_continuation_provenance_fails_closed(self) -> None:
        corruptions = (
            "missing_continuation",
            "missing_target",
            "missing_authority",
            "missing_confirmation",
            "duplicated_key_mismatch",
            "duplicated_job_mismatch",
            "duplicated_sequence_mismatch",
            "binding_fingerprint_mismatch",
            "binding_epoch_mismatch",
            "authority_parent_mismatch",
        )
        for corruption in corruptions:
            with self.subTest(corruption=corruption), tempfile.TemporaryDirectory() as temporary:
                catalog, owner, candidate, target, authority_id, epoch = (
                    self._continuation_fixture(Path(temporary))
                )
                try:
                    self._admit_continuation(
                        catalog,
                        owner,
                        candidate,
                        target,
                        authority_id,
                        str(epoch["layout_fingerprint_sha256"]),
                    )
                    if corruption == "missing_continuation":
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_sequence_continuations_no_delete"
                        )
                        catalog.connection.execute(
                            "DELETE FROM operation_sequence_continuations"
                        )
                    elif corruption == "missing_target":
                        catalog.connection.execute("DELETE FROM operation_hardware_targets")
                    elif corruption == "missing_authority":
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_format_authorizations_no_delete"
                        )
                        catalog.connection.execute(
                            "DELETE FROM operation_format_authorizations"
                        )
                    elif corruption == "missing_confirmation":
                        catalog.connection.commit()
                        catalog.connection.execute("PRAGMA foreign_keys=OFF")
                        catalog.connection.execute("DELETE FROM format_confirmations")
                    elif corruption == "duplicated_key_mismatch":
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_sequence_continuations_no_update"
                        )
                        catalog.connection.execute(
                            "UPDATE operation_sequence_continuations SET "
                            "continuation_idempotency_key=?",
                            ("c" * 64,),
                        )
                    elif corruption == "duplicated_job_mismatch":
                        catalog.connection.commit()
                        catalog.connection.execute("PRAGMA foreign_keys=OFF")
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_sequence_continuations_no_update"
                        )
                        catalog.connection.execute(
                            "UPDATE operation_sequence_continuations SET "
                            "job_id='CORRUPT-JOB'"
                        )
                    elif corruption == "duplicated_sequence_mismatch":
                        catalog.connection.commit()
                        catalog.connection.execute("PRAGMA foreign_keys=OFF")
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_sequence_continuations_no_update"
                        )
                        catalog.connection.execute(
                            "UPDATE operation_sequence_continuations SET "
                            "cassette_sequence=2"
                        )
                    elif corruption == "binding_fingerprint_mismatch":
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_sequence_continuations_no_update"
                        )
                        catalog.connection.execute(
                            "UPDATE operation_sequence_continuations SET "
                            "layout_fingerprint_sha256=?",
                            ("c" * 64,),
                        )
                    elif corruption == "binding_epoch_mismatch":
                        catalog.connection.commit()
                        catalog.connection.execute("PRAGMA foreign_keys=OFF")
                        catalog.connection.execute(
                            "DROP TRIGGER trg_operation_sequence_continuations_no_update"
                        )
                        catalog.connection.execute(
                            "UPDATE operation_sequence_continuations SET layout_epoch=99"
                        )
                    else:
                        catalog.connection.commit()
                        catalog.connection.execute("PRAGMA foreign_keys=OFF")
                        catalog.connection.execute(
                            "DROP TRIGGER trg_automatic_format_authorizations_no_update"
                        )
                        catalog.connection.execute(
                            "UPDATE automatic_format_authorizations SET "
                            "job_id='CORRUPT-JOB' WHERE authorization_id=?",
                            (authority_id,),
                        )
                    catalog.connection.commit()
                    before_audits = len(self._continuation_audits(catalog))
                    with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                        self._admit_continuation(
                            catalog,
                            owner,
                            replace(candidate, id=f"corrupt-{corruption}"),
                            target,
                            authority_id,
                            str(epoch["layout_fingerprint_sha256"]),
                        )
                    self.assertEqual(before_audits, len(self._continuation_audits(catalog)))
                finally:
                    catalog.close()

    def test_append_continuation_rejects_unexpected_persisted_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(Path(temporary), operation="append")
            )
            self.addCleanup(catalog.close)
            self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            unexpected = "b" * 64
            catalog.connection.execute(
                "INSERT INTO automatic_format_authorizations("
                "authorization_id,job_id,cassette_sequence,layout_epoch,"
                "layout_fingerprint_sha256,expected_label,expected_operation,"
                "reuse_registered,authorized_by,authorized_at,request_sha256) "
                "VALUES(?,?,?,?,?,?,'format',0,'fixture','2026-08-31T12:00:00+00:00',?)",
                (
                    unexpected,
                    candidate.job_id,
                    1,
                    epoch["epoch_number"],
                    epoch["layout_fingerprint_sha256"],
                    "CT0001",
                    "a" * 64,
                ),
            )
            catalog.connection.execute(
                "INSERT INTO format_confirmations("
                "operation_id,job_id,cassette_sequence,expected_label,"
                "confirmed_by,confirmed_at) VALUES(?,?,?,?,?,?)",
                (
                    candidate.id,
                    candidate.job_id,
                    1,
                    "CT0001",
                    "fixture",
                    "2026-08-31T12:00:01+00:00",
                ),
            )
            catalog.connection.execute(
                "INSERT INTO operation_format_authorizations("
                "operation_id,authorization_id,linked_at) VALUES(?,?,?)",
                (candidate.id, unexpected, "2026-08-31T12:00:01+00:00"),
            )
            catalog.connection.commit()
            before_audits = len(self._continuation_audits(catalog))
            with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                self._admit_continuation(
                    catalog,
                    owner,
                    replace(candidate, id="unexpected-append-authority"),
                    target,
                    None,
                    str(epoch["layout_fingerprint_sha256"]),
                )
            self.assertEqual(before_audits, len(self._continuation_audits(catalog)))

    def test_continuation_audit_failures_have_exact_rollback_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(Path(temporary))
            )
            self.addCleanup(catalog.close)
            before_history = tuple(
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT * FROM job_management_history ORDER BY id"
                )
            )
            before_management = tuple(
                catalog.connection.execute(
                    "SELECT * FROM job_management_state WHERE job_id=?",
                    (candidate.job_id,),
                ).fetchone()
            )
            original_audit = Catalog._record_audit_tx

            def fail_admitted(*args, **kwargs):
                action = args[2]
                if action == "automatic.sequence.continuation.admitted":
                    raise sqlite3.IntegrityError("forced admitted audit failure")
                return original_audit(*args, **kwargs)

            with (
                patch.object(Catalog, "_record_audit_tx", side_effect=fail_admitted),
                self.assertRaisesRegex(sqlite3.IntegrityError, "forced admitted"),
            ):
                self._admit_continuation(
                    catalog,
                    owner,
                    candidate,
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
            for table in (
                "daemon_operations",
                "operation_hardware_targets",
                "operation_sequence_continuations",
                "format_confirmations",
                "operation_format_authorizations",
            ):
                with self.subTest(table=table):
                    self.assertEqual(
                        0,
                        catalog.connection.execute(
                            f"SELECT COUNT(*) FROM {table}"
                        ).fetchone()[0],
                    )
            self.assertEqual(
                before_history,
                tuple(
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_management_history ORDER BY id"
                    )
                ),
            )
            self.assertEqual(
                before_management,
                tuple(
                    catalog.connection.execute(
                        "SELECT * FROM job_management_state WHERE job_id=?",
                        (candidate.job_id,),
                    ).fetchone()
                ),
            )
            self.assertEqual(
                0,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM audit_entries WHERE action IN "
                    "('operation.start','automatic.sequence.continuation.admitted')"
                ).fetchone()[0],
            )

            admitted = self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            replay_calls = 0

            def fail_replayed(*args, **kwargs):
                nonlocal replay_calls
                action = args[2]
                if action == "automatic.sequence.continuation.replayed":
                    replay_calls += 1
                    raise sqlite3.IntegrityError("forced replay audit failure")
                return original_audit(*args, **kwargs)

            before_audits = len(self._continuation_audits(catalog))
            with (
                patch.object(Catalog, "_record_audit_tx", side_effect=fail_replayed),
                self.assertRaisesRegex(sqlite3.IntegrityError, "forced replay"),
            ):
                self._admit_continuation(
                    catalog,
                    owner,
                    replace(candidate, id="failed-replay-audit"),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
            self.assertEqual(1, replay_calls)
            self.assertEqual(before_audits, len(self._continuation_audits(catalog)))
            self.assertEqual(admitted.record.id, catalog.get_operation(candidate.id)["id"])

    def test_operation_insert_race_uses_exact_replay_loader_and_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(root)
            )
            database = catalog.path
            admitted = self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            normal = self._admit_continuation(
                catalog,
                owner,
                replace(candidate, id="normal-replay-candidate"),
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            catalog.finish_operation(
                OperationFence(admitted.record.id, owner.generation), "succeeded"
            )
            catalog.close()

            racing = _MissExistingOperationLookupCatalog(database)
            try:
                raced = self._admit_continuation(
                    racing,
                    owner,
                    replace(candidate, id="race-loser-candidate"),
                    target,
                    authority_id,
                    str(epoch["layout_fingerprint_sha256"]),
                )
                payloads = [payload for _action, payload in self._continuation_audits(racing)]
                self.assertEqual(2, racing.operation_lookup_count)
                self.assertTrue(normal.replayed)
                self.assertTrue(raced.replayed)
                self.assertEqual(candidate.id, raced.record.id)
                self.assertEqual(set(payloads[-2]), set(payloads[-1]))
                self.assertIn("layout_epoch", payloads[-1])
                self.assertEqual(
                    {**payloads[-2], "outcome": "replayed"}, payloads[-1]
                )
            finally:
                racing.close()

    def test_operation_insert_race_mismatch_writes_no_replay_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(root)
            )
            database = catalog.path
            admitted = self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            catalog.finish_operation(
                OperationFence(admitted.record.id, owner.generation), "succeeded"
            )
            catalog.connection.execute(
                "DROP TRIGGER trg_operation_sequence_continuations_no_update"
            )
            catalog.connection.execute(
                "UPDATE operation_sequence_continuations SET "
                "layout_fingerprint_sha256=? WHERE operation_id=?",
                ("e" * 64, candidate.id),
            )
            catalog.connection.commit()
            before_audits = len(self._continuation_audits(catalog))
            catalog.close()

            racing = _MissExistingOperationLookupCatalog(database)
            try:
                with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                    self._admit_continuation(
                        racing,
                        owner,
                        replace(candidate, id="race-mismatch-candidate"),
                        target,
                        authority_id,
                        str(epoch["layout_fingerprint_sha256"]),
                    )
                self.assertEqual(2, racing.operation_lookup_count)
                self.assertEqual(before_audits, len(self._continuation_audits(racing)))
            finally:
                racing.close()

    def test_operation_insert_race_replay_audit_failure_is_not_reclassified(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog, owner, candidate, target, authority_id, epoch = (
                self._continuation_fixture(root)
            )
            database = catalog.path
            admitted = self._admit_continuation(
                catalog,
                owner,
                candidate,
                target,
                authority_id,
                str(epoch["layout_fingerprint_sha256"]),
            )
            catalog.finish_operation(
                OperationFence(admitted.record.id, owner.generation), "succeeded"
            )
            before_audits = len(self._continuation_audits(catalog))
            catalog.close()

            racing = _MissExistingOperationLookupCatalog(database)
            original_audit = Catalog._record_audit_tx
            replay_calls = 0

            def fail_race_replay(*args, **kwargs):
                nonlocal replay_calls
                if args[2] == "automatic.sequence.continuation.replayed":
                    replay_calls += 1
                    raise sqlite3.IntegrityError("forced race replay audit failure")
                return original_audit(*args, **kwargs)

            try:
                with (
                    patch.object(Catalog, "_record_audit_tx", side_effect=fail_race_replay),
                    self.assertRaisesRegex(sqlite3.IntegrityError, "forced race replay"),
                ):
                    self._admit_continuation(
                        racing,
                        owner,
                        replace(candidate, id="race-audit-failure-candidate"),
                        target,
                        authority_id,
                        str(epoch["layout_fingerprint_sha256"]),
                    )
                self.assertEqual(1, replay_calls)
                self.assertEqual(2, racing.operation_lookup_count)
                self.assertEqual(before_audits, len(self._continuation_audits(racing)))
                self.assertIsNotNone(racing.get_operation(candidate.id))
            finally:
                racing.close()


    def test_sequence_candidate_stops_at_the_current_unpromoted_reserve(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog = self._sequence_catalog(
                Path(temporary),
                job_id="ORDERED",
                cassettes=[
                    ("AA0001", "SERIAL-1", 0, 0),
                    ("BB0002", "SERIAL-2", 1, 7),
                ],
            )
            self.addCleanup(catalog.close)
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET operation='append' "
                "WHERE job_id='ORDERED' AND sequence=2"
            )
            self._authorize_and_enable_sequence(catalog, "ORDERED")

            self.assertIsNone(catalog.next_automatic_sequence_candidate())

            catalog.update_automatic_job("ORDERED", "waiting_media", current_sequence=2)
            candidate = catalog.next_automatic_sequence_candidate()
            self.assertEqual("ORDERED", candidate["job_id"])
            self.assertEqual(2, candidate["cassette_sequence"])
            self.assertIsNone(candidate["authorization_id"])

    def test_sequence_candidate_requires_exact_registered_reuse_decision(self) -> None:
        for allowed_reuse in (False, True):
            with self.subTest(allowed_reuse=allowed_reuse), tempfile.TemporaryDirectory() as temporary:
                catalog = self._sequence_catalog(
                    Path(temporary),
                    job_id="REUSE",
                    cassettes=[("CC0003", "SERIAL-3", 1, 7)],
                    allow_registered_reuse=allowed_reuse,
                )
                self.addCleanup(catalog.close)
                authorization_id = self._authorize_and_enable_sequence(
                    catalog, "REUSE"
                )[0]

                candidate = catalog.next_automatic_sequence_candidate()
                self.assertEqual(authorization_id, candidate["authorization_id"])
                self.assertEqual(
                    authorization_id,
                    catalog.format_sequence_authorization("REUSE", 1)[
                        "authorization_id"
                    ],
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET reuse_registered=? "
                    "WHERE job_id='REUSE' AND sequence=1",
                    (int(not allowed_reuse),),
                )

                self.assertIsNone(catalog.format_sequence_authorization("REUSE", 1))
                self.assertIsNone(catalog.next_automatic_sequence_candidate())

    def test_sequence_authorization_rejects_noncanonical_legacy_label(self) -> None:
        for label in ("ab1234", "AB!234"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                catalog = self._sequence_catalog(
                    Path(temporary),
                    job_id="LEGACY",
                    cassettes=[(label, "SERIAL-4", 1, 7)],
                )
                self.addCleanup(catalog.close)
                fingerprint = catalog.latest_layout_epoch("LEGACY")[
                    "layout_fingerprint_sha256"
                ]

                with self.assertRaisesRegex(
                    ValidationError, "canonical physical label"
                ):
                    catalog.authorize_automatic_format_sequence(
                        "LEGACY",
                        expected_revision=0,
                        layout_fingerprint_sha256=fingerprint,
                        actor="admin-1",
                        idempotency_key="reject-legacy-label",
                        authorized_at="2026-08-30T18:00:00+00:00",
                    )

    def test_sequence_authorization_replays_only_the_exact_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog = self._sequence_catalog(
                Path(temporary),
                job_id="REPLAY",
                cassettes=[("DD0004", "SERIAL-4", 1, 7)],
            )
            self.addCleanup(catalog.close)
            fingerprint = catalog.latest_layout_epoch("REPLAY")[
                "layout_fingerprint_sha256"
            ]
            arguments = {
                "expected_revision": 0,
                "layout_fingerprint_sha256": fingerprint,
                "actor": "admin-1",
                "idempotency_key": "authorize-replay",
                "authorized_at": "2026-08-30T18:00:00+00:00",
            }

            first = catalog.authorize_automatic_format_sequence("REPLAY", **arguments)
            self.assertEqual(
                first,
                catalog.authorize_automatic_format_sequence("REPLAY", **arguments),
            )
            with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                catalog.authorize_automatic_format_sequence(
                    "REPLAY", **{**arguments, "authorized_at": "2026-08-30T18:01:00+00:00"}
                )
            with self.assertRaisesRegex(CatalogError, "revision_conflict"):
                catalog.authorize_automatic_format_sequence(
                    "REPLAY", **{**arguments, "expected_revision": 1, "idempotency_key": "stale-revision"}
                )
            with self.assertRaisesRegex(CatalogError, "layout_conflict"):
                catalog.authorize_automatic_format_sequence(
                    "REPLAY", **{**arguments, "layout_fingerprint_sha256": "f" * 64, "idempotency_key": "stale-layout"}
                )
            catalog.connection.execute(
                "UPDATE job_management_state SET retired_at='2026-08-30T18:02:00+00:00' "
                "WHERE job_id='REPLAY'"
            )
            with self.assertRaisesRegex(CatalogError, "job_retired"):
                catalog.authorize_automatic_format_sequence(
                    "REPLAY", **{**arguments, "idempotency_key": "retired-job"}
                )

    def test_sequence_authorization_rejects_imported_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog = self._sequence_catalog(
                Path(temporary),
                job_id="IMPORTED",
                cassettes=[("FF0006", "SERIAL-6", 1, 7)],
            )
            self.addCleanup(catalog.close)
            catalog.connection.execute(
                "INSERT INTO imported_job_policies("
                "job_id,assignment_sha256,bundle_sha256,authority_state,"
                "windows_authority,rollback_allowed,frozen_at) "
                "VALUES('IMPORTED',?,?, 'active_linux','resumable',0,?)",
                ("a" * 64, "b" * 64, "2026-08-30T18:00:00+00:00"),
            )
            fingerprint = catalog.latest_layout_epoch("IMPORTED")[
                "layout_fingerprint_sha256"
            ]

            with self.assertRaisesRegex(CatalogError, "native_only"):
                catalog.authorize_automatic_format_sequence(
                    "IMPORTED",
                    expected_revision=0,
                    layout_fingerprint_sha256=fingerprint,
                    actor="admin-1",
                    idempotency_key="imported-denied",
                    authorized_at="2026-08-30T18:00:00+00:00",
                )

    def test_sequence_candidate_uses_a_stable_job_tie_break(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            catalog = Catalog(root / "catalog.db")
            self.addCleanup(catalog.close)
            catalog.initialize()
            for library_id in ("LIB-B", "LIB-A"):
                source = root / library_id
                source.mkdir()
                catalog.add_library(library_id, library_id, str(source))
            for job_id, library_id, label in (
                ("JOB-B", "LIB-B", "GG0007"),
                ("JOB-A", "LIB-A", "HH0008"),
            ):
                catalog.create_automatic_job(
                    job_id,
                    library_id,
                    "synthetic-drive",
                    "/synthetic/mount",
                    [(label, f"SERIAL-{job_id}", 1, 7)],
                    force_format=True,
                )
                self._authorize_and_enable_sequence(catalog, job_id)

            candidate = catalog.next_automatic_sequence_candidate()
            self.assertEqual("JOB-A", candidate["job_id"])
            self.assertEqual(1, candidate["cassette_sequence"])

    def test_sequence_authority_tables_are_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            catalog = self._sequence_catalog(
                Path(temporary),
                job_id="IMMUTABLE",
                cassettes=[("EE0005", "SERIAL-5", 1, 7)],
            )
            self.addCleanup(catalog.close)
            authorization_id = self._authorize_and_enable_sequence(
                catalog, "IMMUTABLE"
            )[0]
            catalog.connection.execute(
                "INSERT INTO daemon_operations("
                "id,kind,state,phase,idempotency_key,principal,owner_generation,"
                "job_id,cassette_sequence,started_at) "
                "VALUES('format-operation','archive.native','running',NULL,"
                "'format-operation','admin-1',1,'IMMUTABLE',1,"
                "'2026-08-30T18:02:00+00:00')"
            )
            catalog.connection.execute(
                "INSERT INTO format_confirmations("
                "operation_id,job_id,cassette_sequence,expected_label,confirmed_by,confirmed_at) "
                "VALUES('format-operation','IMMUTABLE',1,'EE0005','admin-1',"
                "'2026-08-30T18:02:00+00:00')"
            )
            catalog.connection.execute(
                "INSERT INTO operation_format_authorizations("
                "operation_id,authorization_id,linked_at) VALUES(?,?,?)",
                (
                    "format-operation",
                    authorization_id,
                    "2026-08-30T18:02:00+00:00",
                ),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                catalog.connection.execute(
                    "UPDATE operation_format_authorizations SET linked_at='changed'"
                )
            with self.assertRaises(sqlite3.IntegrityError):
                catalog.connection.execute("DELETE FROM operation_format_authorizations")

    def test_authority_is_immutable_and_bound_to_exact_layout_and_cassette(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=35)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "AUTO-ONE",
                    "LIB1",
                    "synthetic-drive",
                    "/synthetic/mount",
                    [
                        (f"TAPE{sequence:02d}", f"SERIAL-{sequence}", 1, 7)
                        for sequence in range(1, 21)
                    ],
                    force_format=True,
                )
                catalog.connection.execute("DROP TRIGGER trg_layout_epochs_no_update")
                catalog.connection.execute(
                    "UPDATE job_layout_epochs SET layout_fingerprint_sha256=? "
                    "WHERE job_id='AUTO-ONE'",
                    ("a" * 64,),
                )
                catalog.connection.execute(
                    "CREATE TRIGGER trg_layout_epochs_no_update "
                    "BEFORE UPDATE ON job_layout_epochs "
                    "BEGIN SELECT RAISE(ABORT,'immutable_layout_epoch'); END"
                )
                catalog.connection.commit()

            with Catalog(database) as catalog:
                initialize_current_with_protected_backup(catalog, root)
                ids = catalog.authorize_automatic_format_sequence(
                    "AUTO-ONE",
                    expected_revision=0,
                    layout_fingerprint_sha256="a" * 64,
                    actor="admin-1",
                    idempotency_key="authorize-one",
                    authorized_at="2026-08-30T18:00:00+00:00",
                )
                self.assertEqual(20, len(ids))
                row = catalog.format_sequence_authorization("AUTO-ONE", 1)
                self.assertEqual("TAPE01", row["expected_label"])
                self.assertEqual("format", row["expected_operation"])
                with self.assertRaises(sqlite3.IntegrityError):
                    catalog.connection.execute(
                        "UPDATE automatic_format_authorizations "
                        "SET expected_label='WRONG1'"
                    )

    def test_new_catalog_stops_at_requested_schema_version(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"

            with Catalog(database_path) as catalog:
                catalog.initialize(target_version=1)
                application_tables = {
                    row[0]
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master "
                        "WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                    )
                }
                tape_columns = {
                    row[1]
                    for row in catalog.connection.execute("PRAGMA table_info(tapes)")
                }
                library_columns = {
                    row[1]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(libraries)"
                    )
                }
                file_columns = {
                    row[1]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(file_versions)"
                    )
                }

            self.assertEqual("1", read_schema_version(database_path))
            self.assertEqual(
                {"metadata", "libraries", "tapes", "blocks", "file_versions", "events"},
                application_tables,
            )
            self.assertNotIn("cassette_number", tape_columns)
            self.assertNotIn("last_scan_files", library_columns)
            self.assertNotIn("parent_path", file_columns)
            self.assertNotIn("metadata_state", file_columns)

    def test_schema_seventeen_format_rebindings_migrate_without_loss(self) -> None:
        for column_layout in ("identify", "probe_media"):
            for populated in (False, True):
                with (
                    self.subTest(
                        column_layout=column_layout,
                        populated=populated,
                    ),
                    tempfile.TemporaryDirectory() as temporary,
                ):
                    database_path = make_schema_17_format_rebinding_catalog(
                        Path(temporary) / "catalog.db",
                        column_layout=column_layout,
                        populated=populated,
                    )

                    with Catalog(database_path) as catalog:
                        initialize_current_with_protected_backup(
                            catalog, database_path.parent
                        )
                        catalog.initialize()
                        columns = {
                            row[1]
                            for row in catalog.connection.execute(
                                "PRAGMA table_info(format_media_rebindings)"
                            )
                        }
                        rows = catalog.connection.execute(
                            "SELECT operation_id,pre_probe_media_command_id,"
                            "format_command_id,post_probe_media_command_id,"
                            "pre_media_identity_sha256,"
                            "post_media_identity_sha256 "
                            "FROM format_media_rebindings"
                        ).fetchall()
                        if populated:
                            self.assertEqual(
                                (
                                    "operation-schema17",
                                    "pre-command",
                                    "format-command",
                                    "post-command",
                                    "1" * 64,
                                    "2" * 64,
                                ),
                                tuple(rows[0]),
                            )
                            with self.assertRaisesRegex(
                                sqlite3.IntegrityError,
                                "format media rebinding is immutable",
                            ):
                                catalog.connection.execute(
                                    "UPDATE format_media_rebindings "
                                    "SET observed_label='SUBSTITUTED'"
                                )
                            with self.assertRaisesRegex(
                                sqlite3.IntegrityError,
                                "format media rebinding is immutable",
                            ):
                                catalog.connection.execute(
                                    "DELETE FROM format_media_rebindings"
                                )
                        else:
                            self.assertEqual([], rows)

                    self.assertEqual(
                        str(SCHEMA_VERSION), read_schema_version(database_path)
                    )
                    self.assertIn("pre_probe_media_command_id", columns)
                    self.assertIn("post_probe_media_command_id", columns)
                    self.assertNotIn("pre_identify_command_id", columns)
                    self.assertNotIn("post_identify_command_id", columns)
                    self.assertEqual(["ok"], integrity_check(database_path))
                    self.assertEqual([], foreign_key_violations(database_path))

    def test_schema_seventeen_hybrid_rebinding_layout_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = make_schema_17_format_rebinding_catalog(
                Path(temporary) / "catalog.db",
                column_layout="identify",
                populated=True,
            )
            with sqlite3.connect(database_path) as connection:
                connection.execute(
                    "ALTER TABLE format_media_rebindings RENAME COLUMN "
                    "pre_identify_command_id TO pre_probe_media_command_id"
                )

            with (
                Catalog(database_path) as catalog,
                self.assertRaisesRegex(CatalogError, "layout is invalid"),
            ):
                catalog.initialize(target_version=18)

            self.assertEqual("17", read_schema_version(database_path))
            self.assertEqual(["ok"], integrity_check(database_path))
            self.assertEqual([], foreign_key_violations(database_path))

    def test_direct_schema_thirteen_upgrade_requires_protected_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = make_populated_schema_13_catalog(
                Path(temporary) / "catalog.db"
            )

            with (
                Catalog(database_path) as catalog,
                self.assertRaisesRegex(CatalogError, "protected backup"),
            ):
                catalog.initialize()

            self.assertEqual("13", read_schema_version(database_path))
            with closing(sqlite3.connect(database_path)) as connection:
                daemon_table = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='daemon_operations'"
                ).fetchone()
            self.assertIsNone(daemon_table)

    def test_hardware_target_binding_is_canonical_hashed_and_redacted(self) -> None:
        target = synthetic_target()
        canonical_equivalent = HardwareTargetBinding.from_verified_inputs(
            Path("/synthetic/root/../mount-a"),
            "synthetic-tape-a",
            "synthetic-scsi-a",
            ("archive.resume", "JOB-SYNTHETIC", "4", "media-a", "", ""),
        )
        self.assertEqual(
            target.mount_path_sha256, canonical_equivalent.mount_path_sha256
        )
        values = asdict(target)
        self.assertEqual(
            {
                "mount_path_sha256",
                "tape_device_identity_sha256",
                "scsi_device_identity_sha256",
                "expected_media_scope_sha256",
            },
            set(values),
        )
        self.assertTrue(
            all(re.fullmatch(r"[0-9a-f]{64}", value) for value in values.values())
        )
        rendered = json.dumps(values, sort_keys=True)
        for raw in (
            "/synthetic/mount-a",
            "synthetic-tape-a",
            "synthetic-scsi-a",
            "media-a",
        ):
            self.assertNotIn(raw, rendered)

    def test_populated_schema_thirteen_migrates_through_fourteen_with_foreign_keys(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = make_populated_schema_13_catalog(root / "catalog.db")
            before = canonical_row_snapshot(database_path, POPULATED_TABLES)
            expected = normalize_snapshot_value(
                before,
                table="automatic_jobs",
                column="status",
                old="formatting",
                new="formatting_media",
            )
            expected = normalize_snapshot_value(
                expected,
                table="automatic_cassettes",
                column="status",
                old="formatting",
                new="formatting_media",
            )
            for library in expected["libraries"]:
                library.update(
                    {
                        "enabled": 1 if library["status"] == "active" else 0,
                        "source_canonical_root": None,
                        "source_identity_sha256": None,
                        "scan_state": "never",
                        "scan_revision": 0,
                        "scan_fingerprint_sha256": None,
                        "source_kind": "local",
                        "metadata_revision": 0,
                    }
                )
            for item in expected["automatic_cassette_items"]:
                item["tape_relative_path"] = item["relative_path"]
            for version in expected["file_versions"]:
                version["source_change_ns"] = None

            prepare_and_initialize(database_path)

            self.assertEqual(str(SCHEMA_VERSION), read_schema_version(database_path))
            self.assertEqual(
                expected, canonical_row_snapshot(database_path, POPULATED_TABLES)
            )
            self.assertEqual(["ok"], integrity_check(database_path))
            self.assertEqual([], foreign_key_violations(database_path))
            with Catalog(database_path) as catalog:
                self.assertEqual(
                    "formatting_media", catalog.get_automatic_job("JOB1")["status"]
                )
                daemon_fence = catalog.claim_daemon_owner("catalog-test")
                admitted = catalog.admit_operation(
                    operation_candidate("op-1", "key-1"),
                    daemon_fence,
                    admission_open=True,
                )
                self.assertFalse(admitted.replayed)
                self.assertEqual("op-1", catalog.active_operation()["id"])
                indexes = {
                    row[1]
                    for row in catalog.connection.execute(
                        "PRAGMA index_list(daemon_operations)"
                    )
                }
                self.assertIn("ux_daemon_one_blocking", indexes)

    def test_existing_schema_fourteen_adds_release_authorization_table_in_place(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"
            with Catalog(database_path) as catalog:
                catalog.initialize()
                catalog.connection.execute(
                    "DROP TABLE IF EXISTS hardware_command_release_authorizations"
                )
                catalog.connection.commit()

            with Catalog(database_path) as catalog:
                catalog.initialize()
                table = catalog.connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='hardware_command_release_authorizations'"
                ).fetchone()

            self.assertIsNotNone(table)
            self.assertEqual(str(SCHEMA_VERSION), read_schema_version(database_path))
            self.assertEqual(["ok"], integrity_check(database_path))
            self.assertEqual([], foreign_key_violations(database_path))

    def test_command_release_authorization_is_idempotent_and_not_execution(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"
            with Catalog(database_path) as catalog:
                catalog.initialize()
                owner = catalog.claim_daemon_owner("daemon-1")
                admission = catalog.admit_operation(
                    operation_candidate("op-1", "key-1"),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admission.record.id, owner.generation)
                process = ProcessIdentity("boot-a", 4321, 991, 4321)
                catalog.reserve_hardware_command(
                    fence, "cmd-1", "unmount", sha256_fixture("argv")
                )
                catalog.record_blocked_process("cmd-1", fence, process)

                catalog.authorize_hardware_command_release("cmd-1", fence, "b" * 64)
                catalog.authorize_hardware_command_release("cmd-1", fence, "b" * 64)
                authorized = catalog.command("cmd-1")

                self.assertEqual("release_authorized", authorized.state)
                self.assertEqual("authorized", authorized.release_status)
                self.assertEqual("b" * 64, authorized.release_permit_sha256)
                self.assertIsNotNone(authorized.release_authorized_at)
                self.assertIsNone(authorized.release_confirmed_at)
                self.assertIsNone(authorized.released_at)
                with self.assertRaises(CatalogError):
                    catalog.authorize_hardware_command_release("cmd-1", fence, "c" * 64)
                catalog.reserve_hardware_command(
                    fence, "cmd-2", "status", sha256_fixture("argv-2")
                )
                catalog.record_blocked_process(
                    "cmd-2", fence, ProcessIdentity("boot-a", 4322, 992, 4322)
                )
                with self.assertRaisesRegex(CatalogError, "reused"):
                    catalog.authorize_hardware_command_release("cmd-2", fence, "b" * 64)

                catalog.confirm_hardware_command_released("cmd-1", fence, "b" * 64)
                catalog.confirm_hardware_command_released("cmd-1", fence, "b" * 64)
                released = catalog.command("cmd-1")

                self.assertEqual("released", released.state)
                self.assertEqual("released", released.release_status)
                self.assertIsNotNone(released.released_at)
                self.assertEqual(released.released_at, released.release_confirmed_at)

    def test_ambiguous_release_requires_exact_current_negative_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"
            with Catalog(database_path) as catalog:
                catalog.initialize()
                owner = catalog.claim_daemon_owner("daemon-1")
                admission = catalog.admit_operation(
                    operation_candidate("op-1", "key-1"),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )
                fence = OperationFence(admission.record.id, owner.generation)
                process = ProcessIdentity("boot-a", 4321, 991, 4321)
                permit = "b" * 64
                catalog.reserve_hardware_command(
                    fence, "cmd-1", "unmount", sha256_fixture("argv")
                )
                catalog.record_blocked_process("cmd-1", fence, process)
                catalog.authorize_hardware_command_release("cmd-1", fence, permit)
                catalog.mark_hardware_command_release_ambiguous("cmd-1", owner, permit)
                current = catalog.claim_daemon_owner("daemon-2")
                catalog.recover_interrupted_operations(current)
                exact = {
                    "scope_command_id": "cmd-1",
                    "scope_owner_generation": owner.generation,
                    "observed_pid": process.pid,
                    "permit_sha256": permit,
                }
                mismatches = (
                    {**exact, "scope_command_id": "cmd-other"},
                    {**exact, "scope_owner_generation": current.generation},
                    {**exact, "observed_pid": process.pid + 1},
                    {**exact, "permit_sha256": "f" * 64},
                )

                for evidence in mismatches:
                    with (
                        self.subTest(evidence=evidence),
                        self.assertRaisesRegex(CatalogError, "does not match"),
                    ):
                        catalog.reconcile_ambiguous_hardware_command_unreleased(
                            "cmd-1", current, **evidence
                        )
                with self.assertRaises(StaleDaemonFence):
                    catalog.reconcile_ambiguous_hardware_command_unreleased(
                        "cmd-1", owner, **exact
                    )

                command = catalog.command("cmd-1")
                self.assertEqual("release_authorized", command.state)
                self.assertEqual("ambiguous", command.release_status)
                self.assertEqual(
                    "recovery_required", catalog.get_operation("op-1")["state"]
                )

    def test_operation_admission_replay_fences_mutations_and_redacts_audit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"
            with Catalog(database_path) as catalog:
                catalog.initialize()
                first_owner = catalog.claim_daemon_owner("daemon-1")
                candidate = operation_candidate("op-1", "same-key")
                admitted = catalog.admit_operation(
                    candidate, first_owner, admission_open=True
                )
                replayed = catalog.admit_operation(
                    replace(candidate, id="op-replay"),
                    first_owner,
                    admission_open=False,
                )
                self.assertFalse(admitted.replayed)
                self.assertTrue(replayed.replayed)
                self.assertEqual("op-1", replayed.record.id)
                with self.assertRaises(OperationConflict):
                    catalog.admit_operation(
                        operation_candidate("op-2", "other-key"),
                        first_owner,
                        admission_open=True,
                    )

                operation_fence = OperationFence("op-1", first_owner.generation)
                catalog.record_phase_sample(
                    operation_fence,
                    "writing_manifest",
                    "2026-08-21T12:00:01+00:00",
                    0.5,
                )
                second_owner = catalog.claim_daemon_owner("daemon-2")
                with self.assertRaises(StaleOperationFence):
                    catalog.finish_operation(operation_fence, "succeeded")
                self.assertEqual(first_owner.generation + 1, second_owner.generation)

                redacted_value = "never-persist-this-value"
                catalog.record_audit(
                    "admin",
                    "operation.test",
                    "denied",
                    "request-1",
                    None,
                    {
                        "Authorization": redacted_value,
                        "nested": {
                            "smb_password": redacted_value,
                            "sMbUsername": redacted_value,
                            "ACCESS-TOKEN": redacted_value,
                            "safe": "retained",
                        },
                        "items": [{"sessionCookie": redacted_value}],
                    },
                )
                payload = catalog.connection.execute(
                    "SELECT payload_json FROM audit_entries ORDER BY id DESC LIMIT 1"
                ).fetchone()[0]
                self.assertNotIn(redacted_value, payload)
                decoded = json.loads(payload)
                self.assertEqual("retained", decoded["nested"]["safe"])
                self.assertEqual("[REDACTED]", decoded["Authorization"])
                self.assertLess(catalog.reserve_event_id(), catalog.reserve_event_id())

    def test_recovery_requires_exact_quiescent_command_and_physical_receipts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"
            target = synthetic_target()
            observed_media = sha256_fixture("synthetic-observed-media-a")
            identify_process = ProcessIdentity("boot-a", 4000, 900, 4000)
            process = ProcessIdentity("boot-a", 4321, 991, 4321)
            with Catalog(database_path) as catalog:
                catalog.initialize()
                old_owner = catalog.claim_daemon_owner("daemon-1")
                admitted = catalog.admit_operation(
                    operation_candidate("op-crashed", "old-key"),
                    old_owner,
                    admission_open=True,
                    hardware_target=target,
                )
                old_fence = OperationFence(admitted.record.id, old_owner.generation)
                catalog.reserve_hardware_command(
                    old_fence,
                    "cmd-identify",
                    "identify",
                    sha256_fixture("identify argv"),
                )
                with self.assertRaises(CommandQuiescenceRequired):
                    catalog.bind_observed_media_identity(old_fence, observed_media)
                catalog.record_blocked_process(
                    "cmd-identify", old_fence, identify_process
                )
                confirm_command_release(catalog, "cmd-identify", old_fence)
                catalog.acknowledge_command_quiescence(
                    "cmd-identify",
                    old_owner,
                    CommandExitEvidence(
                        "cmd-identify",
                        identify_process,
                        "completed",
                        command_exit_after_release(catalog, "cmd-identify"),
                    ),
                )
                catalog.reserve_hardware_command(
                    old_fence,
                    "cmd-probe-media",
                    "probe_media",
                    sha256_fixture("media probe argv"),
                )
                probe_process = ProcessIdentity("boot-a", 4001, 901, 4001)
                catalog.record_blocked_process(
                    "cmd-probe-media", old_fence, probe_process
                )
                confirm_command_release(catalog, "cmd-probe-media", old_fence)
                catalog.acknowledge_command_quiescence(
                    "cmd-probe-media",
                    old_owner,
                    CommandExitEvidence(
                        "cmd-probe-media",
                        probe_process,
                        "completed",
                        command_exit_after_release(catalog, "cmd-probe-media"),
                    ),
                )
                catalog.bind_observed_media_identity(old_fence, observed_media)
                catalog.reserve_hardware_command(
                    old_fence, "cmd-unmount", "unmount", sha256_fixture("unmount argv")
                )
                self.assertEqual(
                    observed_media,
                    catalog.command("cmd-unmount").observed_media_identity_sha256,
                )
                catalog.record_blocked_process("cmd-unmount", old_fence, process)
                confirm_command_release(catalog, "cmd-unmount", old_fence)
                catalog.finish_operation(
                    old_fence,
                    "recovery_required",
                    error_class="operator_required",
                    error_code="recovery_required",
                )
                current = catalog.claim_daemon_owner("daemon-2")

                with self.assertRaises(CommandQuiescenceRequired):
                    catalog.create_command_quiescence_receipt("op-crashed", current)
                with self.assertRaises(OperationConflict):
                    catalog.admit_operation(
                        operation_candidate("replacement", "replacement-key"),
                        current,
                        admission_open=True,
                    )

                catalog.acknowledge_command_quiescence(
                    "cmd-unmount",
                    current,
                    CommandExitEvidence(
                        "cmd-unmount",
                        process,
                        "terminated",
                        command_exit_after_release(catalog, "cmd-unmount"),
                    ),
                )
                command_receipt = catalog.create_command_quiescence_receipt(
                    "op-crashed", current
                )
                physical_receipt = catalog.create_physical_reconciliation_receipt(
                    "op-crashed",
                    current,
                    command_receipt.id,
                    VerifiedPhysicalQuiescence(
                        target=target,
                        observed_media_identity_sha256=observed_media,
                        mounted=False,
                        media_loaded=False,
                        drive_busy=False,
                        related_processes=(),
                    ),
                )
                self.assertEqual(target, physical_receipt.target)
                self.assertEqual(
                    observed_media, physical_receipt.observed_media_identity_sha256
                )
                self.assertLess(
                    command_receipt.recorded_at, physical_receipt.recorded_at
                )
                resolved = catalog.resolve_recovery(
                    "op-crashed",
                    current,
                    SafeRecoveryResolution(
                        reason_code="terminated-and-physically-reconciled",
                        command_receipt_id=command_receipt.id,
                        physical_receipt_id=physical_receipt.id,
                    ),
                )
                self.assertEqual("cancelled", resolved.state)
                replacement = catalog.admit_operation(
                    operation_candidate("replacement", "replacement-key"),
                    current,
                    admission_open=True,
                )
                self.assertEqual("replacement", replacement.record.id)

    def test_observed_media_binding_is_set_once_and_mismatch_requires_recovery(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            owner = catalog.claim_daemon_owner("daemon-1")
            admission = catalog.admit_operation(
                operation_candidate("op-1", "key-1"),
                owner,
                admission_open=True,
                hardware_target=synthetic_target(),
            )
            fence = OperationFence(admission.record.id, owner.generation)
            catalog.reserve_hardware_command(
                fence, "cmd-identify", "identify", sha256_fixture("argv")
            )
            first = sha256_fixture("synthetic-observed-media-a")
            process = ProcessIdentity("boot-a", 100, 200, 100)
            catalog.record_blocked_process("cmd-identify", fence, process)
            confirm_command_release(catalog, "cmd-identify", fence)
            catalog.acknowledge_command_quiescence(
                "cmd-identify",
                owner,
                CommandExitEvidence(
                    "cmd-identify",
                    process,
                    "completed",
                    command_exit_after_release(catalog, "cmd-identify"),
                ),
            )
            catalog.reserve_hardware_command(
                fence,
                "cmd-probe-media",
                "probe_media",
                sha256_fixture("media probe argv"),
            )
            probe_process = ProcessIdentity("boot-a", 101, 201, 101)
            catalog.record_blocked_process("cmd-probe-media", fence, probe_process)
            confirm_command_release(catalog, "cmd-probe-media", fence)
            catalog.acknowledge_command_quiescence(
                "cmd-probe-media",
                owner,
                CommandExitEvidence(
                    "cmd-probe-media",
                    probe_process,
                    "completed",
                    command_exit_after_release(catalog, "cmd-probe-media"),
                ),
            )
            catalog.bind_observed_media_identity(fence, first)
            catalog.bind_observed_media_identity(fence, first)

            with self.assertRaises(MediaTargetMismatch):
                catalog.bind_observed_media_identity(
                    fence, sha256_fixture("synthetic-observed-media-b")
                )

            self.assertEqual(
                "recovery_required", catalog.get_operation("op-1")["state"]
            )
            binding = catalog.connection.execute(
                """
                    SELECT observed_media_identity_sha256
                    FROM operation_media_identity_bindings WHERE operation_id='op-1'
                    """
            ).fetchone()[0]
            self.assertEqual(first, binding)
            with self.assertRaises(StaleOperationFence):
                catalog.authorize_hardware_command_release(
                    "cmd-identify", fence, sha256_fixture("release:cmd-identify")
                )

    def test_clean_probe_for_a_different_target_is_rejected_without_leaking_values(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database_path = Path(temporary) / "catalog.db"
            expected = synthetic_target()
            process = ProcessIdentity("boot-a", 100, 200, 100)
            with Catalog(database_path) as catalog:
                catalog.initialize()
                owner = catalog.claim_daemon_owner("daemon-1")
                admission = catalog.admit_operation(
                    operation_candidate("op-1", "key-1"),
                    owner,
                    admission_open=True,
                    hardware_target=expected,
                )
                fence = OperationFence(admission.record.id, owner.generation)
                catalog.reserve_hardware_command(
                    fence, "cmd-1", "unmount", sha256_fixture("argv")
                )
                catalog.record_blocked_process("cmd-1", fence, process)
                confirm_command_release(catalog, "cmd-1", fence)
                catalog.finish_operation(fence, "recovery_required")
                current = catalog.claim_daemon_owner("daemon-2")
                catalog.acknowledge_command_quiescence(
                    "cmd-1",
                    current,
                    CommandExitEvidence(
                        "cmd-1",
                        process,
                        "completed",
                        command_exit_after_release(catalog, "cmd-1"),
                    ),
                )
                command_receipt = catalog.create_command_quiescence_receipt(
                    "op-1", current
                )
                with self.assertRaises(PhysicalTargetMismatch) as caught:
                    catalog.create_physical_reconciliation_receipt(
                        "op-1",
                        current,
                        command_receipt.id,
                        VerifiedPhysicalQuiescence(
                            target=synthetic_target(mount="mount-b"),
                            observed_media_identity_sha256=None,
                            mounted=False,
                            media_loaded=False,
                            drive_busy=False,
                            related_processes=(),
                        ),
                    )
                self.assertEqual("mount_path_sha256", caught.exception.dimension)
                rendered = str(caught.exception) + json.dumps(
                    catalog.latest_audit_payload()
                )
                self.assertNotIn("/synthetic/", rendered)
                self.assertNotIn("mount-a", rendered)
                self.assertEqual(0, catalog.physical_receipt_count("op-1"))

    def test_nonquiescent_command_blocks_admission_after_operation_is_terminal(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            owner = catalog.claim_daemon_owner("daemon-1")
            admission = catalog.admit_operation(
                operation_candidate("old", "old-key"),
                owner,
                admission_open=True,
                hardware_target=synthetic_target(),
            )
            fence = OperationFence(admission.record.id, owner.generation)
            with self.assertRaises(ValidationError):
                catalog.reserve_hardware_command(
                    fence, "cmd-shell", "arbitrary-shell", sha256_fixture("argv")
                )
            catalog.reserve_hardware_command(
                fence, "cmd-format", "format", sha256_fixture("argv")
            )
            process = ProcessIdentity("boot-a", 100, 200, 100)
            catalog.record_blocked_process("cmd-format", fence, process)
            confirm_command_release(catalog, "cmd-format", fence)
            catalog.finish_operation(fence, "cancelled")
            current = catalog.claim_daemon_owner("daemon-2")

            with self.assertRaises(CommandQuiescenceRequired):
                catalog.admit_operation(
                    operation_candidate("new", "new-key"),
                    current,
                    admission_open=True,
                )

    def test_imported_job_policy_freeze_records_hash_receipt_and_null_activation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = build_frozen_job_fixture(
                root / "catalog.db", schema_version=13
            )
            prepare_and_initialize(database_path)
            with Catalog(database_path) as catalog:
                report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                self.assertTrue(report.accepted, report.error_codes)
                assignment = report.assignment_sha256
                bundle = sha256_fixture("synthetic-bundle")
                cassette_plan = canonical_cassette_plan_sha256(
                    catalog.connection,
                    "JOB-MIGRATION",
                    assignment_sha256=assignment,
                )

                catalog.freeze_imported_job(
                    "JOB-MIGRATION",
                    assignment,
                    cassette_plan,
                    bundle,
                )

                policy = catalog.get_import_policy("JOB-MIGRATION")
                self.assertEqual("frozen-allocation", policy.policy_kind)
                self.assertEqual("pre_cutover", policy.authority_state)
                self.assertEqual("resumable", policy.windows_authority)
                self.assertTrue(policy.rollback_allowed)
                self.assertEqual(cassette_plan, policy.cassette_plan_sha256)
                self.assertIsNone(policy.activated_by_operation)
                self.assertIsNone(policy.activated_at)
                receipt = catalog.connection.execute(
                    """
                    SELECT bundle_sha256, assignment_sha256, cassette_plan_sha256,
                           completed_evidence_sha256
                    FROM migration_receipts WHERE job_id='JOB-MIGRATION'
                    """
                ).fetchone()
                self.assertEqual(
                    (
                        bundle,
                        assignment,
                        cassette_plan,
                        policy.completed_evidence_sha256,
                    ),
                    tuple(receipt),
                )

    def test_schema_twenty_one_repairs_corrupt_pre_cutover_format_cassettes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = build_frozen_job_fixture(
                root / "catalog.db", schema_version=21
            )
            with Catalog(database_path) as catalog:
                report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                self.assertTrue(report.accepted, report.error_codes)
                completed_before = tuple(
                    catalog.connection.execute(
                        "SELECT sequence, status, reuse_registered, started_at, "
                        "completed_at FROM automatic_cassettes "
                        "WHERE job_id='JOB-MIGRATION' AND sequence<=3 "
                        "ORDER BY sequence"
                    )
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='waiting_media', "
                    "reuse_registered=1, started_at='2026-08-25T12:00:00+00:00' "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET reuse_registered=1 "
                    "WHERE job_id='JOB-MIGRATION' AND sequence BETWEEN 5 AND 20"
                )
                catalog.connection.commit()
                stale_plan = canonical_cassette_plan_sha256(
                    catalog.connection,
                    "JOB-MIGRATION",
                    assignment_sha256=report.assignment_sha256,
                )
                catalog.freeze_imported_job(
                    "JOB-MIGRATION",
                    report.assignment_sha256,
                    stale_plan,
                    sha256_fixture("synthetic-bundle"),
                )
                with self.assertRaises(FrozenJobStateInvalid):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

            prepare_and_initialize(database_path)

            with Catalog(database_path) as catalog:
                self.assertEqual(
                    str(SCHEMA_VERSION), read_schema_version(database_path)
                )
                self.assertEqual(
                    completed_before,
                    tuple(
                        catalog.connection.execute(
                            "SELECT sequence, status, reuse_registered, started_at, "
                            "completed_at FROM automatic_cassettes "
                            "WHERE job_id='JOB-MIGRATION' AND sequence<=3 "
                            "ORDER BY sequence"
                        )
                    ),
                )
                normalized = tuple(
                    catalog.connection.execute(
                        "SELECT sequence, status, operation, reuse_registered, started_at "
                        "FROM automatic_cassettes WHERE job_id='JOB-MIGRATION' "
                        "AND sequence>=4 ORDER BY sequence"
                    )
                )
                self.assertEqual(
                    [(4, "waiting_media", "format", 0, None)]
                    + [
                        (sequence, "pending", "format", 0, None)
                        for sequence in range(5, 21)
                    ],
                    [tuple(row) for row in normalized],
                )
                canonical_plan = canonical_cassette_plan_sha256(
                    catalog.connection,
                    "JOB-MIGRATION",
                    assignment_sha256=report.assignment_sha256,
                )
                self.assertNotEqual(stale_plan, canonical_plan)
                self.assertEqual(
                    canonical_plan,
                    catalog.connection.execute(
                        "SELECT cassette_plan_sha256 FROM imported_job_policies "
                        "WHERE job_id='JOB-MIGRATION'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    canonical_plan,
                    catalog.connection.execute(
                        "SELECT cassette_plan_sha256 FROM migration_receipts "
                        "WHERE job_id='JOB-MIGRATION'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    4,
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION").cassettes[3].sequence,
                )

    def test_schema_twenty_one_does_not_bless_tampered_cassette_plan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database_path = build_frozen_job_fixture(
                root / "catalog.db", schema_version=21
            )
            with Catalog(database_path) as catalog:
                report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                self.assertTrue(report.accepted, report.error_codes)
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='waiting_media', "
                    "reuse_registered=1, started_at='2026-08-25T12:00:00+00:00' "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET reuse_registered=1 "
                    "WHERE job_id='JOB-MIGRATION' AND sequence BETWEEN 5 AND 20"
                )
                catalog.connection.commit()
                catalog.freeze_imported_job(
                    "JOB-MIGRATION",
                    report.assignment_sha256,
                    canonical_cassette_plan_sha256(
                        catalog.connection,
                        "JOB-MIGRATION",
                        assignment_sha256=report.assignment_sha256,
                    ),
                    sha256_fixture("synthetic-bundle"),
                )
                catalog.connection.execute(
                    "DROP TRIGGER freeze_imported_cassette_identity_update"
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET physical_label='HACK04' "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                )
                catalog._install_imported_job_freeze_triggers(catalog.connection)
                catalog.connection.execute(
                    "UPDATE imported_job_policies SET cassette_plan_sha256=? "
                    "WHERE job_id='JOB-MIGRATION'",
                    ("f" * 64,),
                )
                catalog.connection.execute(
                    "UPDATE migration_receipts SET cassette_plan_sha256=? "
                    "WHERE job_id='JOB-MIGRATION'",
                    ("f" * 64,),
                )
                catalog.connection.commit()

            prepare_and_initialize(database_path)

            with Catalog(database_path) as catalog:
                row = catalog.connection.execute(
                    "SELECT physical_label, reuse_registered, started_at "
                    "FROM automatic_cassettes WHERE job_id='JOB-MIGRATION' "
                    "AND sequence=4"
                ).fetchone()
                expected_cassette = ("HACK04", 1, "2026-08-25T12:00:00+00:00")
                self.assertEqual(expected_cassette, tuple(row))
                self.assertEqual(
                    "f" * 64,
                    catalog.connection.execute(
                        "SELECT cassette_plan_sha256 FROM imported_job_policies "
                        "WHERE job_id='JOB-MIGRATION'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    "f" * 64,
                    catalog.connection.execute(
                        "SELECT cassette_plan_sha256 FROM migration_receipts "
                        "WHERE job_id='JOB-MIGRATION'"
                    ).fetchone()[0],
                )
                with self.assertRaises(FrozenJobAssignmentChanged):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_registered_tape_reuse_requires_override_and_is_purged_only_on_format_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "OLD",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 1, 10)],
                    force_format=True,
                )
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("OLD-BLOCK", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1",
                    "OLD-BLOCK",
                    "AB1234",
                    "old.bin",
                    "old/files/old.bin",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.update_automatic_cassette(
                    "OLD",
                    1,
                    "completed",
                    tape_id="AB1234",
                    block_id="OLD-BLOCK",
                    copied_files=1,
                    copied_bytes=10,
                )
                catalog.update_automatic_job("OLD", "completed", current_sequence=1)

                with self.assertRaisesRegex(CatalogError, "gia registrata"):
                    catalog.create_automatic_job(
                        "SAFE",
                        "LIB1",
                        "TAPE0",
                        "L:\\",
                        [("AB1234", "AB1234", 1, 10)],
                        force_format=True,
                    )

                catalog.create_automatic_job(
                    "REUSE",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 1, 10)],
                    force_format=True,
                    allow_registered_reuse=True,
                )
                queued = catalog.list_automatic_cassettes("REUSE")[0]
                self.assertEqual(1, queued["reuse_registered"])
                self.assertIsNotNone(catalog.get_tape("AB1234"))
                self.assertIn("old.bin", catalog.latest_versions("LIB1"))

                result = catalog.commit_registered_tape_reformat("REUSE", 1)

                self.assertEqual(
                    {"tapes": 1, "blocks": 1, "files": 1, "jobs": 1}, result
                )
                with self.assertRaises(CatalogError):
                    catalog.get_tape("AB1234")
                self.assertEqual({}, catalog.latest_versions("LIB1"))
                self.assertEqual("failed", catalog.get_automatic_job("OLD")["status"])
                old_cassette = catalog.list_automatic_cassettes("OLD")[0]
                self.assertEqual("failed", old_cassette["status"])

    def test_automatic_cassette_manifest_persists_exact_file_assignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 2, 30)],
                    force_format=True,
                )

                catalog.replace_automatic_cassette_manifest(
                    "JOB1",
                    1,
                    [
                        ("LIB1", "folder/a.mxf", 10, 101),
                        ("LIB1", "folder/b.mxf", 20, 202),
                    ],
                )

                self.assertEqual(
                    [
                        ("LIB1", "folder/a.mxf", 10, 101),
                        ("LIB1", "folder/b.mxf", 20, 202),
                    ],
                    [
                        (
                            row["library_id"],
                            row["relative_path"],
                            row["size"],
                            row["mtime_ns"],
                        )
                        for row in catalog.list_automatic_cassette_manifest("JOB1", 1)
                    ],
                )

    def test_schema_nine_cassette_queue_is_migrated_to_safe_format_operations(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO metadata(key, value) VALUES('schema_version', '9');
                    CREATE TABLE automatic_cassettes (
                        job_id TEXT NOT NULL,
                        sequence INTEGER NOT NULL,
                        physical_label TEXT NOT NULL COLLATE NOCASE,
                        tape_serial TEXT NOT NULL,
                        status TEXT NOT NULL,
                        tape_id TEXT,
                        block_id TEXT,
                        planned_files INTEGER NOT NULL,
                        planned_bytes INTEGER NOT NULL,
                        copied_files INTEGER NOT NULL DEFAULT 0,
                        copied_bytes INTEGER NOT NULL DEFAULT 0,
                        started_at TEXT,
                        completed_at TEXT,
                        error TEXT,
                        PRIMARY KEY(job_id, sequence),
                        UNIQUE(job_id, physical_label),
                        UNIQUE(job_id, tape_serial)
                    );
                    """
                )

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                columns = {
                    row["name"]: row
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(automatic_cassettes)"
                    )
                }
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertEqual("'format'", columns["operation"]["dflt_value"])
                self.assertEqual("0", columns["reuse_registered"]["dflt_value"])

    def test_automatic_job_persists_media_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234L5", "AB1234", 1, 10)],
                    force_format=True,
                    media_key="LTO-5",
                )

                self.assertEqual(
                    "LTO-5", catalog.get_automatic_job("JOB1")["media_key"]
                )

    def test_automatic_job_can_be_renamed_without_changing_identity_or_queue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 1, 10)],
                    force_format=True,
                )

                catalog.rename_automatic_job("JOB1", "  Archivio produzioni  ")

                job = catalog.get_automatic_job("JOB1")
                queue = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("JOB1", job["id"])
                self.assertEqual("Archivio produzioni", job["display_name"])
                self.assertEqual("AB1234", queue[0]["physical_label"])
                event = catalog.connection.execute(
                    "SELECT payload_json FROM events WHERE action='automatic_job.rename'"
                ).fetchone()
                self.assertIsNotNone(event)

                with self.assertRaisesRegex(ValidationError, "nome"):
                    catalog.rename_automatic_job("JOB1", "   ")

    def test_automatic_job_deletion_removes_only_scheduler_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.add_library("LIB2", "Other library", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("DONE01", "DONE01", 1, 10), ("LIVE02", "LIVE02", 1, 8)],
                    force_format=True,
                )
                catalog.create_automatic_job(
                    "JOB2",
                    "LIB2",
                    "TAPE1",
                    "M:\\",
                    [("KEEP03", "KEEP03", 0, 0)],
                    force_format=True,
                )
                for tape_id in ("DONE01", "LIVE02"):
                    catalog.register_tape(
                        tape_id,
                        tape_id,
                        tape_id,
                        "LTFS",
                        "L:\\",
                        cassette_number=tape_id,
                    )
                catalog.create_block("BLOCK-DONE", "LIB1", "DONE01", "done", 1, 10)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-DONE",
                    "DONE01",
                    "done.bin",
                    "done/done.bin",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-DONE")
                catalog.create_block("BLOCK-LIVE", "LIB1", "LIVE02", "live", 1, 8)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-LIVE",
                    "LIVE02",
                    "partial.bin",
                    "live/partial.bin",
                    8,
                    2,
                    "b" * 64,
                )
                catalog.update_automatic_cassette(
                    "JOB1",
                    1,
                    "completed",
                    tape_id="DONE01",
                    block_id="BLOCK-DONE",
                    copied_files=1,
                    copied_bytes=10,
                )
                catalog.update_automatic_cassette(
                    "JOB1",
                    2,
                    "writing",
                    tape_id="LIVE02",
                    block_id="BLOCK-LIVE",
                    copied_files=1,
                    copied_bytes=8,
                )

                result = catalog.delete_automatic_job("JOB1")

                self.assertEqual(2, result["deleted_cassettes"])
                self.assertEqual(1, result["failed_incomplete_blocks"])
                with self.assertRaisesRegex(CatalogError, "non trovato"):
                    catalog.get_automatic_job("JOB1")
                self.assertEqual("JOB2", catalog.get_automatic_job("JOB2")["id"])
                self.assertEqual([], catalog.list_automatic_cassettes("JOB1"))
                self.assertEqual([], catalog.list_automatic_job_libraries("JOB1"))
                self.assertEqual("LIB1", catalog.get_library("LIB1")["id"])
                self.assertEqual(
                    ["DONE01", "LIVE02"],
                    sorted(row["id"] for row in catalog.list_tapes()),
                )
                blocks = {
                    row["id"]: row
                    for row in catalog.list_blocks(include_forgotten=True)
                }
                self.assertEqual("completed", blocks["BLOCK-DONE"]["status"])
                self.assertEqual("failed", blocks["BLOCK-LIVE"]["status"])
                self.assertEqual(
                    "Job eliminato dall'operatore prima del completamento",
                    blocks["BLOCK-LIVE"]["error"],
                )
                self.assertEqual(["done.bin"], list(catalog.latest_versions("LIB1")))
                event = catalog.connection.execute(
                    "SELECT payload_json FROM events WHERE action='automatic_job.delete'"
                ).fetchone()
                self.assertIsNotNone(event)

    def test_schema_seven_jobs_are_migrated_with_their_id_as_initial_name(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=7)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.connection.execute(
                    "INSERT INTO automatic_jobs("
                    "id,library_id,device_name,mount_path,status,current_sequence,"
                    "total_cassettes,destructive_confirmed_at,force_format,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        "JOB-LEGACY",
                        "LIB1",
                        "TAPE0",
                        "L:\\",
                        "planned",
                        0,
                        1,
                        "2026-08-22T00:00:00+00:00",
                        1,
                        "2026-08-22T00:00:01+00:00",
                    ),
                )
                catalog.connection.commit()

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                job = catalog.get_automatic_job("JOB-LEGACY")
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertEqual("LTO-6", job["media_key"])
                self.assertEqual("JOB-LEGACY", job["display_name"])

    def test_reset_automatic_cassette_discards_only_its_attempt_and_pauses_job(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            source = Path(temporary) / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("DONE01", "DONE01", 1, 10), ("LIVE02", "LIVE02", 2, 20)],
                    force_format=True,
                )
                for tape_id in ("DONE01", "LIVE02"):
                    catalog.register_tape(
                        tape_id,
                        tape_id,
                        tape_id,
                        "LTFS",
                        "L:\\",
                        cassette_number=tape_id,
                    )
                catalog.create_block("BLOCK-DONE", "LIB1", "DONE01", "done", 1, 10)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-DONE",
                    "DONE01",
                    "done.bin",
                    "done/done.bin",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-DONE")
                catalog.update_automatic_cassette(
                    "JOB1",
                    1,
                    "completed",
                    tape_id="DONE01",
                    block_id="BLOCK-DONE",
                    copied_files=1,
                    copied_bytes=10,
                )
                catalog.create_block("BLOCK-LIVE", "LIB1", "LIVE02", "live", 2, 20)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-LIVE",
                    "LIVE02",
                    "partial.bin",
                    "live/partial.bin",
                    8,
                    2,
                    "b" * 64,
                )
                catalog.update_automatic_job("JOB1", "writing", current_sequence=2)
                catalog.update_automatic_cassette(
                    "JOB1",
                    2,
                    "writing",
                    tape_id="LIVE02",
                    block_id="BLOCK-LIVE",
                    copied_files=1,
                    copied_bytes=8,
                )

                result = catalog.reset_automatic_cassette(
                    "JOB1", 2, "Interrotta dall'operatore"
                )

                self.assertEqual({"blocks": 1, "files": 1, "tapes": 1}, result)
                self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
                cassettes = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("completed", cassettes[0]["status"])
                self.assertEqual("pending", cassettes[1]["status"])
                self.assertIsNone(cassettes[1]["tape_id"])
                self.assertEqual(0, cassettes[1]["copied_bytes"])
                self.assertEqual(
                    ["BLOCK-DONE"], [row["id"] for row in catalog.list_blocks()]
                )
                self.assertEqual(
                    ["DONE01"], [row["id"] for row in catalog.list_tapes()]
                )
                self.assertEqual(["done.bin"], list(catalog.latest_versions("LIB1")))

    def test_distinct_ltfs_labels_can_share_the_storeopen_win32_serial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE01", "00007AF3", "TAPE01", "LTFS", "L:\\")
                catalog.register_tape("TAPE02", "00007AF3", "TAPE02", "LTFS", "L:\\")

                self.assertEqual(
                    [("TAPE01", "00007AF3"), ("TAPE02", "00007AF3")],
                    [(row["id"], row["volume_serial"]) for row in catalog.list_tapes()],
                )
                with self.assertRaisesRegex(CatalogError, "(?i)etichetta LTFS TAPE02"):
                    catalog.register_tape(
                        "TAPE03", "DIFFERENT", "tape02", "LTFS", "M:\\"
                    )

                indexes = {
                    row[1]
                    for row in catalog.connection.execute("PRAGMA index_list(tapes)")
                }
                self.assertNotIn("ux_tapes_volume_serial", indexes)
                self.assertIn("ux_tapes_ltfs_volume_label", indexes)

    def test_schema_twelve_migrates_from_win32_serial_identity_to_ltfs_label_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO metadata(key, value) VALUES('schema_version', '12');
                    CREATE TABLE tapes (
                        id TEXT PRIMARY KEY COLLATE NOCASE,
                        cassette_number TEXT NOT NULL,
                        volume_serial TEXT NOT NULL,
                        volume_label TEXT NOT NULL,
                        filesystem TEXT NOT NULL,
                        mount_hint TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_seen_at TEXT NOT NULL
                    );
                    INSERT INTO tapes VALUES(
                        'TAPE01', 'TAPE01', '00007AF3', 'TAPE01', 'LTFS', 'L:\\',
                        'active', '2026-08-20T10:55:56+00:00', '2026-08-20T17:21:41+00:00'
                    );
                    CREATE UNIQUE INDEX ux_tapes_volume_serial
                        ON tapes(volume_serial COLLATE NOCASE);
                    """
                )

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                catalog.register_tape(
                    "TAPE02",
                    "00007AF3",
                    "TAPE02",
                    "LTFS",
                    "L:\\",
                    cassette_number="TAPE02",
                )
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                indexes = {
                    row[1]
                    for row in catalog.connection.execute("PRAGMA index_list(tapes)")
                }

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertNotIn("ux_tapes_volume_serial", indexes)
                self.assertIn("ux_tapes_ltfs_volume_label", indexes)

    def test_reregistering_same_ltfs_label_refreshes_diagnostic_win32_serial(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.register_tape("TAPE01", "00007AF3", "TAPE01", "LTFS", "L:\\")

            catalog.register_tape("TAPE01", "A1B2C3D4", "tape01", "LTFS", "M:\\")

            tape = catalog.get_tape("TAPE01")
            self.assertEqual("A1B2C3D4", tape["volume_serial"])
            self.assertEqual("M:\\", tape["mount_hint"])

    def test_schema_one_is_migrated_and_existing_tape_keeps_a_cassette_number(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    """
                    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO metadata(key, value) VALUES('schema_version', '1');
                    CREATE TABLE tapes (
                        id TEXT PRIMARY KEY COLLATE NOCASE,
                        volume_serial TEXT NOT NULL,
                        volume_label TEXT NOT NULL,
                        filesystem TEXT NOT NULL,
                        mount_hint TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        last_seen_at TEXT NOT NULL
                    );
                    INSERT INTO tapes VALUES(
                        'TAPE_OLD', 'ABC123', 'Vecchio nastro', 'LTFS', 'L:\\',
                        'active', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00'
                    );
                    """
                )

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                tape = catalog.get_tape("TAPE_OLD")
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertEqual("TAPE_OLD", tape["cassette_number"])

    def test_file_search_locates_current_and_historical_cassettes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source))
                catalog.register_tape(
                    "TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0042"
                )
                catalog.register_tape(
                    "TAPE2", "SERIAL2", "Tape 2", "LTFS", "L:\\", "CASS-0043"
                )
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 10
                )
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "film/video.mxf",
                    ".lto-backup/block1/video.mxf",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("block1")
                catalog.create_block(
                    "block2", "LIB1", "TAPE2", ".lto-backup/block2", 1, 20
                )
                catalog.record_file_version(
                    "LIB1",
                    "block2",
                    "TAPE2",
                    "film/video.mxf",
                    ".lto-backup/block2/video.mxf",
                    20,
                    2,
                    "b" * 64,
                )
                catalog.complete_block("block2")

                current = catalog.search_files("video")
                history = catalog.search_files("video", include_history=True)

                self.assertEqual(1, len(current))
                self.assertEqual("CASS-0043", current[0]["cassette_number"])
                self.assertEqual(
                    ".lto-backup/block2/video.mxf", current[0]["tape_relative_path"]
                )
                self.assertEqual(
                    ["CASS-0043", "CASS-0042"],
                    [row["cassette_number"] for row in history],
                )

    def test_failed_or_uncommitted_blocks_are_never_current_or_restorable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source))
                catalog.register_tape(
                    "TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0042"
                )
                for block_id, relative_path in (
                    ("copying-block", "copying.bin"),
                    ("failed-block", "failed.bin"),
                ):
                    catalog.create_block(
                        block_id, "LIB1", "TAPE1", f".lto-backup/{block_id}", 1, 10
                    )
                    catalog.record_file_version(
                        "LIB1",
                        block_id,
                        "TAPE1",
                        relative_path,
                        f".lto-backup/{block_id}/{relative_path}",
                        10,
                        1,
                        "a" * 64,
                    )
                catalog.fail_block("failed-block", "errore simulato")

                self.assertEqual({}, catalog.latest_versions("LIB1"))
                self.assertEqual([], catalog.restore_plan("LIB1"))
                self.assertEqual([], catalog.library_tape_distribution("LIB1"))
                self.assertEqual([], catalog.restore_files_for_tape("LIB1", "TAPE1"))
                self.assertEqual([], catalog.browse_backup_children("LIB1"))
                self.assertEqual([], catalog.search_files(".bin"))
                self.assertEqual([], catalog.search_files(".bin", include_history=True))

                catalog.complete_block("copying-block")

                self.assertEqual(["copying.bin"], list(catalog.latest_versions("LIB1")))
                self.assertEqual(1, len(catalog.restore_plan("LIB1")))
                self.assertEqual(1, len(catalog.search_files("copying.bin")))
                self.assertEqual(
                    [], catalog.search_files("failed.bin", include_history=True)
                )

                catalog.fail_block("copying-block", "errore tardivo ignorato")
                self.assertEqual(["copying.bin"], list(catalog.latest_versions("LIB1")))

    def test_block_forgetting_is_logical_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source))
                catalog.register_tape("TAPE1", "ABC123", "Tape 1", "LTFS", "X:\\")
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 10
                )
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "file.bin",
                    ".lto-backup/block1/file.bin",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("block1")

                catalog.forget_block("block1")
                self.assertEqual([], catalog.list_blocks())
                self.assertEqual(1, len(catalog.list_blocks(include_forgotten=True)))
                self.assertEqual({}, catalog.latest_versions("LIB1"))

                block = catalog.list_blocks(include_forgotten=True)[0]
                self.assertEqual(0, block["visible"])
                self.assertEqual("TAPE1", block["tape_id"])

    def test_library_retirement_preserves_catalog_data_and_job_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_one = root / "source-one"
            source_two = root / "source-two"
            source_one.mkdir()
            source_two.mkdir()
            physical_one = source_one / "one.bin"
            physical_two = source_two / "two.bin"
            physical_one.write_bytes(b"one")
            physical_two.write_bytes(b"two")
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source_one))
                catalog.add_library("LIB2", "Library 2", str(source_two))
                catalog.register_tape("TAPE1", "ABC123", "Tape 1", "LTFS", "X:\\")
                for library_id, block_id, path in (
                    ("LIB1", "block1", "one.bin"),
                    ("LIB2", "block2", "two.bin"),
                ):
                    catalog.create_block(
                        block_id, library_id, "TAPE1", f".lto-backup/{block_id}", 1, 3
                    )
                    catalog.record_file_version(
                        library_id,
                        block_id,
                        "TAPE1",
                        path,
                        f".lto-backup/{block_id}/files/{path}",
                        3,
                        1,
                        "a" * 64,
                    )
                    catalog.complete_block(block_id)
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 2, 6)],
                    library_ids=["LIB1", "LIB2"],
                )
                catalog.update_automatic_job("JOB1", "completed")

                result = catalog.retire_named_library("LIB1")

                self.assertEqual(
                    ["LIB1", "LIB2"],
                    [row["id"] for row in catalog.list_libraries(True)],
                )
                self.assertEqual(
                    ["block1"],
                    [
                        row["id"]
                        for row in catalog.list_blocks("LIB1", include_forgotten=True)
                    ],
                )
                self.assertEqual(1, len(catalog.latest_versions("LIB1")))
                self.assertEqual(
                    ["block2"], [row["id"] for row in catalog.list_blocks("LIB2")]
                )
                self.assertEqual(["TAPE1"], [row["id"] for row in catalog.list_tapes()])
                job = catalog.get_automatic_job("JOB1")
                self.assertEqual("LIB1", job["library_id"])
                self.assertEqual(
                    ["LIB1", "LIB2"],
                    [
                        row["library_id"]
                        for row in catalog.list_automatic_job_libraries("JOB1")
                    ],
                )
                self.assertTrue(physical_one.is_file())
                self.assertTrue(physical_two.is_file())
                self.assertEqual("retired", result["status"])
                self.assertFalse(result["enabled"])

    def test_library_retirement_refuses_an_unfinished_automatic_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 1, 3)],
                )

                with self.assertRaisesRegex(CatalogError, "library_in_use"):
                    catalog.retire_named_library("LIB1")

                self.assertEqual("LIB1", catalog.get_library("LIB1")["id"])

    def test_catalog_integrity_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB_A", "A", str(source))
                self.assertEqual(
                    "ok",
                    catalog.connection.execute("PRAGMA integrity_check").fetchone()[0],
                )
                exported = catalog.export()
                self.assertEqual(SCHEMA_VERSION, exported["schema_version"])
                self.assertEqual("LIB_A", exported["libraries"][0]["id"])
                self.assertIn("events", exported)
                self.assertNotIn("events", catalog.export(include_events=False))

    def test_catalog_backup_is_an_atomic_consistent_sqlite_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB_A", "A", str(source))
                backup = catalog.backup_to(root / "backup" / "catalog-latest.db")

            with Catalog(backup) as copied:
                copied.initialize()
                self.assertEqual(
                    "ok",
                    copied.connection.execute("PRAGMA integrity_check").fetchone()[0],
                )
                self.assertEqual(
                    ["LIB_A"], [row["id"] for row in copied.list_libraries()]
                )

    def test_catalog_backup_does_not_require_mkdir_on_existing_parents(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            real_mkdir = os.mkdir
            real_open = os.open
            directory_flags = (
                os.O_RDONLY
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )

            def reject_mkdir_for_existing_parent(
                path, mode=0o777, *, dir_fd=None
            ):
                try:
                    descriptor = real_open(
                        path,
                        directory_flags,
                        dir_fd=dir_fd,
                    )
                except FileNotFoundError:
                    return real_mkdir(path, mode, dir_fd=dir_fd)
                else:
                    os.close(descriptor)
                    raise PermissionError("existing parent is not writable")

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with patch(
                    "ltobackup.catalog.os.mkdir",
                    side_effect=reject_mkdir_for_existing_parent,
                ):
                    backup = catalog.backup_to(destination)

            self.assertEqual(destination, backup)
            self.assertTrue(backup.is_file())

    def test_catalog_backup_uses_search_only_access_for_existing_ancestors(
        self,
    ) -> None:
        if not getattr(os, "O_PATH", 0):
            self.skipTest("O_PATH is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            real_open = os.open

            def deny_read_access_to_named_directories(
                path, flags, mode=0o777, *, dir_fd=None
            ):
                if (
                    flags & os.O_DIRECTORY
                    and not flags & os.O_PATH
                    and os.fspath(path) not in {"/", "."}
                ):
                    raise PermissionError("ancestor permits search but not read")
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with patch(
                    "ltobackup.catalog.os.open",
                    side_effect=deny_read_access_to_named_directories,
                ):
                    backup = catalog.backup_to(destination)

            self.assertEqual(destination, backup)
            self.assertTrue(backup.is_file())

    def test_catalog_backup_accepts_anchored_proc_self_directory_descriptor(
        self,
    ) -> None:
        if not Path("/proc/self/fd").is_dir():
            self.skipTest("Linux process descriptor paths are unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = os.open(
                root,
                getattr(os, "O_PATH", os.O_RDONLY)
                | os.O_DIRECTORY
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                destination = (
                    Path("/proc/self/fd")
                    / str(descriptor)
                    / "backup"
                    / "catalog.db"
                )
                with Catalog(root / "catalog.db") as catalog:
                    catalog.initialize()
                    backup = catalog.backup_to(destination)
            finally:
                os.close(descriptor)

            self.assertEqual(destination, backup)
            self.assertTrue((root / "backup" / "catalog.db").is_file())

    def test_catalog_backup_is_a_private_regular_file_with_permissive_umask(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                previous_umask = os.umask(0)
                try:
                    backup = catalog.backup_to(root / "backup" / "catalog.db")
                finally:
                    os.umask(previous_umask)

            details = backup.stat(follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual(0o600, stat.S_IMODE(details.st_mode))
            self.assertEqual(1, details.st_nlink)

    def test_catalog_backup_rejects_destination_symlink_without_touching_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            destination.parent.mkdir()
            victim = root / "victim.txt"
            victim.write_bytes(b"must remain unchanged")
            destination.symlink_to(victim)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with self.assertRaises(ValidationError):
                    catalog.backup_to(destination)

            self.assertTrue(destination.is_symlink())
            self.assertEqual(b"must remain unchanged", victim.read_bytes())

    def test_catalog_backup_rejects_destination_hardlink_without_touching_target(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            destination.parent.mkdir()
            victim = root / "victim.db"
            victim.write_bytes(b"must remain unchanged")
            os.link(victim, destination)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with self.assertRaises(ValidationError):
                    catalog.backup_to(destination)

            self.assertEqual(b"must remain unchanged", victim.read_bytes())
            self.assertEqual(victim.stat().st_ino, destination.stat().st_ino)

    def test_catalog_backup_does_not_follow_predictable_temporary_symlink(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            destination.parent.mkdir()
            victim = root / "victim.db"
            with closing(sqlite3.connect(victim)) as connection:
                connection.execute("CREATE TABLE sentinel(value TEXT NOT NULL)")
                connection.execute("INSERT INTO sentinel VALUES('untouched')")
                connection.commit()
            victim_before = victim.read_bytes()
            attacker_temporary = destination.with_name(destination.name + ".tmp")
            attacker_temporary.symlink_to(victim)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                backup = catalog.backup_to(destination)

            self.assertTrue(attacker_temporary.is_symlink())
            self.assertEqual(victim_before, victim.read_bytes())
            details = backup.stat(follow_symlinks=False)
            self.assertTrue(stat.S_ISREG(details.st_mode))
            self.assertEqual(0o600, stat.S_IMODE(details.st_mode))

    def test_catalog_backup_rejects_hostile_temporary_symlink_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            victim = root / "victim.db"
            victim.write_bytes(b"must remain unchanged")
            real_open = os.open
            hostile_paths: list[Path] = []

            def inject_symlink(path, flags, mode=0o777, *, dir_fd=None):
                if flags & os.O_CREAT:
                    os.symlink(victim, path, dir_fd=dir_fd)
                    hostile_paths.append(destination.parent / Path(path))
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with (
                    patch("ltobackup.catalog.os.open", side_effect=inject_symlink),
                    self.assertRaises(ValidationError),
                ):
                    catalog.backup_to(destination)

            self.assertEqual(b"must remain unchanged", victim.read_bytes())
            self.assertEqual(1, len(hostile_paths))
            self.assertTrue(hostile_paths[0].is_symlink())

    def test_catalog_backup_rejects_hostile_temporary_hardlink_collision(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            victim = root / "victim.db"
            victim.write_bytes(b"must remain unchanged")
            real_open = os.open
            hostile_paths: list[Path] = []

            def inject_hardlink(path, flags, mode=0o777, *, dir_fd=None):
                if flags & os.O_CREAT:
                    os.link(victim, path, dst_dir_fd=dir_fd)
                    hostile_paths.append(destination.parent / Path(path))
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with (
                    patch("ltobackup.catalog.os.open", side_effect=inject_hardlink),
                    self.assertRaises(ValidationError),
                ):
                    catalog.backup_to(destination)

            self.assertEqual(b"must remain unchanged", victim.read_bytes())
            self.assertEqual(1, len(hostile_paths))
            self.assertEqual(victim.stat().st_ino, hostile_paths[0].stat().st_ino)

    def test_catalog_backup_is_mode_0600_before_atomic_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            observed_modes: list[int] = []
            observed_link_counts: list[int] = []
            real_replace = os.replace

            def inspect_then_replace(source, target, *args, **kwargs):
                details = os.stat(
                    source,
                    dir_fd=kwargs.get("src_dir_fd"),
                    follow_symlinks=False,
                )
                observed_modes.append(stat.S_IMODE(details.st_mode))
                observed_link_counts.append(details.st_nlink)
                return real_replace(source, target, *args, **kwargs)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                previous_umask = os.umask(0)
                try:
                    with patch(
                        "ltobackup.catalog.os.replace",
                        side_effect=inspect_then_replace,
                    ):
                        catalog.backup_to(destination)
                finally:
                    os.umask(previous_umask)

            self.assertEqual([0o600], observed_modes)
            self.assertEqual([1], observed_link_counts)

    def test_catalog_backup_fsyncs_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            observed_types: list[int] = []
            real_fsync = os.fsync

            def inspect_then_fsync(descriptor):
                observed_types.append(stat.S_IFMT(os.fstat(descriptor).st_mode))
                return real_fsync(descriptor)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with patch(
                    "ltobackup.catalog.os.fsync", side_effect=inspect_then_fsync
                ):
                    catalog.backup_to(root / "backup" / "catalog.db")

            self.assertIn(stat.S_IFREG, observed_types)
            self.assertIn(stat.S_IFDIR, observed_types)

    def test_catalog_backup_failure_preserves_existing_destination_atomically(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup.db"
            destination.write_bytes(b"previous complete backup")
            catalog = Catalog(root / "catalog.db")
            catalog.initialize()
            catalog.close()

            with self.assertRaises(sqlite3.ProgrammingError):
                catalog.backup_to(destination)

            self.assertEqual(b"previous complete backup", destination.read_bytes())
            self.assertEqual([], list(root.glob(f".{destination.name}.*.tmp")))

    def test_catalog_backup_directory_fd_accepts_only_a_single_basename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup_root = root / "backups"
            backup_root.mkdir()
            directory_fd = os.open(
                backup_root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
            )
            try:
                with Catalog(root / "catalog.db") as catalog:
                    catalog.initialize()
                    for unsafe in (".", "..", "nested/catalog.db", "../catalog.db"):
                        with self.subTest(unsafe=unsafe), self.assertRaises(
                            ValidationError
                        ):
                            catalog.backup_to(Path(unsafe), directory_fd=directory_fd)
            finally:
                os.close(directory_fd)

            self.assertEqual([], list(backup_root.iterdir()))

    def test_catalog_backup_rejects_intermediate_parent_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            linked_parent = root / "linked"
            linked_parent.symlink_to(outside, target_is_directory=True)

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with self.assertRaises(ValidationError):
                    catalog.backup_to(linked_parent / "nested" / "catalog.db")

            self.assertEqual([], list(outside.iterdir()))

    def test_catalog_backup_cleans_owned_temporary_when_initial_hardening_fails(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "backup" / "catalog.db"
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                with (
                    patch(
                        "ltobackup.catalog.os.fchmod",
                        side_effect=OSError("injected initial hardening failure"),
                    ),
                    self.assertRaisesRegex(
                        OSError, "injected initial hardening failure"
                    ),
                ):
                    catalog.backup_to(destination)

            self.assertEqual([], list(destination.parent.iterdir()))

    def test_catalog_prunes_old_operational_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                with catalog.transaction() as db:
                    db.executemany(
                        "INSERT INTO events(occurred_at, action, payload_json) VALUES(?, ?, ?)",
                        (("2026-01-01", "test", "{}") for _ in range(50_100)),
                    )

            with Catalog(database) as catalog:
                catalog.initialize()
                count = catalog.connection.execute(
                    "SELECT COUNT(*) FROM events"
                ).fetchone()[0]
                self.assertLessEqual(count, 50_000)

    def test_automatic_job_and_ordered_cassette_queue_are_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.add_library("LIB2", "Library 2", str(source))
                catalog.create_automatic_job(
                    "JOB1",
                    "LIB1",
                    "TAPE0",
                    "L:\\",
                    [("AB1234", "AB1234", 4, 1000), ("CD5678L6", "CD5678", 2, 500)],
                    library_ids=["LIB1", "LIB2"],
                )
                catalog.update_automatic_job(
                    "JOB1", "waiting_media", current_sequence=1
                )
                catalog.update_automatic_cassette("JOB1", 1, "formatting")

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                self.assertEqual(
                    "waiting_media", catalog.get_automatic_job("JOB1")["status"]
                )
                queue = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual(
                    ["AB1234", "CD5678L6"], [row["physical_label"] for row in queue]
                )
                self.assertEqual("formatting_media", queue[0]["status"])
                self.assertEqual(
                    ["LIB1", "LIB2"],
                    [
                        row["library_id"]
                        for row in catalog.list_automatic_job_libraries("JOB1")
                    ],
                )
                with self.assertRaisesRegex(Exception, "gia il job non concluso"):
                    catalog.create_automatic_job(
                        "JOB2", "LIB1", "TAPE0", "L:\\", [("EF9012", "EF9012", 1, 10)]
                    )

    def test_multiple_independent_jobs_are_persistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            database = root / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source))
                catalog.add_library("LIB2", "Library 2", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.create_automatic_job(
                    "JOB2", "LIB2", "TAPE0", "L:\\", [("CD5678", "CD5678", 1, 20)]
                )

            with Catalog(database) as catalog:
                catalog.initialize()
                jobs = catalog.list_automatic_jobs()
                self.assertEqual({"JOB1", "JOB2"}, {job["id"] for job in jobs})
                self.assertEqual("planned", catalog.get_automatic_job("JOB1")["status"])
                self.assertEqual("planned", catalog.get_automatic_job("JOB2")["status"])

    def test_completed_automatic_job_can_append_ordered_cassettes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            database = root / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 2, 100)]
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)

                catalog.append_automatic_cassettes(
                    "JOB1",
                    [("CD5678L6", "CD5678", 3, 200), ("EF9012", "EF9012", 1, 50)],
                )

            with Catalog(database) as catalog:
                catalog.initialize()
                job = catalog.get_automatic_job("JOB1")
                queue = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("planned", job["status"])
                self.assertEqual(3, job["total_cassettes"])
                self.assertEqual(1, job["current_sequence"])
                self.assertIsNone(job["completed_at"])
                self.assertEqual([1, 2, 3], [row["sequence"] for row in queue])
                self.assertEqual(
                    ["AB1234", "CD5678L6", "EF9012"],
                    [row["physical_label"] for row in queue],
                )
                self.assertEqual(
                    ["completed", "pending", "pending"],
                    [row["status"] for row in queue],
                )

    def test_schema_three_job_is_migrated_to_one_linked_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            database = root / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=4)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.connection.execute(
                    "INSERT INTO automatic_jobs("
                    "id,library_id,device_name,mount_path,status,current_sequence,"
                    "total_cassettes,destructive_confirmed_at,created_at) "
                    "VALUES('JOB1','LIB1','TAPE0','L:\\','planned',0,1,?,?)",
                    ("2026-08-26T00:00:00+00:00",) * 2,
                )
                catalog.connection.execute(
                    "UPDATE metadata SET value='3' WHERE key='schema_version'"
                )
                catalog.connection.commit()

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                links = catalog.list_automatic_job_libraries("JOB1")

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertEqual(["LIB1"], [row["library_id"] for row in links])

    def test_offline_browser_lists_folders_and_files_with_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Film", str(source))
                catalog.register_tape(
                    "TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100"
                )
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 3, 60
                )
                metadata = {
                    "created_ns": 10,
                    "accessed_ns": 20,
                    "source_mode": 33206,
                    "windows_attributes": 32,
                    "owner_name": "STUDIO\\operator",
                    "owner_sid": "S-1-5-21-1",
                    "security_descriptor": "O:S-1-5-21-1G:BAD:(A;;FA;;;SY)",
                    "alternate_streams": [{"name": "Zone.Identifier", "size": 12}],
                    "metadata_state": "complete",
                    "metadata_error": None,
                }
                for path, size in (
                    ("film/masters/a.mxf", 10),
                    ("film/b.mov", 20),
                    ("root.txt", 30),
                ):
                    catalog.record_file_version(
                        "LIB1",
                        "block1",
                        "TAPE1",
                        path,
                        f".lto-backup/block1/files/{path}",
                        size,
                        30,
                        "a" * 64,
                        metadata=metadata,
                    )
                catalog.complete_block("block1")

                root_children = catalog.browse_backup_children("LIB1", "")
                film_children = catalog.browse_backup_children("LIB1", "film")
                master_children = catalog.browse_backup_children("LIB1", "film/masters")

                self.assertEqual(
                    [("directory", "film"), ("file", "root.txt")],
                    [(row["kind"], row["name"]) for row in root_children],
                )
                self.assertEqual(
                    [("directory", "masters"), ("file", "b.mov")],
                    [(row["kind"], row["name"]) for row in film_children],
                )
                file_row = master_children[0]
                self.assertEqual("file", file_row["kind"])
                self.assertEqual("CASS-0100", file_row["cassette_number"])
                self.assertEqual("STUDIO\\operator", file_row["owner_name"])
                self.assertEqual(
                    [{"name": "Zone.Identifier", "size": 12}],
                    file_row["alternate_streams"],
                )

    def test_schema_four_catalog_is_backfilled_for_offline_browsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\")
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 10
                )
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "old/folder/file.bin",
                    ".lto-backup/block1/files/old/folder/file.bin",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("block1")
                catalog.connection.execute(
                    "DROP TABLE ltfs_qualification_reconciliations"
                )
                catalog.connection.execute(
                    "UPDATE metadata SET value='4' WHERE key='schema_version'"
                )
                catalog.connection.commit()

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                row = catalog.latest_versions("LIB1")["old/folder/file.bin"]

                self.assertEqual(
                    str(SCHEMA_VERSION),
                    catalog.connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0],
                )
                self.assertEqual("old/folder", row["parent_path"])
                self.assertEqual("file.bin", row["file_name"])
                self.assertEqual("legacy", row["metadata_state"])

    def test_schema_five_adds_persistent_library_scan_totals(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    f"""
                    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO metadata(key, value) VALUES('schema_version', '5');
                    CREATE TABLE libraries (
                        id TEXT PRIMARY KEY COLLATE NOCASE,
                        name TEXT NOT NULL,
                        source_root TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        retired_at TEXT
                    );
                    INSERT INTO libraries(id, name, source_root, status, created_at)
                    VALUES('LIB1', 'Library', '{source.as_posix()}', 'active', '2026-01-01');
                    """
                )

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                library = catalog.get_library("LIB1")
                schema = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), schema)
                self.assertIsNone(library["last_scan_files"])
                self.assertIsNone(library["last_scan_bytes"])
                self.assertIsNone(library["last_scanned_at"])

    def test_schema_six_keeps_legacy_jobs_out_of_force_format_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with closing(sqlite3.connect(database)) as connection:
                connection.executescript(
                    f"""
                    CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO metadata(key, value) VALUES('schema_version', '6');
                    CREATE TABLE libraries (
                        id TEXT PRIMARY KEY COLLATE NOCASE,
                        name TEXT NOT NULL,
                        source_root TEXT NOT NULL,
                        status TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        retired_at TEXT,
                        last_scan_files INTEGER,
                        last_scan_bytes INTEGER,
                        last_scanned_at TEXT
                    );
                    INSERT INTO libraries(id, name, source_root, status, created_at)
                    VALUES('LIB1', 'Library', '{source.as_posix()}', 'active', '2026-01-01');
                    CREATE TABLE automatic_jobs (
                        id TEXT PRIMARY KEY COLLATE NOCASE,
                        library_id TEXT NOT NULL REFERENCES libraries(id),
                        device_name TEXT NOT NULL,
                        mount_path TEXT NOT NULL,
                        status TEXT NOT NULL,
                        current_sequence INTEGER NOT NULL DEFAULT 0,
                        total_cassettes INTEGER NOT NULL,
                        destructive_confirmed_at TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        started_at TEXT,
                        completed_at TEXT,
                        last_error TEXT
                    );
                    INSERT INTO automatic_jobs(
                        id, library_id, device_name, mount_path, status,
                        total_cassettes, destructive_confirmed_at, created_at
                    ) VALUES('LEGACY', 'LIB1', 'TAPE0', 'L:\\', 'planned', 1, '2026-01-01', '2026-01-01');
                    """
                )

            prepare_and_initialize(database)
            with Catalog(database) as catalog:
                job = catalog.get_automatic_job("LEGACY")
                schema = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), schema)
                self.assertEqual(0, job["force_format"])


class JobPlanDraftCatalogTests(unittest.TestCase):
    @staticmethod
    def _frozen_plan(source_root: str = "/source") -> dict:
        canonical_json = json.dumps(
            {
                "application_settings": {
                    "fingerprint_sha256": "a" * 64,
                    "revision": 0,
                },
                "base_job": None,
                "canonical_json_version": 1,
                "cassettes": [
                    {
                        "allocation_bytes": 12,
                        "capacity_utilization": 0.000001,
                        "items": [
                            {
                                "library_id": "LIB1",
                                "mtime_ns": 123,
                                "relative_path": "payload.bin",
                                "size": 7,
                            }
                        ],
                        "objects": 1,
                        "operation": "format",
                        "payload_bytes": 7,
                        "sequence": 1,
                    }
                ],
                "kind": "create",
                "libraries": [
                    {
                        "library_id": "LIB1",
                        "scan_fingerprint_sha256": "b" * 64,
                        "scan_revision": 0,
                        "source_root": source_root,
                    }
                ],
                "library_ids": ["LIB1"],
                "media_key": "LTO-6",
                "plan_schema_version": 1,
                "planner_version": "automatic-ltfs-v1",
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return {
            "canonical_json": canonical_json,
            "digest_sha256": hashlib.sha256(canonical_json.encode("utf-8")).hexdigest(),
            "canonical_json_version": 1,
            "plan_schema_version": 1,
            "planner_version": "automatic-ltfs-v1",
            "application_settings_revision": 0,
            "application_settings_fingerprint_sha256": "a" * 64,
            "libraries": [
                {
                    "sequence": 1,
                    "library_id": "LIB1",
                    "source_root": source_root,
                    "scan_revision": 0,
                    "scan_fingerprint_sha256": "b" * 64,
                }
            ],
            "cassettes": [
                {
                    "sequence": 1,
                    "objects": 1,
                    "payload_bytes": 7,
                    "allocation_bytes": 12,
                    "capacity_utilization": 0.000001,
                    "operation": "format",
                    "items": [
                        {
                            "item_sequence": 1,
                            "library_id": "LIB1",
                            "relative_path": "payload.bin",
                            "size": 7,
                            "mtime_ns": 123,
                        }
                    ],
                }
            ],
        }

    def _ready_current_create_plan(
        self,
        catalog: Catalog,
        source: Path,
        *,
        plan_id: str,
    ) -> dict:
        catalog.import_application_settings_once(Settings(), legacy_source_sha256=None)
        catalog.add_library("LIB1", "Library", str(source))
        catalog.create_job_plan_draft(
            plan_id=plan_id,
            kind="create",
            creator="admin",
            created_at="2026-08-25T10:00:00+00:00",
            expires_at="2026-08-26T10:00:00+00:00",
            media_key="LTO-6",
            library_ids=("LIB1",),
        )
        return catalog.complete_job_plan_draft(
            plan_id,
            self._frozen_plan(str(source)),
        )

    def test_plan_consumption_resolves_exact_and_long_registered_label_prefixes(
        self,
    ) -> None:
        cases = (
            ("EX1234", "CASSETTE-EXACT", "EX1234"),
            ("ID1234-LONG-TAPE-ID", "CASSETTE-ID-PREFIX", "ID1234"),
            ("TAPE-CASSETTE-PREFIX", "CN1234-LONG-CASSETTE", "CN1234"),
        )
        for tape_id, cassette_number, label in cases:
            with self.subTest(tape_id=tape_id, cassette_number=cassette_number):
                with tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    source = root / "source"
                    source.mkdir()
                    with Catalog(root / "catalog.db") as catalog:
                        catalog.initialize()
                        ready = self._ready_current_create_plan(
                            catalog, source, plan_id="PLAN-RESOLVE"
                        )
                        catalog.register_tape(
                            tape_id,
                            f"SERIAL-{label}",
                            f"VOLUME-{label}",
                            "LTFS",
                            "/tape",
                            cassette_number=cassette_number,
                        )

                        catalog.consume_job_plan(
                            plan_id="PLAN-RESOLVE",
                            digest_sha256=ready["digest_sha256"],
                            labels=(label,),
                            idempotency_key="consume-resolve",
                            request_sha256="c" * 64,
                            job_id="JOB-RESOLVE",
                            display_name="Resolver",
                            device_name="TAPE0",
                            mount_path="AUTO",
                            consumed_at="2026-08-25T11:00:00+00:00",
                            actor="admin",
                            allow_registered_reuse=True,
                            authorize_automatic_formatting=True,
                        )

                        cassette = catalog.list_automatic_cassettes("JOB-RESOLVE")[0]
                        self.assertEqual(1, cassette["reuse_registered"])
                        self.assertEqual("format", cassette["operation"])

    def test_plan_consumption_rejects_ambiguous_registered_label_without_residue(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                ready = self._ready_current_create_plan(
                    catalog, source, plan_id="PLAN-AMBIGUOUS"
                )
                catalog.register_tape(
                    "AB1234-LONG-ID",
                    "SERIAL-ONE",
                    "VOLUME-ONE",
                    "LTFS",
                    "/tape/one",
                    cassette_number="CASSETTE-ONE",
                )
                catalog.register_tape(
                    "OTHER-LONG-ID",
                    "SERIAL-TWO",
                    "VOLUME-TWO",
                    "LTFS",
                    "/tape/two",
                    cassette_number="AB1234-LONG-CASSETTE",
                )

                with self.assertRaisesRegex(
                    CatalogError, "plan_label_identity_ambiguous"
                ):
                    catalog.consume_job_plan(
                        plan_id="PLAN-AMBIGUOUS",
                        digest_sha256=ready["digest_sha256"],
                        labels=("AB1234",),
                        idempotency_key="consume-ambiguous",
                        request_sha256="d" * 64,
                        job_id="JOB-AMBIGUOUS",
                        display_name="Ambiguous",
                        device_name="TAPE0",
                        mount_path="AUTO",
                        consumed_at="2026-08-25T11:00:00+00:00",
                        actor="admin",
                        allow_registered_reuse=True,
                        authorize_automatic_formatting=True,
                    )

                self.assertEqual([], catalog.list_automatic_jobs())
                self.assertEqual("ready", catalog.get_job_plan("PLAN-AMBIGUOUS")["state"])

    def test_commit_reformat_uses_same_long_identity_and_missing_is_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                ready = self._ready_current_create_plan(
                    catalog, source, plan_id="PLAN-COMMIT"
                )
                catalog.create_automatic_job(
                    "OLD-LONG",
                    "LIB1",
                    "TAPE9",
                    "AUTO",
                    [("AB1234", "AB1234", 1, 10)],
                    force_format=True,
                )
                catalog.register_tape(
                    "AB1234-LONG-ID",
                    "SERIAL-OLD",
                    "VOLUME-OLD",
                    "LTFS",
                    "/tape/old",
                    cassette_number="AB1234-LONG-CASSETTE",
                )
                catalog.create_block(
                    "OLD-BLOCK", "LIB1", "AB1234-LONG-ID", "old", 1, 10
                )
                catalog.record_file_version(
                    "LIB1",
                    "OLD-BLOCK",
                    "AB1234-LONG-ID",
                    "old.bin",
                    "old/files/old.bin",
                    10,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.update_automatic_cassette(
                    "OLD-LONG",
                    1,
                    "completed",
                    tape_id="AB1234-LONG-ID",
                    block_id="OLD-BLOCK",
                    copied_files=1,
                    copied_bytes=10,
                )
                catalog.update_automatic_job(
                    "OLD-LONG", "completed", current_sequence=1
                )
                catalog.consume_job_plan(
                    plan_id="PLAN-COMMIT",
                    digest_sha256=ready["digest_sha256"],
                    labels=("AB1234",),
                    idempotency_key="consume-commit",
                    request_sha256="e" * 64,
                    job_id="JOB-COMMIT",
                    display_name="Commit",
                    device_name="TAPE0",
                    mount_path="AUTO",
                    consumed_at="2026-08-25T11:00:00+00:00",
                    actor="admin",
                    allow_registered_reuse=True,
                    authorize_automatic_formatting=True,
                )

                result = catalog.commit_registered_tape_reformat("JOB-COMMIT", 1)

                self.assertEqual(
                    {"tapes": 1, "blocks": 1, "files": 1, "jobs": 1}, result
                )
                self.assertEqual({}, catalog.latest_versions("LIB1"))
                self.assertEqual(
                    "failed", catalog.get_automatic_job("OLD-LONG")["status"]
                )
                with self.assertRaises(CatalogError):
                    catalog.get_tape("AB1234-LONG-ID")
                catalog.register_tape(
                    "AB1234-REFORMATTED",
                    "SERIAL-NEW",
                    "VOLUME-NEW",
                    "LTFS",
                    "/tape/new",
                    cassette_number="AB1234-REFORMATTED-CASSETTE",
                )
                self.assertEqual(
                    result,
                    catalog.commit_registered_tape_reformat("JOB-COMMIT", 1),
                )
                self.assertEqual(
                    "AB1234-REFORMATTED",
                    catalog.get_tape("AB1234-REFORMATTED")["id"],
                )

                missing_source = root / "missing-source"
                missing_source.mkdir()
                catalog.add_library("LIB2", "Missing", str(missing_source))
                catalog.create_automatic_job(
                    "JOB-MISSING",
                    "LIB2",
                    "TAPE1",
                    "AUTO",
                    [("ZZ9999", "ZZ9999", 0, 0)],
                    force_format=True,
                    allow_registered_reuse=True,
                )
                with self.assertRaisesRegex(
                    CatalogError, "registered_tape_identity_missing"
                ):
                    catalog.commit_registered_tape_reformat("JOB-MISSING", 1)

                ambiguous_source = root / "ambiguous-source"
                ambiguous_source.mkdir()
                catalog.add_library("LIB3", "Ambiguous", str(ambiguous_source))
                catalog.register_tape(
                    "XY1234-LONG-ID",
                    "SERIAL-AMBIGUOUS-ONE",
                    "VOLUME-AMBIGUOUS-ONE",
                    "LTFS",
                    "/tape/ambiguous-one",
                    cassette_number="CASSETTE-AMBIGUOUS-ONE",
                )
                catalog.register_tape(
                    "OTHER-AMBIGUOUS-ID",
                    "SERIAL-AMBIGUOUS-TWO",
                    "VOLUME-AMBIGUOUS-TWO",
                    "LTFS",
                    "/tape/ambiguous-two",
                    cassette_number="XY1234-LONG-CASSETTE",
                )
                catalog.create_automatic_job(
                    "JOB-AMBIGUOUS-COMMIT",
                    "LIB3",
                    "TAPE2",
                    "AUTO",
                    [("XY1234", "XY1234", 0, 0)],
                    force_format=True,
                    allow_registered_reuse=True,
                )
                with self.assertRaisesRegex(
                    CatalogError, "registered_tape_identity_ambiguous"
                ):
                    catalog.commit_registered_tape_reformat(
                        "JOB-AMBIGUOUS-COMMIT", 1
                    )

    @staticmethod
    def _replace_canonical(plan: dict, **changes: object) -> dict:
        payload = json.loads(plan["canonical_json"])
        payload.update(changes)
        canonical_json = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        plan["canonical_json"] = canonical_json
        plan["digest_sha256"] = hashlib.sha256(
            canonical_json.encode("utf-8")
        ).hexdigest()
        return plan

    def test_ready_plan_preserves_nonportable_source_relative_path(self) -> None:
        """Using Windows path rules for source evidence rejects valid NFS names."""
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id="PLAN-SOURCE-PATH",
                kind="create",
                creator="operator",
                created_at="2026-08-25T10:00:00+00:00",
                expires_at="2026-08-26T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
            )
            frozen = self._frozen_plan()
            source_path = "I Flintstones /episode.mkv"
            frozen["cassettes"][0]["items"][0]["relative_path"] = source_path
            payload = json.loads(frozen["canonical_json"])
            payload["cassettes"][0]["items"][0]["relative_path"] = source_path
            frozen = self._replace_canonical(frozen, cassettes=payload["cassettes"])

            completed = catalog.complete_job_plan_draft(
                "PLAN-SOURCE-PATH", frozen
            )

            self.assertEqual(
                source_path,
                completed["cassettes"][0]["items"][0]["relative_path"],
            )

    @staticmethod
    def _connected_share(catalog: Catalog, share_id: str) -> tuple[dict, dict]:
        def fingerprint(value: str) -> str:
            return hashlib.sha256(value.encode()).hexdigest()

        created = catalog.create_managed_share(
            share_id,
            f"Share {share_id}",
            "nfs",
            json.dumps(
                {
                    "export": f"/archive/{share_id}",
                    "kind": "nfs",
                    "retransmissions": 2,
                    "server": "nas.example.test",
                    "timeout_seconds": 60,
                    "version": "4.2",
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
            actor="operator",
            idempotency_key=f"create-{share_id}",
            request_fingerprint_sha256=fingerprint(f"create-{share_id}"),
        )
        connected = catalog.update_managed_share(
            share_id,
            expected_revision=created["revision"],
            actor="operator",
            idempotency_key=f"connect-{share_id}",
            request_fingerprint_sha256=fingerprint(f"connect-{share_id}"),
            desired_state="connected",
        )
        catalog.record_managed_share_observation(
            share_id,
            actor="daemon",
            observed_state="connected",
            safe_error_code=None,
            mount_identity_sha256="c" * 64,
            mounted_config_revision=1,
            mounted_credential_generation=0,
            checked_at="2026-08-26T12:00:00+00:00",
        )
        evidence = {
            "kind": "managed_share",
            "share_id": share_id,
            "resource_revision": connected["revision"],
            "config_revision": 1,
            "credential_generation": 0,
            "mount_identity_sha256": "c" * 64,
            "read_only": True,
            "filesystem_type": "nfs4",
            "source_sha256": "d" * 64,
            "admitted_endpoints_sha256": "e" * 64,
            "relative_subpath": "media",
            "source_identity_sha256": "f" * 64,
        }
        return connected, evidence

    @classmethod
    def _persist_library(
        cls,
        catalog: Catalog,
        root: Path,
        *,
        network_share: str | None = None,
    ) -> tuple[dict | None, str | None]:
        if network_share is None:
            catalog.add_named_library("LIB1", "Library", str(root), str(root), "f" * 64)
            return None, None
        share, evidence = cls._connected_share(catalog, network_share)
        catalog.add_named_network_library(
            "LIB1",
            "Library",
            str(root),
            "f" * 64,
            network_share,
            "media",
            expected_share_revision=share["revision"],
            binding_evidence=evidence,
        )
        lease_id = catalog.acquire_managed_source_lease(
            network_share,
            consumer_kind="plan",
            consumer_id=f"plan-{network_share}",
            owner_id="daemon",
            daemon_generation=1,
        )
        return evidence, lease_id

    @classmethod
    def _with_managed_sources(
        cls,
        plan: dict,
        entries: list[dict],
        leases: dict[str, str],
    ) -> dict:
        cls._replace_canonical(plan, managed_sources=entries)
        plan["managed_sources"] = entries
        plan["managed_source_leases"] = leases
        return plan

    @staticmethod
    def _assert_plan_publish_rolled_back(catalog: Catalog, plan_id: str) -> None:
        assert catalog.get_job_plan(plan_id)["state"] == "building"
        for table in (
            "job_plan_libraries",
            "job_plan_cassettes",
            "job_plan_items",
            "job_plan_share_evidence",
        ):
            count = catalog.connection.execute(
                f"SELECT count(*) FROM {table} WHERE plan_id=?", (plan_id,)
            ).fetchone()[0]
            assert count == 0

    @staticmethod
    def _install_pre_fix_schema_23_plan_triggers(db: sqlite3.Connection) -> None:
        db.executescript(
            """
            DROP TRIGGER job_plan_libraries_immutable_delete;
            DROP TRIGGER job_plan_cassettes_immutable_delete;
            DROP TRIGGER job_plan_items_immutable_delete;
            DROP TRIGGER job_plan_draft_frozen_fields_immutable;
            DROP TRIGGER job_plan_draft_controlled_delete;

            CREATE TRIGGER job_plan_libraries_immutable_delete
            BEFORE DELETE ON job_plan_libraries
            WHEN (SELECT state FROM job_plan_drafts WHERE id=OLD.plan_id)!='expired'
            BEGIN
                SELECT RAISE(ABORT, 'job plan manifest is immutable');
            END;
            CREATE TRIGGER job_plan_cassettes_immutable_delete
            BEFORE DELETE ON job_plan_cassettes
            WHEN (SELECT state FROM job_plan_drafts WHERE id=OLD.plan_id)!='expired'
            BEGIN
                SELECT RAISE(ABORT, 'job plan manifest is immutable');
            END;
            CREATE TRIGGER job_plan_items_immutable_delete
            BEFORE DELETE ON job_plan_items
            WHEN (SELECT state FROM job_plan_drafts WHERE id=OLD.plan_id)!='expired'
            BEGIN
                SELECT RAISE(ABORT, 'job plan manifest is immutable');
            END;

            CREATE TRIGGER job_plan_draft_frozen_fields_immutable
            BEFORE UPDATE ON job_plan_drafts
            WHEN OLD.state IN ('ready','failed','expired','consumed') AND (
                NEW.kind!=OLD.kind OR NEW.creator!=OLD.creator
                OR NEW.created_at!=OLD.created_at OR NEW.expires_at!=OLD.expires_at
                OR NEW.media_key!=OLD.media_key
                OR NEW.requested_library_ids_json!=OLD.requested_library_ids_json
                OR NEW.canonical_json!=OLD.canonical_json
                OR NEW.digest_sha256!=OLD.digest_sha256
                OR NEW.canonical_json_version!=OLD.canonical_json_version
                OR NEW.plan_schema_version!=OLD.plan_schema_version
                OR NEW.planner_version!=OLD.planner_version
                OR NEW.application_settings_revision!=OLD.application_settings_revision
                OR NEW.application_settings_fingerprint_sha256
                   !=OLD.application_settings_fingerprint_sha256
                OR NEW.base_job_id IS NOT OLD.base_job_id
                OR NEW.base_job_revision IS NOT OLD.base_job_revision
                OR NEW.base_job_fingerprint_sha256 IS NOT OLD.base_job_fingerprint_sha256
            )
            BEGIN
                SELECT RAISE(ABORT, 'job plan draft is immutable');
            END;
            """
        )

    def test_schema_twenty_two_forward_migration_adds_plan_drafts_and_manifest_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=22)
                self.assertEqual(
                    [],
                    list(
                        catalog.connection.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' "
                            "AND name LIKE 'job_plan_%'"
                        )
                    ),
                )

            prepare_and_initialize(database)

            with Catalog(database) as catalog:
                tables = {
                    row["name"]
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                columns = {
                    row["name"]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(job_plan_drafts)"
                    )
                }
                self.assertEqual(41, SCHEMA_VERSION)
                self.assertTrue(
                    {
                        "job_plan_drafts",
                        "job_plan_libraries",
                        "job_plan_cassettes",
                        "job_plan_items",
                        "cartridges",
                    }.issubset(tables)
                )
                self.assertTrue(
                    {
                        "id",
                        "state",
                        "kind",
                        "creator",
                        "created_at",
                        "expires_at",
                        "digest_sha256",
                        "media_key",
                        "canonical_json",
                        "canonical_json_version",
                        "plan_schema_version",
                        "planner_version",
                        "application_settings_revision",
                        "application_settings_fingerprint_sha256",
                        "consumed_job_id",
                    }.issubset(columns)
                )
                self.assertEqual([], foreign_key_violations(database))
                self.assertEqual(["ok"], integrity_check(database))

    def test_schema_twenty_three_upgrades_pre_fix_plan_triggers_to_version_twenty_four(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            source = Path(temporary) / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            with Catalog(database) as catalog:
                catalog.initialize(target_version=23)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_job_plan_draft(
                    plan_id="PLAN-FAILED-V23",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                catalog.fail_job_plan_draft(
                    "PLAN-FAILED-V23", "scan_failed", "source unavailable"
                )
                catalog.create_job_plan_draft(
                    plan_id="PLAN-CONSUMED-V23",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = self._frozen_plan(str(source))
                catalog.complete_job_plan_draft("PLAN-CONSUMED-V23", frozen)
                catalog.consume_job_plan(
                    plan_id="PLAN-CONSUMED-V23",
                    digest_sha256=frozen["digest_sha256"],
                    labels=("AB1234",),
                    idempotency_key="request-v23",
                    request_sha256="d" * 64,
                    job_id="JOB-CONSUMED-V23",
                    display_name="Schema 23",
                    device_name="TAPE0",
                    mount_path="AUTO",
                    consumed_at="2026-08-25T10:30:00+00:00",
                    authorize_automatic_formatting=True,
                )
                catalog.create_job_plan_draft(
                    plan_id="PLAN-EXPIRED-V23",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-24T10:00:00+00:00",
                    expires_at="2026-08-25T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                catalog.cleanup_expired_job_plans("2026-08-25T10:00:01+00:00")
                self._install_pre_fix_schema_23_plan_triggers(catalog.connection)
                catalog.connection.commit()
                trigger_names = {
                    row["name"]
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='trigger' "
                        "AND name LIKE 'job_plan_%'"
                    )
                }
                frozen_trigger = catalog.connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' "
                    "AND name='job_plan_draft_frozen_fields_immutable'"
                ).fetchone()["sql"]
                self.assertNotIn("job_plan_draft_controlled_delete", trigger_names)
                self.assertNotIn("failure_code", frozen_trigger)

            with Catalog(database) as catalog:
                initialize_current_with_protected_backup(catalog, database.parent)
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()["value"]
                self.assertEqual(str(SCHEMA_VERSION), version)
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    catalog.connection.execute(
                        "UPDATE job_plan_drafts SET failure_code='rewritten' "
                        "WHERE id='PLAN-FAILED-V23'"
                    )
                catalog.connection.rollback()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    catalog.connection.execute(
                        "UPDATE job_plan_drafts SET consumption_key='rewritten' "
                        "WHERE id='PLAN-CONSUMED-V23'"
                    )
                catalog.connection.rollback()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "expired cleanup"):
                    catalog.connection.execute(
                        "DELETE FROM job_plan_drafts WHERE id='PLAN-EXPIRED-V23'"
                    )
                catalog.connection.rollback()
                self.assertEqual([], foreign_key_violations(database))
                self.assertEqual(["ok"], integrity_check(database))

    def test_building_draft_requires_at_least_one_ordered_library(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            with self.assertRaisesRegex(ValidationError, "library"):
                catalog.create_job_plan_draft(
                    plan_id="PLAN-EMPTY",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                )

    def test_ready_plan_manifest_is_persisted_exactly_and_is_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.create_job_plan_draft(
                    plan_id="PLAN-1",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                catalog.complete_job_plan_draft("PLAN-1", self._frozen_plan())

                plan = catalog.get_job_plan("PLAN-1")

                self.assertEqual("ready", plan["state"])
                self.assertEqual(
                    self._frozen_plan()["canonical_json"], plan["canonical_json"]
                )
                self.assertEqual(["LIB1"], plan["library_ids"])
                self.assertEqual(
                    "b" * 64, plan["libraries"][0]["scan_fingerprint_sha256"]
                )
                self.assertEqual(12, plan["cassettes"][0]["allocation_bytes"])
                self.assertEqual(
                    "payload.bin", plan["cassettes"][0]["items"][0]["relative_path"]
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    catalog.connection.execute(
                        "UPDATE job_plan_items SET size=8 WHERE plan_id='PLAN-1'"
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    catalog.connection.execute(
                        "INSERT INTO job_plan_cassettes("
                        "plan_id,sequence,objects,payload_bytes,allocation_bytes,"
                        "capacity_utilization,operation) "
                        "VALUES('PLAN-1',2,0,0,0,0,'reserve')"
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "state"):
                    catalog.connection.execute(
                        "UPDATE job_plan_drafts SET state='building' WHERE id='PLAN-1'"
                    )

    def test_direct_publish_rejects_missing_network_evidence_cardinality(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                self._persist_library(catalog, source, network_share="archive")
                catalog.create_job_plan_draft(
                    plan_id="PLAN-MISSING",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )

                with self.assertRaisesRegex(
                    ValidationError, "managed source plan cardinality"
                ):
                    catalog.complete_job_plan_draft(
                        "PLAN-MISSING", self._frozen_plan(str(source))
                    )

                self._assert_plan_publish_rolled_back(catalog, "PLAN-MISSING")

    def test_direct_publish_rejects_context_for_local_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                self._persist_library(catalog, source)
                _share, evidence = self._connected_share(catalog, "extra")
                lease_id = catalog.acquire_managed_source_lease(
                    "extra",
                    consumer_kind="plan",
                    consumer_id="plan-extra",
                    owner_id="daemon",
                    daemon_generation=1,
                )
                catalog.create_job_plan_draft(
                    plan_id="PLAN-EXTRA",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = self._with_managed_sources(
                    self._frozen_plan(str(source)),
                    [{"library_id": "LIB1", "evidence": evidence}],
                    {"lib1": lease_id},
                )

                with self.assertRaisesRegex(
                    ValidationError, "managed source plan cardinality"
                ):
                    catalog.complete_job_plan_draft("PLAN-EXTRA", frozen)

                self._assert_plan_publish_rolled_back(catalog, "PLAN-EXTRA")

    def test_direct_publish_rejects_duplicate_managed_library_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                evidence, lease_id = self._persist_library(
                    catalog, source, network_share="archive"
                )
                assert evidence is not None and lease_id is not None
                catalog.create_job_plan_draft(
                    plan_id="PLAN-DUPLICATE",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                entry = {"library_id": "LIB1", "evidence": evidence}
                frozen = self._with_managed_sources(
                    self._frozen_plan(str(source)),
                    [entry, entry],
                    {"lib1": lease_id},
                )

                with self.assertRaisesRegex(
                    ValidationError, "managed source plan cardinality"
                ):
                    catalog.complete_job_plan_draft("PLAN-DUPLICATE", frozen)

                self._assert_plan_publish_rolled_back(catalog, "PLAN-DUPLICATE")

    def test_direct_publish_rejects_managed_binding_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                self._persist_library(catalog, source, network_share="archive")
                _other_share, other_evidence = self._connected_share(catalog, "other")
                other_lease = catalog.acquire_managed_source_lease(
                    "other",
                    consumer_kind="plan",
                    consumer_id="plan-other",
                    owner_id="daemon",
                    daemon_generation=1,
                )
                catalog.create_job_plan_draft(
                    plan_id="PLAN-MIXED",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = self._with_managed_sources(
                    self._frozen_plan(str(source)),
                    [{"library_id": "LIB1", "evidence": other_evidence}],
                    {"lib1": other_lease},
                )

                with self.assertRaisesRegex(
                    ValidationError, "managed source plan identity"
                ):
                    catalog.complete_job_plan_draft("PLAN-MIXED", frozen)

                self._assert_plan_publish_rolled_back(catalog, "PLAN-MIXED")

    def test_direct_publish_rejects_mixed_frozen_binding_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                evidence, lease_id = self._persist_library(
                    catalog, source, network_share="archive"
                )
                assert evidence is not None and lease_id is not None
                catalog.create_job_plan_draft(
                    plan_id="PLAN-MIXED-EVIDENCE",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = self._with_managed_sources(
                    self._frozen_plan(str(source)),
                    [
                        {
                            "library_id": "LIB1",
                            "evidence": {**evidence, "source_sha256": "0" * 64},
                        }
                    ],
                    {"lib1": lease_id},
                )

                with self.assertRaisesRegex(
                    ValidationError, "managed source plan identity"
                ):
                    catalog.complete_job_plan_draft("PLAN-MIXED-EVIDENCE", frozen)

                self._assert_plan_publish_rolled_back(catalog, "PLAN-MIXED-EVIDENCE")

    def test_direct_publish_accepts_exact_network_and_legacy_local_plans(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network = root / "network"
            local = root / "local"
            network.mkdir()
            local.mkdir()
            with Catalog(root / "network.db") as catalog:
                catalog.initialize()
                evidence, lease_id = self._persist_library(
                    catalog, network, network_share="archive"
                )
                assert evidence is not None and lease_id is not None
                catalog.create_job_plan_draft(
                    plan_id="PLAN-NETWORK",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = self._with_managed_sources(
                    self._frozen_plan(str(network)),
                    [{"library_id": "LIB1", "evidence": evidence}],
                    {"lib1": lease_id},
                )
                network_plan = catalog.complete_job_plan_draft("PLAN-NETWORK", frozen)
            with Catalog(root / "local.db") as catalog:
                catalog.initialize()
                self._persist_library(catalog, local)
                catalog.create_job_plan_draft(
                    plan_id="PLAN-LOCAL",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                local_plan = catalog.complete_job_plan_draft(
                    "PLAN-LOCAL", self._frozen_plan(str(local))
                )

            self.assertEqual("ready", network_plan["state"])
            self.assertEqual("ready", local_plan["state"])

    def test_ready_relational_manifest_must_match_digest_bound_canonical_json(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.create_job_plan_draft(
                    plan_id="PLAN-BOUND",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                relationally_tampered = self._frozen_plan()
                relationally_tampered["cassettes"][0]["items"][0]["size"] = 8
                relationally_tampered["cassettes"][0]["payload_bytes"] = 8

                with self.assertRaisesRegex(
                    ValidationError, "canonical.*relational|relational.*canonical"
                ):
                    catalog.complete_job_plan_draft("PLAN-BOUND", relationally_tampered)

    def test_ready_canonical_media_must_match_the_draft(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id="PLAN-MEDIA",
                kind="create",
                creator="operator",
                created_at="2026-08-25T10:00:00+00:00",
                expires_at="2026-08-26T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
            )
            wrong_media = self._replace_canonical(
                self._frozen_plan(), media_key="LTO-5"
            )

            with self.assertRaisesRegex(ValidationError, "canonical.*draft"):
                catalog.complete_job_plan_draft("PLAN-MEDIA", wrong_media)

    def test_create_canonical_base_must_be_explicit_null(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id="PLAN-CREATE-BASE",
                kind="create",
                creator="operator",
                created_at="2026-08-25T10:00:00+00:00",
                expires_at="2026-08-26T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
            )
            missing_base = self._frozen_plan()
            payload = json.loads(missing_base["canonical_json"])
            del payload["base_job"]
            canonical_json = json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            missing_base["canonical_json"] = canonical_json
            missing_base["digest_sha256"] = hashlib.sha256(
                canonical_json.encode("utf-8")
            ).hexdigest()

            with self.assertRaisesRegex(ValidationError, "canonical.*draft"):
                catalog.complete_job_plan_draft("PLAN-CREATE-BASE", missing_base)

    def test_extend_canonical_base_must_match_the_frozen_draft_base(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id="PLAN-EXTEND-BASE",
                kind="extend",
                creator="operator",
                created_at="2026-08-25T10:00:00+00:00",
                expires_at="2026-08-26T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
                base_job_id="JOB-BASE",
                base_job_revision=3,
                base_job_fingerprint_sha256="c" * 64,
            )
            wrong_base = self._replace_canonical(
                self._frozen_plan(),
                kind="extend",
                base_job={
                    "fingerprint_sha256": "c" * 64,
                    "id": "JOB-WRONG",
                    "revision": 3,
                },
            )

            with self.assertRaisesRegex(ValidationError, "canonical.*draft"):
                catalog.complete_job_plan_draft("PLAN-EXTEND-BASE", wrong_base)

    def test_plan_state_machine_covers_failed_expired_and_both_kinds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                for plan_id, kind in (
                    ("PLAN-CREATE", "create"),
                    ("PLAN-EXTEND", "extend"),
                ):
                    catalog.create_job_plan_draft(
                        plan_id=plan_id,
                        kind=kind,
                        creator="operator",
                        created_at="2026-08-24T10:00:00+00:00",
                        expires_at="2026-08-25T10:00:00+00:00",
                        media_key="LTO-6",
                        library_ids=("LIB1",),
                        **(
                            {
                                "base_job_id": "JOB-BASE",
                                "base_job_revision": 0,
                                "base_job_fingerprint_sha256": "c" * 64,
                            }
                            if kind == "extend"
                            else {}
                        ),
                    )
                catalog.fail_job_plan_draft("PLAN-CREATE", "plan_failed", "scan failed")
                expired = catalog.cleanup_expired_job_plans("2026-08-25T10:00:01+00:00")

                self.assertEqual("failed", catalog.get_job_plan("PLAN-CREATE")["state"])
                self.assertEqual("extend", catalog.get_job_plan("PLAN-EXTEND")["kind"])
                self.assertEqual(
                    "expired", catalog.get_job_plan("PLAN-EXTEND")["state"]
                )
                self.assertEqual(1, expired)

    def test_failed_plan_evidence_and_terminal_parent_are_immutable(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id="PLAN-FAILED",
                kind="create",
                creator="operator",
                created_at="2026-08-25T10:00:00+00:00",
                expires_at="2026-08-26T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
            )
            catalog.fail_job_plan_draft(
                "PLAN-FAILED", "scan_failed", "source unavailable"
            )

            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                catalog.connection.execute(
                    "UPDATE job_plan_drafts SET failure_code='rewritten',"
                    "failure_message='rewritten' WHERE id='PLAN-FAILED'"
                )
            with self.assertRaisesRegex(sqlite3.IntegrityError, "expired cleanup"):
                catalog.connection.execute(
                    "DELETE FROM job_plan_drafts WHERE id='PLAN-FAILED'"
                )

    def test_expired_plan_parent_is_deleted_only_by_controlled_purge(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id="PLAN-EXPIRED",
                kind="create",
                creator="operator",
                created_at="2026-08-24T10:00:00+00:00",
                expires_at="2026-08-25T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
            )
            catalog.complete_job_plan_draft("PLAN-EXPIRED", self._frozen_plan())
            catalog.cleanup_expired_job_plans("2026-08-25T10:00:01+00:00")

            with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                catalog.connection.execute(
                    "DELETE FROM job_plan_items WHERE plan_id='PLAN-EXPIRED'"
                )
            catalog.connection.rollback()
            with self.assertRaisesRegex(sqlite3.IntegrityError, "expired cleanup"):
                catalog.connection.execute(
                    "DELETE FROM job_plan_drafts WHERE id='PLAN-EXPIRED'"
                )
            catalog.connection.rollback()

            self.assertEqual(
                1,
                catalog.purge_expired_job_plans("2026-08-25T10:00:01+00:00"),
            )
            with self.assertRaisesRegex(CatalogError, "not found"):
                catalog.get_job_plan("PLAN-EXPIRED")


class ApplicationSettingsCatalogTests(unittest.TestCase):

    def test_source_policy_update_is_optional_and_preserves_old_clients(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                current = catalog.import_application_settings_once(
                    Settings(min_age_seconds=0), legacy_source_sha256=None
                )
                candidate = {
                    "capacity_reserve_bytes": current["capacity_reserve_bytes"],
                    "minimum_source_file_age_seconds": current[
                        "minimum_source_file_age_seconds"
                    ],
                    "copy_buffer_bytes": current["copy_buffer_bytes"],
                    "content_verification_policy": current["content_verification_policy"],
                    "default_media_profile": current["default_media_profile"],
                    "tape_root_directory": current["tape_root_directory"],
                }
                legacy = catalog.update_application_settings(
                    candidate,
                    expected_revision=current["revision"],
                    actor="admin",
                    idempotency_key="legacy-source-policy",
                    request_sha256="a" * 64,
                )
                self.assertEqual(
                    "size_mtime_change", legacy["source_change_detection_policy"]
                )
                explicit = catalog.update_application_settings(
                    {**candidate, "source_change_detection_policy": "size_mtime"},
                    expected_revision=legacy["revision"],
                    actor="admin",
                    idempotency_key="explicit-source-policy",
                    request_sha256="b" * 64,
                )
                self.assertEqual("size_mtime", explicit["source_change_detection_policy"])
                with self.assertRaises(ValidationError):
                    catalog.update_application_settings(
                        {**candidate, "source_change_detection_policy": "invalid"},
                        expected_revision=explicit["revision"],
                        actor="admin",
                        idempotency_key="invalid-source-policy",
                        request_sha256="c" * 64,
                    )

    @staticmethod
    def _create_released_schema_34_policy_fixture(database: Path) -> dict[str, object]:
        """Materialize the released v34 policy FK with a non-null plan identity."""

        with Catalog(database) as catalog:
            catalog.initialize(target_version=34)
            catalog.create_job_plan_draft(
                plan_id="PLAN-RELEASED-V34",
                kind="create",
                creator="operator",
                created_at="2026-08-28T10:00:00+00:00",
                expires_at="2026-08-29T10:00:00+00:00",
                media_key="LTO-6",
                library_ids=("LIB1",),
            )
            policy_json = json.dumps(
                {"selected_media_profile": "LTO-6"},
                separators=(",", ":"),
                sort_keys=True,
            )
            catalog.connection.execute(
                "INSERT INTO job_policy_snapshots("
                "job_id,plan_id,settings_revision,policy_json,policy_sha256,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    "JOB-RELEASED-V34",
                    "PLAN-RELEASED-V34",
                    7,
                    policy_json,
                    hashlib.sha256(policy_json.encode("utf-8")).hexdigest(),
                    "2026-08-28T10:01:00+00:00",
                ),
            )
            catalog.connection.commit()
            return dict(
                catalog.connection.execute(
                    "SELECT * FROM job_policy_snapshots "
                    "WHERE job_id='JOB-RELEASED-V34'"
                ).fetchone()
            )

    @staticmethod
    def _policy_snapshot_schema(catalog: Catalog) -> list[tuple[str, str, str]]:
        return [
            (str(row["type"]), str(row["name"]), str(row["sql"]))
            for row in catalog.connection.execute(
                "SELECT type,name,sql FROM sqlite_master "
                "WHERE tbl_name='job_policy_snapshots' AND sql IS NOT NULL "
                "ORDER BY type,name"
            )
        ]

    def test_schema_thirty_five_rebuilds_released_policy_snapshot_fk_losslessly(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            upgraded_path = root / "upgraded.db"
            fresh_path = root / "fresh.db"
            expected = self._create_released_schema_34_policy_fixture(upgraded_path)

            with Catalog(upgraded_path) as released:
                released_fk_targets = {
                    str(row["table"])
                    for row in released.connection.execute(
                        "PRAGMA foreign_key_list(job_policy_snapshots)"
                    )
                }
            self.assertIn("job_plan_drafts", released_fk_targets)

            with Catalog(upgraded_path) as upgraded:
                initialize_current_with_protected_backup(upgraded, root)
                actual = dict(
                    upgraded.connection.execute(
                        "SELECT * FROM job_policy_snapshots "
                        "WHERE job_id='JOB-RELEASED-V34'"
                    ).fetchone()
                )
                upgraded_fk_targets = {
                    str(row["table"])
                    for row in upgraded.connection.execute(
                        "PRAGMA foreign_key_list(job_policy_snapshots)"
                    )
                }
                upgraded_schema = self._policy_snapshot_schema(upgraded)
                self.assertEqual(
                    [], upgraded.connection.execute("PRAGMA foreign_key_check").fetchall()
                )
                old_tables = upgraded.connection.execute(
                    "SELECT name FROM sqlite_master WHERE name LIKE '%v35_old%' "
                    "UNION ALL SELECT name FROM sqlite_temp_master "
                    "WHERE name LIKE 'schema35_stage_%'"
                ).fetchall()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    upgraded.connection.execute(
                        "UPDATE job_policy_snapshots SET settings_revision=8 "
                        "WHERE job_id='JOB-RELEASED-V34'"
                    )
                upgraded.connection.rollback()
                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    upgraded.connection.execute(
                        "DELETE FROM job_policy_snapshots "
                        "WHERE job_id='JOB-RELEASED-V34'"
                    )
                upgraded.connection.rollback()

            with Catalog(fresh_path) as fresh:
                fresh.initialize()
                fresh_schema = self._policy_snapshot_schema(fresh)

            self.assertEqual(expected, actual)
            self.assertNotIn("job_plan_drafts", upgraded_fk_targets)
            self.assertEqual([], old_tables)
            self.assertEqual(fresh_schema, upgraded_schema)
            self.assertEqual([], foreign_key_violations(upgraded_path))

    def test_schema_thirty_five_fk_violation_rolls_back_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=34)
            with closing(sqlite3.connect(database)) as connection:
                connection.execute("PRAGMA foreign_keys=OFF")
                connection.execute(
                    "INSERT INTO job_policy_snapshots("
                    "job_id,plan_id,settings_revision,policy_json,policy_sha256,created_at) "
                    "VALUES('JOB-DANGLING','PLAN-DANGLING',1,'{}',?,?)",
                    ("a" * 64, "2026-08-28T10:00:00+00:00"),
                )
                connection.commit()
                self.assertNotEqual([], list(connection.execute("PRAGMA foreign_key_check")))

            with (
                Catalog(database) as catalog,
                self.assertRaisesRegex(CatalogError, "foreign key"),
            ):
                catalog.initialize(target_version=35)

            self.assertEqual("34", read_schema_version(database))
            with closing(sqlite3.connect(database)) as connection:
                self.assertEqual(
                    [],
                    list(
                        connection.execute(
                            "SELECT name FROM sqlite_master "
                            "WHERE name IN ('job_incremental_policies',"
                            "'job_layout_epochs')"
                        )
                    ),
                )

    def test_schema_twenty_seven_jobs_and_ready_plans_gain_compatibility_policy(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            other_source = root / "other-source"
            source.mkdir()
            other_source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=27)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.add_library("LIB2", "Other", str(other_source))
                catalog.create_automatic_job(
                    "JOB-V27",
                    "LIB2",
                    "/dev/tape/by-id/test-nst",
                    "/mnt/tape",
                    [("ZX9876", "ZX9876", 1, 7)],
                    force_format=True,
                    media_key="LTO-10 PA",
                )
                catalog.create_job_plan_draft(
                    plan_id="PLAN-V27-COMPAT",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = JobPlanDraftCatalogTests._frozen_plan(str(source))
                ready = catalog.complete_job_plan_draft("PLAN-V27-COMPAT", frozen)
                canonical_before = ready["canonical_json"]
                digest_before = ready["digest_sha256"]

            with Catalog(database) as catalog:
                initialize_current_with_protected_backup(catalog, root)
                catalog.import_application_settings_once(
                    Settings(
                        reserve_bytes=123,
                        buffer_bytes=2 * 1024**2,
                        min_age_seconds=77,
                        tape_root_directory=".lto-backup",
                        verify_unchanged_content=True,
                        default_media_key="LTO-10 LA",
                    ),
                    legacy_source_sha256=None,
                )
                native_policy = catalog.get_job_policy_snapshot("JOB-V27")
                resumed_settings = ProductionNativeArchive._settings_for_admitted_job(
                    SimpleNamespace(admitted_copy_buffer_bytes=lambda: 2 * 1024**2),
                    catalog,
                    "JOB-V27",
                    catalog_backup_directory=str(root / "backups"),
                )
                plan_policy = catalog.get_job_plan_policy_snapshot("PLAN-V27-COMPAT")
                ready_after = catalog.get_job_plan("PLAN-V27-COMPAT")
                created_job_id, replayed = catalog.consume_job_plan(
                    plan_id="PLAN-V27-COMPAT",
                    digest_sha256=digest_before,
                    labels=("AB1234",),
                    idempotency_key="consume-v27-plan",
                    request_sha256="c" * 64,
                    job_id="JOB-FROM-V27-PLAN",
                    display_name="Compatibility job",
                    device_name="/dev/tape/by-id/test-nst",
                    mount_path="/mnt/tape",
                    consumed_at="2026-08-25T11:00:00+00:00",
                    actor="admin",
                    authorize_automatic_formatting=True,
                )
                consumed_policy = catalog.get_job_policy_snapshot(created_job_id)

            self.assertEqual("LTO-10 PA", native_policy["selected_media_profile"])
            self.assertEqual("full", native_policy["content_verification_policy"])
            self.assertEqual("LTO-10 LA", resumed_settings.default_media_key)
            self.assertEqual(37_030_000_000_000, resumed_settings.tape_capacity_bytes)
            self.assertEqual(2 * 1024**2, resumed_settings.buffer_bytes)
            self.assertEqual(77, resumed_settings.min_age_seconds)
            self.assertEqual(
                str(root / "backups"), resumed_settings.catalog_backup_directory
            )
            self.assertEqual("LTO-6", plan_policy["selected_media_profile"])
            self.assertEqual(canonical_before, ready_after["canonical_json"])
            self.assertEqual(digest_before, ready_after["digest_sha256"])
            self.assertFalse(replayed)
            self.assertEqual("LTO-6", consumed_policy["selected_media_profile"])
            self.assertEqual("full", consumed_policy["content_verification_policy"])

    def test_schema_twenty_eight_is_additive_and_preserves_plan_share_and_job_rows(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = root / "catalog.db"
            source = root / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=27)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_job_plan_draft(
                    plan_id="PLAN-V27",
                    kind="create",
                    creator="operator",
                    created_at="2026-08-25T10:00:00+00:00",
                    expires_at="2026-08-26T10:00:00+00:00",
                    media_key="LTO-6",
                    library_ids=("LIB1",),
                )
                frozen = JobPlanDraftCatalogTests._frozen_plan(str(source))
                catalog.complete_job_plan_draft("PLAN-V27", frozen)
                catalog.create_managed_share(
                    "archive",
                    "Archive NAS",
                    "nfs",
                    json.dumps(
                        {
                            "export": "/archive",
                            "kind": "nfs",
                            "retransmissions": 2,
                            "server": "nas.example.test",
                            "timeout_seconds": 60,
                            "version": "4.2",
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ),
                    actor="admin",
                    idempotency_key="create-share-v27",
                    request_fingerprint_sha256="f" * 64,
                )
                before = canonical_row_snapshot(
                    database,
                    (
                        "job_plan_drafts",
                        "job_plan_libraries",
                        "job_plan_cassettes",
                        "job_plan_items",
                        "managed_shares",
                        "share_operations",
                        "library_share_bindings",
                        "job_management_state",
                    ),
                )
                for share in before["managed_shares"]:
                    share.update(
                        {
                            "config_revision": 1,
                            "mounted_config_revision": None,
                            "mounted_credential_generation": None,
                            "removed_at": None,
                        }
                    )
                # Schema 35 freezes the physical LTFS path once during
                # migration; every pre-35 logical row has one deterministic
                # backfill value and all pre-existing columns remain exact.
                for item in before["job_plan_items"]:
                    item["tape_relative_path"] = item["relative_path"]

            with Catalog(database) as catalog:
                initialize_current_with_protected_backup(catalog, root)
                tables = {
                    str(row["name"])
                    for row in catalog.connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                operation_columns = {
                    str(row["name"])
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(daemon_operations)"
                    )
                }
            after = canonical_row_snapshot(database, tuple(before))

            self.assertEqual(41, SCHEMA_VERSION)
            self.assertEqual("41", read_schema_version(database))
            self.assertEqual(before, after)
            self.assertTrue(
                {
                    "application_settings",
                    "job_plan_policy_snapshots",
                    "job_policy_snapshots",
                }.issubset(tables)
            )
            self.assertIn("copy_buffer_bytes", operation_columns)
            self.assertEqual([], foreign_key_violations(database))
            self.assertEqual(["ok"], integrity_check(database))

    def test_legacy_settings_import_is_exact_once_and_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            original = Settings(
                reserve_bytes=123,
                tape_capacity_bytes=9_999,
                buffer_bytes=2 * 1024**2,
                min_age_seconds=77,
                tape_root_directory=".lto-backup",
                verify_unchanged_content=True,
                default_media_key="LTO-10 PA",
            )
            changed = Settings(
                reserve_bytes=456,
                buffer_bytes=4 * 1024**2,
                min_age_seconds=88,
                tape_root_directory="archive",
                default_media_key="LTO-5",
            )
            with Catalog(database) as catalog:
                catalog.initialize()
                first = catalog.import_application_settings_once(
                    original, legacy_source_sha256="a" * 64
                )
                second = catalog.import_application_settings_once(
                    changed, legacy_source_sha256="b" * 64
                )

            self.assertEqual(first, second)
            self.assertEqual(1, first["revision"])
            self.assertEqual(123, first["capacity_reserve_bytes"])
            self.assertEqual(9_999, first["legacy_tape_capacity_bytes"])
            self.assertEqual("full", first["content_verification_policy"])
            self.assertEqual("LTO-10 PA", first["default_media_profile"])
            self.assertEqual("a" * 64, first["legacy_source_sha256"])

    def test_schema_twenty_eight_adds_library_metadata_revision_additively(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            source = Path(temporary) / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize(target_version=28)
                catalog.add_library("LIB1", "Library", str(source))
                catalog.update_library_scan("LIB1", 3, 21)
                before = dict(catalog.get_library("LIB1"))

            with Catalog(database) as catalog:
                initialize_current_with_protected_backup(catalog, database.parent)
                after = dict(catalog.get_named_library("LIB1"))
                columns = {
                    row["name"]
                    for row in catalog.connection.execute(
                        "PRAGMA table_info(libraries)"
                    )
                }

            self.assertEqual(41, SCHEMA_VERSION)
            self.assertEqual("41", read_schema_version(database))
            self.assertIn("metadata_revision", columns)
            self.assertEqual(0, after["metadata_revision"])
            self.assertEqual(before["last_scan_files"], after["last_scan_files"])
            self.assertEqual(before["last_scan_bytes"], after["last_scan_bytes"])
            self.assertEqual([], foreign_key_violations(database))
            self.assertEqual(["ok"], integrity_check(database))

    def test_settings_update_revision_receipt_and_audit_are_one_transaction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.import_application_settings_once(
                    Settings(min_age_seconds=0), legacy_source_sha256=None
                )
                candidate = {
                    "capacity_reserve_bytes": 1024,
                    "minimum_source_file_age_seconds": 60,
                    "copy_buffer_bytes": 4 * 1024**2,
                    "content_verification_policy": "manifest",
                    "default_media_profile": "LTO-10 LA",
                    "tape_root_directory": ".lto-backup",
                }
                updated = catalog.update_application_settings(
                    candidate,
                    expected_revision=1,
                    actor="admin",
                    idempotency_key="settings-put-1",
                    request_sha256="c" * 64,
                )
                replay = catalog.update_application_settings(
                    candidate,
                    expected_revision=1,
                    actor="admin",
                    idempotency_key="settings-put-1",
                    request_sha256="c" * 64,
                )

                self.assertEqual(updated, replay)
                self.assertEqual(2, updated["revision"])
                self.assertEqual(
                    1,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM audit_entries "
                        "WHERE action='application.settings.update' AND result='accepted'"
                    ).fetchone()[0],
                )
                with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                    catalog.update_application_settings(
                        {**candidate, "copy_buffer_bytes": 8 * 1024**2},
                        expected_revision=1,
                        actor="admin",
                        idempotency_key="settings-put-1",
                        request_sha256="d" * 64,
                    )
                with self.assertRaisesRegex(CatalogError, "settings_revision_conflict"):
                    catalog.update_application_settings(
                        candidate,
                        expected_revision=1,
                        actor="admin",
                        idempotency_key="settings-put-2",
                        request_sha256="c" * 64,
                    )

    def test_settings_update_rolls_back_revision_receipt_and_audit_together(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                original = catalog.import_application_settings_once(
                    Settings(min_age_seconds=0), legacy_source_sha256=None
                )
                candidate = {
                    "capacity_reserve_bytes": 1024,
                    "minimum_source_file_age_seconds": 60,
                    "copy_buffer_bytes": 4 * 1024**2,
                    "content_verification_policy": "manifest",
                    "default_media_profile": "LTO-10 LA",
                    "tape_root_directory": ".lto-backup",
                }

                with (
                    patch.object(
                        catalog,
                        "_record_audit_tx",
                        side_effect=RuntimeError("injected audit failure"),
                    ),
                    self.assertRaisesRegex(RuntimeError, "injected audit failure"),
                ):
                    catalog.update_application_settings(
                        candidate,
                        expected_revision=1,
                        actor="admin",
                        idempotency_key="settings-put-rollback",
                        request_sha256="f" * 64,
                    )

                self.assertEqual(original, catalog.get_application_settings())
                self.assertEqual(
                    0,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM management_idempotency "
                        "WHERE idempotency_key='settings-put-rollback'"
                    ).fetchone()[0],
                )
                self.assertEqual(
                    0,
                    catalog.connection.execute(
                        "SELECT COUNT(*) FROM audit_entries "
                        "WHERE action='application.settings.update'"
                    ).fetchone()[0],
                )

    def test_operation_admission_freezes_copy_buffer_in_the_same_transaction(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.import_application_settings_once(
                    Settings(buffer_bytes=2 * 1024**2), legacy_source_sha256=None
                )
                owner = catalog.claim_daemon_owner("settings-buffer-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate("buffer-operation", "buffer-operation-key"),
                    owner,
                    admission_open=True,
                )
                current = catalog.get_application_settings()
                catalog.update_application_settings(
                    {
                        "capacity_reserve_bytes": current["capacity_reserve_bytes"],
                        "minimum_source_file_age_seconds": current[
                            "minimum_source_file_age_seconds"
                        ],
                        "copy_buffer_bytes": 8 * 1024**2,
                        "content_verification_policy": current[
                            "content_verification_policy"
                        ],
                        "default_media_profile": current["default_media_profile"],
                        "tape_root_directory": current["tape_root_directory"],
                    },
                    expected_revision=current["revision"],
                    actor="admin",
                    idempotency_key="buffer-settings-update",
                    request_sha256="e" * 64,
                )
                stored = catalog.get_operation("buffer-operation")

            self.assertFalse(admitted.replayed)
            self.assertEqual(2 * 1024**2, stored["copy_buffer_bytes"])


class NativeResetCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "catalog.db"
        self.sources = (self.root / "Film", self.root / "Anime")
        for source in self.sources:
            source.mkdir()
        with Catalog(self.database) as catalog:
            catalog.initialize()
            catalog.add_library("01", "Film", str(self.sources[0]))
            catalog.add_library("02", "Anime", str(self.sources[1]))
            catalog.create_automatic_job(
                "JOB-OLD",
                "01",
                "/dev/tape/by-id/drive-nst",
                "/mnt/tape",
                [("TAPE01", "TAPE01", 1, 10), ("TAPE02", "TAPE02", 1, 20)],
                library_ids=["01", "02"],
                force_format=True,
            )
            owner = catalog.claim_daemon_owner("daemon-native-reset")
            operation = OperationRecord(
                id="operation-native-reset",
                kind="catalog.reset_create",
                state="running",
                phase=None,
                idempotency_key="native-reset-1",
                principal="admin",
                job_id="NATIVE-20260825-000000-abcdef01",
                cassette_sequence=None,
                started_at="2026-08-25T00:00:00+00:00",
                finished_at=None,
            )
            catalog.admit_operation(operation, owner, admission_open=True)
            self.fence = OperationFence(operation.id, owner.generation)

    def test_reset_preserves_history_and_creates_fresh_label_namespace(self) -> None:
        new_job_id = "NATIVE-20260825-000000-abcdef01"
        with Catalog(self.database) as catalog:
            catalog.update_incremental_policy(
                "JOB-OLD",
                "daily",
                expected_revision=1,
                updated_at="2026-08-25T00:00:00+00:00",
            )
            catalog.reset_and_create_native_job(
                self.fence,
                expected_job_id="JOB-OLD",
                job_id=new_job_id,
                display_name="Backup completo",
                source_roots=self.sources,
                device_name="/dev/tape/by-id/drive-nst",
                mount_path="/mnt/tape",
                labels=("TAPE01", "TAPE02"),
            )

            old = catalog.get_automatic_job("JOB-OLD")
            new = catalog.get_automatic_job(new_job_id)
            old_cassettes = catalog.list_automatic_cassettes("JOB-OLD")
            new_cassettes = catalog.list_automatic_cassettes(new_job_id)
            new_libraries = catalog.list_automatic_job_libraries(new_job_id)
            old_policy = dict(catalog.connection.execute(
                "SELECT * FROM job_incremental_policies WHERE job_id='JOB-OLD'"
            ).fetchone())
            new_policy = catalog.incremental_policy(new_job_id)
            new_epoch = catalog.latest_layout_epoch(new_job_id)

        self.assertEqual("failed", old["status"])
        self.assertEqual(["failed", "failed"], [row["status"] for row in old_cassettes])
        self.assertEqual("planned", new["status"])
        self.assertEqual("Backup completo", new["display_name"])
        self.assertEqual(
            [("TAPE01", "TAPE01"), ("TAPE02", "TAPE02")],
            [(row["physical_label"], row["tape_serial"]) for row in new_cassettes],
        )
        self.assertEqual(2, len(new_libraries))
        self.assertEqual("off", old_policy["cadence"])
        self.assertIsNone(old_policy["next_eligible_at"])
        self.assertEqual("off", new_policy["cadence"])
        self.assertEqual((1, "initial"), (new_epoch["epoch_number"], new_epoch["kind"]))
        self.assertTrue(
            all(row["library_id"].startswith(new_job_id) for row in new_libraries)
        )

    def test_reset_preserves_the_legacy_fallback_library_name_in_persisted_state(self) -> None:
        new_job_id = "NATIVE-20260825-000000-abcdef01"
        with Catalog(self.database) as catalog:
            catalog.reset_and_create_native_job(
                self.fence,
                expected_job_id="JOB-OLD",
                job_id=new_job_id,
                display_name="Backup completo",
                source_roots=(Path("/"),),
                device_name="/dev/tape/by-id/drive-nst",
                mount_path="/mnt/tape",
                labels=("TAPE01",),
            )
            library = catalog.get_library(f"{new_job_id}-L01")

        self.assertEqual("Sorgente 1", library["name"])

    def test_reset_target_race_rolls_back_every_change(self) -> None:
        with Catalog(self.database) as catalog:
            with self.assertRaises(CatalogError):
                catalog.reset_and_create_native_job(
                    self.fence,
                    expected_job_id="JOB-WRONG",
                    job_id="NATIVE-20260825-000000-abcdef01",
                    display_name="Backup completo",
                    source_roots=self.sources,
                    device_name="/dev/tape/by-id/drive-nst",
                    mount_path="/mnt/tape",
                    labels=("TAPE01",),
                )
            self.assertEqual("planned", catalog.get_automatic_job("JOB-OLD")["status"])
            self.assertEqual(1, len(catalog.list_automatic_jobs()))

    def test_reset_commits_a_complete_preflighted_plan_atomically(self) -> None:
        new_job_id = "NATIVE-20260825-000000-abcdef01"
        planned = (
            (
                1,
                2,
                30,
                (
                    (f"{new_job_id}-L01", "film-a.mkv", 10, 100),
                    (f"{new_job_id}-L02", "anime-a.mkv", 20, 200),
                ),
            ),
            (2, 0, 0, ()),
        )
        with Catalog(self.database) as catalog:
            catalog.reset_and_create_native_job(
                self.fence,
                expected_job_id="JOB-OLD",
                job_id=new_job_id,
                display_name="Backup completo",
                source_roots=self.sources,
                device_name="/dev/tape/by-id/drive-nst",
                mount_path="/mnt/tape",
                labels=("TAPE01", "TAPE02"),
                planned_cassettes=planned,
            )
            cassettes = catalog.list_automatic_cassettes(new_job_id)
            manifest = catalog.list_automatic_cassette_manifest(new_job_id, 1)

        self.assertEqual(
            (2, 30), (cassettes[0]["planned_files"], cassettes[0]["planned_bytes"])
        )
        self.assertEqual(
            (0, 0), (cassettes[1]["planned_files"], cassettes[1]["planned_bytes"])
        )
        self.assertEqual(
            ["film-a.mkv", "anime-a.mkv"], [row["relative_path"] for row in manifest]
        )

    def test_invalid_preflighted_plan_does_not_supersede_old_job(self) -> None:
        new_job_id = "NATIVE-20260825-000000-abcdef01"
        with Catalog(self.database) as catalog:
            with self.assertRaises(ValidationError):
                catalog.reset_and_create_native_job(
                    self.fence,
                    expected_job_id="JOB-OLD",
                    job_id=new_job_id,
                    display_name="Backup completo",
                    source_roots=self.sources,
                    device_name="/dev/tape/by-id/drive-nst",
                    mount_path="/mnt/tape",
                    labels=("TAPE01", "TAPE02"),
                    planned_cassettes=((1, 1, 10, ()),),
                )
            self.assertEqual("planned", catalog.get_automatic_job("JOB-OLD")["status"])
            self.assertEqual(1, len(catalog.list_automatic_jobs()))



    def test_native_reset_freezes_source_change_policy_from_settings(self) -> None:
        new_job_id = "NATIVE-20260825-000000-abcdef01"
        with Catalog(self.database) as catalog:
            authority = catalog.import_application_settings_once(
                Settings(min_age_seconds=0), legacy_source_sha256=None
            )
            catalog.reset_and_create_native_job(
                self.fence,
                expected_job_id="JOB-OLD",
                job_id=new_job_id,
                display_name="Backup completo",
                source_roots=self.sources,
                device_name="/dev/tape/by-id/drive-nst",
                mount_path="/mnt/tape",
                labels=("TAPE01",),
                application_settings=authority,
            )
            policy = catalog.get_job_policy_snapshot(new_job_id)
        self.assertEqual("size_mtime_change", policy["source_change_detection_policy"])
class CatalogSearchQueryTests(unittest.TestCase):
    """Contract coverage for the schema-32, database-only catalog queries."""

    SHA_A = "a" * 64
    SHA_B = "b" * 64
    SHA_C = "c" * 64
    SHA_D = "d" * 64

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        source = root / "source"
        source.mkdir()
        self.catalog = Catalog(root / "catalog.db")
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        self.catalog.add_library("LIB1", "Library one", str(source))
        self.catalog.add_library("LIB2", "Library two", str(source))
        self.catalog.register_tape(
            "TAPE1", "SERIAL-A", "VOLUME-A", "LTFS", "/never-mounted", "NUMBER-A"
        )
        self.catalog.register_tape(
            "TAPE2", "SERIAL-B", "VOLUME-B", "LTFS", "/never-mounted", "NUMBER-B"
        )
        self.catalog.register_tape(
            "TAPE3", "SERIAL-C", "VOLUME-C", "LTFS", "/never-mounted", "NUMBER-C"
        )
        self.catalog.create_automatic_job(
            "JOB1",
            "LIB1",
            "/dev/never-opened",
            "/never-mounted",
            [("A00100", "SERIAL-A", 1, 100), ("B00100", "SERIAL-B", 2, 250)],
        )
        self.version_a = self._add_version(
            "BLOCK-A",
            "LIB1",
            "TAPE1",
            "shared/movie.mxf",
            100,
            self.SHA_A,
            "2026-08-20T10:00:00+00:00",
        )
        self.version_b = self._add_version(
            "BLOCK-B",
            "LIB1",
            "TAPE2",
            "shared/movie.mxf",
            200,
            self.SHA_B,
            "2026-08-21T10:00:00+00:00",
        )
        self.version_c = self._add_version(
            "BLOCK-B-CLIP",
            "LIB1",
            "TAPE2",
            "folder/clip.mxf",
            50,
            self.SHA_C,
            "2026-08-22T10:00:00+00:00",
        )
        self.version_d = self._add_version(
            "BLOCK-D",
            "LIB2",
            "TAPE3",
            "other/feature.mov",
            300,
            self.SHA_D,
            "2026-08-23T10:00:00+00:00",
        )
        self.catalog.update_automatic_cassette(
            "JOB1", 1, "completed", tape_id="TAPE1", block_id="BLOCK-A"
        )
        self.catalog.update_automatic_cassette(
            "JOB1", 2, "completed", tape_id="TAPE2", block_id="BLOCK-B"
        )
        hidden = self._add_version(
            "BLOCK-HIDDEN",
            "LIB1",
            "TAPE1",
            "hidden/never.mxf",
            400,
            self.SHA_D,
            "2026-08-24T10:00:00+00:00",
        )
        self.catalog.connection.execute(
            "UPDATE blocks SET visible=0 WHERE id='BLOCK-HIDDEN'"
        )
        self.catalog.connection.commit()
        self.hidden_version = hidden

    def _add_version(
        self,
        block_id: str,
        library_id: str,
        tape_id: str,
        relative_path: str,
        size: int,
        sha256: str,
        copied_at: str,
    ) -> int:
        self.catalog.create_block(
            block_id, library_id, tape_id, f".lto/{block_id}", 1, size
        )
        version_id = self.catalog.record_file_version(
            library_id,
            block_id,
            tape_id,
            relative_path,
            f".lto/{block_id}/files/{relative_path}",
            size,
            123,
            sha256,
            metadata={"metadata_state": "complete", "owner_name": "operator"},
        )
        self.catalog.complete_block(block_id)
        self.catalog.connection.execute(
            "UPDATE file_versions SET copied_at=? WHERE id=?", (copied_at, version_id)
        )
        self.catalog.connection.commit()
        return version_id

    def test_search_filters_each_supported_field_and_combines_them(self) -> None:
        cases = (
            ({"query": "movie"}, [self.version_b, self.version_a]),
            ({"library_id": "LIB2"}, [self.version_d]),
            ({"job_id": "JOB1"}, [self.version_b, self.version_a]),
            ({"cassette": "number-b"}, [self.version_c, self.version_b]),
            ({"cassette": "a00100"}, [self.version_a]),
            ({"cassette": "volume-b"}, [self.version_c, self.version_b]),
            ({"cassette": "serial-b"}, [self.version_c, self.version_b]),
            ({"sha256": self.SHA_B.upper()}, [self.version_b]),
            ({"min_size": 100, "max_size": 200}, [self.version_b, self.version_a]),
            (
                {
                    "copied_after": "2026-08-21T00:00:00+00:00",
                    "copied_before": "2026-08-22T23:59:59+00:00",
                },
                [self.version_c, self.version_b],
            ),
            (
                {
                    "query": "movie",
                    "library_id": "LIB1",
                    "job_id": "JOB1",
                    "cassette": "b00100",
                    "sha256": self.SHA_B,
                    "min_size": 200,
                    "max_size": 200,
                    "copied_after": "2026-08-21T00:00:00+00:00",
                    "copied_before": "2026-08-21T23:59:59+00:00",
                },
                [self.version_b],
            ),
        )
        for filters, expected_ids in cases:
            with self.subTest(filters=filters):
                page = self.catalog.search_file_versions(
                    include_history=True, **filters
                )
                self.assertEqual(expected_ids, [item["id"] for item in page["items"]])

    def test_search_returns_current_by_default_and_visible_history_on_request(
        self,
    ) -> None:
        current = self.catalog.search_file_versions(query="mxf")
        history = self.catalog.search_file_versions(query="mxf", include_history=True)

        self.assertEqual(
            [self.version_c, self.version_b], [item["id"] for item in current["items"]]
        )
        self.assertEqual(
            [self.version_c, self.version_b, self.version_a],
            [item["id"] for item in history["items"]],
        )
        self.assertEqual(
            [True, True, False], [item["is_current"] for item in history["items"]]
        )
        self.assertNotIn(self.hidden_version, [item["id"] for item in history["items"]])

    def test_search_uses_a_stable_opaque_keyset_cursor(self) -> None:
        first = self.catalog.search_file_versions(include_history=True, limit=2)
        second = self.catalog.search_file_versions(
            include_history=True, limit=2, cursor=first["next_cursor"]
        )

        self.assertEqual(
            [self.version_d, self.version_c], [item["id"] for item in first["items"]]
        )
        self.assertEqual(
            [self.version_b, self.version_a], [item["id"] for item in second["items"]]
        )
        self.assertIsNone(second["next_cursor"])
        with self.assertRaises(ValidationError):
            self.catalog.search_file_versions(cursor="not-a-cursor")

    def test_imported_comma_delimited_blocks_keep_job_attribution_boundary_safe(
        self,
    ) -> None:
        version_one = self._add_version(
            "BLOCK-1",
            "LIB1",
            "TAPE1",
            "imported/one.mxf",
            10,
            self.SHA_A,
            "2026-08-25T10:00:00+00:00",
        )
        version_ten = self._add_version(
            "BLOCK-10",
            "LIB1",
            "TAPE1",
            "imported/ten.mxf",
            10,
            self.SHA_A,
            "2026-08-24T10:00:00+00:00",
        )
        self.catalog.connection.execute(
            "UPDATE automatic_cassettes SET block_id='BLOCK-1,BLOCK-B' "
            "WHERE job_id='JOB1' AND sequence=1"
        )
        self.catalog.connection.commit()

        page = self.catalog.search_file_versions(
            query="imported", job_id="JOB1", include_history=True
        )
        matched = self.catalog.get_file_version(version_one)
        non_member = self.catalog.get_file_version(version_ten)

        self.assertEqual([version_one], [item["id"] for item in page["items"]])
        self.assertEqual("JOB1", matched["job_id"])
        self.assertEqual("JOB1", matched["job_display_name"])
        self.assertIsNone(non_member["job_id"])
        self.assertIsNone(non_member["job_display_name"])

    def test_browse_page_uses_sql_keyset_pagination_for_more_than_two_hundred_children(
        self,
    ) -> None:
        self.catalog.add_library(
            "LIBP",
            "Paged library",
            str(self.catalog.get_library("LIB1")["source_root"]),
        )
        self.catalog.create_block(
            "BLOCK-PAGED", "LIBP", "TAPE1", ".lto/paged", 201, 201
        )
        for index in range(201):
            relative_path = f"directory-{index:03d}/file.mxf"
            self.catalog.record_file_version(
                "LIBP",
                "BLOCK-PAGED",
                "TAPE1",
                relative_path,
                f".lto/paged/files/{relative_path}",
                1,
                index,
                f"{index:064x}",
            )
        self.catalog.complete_block("BLOCK-PAGED")

        browse_page = getattr(self.catalog, "browse_backup_children_page", None)
        self.assertIsNotNone(browse_page, "paged catalog browse is missing")
        first = browse_page("LIBP", limit=200)
        second = browse_page("LIBP", limit=200, cursor=first["next_cursor"])

        self.assertEqual(200, len(first["items"]))
        self.assertIsInstance(first["next_cursor"], str)
        self.assertEqual(1, len(second["items"]))
        self.assertIsNone(second["next_cursor"])
        self.assertEqual(
            [f"directory-{index:03d}" for index in range(201)],
            [item["name"] for item in first["items"] + second["items"]],
        )
        with self.assertRaises(ValidationError):
            self.catalog.browse_backup_children_page("LIBP", limit=201)

    def test_browse_page_keyset_retains_case_distinct_directory_siblings(self) -> None:
        self.catalog.add_library(
            "LIBC",
            "Case library",
            str(self.catalog.get_library("LIB1")["source_root"]),
        )
        self.catalog.create_block("BLOCK-CASE", "LIBC", "TAPE1", ".lto/case", 2, 2)
        for directory in ("Foo", "foo"):
            relative_path = f"{directory}/file.mxf"
            self.catalog.record_file_version(
                "LIBC",
                "BLOCK-CASE",
                "TAPE1",
                relative_path,
                f".lto/case/files/{relative_path}",
                1,
                1,
                ("a" if directory == "Foo" else "b") * 64,
            )
        self.catalog.complete_block("BLOCK-CASE")

        names: list[str] = []
        cursor = None
        while True:
            page = self.catalog.browse_backup_children_page(
                "LIBC", limit=1, cursor=cursor
            )
            names.extend(item["name"] for item in page["items"])
            cursor = page["next_cursor"]
            if cursor is None:
                break

        self.assertEqual(["Foo", "foo"], names)
        self.assertEqual(2, len(set(names)))

    def test_search_and_detail_expose_physical_label_only_when_attributed(self) -> None:
        page = self.catalog.search_file_versions(query="movie")
        attributed = self.catalog.get_file_version(self.version_b)
        legacy = self.catalog.get_file_version(self.version_d)

        self.assertEqual("B00100", page["items"][0]["physical_label"])
        self.assertEqual("B00100", attributed["physical_label"])
        self.assertIsNone(legacy["physical_label"])

    def test_version_detail_is_exact_and_hidden_versions_are_unavailable(self) -> None:
        detail = self.catalog.get_file_version(self.version_b)

        self.assertEqual(
            {
                "id": self.version_b,
                "library_id": "LIB1",
                "library_name": "Library one",
                "job_id": "JOB1",
                "job_display_name": "JOB1",
                "block_id": "BLOCK-B",
                "tape_id": "TAPE2",
                "cassette_number": "NUMBER-B",
                "relative_path": "shared/movie.mxf",
                "tape_relative_path": ".lto/BLOCK-B/files/shared/movie.mxf",
                "size": 200,
                "mtime_ns": 123,
                "sha256": self.SHA_B,
                "copied_at": "2026-08-21T10:00:00+00:00",
                "metadata_state": "complete",
                "is_current": True,
            }.items(),
            {
                key: detail[key]
                for key in (
                    "id",
                    "library_id",
                    "library_name",
                    "job_id",
                    "job_display_name",
                    "block_id",
                    "tape_id",
                    "cassette_number",
                    "relative_path",
                    "tape_relative_path",
                    "size",
                    "mtime_ns",
                    "sha256",
                    "copied_at",
                    "metadata_state",
                    "is_current",
                )
            }.items(),
        )
        with self.assertRaises(CatalogError):
            self.catalog.get_file_version(self.hidden_version)

    def test_search_rejects_invalid_ranges_and_unbounded_inputs(self) -> None:
        for filters in (
            {"limit": 0},
            {"limit": 201},
            {"min_size": -1},
            {"min_size": 2**63},
            {"min_size": 201, "max_size": 200},
            {"copied_after": "invalid"},
            {
                "copied_after": "2026-08-23T00:00:00+00:00",
                "copied_before": "2026-08-22T00:00:00+00:00",
            },
            {"query": "x" * 257},
        ):
            with self.subTest(filters=filters), self.assertRaises(ValidationError):
                self.catalog.search_file_versions(**filters)

    def test_search_and_browse_read_only_from_the_database(self) -> None:
        with patch(
            "ltobackup.catalog.require_ltfs_profile", side_effect=AssertionError
        ):
            page = self.catalog.search_file_versions(query="movie")
            children = self.catalog.browse_backup_children("LIB1", "shared")
            root_children = self.catalog.browse_backup_children("LIB1")

        self.assertEqual([self.version_b], [item["id"] for item in page["items"]])
        self.assertEqual(["movie.mxf"], [item["name"] for item in children])
        self.assertEqual(
            ["folder", "shared"],
            [item["name"] for item in root_children if item["kind"] == "directory"],
        )


class RecoveryAttemptLedgerTests(unittest.TestCase):
    STARTED_AT = "2026-08-28T09:00:00+00:00"
    OUTCOME_AT = "2026-08-28T09:00:01+00:00"
    NEXT_AT = "2026-08-28T09:00:03+00:00"

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.database = self.root / "catalog.db"
        self.catalog = Catalog(self.database)
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        self.catalog.add_library("recovery-library", "Recovery", str(self.root))
        self.catalog.create_automatic_job(
            "recovery-job",
            "recovery-library",
            "synthetic-drive",
            "/synthetic/mount",
            [("RC0001", "SERIAL-1", 1, 7)],
        )
        self.fence = self.catalog.claim_daemon_owner("recovery-daemon")
        self.catalog.admit_operation(
            operation_candidate(
                "recovery-operation",
                "recovery-key",
                job_id="recovery-job",
                cassette_sequence=1,
            ),
            self.fence,
            admission_open=True,
        )

    def _begin(self, attempt_number: int = 1):
        return self.catalog.begin_recovery_attempt(
            "recovery-operation",
            attempt_number,
            self.fence,
            trigger="daemon_restart",
            evidence_sha256="a" * 64,
            decision="retry_identification",
            recorded_at=self.STARTED_AT,
        )

    def _finish(
        self,
        attempt_number: int = 1,
        *,
        state: str = "retry_scheduled",
        evidence_sha256: str = "b" * 64,
        decision: str = "retry_identification",
        recorded_at: str = OUTCOME_AT,
        next_eligible_at: str | None = NEXT_AT,
    ):
        return self.catalog.finish_recovery_attempt(
            "recovery-operation",
            attempt_number,
            self.fence,
            state=state,
            evidence_sha256=evidence_sha256,
            decision=decision,
            recorded_at=recorded_at,
            next_eligible_at=next_eligible_at,
        )

    def test_restore_recovery_actions_are_durable_ledger_decisions(self) -> None:
        for attempt_number, decision in enumerate(
            (
                "prepare_restore_retry",
                "reconcile_restore_commit",
                "finalize_restore_control",
            ),
            1,
        ):
            with self.subTest(decision=decision):
                started = self.catalog.begin_recovery_attempt(
                    "recovery-operation",
                    attempt_number,
                    self.fence,
                    trigger="daemon_restart",
                    evidence_sha256=f"{attempt_number}" * 64,
                    decision=decision,
                    recorded_at=(
                        datetime.fromisoformat(self.STARTED_AT)
                        + timedelta(seconds=attempt_number)
                    ).isoformat(),
                )
                self.assertEqual(decision, started.started_decision)

    def test_restore_recovery_attempt_uses_restore_cassette_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "restore-catalog.db") as catalog:
                catalog.initialize()
                plan = seed_one_tape_two_item_restore_plan(catalog)
                run = catalog.create_restore_run(
                    str(plan["id"]), actor="operator-1",
                    idempotency_key="restore-recovery-run", request_sha256="e" * 64,
                )
                owner = catalog.claim_daemon_owner("restore-recovery-daemon")
                admitted = catalog.admit_operation(
                    operation_candidate(
                        "restore-recovery-operation", "restore-recovery-key",
                        kind="restore.cassette", job_id=str(run["id"]),
                        cassette_sequence=1,
                    ),
                    owner,
                    admission_open=True,
                    hardware_target=synthetic_target(),
                )

                started = catalog.begin_recovery_attempt(
                    admitted.record.id,
                    1,
                    owner,
                    trigger="daemon_restart",
                    evidence_sha256="f" * 64,
                    decision="enter_critical_quarantine",
                    recorded_at=self.STARTED_AT,
                )

                self.assertEqual("TAPE01", started.cassette_label)

    def _insert_raw_outcome(
        self,
        *,
        attempt_number: int = 1,
        job_id: str = "recovery-job",
        cassette_sequence: int = 1,
        cassette_label: str = "RC0001",
        trigger: str = "daemon_restart",
    ) -> None:
        self.catalog.connection.execute(
            "INSERT INTO recovery_attempt_events("
            "operation_id,attempt_number,event_sequence,job_id,cassette_sequence,"
            "cassette_label,trigger,evidence_sha256,decision,state,"
            "daemon_generation,recorded_at,next_eligible_at"
            ") VALUES(?,?,2,?,?,?,?,?,?,'failed_safe',?,?,NULL)",
            (
                "recovery-operation",
                attempt_number,
                job_id,
                cassette_sequence,
                cassette_label,
                trigger,
                "b" * 64,
                "retry_identification",
                self.fence.generation,
                self.OUTCOME_AT,
            ),
        )

    def _critical(self) -> None:
        self.catalog.finish_operation(
            OperationFence("recovery-operation", self.fence.generation),
            "recovery_required",
            error_class="operator_required",
            error_code="recovery_required",
        )
        self.catalog.begin_recovery_attempt(
            "recovery-operation",
            1,
            self.fence,
            trigger="daemon_restart",
            evidence_sha256="a" * 64,
            decision="enter_critical_quarantine",
            recorded_at=self.STARTED_AT,
        )
        self.catalog.finish_recovery_attempt(
            "recovery-operation",
            1,
            self.fence,
            state="critical_quarantine",
            evidence_sha256="b" * 64,
            decision="enter_critical_quarantine",
            recorded_at=self.OUTCOME_AT,
        )

    def test_critical_reassessment_consumes_every_key_once_and_audits_atomically(
        self,
    ) -> None:
        target = synthetic_target()
        observed = sha256_fixture("critical-reassessment-observed")
        self.catalog.connection.execute(
            "INSERT INTO operation_hardware_targets VALUES(?,?,?,?,?,?)",
            (
                "recovery-operation",
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                self.STARTED_AT,
            ),
        )
        self.catalog.connection.execute(
            "INSERT INTO hardware_command_executions("
            "id,operation_id,issued_generation,command_kind,argv_sha256,"
            "mount_path_sha256,tape_device_identity_sha256,"
            "scsi_device_identity_sha256,expected_media_scope_sha256,"
            "observed_media_identity_sha256,state,exit_outcome,created_at,"
            "exit_observed_at,quiesced_at) VALUES(?,?,?,?,?,?,?,?,?,?,"
            "'quiesced','completed',?,?,?)",
            (
                "critical-reassessment-probe",
                "recovery-operation",
                self.fence.generation,
                "probe_media",
                "1" * 64,
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                observed,
                self.STARTED_AT,
                self.STARTED_AT,
                self.STARTED_AT,
            ),
        )
        self.catalog.connection.execute(
            "INSERT INTO operation_media_identity_bindings VALUES(?,?,?,?)",
            (
                "recovery-operation",
                observed,
                "critical-reassessment-probe",
                self.STARTED_AT,
            ),
        )
        self.catalog.connection.commit()
        self._critical()
        observed_at = datetime.now(UTC).isoformat()
        identity = {
            "job_id": "recovery-job",
            "cassette_sequence": 1,
            "expected_label": "RC0001",
            "expected_daemon_generation": self.fence.generation,
            "target": target,
            "observed_media_identity_sha256": observed,
            "observation": CriticalRecoveryObservation(
                operation_id="recovery-operation",
                daemon_generation=self.fence.generation,
                target=target,
                bound_media_identity_sha256=observed,
                observed_media_identity_sha256=None,
                command_ledger_sha256=critical_command_ledger_sha256(
                    self.catalog.hardware_commands_for_operation(
                        "recovery-operation"
                    )
                ),
                commands_quiescent=True,
                mounted=False,
                media_loaded=False,
                drive_busy=False,
                related_process_count=0,
                evidence_category="media_identity_mismatch",
                evidence_sha256="c" * 64,
                observed_at=observed_at,
            ),
            "consumed_at": observed_at,
        }

        self.catalog.record_critical_reassessment(
            "recovery-operation",
            self.fence,
            principal="web-user-1",
            idempotency_key="critical-reconcile-1",
            **identity,
            attempt_number=1,
            evidence_sha256="b" * 64,
        )

        with self.assertRaisesRegex(CatalogError, "one-shot"):
            self.catalog.record_critical_reassessment(
                "recovery-operation",
                self.fence,
                principal="web-user-1",
                idempotency_key="critical-reconcile-1",
                **identity,
                attempt_number=1,
                evidence_sha256="b" * 64,
            )
        accepted = self.catalog.connection.execute(
            "SELECT * FROM audit_entries WHERE request_id='critical-reconcile-1'"
        ).fetchall()
        self.assertEqual(1, len(accepted))
        self.assertEqual("accepted", accepted[0]["result"])

        with self.assertRaisesRegex(CatalogError, "mismatched"):
            self.catalog.record_critical_reassessment(
                "recovery-operation",
                self.fence,
                principal="web-user-1",
                idempotency_key="critical-reconcile-wrong-label",
                **{**identity, "expected_label": "WRONG1"},
                attempt_number=1,
                evidence_sha256="b" * 64,
            )
        self.assertEqual(
            "rejected",
            self.catalog.connection.execute(
                "SELECT result FROM audit_entries "
                "WHERE request_id='critical-reconcile-wrong-label'"
            ).fetchone()[0],
        )

        with patch.object(
            Catalog, "_record_audit_tx", side_effect=RuntimeError("audit failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "audit failed"):
                self.catalog.record_critical_reassessment(
                    "recovery-operation",
                    self.fence,
                    principal="web-user-1",
                    idempotency_key="critical-reconcile-rollback",
                    **identity,
                    attempt_number=1,
                    evidence_sha256="c" * 64,
                )
        self.catalog.record_critical_reassessment(
            "recovery-operation",
            self.fence,
            principal="web-user-1",
            idempotency_key="critical-reconcile-rollback",
            **identity,
            attempt_number=1,
            evidence_sha256="c" * 64,
        )

    def test_critical_abandon_requires_exact_quiescence_and_rolls_back_with_audit(
        self,
    ) -> None:
        target = synthetic_target()
        observed = sha256_fixture("critical-observed")
        generation = self.fence.generation
        self.catalog.connection.execute(
            "INSERT INTO operation_hardware_targets VALUES(?,?,?,?,?,?)",
            (
                "recovery-operation",
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                "2026-08-28T08:59:00+00:00",
            ),
        )
        self.catalog.connection.execute(
            "INSERT INTO hardware_command_executions("
            "id,operation_id,issued_generation,command_kind,argv_sha256,"
            "mount_path_sha256,tape_device_identity_sha256,"
            "scsi_device_identity_sha256,expected_media_scope_sha256,"
            "observed_media_identity_sha256,state,exit_outcome,created_at,"
            "exit_observed_at,quiesced_at) VALUES(?,?,?,?,?,?,?,?,?,?,"
            "'quiesced','completed',?,?,?)",
            (
                "critical-command",
                "recovery-operation",
                generation,
                "probe_media",
                "1" * 64,
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                observed,
                "2026-08-28T08:59:01+00:00",
                "2026-08-28T08:59:02+00:00",
                "2026-08-28T08:59:03+00:00",
            ),
        )
        self.catalog.connection.execute(
            "INSERT INTO operation_media_identity_bindings VALUES(?,?,?,?)",
            (
                "recovery-operation",
                observed,
                "critical-command",
                "2026-08-28T08:59:04+00:00",
            ),
        )
        self.catalog.connection.execute(
            "INSERT INTO command_quiescence_receipts VALUES(?,?,?,?)",
            (
                "critical-command-receipt",
                "recovery-operation",
                generation,
                "2026-08-28T08:59:05+00:00",
            ),
        )
        self.catalog.connection.execute(
            "INSERT INTO command_quiescence_receipt_items VALUES(?,?,?)",
            ("critical-command-receipt", "critical-command", "completed"),
        )
        self.catalog.connection.execute(
            "INSERT INTO physical_reconciliation_receipts VALUES(?,?,?,?,?,?,?,?,?,"
            "0,0,0,0,?)",
            (
                "critical-physical-receipt",
                "recovery-operation",
                generation,
                "critical-command-receipt",
                target.mount_path_sha256,
                target.tape_device_identity_sha256,
                target.scsi_device_identity_sha256,
                target.expected_media_scope_sha256,
                observed,
                "2026-08-28T08:59:06+00:00",
            ),
        )
        self.catalog.connection.commit()
        self._critical()
        action_observed_at = datetime.now(UTC).isoformat()
        identity = {
            "job_id": "recovery-job",
            "cassette_sequence": 1,
            "expected_label": "RC0001",
            "expected_daemon_generation": self.fence.generation,
            "attempt_number": 1,
            "evidence_sha256": "b" * 64,
            "target": target,
            "observed_media_identity_sha256": observed,
            "observation": CriticalRecoveryObservation(
                operation_id="recovery-operation",
                daemon_generation=self.fence.generation,
                target=target,
                bound_media_identity_sha256=observed,
                observed_media_identity_sha256=None,
                command_ledger_sha256=critical_command_ledger_sha256(
                    self.catalog.hardware_commands_for_operation(
                        "recovery-operation"
                    )
                ),
                commands_quiescent=True,
                mounted=False,
                media_loaded=False,
                drive_busy=False,
                related_process_count=0,
                evidence_category="identification_retry_safe",
                evidence_sha256="d" * 64,
                observed_at=action_observed_at,
            ),
            "consumed_at": action_observed_at,
        }

        with self.assertRaisesRegex(CatalogError, "mismatched"):
            self.catalog.abandon_critical_attempt(
                "recovery-operation",
                self.fence,
                principal="web-user-1",
                idempotency_key="critical-abandon-wrong-label",
                **{**identity, "expected_label": "WR0001"},
            )
        self.assertEqual(
            "recovery_required",
            self.catalog.get_operation("recovery-operation")["state"],
        )

        with self.assertRaisesRegex(CatalogError, "mismatched"):
            self.catalog.abandon_critical_attempt(
                "recovery-operation",
                self.fence,
                principal="web-user-1",
                idempotency_key="critical-abandon-stale-generation",
                **{
                    **identity,
                    "expected_daemon_generation": self.fence.generation + 1,
                },
            )
        self.assertEqual(
            "recovery_required",
            self.catalog.get_operation("recovery-operation")["state"],
        )

        with patch.object(
            Catalog, "_record_audit_tx", side_effect=RuntimeError("audit failed")
        ):
            with self.assertRaisesRegex(RuntimeError, "audit failed"):
                self.catalog.abandon_critical_attempt(
                    "recovery-operation",
                    self.fence,
                    principal="web-user-1",
                    idempotency_key="critical-abandon-rollback",
                    **identity,
                )
        self.assertEqual(
            "recovery_required",
            self.catalog.get_operation("recovery-operation")["state"],
        )
        abandoned = self.catalog.abandon_critical_attempt(
            "recovery-operation",
            self.fence,
            principal="web-user-1",
            idempotency_key="critical-abandon-rollback",
            **identity,
        )
        self.assertEqual("failed", abandoned.state)

    def test_schema_thirty_three_migrates_schema_thirty_two_without_data_loss(
        self,
    ) -> None:
        database = self.root / "schema-32.db"
        with Catalog(database) as catalog:
            catalog.initialize(target_version=32)
            catalog.add_library("legacy-library", "Legacy", str(self.root))
            before = dict(catalog.get_named_library("legacy-library"))

        with Catalog(database) as catalog:
            initialize_current_with_protected_backup(catalog, database.parent)
            table_info = tuple(
                catalog.connection.execute(
                    "PRAGMA table_info(recovery_attempt_events)"
                )
            )
            columns = {row["name"] for row in table_info}
            primary_key = tuple(
                row["name"]
                for row in sorted(table_info, key=lambda row: row["pk"])
                if row["pk"]
            )
            after = dict(catalog.get_named_library("legacy-library"))

        self.assertEqual(41, SCHEMA_VERSION)
        self.assertEqual("41", read_schema_version(database))
        self.assertEqual(before, after)
        self.assertEqual(
            ("operation_id", "attempt_number", "event_sequence"), primary_key
        )
        self.assertTrue(
            {
                "job_id",
                "cassette_sequence",
                "cassette_label",
                "trigger",
                "evidence_sha256",
                "decision",
                "state",
                "daemon_generation",
                "recorded_at",
                "next_eligible_at",
            }
            <= columns
        )
        self.assertEqual(["ok"], integrity_check(database))
        self.assertEqual([], foreign_key_violations(database))

    def test_schema_thirty_four_adds_native_attempt_ownership_additively(
        self,
    ) -> None:
        database = self.root / "schema-33.db"
        with Catalog(database) as catalog:
            catalog.initialize(target_version=33)
            catalog.add_library("legacy-library", "Legacy", str(self.root))
            before = dict(catalog.get_named_library("legacy-library"))

        with Catalog(database) as catalog:
            initialize_current_with_protected_backup(catalog, database.parent)
            after = dict(catalog.get_named_library("legacy-library"))
            tables = {
                str(row[0])
                for row in catalog.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            triggers = {
                str(row[0])
                for row in catalog.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger'"
                )
            }
            operation_block_columns = {
                str(row["name"])
                for row in catalog.connection.execute(
                    "PRAGMA table_info(automatic_operation_blocks)"
                )
            }
            operation_block_tombstone_columns = {
                str(row["name"])
                for row in catalog.connection.execute(
                    "PRAGMA table_info(automatic_operation_block_tombstones)"
                )
            }
            dispatch_columns = {
                str(row["name"])
                for row in catalog.connection.execute(
                    "PRAGMA table_info(native_recovery_dispatches)"
                )
            }

        self.assertEqual("41", read_schema_version(database))
        self.assertEqual(before, after)
        self.assertIn("automatic_operation_blocks", tables)
        self.assertIn("automatic_operation_block_tombstones", tables)
        self.assertIn("native_recovery_dispatches", tables)
        self.assertEqual(
            {
                "block_id",
                "operation_id",
                "job_id",
                "cassette_sequence",
                "created_at",
            },
            operation_block_columns,
        )
        self.assertEqual(
            {
                "block_id",
                "operation_id",
                "job_id",
                "cassette_sequence",
                "daemon_generation",
                "created_at",
                "disposition",
                "archived_at",
            },
            operation_block_tombstone_columns,
        )
        self.assertEqual(
            {
                "operation_id",
                "owner_generation",
                "state",
                "admitted_at",
                "started_at",
                "finished_at",
            },
            dispatch_columns,
        )
        self.assertTrue(
            {
                "trg_automatic_operation_blocks_no_update",
                "trg_automatic_operation_blocks_no_delete",
                "trg_automatic_operation_block_tombstones_no_update",
                "trg_automatic_operation_block_tombstones_no_delete",
            }
            <= triggers
        )
        self.assertEqual(["ok"], integrity_check(database))
        self.assertEqual([], foreign_key_violations(database))

    def test_schema_thirty_four_repairs_pre_compatibility_lifecycle_layout(
        self,
    ) -> None:
        self.catalog.register_tape(
            "RC0001",
            "SERIAL-1",
            "RC0001",
            "LTFS",
            "/synthetic/mount",
        )
        self.catalog.create_block(
            "legacy-operation-block",
            "recovery-library",
            "RC0001",
            "blocks/legacy-operation-block",
            1,
            7,
        )
        self.catalog.connection.execute(
            "INSERT INTO automatic_operation_blocks("
            "block_id,operation_id,job_id,cassette_sequence,created_at) "
            "VALUES('legacy-operation-block','recovery-operation',"
            "'recovery-job',1,'2026-08-28T09:00:00+00:00')"
        )
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_blocks_no_delete"
        )
        self.catalog.connection.execute(
            "CREATE TRIGGER trg_automatic_operation_blocks_no_delete "
            "BEFORE DELETE ON automatic_operation_blocks "
            "BEGIN SELECT RAISE(ABORT,'immutable_automatic_operation_block'); END"
        )
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_block_tombstones_no_update"
        )
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_block_tombstones_no_delete"
        )
        self.catalog.connection.execute(
            "DROP TABLE automatic_operation_block_tombstones"
        )
        self.catalog.connection.commit()

        self.catalog.initialize()

        table = self.catalog.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='automatic_operation_block_tombstones'"
        ).fetchone()
        trigger = self.catalog.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' "
            "AND name='trg_automatic_operation_blocks_no_delete'"
        ).fetchone()
        triggers = {
            str(row[0])
            for row in self.catalog.connection.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'"
            )
        }

        self.assertIsNotNone(table)
        self.assertIn("lto_operation_block_archive_active", str(trigger["sql"]))
        self.assertTrue(
            {
                "trg_automatic_operation_block_tombstones_no_update",
                "trg_automatic_operation_block_tombstones_no_delete",
            }
            <= triggers
        )
        repaired = self.catalog.connection.execute(
            "SELECT block_id,operation_id,job_id,cassette_sequence,created_at "
            "FROM automatic_operation_blocks"
        ).fetchone()
        self.assertEqual(
            (
                "legacy-operation-block",
                "recovery-operation",
                "recovery-job",
                1,
                "2026-08-28T09:00:00+00:00",
            ),
            tuple(repaired),
        )
        self.assertEqual("41", read_schema_version(self.database))
        self.assertEqual(["ok"], integrity_check(self.database))
        self.assertEqual([], foreign_key_violations(self.database))

    def test_schema_thirty_four_expands_lifecycle_dispositions_without_data_loss(
        self,
    ) -> None:
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_blocks_no_delete"
        )
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_block_tombstones_insert_controlled"
        )
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_block_tombstones_no_update"
        )
        self.catalog.connection.execute(
            "DROP TRIGGER trg_automatic_operation_block_tombstones_no_delete"
        )
        self.catalog.connection.execute(
            "DROP TABLE automatic_operation_block_tombstones"
        )
        self.catalog.connection.execute(
            "CREATE TABLE automatic_operation_block_tombstones("
            "block_id TEXT PRIMARY KEY,operation_id TEXT NOT NULL,"
            "job_id TEXT NOT NULL COLLATE NOCASE,cassette_sequence INTEGER NOT NULL,"
            "daemon_generation INTEGER NOT NULL,created_at TEXT NOT NULL,"
            "disposition TEXT NOT NULL CHECK(disposition IN ("
            "'job_deleted','registered_tape_reformatted')),archived_at TEXT NOT NULL)"
        )
        legacy = (
            "legacy-block",
            "legacy-operation",
            "legacy-job",
            7,
            3,
            "2026-08-28T08:00:00+00:00",
            "job_deleted",
            "2026-08-28T09:00:00+00:00",
        )
        self.catalog.connection.execute(
            "INSERT INTO automatic_operation_block_tombstones VALUES(?,?,?,?,?,?,?,?)",
            legacy,
        )
        self.catalog.connection.commit()

        self.catalog.initialize()

        table = self.catalog.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='automatic_operation_block_tombstones'"
        ).fetchone()
        retained = self.catalog.connection.execute(
            "SELECT * FROM automatic_operation_block_tombstones "
            "WHERE block_id='legacy-block'"
        ).fetchone()
        self.assertIn("registered_tape_reset", str(table["sql"]))
        self.assertIn("registered_tape_recovery_reset", str(table["sql"]))
        self.assertEqual(legacy, tuple(retained))
        self.assertEqual(["ok"], integrity_check(self.database))
        self.assertEqual([], foreign_key_violations(self.database))

    def test_begin_finish_exact_replay_and_folded_listing(self) -> None:
        started = self._begin()
        self.assertEqual(started, self._begin())
        self.assertEqual("started", started.state)
        self.assertEqual("recovery-job", started.job_id)
        self.assertEqual(1, started.cassette_sequence)
        self.assertEqual("RC0001", started.cassette_label)
        self.assertEqual(self.STARTED_AT, started.started_at)
        self.assertIsNone(started.outcome_at)

        finished = self._finish()
        self.assertEqual(finished, self._finish())
        self.assertEqual("retry_scheduled", finished.state)
        self.assertEqual("b" * 64, finished.evidence_sha256)
        self.assertEqual(self.OUTCOME_AT, finished.outcome_at)
        self.assertEqual(self.NEXT_AT, finished.next_eligible_at)
        self.assertEqual((finished,), self.catalog.list_recovery_attempts())
        self.assertEqual(
            (finished,),
            self.catalog.list_recovery_attempts("recovery-operation"),
        )
        rows = self.catalog.connection.execute(
            "SELECT event_sequence,state,job_id,cassette_sequence,cassette_label,"
            "trigger FROM recovery_attempt_events ORDER BY event_sequence"
        ).fetchall()
        self.assertEqual([1, 2], [row["event_sequence"] for row in rows])
        self.assertEqual(["started", "retry_scheduled"], [row["state"] for row in rows])
        self.assertTrue(
            all(
                (row["job_id"], row["cassette_sequence"], row["cassette_label"])
                == ("recovery-job", 1, "RC0001")
                for row in rows
            )
        )
        self.assertTrue(all(row["trigger"] == "daemon_restart" for row in rows))

    def test_claim_recovery_attempt_has_one_owner_across_clock_skew(self) -> None:
        first = self.catalog.claim_recovery_attempt(
            "recovery-operation",
            1,
            self.fence,
            trigger="daemon_restart",
            evidence_sha256="a" * 64,
            decision="retry_identification",
            recorded_at=self.STARTED_AT,
        )
        replay = self.catalog.claim_recovery_attempt(
            "recovery-operation",
            1,
            self.fence,
            trigger="daemon_restart",
            evidence_sha256="a" * 64,
            decision="retry_identification",
            recorded_at="2026-08-28T09:00:00.000001+00:00",
        )

        self.assertTrue(first.owned)
        self.assertFalse(replay.owned)
        self.assertEqual(first.attempt, replay.attempt)
        self.assertEqual(self.STARTED_AT, replay.attempt.started_at)

    def test_conflicting_begin_or_finish_replay_is_rejected(self) -> None:
        self._begin()
        with self.assertRaises(CatalogError):
            self.catalog.begin_recovery_attempt(
                "recovery-operation",
                1,
                self.fence,
                trigger="manual_resume",
                evidence_sha256="a" * 64,
                decision="retry_identification",
                recorded_at=self.STARTED_AT,
            )
        self._finish()
        with self.assertRaises(CatalogError):
            self._finish(
                state="failed_safe",
                decision="retry_identification",
                next_eligible_at=None,
            )
        self.assertEqual(2, self.catalog.connection.execute(
            "SELECT COUNT(*) FROM recovery_attempt_events"
        ).fetchone()[0])

    def test_finish_requires_begin_and_current_daemon_fence(self) -> None:
        with self.assertRaises(CatalogError):
            self._finish()
        self._begin()
        replacement = self.catalog.claim_daemon_owner("replacement-daemon")
        with self.assertRaises(StaleDaemonFence):
            self._finish()
        with self.assertRaises(StaleDaemonFence):
            self.catalog.begin_recovery_attempt(
                "recovery-operation",
                2,
                self.fence,
                trigger="daemon_restart",
                evidence_sha256="a" * 64,
                decision="retry_identification",
                recorded_at=self.STARTED_AT,
            )
        self.assertEqual(2, replacement.generation)

    def test_invalid_attempt_payloads_are_rejected_without_rows(self) -> None:
        invalid_begin = (
            {"attempt_number": 0},
            {"trigger": "x" * 129},
            {"evidence_sha256": "A" * 64},
            {"decision": "arbitrary_shell_command"},
            {"recorded_at": "2026-08-28T09:00:00"},
        )
        for overrides in invalid_begin:
            with self.subTest(overrides=overrides), self.assertRaises(ValidationError):
                arguments = {
                    "attempt_number": 1,
                    "trigger": "daemon_restart",
                    "evidence_sha256": "a" * 64,
                    "decision": "retry_identification",
                    "recorded_at": self.STARTED_AT,
                }
                arguments.update(overrides)
                self.catalog.begin_recovery_attempt(
                    "recovery-operation",
                    arguments.pop("attempt_number"),
                    self.fence,
                    **arguments,
                )
        self.assertEqual((), self.catalog.list_recovery_attempts())

    def test_invalid_outcome_state_digest_and_timestamps_are_rejected(self) -> None:
        self._begin()
        cases = (
            {"state": "started", "next_eligible_at": None},
            {"state": "unknown", "next_eligible_at": None},
            {"evidence_sha256": "B" * 64},
            {"recorded_at": self.STARTED_AT},
            {"recorded_at": "2026-08-28T09:00:01"},
            {"state": "retry_scheduled", "next_eligible_at": None},
            {"state": "succeeded", "next_eligible_at": self.NEXT_AT},
            {
                "state": "retry_scheduled",
                "next_eligible_at": "2026-08-28T08:59:59+00:00",
            },
            {
                "state": "retry_scheduled",
                "next_eligible_at": "2026-08-28T09:00:03."
                + "1" * 65
                + "+00:00",
            },
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(ValidationError):
                arguments = {
                    "state": "retry_scheduled",
                    "evidence_sha256": "b" * 64,
                    "decision": "retry_identification",
                    "recorded_at": self.OUTCOME_AT,
                    "next_eligible_at": self.NEXT_AT,
                }
                arguments.update(overrides)
                self._finish(**arguments)
        self.assertEqual("started", self.catalog.list_recovery_attempts()[0].state)

    def test_event_history_rejects_update_and_delete(self) -> None:
        self._begin()
        self._finish()
        for statement in (
            "UPDATE recovery_attempt_events SET decision='retry_unload'",
            "DELETE FROM recovery_attempt_events",
        ):
            with self.subTest(statement=statement), self.assertRaises(sqlite3.IntegrityError):
                self.catalog.connection.execute(statement)
        self.assertEqual(2, self.catalog.connection.execute(
            "SELECT COUNT(*) FROM recovery_attempt_events"
        ).fetchone()[0])

    def test_raw_outcome_cannot_precede_its_start_event(self) -> None:
        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_raw_outcome()

        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM recovery_attempt_events"
            ).fetchone()[0],
        )

    def test_raw_outcome_requires_exact_immutable_start_identity(self) -> None:
        self._begin()
        cases = (
            {"attempt_number": 2},
            {"job_id": "different-job"},
            {"cassette_sequence": 2, "cassette_label": "RC0002"},
            {"cassette_label": "RC9999"},
            {"trigger": "different_trigger"},
        )
        for overrides in cases:
            with self.subTest(overrides=overrides), self.assertRaises(
                sqlite3.IntegrityError
            ):
                self._insert_raw_outcome(**overrides)

        rows = self.catalog.connection.execute(
            "SELECT event_sequence,state FROM recovery_attempt_events"
        ).fetchall()
        self.assertEqual([(1, "started")], [tuple(row) for row in rows])

    def test_current_schema_repairs_missing_outcome_identity_trigger(self) -> None:
        self.catalog.connection.execute(
            "DROP TRIGGER trg_recovery_attempt_events_outcome_requires_start"
        )
        self.catalog.connection.commit()
        self.catalog.close()
        self.catalog = Catalog(self.database)
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()

        with self.assertRaises(sqlite3.IntegrityError):
            self._insert_raw_outcome()

        self.assertEqual(
            0,
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM recovery_attempt_events"
            ).fetchone()[0],
        )

    def test_finished_attempt_survives_catalog_restart(self) -> None:
        self._begin()
        expected = self._finish()
        self.catalog.close()

        with Catalog(self.database) as catalog:
            catalog.initialize()
            self.assertEqual((expected,), catalog.list_recovery_attempts())


class SourceChangeSchemaMigrationTests(unittest.TestCase):
    def test_schema_40_requires_backup_and_preserves_legacy_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = build_frozen_job_fixture(
                root / "catalog.db", schema_version=40, completed=1, total=4
            )
            with Catalog(database) as catalog:
                catalog.import_application_settings_once(
                    Settings(min_age_seconds=0), legacy_source_sha256=None
                )
                versions_before = [
                    dict(row) for row in catalog.connection.execute(
                        "SELECT * FROM file_versions ORDER BY id"
                    )
                ]
                snapshots_before = [
                    tuple(row) for row in catalog.connection.execute(
                        "SELECT job_id,policy_json,policy_sha256 "
                        "FROM job_policy_snapshots ORDER BY job_id"
                    )
                ]
                self.assertTrue(versions_before)
                self.assertTrue(snapshots_before)
                with self.assertRaisesRegex(CatalogError, "protected backup"):
                    catalog.initialize(target_version=41)
            backups = root / "backups"
            BackupManager(database, backups, retention=5).prepare_and_initialize()
            self.assertEqual("41", read_schema_version(database))
            self.assertTrue(tuple(backups.glob("*.sqlite3")))
            with Catalog(database) as catalog:
                versions_after = [
                    dict(row) for row in catalog.connection.execute(
                        "SELECT * FROM file_versions ORDER BY id"
                    )
                ]
                snapshots_after = [
                    tuple(row) for row in catalog.connection.execute(
                        "SELECT job_id,policy_json,policy_sha256 "
                        "FROM job_policy_snapshots ORDER BY job_id"
                    )
                ]
                self.assertEqual(
                    versions_before,
                    [{key: row[key] for key in versions_before[0]} for row in versions_after],
                )
                self.assertTrue(all(row["source_change_ns"] is None for row in versions_after))
                self.assertEqual(snapshots_before, snapshots_after)
                self.assertEqual(
                    "size_mtime_change",
                    catalog.get_application_settings()["source_change_detection_policy"],
                )

    def test_new_file_version_persists_dedicated_change_time(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = build_frozen_job_fixture(
                Path(temporary) / "catalog.db",
                schema_version=41,
                completed=1,
                total=4,
            )
            with Catalog(database) as catalog:
                version_id = catalog.record_file_version(
                    "LIB1", "BLOCK01", "TAPE01", "added.bin",
                    "archive/files/added.bin", 7, 11, "a" * 64,
                    metadata={"source_change_ns": 123456789},
                )
                stored = catalog.connection.execute(
                    "SELECT source_change_ns FROM file_versions WHERE id=?",
                    (version_id,),
                ).fetchone()
                self.assertEqual(123456789, stored["source_change_ns"])

    def test_schema_41_failure_rolls_back_both_columns_and_retains_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database = build_frozen_job_fixture(
                root / "catalog.db", schema_version=40, completed=1, total=4
            )
            original = Catalog._migrate_v40_to_v41

            def fail_after_ddl(catalog: Catalog, db: sqlite3.Connection) -> None:
                original(catalog, db)
                raise CatalogError("injected migration failure")

            backups = root / "backups"
            with patch.object(Catalog, "_migrate_v40_to_v41", fail_after_ddl):
                with self.assertRaisesRegex(CatalogError, "injected migration failure"):
                    BackupManager(database, backups, retention=5).prepare_and_initialize()
            self.assertEqual("40", read_schema_version(database))
            self.assertTrue(tuple(backups.glob("*.sqlite3")))
            with sqlite3.connect(database) as connection:
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(file_versions)")
                }
                self.assertNotIn("source_change_ns", columns)
                self.assertEqual(["ok"], [row[0] for row in connection.execute("PRAGMA integrity_check")])



if __name__ == "__main__":
    unittest.main()
