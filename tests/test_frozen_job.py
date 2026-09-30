from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import ExitStack, closing, contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from ltobackup.application import LtoApplication
from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.archive_runtime import ProductionArchiveResume
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.frozen_job import (
    FrozenJobAssignmentChanged,
    FrozenJobAuthorityInvalid,
    FrozenJobNotImported,
    FrozenJobPlan,
    FrozenJobStateInvalid,
)
from ltobackup.daemon.incremental import IncrementalScanCoordinator
from ltobackup.daemon.management import ManagementService
from ltobackup.daemon.models import (
    CommandExitEvidence,
    CommandQuiescenceRequired,
    DaemonFence,
    HardwareTargetBinding,
    OperationFence,
    OperationRecord,
    ProcessIdentity,
    RecoveryCommandFence,
    SafeRecoveryResolution,
    StaleOperationFence,
    VerifiedPhysicalQuiescence,
    cutover_catalog_binding_sha256,
    expected_media_scope_sha256,
    imported_postcommit_command_sha256,
    imported_recovery_lineage_sha256,
)
from ltobackup.daemon.service import DaemonService
from ltobackup.errors import CatalogError, ValidationError
from ltobackup.linux_settings import LinuxPaths, LinuxSettings
from ltobackup.migration.validator import (
    MigrationValidator,
    ReadOnlyCatalog,
    canonical_cassette_plan_sha256,
)
from ltobackup.settings import Settings, save_settings
from tests.fixtures import build_frozen_job_fixture

PATH_FIXTURE = (
    ("Caffè/episodio.mkv", "Caffè/episodio.mkv"),
    ("I Flintstones /episode.mkv", "~lto1~I Flintstones%20/episode.mkv"),
    ("I Flintstones%20/episode.mkv", "I Flintstones%20/episode.mkv"),
    ("~lto1~literal/file.mkv", "~lto1~~lto1~literal/file.mkv"),
    ("CON.txt", "~lto1~CON.txt"),
)


@contextmanager
def _frozen_layout_consumption_guard():
    targets = {
        "application.analyze": "ltobackup.application.analyze_library",
        "scanner.analyze": "ltobackup.scanner.analyze_library",
        "scanner.scan": "ltobackup.scanner.scan_library",
        "engine.scan": "ltobackup.engine.BackupEngine.scan",
        "application.plan": "ltobackup.application._plan_ltfs_batches",
        "application.select": "ltobackup.application._select_ltfs_batch",
        "engine.plan": "ltobackup.engine.plan_tape_batches",
        "engine.select": "ltobackup.engine.select_tape_batch",
        "application.mapper": "ltobackup.application.ltfs_tape_relative_path",
        "catalog.mapper": "ltobackup.catalog.ltfs_tape_relative_path",
        "engine.mapper": "ltobackup.engine.ltfs_tape_relative_path",
        "archive.mapper": "ltobackup.daemon.archive_runner.ltfs_tape_relative_path",
    }
    spies = {
        name: mock.Mock(
            side_effect=AssertionError(f"frozen consumer crossed {name}")
        )
        for name in (
            *targets,
            "source.iterdir",
            "source.glob",
            "source.rglob",
            "source.scandir",
            "source.walk",
        )
    }
    with ExitStack() as stack:
        for name, target in targets.items():
            stack.enter_context(mock.patch(target, spies[name]))
        for name, owner, attribute in (
            ("source.iterdir", Path, "iterdir"),
            ("source.glob", Path, "glob"),
            ("source.rglob", Path, "rglob"),
            ("source.scandir", os, "scandir"),
            ("source.walk", os, "walk"),
        ):
            stack.enter_context(mock.patch.object(owner, attribute, spies[name]))
        yield spies


class FrozenJobPlanTests(unittest.TestCase):
    _FIXR6_SCHEMA14_FIXTURE = Path(__file__).parent / "fixtures" / "fixr6_schema14.sql"
    _FIXR6_SUCCEEDED_SCHEMA14_FIXTURE = (
        Path(__file__).parent / "fixtures" / "fixr6_succeeded_schema14.sql"
    )

    @staticmethod
    def _confirm_command_release(
        catalog: Catalog,
        command_id: str,
        fence: OperationFence | RecoveryCommandFence,
    ) -> None:
        permit = hashlib.sha256(f"release:{command_id}".encode()).hexdigest()
        catalog.authorize_hardware_command_release(command_id, fence, permit)
        catalog.confirm_hardware_command_released(command_id, fence, permit)

    @staticmethod
    def _seed_released_authorizations(
        connection: sqlite3.Connection,
        command_ids: tuple[str, ...],
    ) -> None:
        for command_id in command_ids:
            command = connection.execute(
                "SELECT created_at, released_at FROM hardware_command_executions "
                "WHERE id=?",
                (command_id,),
            ).fetchone()
            connection.execute(
                "INSERT INTO hardware_command_release_authorizations("
                "command_id, permit_sha256, release_status, authorized_at, "
                "confirmed_at) VALUES(?, ?, 'released', ?, ?)",
                (
                    command_id,
                    hashlib.sha256(f"release:{command_id}".encode()).hexdigest(),
                    command[0],
                    command[1],
                ),
            )

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "catalog.db"
        build_frozen_job_fixture(
            self.database,
            completed=3,
            total=20,
            schema_version=SCHEMA_VERSION,
            blocks_per_cassette=2,
        )
        with Catalog(self.database) as catalog:
            report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
            self.assertTrue(report.accepted, report.error_codes)
            catalog.freeze_imported_job(
                "JOB-MIGRATION",
                report.assignment_sha256,
                canonical_cassette_plan_sha256(
                    catalog.connection,
                    "JOB-MIGRATION",
                    assignment_sha256=report.assignment_sha256,
                ),
                "b" * 64,
            )
            self.source = Path(
                catalog.connection.execute(
                    "SELECT source_root FROM libraries WHERE id='LIB1'"
                ).fetchone()[0]
            )
        self._write_current_sources()

    def _write_current_sources(self) -> None:
        with ReadOnlyCatalog(self.database) as catalog:
            rows = catalog.connection.execute(
                "SELECT relative_path, size, mtime_ns "
                "FROM automatic_cassette_items "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4 "
                "ORDER BY item_sequence"
            ).fetchall()
        for row in rows:
            path = self.source / row["relative_path"]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"x" * row["size"])
            os.utime(path, ns=(row["mtime_ns"], row["mtime_ns"]))

    def _load(self) -> FrozenJobPlan:
        with ReadOnlyCatalog(self.database) as catalog:
            return FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def _complete_four_activation(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command("unload-4", "unload", "completed")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(fence, "succeeded")

    @staticmethod
    def _admit_recovery_operation(database: Path, sequence: int) -> None:
        with ReadOnlyCatalog(database) as catalog:
            plan = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
        cassette = plan.cassettes[sequence - 1]
        target = HardwareTargetBinding.from_verified_inputs(
            database.parent / "mount",
            "tape-device-a",
            "scsi-device-a",
            (
                "archive.resume",
                plan.job_id,
                str(sequence),
                cassette.physical_label,
                "",
                "",
            ),
        )
        with Catalog(database) as catalog:
            daemon_fence = catalog.current_daemon_fence()
            assert daemon_fence is not None
            catalog.admit_operation(
                OperationRecord(
                    f"operation-{sequence}",
                    "archive.resume",
                    "running",
                    None,
                    f"resume-{sequence}",
                    "admin",
                    plan.job_id,
                    sequence,
                    "2026-08-22T04:00:00+00:00",
                    None,
                ),
                daemon_fence,
                admission_open=True,
                hardware_target=target,
            )
            catalog.connection.execute(
                "INSERT INTO hardware_command_executions("
                "id, operation_id, issued_generation, command_kind, argv_sha256, "
                "mount_path_sha256, tape_device_identity_sha256, "
                "scsi_device_identity_sha256, expected_media_scope_sha256, "
                "observed_media_identity_sha256, state, exit_outcome, created_at, "
                "released_at, exit_observed_at, quiesced_at) "
                "VALUES(?, ?, ?, 'identify', ?, ?, ?, ?, ?, NULL, 'quiesced', "
                "'completed', ?, ?, ?, ?)",
                (
                    f"identify-{sequence}",
                    f"operation-{sequence}",
                    daemon_fence.generation,
                    f"{sequence:064x}",
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    "2026-08-22T04:00:01+00:00",
                    "2026-08-22T04:00:02+00:00",
                    "2026-08-22T04:00:03+00:00",
                    "2026-08-22T04:00:03+00:00",
                ),
            )
            catalog.connection.execute(
                "INSERT INTO hardware_command_executions("
                "id, operation_id, issued_generation, command_kind, argv_sha256, "
                "mount_path_sha256, tape_device_identity_sha256, "
                "scsi_device_identity_sha256, expected_media_scope_sha256, "
                "observed_media_identity_sha256, state, exit_outcome, created_at, "
                "released_at, exit_observed_at, quiesced_at) "
                "VALUES(?, ?, ?, 'probe_media', ?, ?, ?, ?, ?, NULL, 'quiesced', "
                "'completed', ?, ?, ?, ?)",
                (
                    f"probe-media-{sequence}",
                    f"operation-{sequence}",
                    daemon_fence.generation,
                    f"{sequence + 1:064x}",
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    "2026-08-22T04:00:04+00:00",
                    "2026-08-22T04:00:05+00:00",
                    "2026-08-22T04:00:06+00:00",
                    "2026-08-22T04:00:06+00:00",
                ),
            )
            catalog.connection.commit()
            catalog.bind_observed_media_identity(
                OperationFence(f"operation-{sequence}", daemon_fence.generation),
                f"{sequence + 100:064x}",
            )
            catalog.finish_operation(
                OperationFence(f"operation-{sequence}", daemon_fence.generation),
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
            recovery_owner = catalog.claim_daemon_owner(f"daemon-recovery-{sequence}")
            catalog.recover_interrupted_operations(recovery_owner)

    @staticmethod
    def _database_dump(path: Path) -> tuple[str, ...]:
        with closing(sqlite3.connect(path)) as connection:
            return tuple(connection.iterdump())

    @classmethod
    def _restore_real_fixr6_schema_fourteen(cls, destination: Path) -> None:
        cls._restore_schema_fourteen_fixture(destination, cls._FIXR6_SCHEMA14_FIXTURE)

    @staticmethod
    def _restore_schema_fourteen_fixture(destination: Path, fixture: Path) -> None:
        if destination.exists():
            destination.unlink()
        with closing(sqlite3.connect(destination)) as connection:
            connection.executescript(fixture.read_text(encoding="utf-8"))

    def _downgrade_lineage_to_fixr6_schema_fourteen(self) -> None:
        with closing(sqlite3.connect(self.database)) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("BEGIN IMMEDIATE")
            # A real schema-14 database predates the schema-21 reconciliation
            # table. Keeping it would create a synthetic hybrid whose foreign
            # key is retargeted by later table-rebuild migrations.
            connection.execute(
                "DROP TABLE IF EXISTS ltfs_qualification_reconciliations"
            )
            connection.execute(
                "CREATE TABLE imported_recovery_lineage_receipts_v14 ("
                "id TEXT PRIMARY KEY,"
                "job_id TEXT NOT NULL,"
                "sequence INTEGER NOT NULL CHECK(sequence = 4),"
                "operation_id TEXT NOT NULL REFERENCES daemon_operations(id),"
                "original_owner_generation INTEGER NOT NULL,"
                "recovery_generation INTEGER NOT NULL,"
                "daemon_owner_id TEXT NOT NULL,"
                "prior_lineage_id TEXT REFERENCES "
                "imported_recovery_lineage_receipts(id),"
                "commit_binding_sha256 TEXT NOT NULL "
                "CHECK(length(commit_binding_sha256) = 64),"
                "restart_state TEXT NOT NULL "
                "CHECK(restart_state IN ('running','recovery_required')),"
                "command_ids_json TEXT NOT NULL,"
                "command_evidence_sha256 TEXT NOT NULL "
                "CHECK(length(command_evidence_sha256) = 64),"
                "recorded_at TEXT NOT NULL,"
                "lineage_sha256 TEXT NOT NULL CHECK(length(lineage_sha256) = 64),"
                "UNIQUE(operation_id, recovery_generation))"
            )
            retained_columns = (
                "id,job_id,sequence,operation_id,original_owner_generation,"
                "recovery_generation,daemon_owner_id,prior_lineage_id,"
                "commit_binding_sha256,restart_state,command_ids_json,"
                "command_evidence_sha256,recorded_at,lineage_sha256"
            )
            connection.execute(
                f"INSERT INTO imported_recovery_lineage_receipts_v14("
                f"{retained_columns}) SELECT {retained_columns} "
                "FROM imported_recovery_lineage_receipts"
            )
            connection.execute("DROP TABLE imported_recovery_lineage_receipts")
            connection.execute(
                "ALTER TABLE imported_recovery_lineage_receipts_v14 "
                "RENAME TO imported_recovery_lineage_receipts"
            )
            connection.execute(
                "UPDATE metadata SET value='14' WHERE key='schema_version'"
            )
            connection.commit()
            connection.execute("PRAGMA foreign_keys=ON")
            self.assertEqual(
                [], connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            self.assertEqual(
                [("ok",)],
                connection.execute("PRAGMA integrity_check").fetchall(),
            )

    def _seed_durable_four_commit(self) -> None:
        plan = self._load()
        target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount",
            "tape-device-a",
            "scsi-device-a",
            (
                "archive.resume",
                plan.job_id,
                "4",
                plan.cassettes[3].physical_label,
                "",
                "",
            ),
        )
        with Catalog(self.database) as catalog:
            catalog.register_tape(
                "TAPE04",
                "SERIAL04",
                "TAPE04",
                "LTFS",
                "/synthetic/mount",
                cassette_number="TAPE04",
            )
            for number, item in enumerate(plan.cassettes[3].items, 1):
                block_id = f"BLOCK04-{number:02d}"
                catalog.create_block(
                    block_id, item.library_id, "TAPE04", "archive", 1, item.size
                )
                catalog.record_file_version(
                    item.library_id,
                    block_id,
                    "TAPE04",
                    item.relative_path,
                    f"archive/files/{item.relative_path}",
                    item.size,
                    item.mtime_ns,
                    f"{400 + number:064x}",
                )
                catalog.complete_block(block_id)
            catalog.update_automatic_cassette(
                plan.job_id,
                4,
                "completed",
                tape_id="TAPE04",
                block_id="BLOCK04-01,BLOCK04-02",
                copied_files=2,
                copied_bytes=8,
            )
            catalog.update_automatic_job(
                plan.job_id, "waiting_media", current_sequence=5
            )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET started_at=?, completed_at=? "
                "WHERE job_id=? AND sequence=4",
                ("2026-08-22T00:01:00+00:00", "2026-08-22T00:02:00+00:00", plan.job_id),
            )
            connection.execute(
                "INSERT INTO daemon_operations(id, kind, state, phase, idempotency_key, "
                "principal, owner_generation, job_id, cassette_sequence, started_at, "
                "finished_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "operation-4",
                    "archive.resume",
                    "succeeded",
                    "unloading",
                    "resume-4",
                    "admin",
                    1,
                    plan.job_id,
                    4,
                    "2026-08-22T00:00:00+00:00",
                    "2026-08-22T00:03:00+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO operation_hardware_targets VALUES(?, ?, ?, ?, ?, ?)",
                (
                    "operation-4",
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    "2026-08-22T00:00:10+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO hardware_command_executions(id, operation_id, "
                "issued_generation, command_kind, argv_sha256, mount_path_sha256, "
                "tape_device_identity_sha256, scsi_device_identity_sha256, "
                "expected_media_scope_sha256, observed_media_identity_sha256, state, "
                "exit_outcome, created_at, released_at, exit_observed_at, quiesced_at) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, 'quiesced', 'completed', ?, ?, ?, ?)",
                (
                    "identify-4",
                    "operation-4",
                    1,
                    "identify",
                    "9" * 64,
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    "2026-08-22T00:00:30+00:00",
                    "2026-08-22T00:00:31+00:00",
                    "2026-08-22T00:00:33+00:00",
                    "2026-08-22T00:00:33+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO operation_media_identity_bindings VALUES(?, ?, ?, ?)",
                ("operation-4", "8" * 64, "identify-4", "2026-08-22T00:00:34+00:00"),
            )
            connection.execute(
                "UPDATE hardware_command_executions SET boot_id='boot-identify-4', "
                "pid=4100, process_start_ticks=5100, process_group_id=4100 "
                "WHERE id='identify-4'"
            )
            self._seed_released_authorizations(connection, ("identify-4",))
            connection.execute(
                "INSERT INTO cutover_authorizations(id, credential_sha256, job_id, "
                "cassette_sequence, bundle_sha256, catalog_binding_sha256, "
                "assignment_sha256, expected_label, host_id, drive_serial_sha256, "
                "peer_kind, created_at, expires_at, consumed_at, consumed_by_operation_id) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "authorization-4",
                    "7" * 64,
                    plan.job_id,
                    4,
                    plan.bundle_sha256,
                    cutover_catalog_binding_sha256(
                        plan.job_id,
                        plan.bundle_sha256,
                        plan.assignment_sha256,
                        plan.cassette_plan_sha256,
                        plan.completed_evidence_sha256,
                        plan.cassettes[3].physical_label,
                    ),
                    plan.assignment_sha256,
                    plan.cassettes[3].physical_label,
                    "host-a",
                    target.tape_device_identity_sha256,
                    "local_admin",
                    "2026-08-21T23:59:00+00:00",
                    "2026-08-22T01:00:00+00:00",
                    "2026-08-22T00:00:20+00:00",
                    "operation-4",
                ),
            )

    def _seed_running_four_commit(
        self, *, include_prebind_retry: bool = False
    ) -> OperationFence:
        plan = self._load()
        target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount",
            "tape-device-a",
            "scsi-device-a",
            (
                "archive.resume",
                plan.job_id,
                "4",
                plan.cassettes[3].physical_label,
                "",
                "",
            ),
        )
        with Catalog(self.database) as catalog:
            catalog.register_tape(
                "TAPE04",
                "SERIAL04",
                "TAPE04",
                "LTFS",
                "/synthetic/mount",
                cassette_number="TAPE04",
            )
            for number, item in enumerate(plan.cassettes[3].items, 1):
                block_id = f"BLOCK04-{number:02d}"
                catalog.create_block(
                    block_id, item.library_id, "TAPE04", "archive", 1, item.size
                )
                catalog.stage_file_version(
                    item.library_id,
                    block_id,
                    "TAPE04",
                    item.relative_path,
                    f"archive/files/{item.relative_path}",
                    item.size,
                    item.mtime_ns,
                    f"{500 + number:064x}",
                )
            catalog.update_automatic_cassette(
                plan.job_id,
                4,
                "committing",
                tape_id="TAPE04",
                block_id="BLOCK04-01,BLOCK04-02",
                copied_files=2,
                copied_bytes=8,
            )
            catalog.update_automatic_job(plan.job_id, "writing", current_sequence=4)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO daemon_ownership VALUES(1, 'daemon-a', 1, ?)",
                ("2026-08-22T00:00:00+00:00",),
            )
            connection.execute(
                "INSERT INTO daemon_operations(id, kind, state, phase, idempotency_key, "
                "principal, owner_generation, job_id, cassette_sequence, started_at) "
                "VALUES('operation-4', 'archive.resume', 'running', 'committing', "
                "'resume-4', 'admin', 1, 'JOB-MIGRATION', 4, ?)",
                ("2026-08-22T00:00:05+00:00",),
            )
            connection.execute(
                "INSERT INTO operation_hardware_targets VALUES(?, ?, ?, ?, ?, ?)",
                (
                    "operation-4",
                    target.mount_path_sha256,
                    target.tape_device_identity_sha256,
                    target.scsi_device_identity_sha256,
                    target.expected_media_scope_sha256,
                    "2026-08-22T00:00:10+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO cutover_authorizations(id, credential_sha256, job_id, "
                "cassette_sequence, bundle_sha256, catalog_binding_sha256, "
                "assignment_sha256, expected_label, host_id, drive_serial_sha256, "
                "peer_kind, created_at, expires_at, consumed_at, consumed_by_operation_id) "
                "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "authorization-4",
                    "7" * 64,
                    plan.job_id,
                    4,
                    plan.bundle_sha256,
                    cutover_catalog_binding_sha256(
                        plan.job_id,
                        plan.bundle_sha256,
                        plan.assignment_sha256,
                        plan.cassette_plan_sha256,
                        plan.completed_evidence_sha256,
                        plan.cassettes[3].physical_label,
                    ),
                    plan.assignment_sha256,
                    plan.cassettes[3].physical_label,
                    "host-a",
                    target.tape_device_identity_sha256,
                    "local_admin",
                    "2026-08-21T23:59:00+00:00",
                    "2026-08-22T01:00:00+00:00",
                    "2026-08-22T00:00:20+00:00",
                    "operation-4",
                ),
            )
            retry_commands = (
                (
                    (
                        "identify-retry-4",
                        "identify",
                        None,
                        "2026-08-22T00:00:20.100000+00:00",
                        "2026-08-22T00:00:20.200000+00:00",
                        "2026-08-22T00:00:20.300000+00:00",
                        "2026-08-22T00:00:20.300000+00:00",
                    ),
                    (
                        "probe-retry-4",
                        "probe_media",
                        None,
                        "2026-08-22T00:00:20.400000+00:00",
                        "2026-08-22T00:00:20.500000+00:00",
                        "2026-08-22T00:00:20.600000+00:00",
                        "2026-08-22T00:00:20.600000+00:00",
                    ),
                )
                if include_prebind_retry
                else ()
            )
            commands = retry_commands + (
                (
                    "identify-pre-4",
                    "identify",
                    None,
                    "2026-08-22T00:00:21+00:00",
                    "2026-08-22T00:00:22+00:00",
                    "2026-08-22T00:00:24+00:00",
                    "2026-08-22T00:00:24+00:00",
                ),
                (
                    "probe-pre-4",
                    "probe_media",
                    None,
                    "2026-08-22T00:00:24.100000+00:00",
                    "2026-08-22T00:00:24.200000+00:00",
                    "2026-08-22T00:00:24.300000+00:00",
                    "2026-08-22T00:00:24.300000+00:00",
                ),
                (
                    "inquiry-format-4",
                    "inquiry",
                    "7" * 64,
                    "2026-08-22T00:00:25+00:00",
                    "2026-08-22T00:00:26+00:00",
                    "2026-08-22T00:00:27+00:00",
                    "2026-08-22T00:00:27+00:00",
                ),
                (
                    "format-4",
                    "format",
                    "7" * 64,
                    "2026-08-22T00:00:28+00:00",
                    "2026-08-22T00:00:29+00:00",
                    "2026-08-22T00:00:30+00:00",
                    "2026-08-22T00:00:30+00:00",
                ),
                (
                    "identify-post-4",
                    "identify",
                    "7" * 64,
                    "2026-08-22T00:00:31+00:00",
                    "2026-08-22T00:00:32+00:00",
                    "2026-08-22T00:00:33+00:00",
                    "2026-08-22T00:00:33+00:00",
                ),
                (
                    "probe-post-4",
                    "probe_media",
                    "7" * 64,
                    "2026-08-22T00:00:33.100000+00:00",
                    "2026-08-22T00:00:33.200000+00:00",
                    "2026-08-22T00:00:33.300000+00:00",
                    "2026-08-22T00:00:33.300000+00:00",
                ),
                (
                    "inquiry-mount-4",
                    "inquiry",
                    "8" * 64,
                    "2026-08-22T00:00:35+00:00",
                    "2026-08-22T00:00:36+00:00",
                    "2026-08-22T00:00:37+00:00",
                    "2026-08-22T00:00:37+00:00",
                ),
            )
            connection.executemany(
                "INSERT INTO hardware_command_executions(id, operation_id, "
                "issued_generation, command_kind, argv_sha256, mount_path_sha256, "
                "tape_device_identity_sha256, scsi_device_identity_sha256, "
                "expected_media_scope_sha256, observed_media_identity_sha256, state, "
                "exit_outcome, created_at, released_at, exit_observed_at, quiesced_at) "
                "VALUES(?, 'operation-4', 1, ?, ?, ?, ?, ?, ?, ?, 'quiesced', "
                "'completed', ?, ?, ?, ?)",
                [
                    (
                        command_id,
                        kind,
                        f"{600 + index:064x}",
                        target.mount_path_sha256,
                        target.tape_device_identity_sha256,
                        target.scsi_device_identity_sha256,
                        target.expected_media_scope_sha256,
                        observed,
                        created,
                        released,
                        exited,
                        quiesced,
                    )
                    for index, (
                        command_id,
                        kind,
                        observed,
                        created,
                        released,
                        exited,
                        quiesced,
                    ) in enumerate(commands)
                ],
            )
            connection.execute(
                "UPDATE hardware_command_executions SET boot_id='boot-' || id, "
                "pid=4100 + rowid, process_start_ticks=5100 + rowid, "
                "process_group_id=4100 + rowid WHERE operation_id='operation-4'"
            )
            self._seed_released_authorizations(
                connection, tuple(command[0] for command in commands)
            )
            connection.execute(
                "INSERT INTO operation_media_identity_bindings VALUES(?, ?, ?, ?)",
                (
                    "operation-4",
                    "8" * 64,
                    "probe-post-4",
                    "2026-08-22T00:00:34+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO format_confirmations VALUES(?,?,?,?,?,?)",
                (
                    "operation-4",
                    plan.job_id,
                    4,
                    plan.cassettes[3].physical_label,
                    "admin",
                    "2026-08-22T00:00:20+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO format_media_rebindings(operation_id,owner_generation,"
                "confirmation_confirmed_at,pre_probe_media_command_id,format_command_id,"
                "post_probe_media_command_id,expected_label,observed_label,expected_serial,"
                "observed_serial,post_volume_uuid,post_index_generation,"
                "pre_media_identity_sha256,post_media_identity_sha256,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "operation-4",
                    1,
                    "2026-08-22T00:00:20+00:00",
                    "probe-pre-4",
                    "format-4",
                    "probe-post-4",
                    plan.cassettes[3].physical_label,
                    plan.cassettes[3].physical_label,
                    plan.cassettes[3].tape_serial,
                    plan.cassettes[3].tape_serial,
                    "22222222-2222-4222-8222-222222222222",
                    8,
                    "7" * 64,
                    "8" * 64,
                    "2026-08-22T00:00:34+00:00",
                ),
            )
            connection.execute(
                "UPDATE automatic_cassettes SET started_at=? WHERE job_id=? AND sequence=4",
                ("2026-08-22T00:01:00+00:00", plan.job_id),
            )
            connection.execute(
                "UPDATE blocks SET started_at=? WHERE id LIKE 'BLOCK04-%'",
                ("2026-08-22T00:01:10+00:00",),
            )
            connection.execute(
                "UPDATE file_versions SET copied_at=? WHERE block_id LIKE 'BLOCK04-%'",
                ("2026-08-22T00:01:20+00:00",),
            )
            connection.execute(
                "INSERT INTO ltfs_terminal_receipts(operation_id,owner_generation,"
                "job_id,sequence,receipt_operation_uuid,session_id,request_sha256,"
                "volume_uuid,prior_generation,new_generation,bytes_valid,byte_count,"
                "files_valid,file_count,media_committed,catalog_acknowledged,"
                "device_close_result_valid,device_close_result,cleanup_failed,result,"
                "terminal_sha256,request_nonce,finalization_nonce,broker_proof,"
                "observed_volume_label,observed_media_identity_sha256,"
                "standalone_receipt_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,"
                "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "operation-4",
                    1,
                    plan.job_id,
                    4,
                    "11111111-1111-4111-8111-111111111111",
                    "session-4",
                    "6" * 64,
                    "22222222-2222-4222-8222-222222222222",
                    7,
                    8,
                    1,
                    8,
                    1,
                    2,
                    1,
                    1,
                    1,
                    0,
                    0,
                    0,
                    "9" * 64,
                    b"r" * 32,
                    b"f" * 32,
                    b"p" * 32,
                    plan.cassettes[3].physical_label,
                    "8" * 64,
                    "{}",
                    "2026-08-22T00:02:30+00:00",
                ),
            )
        return OperationFence("operation-4", 1)

    def _append_quiesced_postcommit_command(
        self,
        command_id: str,
        kind: str,
        outcome: str,
        *,
        start_microseconds: int = 1,
        issued_generation: int = 1,
    ) -> str:
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            target = connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            committed_at = connection.execute(
                "SELECT committed_at FROM imported_cassette_commit_receipts "
                "WHERE job_id='JOB-MIGRATION'"
            ).fetchone()[0]
            lineage = connection.execute(
                "SELECT recorded_at FROM imported_recovery_lineage_receipts "
                "WHERE operation_id='operation-4' AND recovery_generation=?",
                (issued_generation,),
            ).fetchone()
            committed = datetime.fromisoformat(committed_at)
            if lineage is not None:
                committed = max(
                    committed, datetime.fromisoformat(lineage["recorded_at"])
                )
            created = (
                committed + timedelta(microseconds=start_microseconds)
            ).isoformat()
            released = (
                committed + timedelta(microseconds=start_microseconds + 1)
            ).isoformat()
            terminal = (
                committed + timedelta(microseconds=start_microseconds + 2)
            ).isoformat()
            times = (created, released, terminal, terminal)
            connection.execute(
                "INSERT INTO hardware_command_executions(id, operation_id, "
                "issued_generation, command_kind, argv_sha256, mount_path_sha256, "
                "tape_device_identity_sha256, scsi_device_identity_sha256, "
                "expected_media_scope_sha256, observed_media_identity_sha256, state, "
                "exit_outcome, boot_id, pid, process_start_ticks, process_group_id, "
                "created_at, released_at, exit_observed_at, quiesced_at) "
                "VALUES(?, 'operation-4', ?, ?, ?, ?, ?, ?, ?, ?, 'quiesced', ?, "
                "?, 4100, 5100, 4100, ?, ?, ?, ?)",
                (
                    command_id,
                    issued_generation,
                    kind,
                    "4" * 64,
                    target["mount_path_sha256"],
                    target["tape_device_identity_sha256"],
                    target["scsi_device_identity_sha256"],
                    target["expected_media_scope_sha256"],
                    media,
                    outcome,
                    f"boot-{command_id}",
                    *times,
                ),
            )
            self._seed_released_authorizations(connection, (command_id,))
        return times[-1]

    def _activate_and_finish_with_released_unload(self) -> OperationFence:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "completed")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(fence, "succeeded")
        return fence

    def _run_public_postcommit_command(
        self,
        fence: OperationFence | RecoveryCommandFence,
        command_id: str,
        outcome: str,
    ) -> None:
        with Catalog(self.database) as catalog:
            owner_row = catalog.connection.execute(
                "SELECT owner_id, generation FROM daemon_ownership WHERE singleton=1"
            ).fetchone()
            owner = DaemonFence(owner_row["owner_id"], owner_row["generation"])
            catalog.reserve_hardware_command(fence, command_id, "unload", "4" * 64)
            if outcome == "launch_aborted":
                created_at = catalog.command(command_id).created_at
                quiesced_at = (
                    datetime.fromisoformat(created_at) + timedelta(microseconds=1)
                ).isoformat()
                catalog.acknowledge_command_quiescence(
                    command_id,
                    owner,
                    CommandExitEvidence(
                        command_id=command_id,
                        process=None,
                        outcome="launch_aborted",
                        quiesced_at=quiesced_at,
                    ),
                )
                return
            process = ProcessIdentity(
                boot_id=f"boot-{command_id}",
                pid=4100,
                start_ticks=5100,
                process_group_id=4100,
            )
            catalog.record_blocked_process(command_id, fence, process)
            self._confirm_command_release(catalog, command_id, fence)
            released_at = catalog.command(command_id).released_at
            quiesced_at = (
                datetime.fromisoformat(released_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.acknowledge_command_quiescence(
                command_id,
                owner,
                CommandExitEvidence(
                    command_id=command_id,
                    process=process,
                    outcome=outcome,
                    quiesced_at=quiesced_at,
                ),
            )

    def _resolve_current_recovery(
        self,
        current: DaemonFence,
        reason_code: str,
    ) -> None:
        with Catalog(self.database) as catalog:
            command_receipt = catalog.create_command_quiescence_receipt(
                "operation-4", current
            )

            target_row = catalog.connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = catalog.connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            physical = catalog.create_physical_reconciliation_receipt(
                "operation-4",
                current,
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=HardwareTargetBinding(
                        target_row["mount_path_sha256"],
                        target_row["tape_device_identity_sha256"],
                        target_row["scsi_device_identity_sha256"],
                        target_row["expected_media_scope_sha256"],
                    ),
                    observed_media_identity_sha256=media,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
            catalog.resolve_recovery(
                "operation-4",
                current,
                SafeRecoveryResolution(
                    reason_code=reason_code,
                    command_receipt_id=command_receipt.id,
                    physical_receipt_id=physical.id,
                ),
            )

    def _copy_database(self, name: str) -> Path:
        destination = self.root / name
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(destination)) as target,
        ):
            source.backup(target)
        return destination

    @staticmethod
    def _duplicate_release_row(database: Path, command_id: str) -> None:
        with sqlite3.connect(database) as connection:
            connection.executescript(
                """
                ALTER TABLE hardware_command_release_authorizations
                    RENAME TO original_release_authorizations;
                CREATE TABLE hardware_command_release_authorizations (
                    command_id TEXT NOT NULL,
                    permit_sha256 TEXT NOT NULL,
                    release_status TEXT NOT NULL,
                    authorized_at TEXT NOT NULL,
                    confirmed_at TEXT
                );
                INSERT INTO hardware_command_release_authorizations
                    SELECT * FROM original_release_authorizations;
                """
            )
            connection.execute(
                """
                INSERT INTO hardware_command_release_authorizations
                    SELECT command_id,
                           'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                           release_status, authorized_at, confirmed_at
                    FROM original_release_authorizations
                    WHERE command_id=?
                """,
                (command_id,),
            )
            connection.execute("DROP TABLE original_release_authorizations")

    @staticmethod
    def _duplicate_postcommit_receipt(database: Path) -> None:
        with sqlite3.connect(database) as connection:
            connection.executescript(
                """
                ALTER TABLE imported_postcommit_command_receipts
                    RENAME TO original_postcommit_receipts;
                CREATE TABLE imported_postcommit_command_receipts (
                    command_id TEXT NOT NULL,
                    operation_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    issued_generation INTEGER NOT NULL,
                    recovery_lineage_id TEXT,
                    command_order INTEGER NOT NULL,
                    command_evidence_sha256 TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                INSERT INTO imported_postcommit_command_receipts
                    SELECT * FROM original_postcommit_receipts;
                INSERT INTO imported_postcommit_command_receipts
                    SELECT * FROM original_postcommit_receipts;
                DROP TABLE original_postcommit_receipts;
                """
            )

    @staticmethod
    def _rebind_schema14_postcommit_receipt(database: Path, command_id: str) -> None:
        legacy_fields = (
            "id",
            "operation_id",
            "issued_generation",
            "command_kind",
            "argv_sha256",
            "mount_path_sha256",
            "tape_device_identity_sha256",
            "scsi_device_identity_sha256",
            "expected_media_scope_sha256",
            "observed_media_identity_sha256",
            "state",
            "exit_outcome",
            "boot_id",
            "pid",
            "process_start_ticks",
            "process_group_id",
            "created_at",
            "released_at",
            "exit_observed_at",
            "quiesced_at",
        )
        with sqlite3.connect(database) as connection:
            connection.row_factory = sqlite3.Row
            command = connection.execute(
                "SELECT * FROM hardware_command_executions WHERE id=?",
                (command_id,),
            ).fetchone()
            evidence = imported_postcommit_command_sha256(
                tuple(command[field] for field in legacy_fields)
            )
            connection.execute(
                "UPDATE imported_postcommit_command_receipts "
                "SET command_evidence_sha256=? WHERE command_id=?",
                (evidence, command_id),
            )
            connection.commit()

    def _catalog_snapshot(self) -> dict[str, tuple[tuple[object, ...], ...]]:
        tables = (
            "automatic_jobs",
            "automatic_cassettes",
            "automatic_cassette_items",
            "imported_job_policies",
            "migration_receipts",
        )
        with sqlite3.connect(self.database) as connection:
            return {
                table: tuple(
                    tuple(row)
                    for row in connection.execute(
                        f"SELECT * FROM {table} ORDER BY rowid"
                    )
                )
                for table in tables
            }

    def test_new_source_file_is_not_added_to_frozen_job(self) -> None:
        original = self._load()

        (self.source / "new-after-export.mxf").write_bytes(b"new")
        reloaded = self._load()

        self.assertEqual(original.assignment_sha256, reloaded.assignment_sha256)
        self.assertNotIn("new-after-export.mxf", reloaded.relative_paths)
        self.assertEqual(
            tuple((item.sequence, item.item_sequence) for item in reloaded.items),
            tuple(
                sorted((item.sequence, item.item_sequence) for item in reloaded.items)
            ),
        )

    def test_resume_requests_four_without_reading_previous_tapes(self) -> None:
        plan = self._load()

        current = plan.next_cassette()
        validation = plan.validate_sources()

        self.assertEqual(4, current.sequence)
        self.assertTrue(validation.accepted, validation.issues)
        self.assertEqual(4, validation.sequence)
        self.assertEqual(2, validation.checked_files)

    def test_missing_or_changed_current_source_blocks_without_catalog_mutation(
        self,
    ) -> None:
        plan = self._load()
        current = plan.next_cassette()
        missing = self.source / current.items[0].relative_path
        changed = self.source / current.items[1].relative_path
        before = self._catalog_snapshot()

        missing.unlink()
        changed.write_bytes(b"changed")
        validation = plan.validate_sources()

        self.assertFalse(validation.accepted)
        self.assertTrue(validation.blocked)
        self.assertEqual("operator_required", validation.error_class)
        self.assertEqual("frozen_source_validation_failed", validation.error_code)
        self.assertEqual(
            ("source_missing", "source_changed"),
            tuple(issue.code for issue in validation.issues),
        )
        self.assertEqual(before, self._catalog_snapshot())

    def test_assignment_hash_is_recomputed_and_tampering_is_rejected(self) -> None:
        with sqlite3.connect(self.database) as connection:
            # Simulate corruption below the catalog API: normal writes are stopped
            # by the freeze trigger, while load-time attestation remains mandatory.
            connection.execute("DROP TRIGGER freeze_imported_cassette_item_update")
            connection.execute(
                "UPDATE automatic_cassette_items SET size=size+1 "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4 AND item_sequence=1"
            )

        with self.assertRaises(FrozenJobAssignmentChanged) as caught:
            self._load()

        self.assertEqual("frozen-assignment-changed", caught.exception.code)

    def test_cassette_plan_hash_is_recomputed_after_storage_corruption(self) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute("DROP TRIGGER freeze_imported_cassette_identity_update")
            connection.execute(
                "UPDATE automatic_cassettes SET physical_label='CORRUPTED-004' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            )

        with self.assertRaises(FrozenJobAssignmentChanged) as caught:
            self._load()

        self.assertEqual("frozen-assignment-changed", caught.exception.code)

    def test_completed_imported_cassettes_require_relational_evidence(self) -> None:
        mutations = (
            (
                "UPDATE automatic_cassettes SET tape_id='MISSING-TAPE' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=1"
            ),
            (
                "UPDATE automatic_cassettes SET block_id='MISSING-BLOCK' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=1"
            ),
            (
                "UPDATE automatic_cassettes SET tape_id='TAPE02' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=1"
            ),
            (
                "UPDATE automatic_cassettes SET "
                "block_id='BLOCK02-01,BLOCK02-02' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=1"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"completed-evidence-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobStateInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_frozen_catalog_blocks_plan_identity_and_manifest_mutation(self) -> None:
        mutations = (
            (
                (
                    "UPDATE automatic_cassettes SET physical_label='MUTATED-004' "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                ),
                (),
            ),
            (
                (
                    "UPDATE automatic_cassettes SET operation='append' "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                ),
                (),
            ),
            (
                (
                    "UPDATE automatic_cassettes SET tape_serial='MUTATED-SERIAL' "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                ),
                (),
            ),
            (
                (
                    "UPDATE automatic_cassettes SET planned_bytes=planned_bytes+1 "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                ),
                (),
            ),
            (
                (
                    "UPDATE automatic_cassettes SET reuse_registered=1 "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                ),
                (),
            ),
            (
                "UPDATE automatic_jobs SET total_cassettes=21 WHERE id='JOB-MIGRATION'",
                (),
            ),
            (
                (
                    "DELETE FROM automatic_cassette_items "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4 "
                    "AND item_sequence=1"
                ),
                (),
            ),
            ("DELETE FROM automatic_jobs WHERE id='JOB-MIGRATION'", ()),
        )
        for index, (statement, parameters) in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"immutable-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with (
                    sqlite3.connect(copy) as connection,
                    self.assertRaisesRegex(
                        sqlite3.IntegrityError, "imported frozen job plan is immutable"
                    ),
                ):
                    connection.execute(statement, parameters)

    def test_pre_cutover_rejects_partial_four_and_nonpristine_future(self) -> None:
        mutations = (
            (
                "UPDATE automatic_cassettes SET tape_id='partial-4' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes SET block_id='partial-4' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes SET copied_files=1 "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes SET copied_bytes=4 "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes SET status='waiting_media', "
                "started_at='2026-08-22T00:00:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes SET completed_at="
                "'2026-08-22T00:00:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes SET error='interrupted' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            ),
            (
                "UPDATE automatic_cassettes "
                "SET started_at='2026-08-22T00:00:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=5"
            ),
            (
                "UPDATE automatic_cassettes SET status='writing' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=5"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"partial-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobStateInvalid) as caught,
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")
                self.assertEqual("frozen-job-state-invalid", caught.exception.code)
                self.assertEqual("operator_required", caught.exception.error_class)

    def test_non_imported_job_is_rejected(self) -> None:
        other = self.root / "not-imported.db"
        build_frozen_job_fixture(other, schema_version=14)

        with (
            ReadOnlyCatalog(other) as catalog,
            self.assertRaises(FrozenJobNotImported) as caught,
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

        self.assertEqual("job-not-imported", caught.exception.code)

    def test_policy_receipt_and_authority_must_remain_coherent(self) -> None:
        cases = {
            "receipt": (
                "UPDATE migration_receipts SET bundle_sha256=? WHERE job_id=?",
                ("c" * 64, "JOB-MIGRATION"),
            ),
            "authority": (
                (
                    "UPDATE imported_job_policies SET authority_state='active_linux' "
                    "WHERE job_id=?"
                ),
                ("JOB-MIGRATION",),
            ),
        }
        for name, (statement, values) in cases.items():
            with self.subTest(name=name):
                copy = self.root / f"{name}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement, values)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid) as caught,
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")
                self.assertEqual("frozen-authority-invalid", caught.exception.code)

    def test_activation_rejects_forged_four_without_media_commit(self) -> None:
        original = self._load()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO daemon_operations(id, kind, state, phase, "
                "idempotency_key, principal, owner_generation, job_id, "
                "cassette_sequence, started_at, finished_at) "
                "VALUES('operation-4', 'archive.resume', 'succeeded', 'unloading', "
                "'resume-4', 'admin', 1, 'JOB-MIGRATION', 4, "
                "'2026-08-22T00:00:00+00:00', '2026-08-22T00:02:00+00:00')"
            )
            connection.execute(
                "INSERT INTO operation_hardware_targets(operation_id, "
                "mount_path_sha256, tape_device_identity_sha256, "
                "scsi_device_identity_sha256, expected_media_scope_sha256, "
                "bound_at) VALUES('operation-4', ?, ?, ?, ?, ?)",
                (
                    "d" * 64,
                    "e" * 64,
                    "f" * 64,
                    "a" * 64,
                    "2026-08-22T00:00:10+00:00",
                ),
            )
            connection.execute(
                "INSERT INTO cutover_authorizations(id, credential_sha256, job_id, "
                "cassette_sequence, bundle_sha256, catalog_binding_sha256, "
                "assignment_sha256, expected_label, host_id, drive_serial_sha256, "
                "peer_kind, created_at, expires_at, consumed_at, "
                "consumed_by_operation_id) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?)",
                (
                    "authorization-4",
                    "c" * 64,
                    "JOB-MIGRATION",
                    4,
                    original.bundle_sha256,
                    cutover_catalog_binding_sha256(
                        original.job_id,
                        original.bundle_sha256,
                        original.assignment_sha256,
                        original.cassette_plan_sha256,
                        original.completed_evidence_sha256,
                        original.cassettes[3].physical_label,
                    ),
                    original.assignment_sha256,
                    original.cassettes[3].physical_label,
                    "host-a",
                    "b" * 64,
                    "local_admin",
                    "2026-08-21T23:59:00+00:00",
                    "2026-08-22T01:00:00+00:00",
                    "2026-08-22T00:00:20+00:00",
                    "operation-4",
                ),
            )
            connection.execute(
                "UPDATE automatic_cassettes SET status='completed', "
                "tape_id='TAPE04', block_id='BLOCK04-01,BLOCK04-02', "
                "copied_files=2, copied_bytes=8, "
                "started_at='2026-08-22T00:00:30+00:00', "
                "completed_at='2026-08-22T00:01:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            )
            connection.execute(
                "UPDATE automatic_jobs SET status='waiting_media', current_sequence=5 "
                "WHERE id='JOB-MIGRATION'"
            )
        with (
            Catalog(self.database) as catalog,
            self.assertRaises(ValidationError),
        ):
            catalog.activate_imported_job_authority("JOB-MIGRATION", "operation-4")

    def test_terminal_operation_cannot_posthoc_activate_authority(self) -> None:
        self._seed_durable_four_commit()

        with (
            Catalog(self.database) as catalog,
            self.assertRaises(ValidationError),
        ):
            catalog.activate_imported_job_authority("JOB-MIGRATION", "operation-4")

    def test_running_callback_atomically_commits_four_and_activates_authority(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()

        with Catalog(self.database) as catalog:
            policy = catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            operation = catalog.get_operation("operation-4")
            cassette = catalog.connection.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            ).fetchone()

        self.assertEqual("active_linux", policy.authority_state)
        self.assertEqual("running", operation["state"])
        self.assertEqual("unloading", operation["phase"])
        self.assertEqual("completed", cassette["status"])
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

        with Catalog(self.database) as catalog:
            replayed = catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command("unload-4", "unload", "completed")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(fence, "succeeded")
        self.assertEqual(policy, replayed)
        self.assertEqual(5, self._load().next_cassette().sequence)

    def test_sequence_four_authority_and_frozen_replay_accept_prebind_poll_retry(
        self,
    ) -> None:
        fence = self._seed_running_four_commit(include_prebind_retry=True)

        with Catalog(self.database) as catalog:
            policy = catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            command_ids = tuple(
                json.loads(
                    catalog.connection.execute(
                        "SELECT command_ids_json FROM "
                        "imported_cassette_commit_receipts "
                        "WHERE job_id='JOB-MIGRATION' AND sequence=4"
                    ).fetchone()[0]
                )
            )

        self.assertEqual("active_linux", policy.authority_state)
        self.assertEqual(
            (
                "identify-retry-4",
                "probe-retry-4",
                "identify-pre-4",
                "probe-pre-4",
                "inquiry-format-4",
                "format-4",
                "identify-post-4",
                "probe-post-4",
                "inquiry-mount-4",
            ),
            command_ids,
        )
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

    def test_current_schema_commit_never_falls_back_without_format_rebind(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            catalog.connection.execute(
                "DROP TRIGGER format_media_rebindings_immutable_delete"
            )
            catalog.connection.execute(
                "DELETE FROM format_media_rebindings WHERE operation_id='operation-4'"
            )
            catalog.connection.commit()

        with (
            ReadOnlyCatalog(self.database) as catalog,
            self.assertRaises(FrozenJobAuthorityInvalid),
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_recovery_lookup_uses_real_active_plan_at_boundaries(self) -> None:
        self._complete_four_activation()
        cassette_twenty = self.root / "cassette-twenty.db"
        with (
            sqlite3.connect(self.database) as source,
            sqlite3.connect(cassette_twenty) as target,
        ):
            source.backup(target)

        self._admit_recovery_operation(self.database, 5)
        with ReadOnlyCatalog(self.database) as catalog:
            five = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
        self.assertEqual("active_linux", five.authority_state)
        self.assertEqual(5, five.cassette_for_recovery(5).sequence)

        with sqlite3.connect(cassette_twenty) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET status='completed', "
                "tape_id='TAPE' || printf('%02d', sequence), "
                "block_id='BLOCK' || printf('%02d', sequence), "
                "copied_files=planned_files, copied_bytes=planned_bytes, "
                "started_at='2026-08-22T02:00:00+00:00', "
                "completed_at='2026-08-22T02:01:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence BETWEEN 5 AND 19"
            )
            connection.execute(
                "UPDATE automatic_jobs SET status='waiting_media', "
                "current_sequence=20 WHERE id='JOB-MIGRATION'"
            )
            connection.commit()
        self._admit_recovery_operation(cassette_twenty, 20)
        with ReadOnlyCatalog(cassette_twenty) as catalog:
            twenty = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
        self.assertEqual("active_linux", twenty.authority_state)
        self.assertEqual(20, twenty.cassette_for_recovery(20).sequence)

    def test_production_hook_loads_real_active_recovery_plan_at_boundaries(
        self,
    ) -> None:
        self._complete_four_activation()
        cassette_twenty = self.root / "production-cassette-twenty.db"
        with (
            sqlite3.connect(self.database) as source,
            sqlite3.connect(cassette_twenty) as target,
        ):
            source.backup(target)
        with sqlite3.connect(cassette_twenty) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET status='completed', "
                "tape_id='TAPE' || printf('%02d', sequence), "
                "block_id='BLOCK' || printf('%02d', sequence), "
                "copied_files=planned_files, copied_bytes=planned_bytes, "
                "started_at='2026-08-22T02:00:00+00:00', "
                "completed_at='2026-08-22T02:01:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence BETWEEN 5 AND 19"
            )
            connection.execute(
                "UPDATE automatic_jobs SET status='waiting_media', "
                "current_sequence=20 WHERE id='JOB-MIGRATION'"
            )
            connection.commit()

        for database, sequence in (
            (self.database, 5),
            (cassette_twenty, 20),
        ):
            with self.subTest(sequence=sequence):
                self._admit_recovery_operation(database, sequence)
                with Catalog(database) as catalog:
                    target = catalog.hardware_target_binding(f"operation-{sequence}")
                    daemon_fence = catalog.current_daemon_fence()
                self.assertIsNotNone(target)
                self.assertIsNotNone(daemon_fence)
                calls = []

                class Sessions:
                    def __init__(self, recoveries, terminal):
                        self._recoveries = recoveries
                        self._terminal = terminal

                    def start_ltfs_session(self, *_args, **_kwargs):
                        raise AssertionError("recovery must not start a second session")

                    def recover_pending_ltfs_session(self, admission):
                        self._recoveries.append(admission)
                        return self._terminal

                runtime = ProductionArchiveResume.__new__(ProductionArchiveResume)
                runtime._settings = object()
                runtime._catalog_factory = lambda database=database: Catalog(database)
                runtime._device_identities = object()
                runtime._ltfs_sessions = Sessions(calls, None)
                runtime._scope_manager = object()
                runtime._privilege_boundary = object()
                with (
                    mock.patch(
                        "ltobackup.daemon.archive_runtime."
                        "LinuxLtfsBackend.target_binding_from",
                        return_value=target,
                    ),
                    mock.patch(
                        "ltobackup.daemon.archive_runtime._production_supervisor",
                        return_value=object(),
                    ),
                ):
                    terminal = runtime.reconcile_pending_ltfs_operation(
                        f"operation-{sequence}",
                        RecoveryCommandFence(
                            f"operation-{sequence}", daemon_fence.generation
                        ),
                    )

                self.assertIsNone(terminal)
                self.assertEqual(1, len(calls))
                self.assertEqual(f"operation-{sequence}", calls[0].fence.operation_id)

    def test_recovery_lookup_rejects_invalid_missing_and_duplicate_sequence(
        self,
    ) -> None:
        self._complete_four_activation()
        plan = self._load()
        for invalid in (True, False, None, "5", 3, 21):
            with (
                self.subTest(recovery_sequence=invalid),
                self.assertRaises(FrozenJobStateInvalid),
            ):
                plan.cassette_for_recovery(invalid)
        with self.assertRaises(FrozenJobStateInvalid):
            replace(
                plan,
                cassettes=plan.cassettes + (plan.cassettes[4],),
            ).cassette_for_recovery(5)
        with self.assertRaises(FrozenJobStateInvalid):
            replace(
                plan,
                cassettes=tuple(
                    cassette for cassette in plan.cassettes if cassette.sequence != 5
                ),
            ).cassette_for_recovery(5)

    def test_commit_rejects_released_precommit_commands_without_release_rows(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with sqlite3.connect(self.database) as connection:
            connection.execute("DELETE FROM hardware_command_release_authorizations")

        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

    def test_commit_rejects_duplicate_precommit_release_rows(self) -> None:
        fence = self._seed_running_four_commit()
        self._duplicate_release_row(self.database, "identify-post-4")

        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

    def test_commit_rejects_unload_inside_frozen_precommit_ledger(self) -> None:
        fence = self._seed_running_four_commit()
        with sqlite3.connect(self.database) as connection:
            target = connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO hardware_command_executions(id, operation_id, "
                "issued_generation, command_kind, argv_sha256, mount_path_sha256, "
                "tape_device_identity_sha256, scsi_device_identity_sha256, "
                "expected_media_scope_sha256, observed_media_identity_sha256, state, "
                "exit_outcome, created_at, released_at, exit_observed_at, quiesced_at) "
                "VALUES('early-unload-4', 'operation-4', 1, 'unload', ?, ?, ?, ?, ?, ?, "
                "'quiesced', 'completed', ?, ?, ?, ?)",
                (
                    "4" * 64,
                    *tuple(target[index] for index in range(1, 5)),
                    media,
                    "2026-08-22T00:02:31+00:00",
                    "2026-08-22T00:02:32+00:00",
                    "2026-08-22T00:02:33+00:00",
                    "2026-08-22T00:02:34+00:00",
                ),
            )

        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

    def test_succeeded_active_operation_requires_postcommit_unload(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            catalog.finish_operation(fence, "succeeded")

        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_generic_cancelled_active_operation_has_no_recovery_authority(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            committed_at = catalog.connection.execute(
                "SELECT committed_at FROM imported_cassette_commit_receipts "
                "WHERE job_id='JOB-MIGRATION'"
            ).fetchone()[0]
            catalog.connection.execute(
                "UPDATE daemon_operations SET state='cancelled', finished_at=? "
                "WHERE id='operation-4'",
                (
                    (
                        datetime.fromisoformat(committed_at) + timedelta(microseconds=1)
                    ).isoformat(),
                ),
            )
            catalog.connection.commit()

        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_commit_transaction_rolls_back_every_authority_and_catalog_change(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with sqlite3.connect(self.database) as connection:
            before = {
                table: tuple(
                    connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
                )
                for table in (
                    "blocks",
                    "file_versions",
                    "automatic_jobs",
                    "automatic_cassettes",
                    "imported_job_policies",
                    "imported_cassette_commit_receipts",
                    "daemon_operations",
                )
            }
            connection.execute(
                "CREATE TRIGGER reject_authority_activation BEFORE UPDATE "
                "ON imported_job_policies BEGIN SELECT RAISE(ABORT, 'injected'); END"
            )
        with (
            Catalog(self.database) as catalog,
            self.assertRaises(sqlite3.IntegrityError),
        ):
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        with sqlite3.connect(self.database) as connection:
            after = {
                table: tuple(
                    connection.execute(f"SELECT * FROM {table} ORDER BY rowid")
                )
                for table in before
            }
        self.assertEqual(before, after)

    def test_commit_replay_requires_the_exact_same_fenced_evidence(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            catalog.connection.execute(
                "UPDATE hardware_command_executions SET argv_sha256=? "
                "WHERE id='inquiry-mount-4'",
                ("3" * 64,),
            )
            catalog.connection.commit()
            with self.assertRaises(ValidationError):
                catalog.commit_imported_cassette_authority(
                    fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
                )

    def test_commit_replay_rejects_injected_extra_precommit_command(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            target = catalog.connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = catalog.connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            catalog.connection.execute(
                "INSERT INTO hardware_command_executions(id, operation_id, "
                "issued_generation, command_kind, argv_sha256, mount_path_sha256, "
                "tape_device_identity_sha256, scsi_device_identity_sha256, "
                "expected_media_scope_sha256, observed_media_identity_sha256, state, "
                "exit_outcome, created_at, released_at, exit_observed_at, quiesced_at) "
                "VALUES('injected-before-commit', 'operation-4', 1, 'status', ?, ?, ?, ?, ?, ?, "
                "'quiesced', 'completed', ?, ?, ?, ?)",
                (
                    "5" * 64,
                    *tuple(target[index] for index in range(1, 5)),
                    media,
                    "2026-08-22T00:02:31+00:00",
                    "2026-08-22T00:02:32+00:00",
                    "2026-08-22T00:02:33+00:00",
                    "2026-08-22T00:02:34+00:00",
                ),
            )
            catalog.connection.commit()
            with self.assertRaises(ValidationError):
                catalog.commit_imported_cassette_authority(
                    fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
                )

    def test_replay_and_active_load_reject_unmodeled_postcommit_command(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command(
            "forbidden-remount-4", "mount", "completed"
        )

        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_restart_recovery_lineage_accepts_current_generation_two(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command("unload-4", "unload", "terminated")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
        self._append_quiesced_postcommit_command(
            "retry-unload-4",
            "unload",
            "completed",
            start_microseconds=10,
            issued_generation=2,
        )
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", 2), "retry-unload-4"
            )
            command_receipt = catalog.create_command_quiescence_receipt(
                "operation-4", current
            )
            target_row = catalog.connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = catalog.connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            physical = catalog.create_physical_reconciliation_receipt(
                "operation-4",
                current,
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=HardwareTargetBinding(
                        target_row["mount_path_sha256"],
                        target_row["tape_device_identity_sha256"],
                        target_row["scsi_device_identity_sha256"],
                        target_row["expected_media_scope_sha256"],
                    ),
                    observed_media_identity_sha256=media,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
            catalog.resolve_recovery(
                "operation-4",
                current,
                SafeRecoveryResolution(
                    reason_code="restart-unload-reconciled",
                    command_receipt_id=command_receipt.id,
                    physical_receipt_id=physical.id,
                ),
            )

        self.assertEqual(5, self._load().next_cassette().sequence)
        lineage_mutations = (
            "DELETE FROM imported_recovery_lineage_receipts",
            "UPDATE imported_recovery_lineage_receipts SET recovery_generation=3",
            (
                "UPDATE imported_recovery_lineage_receipts SET "
                "command_evidence_sha256="
                "'0000000000000000000000000000000000000000000000000000000000000000'"
            ),
        )
        for index, statement in enumerate(lineage_mutations):
            with self.subTest(lineage_mutation=index):
                copy = self.root / f"lineage-proof-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_restart_immediately_after_commit_is_attested_but_blocks_five(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)

        plan = self._load()
        self.assertEqual("active_linux", plan.authority_state)
        with self.assertRaises(FrozenJobStateInvalid):
            plan.next_cassette()
        self.assertEqual(5, plan.cassette_for_recovery(5).sequence)
        self.assertEqual(20, plan.cassette_for_recovery(20).sequence)
        with Catalog(self.database) as catalog:
            third = catalog.claim_daemon_owner("daemon-c")
            catalog.recover_interrupted_operations(third)
            catalog.recover_interrupted_operations(third)
            lineage_count = catalog.connection.execute(
                "SELECT COUNT(*) FROM imported_recovery_lineage_receipts "
                "WHERE operation_id='operation-4'"
            ).fetchone()[0]
        self.assertEqual(3, third.generation)
        self.assertEqual(2, lineage_count)
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()
        self._append_quiesced_postcommit_command(
            "restart-unload-4",
            "unload",
            "completed",
            issued_generation=3,
        )
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", 3), "restart-unload-4"
            )
            command_receipt = catalog.create_command_quiescence_receipt(
                "operation-4", third
            )
            target_row = catalog.connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = catalog.connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            physical = catalog.create_physical_reconciliation_receipt(
                "operation-4",
                third,
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=HardwareTargetBinding(
                        target_row["mount_path_sha256"],
                        target_row["tape_device_identity_sha256"],
                        target_row["scsi_device_identity_sha256"],
                        target_row["expected_media_scope_sha256"],
                    ),
                    observed_media_identity_sha256=media,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
            catalog.resolve_recovery(
                "operation-4",
                third,
                SafeRecoveryResolution(
                    reason_code="postcommit-crash-unload-completed",
                    command_receipt_id=command_receipt.id,
                    physical_receipt_id=physical.id,
                ),
            )
        self.assertEqual(5, self._load().next_cassette().sequence)

    def test_restart_backfills_historical_quiesced_command_receipt(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "terminated")
        with Catalog(self.database) as catalog:
            self.assertEqual(
                0,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM imported_postcommit_command_receipts"
                ).fetchone()[0],
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)

        corrupted = self.root / "historical-command-corrupted.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(corrupted)) as target,
        ):
            source.backup(target)
        with closing(sqlite3.connect(corrupted)) as connection:
            connection.execute(
                "UPDATE hardware_command_executions SET argv_sha256=? "
                "WHERE id='unload-4'",
                ("5" * 64,),
            )
            connection.commit()
        with Catalog(corrupted) as catalog, self.assertRaises(ValidationError):
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", current.generation), "unload-4"
            )

        wrong_owner = self.root / "historical-command-wrong-owner.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(wrong_owner)) as target,
        ):
            source.backup(target)
        with closing(sqlite3.connect(wrong_owner)) as connection:
            connection.execute(
                "UPDATE daemon_ownership SET owner_id='daemon-forged' WHERE singleton=1"
            )
            connection.commit()
        with Catalog(wrong_owner) as catalog, self.assertRaises(ValidationError):
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", current.generation), "unload-4"
            )

        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", current.generation), "unload-4"
            )
            receipt = catalog.connection.execute(
                "SELECT * FROM imported_postcommit_command_receipts "
                "WHERE command_id='unload-4'"
            ).fetchone()
        self.assertEqual(1, receipt["issued_generation"])
        self.assertIsNotNone(receipt["recovery_lineage_id"])
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

    def test_restart_reconciles_pending_reserved_command_to_terminal_receipt(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            catalog.reserve_hardware_command(fence, "unload-4", "unload", "4" * 64)
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)

        pending = self._load()
        with self.assertRaises(FrozenJobStateInvalid):
            pending.next_cassette()

        corrupted = self._copy_database("pending-command-corrupted.db")
        with closing(sqlite3.connect(corrupted)) as connection:
            connection.execute(
                "UPDATE hardware_command_executions SET argv_sha256=? "
                "WHERE id='unload-4'",
                ("5" * 64,),
            )
            connection.commit()
        with Catalog(corrupted) as catalog:
            command = catalog.command("unload-4")
            quiesced_at = (
                datetime.fromisoformat(command.created_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.acknowledge_command_quiescence(
                "unload-4",
                current,
                CommandExitEvidence(
                    command_id="unload-4",
                    process=None,
                    outcome="launch_aborted",
                    quiesced_at=quiesced_at,
                ),
            )
            with self.assertRaises(ValidationError):
                catalog.attest_imported_postcommit_command(
                    RecoveryCommandFence("operation-4", current.generation),
                    "unload-4",
                )

        early = self._copy_database("pending-command-early-terminal.db")
        with Catalog(early) as catalog:
            command = catalog.command("unload-4")
            quiesced_at = (
                datetime.fromisoformat(command.created_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.acknowledge_command_quiescence(
                "unload-4",
                current,
                CommandExitEvidence(
                    command_id="unload-4",
                    process=None,
                    outcome="launch_aborted",
                    quiesced_at=quiesced_at,
                ),
            )
            with self.assertRaises(ValidationError):
                catalog.attest_imported_postcommit_command(
                    RecoveryCommandFence("operation-4", current.generation),
                    "unload-4",
                )

        with Catalog(self.database) as catalog:
            command = catalog.command("unload-4")
            observed_at = catalog.connection.execute(
                "SELECT recorded_at FROM imported_recovery_lineage_receipts "
                "WHERE operation_id='operation-4' ORDER BY recovery_generation DESC"
            ).fetchone()[0]
            quiesced_at = (
                datetime.fromisoformat(observed_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.acknowledge_command_quiescence(
                "unload-4",
                current,
                CommandExitEvidence(
                    command_id="unload-4",
                    process=None,
                    outcome="launch_aborted",
                    quiesced_at=quiesced_at,
                ),
            )

        terminal_unattested = self._load()
        with self.assertRaises(FrozenJobStateInvalid):
            terminal_unattested.next_cassette()

        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", current.generation), "unload-4"
            )
            receipt = catalog.connection.execute(
                "SELECT recovery_lineage_id FROM imported_postcommit_command_receipts "
                "WHERE command_id='unload-4'"
            ).fetchone()
        self.assertIsNotNone(receipt["recovery_lineage_id"])
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

    def test_pending_authorized_release_cannot_postdate_lineage_receipt(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            catalog.reserve_hardware_command(fence, "unload-4", "unload", "4" * 64)
            process = ProcessIdentity("boot-unload", 4100, 5100, 4100)
            catalog.record_blocked_process("unload-4", fence, process)
            permit = hashlib.sha256(b"release:unload-4").hexdigest()
            catalog.authorize_hardware_command_release("unload-4", fence, permit)
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)

        with ReadOnlyCatalog(self.database) as catalog:
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

        with closing(sqlite3.connect(self.database)) as connection:
            connection.row_factory = sqlite3.Row
            lineage = connection.execute(
                "SELECT * FROM imported_recovery_lineage_receipts "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            observations = [
                list(value)
                for value in json.loads(lineage["command_observations_json"])
            ]
            self.assertEqual("authorized", observations[0][21])
            observations[0][22] = "2099-01-01T00:00:00+00:00"
            frozen_observations = tuple(tuple(value) for value in observations)
            evidence = imported_postcommit_command_sha256(frozen_observations)
            lineage_sha256 = imported_recovery_lineage_sha256(
                (
                    lineage["id"],
                    lineage["job_id"],
                    lineage["sequence"],
                    lineage["operation_id"],
                    lineage["original_owner_generation"],
                    lineage["recovery_generation"],
                    lineage["daemon_owner_id"],
                    lineage["prior_lineage_id"],
                    lineage["commit_binding_sha256"],
                    lineage["restart_state"],
                    tuple(json.loads(lineage["command_ids_json"])),
                    evidence,
                    lineage["recorded_at"],
                )
            )
            connection.execute(
                "UPDATE hardware_command_release_authorizations "
                "SET authorized_at=? WHERE command_id='unload-4'",
                (observations[0][22],),
            )
            connection.execute(
                "UPDATE imported_recovery_lineage_receipts SET "
                "command_observations_json=?, command_evidence_sha256=?, "
                "lineage_sha256=? WHERE id=?",
                (
                    json.dumps(frozen_observations, separators=(",", ":")),
                    evidence,
                    lineage_sha256,
                    lineage["id"],
                ),
            )
            connection.commit()

        with (
            ReadOnlyCatalog(self.database) as catalog,
            self.assertRaises(FrozenJobAuthorityInvalid),
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_public_postcommit_command_state_matrix(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

        scenarios = (
            ("reserved-aborted", "reserved", "launch_aborted", True),
            ("blocked-terminated", "blocked", "terminated", False),
            ("released-terminated", "released", "terminated", True),
            ("released-completed", "released", "completed", True),
            ("reserved-terminated", "reserved", "terminated", False),
            ("reserved-completed", "reserved", "completed", False),
            ("blocked-aborted", "blocked", "launch_aborted", True),
            ("blocked-completed", "blocked", "completed", False),
            ("released-aborted", "released", "launch_aborted", False),
        )
        for index, (name, launch_state, outcome, accepted) in enumerate(scenarios):
            with self.subTest(name=name):
                database = self._copy_database(f"state-matrix-{index}.db")
                with Catalog(database) as catalog:
                    owner = DaemonFence("daemon-a", 1)
                    catalog.reserve_hardware_command(
                        fence, "unload-4", "unload", "4" * 64
                    )
                    process = None
                    if launch_state in {"blocked", "released"}:
                        process = ProcessIdentity("boot-unload", 4100, 5100, 4100)
                        catalog.record_blocked_process("unload-4", fence, process)
                    if launch_state == "released":
                        self._confirm_command_release(catalog, "unload-4", fence)
                    command = catalog.command("unload-4")
                    boundary = command.released_at or command.created_at
                    quiesced_at = (
                        datetime.fromisoformat(boundary) + timedelta(microseconds=1)
                    ).isoformat()
                    evidence = CommandExitEvidence(
                        command_id="unload-4",
                        process=process,
                        outcome=outcome,
                        quiesced_at=quiesced_at,
                    )
                    if not accepted:
                        with self.assertRaises(
                            (ValidationError, CommandQuiescenceRequired)
                        ):
                            catalog.acknowledge_command_quiescence(
                                "unload-4", owner, evidence
                            )
                        continue
                    catalog.acknowledge_command_quiescence("unload-4", owner, evidence)
                    command = catalog.command("unload-4")
                    self.assertEqual("quiesced", command.state)
                    self.assertEqual(outcome, command.exit_outcome)
                    self.assertEqual(
                        launch_state == "released", command.released_at is not None
                    )
                    catalog.attest_imported_postcommit_command(fence, "unload-4")
                    self.assertEqual(
                        1,
                        catalog.connection.execute(
                            "SELECT COUNT(*) FROM imported_postcommit_command_receipts"
                        ).fetchone()[0],
                    )

    def test_restart_reconciles_blocked_and_released_command_observations(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

        for index, launch_state in enumerate(("blocked", "released")):
            with self.subTest(launch_state=launch_state):
                database = self._copy_database(f"restart-{launch_state}-{index}.db")
                with Catalog(database) as catalog:
                    catalog.reserve_hardware_command(
                        fence, "unload-4", "unload", "4" * 64
                    )
                    process = ProcessIdentity("boot-unload", 4100, 5100, 4100)
                    catalog.record_blocked_process("unload-4", fence, process)
                    if launch_state == "released":
                        self._confirm_command_release(catalog, "unload-4", fence)
                    current = catalog.claim_daemon_owner("daemon-b")
                    catalog.recover_interrupted_operations(current)
                    observed_at = catalog.connection.execute(
                        "SELECT recorded_at FROM imported_recovery_lineage_receipts "
                        "WHERE operation_id='operation-4' "
                        "ORDER BY recovery_generation DESC"
                    ).fetchone()[0]
                    quiesced_at = (
                        datetime.fromisoformat(observed_at) + timedelta(microseconds=1)
                    ).isoformat()
                    catalog.acknowledge_command_quiescence(
                        "unload-4",
                        current,
                        CommandExitEvidence(
                            command_id="unload-4",
                            process=process,
                            outcome=(
                                "terminated"
                                if launch_state == "released"
                                else "launch_aborted"
                            ),
                            quiesced_at=quiesced_at,
                        ),
                    )
                    catalog.attest_imported_postcommit_command(
                        RecoveryCommandFence("operation-4", current.generation),
                        "unload-4",
                    )
                    receipt = catalog.connection.execute(
                        "SELECT recovery_lineage_id FROM "
                        "imported_postcommit_command_receipts "
                        "WHERE command_id='unload-4'"
                    ).fetchone()
                self.assertIsNotNone(receipt["recovery_lineage_id"])
                with ReadOnlyCatalog(database) as catalog:
                    plan = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
                with self.assertRaises(FrozenJobStateInvalid):
                    plan.next_cassette()

    def test_schema_fourteen_lineage_upgrade_backfills_exact_observation(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "terminated")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
        self._downgrade_lineage_to_fixr6_schema_fourteen()

        manager = BackupManager(self.database, self.root / "schema-backups")
        manager.prepare_and_initialize()
        fresh_database = self.root / "fresh-schema-fifteen.db"
        BackupManager(
            fresh_database, self.root / "fresh-schema-backups"
        ).prepare_and_initialize()
        with Catalog(self.database) as catalog:
            observation = catalog.connection.execute(
                "SELECT command_observations_json FROM "
                "imported_recovery_lineage_receipts"
            ).fetchone()[0]
            upgraded_schema = tuple(
                tuple(row)
                for row in catalog.connection.execute(
                    "PRAGMA table_info(imported_recovery_lineage_receipts)"
                )
            )
            upgraded_objects = tuple(
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "WHERE name='imported_recovery_lineage_receipts' "
                    "OR tbl_name='imported_recovery_lineage_receipts' "
                    "ORDER BY type, name"
                )
            )
        with closing(sqlite3.connect(fresh_database)) as connection:
            fresh_schema = tuple(
                tuple(row)
                for row in connection.execute(
                    "PRAGMA table_info(imported_recovery_lineage_receipts)"
                )
            )
            fresh_objects = tuple(
                tuple(row)
                for row in connection.execute(
                    "SELECT type, name, tbl_name, sql FROM sqlite_master "
                    "WHERE name='imported_recovery_lineage_receipts' "
                    "OR tbl_name='imported_recovery_lineage_receipts' "
                    "ORDER BY type, name"
                )
            )
        self.assertIsNotNone(observation)
        self.assertEqual(fresh_schema, upgraded_schema)
        self.assertEqual(fresh_objects, upgraded_objects)
        self.assertEqual(
            set(range(14, SCHEMA_VERSION)),
            {record.schema_version for record in manager.list_backups(protected=True)},
        )
        legacy = next(
            record
            for record in manager.list_backups(protected=True)
            if record.schema_version == 14
        )
        with closing(sqlite3.connect(legacy.path)) as connection:
            legacy_observation_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(imported_recovery_lineage_receipts)"
                )
            }
            legacy_lineages = connection.execute(
                "SELECT COUNT(*) FROM imported_recovery_lineage_receipts"
            ).fetchone()[0]
        self.assertNotIn("command_observations_json", legacy_observation_columns)
        self.assertEqual(1, legacy_lineages)
        plan = self._load()
        self.assertEqual("active_linux", plan.authority_state)
        with self.assertRaises(FrozenJobStateInvalid):
            plan.next_cassette()

    def test_real_fixr6_schema_fourteen_lineage_upgrades_legacy_digest(self) -> None:
        database = self.root / "real-fixr6-schema14.db"
        self._restore_real_fixr6_schema_fourteen(database)
        with closing(sqlite3.connect(database)) as connection:
            schema = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            lineage = connection.execute(
                "SELECT command_evidence_sha256, lineage_sha256 "
                "FROM imported_recovery_lineage_receipts"
            ).fetchone()
        self.assertEqual("14", schema)
        self.assertEqual(
            "826afa05f5562249f95291a7c3e376cf4e10699f33246075e984e00028db7006",
            lineage[0],
        )
        self.assertEqual(
            "ded0214f9a20bfc134d4cee0d50fd7518d130a454421806460815e5dc75cc577",
            lineage[1],
        )

        BackupManager(
            database, self.root / "real-fixr6-schema14-backups"
        ).prepare_and_initialize()

        with ReadOnlyCatalog(database) as catalog:
            plan = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
            upgraded = catalog.connection.execute(
                "SELECT command_observations_json, command_evidence_sha256, "
                "lineage_sha256 FROM imported_recovery_lineage_receipts"
            ).fetchone()
            upgraded_scope = catalog.connection.execute(
                "SELECT expected_media_scope_sha256 FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()[0]
        self.assertEqual("active_linux", plan.authority_state)
        self.assertIsNotNone(upgraded[0])
        observations = tuple(tuple(value) for value in json.loads(upgraded[0]))
        self.assertTrue(observations)
        self.assertTrue(all(len(observation) == 24 for observation in observations))
        self.assertEqual(
            expected_media_scope_sha256(
                (
                    "archive.resume",
                    "JOB-MIGRATION",
                    "4",
                    "TAPE04",
                    "",
                    "",
                )
            ),
            upgraded_scope,
        )
        self.assertNotEqual(lineage[0], upgraded[1])
        self.assertNotEqual(lineage[1], upgraded[2])

    def test_real_fixr6_lineage_release_tamper_rolls_back_upgrade(self) -> None:
        mutations = {
            "missing": (
                "DELETE FROM hardware_command_release_authorizations "
                "WHERE command_id='unload-4'"
            ),
            "status": (
                "UPDATE hardware_command_release_authorizations "
                "SET release_status='aborted' WHERE command_id='unload-4'"
            ),
        }
        for name, statement in mutations.items():
            with self.subTest(mutation=name):
                database = self.root / f"real-fixr6-{name}.db"
                self._restore_real_fixr6_schema_fourteen(database)
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("PRAGMA foreign_keys=OFF")
                    connection.execute(statement)
                    connection.commit()
                before = self._database_dump(database)
                manager = BackupManager(
                    database, self.root / f"real-fixr6-{name}-backups"
                )

                with self.assertRaisesRegex(CatalogError, "legacy recovery lineage"):
                    manager.prepare_and_initialize()

                self.assertEqual(before, self._database_dump(database))
                with closing(sqlite3.connect(database)) as connection:
                    schema = connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0]
                self.assertEqual("14", schema)

    def test_real_fixr6_succeeded_receipts_upgrade_without_lineage(self) -> None:
        database = self.root / "real-fixr6-succeeded-schema14.db"
        self._restore_schema_fourteen_fixture(
            database, self._FIXR6_SUCCEEDED_SCHEMA14_FIXTURE
        )
        with closing(sqlite3.connect(database)) as connection:
            schema = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            receipts = tuple(
                connection.execute(
                    "SELECT command_id, command_evidence_sha256 FROM "
                    "imported_postcommit_command_receipts ORDER BY command_order"
                )
            )
            lineage_count = connection.execute(
                "SELECT COUNT(*) FROM imported_recovery_lineage_receipts"
            ).fetchone()[0]
        self.assertEqual("14", schema)
        self.assertEqual(0, lineage_count)
        self.assertEqual(
            (
                (
                    "unload-4",
                    "423917f375fc076f7e2fe9694ed573b00ca66788dec209d679db4ab1f15aa21a",
                ),
            ),
            receipts,
        )

        BackupManager(
            database, self.root / "real-fixr6-succeeded-schema14-backups"
        ).prepare_and_initialize()

        with ReadOnlyCatalog(database) as catalog:
            plan = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
            upgraded = tuple(
                catalog.connection.execute(
                    "SELECT command_id, command_evidence_sha256 FROM "
                    "imported_postcommit_command_receipts ORDER BY command_order"
                )
            )
            upgraded_lineage_count = catalog.connection.execute(
                "SELECT COUNT(*) FROM imported_recovery_lineage_receipts"
            ).fetchone()[0]
        self.assertEqual(5, plan.next_cassette().sequence)
        self.assertEqual(0, upgraded_lineage_count)
        self.assertEqual(
            tuple(row[0] for row in receipts), tuple(row[0] for row in upgraded)
        )
        self.assertTrue(
            all(before[1] != after[1] for before, after in zip(receipts, upgraded))
        )

    def test_real_fixr6_succeeded_receipt_tamper_rolls_back_upgrade(self) -> None:
        mutations = {
            "missing": (
                "DELETE FROM imported_postcommit_command_receipts "
                "WHERE command_id='unload-4'"
            ),
            "orphan": (
                "UPDATE imported_postcommit_command_receipts "
                "SET command_id='orphan-unload-4' WHERE command_id='unload-4'"
            ),
            "digest": (
                "UPDATE imported_postcommit_command_receipts "
                f"SET command_evidence_sha256='{'0' * 64}' "
                "WHERE command_id='unload-4'"
            ),
        }
        for name, statement in mutations.items():
            with self.subTest(mutation=name):
                database = self.root / f"real-fixr6-succeeded-{name}.db"
                self._restore_schema_fourteen_fixture(
                    database, self._FIXR6_SUCCEEDED_SCHEMA14_FIXTURE
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute("PRAGMA foreign_keys=OFF")
                    connection.execute(statement)
                    connection.commit()
                self._assert_schema_fourteen_upgrade_rolls_back(database, name)

        duplicate = self.root / "real-fixr6-succeeded-duplicate.db"
        self._restore_schema_fourteen_fixture(
            duplicate, self._FIXR6_SUCCEEDED_SCHEMA14_FIXTURE
        )
        self._duplicate_postcommit_receipt(duplicate)
        self._assert_schema_fourteen_upgrade_rolls_back(duplicate, "duplicate")

    def test_real_fixr6_postcommit_target_tamper_is_not_normalized(self) -> None:
        fields = (
            "mount_path_sha256",
            "tape_device_identity_sha256",
            "scsi_device_identity_sha256",
            "expected_media_scope_sha256",
            "observed_media_identity_sha256",
        )
        for index, field in enumerate(fields):
            with self.subTest(field=field):
                database = self.root / f"real-fixr6-target-{index}.db"
                self._restore_schema_fourteen_fixture(
                    database, self._FIXR6_SUCCEEDED_SCHEMA14_FIXTURE
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(
                        f"UPDATE hardware_command_executions SET {field}=? "
                        "WHERE id='unload-4'",
                        ("f" * 64,),
                    )
                    connection.commit()
                self._rebind_schema14_postcommit_receipt(database, "unload-4")
                self._assert_schema_fourteen_upgrade_rolls_back(
                    database, f"target-{index}"
                )

    def test_real_fixr6_operation_and_commit_target_mismatch_rolls_back(self) -> None:
        mutations = {
            "operation": (
                "UPDATE operation_hardware_targets SET mount_path_sha256=? "
                "WHERE operation_id='operation-4'"
            ),
            "commit": (
                "UPDATE imported_cassette_commit_receipts SET mount_path_sha256=? "
                "WHERE operation_id='operation-4'"
            ),
        }
        for name, statement in mutations.items():
            with self.subTest(mutation=name):
                database = self.root / f"real-fixr6-{name}-target.db"
                self._restore_schema_fourteen_fixture(
                    database, self._FIXR6_SUCCEEDED_SCHEMA14_FIXTURE
                )
                with closing(sqlite3.connect(database)) as connection:
                    connection.execute(statement, ("f" * 64,))
                    connection.commit()
                self._assert_schema_fourteen_upgrade_rolls_back(
                    database, f"{name}-target"
                )

    def _assert_schema_fourteen_upgrade_rolls_back(
        self, database: Path, name: str
    ) -> None:
        before = self._database_dump(database)
        manager = BackupManager(
            database, self.root / f"real-fixr6-succeeded-{name}-backups"
        )
        with self.assertRaises(CatalogError):
            manager.prepare_and_initialize()
        self.assertEqual(before, self._database_dump(database))
        with closing(sqlite3.connect(database)) as connection:
            schema = connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
        self.assertEqual("14", schema)

    def test_schema_fourteen_lineage_upgrade_rejects_incomplete_backfill(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "terminated")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
        self._downgrade_lineage_to_fixr6_schema_fourteen()
        baseline = self.root / "fixr6-lineage.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(baseline)) as target,
        ):
            source.backup(target)

        mutations = {
            "missing-command": (
                (
                    "DELETE FROM imported_postcommit_command_receipts "
                    "WHERE command_id='unload-4'"
                ),
                (
                    "DELETE FROM hardware_command_release_authorizations "
                    "WHERE command_id='unload-4'"
                ),
                "DELETE FROM hardware_command_executions WHERE id='unload-4'",
            ),
            "invalid-json": (
                ("UPDATE imported_recovery_lineage_receipts SET command_ids_json='{'"),
            ),
            "digest-mismatch": (
                (
                    "UPDATE imported_recovery_lineage_receipts "
                    f"SET command_evidence_sha256='{'0' * 64}'"
                ),
            ),
            "malformed-identity": (
                (
                    "UPDATE hardware_command_executions "
                    "SET argv_sha256='not-a-sha256' WHERE id='unload-4'"
                ),
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                candidate = self.root / f"malformed-{name}.db"
                with (
                    closing(sqlite3.connect(baseline)) as source,
                    closing(sqlite3.connect(candidate)) as target,
                ):
                    source.backup(target)
                with closing(sqlite3.connect(candidate)) as connection:
                    connection.execute("PRAGMA foreign_keys=OFF")
                    for statement in mutation:
                        connection.execute(statement)
                    connection.commit()
                before = self._database_dump(candidate)
                manager = BackupManager(
                    candidate, self.root / f"malformed-{name}-backups"
                )

                with self.assertRaisesRegex(CatalogError, "legacy recovery lineage"):
                    manager.prepare_and_initialize()

                self.assertEqual(before, self._database_dump(candidate))
                with closing(sqlite3.connect(candidate)) as connection:
                    schema = connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0]
                self.assertEqual("14", schema)
                protected = manager.list_backups(protected=True)
                self.assertEqual({14}, {item.schema_version for item in protected})
                self.assertTrue(all(item.verified for item in protected))

                with (
                    closing(sqlite3.connect(baseline)) as source,
                    closing(sqlite3.connect(candidate)) as target,
                ):
                    source.backup(target)
                manager.prepare_and_initialize()
                with closing(sqlite3.connect(candidate)) as connection:
                    upgraded = connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0]
                self.assertEqual(str(SCHEMA_VERSION), upgraded)

    def test_schema_fourteen_upgrade_revalidates_full_frozen_authority(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "terminated")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
        self._downgrade_lineage_to_fixr6_schema_fourteen()
        baseline = self.root / "fixr6-semantic-authority.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(baseline)) as target,
        ):
            source.backup(target)

        mutations = {
            "commit-source": "UPDATE imported_cassette_commit_receipts "
            f"SET evidence_sha256='{'1' * 64}'",
            "commit-target": "UPDATE imported_cassette_commit_receipts "
            f"SET mount_path_sha256='{'2' * 64}'",
            "commit-media": "UPDATE imported_cassette_commit_receipts "
            f"SET observed_media_identity_sha256='{'3' * 64}'",
            "operation-target": "UPDATE operation_hardware_targets "
            f"SET tape_device_identity_sha256='{'4' * 64}'",
            "media-binding": "UPDATE operation_media_identity_bindings "
            f"SET observed_media_identity_sha256='{'5' * 64}'",
            "cutover-authorization": "UPDATE cutover_authorizations "
            f"SET credential_sha256='{'6' * 64}'",
            "canonical-commit-binding": "UPDATE imported_cassette_commit_receipts "
            f"SET commit_binding_sha256='{'7' * 64}'",
        }
        for name, mutation in mutations.items():
            with self.subTest(mutation=name):
                candidate = self.root / f"semantic-{name}.db"
                with (
                    closing(sqlite3.connect(baseline)) as source,
                    closing(sqlite3.connect(candidate)) as target,
                ):
                    source.backup(target)
                with closing(sqlite3.connect(candidate)) as connection:
                    connection.execute(mutation)
                    connection.commit()
                before = self._database_dump(candidate)
                manager = BackupManager(
                    candidate, self.root / f"semantic-{name}-backups"
                )

                with self.assertRaises(CatalogError):
                    manager.prepare_and_initialize()

                self.assertEqual(before, self._database_dump(candidate))
                with closing(sqlite3.connect(candidate)) as connection:
                    schema = connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()[0]
                self.assertEqual("14", schema)
                protected = manager.list_backups(protected=True)
                self.assertEqual({14}, {item.schema_version for item in protected})
                self.assertTrue(all(item.verified for item in protected))

    def test_later_restart_reconciles_prior_recovery_generation_command(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
            second = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(second)
            recovery_fence = RecoveryCommandFence("operation-4", second.generation)
            catalog.reserve_hardware_command(
                recovery_fence, "unload-4", "unload", "4" * 64
            )
            process = ProcessIdentity("boot-unload", 4100, 5100, 4100)
            catalog.record_blocked_process("unload-4", recovery_fence, process)
            third = catalog.claim_daemon_owner("daemon-c")
            catalog.recover_interrupted_operations(third)
            observed_at = catalog.connection.execute(
                "SELECT recorded_at FROM imported_recovery_lineage_receipts "
                "WHERE recovery_generation=?",
                (third.generation,),
            ).fetchone()[0]
            quiesced_at = (
                datetime.fromisoformat(observed_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.acknowledge_command_quiescence(
                "unload-4",
                third,
                CommandExitEvidence(
                    command_id="unload-4",
                    process=process,
                    outcome="launch_aborted",
                    quiesced_at=quiesced_at,
                ),
            )
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", third.generation), "unload-4"
            )
            receipt = catalog.connection.execute(
                "SELECT issued_generation, recovery_lineage_id FROM "
                "imported_postcommit_command_receipts WHERE command_id='unload-4'"
            ).fetchone()
        self.assertEqual(2, receipt["issued_generation"])
        self.assertIsNotNone(receipt["recovery_lineage_id"])
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

    def test_launch_aborted_postcommit_command_uses_public_lifecycle(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "launch_aborted")
        with Catalog(self.database) as catalog:
            command = catalog.command("unload-4")
            self.assertIsNone(command.released_at)
            self.assertEqual("launch_aborted", command.exit_outcome)
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

        malformed = self.root / "launch-aborted-released.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(malformed)) as target,
        ):
            source.backup(target)
        with closing(sqlite3.connect(malformed)) as connection:
            connection.execute(
                "UPDATE hardware_command_executions SET released_at=created_at "
                "WHERE id='unload-4'"
            )
            connection.commit()
        with (
            ReadOnlyCatalog(malformed) as catalog,
            self.assertRaises(FrozenJobAuthorityInvalid),
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_commit_replay_accepts_attested_pre_authorization_launch_abort(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            expected = catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "launch_aborted")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            replayed = catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

        self.assertEqual(expected, replayed)

    def test_completed_unload_crash_resolves_without_replay_unload(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "completed")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)

        stale_active = self.root / "completed-unload-stale-active-owner.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(stale_active)) as target,
        ):
            source.backup(target)
        with Catalog(stale_active) as catalog:
            catalog.claim_daemon_owner("daemon-c")
        with (
            ReadOnlyCatalog(stale_active) as catalog,
            self.assertRaises(FrozenJobAuthorityInvalid),
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

        plan = self._load()
        with self.assertRaises(FrozenJobStateInvalid):
            plan.next_cassette()
        self._resolve_current_recovery(current, "completed-unload-after-crash")
        with Catalog(self.database) as catalog:
            unload_count = catalog.connection.execute(
                "SELECT COUNT(*) FROM hardware_command_executions "
                "WHERE operation_id='operation-4' AND command_kind='unload'"
            ).fetchone()[0]
        self.assertEqual(1, unload_count)
        self.assertEqual(5, self._load().next_cassette().sequence)

    def test_resolved_recovery_survives_later_daemon_generations(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "completed")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
        self._resolve_current_recovery(current, "completed-unload-after-crash")

        with Catalog(self.database) as catalog:
            self.assertEqual(3, catalog.claim_daemon_owner("daemon-c").generation)
            self.assertEqual(4, catalog.claim_daemon_owner("daemon-d").generation)
        self.assertEqual(5, self._load().next_cassette().sequence)

        missing = self.root / "terminal-lineage-missing.db"
        with (
            closing(sqlite3.connect(self.database)) as source,
            closing(sqlite3.connect(missing)) as target,
        ):
            source.backup(target)
        with closing(sqlite3.connect(missing)) as connection:
            connection.execute("DELETE FROM imported_recovery_lineage_receipts")
            connection.commit()
        with (
            ReadOnlyCatalog(missing) as catalog,
            self.assertRaises(FrozenJobAuthorityInvalid),
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_attested_postcommit_command_mutation_is_rejected(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command("unload-4", "unload", "completed")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(fence, "succeeded")
        mutations = (
            (
                "UPDATE hardware_command_executions SET argv_sha256='9' || "
                "substr(argv_sha256, 2) WHERE id='unload-4'"
            ),
            (
                "UPDATE hardware_command_executions SET "
                "released_at=exit_observed_at WHERE id='unload-4'"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"postcommand-evidence-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_active_authority_rejects_missing_postcommit_release_row(self) -> None:
        self._activate_and_finish_with_released_unload()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM hardware_command_release_authorizations "
                "WHERE command_id='unload-4'"
            )

        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_active_authority_rejects_tampered_release_permit(self) -> None:
        self._activate_and_finish_with_released_unload()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE hardware_command_release_authorizations "
                "SET permit_sha256=? WHERE command_id='unload-4'",
                ("f" * 64,),
            )

        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_active_authority_rejects_tampered_release_status(self) -> None:
        self._activate_and_finish_with_released_unload()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE hardware_command_release_authorizations "
                "SET release_status='aborted' WHERE command_id='unload-4'"
            )

        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_active_authority_rejects_tampered_release_timestamp(self) -> None:
        self._activate_and_finish_with_released_unload()
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE hardware_command_release_authorizations "
                "SET confirmed_at='2099-01-01T00:00:00+00:00' "
                "WHERE command_id='unload-4'"
            )

        with self.assertRaises(FrozenJobAuthorityInvalid):
            self._load()

    def test_active_authority_rejects_duplicate_release_rows(self) -> None:
        self._activate_and_finish_with_released_unload()
        copy = self._copy_database("duplicate-release-row.db")
        self._duplicate_release_row(copy, "unload-4")

        with (
            ReadOnlyCatalog(copy) as catalog,
            self.assertRaises(FrozenJobAuthorityInvalid),
        ):
            FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_recovery_lineage_rejects_missing_release_evidence(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "unload-4", "completed")
        with Catalog(self.database) as catalog:
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.connection.execute(
                "DELETE FROM hardware_command_release_authorizations "
                "WHERE command_id='unload-4'"
            )
            catalog.connection.commit()
            with self.assertRaises(CatalogError):
                catalog.recover_interrupted_operations(current)

    def test_commit_replay_rejects_duplicate_postcommit_unloads(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command("unload-4", "unload", "completed")
        self._append_quiesced_postcommit_command(
            "duplicate-unload-4", "unload", "completed", start_microseconds=10
        )

        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )

    def test_cutover_authorization_full_evidence_is_immutable(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        mutations = (
            (
                "UPDATE cutover_authorizations SET credential_sha256='9' || "
                "substr(credential_sha256, 2) WHERE id='authorization-4'"
            ),
            (
                "UPDATE cutover_authorizations SET host_id='forged-host' "
                "WHERE id='authorization-4'"
            ),
            (
                "UPDATE cutover_authorizations SET "
                "created_at='2026-08-21T23:58:00+00:00' "
                "WHERE id='authorization-4'"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"authorization-evidence-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_replay_and_active_load_reattest_authority_record_ids(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        mutations = (
            (
                "UPDATE imported_cassette_commit_receipts "
                "SET migration_receipt_id='forged-migration-receipt'"
            ),
            (
                "UPDATE imported_cassette_commit_receipts "
                "SET cutover_authorization_id='forged-cutover-authorization'"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"authority-id-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with Catalog(copy) as catalog, self.assertRaises(ValidationError):
                    catalog.commit_imported_cassette_authority(
                        fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
                    )
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_resolved_postcommit_unload_recovery_allows_next_cassette(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._append_quiesced_postcommit_command("unload-4", "unload", "terminated")
        daemon_fence = DaemonFence("daemon-a", 1)
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
        self._append_quiesced_postcommit_command(
            "retry-unload-4",
            "unload",
            "completed",
            start_microseconds=10,
        )
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(
                RecoveryCommandFence("operation-4", 1), "retry-unload-4"
            )
            command_receipt = catalog.create_command_quiescence_receipt(
                "operation-4", daemon_fence
            )
            target_row = catalog.connection.execute(
                "SELECT * FROM operation_hardware_targets "
                "WHERE operation_id='operation-4'"
            ).fetchone()
            media = catalog.connection.execute(
                "SELECT observed_media_identity_sha256 FROM "
                "operation_media_identity_bindings WHERE operation_id='operation-4'"
            ).fetchone()[0]
            target = HardwareTargetBinding(
                target_row["mount_path_sha256"],
                target_row["tape_device_identity_sha256"],
                target_row["scsi_device_identity_sha256"],
                target_row["expected_media_scope_sha256"],
            )
            physical_receipt = catalog.create_physical_reconciliation_receipt(
                "operation-4",
                daemon_fence,
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=target,
                    observed_media_identity_sha256=media,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
            resolved = catalog.resolve_recovery(
                "operation-4",
                daemon_fence,
                SafeRecoveryResolution(
                    reason_code="unload-reconciled-physically-safe",
                    command_receipt_id=command_receipt.id,
                    physical_receipt_id=physical_receipt.id,
                ),
            )

        self.assertEqual("cancelled", resolved.state)
        self.assertEqual(5, self._load().next_cassette().sequence)

        mutations = (
            "UPDATE recovery_resolutions SET resolved_by_generation=2",
            (
                "UPDATE physical_reconciliation_receipts SET recorded_at=("
                "SELECT committed_at FROM imported_cassette_commit_receipts)"
            ),
            (
                "UPDATE hardware_command_executions SET issued_generation=2 "
                "WHERE id='retry-unload-4'"
            ),
            "DELETE FROM hardware_command_executions WHERE id='retry-unload-4'",
            (
                "UPDATE imported_recovery_resolution_receipts SET "
                "resolution_evidence_sha256="
                "'0000000000000000000000000000000000000000000000000000000000000000'"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(recovery_mutation=index):
                copy = self.root / f"recovery-proof-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_sequence_four_failed_unload_retries_once_under_new_recovery_owner(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "failed-unload-4", "terminated")
        with Catalog(self.database) as catalog:
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="unload_failed",
            )
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
            recovery_fence = RecoveryCommandFence("operation-4", current.generation)
        self._run_public_postcommit_command(
            recovery_fence, "completed-unload-4", "completed"
        )
        with Catalog(self.database) as catalog:
            expected = catalog.attest_imported_postcommit_unload(recovery_fence)
            replayed = catalog.attest_imported_postcommit_unload(recovery_fence)
            self.assertEqual(expected, replayed)
        self._run_public_postcommit_command(
            recovery_fence, "duplicate-completed-unload-4", "completed"
        )
        with Catalog(self.database) as catalog, self.assertRaises(ValidationError):
            catalog.attest_imported_postcommit_unload(recovery_fence)

    def test_sequence_four_original_unload_receipt_replays_after_restart(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "completed-unload-4", "completed")
        with Catalog(self.database) as catalog:
            expected = catalog.attest_imported_postcommit_unload(fence)
            receipt = catalog.connection.execute(
                "SELECT recovery_lineage_id FROM "
                "imported_postcommit_command_receipts "
                "WHERE command_id='completed-unload-4'"
            ).fetchone()
            self.assertIsNone(receipt["recovery_lineage_id"])
            current = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(current)
            replayed = catalog.attest_imported_postcommit_unload(
                RecoveryCommandFence("operation-4", current.generation)
            )
            stored = catalog.connection.execute(
                "SELECT recovery_lineage_id FROM "
                "imported_postcommit_command_receipts "
                "WHERE command_id='completed-unload-4'"
            ).fetchone()
        self.assertEqual(expected, replayed)
        self.assertIsNone(stored["recovery_lineage_id"])

    def test_sequence_four_historical_lineage_receipt_replays_after_restart(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        self._run_public_postcommit_command(fence, "historical-unload-4", "completed")
        with Catalog(self.database) as catalog:
            second = catalog.claim_daemon_owner("daemon-b")
            catalog.recover_interrupted_operations(second)
            expected = catalog.attest_imported_postcommit_unload(
                RecoveryCommandFence("operation-4", second.generation)
            )
            historical = catalog.connection.execute(
                "SELECT recovery_lineage_id FROM "
                "imported_postcommit_command_receipts "
                "WHERE command_id='historical-unload-4'"
            ).fetchone()[0]
            self.assertIsNotNone(historical)
            third = catalog.claim_daemon_owner("daemon-c")
            catalog.recover_interrupted_operations(third)
            replayed = catalog.attest_imported_postcommit_unload(
                RecoveryCommandFence("operation-4", third.generation)
            )
            stored = catalog.connection.execute(
                "SELECT recovery_lineage_id FROM "
                "imported_postcommit_command_receipts "
                "WHERE command_id='historical-unload-4'"
            ).fetchone()[0]
        self.assertEqual(expected, replayed)
        self.assertEqual(historical, stored)

    def test_active_authority_survives_crash_and_unload_failure_after_commit(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        with self.assertRaises(FrozenJobStateInvalid):
            self._load().next_cassette()

        self._append_quiesced_postcommit_command("unload-4", "unload", "terminated")
        with Catalog(self.database) as catalog:
            catalog.attest_imported_postcommit_command(fence, "unload-4")
            catalog.finish_operation(
                fence,
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
        plan = self._load()
        self.assertEqual("active_linux", plan.authority_state)
        with self.assertRaises(FrozenJobStateInvalid):
            plan.next_cassette()

    def test_fenced_commit_rejects_impossible_timeline_and_wrong_generation(
        self,
    ) -> None:
        fence = self._seed_running_four_commit()
        mutations = (
            (
                "UPDATE blocks SET started_at='9999-01-01T00:00:00+00:00' "
                "WHERE id='BLOCK04-01'"
            ),
            (
                "UPDATE hardware_command_executions SET issued_generation=2 "
                "WHERE id='inquiry-mount-4'"
            ),
            (
                "UPDATE hardware_command_executions SET quiesced_at=NULL "
                "WHERE id='inquiry-mount-4'"
            ),
            (
                "UPDATE hardware_command_executions SET quiesced_at='malformed' "
                "WHERE id='inquiry-mount-4'"
            ),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"timeline-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    Catalog(copy) as catalog,
                    self.assertRaises(ValidationError),
                ):
                    catalog.commit_imported_cassette_authority(
                        fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
                    )

    def test_commit_requires_the_exact_current_operation_fence(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.claim_daemon_owner("daemon-b")
            with self.assertRaises(StaleOperationFence):
                catalog.commit_imported_cassette_authority(
                    fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
                )

    def test_active_commit_rejects_mutated_media_and_relational_proof(self) -> None:
        fence = self._seed_running_four_commit()
        with Catalog(self.database) as catalog:
            catalog.commit_imported_cassette_authority(
                fence, "TAPE04", ("BLOCK04-01", "BLOCK04-02")
            )
        mutations = (
            (
                "UPDATE operation_media_identity_bindings SET "
                "observed_media_identity_sha256="
                "'6' || substr(observed_media_identity_sha256, 2)"
            ),
            "UPDATE blocks SET status='failed' WHERE id='BLOCK04-01'",
            "UPDATE file_versions SET visible=0 WHERE block_id='BLOCK04-01'",
            (
                "UPDATE operation_hardware_targets SET mount_path_sha256="
                "'0000000000000000000000000000000000000000000000000000000000000000' "
                "WHERE operation_id='operation-4'"
            ),
            ("UPDATE daemon_operations SET cassette_sequence=5 WHERE id='operation-4'"),
        )
        for index, statement in enumerate(mutations):
            with self.subTest(index=index):
                copy = self.root / f"active-proof-{index}.db"
                with (
                    sqlite3.connect(self.database) as source,
                    sqlite3.connect(copy) as target,
                ):
                    source.backup(target)
                with sqlite3.connect(copy) as connection:
                    connection.execute(statement)
                with (
                    ReadOnlyCatalog(copy) as catalog,
                    self.assertRaises(FrozenJobAuthorityInvalid),
                ):
                    FrozenJobPlan.load(catalog, "JOB-MIGRATION")

    def test_cutover_admission_consumes_only_complete_plan_binding(self) -> None:
        plan = self._load()
        cutover_value = "synthetic-cutover-value"
        rejected_value = "synthetic-rejected-value"
        target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount",
            "tape-device-a",
            "scsi-device-a",
            (
                "archive.resume",
                plan.job_id,
                "4",
                plan.cassettes[3].physical_label,
                "",
                "",
            ),
        )
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "INSERT INTO cutover_authorizations(id, credential_sha256, job_id, "
                "cassette_sequence, bundle_sha256, catalog_binding_sha256, "
                "assignment_sha256, expected_label, host_id, drive_serial_sha256, "
                "peer_kind, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?, ?)",
                (
                    "authorization-4",
                    hashlib.sha256(cutover_value.encode()).hexdigest(),
                    plan.job_id,
                    4,
                    plan.bundle_sha256,
                    cutover_catalog_binding_sha256(
                        plan.job_id,
                        plan.bundle_sha256,
                        plan.assignment_sha256,
                        plan.cassette_plan_sha256,
                        plan.completed_evidence_sha256,
                        plan.cassettes[3].physical_label,
                    ),
                    plan.assignment_sha256,
                    plan.cassettes[3].physical_label,
                    "host-a",
                    target.tape_device_identity_sha256,
                    "local_admin",
                    "2026-08-22T00:00:00+00:00",
                    "9999-12-31T23:59:59+00:00",
                ),
            )
            catalog.connection.execute(
                "INSERT INTO cutover_authorizations(id, credential_sha256, job_id, "
                "cassette_sequence, bundle_sha256, catalog_binding_sha256, "
                "assignment_sha256, expected_label, host_id, drive_serial_sha256, "
                "peer_kind, created_at, expires_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, "
                "?, ?, ?, ?, ?)",
                (
                    "authorization-rejected",
                    hashlib.sha256(rejected_value.encode()).hexdigest(),
                    plan.job_id,
                    4,
                    plan.bundle_sha256,
                    "0" * 64,
                    plan.assignment_sha256,
                    plan.cassettes[3].physical_label,
                    "host-a",
                    target.tape_device_identity_sha256,
                    "local_admin",
                    "2026-08-22T00:00:00+00:00",
                    "9999-12-31T23:59:59+00:00",
                ),
            )
            catalog.connection.commit()
            owner = catalog.claim_daemon_owner("daemon-a")
            candidate = OperationRecord(
                id="operation-4",
                kind="archive.resume",
                state="running",
                phase="identifying_media",
                idempotency_key="resume-4",
                principal="admin",
                job_id=plan.job_id,
                cassette_sequence=4,
                started_at="2026-08-22T00:00:00+00:00",
                finished_at=None,
            )
            with self.assertRaises(ValidationError):
                catalog.admit_operation(
                    candidate,
                    owner,
                    admission_open=True,
                    hardware_target=target,
                    cutover_credential=rejected_value,
                    caller_peer_kind="local_admin",
                    current_host_id="host-a",
                )
            self.assertIsNone(catalog.get_operation("operation-4"))
            admission = catalog.admit_operation(
                candidate,
                owner,
                admission_open=True,
                hardware_target=target,
                cutover_credential=cutover_value,
                caller_peer_kind="local_admin",
                current_host_id="host-a",
            )
            consumed = catalog.connection.execute(
                "SELECT consumed_by_operation_id FROM cutover_authorizations "
                "WHERE id='authorization-4'"
            ).fetchone()[0]

        self.assertFalse(admission.replayed)
        self.assertEqual("operation-4", consumed)

    def test_active_authority_requires_completed_four_and_commit_proof(self) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET status='completed', "
                "tape_id='TAPE04', block_id='BLOCK04-01,BLOCK04-02', "
                "copied_files=2, copied_bytes=8, "
                "started_at='2026-08-22T00:00:30+00:00', "
                "completed_at='2026-08-22T00:01:00+00:00' "
                "WHERE job_id='JOB-MIGRATION' AND sequence=4"
            )
            connection.execute(
                "UPDATE automatic_jobs SET current_sequence=5 WHERE id='JOB-MIGRATION'"
            )
            connection.execute(
                "UPDATE imported_job_policies SET authority_state='active_linux', "
                "windows_authority='historical_read_only', rollback_allowed=0, "
                "activated_by_operation='missing-operation', "
                "activated_at='2026-08-22T00:03:00+00:00' "
                "WHERE job_id='JOB-MIGRATION'"
            )

        with self.assertRaises(FrozenJobAuthorityInvalid) as caught:
            self._load()

        self.assertEqual("frozen-authority-invalid", caught.exception.code)

    def test_active_authority_rejects_cassette_four_still_pending(self) -> None:
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "INSERT INTO daemon_operations(id, kind, state, phase, "
                "idempotency_key, principal, owner_generation, job_id, "
                "cassette_sequence, started_at, finished_at) "
                "VALUES('operation-4', 'archive.resume', 'succeeded', 'unloading', "
                "'resume-4', 'admin', 1, 'JOB-MIGRATION', 4, "
                "'2026-08-22T00:00:00+00:00', "
                "'2026-08-22T00:02:00+00:00')"
            )
            connection.execute(
                "UPDATE imported_job_policies SET authority_state='active_linux', "
                "windows_authority='historical_read_only', rollback_allowed=0, "
                "activated_by_operation='operation-4', "
                "activated_at='2026-08-22T00:03:00+00:00' "
                "WHERE job_id='JOB-MIGRATION'"
            )

        with self.assertRaises(FrozenJobAuthorityInvalid) as caught:
            self._load()

        self.assertEqual("frozen-authority-invalid", caught.exception.code)

    def test_activation_transaction_fails_closed_before_four_is_committed(self) -> None:
        before = self._catalog_snapshot()

        with (
            Catalog(self.database) as catalog,
            self.assertRaises(ValidationError),
        ):
            catalog.activate_imported_job_authority(
                "JOB-MIGRATION", "missing-operation"
            )

        self.assertEqual(before, self._catalog_snapshot())

    def test_service_loads_the_same_read_only_frozen_plan(self) -> None:
        state = self.root / "service-state"
        state.mkdir()
        paths = LinuxPaths.for_root(state, self.root / "daemon.sock")
        with (
            sqlite3.connect(self.database) as source,
            sqlite3.connect(paths.catalog_file) as target,
        ):
            source.backup(target)
        settings = LinuxSettings(state_dir=state, socket_path=paths.socket_path)
        service = DaemonService(
            paths,
            settings,
            BackupManager(paths.catalog_file, paths.backup_dir),
            None,
            EventBus(lambda: Catalog(paths.catalog_file)),
        )

        plan = service.load_frozen_job_plan("JOB-MIGRATION")

        self.assertEqual(4, plan.next_cassette().sequence)
        self.assertEqual("b" * 64, plan.bundle_sha256)


class Schema35FrozenPathTests(unittest.IsolatedAsyncioTestCase):
    async def test_schema35_literal_residual_then_ordered_reserve_then_deficit_is_immutable(self) -> None:
        unit = 1_048_576
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            original = source / "original.bin"
            original.write_bytes(b"o" * (15 * unit))
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=1_429_968_542_720,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB-A", "Library A", str(source))
            service = ManagementService(application, source_roots=(source,))
            service.initialize_application_settings()
            # This schema-35 path test proves legacy no-rescan consumption.
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.connection.execute(
                    "UPDATE application_settings SET source_change_detection_policy='size_mtime'"
                )
                catalog.connection.commit()
            plan = await service.create_plan(
                ("LIB-A",),
                media_key="LTO-5",
                creator="operator",
                plan_id="PLAN-BASE",
            )
            self.assertEqual(1_429_968_542_720, plan["capacity_reserve_bytes"])
            self.assertEqual(1, len(plan["cassettes"]))
            self.assertEqual(20 * unit, plan["cassettes"][0]["allocation_bytes"])
            job = await service.create_job_from_plan(
                plan["id"],
                plan["digest_sha256"],
                ("AB1234", "CD5678"),
                idempotency_key="consume-base",
                display_name="Literal residual",
                actor="operator",
                authorize_automatic_formatting=True,
            )
            job_id = str(job["id"])

            def immutable_rows(catalog: Catalog) -> tuple[tuple[object, ...], ...]:
                statements = (
                    (
                        "SELECT * FROM job_layout_epochs WHERE job_id=? AND epoch_number=1",
                        (job_id,),
                    ),
                    (
                        (
                            "SELECT * FROM job_layout_targets "
                            "WHERE job_id=? AND epoch_number=1 "
                            "ORDER BY plan_sequence"
                        ),
                        (job_id,),
                    ),
                    (
                        (
                            "SELECT * FROM automatic_cassette_items "
                            "WHERE job_id=? AND sequence=1 "
                            "ORDER BY item_sequence"
                        ),
                        (job_id,),
                    ),
                    (
                        "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=1",
                        (job_id,),
                    ),
                    (
                        "SELECT * FROM job_plan_cassettes WHERE plan_id=? ORDER BY sequence",
                        (plan["id"],),
                    ),
                    ("SELECT * FROM blocks WHERE id='BLOCK-BASE'", ()),
                    (
                        "SELECT * FROM file_versions WHERE block_id='BLOCK-BASE' ORDER BY id",
                        (),
                    ),
                )
                return tuple(
                    tuple(tuple(row) for row in catalog.connection.execute(sql, values))
                    for sql, values in statements
                )

            with Catalog(application.paths.catalog_file) as catalog:
                base_cassette = catalog.connection.execute(
                    "SELECT planned_files,planned_bytes FROM automatic_cassettes "
                    "WHERE job_id=? AND sequence=1",
                    (job_id,),
                ).fetchone()
                self.assertEqual((1, 15 * unit), tuple(base_cassette))
                reserve = catalog.connection.execute(
                    "SELECT sequence,planned_files,planned_bytes "
                    "FROM automatic_cassettes WHERE job_id=? AND sequence=2",
                    (job_id,),
                ).fetchone()
                self.assertEqual((2, 0, 0), tuple(reserve))
                catalog.register_tape(
                    "TAPE-A",
                    "SERIAL-A",
                    "VOLUME-A",
                    "LTFS",
                    "/never-mounted",
                    "AB1234",
                )
                catalog.create_block(
                    "BLOCK-BASE",
                    "LIB-A",
                    "TAPE-A",
                    "libraries/LIB-A/blocks/BLOCK-BASE",
                    1,
                    15 * unit,
                )
                catalog.record_file_version(
                    "LIB-A",
                    "BLOCK-BASE",
                    "TAPE-A",
                    "original.bin",
                    "original.bin",
                    15 * unit,
                    original.stat().st_mtime_ns,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-BASE")
                catalog.update_automatic_cassette(
                    job_id,
                    1,
                    "completed",
                    tape_id="TAPE-A",
                    block_id="BLOCK-BASE",
                    copied_files=1,
                    copied_bytes=15 * unit,
                )
                catalog.update_automatic_job(job_id, "completed", current_sequence=1)
                prior = immutable_rows(catalog)
                initial_epoch = dict(catalog.latest_layout_epoch(job_id))
                fence = catalog.claim_daemon_owner("literal-incremental")

            (source / "fits-residual.bin").write_bytes(b"r" * (4 * unit))
            for index in range(1, 4):
                (source / f"reserve-or-label-{index}.bin").write_bytes(
                    bytes([index]) * (12 * unit)
                )

            now = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
            coordinator = IncrementalScanCoordinator(
                application.paths.catalog_file,
                service,
                daemon_generation=lambda: fence.generation,
                now=lambda: now,
            )
            waiting = await coordinator.run_job(
                job_id,
                "manual",
                actor="operator",
                idempotency_key="literal-first-scan",
            )
            self.assertEqual("waiting_labels", waiting["state"])
            self.assertEqual(1, waiting["required_additional_labels"])
            with Catalog(application.paths.catalog_file) as catalog:
                pending = dict(catalog.pending_incremental_extension(job_id))
                extension = catalog.get_job_plan(pending["plan_id"])
            self.assertEqual(
                ("append", "reserve", "format"),
                tuple(row["operation"] for row in extension["cassettes"]),
            )
            self.assertEqual(
                (4 * unit, 24 * unit, 12 * unit),
                tuple(row["payload_bytes"] for row in extension["cassettes"]),
            )
            self.assertEqual(
                (9 * unit, 30 * unit, 17 * unit),
                tuple(row["allocation_bytes"] for row in extension["cassettes"]),
            )

            with (
                mock.patch.object(
                    service,
                    "create_extension_plan",
                    side_effect=AssertionError("labels_added rescanned sources"),
                ) as scanner,
                _frozen_layout_consumption_guard() as label_spies,
            ):
                reserved = await service.reserve_job_labels(
                    job_id,
                    ("EF9012",),
                    actor="operator",
                    idempotency_key="literal-reserve-label",
                    expected_revision=0,
                    authorize_automatic_formatting=True,
                )
                queued = await coordinator.run_job(
                    job_id,
                    "labels_added",
                    actor="operator",
                    idempotency_key="literal-labels-added",
                    authorize_automatic_formatting=True,
                )
            scanner.assert_not_called()
            self.assertEqual(
                {name: 0 for name in label_spies},
                {name: spy.call_count for name, spy in label_spies.items()},
            )
            self.assertEqual(1, reserved["revision"])
            self.assertEqual("extension_queued", queued["state"])
            self.assertEqual(waiting["plan_id"], queued["plan_id"])
            self.assertEqual(waiting["plan_digest_sha256"], queued["plan_digest_sha256"])

            with Catalog(application.paths.catalog_file) as catalog:
                self.assertEqual(prior, immutable_rows(catalog))
                epochs = tuple(
                    dict(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_layout_epochs WHERE job_id=? ORDER BY epoch_number",
                        (job_id,),
                    )
                )
                targets = tuple(
                    dict(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_layout_targets WHERE job_id=? "
                        "ORDER BY epoch_number,plan_sequence",
                        (job_id,),
                    )
                )
                self.assertIsNone(catalog.pending_incremental_extension(job_id))
            self.assertEqual(3, len(epochs))
            self.assertEqual(
                initial_epoch["layout_fingerprint_sha256"],
                epochs[0]["layout_fingerprint_sha256"],
            )
            self.assertEqual(
                initial_epoch["layout_fingerprint_sha256"],
                epochs[1]["prior_epoch_sha256"],
            )
            self.assertEqual(
                epochs[1]["layout_fingerprint_sha256"],
                epochs[2]["prior_epoch_sha256"],
            )
            self.assertEqual(
                ("append", "format", "format"),
                tuple(row["operation"] for row in targets if row["epoch_number"] == 3),
            )

    async def test_initial_and_extension_epochs_freeze_exact_paths_without_remapping_on_consumption(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            for index, (logical, _physical) in enumerate(PATH_FIXTURE, 1):
                path = source / logical
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(bytes([index]) * index)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(reserve_bytes=0, min_age_seconds=0),
            )
            application.add_library("LIB-A", "Library A", str(source))
            service = ManagementService(application, source_roots=(source,))
            service.initialize_application_settings()
            # Keep the historical frozen-layout no-rescan contract explicit.
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.connection.execute(
                    "UPDATE application_settings SET source_change_detection_policy='size_mtime'"
                )
                catalog.connection.commit()
            initial_plan = await service.create_plan(
                ("LIB-A",), media_key="LTO-5", creator="operator", plan_id="PLAN-INITIAL"
            )
            with _frozen_layout_consumption_guard() as initial_spies:
                job = await service.create_job_from_plan(
                    initial_plan["id"],
                    initial_plan["digest_sha256"],
                    ("AB1234", "CD5678"),
                    idempotency_key="consume-initial",
                    display_name="Frozen paths",
                    actor="operator",
                    authorize_automatic_formatting=True,
                )
            self.assertEqual(
                {name: 0 for name in initial_spies},
                {name: spy.call_count for name, spy in initial_spies.items()},
            )
            job_id = str(job["id"])
            with Catalog(application.paths.catalog_file) as catalog:
                initial_items = tuple(
                    (
                        row["relative_path"],
                        row["tape_relative_path"],
                    )
                    for row in catalog.connection.execute(
                        "SELECT relative_path,tape_relative_path "
                        "FROM automatic_cassette_items WHERE job_id=? "
                        "ORDER BY item_sequence",
                        (job_id,),
                    )
                )
                self.assertEqual(dict(PATH_FIXTURE), dict(initial_items))
                self.assertEqual(len(PATH_FIXTURE), len(dict(initial_items)))
                catalog.register_tape(
                    "TAPE-A", "SERIAL-A", "VOLUME-A", "LTFS", "/never-mounted", "CASSETTE-A"
                )
                catalog.create_block(
                    "BLOCK-INITIAL",
                    "LIB-A",
                    "TAPE-A",
                    "libraries/LIB-A/blocks/BLOCK-INITIAL",
                    len(PATH_FIXTURE),
                    sum(range(1, len(PATH_FIXTURE) + 1)),
                )
                for index, (logical, physical) in enumerate(PATH_FIXTURE, 1):
                    catalog.record_file_version(
                        "LIB-A",
                        "BLOCK-INITIAL",
                        "TAPE-A",
                        logical,
                        physical,
                        index,
                        (source / logical).stat().st_mtime_ns,
                        f"{index:064x}",
                    )
                catalog.complete_block("BLOCK-INITIAL")
                catalog.update_automatic_cassette(
                    job_id,
                    1,
                    "completed",
                    tape_id="TAPE-A",
                    block_id="BLOCK-INITIAL",
                    copied_files=len(PATH_FIXTURE),
                    copied_bytes=sum(range(1, len(PATH_FIXTURE) + 1)),
                )
                catalog.update_automatic_job(job_id, "completed", current_sequence=1)
                epoch_before = tuple(
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_layout_epochs WHERE job_id=? ORDER BY epoch_number",
                        (job_id,),
                    )
                )
                targets_before = tuple(
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_layout_targets WHERE job_id=? ORDER BY epoch_number,plan_sequence",
                        (job_id,),
                    )
                )
                cassette_before = tuple(
                    catalog.connection.execute(
                        "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=1",
                        (job_id,),
                    ).fetchone()
                )

            for index, (logical, _physical) in enumerate(PATH_FIXTURE, 1):
                path = source / logical
                path.write_bytes(bytes([index + 20]) * (index + 20))
            extension = await service.create_extension_plan(
                job_id, creator="operator", idempotency_key="plan-extension"
            )
            extension_items = tuple(
                (item["relative_path"], item["tape_relative_path"])
                for cassette in extension["cassettes"]
                for item in cassette["items"]
            )
            self.assertEqual(dict(PATH_FIXTURE), dict(extension_items))
            self.assertEqual(len(PATH_FIXTURE), len(dict(extension_items)))

            with _frozen_layout_consumption_guard() as extension_spies:
                extended = await service.extend_job(
                    job_id,
                    extension["id"],
                    extension["digest_sha256"],
                    (),
                    actor="operator",
                    idempotency_key="consume-extension",
                    expected_revision=0,
                    authorize_automatic_formatting=True,
                )
            self.assertEqual(
                {name: 0 for name in extension_spies},
                {name: spy.call_count for name, spy in extension_spies.items()},
            )

            with Catalog(application.paths.catalog_file) as catalog:
                epochs_after = tuple(
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_layout_epochs WHERE job_id=? ORDER BY epoch_number",
                        (job_id,),
                    )
                )
                targets_after = tuple(
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_layout_targets WHERE job_id=? ORDER BY epoch_number,plan_sequence",
                        (job_id,),
                    )
                )
                cassette_after = tuple(
                    catalog.connection.execute(
                        "SELECT * FROM automatic_cassettes WHERE job_id=? AND sequence=1",
                        (job_id,),
                    ).fetchone()
                )
                extension_rows = tuple(
                    (row["relative_path"], row["tape_relative_path"])
                    for row in catalog.connection.execute(
                        "SELECT relative_path,tape_relative_path "
                        "FROM automatic_cassette_items WHERE job_id=? AND sequence>1 "
                        "ORDER BY sequence,item_sequence",
                        (job_id,),
                    )
                )
            self.assertEqual(epoch_before, epochs_after[: len(epoch_before)])
            self.assertEqual(targets_before, targets_after[: len(targets_before)])
            self.assertEqual(cassette_before, cassette_after)
            self.assertEqual(dict(PATH_FIXTURE), dict(extension_rows))
            self.assertEqual(len(PATH_FIXTURE), len(dict(extension_rows)))
            self.assertEqual(2, len(epochs_after))
            self.assertEqual("AB1234", targets_after[-1][4])
            self.assertEqual(job_id, extended["id"])


if __name__ == "__main__":
    unittest.main()
