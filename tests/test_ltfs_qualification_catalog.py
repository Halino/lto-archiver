import hashlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.errors import CatalogError, ValidationError
from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    qualification_inspection_proof_payload,
    qualification_inspection_snapshot_payload,
)
from ltobackup.qualification.plan import QualificationOperation, QualificationPlan

NOW = 1_787_500_000_000_000_000
RUN_ID = "11111111-1111-4111-8111-111111111111"
VOLUME_UUID = "22222222-2222-4222-8222-222222222222"
POST_VOLUME_UUID = "33333333-3333-4333-8333-333333333333"

RECONCILIATION_COLUMNS = (
    "run_id",
    "catalog_stage_ordinal",
    "broker_stage_ordinal",
    "request_sha256",
    "inspection_snapshot",
    "inspection_snapshot_sha256",
    "inspection_proof",
    "inspection_proof_sha256",
    "terminal_receipt_sha256",
    "terminal_exit_code",
    "evidence_sha256",
    "previous_fence_reason",
    "previous_fenced_at",
    "post_media_evidence",
    "post_media_evidence_sha256",
    "reconciled_at",
)


def make_plan(**overrides):
    fields = {
        "schema": 1,
        "run_id": RUN_ID,
        "job_id": "JOB1",
        "cassette_sequence": 4,
        "physical_label": "CURRENT-LABEL",
        "tape_serial": "CURRENT-SERIAL",
        "drive_serial": "DRIVE-TEST",
        "drive_wwid": "0x5000000000000001",
        "linux_tree_sha256": "a" * 64,
        "ltfs_tree_sha256": "b" * 64,
        "ltfs_rpm_sha256": "c" * 64,
        "issued_at_ns": NOW,
        "expires_at_ns": NOW + 3_600_000_000_000,
        "operations": (
            QualificationOperation.READ_ONLY,
            QualificationOperation.FORMAT,
            QualificationOperation.WIPE,
        ),
    }
    fields.update(overrides)
    return QualificationPlan(**fields)


def make_terminal_inspection(
    plan,
    operation,
    request_sha256,
    *,
    broker_stage_ordinal,
    expected_volume_uuid=VOLUME_UUID,
    expected_generation=7,
    child_exit_code=0,
    proof=b"p" * 32,
):
    snapshot = {
        "run_id": plan.run_id,
        "stage_ordinal": broker_stage_ordinal,
        "state": "TERMINAL",
        "boot_id": "44444444-4444-4444-8444-444444444444",
        "request_sha256": request_sha256,
        "immutable_sha256": "1" * 64,
        "plan_sha256": plan.plan_sha256,
        "operation": operation.value,
        "operation_token_sha256": "2" * 64,
        "tape_device_identity_sha256": "3" * 64,
        "scsi_device_identity_sha256": "4" * 64,
        "expected_media_scope_sha256": "5" * 64,
        "observed_media_identity_sha256": "6" * 64,
        "expected_physical_label": plan.physical_label,
        "expected_tape_serial": plan.tape_serial,
        "expected_drive_serial": plan.drive_serial,
        "expected_drive_wwid": plan.drive_wwid,
        "expected_volume_uuid": expected_volume_uuid,
        "expected_generation": expected_generation,
        "request_nonce": b"n" * 32,
        "created_at": "2026-08-23T00:00:00+00:00",
        "dispatched_at": "2026-08-23T00:00:01+00:00",
        "terminal_at": "2026-08-23T00:00:02+00:00",
    }
    dispatch = BrokerQualificationDispatch(
        protocol_version=1,
        run_id=plan.run_id,
        stage_ordinal=broker_stage_ordinal,
        operation=operation,
        request_sha256=request_sha256,
        dispatch_state="terminal",
        terminal_receipt_sha256="7" * 64,
        child_exit_code=child_exit_code,
        evidence_sha256="8" * 64,
        broker_nonce=b"b" * 32,
        broker_proof=b"d" * 32,
    )
    request = BrokerQualificationInspectionRequest(
        run_id=plan.run_id,
        stage_ordinal=broker_stage_ordinal,
        challenge=b"c" * 32,
    )
    inspection = BrokerQualificationInspection(
        state="terminal",
        stage_snapshot=snapshot,
        dispatch=dispatch,
        observation_nonce=b"o" * 32,
        proof=proof,
    )
    return request, inspection


class QualificationCatalogTests(unittest.TestCase):
    def test_schema_two_exact_mam_plan_survives_catalog_reopen_without_migration(self):
        plan = make_plan(schema=2, expected_mam_medium_serial="V210531095")
        before_schema = self.catalog.connection.execute(
            "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        before_schema = [tuple(row) for row in before_schema]
        self.catalog.create_ltfs_qualification_run(plan)
        path = Path(self.temporary.name) / "catalog.sqlite3"
        self.catalog.close()
        with Catalog(path) as reopened:
            row = reopened.connection.execute(
                "SELECT plan_json,plan_sha256 FROM ltfs_qualification_runs WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()
            restored = QualificationPlan.from_bytes(row["plan_json"].encode())
            self.assertEqual(restored.expected_mam_medium_serial, "V210531095")
            self.assertEqual(row["plan_sha256"], plan.plan_sha256)
            self.assertEqual(restored.canonical_bytes(), plan.canonical_bytes())
            after_schema = reopened.connection.execute(
                "SELECT type,name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall()
            self.assertEqual([tuple(row) for row in after_schema], before_schema)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        source = root / "source"
        source.mkdir()
        self.catalog = Catalog(root / "catalog.sqlite3")
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        self.catalog.add_library("LIB1", "Library", str(source))
        self.catalog.create_automatic_job(
            "JOB1",
            "LIB1",
            "drive",
            "/synthetic/mount",
            [
                ("LABEL1", "SERIAL1", 0, 0),
                ("LABEL2", "SERIAL2", 0, 0),
                ("LABEL3", "SERIAL3", 0, 0),
                ("CURRENT-LABEL", "CURRENT-SERIAL", 0, 0),
            ],
            force_format=True,
        )

    def _upgrade_to_current(self, path: Path) -> None:
        BackupManager(
            path,
            Path(self.temporary.name) / f"{path.stem}-backups",
        ).prepare_and_initialize()

    def test_current_schema_persists_exact_plan_and_is_immutable(self):
        self.assertEqual(41, SCHEMA_VERSION)
        plan = make_plan()
        self.catalog.create_ltfs_qualification_run(plan)
        row = self.catalog.connection.execute(
            "SELECT * FROM ltfs_qualification_runs WHERE run_id=?", (plan.run_id,)
        ).fetchone()
        self.assertEqual(plan.plan_sha256, row["plan_sha256"])
        self.assertEqual(plan.physical_label, row["physical_label"])
        self.assertEqual(plan.tape_serial, row["tape_serial"])
        self.catalog.record_ltfs_qualification_stage(
            run_id=plan.run_id,
            ordinal=1,
            operation=QualificationOperation.READ_ONLY,
            request_sha256="d" * 64,
            dispatched=False,
            terminal_receipt_sha256=None,
            child_exit_code=None,
            before_volume_uuid=None,
            before_generation=None,
            after_volume_uuid=None,
            after_generation=None,
            content_manifest_sha256=None,
            verdict="pre_dispatch_refused",
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.catalog.connection.execute(
                "UPDATE ltfs_qualification_stages SET verdict='pass'"
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.catalog.connection.execute("DELETE FROM ltfs_qualification_stages")

    def test_catalog_label_and_serial_are_exact_not_nocase(self):
        for mutation in (
            replace(make_plan(), physical_label="current-label"),
            replace(make_plan(), tape_serial="current-serial"),
        ):
            with (
                self.subTest(mutation=mutation),
                self.assertRaisesRegex(ValidationError, "identity"),
            ):
                self.catalog.create_ltfs_qualification_run(mutation)

    def test_dispatched_ambiguity_is_fenced_and_cannot_be_replayed(self):
        plan = make_plan()
        self.catalog.create_ltfs_qualification_run(plan)
        self.catalog.record_ltfs_qualification_stage(
            run_id=plan.run_id,
            ordinal=1,
            operation=QualificationOperation.FORMAT,
            request_sha256="d" * 64,
            dispatched=True,
            terminal_receipt_sha256=None,
            child_exit_code=None,
            before_volume_uuid="22222222-2222-4222-8222-222222222222",
            before_generation=7,
            after_volume_uuid=None,
            after_generation=None,
            content_manifest_sha256=None,
            verdict="fenced",
        )
        self.catalog.fence_ltfs_qualification_run(plan.run_id, "ambiguous_dispatch")
        with self.assertRaises((CatalogError, ValidationError, sqlite3.IntegrityError)):
            self.catalog.record_ltfs_qualification_stage(
                run_id=plan.run_id,
                ordinal=1,
                operation=QualificationOperation.FORMAT,
                request_sha256="e" * 64,
                dispatched=True,
                terminal_receipt_sha256="f" * 64,
                child_exit_code=0,
                before_volume_uuid="22222222-2222-4222-8222-222222222222",
                before_generation=7,
                after_volume_uuid="33333333-3333-4333-8333-333333333333",
                after_generation=1,
                content_manifest_sha256=None,
                verdict="pass",
            )
        row = self.catalog.connection.execute(
            "SELECT status,fence_reason FROM ltfs_qualification_runs WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()
        self.assertEqual(("fenced", "ambiguous_dispatch"), tuple(row))

    def test_schema_eighteen_migrates_to_current_with_integrity(self):
        path = Path(self.temporary.name) / "migration.sqlite3"
        with Catalog(path) as catalog:
            catalog.initialize(target_version=18)
        self._upgrade_to_current(path)
        with Catalog(path) as catalog:
            catalog.initialize()
            version = catalog.connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
            tables = {
                row[0]
                for row in catalog.connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertEqual(str(SCHEMA_VERSION), version)
            self.assertIn("ltfs_qualification_runs", tables)
            self.assertIn("ltfs_qualification_stages", tables)
            self.assertEqual(
                [], catalog.connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            self.assertEqual(
                "ok", catalog.connection.execute("PRAGMA integrity_check").fetchone()[0]
            )

    def test_populated_schema_nineteen_migrates_losslessly_and_accepts_load(self):
        path = Path(self.temporary.name) / "migration-19.sqlite3"
        source = Path(self.temporary.name) / "migration-source"
        source.mkdir()
        plan = make_plan(
            operations=(QualificationOperation.READ_ONLY, QualificationOperation.LOAD)
        )
        with Catalog(path) as catalog:
            catalog.initialize(target_version=19)
            catalog.add_library("LIB1", "Library", str(source))
            catalog.create_automatic_job(
                "JOB1",
                "LIB1",
                "drive",
                "/synthetic/mount",
                [
                    ("LABEL1", "SERIAL1", 0, 0),
                    ("LABEL2", "SERIAL2", 0, 0),
                    ("LABEL3", "SERIAL3", 0, 0),
                    ("CURRENT-LABEL", "CURRENT-SERIAL", 0, 0),
                ],
                force_format=True,
            )
            catalog.create_ltfs_qualification_run(plan)
            catalog.record_ltfs_qualification_stage(
                run_id=plan.run_id,
                ordinal=1,
                operation=QualificationOperation.READ_ONLY,
                request_sha256="d" * 64,
                dispatched=True,
                terminal_receipt_sha256=None,
                child_exit_code=None,
                before_volume_uuid="22222222-2222-4222-8222-222222222222",
                before_generation=7,
                after_volume_uuid=None,
                after_generation=None,
                content_manifest_sha256=None,
                verdict="dispatch_started",
            )
        self._upgrade_to_current(path)
        with Catalog(path) as migrated:
            migrated.initialize()
            migrated.record_ltfs_qualification_stage(
                run_id=plan.run_id,
                ordinal=2,
                operation=QualificationOperation.LOAD,
                request_sha256="e" * 64,
                dispatched=True,
                terminal_receipt_sha256="f" * 64,
                child_exit_code=0,
                before_volume_uuid="22222222-2222-4222-8222-222222222222",
                before_generation=7,
                after_volume_uuid="22222222-2222-4222-8222-222222222222",
                after_generation=7,
                content_manifest_sha256=None,
                verdict="pass",
            )
            rows = migrated.connection.execute(
                "SELECT ordinal,operation FROM ltfs_qualification_stages "
                "WHERE run_id=? ORDER BY ordinal",
                (plan.run_id,),
            ).fetchall()
            self.assertEqual(
                [(1, "read_only"), (2, "load")], [tuple(row) for row in rows]
            )
            self.assertEqual(
                [], migrated.connection.execute("PRAGMA foreign_key_check").fetchall()
            )
            self.assertEqual(
                "ok",
                migrated.connection.execute("PRAGMA integrity_check").fetchone()[0],
            )

    def test_schema_twenty_empty_and_populated_migrate_to_exact_schema_twenty_one(self):
        for populated in (False, True):
            with self.subTest(populated=populated):
                path = Path(self.temporary.name) / f"migration-20-{populated}.sqlite3"
                with Catalog(path) as catalog:
                    catalog.initialize(target_version=20)
                    if populated:
                        catalog.add_library("LIB1", "Library", str(path.parent))
                        catalog.create_automatic_job(
                            "JOB1",
                            "LIB1",
                            "drive",
                            "/synthetic/mount",
                            [
                                ("LABEL1", "SERIAL1", 0, 0),
                                ("LABEL2", "SERIAL2", 0, 0),
                                ("LABEL3", "SERIAL3", 0, 0),
                                ("CURRENT-LABEL", "CURRENT-SERIAL", 0, 0),
                            ],
                            force_format=True,
                        )
                        plan = make_plan(operations=(QualificationOperation.READ_ONLY,))
                        catalog.create_ltfs_qualification_run(plan)
                        catalog.record_ltfs_qualification_stage(
                            run_id=plan.run_id,
                            ordinal=1,
                            operation=QualificationOperation.READ_ONLY,
                            request_sha256="d" * 64,
                            dispatched=True,
                            terminal_receipt_sha256=None,
                            child_exit_code=None,
                            before_volume_uuid=VOLUME_UUID,
                            before_generation=7,
                            after_volume_uuid=None,
                            after_generation=None,
                            content_manifest_sha256=None,
                            verdict="dispatch_started",
                        )
                    before = [
                        tuple(row)
                        for row in catalog.connection.execute(
                            "SELECT * FROM ltfs_qualification_stages ORDER BY run_id,ordinal"
                        )
                    ]

                self._upgrade_to_current(path)
                with Catalog(path) as migrated:
                    migrated.initialize()
                    columns = tuple(
                        row["name"]
                        for row in migrated.connection.execute(
                            "PRAGMA table_info(ltfs_qualification_reconciliations)"
                        )
                    )
                    indexes = {
                        row["name"]
                        for row in migrated.connection.execute(
                            "PRAGMA index_list(ltfs_qualification_reconciliations)"
                        )
                    }
                    triggers = {
                        row["name"]
                        for row in migrated.connection.execute(
                            "SELECT name FROM sqlite_master WHERE type='trigger' "
                            "AND tbl_name='ltfs_qualification_reconciliations'"
                        )
                    }
                    after = [
                        tuple(row)
                        for row in migrated.connection.execute(
                            "SELECT * FROM ltfs_qualification_stages ORDER BY run_id,ordinal"
                        )
                    ]
                    self.assertEqual(RECONCILIATION_COLUMNS, columns)
                    self.assertIn(
                        "ix_ltfs_qualification_reconciliations_broker_stage", indexes
                    )
                    self.assertEqual(
                        {
                            "ltfs_qualification_reconciliations_immutable_update",
                            "ltfs_qualification_reconciliations_immutable_delete",
                        },
                        triggers,
                    )
                    self.assertEqual(before, after)
                    self.assertEqual(
                        [],
                        migrated.connection.execute(
                            "PRAGMA foreign_key_check"
                        ).fetchall(),
                    )
                    self.assertEqual(
                        "ok",
                        migrated.connection.execute(
                            "PRAGMA integrity_check"
                        ).fetchone()[0],
                    )
                with Catalog(path) as reopened:
                    reopened.initialize()
                    self.assertEqual(
                        str(SCHEMA_VERSION),
                        reopened.connection.execute(
                            "SELECT value FROM metadata WHERE key='schema_version'"
                        ).fetchone()[0],
                    )

    def test_schema_twenty_one_migration_rejects_hybrid_layout_transactionally(self):
        path = Path(self.temporary.name) / "hybrid-20.sqlite3"
        with Catalog(path) as catalog:
            catalog.initialize(target_version=20)
            catalog.connection.execute(
                "CREATE TABLE ltfs_qualification_reconciliations(run_id TEXT)"
            )
            catalog.connection.commit()

        with self.assertRaisesRegex(CatalogError, "schema 20|Schema 21"):
            self._upgrade_to_current(path)

        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(
                "20",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                ("run_id",),
                tuple(
                    row[1]
                    for row in connection.execute(
                        "PRAGMA table_info(ltfs_qualification_reconciliations)"
                    )
                ),
            )

    def test_schema_twenty_migration_rejects_target_without_checks_or_foreign_key(self):
        path = Path(self.temporary.name) / "weak-hybrid-20.sqlite3"
        with Catalog(path) as catalog:
            catalog.initialize(target_version=20)
            catalog.connection.executescript(
                """
                CREATE TABLE ltfs_qualification_reconciliations (
                    run_id TEXT NOT NULL,
                    catalog_stage_ordinal INTEGER NOT NULL,
                    broker_stage_ordinal INTEGER NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    inspection_snapshot BLOB NOT NULL,
                    inspection_snapshot_sha256 TEXT NOT NULL,
                    inspection_proof BLOB NOT NULL,
                    inspection_proof_sha256 TEXT NOT NULL,
                    terminal_receipt_sha256 TEXT NOT NULL,
                    terminal_exit_code INTEGER NOT NULL,
                    evidence_sha256 TEXT NOT NULL,
                    previous_fence_reason TEXT NOT NULL,
                    previous_fenced_at TEXT NOT NULL,
                    post_media_evidence BLOB NOT NULL,
                    post_media_evidence_sha256 TEXT NOT NULL,
                    reconciled_at TEXT NOT NULL,
                    PRIMARY KEY(run_id, catalog_stage_ordinal)
                );
                CREATE UNIQUE INDEX
                    ix_ltfs_qualification_reconciliations_broker_stage
                ON ltfs_qualification_reconciliations(
                    run_id, broker_stage_ordinal
                );
                CREATE TRIGGER
                    ltfs_qualification_reconciliations_immutable_update
                BEFORE UPDATE ON ltfs_qualification_reconciliations
                BEGIN
                    SELECT RAISE(ABORT,
                        'LTFS qualification reconciliation is immutable');
                END;
                CREATE TRIGGER
                    ltfs_qualification_reconciliations_immutable_delete
                BEFORE DELETE ON ltfs_qualification_reconciliations
                BEGIN
                    SELECT RAISE(ABORT,
                        'LTFS qualification reconciliation is immutable');
                END;
                """
            )

        with self.assertRaisesRegex(CatalogError, "Schema 21"):
            self._upgrade_to_current(path)

        with closing(sqlite3.connect(path)) as connection:
            self.assertEqual(
                "20",
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )
            self.assertEqual(
                [],
                connection.execute(
                    "PRAGMA foreign_key_list(ltfs_qualification_reconciliations)"
                ).fetchall(),
            )

    def test_schema_twenty_one_missing_target_fails_closed_without_recreation(self):
        path = Path(self.temporary.name) / "missing-schema-21.sqlite3"
        with Catalog(path) as catalog:
            catalog.initialize()
            catalog.connection.execute("DROP TABLE ltfs_qualification_reconciliations")
            catalog.connection.commit()

        with (
            Catalog(path) as catalog,
            self.assertRaisesRegex(CatalogError, "Schema 21"),
        ):
            catalog.initialize()

        with closing(sqlite3.connect(path)) as connection:
            self.assertIsNone(
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='ltfs_qualification_reconciliations'"
                ).fetchone()
            )
            self.assertEqual(
                str(SCHEMA_VERSION),
                connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0],
            )

    def test_schema_twenty_one_conditional_trigger_is_rejected_after_permitting_update(
        self,
    ):
        plan, request, inspection = self._fenced_dispatch(
            operations=(QualificationOperation.READ_ONLY,)
        )
        self._reconcile(plan, request, inspection)
        path = self.catalog.path
        self.catalog.connection.executescript(
            """
            DROP TRIGGER ltfs_qualification_reconciliations_immutable_update;
            CREATE TRIGGER ltfs_qualification_reconciliations_immutable_update
            BEFORE UPDATE ON ltfs_qualification_reconciliations
            WHEN 0
            BEGIN
                SELECT RAISE(ABORT,
                    'LTFS qualification reconciliation is immutable');
            END;
            """
        )
        self.catalog.connection.execute(
            "UPDATE ltfs_qualification_reconciliations SET evidence_sha256=?",
            ("9" * 64,),
        )
        self.catalog.connection.commit()
        self.assertEqual(
            "9" * 64,
            self.catalog.connection.execute(
                "SELECT evidence_sha256 FROM ltfs_qualification_reconciliations"
            ).fetchone()[0],
        )

        with (
            Catalog(path) as catalog,
            self.assertRaisesRegex(CatalogError, "Schema 21"),
        ):
            catalog.initialize()

    def test_schema_twenty_one_rejects_extra_or_altered_indexes_and_triggers(self):
        mutations = {
            "extra_index": (
                "CREATE INDEX unexpected_reconciliation_index "
                "ON ltfs_qualification_reconciliations(request_sha256)"
            ),
            "altered_index": (
                "DROP INDEX ix_ltfs_qualification_reconciliations_broker_stage; "
                "CREATE UNIQUE INDEX "
                "ix_ltfs_qualification_reconciliations_broker_stage "
                "ON ltfs_qualification_reconciliations(run_id,request_sha256)"
            ),
            "extra_trigger": (
                "CREATE TRIGGER unexpected_reconciliation_trigger "
                "BEFORE INSERT ON ltfs_qualification_reconciliations "
                "BEGIN SELECT RAISE(ABORT,'unexpected'); END"
            ),
            "altered_trigger": (
                "DROP TRIGGER ltfs_qualification_reconciliations_immutable_delete; "
                "CREATE TRIGGER ltfs_qualification_reconciliations_immutable_delete "
                "BEFORE DELETE ON ltfs_qualification_reconciliations WHEN 0 "
                "BEGIN SELECT RAISE(ABORT,"
                "'LTFS qualification reconciliation is immutable'); END"
            ),
        }
        for name, mutation in mutations.items():
            with self.subTest(name=name):
                path = Path(self.temporary.name) / f"schema-21-{name}.sqlite3"
                with Catalog(path) as catalog:
                    catalog.initialize()
                    catalog.connection.executescript(mutation)
                with (
                    Catalog(path) as catalog,
                    self.assertRaisesRegex(CatalogError, "Schema 21"),
                ):
                    catalog.initialize()

    def test_schema_twenty_one_migration_uses_sqlite_334_additive_ddl(self):
        path = Path(self.temporary.name) / "sqlite-334.sqlite3"
        with Catalog(path) as catalog:
            catalog.initialize(target_version=20)
        statements = []
        manager = BackupManager(
            path,
            Path(self.temporary.name) / "sqlite-334-backups",
        )
        protected_backup = manager.create(
            "before-schema-21-trace",
            protected=True,
        )
        with Catalog(path) as catalog:
            catalog.connection.set_trace_callback(statements.append)
            catalog._initialize_after_protected_backup(
                target_version=SCHEMA_VERSION,
                protected_backup=protected_backup,
            )

        normalized = tuple(
            " ".join(statement.upper().split()) for statement in statements
        )
        unsupported_drop_column = "DROP" + " COLUMN"
        self.assertFalse(
            any(unsupported_drop_column in statement for statement in normalized)
        )
        self.assertTrue(
            any(
                statement.startswith("CREATE TABLE LTFS_QUALIFICATION_RECONCILIATIONS")
                for statement in normalized
            )
        )
        self.assertFalse(
            any(
                statement.startswith("ALTER TABLE LTFS_QUALIFICATION_STAGES")
                for statement in normalized
            )
        )

    def test_reconciliation_rows_reject_update_and_delete(self):
        plan, request, inspection = self._fenced_dispatch(
            operations=(QualificationOperation.READ_ONLY,)
        )
        self._reconcile(plan, request, inspection)
        for statement in (
            "UPDATE ltfs_qualification_reconciliations SET evidence_sha256='9'",
            "DELETE FROM ltfs_qualification_reconciliations",
        ):
            with (
                self.subTest(statement=statement),
                self.assertRaises(sqlite3.IntegrityError),
            ):
                self.catalog.connection.execute(statement)
            self.catalog.connection.rollback()

    def test_reconcile_terminal_stage_atomically_completes_last_plan_stage(self):
        plan, request, inspection = self._fenced_dispatch(
            operations=(QualificationOperation.READ_ONLY,)
        )
        fenced_at = self.catalog.connection.execute(
            "SELECT fenced_at FROM ltfs_qualification_runs WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()[0]

        self._reconcile(plan, request, inspection)

        run = self.catalog.connection.execute(
            "SELECT status,fence_reason,fenced_at FROM ltfs_qualification_runs "
            "WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()
        stages = self.catalog.connection.execute(
            "SELECT ordinal,operation,request_sha256,terminal_receipt_sha256,"
            "child_exit_code,verdict FROM ltfs_qualification_stages "
            "WHERE run_id=? ORDER BY ordinal",
            (plan.run_id,),
        ).fetchall()
        receipt = self.catalog.connection.execute(
            "SELECT * FROM ltfs_qualification_reconciliations WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()
        self.assertEqual(("completed", None, None), tuple(run))
        self.assertEqual(2, len(stages))
        self.assertEqual(
            (2, "read_only", "d" * 64, "7" * 64, 0, "pass"), tuple(stages[1])
        )
        self.assertEqual("ambiguous_dispatch", receipt["previous_fence_reason"])
        self.assertEqual(fenced_at, receipt["previous_fenced_at"])
        self.assertEqual(
            qualification_inspection_snapshot_payload(inspection.stage_snapshot),
            receipt["inspection_snapshot"],
        )
        self.assertEqual(
            hashlib.sha256(receipt["inspection_snapshot"]).hexdigest(),
            receipt["inspection_snapshot_sha256"],
        )
        proof_payload = qualification_inspection_proof_payload(request, inspection)
        expected_proof = (
            b"lto-catalog-inspection-proof-v1\0"
            + len(proof_payload).to_bytes(4, "big")
            + proof_payload
            + inspection.proof
        )
        self.assertEqual(expected_proof, receipt["inspection_proof"])
        self.assertEqual(
            hashlib.sha256(expected_proof).hexdigest(),
            receipt["inspection_proof_sha256"],
        )
        self.assertEqual("7" * 64, receipt["terminal_receipt_sha256"])
        self.assertEqual(0, receipt["terminal_exit_code"])
        self.assertEqual("8" * 64, receipt["evidence_sha256"])
        self.assertEqual(
            hashlib.sha256(receipt["post_media_evidence"]).hexdigest(),
            receipt["post_media_evidence_sha256"],
        )

    def test_reconcile_nonfinal_stage_returns_run_to_running(self):
        plan, request, inspection = self._fenced_dispatch(
            operations=(
                QualificationOperation.READ_ONLY,
                QualificationOperation.FORMAT,
            )
        )

        self._reconcile(plan, request, inspection)

        row = self.catalog.connection.execute(
            "SELECT status,fence_reason,fenced_at FROM ltfs_qualification_runs "
            "WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()
        self.assertEqual(("running", None, None), tuple(row))

    def test_reconcile_final_stage_completes_run_with_prior_pairs(self):
        plan = make_plan(
            operations=(
                QualificationOperation.READ_ONLY,
                QualificationOperation.FORMAT,
            )
        )
        self.catalog.create_ltfs_qualification_run(plan)
        for ordinal, terminal in ((1, False), (2, True)):
            self.catalog.record_ltfs_qualification_stage(
                run_id=plan.run_id,
                ordinal=ordinal,
                operation=QualificationOperation.READ_ONLY,
                request_sha256="a" * 64,
                dispatched=True,
                terminal_receipt_sha256="b" * 64 if terminal else None,
                child_exit_code=0 if terminal else None,
                before_volume_uuid=VOLUME_UUID,
                before_generation=7,
                after_volume_uuid=VOLUME_UUID if terminal else None,
                after_generation=7 if terminal else None,
                content_manifest_sha256="c" * 64 if terminal else None,
                verdict="pass" if terminal else "dispatch_started",
            )
        self.catalog.record_ltfs_qualification_stage(
            run_id=plan.run_id,
            ordinal=3,
            operation=QualificationOperation.FORMAT,
            request_sha256="d" * 64,
            dispatched=True,
            terminal_receipt_sha256=None,
            child_exit_code=None,
            before_volume_uuid=VOLUME_UUID,
            before_generation=7,
            after_volume_uuid=None,
            after_generation=None,
            content_manifest_sha256=None,
            verdict="dispatch_started",
        )
        self.catalog.fence_ltfs_qualification_run(plan.run_id, "ambiguous_dispatch")
        request, inspection = make_terminal_inspection(
            plan,
            QualificationOperation.FORMAT,
            "d" * 64,
            broker_stage_ordinal=2,
        )

        self._reconcile(
            plan,
            request,
            inspection,
            volume_uuid=POST_VOLUME_UUID,
            generation=1,
            observed_media_identity_sha256="9" * 64,
        )

        row = self.catalog.connection.execute(
            "SELECT status,fence_reason,fenced_at FROM ltfs_qualification_runs "
            "WHERE run_id=?",
            (plan.run_id,),
        ).fetchone()
        self.assertEqual(("completed", None, None), tuple(row))
        self.assertEqual(
            4,
            self.catalog.connection.execute(
                "SELECT COUNT(*) FROM ltfs_qualification_stages WHERE run_id=?",
                (plan.run_id,),
            ).fetchone()[0],
        )

    def test_reconcile_exact_replay_is_idempotent_and_divergent_replay_fails(self):
        plan, request, inspection = self._fenced_dispatch(
            operations=(QualificationOperation.READ_ONLY,)
        )
        self._reconcile(plan, request, inspection)
        before = self._reconciliation_state(plan.run_id)

        self._reconcile(plan, request, inspection)
        self.assertEqual(before, self._reconciliation_state(plan.run_id))

        divergent = replace(inspection, proof=b"q" * 32)
        with self.assertRaises((CatalogError, ValidationError)):
            self._reconcile(plan, request, divergent)
        self.assertEqual(before, self._reconciliation_state(plan.run_id))

        divergent_request = replace(request, challenge=b"x" * 32)
        with self.assertRaises((CatalogError, ValidationError)):
            self._reconcile(plan, divergent_request, inspection)
        self.assertEqual(before, self._reconciliation_state(plan.run_id))

    def test_reconcile_rejects_mismatched_terminal_evidence_without_partial_rows(self):
        for name in ("request", "operation", "ordinal", "media"):
            with self.subTest(name=name):
                self._reset_catalog()
                plan, request, inspection = self._fenced_dispatch(
                    operations=(
                        QualificationOperation.READ_ONLY,
                        QualificationOperation.FORMAT,
                    )
                )
                bad_request = request
                bad_inspection = inspection
                overrides = {}
                if name == "request":
                    bad_request, bad_inspection = make_terminal_inspection(
                        plan,
                        QualificationOperation.READ_ONLY,
                        "e" * 64,
                        broker_stage_ordinal=1,
                    )
                elif name == "operation":
                    bad_request, bad_inspection = make_terminal_inspection(
                        plan,
                        QualificationOperation.FORMAT,
                        "d" * 64,
                        broker_stage_ordinal=2,
                    )
                elif name == "ordinal":
                    bad_request, bad_inspection = make_terminal_inspection(
                        plan,
                        QualificationOperation.READ_ONLY,
                        "d" * 64,
                        broker_stage_ordinal=2,
                    )
                else:
                    overrides["physical_label"] = "wrong-label"
                with self.assertRaises((CatalogError, ValidationError, ValueError)):
                    self._reconcile(plan, bad_request, bad_inspection, **overrides)
                self._assert_fenced_without_partial_rows(plan.run_id)

    def test_reconcile_rejects_exit_outside_operation_contract(self):
        plan, request, inspection = self._fenced_dispatch(
            operations=(QualificationOperation.READ_ONLY,)
        )
        invalid_dispatch = object.__new__(BrokerQualificationDispatch)
        for field in inspection.dispatch.__dataclass_fields__:
            object.__setattr__(
                invalid_dispatch,
                field,
                9
                if field == "child_exit_code"
                else getattr(inspection.dispatch, field),
            )
        invalid_inspection = object.__new__(BrokerQualificationInspection)
        for field in inspection.__dataclass_fields__:
            object.__setattr__(
                invalid_inspection,
                field,
                invalid_dispatch if field == "dispatch" else getattr(inspection, field),
            )

        with self.assertRaises((CatalogError, ValidationError, ValueError)):
            self._reconcile(plan, request, invalid_inspection)
        self._assert_fenced_without_partial_rows(plan.run_id)

    def test_reconcile_rejects_missing_or_multiple_unpaired_dispatches(self):
        plan = make_plan(operations=(QualificationOperation.READ_ONLY,))
        self.catalog.create_ltfs_qualification_run(plan)
        self.catalog.fence_ltfs_qualification_run(plan.run_id, "ambiguous_dispatch")
        request, inspection = make_terminal_inspection(
            plan,
            QualificationOperation.READ_ONLY,
            "d" * 64,
            broker_stage_ordinal=1,
        )
        with self.assertRaises((CatalogError, ValidationError)):
            self._reconcile(plan, request, inspection)
        self._assert_fenced_without_partial_rows(plan.run_id)

        self._reset_catalog()
        plan, request, inspection = self._fenced_dispatch(
            operations=(
                QualificationOperation.READ_ONLY,
                QualificationOperation.FORMAT,
            )
        )
        self.catalog.connection.execute(
            "DROP TRIGGER ltfs_qualification_stages_immutable_update"
        )
        self.catalog.connection.execute(
            "INSERT INTO ltfs_qualification_stages SELECT run_id,2,'format',"
            "'e'||substr(request_sha256,2),1,NULL,NULL,before_volume_uuid,"
            "before_generation,NULL,NULL,NULL,'dispatch_started',recorded_at "
            "FROM ltfs_qualification_stages WHERE run_id=? AND ordinal=1",
            (plan.run_id,),
        )
        self.catalog.connection.commit()
        with self.assertRaises((CatalogError, ValidationError)):
            self._reconcile(plan, request, inspection)
        self._assert_fenced_without_partial_rows(plan.run_id)

    def test_reconcile_rolls_back_after_each_append_failure(self):
        for failure_point in ("terminal", "reconciliation"):
            with self.subTest(failure_point=failure_point):
                self._reset_catalog(catalog_class=_FailingReconciliationCatalog)
                plan, request, inspection = self._fenced_dispatch(
                    operations=(QualificationOperation.READ_ONLY,)
                )
                self.catalog.failure_point = failure_point
                with self.assertRaisesRegex(RuntimeError, "injected"):
                    self._reconcile(plan, request, inspection)
                self._assert_fenced_without_partial_rows(plan.run_id)

    def _reset_catalog(self, catalog_class=Catalog):
        self.catalog.close()
        root = Path(self.temporary.name)
        path = root / f"catalog-{id(self)}-{len(list(root.glob('catalog-*')))}.sqlite3"
        self.catalog = catalog_class(path)
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        source = root / f"source-{len(list(root.glob('source-*')))}"
        source.mkdir()
        self.catalog.add_library("LIB1", "Library", str(source))
        self.catalog.create_automatic_job(
            "JOB1",
            "LIB1",
            "drive",
            "/synthetic/mount",
            [
                ("LABEL1", "SERIAL1", 0, 0),
                ("LABEL2", "SERIAL2", 0, 0),
                ("LABEL3", "SERIAL3", 0, 0),
                ("CURRENT-LABEL", "CURRENT-SERIAL", 0, 0),
            ],
            force_format=True,
        )

    def _fenced_dispatch(self, *, operations):
        plan = make_plan(operations=operations)
        operation = QualificationOperation.READ_ONLY
        self.catalog.create_ltfs_qualification_run(plan)
        self.catalog.record_ltfs_qualification_stage(
            run_id=plan.run_id,
            ordinal=1,
            operation=operation,
            request_sha256="d" * 64,
            dispatched=True,
            terminal_receipt_sha256=None,
            child_exit_code=None,
            before_volume_uuid=VOLUME_UUID,
            before_generation=7,
            after_volume_uuid=None,
            after_generation=None,
            content_manifest_sha256=None,
            verdict="dispatch_started",
        )
        self.catalog.fence_ltfs_qualification_run(plan.run_id, "ambiguous_dispatch")
        request, inspection = make_terminal_inspection(
            plan, operation, "d" * 64, broker_stage_ordinal=1
        )
        return plan, request, inspection

    def _reconcile(self, plan, request, inspection, **overrides):
        arguments = {
            "plan": plan,
            "inspection_request": request,
            "inspection": inspection,
            "physical_label": plan.physical_label,
            "tape_serial": plan.tape_serial,
            "drive_serial": plan.drive_serial,
            "drive_wwid": plan.drive_wwid,
            "tape_device_identity_sha256": "3" * 64,
            "scsi_device_identity_sha256": "4" * 64,
            "expected_media_scope_sha256": "5" * 64,
            "observed_media_identity_sha256": "6" * 64,
            "volume_uuid": VOLUME_UUID,
            "generation": 7,
        }
        arguments.update(overrides)
        return self.catalog.reconcile_ltfs_qualification_stage(**arguments)

    def _reconciliation_state(self, run_id):
        return (
            tuple(
                tuple(row)
                for row in self.catalog.connection.execute(
                    "SELECT * FROM ltfs_qualification_stages WHERE run_id=? "
                    "ORDER BY ordinal",
                    (run_id,),
                )
            ),
            tuple(
                tuple(row)
                for row in self.catalog.connection.execute(
                    "SELECT * FROM ltfs_qualification_reconciliations WHERE run_id=?",
                    (run_id,),
                )
            ),
            tuple(
                self.catalog.connection.execute(
                    "SELECT status,fence_reason,fenced_at FROM "
                    "ltfs_qualification_runs WHERE run_id=?",
                    (run_id,),
                ).fetchone()
            ),
        )

    def _assert_fenced_without_partial_rows(self, run_id):
        run = self.catalog.connection.execute(
            "SELECT status,fence_reason,fenced_at FROM ltfs_qualification_runs "
            "WHERE run_id=?",
            (run_id,),
        ).fetchone()
        reconciliations = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM ltfs_qualification_reconciliations WHERE run_id=?",
            (run_id,),
        ).fetchone()[0]
        self.assertEqual("fenced", run["status"])
        self.assertEqual("ambiguous_dispatch", run["fence_reason"])
        self.assertIsNotNone(run["fenced_at"])
        terminal_stages = self.catalog.connection.execute(
            "SELECT COUNT(*) FROM ltfs_qualification_stages "
            "WHERE run_id=? AND terminal_receipt_sha256 IS NOT NULL",
            (run_id,),
        ).fetchone()[0]
        self.assertEqual(0, terminal_stages)
        self.assertEqual(0, reconciliations)


class _FailingReconciliationCatalog(Catalog):
    failure_point = None

    def _insert_ltfs_qualification_terminal_tx(self, *args, **kwargs):
        result = super()._insert_ltfs_qualification_terminal_tx(*args, **kwargs)
        if self.failure_point == "terminal":
            raise RuntimeError("injected after terminal insert")
        return result

    def _insert_ltfs_qualification_reconciliation_tx(self, *args, **kwargs):
        result = super()._insert_ltfs_qualification_reconciliation_tx(*args, **kwargs)
        if self.failure_point == "reconciliation":
            raise RuntimeError("injected after reconciliation insert")
        return result


if __name__ == "__main__":
    unittest.main()
