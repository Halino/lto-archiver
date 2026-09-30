from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.migration.validator import (
    SUPPORTED_BUNDLE_SCHEMAS,
    CatalogContractValidation,
    MigrationValidator,
    ReadOnlyCatalog,
    canonical_sequence_manifest_sha256,
    validate_catalog_contract,
)
from tests.fixtures import build_frozen_job_fixture


class SchemaTwentySixMigrationValidatorTests(unittest.TestCase):
    _SCHEMA_36_COLUMNS = {
        "automatic_format_authorizations": (
            "authorization_id", "job_id", "cassette_sequence", "layout_epoch",
            "layout_fingerprint_sha256", "expected_label", "expected_operation",
            "reuse_registered", "authorized_by", "authorized_at", "request_sha256",
        ),
        "automatic_sequence_state": (
            "job_id", "state", "layout_epoch", "layout_fingerprint_sha256",
            "revision", "enabled_by", "enabled_at", "updated_at",
        ),
        "operation_format_authorizations": (
            "operation_id", "authorization_id", "linked_at",
        ),
    }
    _IMMUTABLE_TRIGGERS = (
        "trg_automatic_format_authorizations_no_update",
        "trg_automatic_format_authorizations_no_delete",
        "trg_operation_format_authorizations_no_update",
        "trg_operation_format_authorizations_no_delete",
    )
    _CONTINUATION_TRIGGERS = (
        "trg_operation_sequence_continuations_no_update",
        "trg_operation_sequence_continuations_no_delete",
    )
    _AUTHORITY_COLUMNS = _SCHEMA_36_COLUMNS["automatic_format_authorizations"]
    _STATE_COLUMNS = _SCHEMA_36_COLUMNS["automatic_sequence_state"]
    _OPERATION_AUTHORITY_COLUMNS = _SCHEMA_36_COLUMNS[
        "operation_format_authorizations"
    ]
    _CONTINUATION_COLUMNS = (
        "operation_id",
        "job_id",
        "cassette_sequence",
        "layout_epoch",
        "layout_fingerprint_sha256",
        "continuation_idempotency_key",
        "linked_at",
    )

    @staticmethod
    def _authority_ddl(*, epoch_unique: bool) -> str:
        unique = (
            "UNIQUE(job_id,cassette_sequence,expected_label,layout_epoch)"
            if epoch_unique
            else "UNIQUE(job_id,cassette_sequence,expected_label)"
        )
        return f"""
            CREATE TABLE {{table}} (
                authorization_id TEXT PRIMARY KEY,
                job_id TEXT NOT NULL COLLATE NOCASE,
                cassette_sequence INTEGER NOT NULL CHECK(cassette_sequence > 0),
                layout_epoch INTEGER NOT NULL CHECK(layout_epoch > 0),
                layout_fingerprint_sha256 TEXT NOT NULL
                    CHECK(length(layout_fingerprint_sha256) = 64),
                expected_label TEXT NOT NULL CHECK(length(expected_label) = 6),
                expected_operation TEXT NOT NULL CHECK(expected_operation = 'format'),
                reuse_registered INTEGER NOT NULL CHECK(reuse_registered IN (0,1)),
                authorized_by TEXT NOT NULL,
                authorized_at TEXT NOT NULL,
                request_sha256 TEXT NOT NULL CHECK(length(request_sha256) = 64),
                {unique},
                FOREIGN KEY(job_id,cassette_sequence)
                    REFERENCES automatic_cassettes(job_id,sequence),
                FOREIGN KEY(job_id,layout_epoch)
                    REFERENCES job_layout_epochs(job_id,epoch_number)
            )
        """

    _STATE_DDL = """
        CREATE TABLE {table} (
            job_id TEXT PRIMARY KEY COLLATE NOCASE REFERENCES automatic_jobs(id),
            state TEXT NOT NULL
                CHECK(state IN ('disabled','enabled','pause_pending','completed')),
            layout_epoch INTEGER NOT NULL CHECK(layout_epoch > 0),
            layout_fingerprint_sha256 TEXT NOT NULL
                CHECK(length(layout_fingerprint_sha256) = 64),
            revision INTEGER NOT NULL CHECK(revision > 0),
            enabled_by TEXT,
            enabled_at TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(job_id,layout_epoch)
                REFERENCES job_layout_epochs(job_id,epoch_number)
        )
    """
    _OPERATION_AUTHORITY_DDL = """
        CREATE TABLE {table} (
            operation_id TEXT PRIMARY KEY REFERENCES format_confirmations(operation_id),
            authorization_id TEXT NOT NULL
                REFERENCES automatic_format_authorizations(authorization_id),
            linked_at TEXT NOT NULL
        )
    """
    _CONTINUATION_DDL = """
        CREATE TABLE {table} (
            operation_id TEXT PRIMARY KEY REFERENCES daemon_operations(id),
            job_id TEXT NOT NULL COLLATE NOCASE,
            cassette_sequence INTEGER NOT NULL CHECK(cassette_sequence > 0),
            layout_epoch INTEGER NOT NULL CHECK(layout_epoch > 0),
            layout_fingerprint_sha256 TEXT NOT NULL
                CHECK(length(layout_fingerprint_sha256) = 64),
            continuation_idempotency_key TEXT NOT NULL UNIQUE,
            linked_at TEXT NOT NULL,
            FOREIGN KEY(job_id,cassette_sequence)
                REFERENCES automatic_cassettes(job_id,sequence),
            FOREIGN KEY(job_id,layout_epoch)
                REFERENCES job_layout_epochs(job_id,epoch_number)
        )
    """

    @staticmethod
    def _real_schema(database: Path, schema_version: int) -> None:
        build_frozen_job_fixture(
            database, completed=3, total=20, schema_version=25
        )
        with Catalog(database) as catalog:
            catalog.initialize(target_version=min(schema_version, 36))
        if schema_version >= 37:
            backup = database.parent / (
                "20260830T180000000000Z-abcdef123456-p-v36-"
                "0123456789abcdef.sqlite3"
            )
            shutil.copy2(database, backup)
            with Catalog(database) as catalog:
                catalog._initialize_after_protected_backup(37, backup)
        if schema_version >= 38:
            backup = database.parent / (
                "20260831T180000000000Z-abcdef123456-p-v37-"
                "0123456789abcdef.sqlite3"
            )
            shutil.copy2(database, backup)
            with Catalog(database) as catalog:
                catalog._initialize_after_protected_backup(38, backup)
        if schema_version >= 39:
            backup = database.parent / (
                "20260831T190000000000Z-abcdef123456-p-v38-"
                "0123456789abcdef.sqlite3"
            )
            shutil.copy2(database, backup)
            with Catalog(database) as catalog:
                catalog._initialize_after_protected_backup(39, backup)
        if schema_version >= 40:
            with Catalog(database) as catalog:
                catalog.initialize(target_version=40)

    @classmethod
    def _rebuild_table(
        cls,
        database: Path,
        table: str,
        columns: tuple[str, ...],
        ddl: str,
    ) -> None:
        replacement = f"{table}_replacement"
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA foreign_keys=OFF")
            for trigger in cls._IMMUTABLE_TRIGGERS + cls._CONTINUATION_TRIGGERS:
                connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
            connection.execute(ddl.format(table=replacement))
            connection.execute(
                f"INSERT INTO {replacement}({','.join(columns)}) "
                f"SELECT {','.join(columns)} FROM {table}"
            )
            connection.execute(f"DROP TABLE {table}")
            connection.execute(f"ALTER TABLE {replacement} RENAME TO {table}")
            cls._install_test_triggers(connection)

    @staticmethod
    def _install_test_triggers(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TRIGGER IF NOT EXISTS trg_automatic_format_authorizations_no_update
            BEFORE UPDATE ON automatic_format_authorizations
            BEGIN SELECT RAISE(ABORT,'immutable_automatic_format_authorization'); END;
            CREATE TRIGGER IF NOT EXISTS trg_automatic_format_authorizations_no_delete
            BEFORE DELETE ON automatic_format_authorizations
            BEGIN SELECT RAISE(ABORT,'immutable_automatic_format_authorization'); END;
            CREATE TRIGGER IF NOT EXISTS trg_operation_format_authorizations_no_update
            BEFORE UPDATE ON operation_format_authorizations
            BEGIN SELECT RAISE(ABORT,'immutable_operation_format_authorization'); END;
            CREATE TRIGGER IF NOT EXISTS trg_operation_format_authorizations_no_delete
            BEFORE DELETE ON operation_format_authorizations
            BEGIN SELECT RAISE(ABORT,'immutable_operation_format_authorization'); END;
            """
        )
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='operation_sequence_continuations'"
        ).fetchone() is not None:
            connection.executescript(
                """
                CREATE TRIGGER IF NOT EXISTS trg_operation_sequence_continuations_no_update
                BEFORE UPDATE ON operation_sequence_continuations
                BEGIN SELECT RAISE(ABORT,'immutable_operation_sequence_continuation'); END;
                CREATE TRIGGER IF NOT EXISTS trg_operation_sequence_continuations_no_delete
                BEFORE DELETE ON operation_sequence_continuations
                BEGIN SELECT RAISE(ABORT,'immutable_operation_sequence_continuation'); END;
                """
            )

    @staticmethod
    def _report(database: Path):
        with ReadOnlyCatalog(database) as catalog:
            return MigrationValidator.inspect(catalog, "JOB-MIGRATION")

    @staticmethod
    def _replace_trigger(database: Path, name: str, ddl: str) -> None:
        with sqlite3.connect(database) as connection:
            connection.execute(f"DROP TRIGGER {name}")
            connection.execute(ddl)

    @staticmethod
    def _rewrite_empty_schema_table(
        database: Path,
        table: str,
        old: str,
        new: str,
    ) -> None:
        with sqlite3.connect(database) as connection:
            table_sql = str(
                connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                    (table,),
                ).fetchone()[0]
            )
            if old not in table_sql:
                raise AssertionError(f"fixture fragment absent from {table}: {old}")
            dependent_sql = tuple(
                str(row[0])
                for row in connection.execute(
                    "SELECT sql FROM sqlite_master WHERE tbl_name=? "
                    "AND type IN ('index','trigger') AND sql IS NOT NULL "
                    "ORDER BY type,name",
                    (table,),
                )
            )
            row_count = int(
                connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            )
            if row_count:
                raise AssertionError(f"schema-tamper fixture table is not empty: {table}")
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute("PRAGMA legacy_alter_table=ON")
            connection.execute(f"ALTER TABLE {table} RENAME TO {table}_legacy_test")
            connection.execute(table_sql.replace(old, new, 1))
            connection.execute(f"DROP TABLE {table}_legacy_test")
            for ddl in dependent_sql:
                connection.execute(ddl)

    @staticmethod
    def _seed_continuation(database: Path) -> None:
        with sqlite3.connect(database) as connection:
            connection.execute("PRAGMA foreign_keys=ON")
            epoch = connection.execute(
                "SELECT epoch_number,layout_fingerprint_sha256 "
                "FROM job_layout_epochs WHERE job_id='JOB-MIGRATION' "
                "ORDER BY epoch_number DESC LIMIT 1"
            ).fetchone()
            connection.execute(
                "INSERT INTO daemon_operations("
                "id,kind,state,idempotency_key,principal,owner_generation,"
                "job_id,cassette_sequence,started_at) "
                "VALUES('CONTINUATION-VALIDATOR','archive.native','succeeded',"
                "'validator-continuation-key','sequence-coordinator',1,"
                "'JOB-MIGRATION',4,'2026-08-31T09:00:00+00:00')"
            )
            connection.execute(
                "INSERT INTO operation_sequence_continuations("
                "operation_id,job_id,cassette_sequence,layout_epoch,"
                "layout_fingerprint_sha256,continuation_idempotency_key,linked_at) "
                "VALUES('CONTINUATION-VALIDATOR','JOB-MIGRATION',4,?,?,?,?)",
                (
                    epoch[0],
                    epoch[1],
                    "validator-continuation-key",
                    "2026-08-31T09:00:00+00:00",
                ),
            )

    def test_schema_twenty_six_and_required_historical_schemas_are_accepted(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for schema_version in (13, 25, 26):
                with self.subTest(schema_version=schema_version):
                    database = root / f"schema-{schema_version}.db"
                    build_frozen_job_fixture(
                        database,
                        completed=3,
                        total=20,
                        schema_version=min(schema_version, 25),
                    )
                    if schema_version == 26:
                        with sqlite3.connect(database) as connection:
                            connection.execute(
                                "UPDATE metadata SET value='26' "
                                "WHERE key='schema_version'"
                            )
                    with ReadOnlyCatalog(database) as catalog:
                        report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")

                    self.assertTrue(report.accepted, report.error_codes)

    def test_schema_thirty_is_supported_for_frozen_bundle_validation(self) -> None:
        self.assertIn(30, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(31, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(32, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(33, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(34, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(36, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(37, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(38, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(39, SUPPORTED_BUNDLE_SCHEMAS)
        self.assertIn(40, SUPPORTED_BUNDLE_SCHEMAS)

    def test_schema_40_requires_exit_code_and_readback_release_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for missing_kind in (
                "exit-code",
                "receipt-table",
                "receipt-update-trigger",
                "receipt-delete-trigger",
            ):
                with self.subTest(missing_kind=missing_kind):
                    database = root / f"schema-40-missing-{missing_kind}.db"
                    self._real_schema(database, 40)
                    with sqlite3.connect(database) as connection:
                        if missing_kind == "exit-code":
                            connection.execute("PRAGMA writable_schema=ON")
                            sql = connection.execute(
                                "SELECT sql FROM sqlite_master WHERE type='table' "
                                "AND name='hardware_command_executions'"
                            ).fetchone()[0]
                            connection.execute(
                                "UPDATE sqlite_master SET sql=? WHERE type='table' "
                                "AND name='hardware_command_executions'",
                                (sql.replace(", terminal_exit_code INTEGER", ""),),
                            )
                            connection.execute("PRAGMA writable_schema=OFF")
                        elif missing_kind == "receipt-table":
                            connection.execute(
                                "DROP TABLE qualification_readback_release_receipts"
                            )
                        elif missing_kind == "receipt-update-trigger":
                            connection.execute(
                                "DROP TRIGGER qualification_readback_release_immutable"
                            )
                        else:
                            connection.execute(
                                "DROP TRIGGER qualification_readback_release_no_delete"
                            )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertTrue(
                        {"required-column-missing", "required-table-missing", "required-trigger-missing"}
                        & set(report.error_codes),
                        report.error_codes,
                    )

    def test_schema_40_requires_exact_readback_receipt_table_contract(self) -> None:
        corruptions = {
            "primary-key": (
                "operation_id TEXT PRIMARY KEY NOT NULL\n                    REFERENCES",
                "operation_id TEXT NOT NULL\n                    REFERENCES",
                "required-primary-key-invalid",
            ),
            "operation-foreign-key": (
                "REFERENCES daemon_operations(id)",
                "",
                "required-foreign-key-invalid",
            ),
            "unload-foreign-key": (
                "REFERENCES hardware_command_executions(id)",
                "",
                "required-foreign-key-invalid",
            ),
            "probe-foreign-key": (
                "probe_command_id TEXT NOT NULL\n                    REFERENCES hardware_command_executions(id)",
                "probe_command_id TEXT NOT NULL",
                "required-foreign-key-invalid",
            ),
            "operation-not-null": (
                "operation_id TEXT PRIMARY KEY NOT NULL",
                "operation_id TEXT PRIMARY KEY",
                "required-column-contract-invalid",
            ),
            "not-null": (
                "owner_generation INTEGER NOT NULL",
                "owner_generation INTEGER",
                "required-column-contract-invalid",
            ),
            "type": (
                "owner_generation INTEGER NOT NULL",
                "owner_generation TEXT NOT NULL",
                "required-column-contract-invalid",
            ),
            "digest-check": (
                "CHECK(length(release_receipt_sha256)=64)",
                "",
                "required-check-constraint-invalid",
            ),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for kind, (old, new, error_code) in corruptions.items():
                with self.subTest(kind=kind):
                    database = root / f"schema-40-invalid-receipt-{kind}.db"
                    self._real_schema(database, 40)
                    self._rewrite_empty_schema_table(
                        database,
                        "qualification_readback_release_receipts",
                        old,
                        new,
                    )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn(error_code, report.error_codes)

    def test_schema_40_requires_integer_terminal_exit_code_column(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "schema-40-exit-code-type.db"
            self._real_schema(database, 40)
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA writable_schema=ON")
                sql = str(connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='hardware_command_executions'"
                ).fetchone()[0])
                connection.execute(
                    "UPDATE sqlite_master SET sql=? WHERE type='table' "
                    "AND name='hardware_command_executions'",
                    (sql.replace(
                        "terminal_exit_code INTEGER",
                        "terminal_exit_code TEXT",
                        1,
                    ),),
                )
                connection.execute("PRAGMA writable_schema=OFF")

            report = self._report(database)
            self.assertFalse(report.accepted)
            self.assertIn("required-column-contract-invalid", report.error_codes)

    def test_schema_40_rejects_invalid_terminal_exit_code_lifecycle_rows(self) -> None:
        cases = (
            ("released", None, 0),
            ("quiesced", "terminated", 1),
            ("quiesced", "launch_aborted", 1),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for state, outcome, exit_code in cases:
                with self.subTest(state=state, outcome=outcome):
                    database = root / f"schema-40-invalid-exit-{state}-{outcome}.db"
                    self._real_schema(database, 40)
                    with sqlite3.connect(database) as connection:
                        operation_id = f"validator-exit-{state}-{outcome}"
                        connection.execute(
                            "INSERT INTO daemon_operations("
                            "id,kind,state,idempotency_key,principal,owner_generation,"
                            "started_at) VALUES(?,?,?,?,?,1,?)",
                            (
                                operation_id,
                                "tape.qualification-readback",
                                "running",
                                operation_id,
                                "validator",
                                "2026-09-04T10:00:00+00:00",
                            ),
                        )
                        connection.execute(
                            "INSERT INTO hardware_command_executions("
                            "id,operation_id,issued_generation,command_kind,"
                            "argv_sha256,mount_path_sha256,"
                            "tape_device_identity_sha256,"
                            "scsi_device_identity_sha256,"
                            "expected_media_scope_sha256,state,exit_outcome,"
                            "created_at,terminal_exit_code) "
                            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                            (
                                f"command-{state}-{outcome}",
                                operation_id,
                                1,
                                "probe_media",
                                "a" * 64,
                                "b" * 64,
                                "c" * 64,
                                "d" * 64,
                                "e" * 64,
                                state,
                                outcome,
                                "2026-09-04T10:00:01+00:00",
                                exit_code,
                            ),
                        )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn(
                        "terminal-exit-code-lifecycle-invalid",
                        report.error_codes,
                    )

    def test_schema_40_allows_legacy_completed_command_without_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "schema-40-legacy-null-exit.db"
            self._real_schema(database, 40)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "INSERT INTO daemon_operations("
                    "id,kind,state,idempotency_key,principal,owner_generation,"
                    "started_at) VALUES('legacy-operation','archive.resume','running',"
                    "'legacy-operation','validator',1,'2026-09-04T10:00:00+00:00')"
                )
                connection.execute(
                    "INSERT INTO hardware_command_executions("
                    "id,operation_id,issued_generation,command_kind,argv_sha256,"
                    "mount_path_sha256,tape_device_identity_sha256,"
                    "scsi_device_identity_sha256,expected_media_scope_sha256,"
                    "state,exit_outcome,created_at,terminal_exit_code) "
                    "VALUES('legacy-command','legacy-operation',1,'identify',"
                    "?,?,?,?,?,'quiesced','completed',?,NULL)",
                    (
                        "a" * 64,
                        "b" * 64,
                        "c" * 64,
                        "d" * 64,
                        "e" * 64,
                        "2026-09-04T10:00:01+00:00",
                    ),
                )

            report = self._report(database)
            self.assertTrue(report.accepted, report.error_codes)

    def test_schema_39_requires_restore_run_table_and_immutable_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for missing_kind in ("table", "trigger", "destination-table"):
                with self.subTest(missing_kind=missing_kind):
                    database = root / f"schema-39-missing-{missing_kind}.db"
                    self._real_schema(database, 39)
                    valid = self._report(database)
                    self.assertTrue(valid.accepted, valid.error_codes)
                    with sqlite3.connect(database) as connection:
                        connection.execute("PRAGMA foreign_keys=OFF")
                        if missing_kind == "table":
                            connection.execute(
                                "DROP TABLE restore_replacement_authorizations"
                            )
                        elif missing_kind == "destination-table":
                            connection.execute("DROP TABLE restore_plan_destinations")
                        else:
                            connection.execute(
                                "DROP TRIGGER restore_run_items_no_delete"
                            )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn(
                        "required-table-missing"
                        if missing_kind in {"table", "destination-table"}
                        else "required-trigger-missing",
                        report.error_codes,
                    )

    def test_schema_39_rejects_noncanonical_identity_trigger_contracts(self) -> None:
        marker = "restore run item identity is immutable"
        cases = (
            (
                "no-op",
                "CREATE TRIGGER restore_run_items_immutable_identity "
                "BEFORE UPDATE ON restore_run_items BEGIN SELECT 1; END",
            ),
            (
                "wrong-table",
                "CREATE TRIGGER restore_run_items_immutable_identity "
                "BEFORE UPDATE ON restore_runs "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            ),
            (
                "wrong-event",
                "CREATE TRIGGER restore_run_items_immutable_identity "
                "BEFORE INSERT ON restore_run_items "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, ddl in cases:
                with self.subTest(label=label):
                    database = root / f"schema-39-trigger-{label}.db"
                    self._real_schema(database, 39)
                    self._replace_trigger(
                        database,
                        "restore_run_items_immutable_identity",
                        ddl,
                    )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn("required-trigger-invalid", report.error_codes)

    def test_schema_39_rejects_destination_snapshot_contract_tampering(self) -> None:
        def restore_destination_triggers(connection: sqlite3.Connection) -> None:
            connection.executescript(
                """
                CREATE TRIGGER restore_plan_destinations_immutable_update
                BEFORE UPDATE ON restore_plan_destinations
                BEGIN SELECT RAISE(ABORT,'restore plan destination is immutable'); END;
                CREATE TRIGGER restore_plan_destinations_immutable_delete
                BEFORE DELETE ON restore_plan_destinations
                BEGIN SELECT RAISE(ABORT,'restore plan destination is immutable'); END;
                """
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                ("weak-trigger", "trigger", "required-trigger-invalid"),
                ("missing-nul-check", "nul-check", "required-check-constraint-invalid"),
                (
                    "missing-anchor-nul-check",
                    "anchor-nul-check",
                    "required-check-constraint-invalid",
                ),
                ("widened-state-kind", "state-kind", "required-check-constraint-invalid"),
                ("wrong-foreign-key", "foreign-key", "required-foreign-key-invalid"),
                ("wrong-primary-key", "primary-key", "required-primary-key-invalid"),
            )
            for label, corruption, expected_error in cases:
                with self.subTest(label=label):
                    database = root / f"schema-39-destination-{label}.db"
                    self._real_schema(database, 39)
                    with sqlite3.connect(database) as connection:
                        if corruption == "trigger":
                            connection.execute(
                                "DROP TRIGGER restore_plan_destinations_immutable_update"
                            )
                            connection.execute(
                                "CREATE TRIGGER restore_plan_destinations_immutable_update "
                                "BEFORE UPDATE ON restore_plan_destinations "
                                "BEGIN SELECT 1; END"
                            )
                        else:
                            schema = connection.execute(
                                "SELECT sql FROM sqlite_master WHERE type='table' "
                                "AND name='restore_plan_destinations'"
                            ).fetchone()[0]
                            connection.execute("DROP TABLE restore_plan_destinations")
                            if corruption == "nul-check":
                                schema = schema.replace(
                                    "AND instr(root,char(0))=0", "", 1
                                )
                            elif corruption == "anchor-nul-check":
                                schema = schema.replace(
                                    "AND instr(anchor,char(0))=0", "", 1
                                )
                            elif corruption == "state-kind":
                                schema = schema.replace(
                                    "'exact','legacy_invalid'",
                                    "'exact','legacy_invalid','remote'",
                                ).replace(
                                    "kind IS NULL OR kind='local'",
                                    "kind IS NULL OR kind IN ('local','remote')",
                                )
                            elif corruption == "foreign-key":
                                schema = schema.replace(
                                    "ON DELETE RESTRICT", "ON DELETE CASCADE", 1
                                )
                            else:
                                schema = schema.replace(
                                    "plan_id TEXT PRIMARY KEY", "plan_id TEXT", 1
                                )
                            connection.execute(schema)
                            restore_destination_triggers(connection)
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn(expected_error, report.error_codes)

    def test_schema_39_rejects_missing_or_wrong_partial_unique_indexes(self) -> None:
        contracts = (
            (
                "ux_restore_one_active_run_per_plan",
                "CREATE UNIQUE INDEX ux_restore_one_active_run_per_plan "
                "ON restore_runs(plan_id) WHERE state IN ('planned')",
            ),
            (
                "ux_restore_item_one_open_conflict",
                "CREATE UNIQUE INDEX ux_restore_item_one_open_conflict "
                "ON restore_item_conflicts(run_id,item_sequence) "
                "WHERE state='recorded'",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index_name, wrong_ddl in contracts:
                for corruption in ("missing", "wrong"):
                    with self.subTest(index=index_name, corruption=corruption):
                        database = root / f"schema-39-{index_name}-{corruption}.db"
                        self._real_schema(database, 39)
                        with sqlite3.connect(database) as connection:
                            connection.execute(f"DROP INDEX {index_name}")
                            if corruption == "wrong":
                                connection.execute(wrong_ddl)
                        report = self._report(database)
                        self.assertFalse(report.accepted)
                        self.assertIn(
                            "required-index-missing"
                            if corruption == "missing"
                            else "required-index-invalid",
                            report.error_codes,
                        )

    def test_schema_39_rejects_weakened_state_fk_and_unique_bindings(self) -> None:
        cases = (
            (
                "state",
                "restore_runs",
                "'cancelled','failed','recovery_required'",
                "'cancelled','failed','recovery_required','unsafe_resume'",
                "required-check-constraint-invalid",
            ),
            (
                "foreign-key",
                "restore_run_items",
                "REFERENCES restore_runs(id,plan_id)",
                "REFERENCES restore_runs(id,id)",
                "required-foreign-key-invalid",
            ),
            (
                "unique",
                "restore_item_conflicts",
                "UNIQUE(id,run_id,item_sequence)",
                "UNIQUE(id,run_id,conflict_sequence)",
                "required-unique-constraint-invalid",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for label, table, old, new, expected_error in cases:
                with self.subTest(label=label):
                    database = root / f"schema-39-contract-{label}.db"
                    self._real_schema(database, 39)
                    self._rewrite_empty_schema_table(database, table, old, new)
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn(expected_error, report.error_codes)

    def test_schema_thirty_six_requires_authority_tables_and_immutable_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "schema-36.db"
            build_frozen_job_fixture(database, completed=3, total=20, schema_version=25)
            with Catalog(database) as catalog:
                catalog.initialize(target_version=36)
            with ReadOnlyCatalog(database) as catalog:
                valid = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
            self.assertTrue(valid.accepted, valid.error_codes)

            with sqlite3.connect(database) as connection:
                connection.execute(
                    "DROP TRIGGER trg_automatic_format_authorizations_no_update"
                )
            with ReadOnlyCatalog(database) as catalog:
                missing = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
            self.assertFalse(missing.accepted)
            self.assertIn("required-trigger-missing", missing.error_codes)

    def test_schema_thirty_six_rejects_each_missing_authority_table(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, table in enumerate(self._SCHEMA_36_COLUMNS):
                with self.subTest(table=table):
                    database = root / f"missing-table-{index}.db"
                    self._real_schema(database, 36)
                    with sqlite3.connect(database) as connection:
                        connection.execute("PRAGMA foreign_keys=OFF")
                        connection.execute(f"DROP TABLE {table}")
                    with ReadOnlyCatalog(database) as catalog:
                        report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                    self.assertFalse(report.accepted)
                    self.assertIn("required-table-missing", report.error_codes)

    def test_schema_thirty_six_rejects_each_missing_required_column(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            case = 0
            for table, columns in self._SCHEMA_36_COLUMNS.items():
                for removed in columns:
                    with self.subTest(table=table, removed=removed):
                        database = root / f"missing-column-{case}.db"
                        case += 1
                        self._real_schema(database, 36)
                        retained = tuple(column for column in columns if column != removed)
                        with sqlite3.connect(database) as connection:
                            connection.execute("PRAGMA foreign_keys=OFF")
                            for trigger in self._IMMUTABLE_TRIGGERS:
                                connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                            connection.execute(f"ALTER TABLE {table} RENAME TO old_table")
                            connection.execute(
                                f"CREATE TABLE {table} AS SELECT {','.join(retained)} "
                                "FROM old_table"
                            )
                            connection.execute("DROP TABLE old_table")
                        with ReadOnlyCatalog(database) as catalog:
                            report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                        self.assertFalse(report.accepted)
                        self.assertIn("required-column-missing", report.error_codes)

    def test_schema_thirty_six_rejects_each_missing_or_corrupt_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, trigger in enumerate(self._IMMUTABLE_TRIGGERS):
                table = (
                    "operation_format_authorizations"
                    if "operation_format" in trigger
                    else "automatic_format_authorizations"
                )
                for corrupt in (False, True):
                    with self.subTest(trigger=trigger, corrupt=corrupt):
                        database = root / f"trigger-{index}-{int(corrupt)}.db"
                        self._real_schema(database, 36)
                        with sqlite3.connect(database) as connection:
                            connection.execute(f"DROP TRIGGER {trigger}")
                            if corrupt:
                                connection.execute(
                                    f"CREATE TRIGGER {trigger} BEFORE INSERT ON {table} "
                                    "BEGIN SELECT RAISE(ABORT,'corrupt_trigger'); END"
                                )
                        with ReadOnlyCatalog(database) as catalog:
                            report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                        self.assertFalse(report.accepted)
                        self.assertIn(
                            "required-trigger-invalid" if corrupt else "required-trigger-missing",
                            report.error_codes,
                        )

    def test_real_schema_thirty_five_and_thirty_seven_contracts_are_valid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for schema_version in (35, 37):
                with self.subTest(schema_version=schema_version):
                    database = root / f"schema-{schema_version}.db"
                    self._real_schema(database, schema_version)
                    with ReadOnlyCatalog(database) as catalog:
                        report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                    self.assertTrue(report.accepted, report.error_codes)

    def test_public_catalog_contract_validation_accepts_schema_38_with_extras(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "schema-38-with-extras.db"
            self._real_schema(database, 38)
            with sqlite3.connect(database) as connection:
                connection.execute(
                    "ALTER TABLE operation_sequence_continuations "
                    "ADD COLUMN verifier_note TEXT"
                )
                connection.execute(
                    "CREATE TABLE unrelated_runtime_state "
                    "(id INTEGER PRIMARY KEY, note TEXT)"
                )
                connection.commit()
                changes_before = connection.total_changes

                result = validate_catalog_contract(connection, 38)

                self.assertIsInstance(result, CatalogContractValidation)
                self.assertTrue(result.valid, result.error_codes)
                self.assertEqual(38, result.schema_version)
                self.assertEqual((), result.error_codes)
                self.assertEqual(changes_before, connection.total_changes)
                self.assertFalse(connection.in_transaction)

    def test_public_catalog_contract_validation_requires_exact_version_and_shape(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "schema-38-invalid.db"
            self._real_schema(database, 38)
            with sqlite3.connect(database) as connection:
                mismatch = validate_catalog_contract(connection, 37)
                self.assertFalse(mismatch.valid)
                self.assertEqual(38, mismatch.schema_version)
                self.assertEqual(
                    ("schema-version-mismatch",), mismatch.error_codes
                )

                connection.execute(
                    "DROP TRIGGER trg_operation_sequence_continuations_no_update"
                )
                connection.execute(
                    "DROP TRIGGER trg_operation_sequence_continuations_no_delete"
                )
                connection.execute("DROP TABLE operation_sequence_continuations")
                connection.commit()
                malformed = validate_catalog_contract(connection, 38)

                self.assertFalse(malformed.valid)
                self.assertEqual(38, malformed.schema_version)
                self.assertEqual(
                    ("required-table-missing", "required-trigger-missing"),
                    malformed.error_codes,
                )

    def test_public_catalog_contract_validation_returns_typed_database_errors(
        self,
    ) -> None:
        connection = sqlite3.connect(":memory:")
        connection.close()

        result = validate_catalog_contract(connection, 38)

        self.assertIsInstance(result, CatalogContractValidation)
        self.assertFalse(result.valid)
        self.assertIsNone(result.schema_version)
        self.assertEqual(
            ("catalog-unreadable", "schema-invalid"), result.error_codes
        )

    def test_schema_thirty_seven_rejects_missing_epoch_unique_constraint(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "schema-37.db"
            self._real_schema(database, 37)
            with sqlite3.connect(database) as connection:
                connection.execute("PRAGMA foreign_keys=OFF")
                for trigger in self._IMMUTABLE_TRIGGERS:
                    connection.execute(f"DROP TRIGGER IF EXISTS {trigger}")
                connection.execute(
                    "ALTER TABLE automatic_format_authorizations RENAME TO old_authorities"
                )
                connection.execute(
                    "CREATE TABLE automatic_format_authorizations AS SELECT * FROM old_authorities"
                )
                connection.execute("DROP TABLE old_authorities")
            with ReadOnlyCatalog(database) as catalog:
                report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
            self.assertFalse(report.accepted)
            self.assertIn("required-unique-constraint-invalid", report.error_codes)

    def test_authority_contract_rejects_each_missing_primary_key(self) -> None:
        cases = (
            (
                37,
                "automatic_format_authorizations",
                self._AUTHORITY_COLUMNS,
                self._authority_ddl(epoch_unique=True),
                "authorization_id TEXT PRIMARY KEY",
                "authorization_id TEXT",
            ),
            (
                37,
                "automatic_sequence_state",
                self._STATE_COLUMNS,
                self._STATE_DDL,
                "job_id TEXT PRIMARY KEY COLLATE NOCASE",
                "job_id TEXT COLLATE NOCASE",
            ),
            (
                37,
                "operation_format_authorizations",
                self._OPERATION_AUTHORITY_COLUMNS,
                self._OPERATION_AUTHORITY_DDL,
                "operation_id TEXT PRIMARY KEY",
                "operation_id TEXT",
            ),
            (
                38,
                "operation_sequence_continuations",
                self._CONTINUATION_COLUMNS,
                self._CONTINUATION_DDL,
                "operation_id TEXT PRIMARY KEY",
                "operation_id TEXT",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (version, table, columns, ddl, old, new) in enumerate(cases):
                with self.subTest(table=table):
                    database = root / f"primary-key-{index}.db"
                    self._real_schema(database, version)
                    self._rebuild_table(database, table, columns, ddl.replace(old, new))
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn("required-primary-key-invalid", report.error_codes)

    def test_schema_specific_authority_unique_keys_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            schema_36 = root / "schema-36.db"
            self._real_schema(schema_36, 36)
            self.assertTrue(self._report(schema_36).accepted)

            wrong_36 = root / "wrong-36.db"
            shutil.copy2(schema_36, wrong_36)
            wrong_ddl = self._authority_ddl(epoch_unique=False).replace(
                "UNIQUE(job_id,cassette_sequence,expected_label)",
                "UNIQUE(expected_label,cassette_sequence,job_id)",
            )
            self._rebuild_table(
                wrong_36,
                "automatic_format_authorizations",
                self._AUTHORITY_COLUMNS,
                wrong_ddl,
            )
            self.assertIn(
                "required-unique-constraint-invalid",
                self._report(wrong_36).error_codes,
            )

            schema_37 = root / "schema-37.db"
            self._real_schema(schema_37, 37)
            both = self._authority_ddl(epoch_unique=True).replace(
                "FOREIGN KEY(job_id,cassette_sequence)",
                "UNIQUE(job_id,cassette_sequence,expected_label),\n"
                "                FOREIGN KEY(job_id,cassette_sequence)",
            )
            self._rebuild_table(
                schema_37,
                "automatic_format_authorizations",
                self._AUTHORITY_COLUMNS,
                both,
            )
            report = self._report(schema_37)
            self.assertFalse(report.accepted)
            self.assertIn("legacy-authority-unique-present", report.error_codes)

            schema_38 = root / "schema-38.db"
            self._real_schema(schema_38, 38)
            continuation_without_unique = self._CONTINUATION_DDL.replace(
                "continuation_idempotency_key TEXT NOT NULL UNIQUE",
                "continuation_idempotency_key TEXT NOT NULL",
            )
            self._rebuild_table(
                schema_38,
                "operation_sequence_continuations",
                self._CONTINUATION_COLUMNS,
                continuation_without_unique,
            )
            self.assertIn(
                "required-unique-constraint-invalid",
                self._report(schema_38).error_codes,
            )

    def test_authority_contract_rejects_missing_and_weakened_foreign_keys(self) -> None:
        cases = (
            (
                37,
                "automatic_format_authorizations",
                self._AUTHORITY_COLUMNS,
                self._authority_ddl(epoch_unique=True),
                "REFERENCES automatic_cassettes(job_id,sequence)",
                "REFERENCES automatic_cassettes(sequence,job_id)",
            ),
            (
                37,
                "automatic_format_authorizations",
                self._AUTHORITY_COLUMNS,
                self._authority_ddl(epoch_unique=True),
                "REFERENCES job_layout_epochs(job_id,epoch_number)",
                "REFERENCES job_layout_epochs(job_id,epoch_number) ON DELETE CASCADE",
            ),
            (
                37,
                "automatic_sequence_state",
                self._STATE_COLUMNS,
                self._STATE_DDL,
                "REFERENCES automatic_jobs(id)",
                "REFERENCES automatic_jobs(id) ON UPDATE CASCADE",
            ),
            (
                37,
                "automatic_sequence_state",
                self._STATE_COLUMNS,
                self._STATE_DDL,
                "REFERENCES job_layout_epochs(job_id,epoch_number)",
                "REFERENCES job_layout_epochs(epoch_number,job_id)",
            ),
            (
                37,
                "operation_format_authorizations",
                self._OPERATION_AUTHORITY_COLUMNS,
                self._OPERATION_AUTHORITY_DDL,
                "REFERENCES format_confirmations(operation_id)",
                "REFERENCES daemon_operations(id)",
            ),
            (
                37,
                "operation_format_authorizations",
                self._OPERATION_AUTHORITY_COLUMNS,
                self._OPERATION_AUTHORITY_DDL,
                "REFERENCES automatic_format_authorizations(authorization_id)",
                "REFERENCES automatic_format_authorizations(authorization_id) ON DELETE CASCADE",
            ),
            (
                38,
                "operation_sequence_continuations",
                self._CONTINUATION_COLUMNS,
                self._CONTINUATION_DDL,
                "REFERENCES daemon_operations(id)",
                "REFERENCES format_confirmations(operation_id)",
            ),
            (
                38,
                "operation_sequence_continuations",
                self._CONTINUATION_COLUMNS,
                self._CONTINUATION_DDL,
                "REFERENCES automatic_cassettes(job_id,sequence)",
                "REFERENCES automatic_cassettes(sequence,job_id)",
            ),
            (
                38,
                "operation_sequence_continuations",
                self._CONTINUATION_COLUMNS,
                self._CONTINUATION_DDL,
                "REFERENCES job_layout_epochs(job_id,epoch_number)",
                "REFERENCES job_layout_epochs(job_id,epoch_number) ON DELETE CASCADE",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (version, table, columns, ddl, old, new) in enumerate(cases):
                with self.subTest(table=table, mutation=index):
                    database = root / f"foreign-key-{index}.db"
                    self._real_schema(database, version)
                    self._rebuild_table(database, table, columns, ddl.replace(old, new))
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn("required-foreign-key-invalid", report.error_codes)

    def test_schema_38_rejects_every_explicit_foreign_key_match_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode in ("FULL", "PARTIAL", "SIMPLE"):
                with self.subTest(mode=mode):
                    database = root / f"match-{mode.casefold()}.db"
                    self._real_schema(database, 38)
                    ddl = self._CONTINUATION_DDL.replace(
                        "REFERENCES daemon_operations(id)",
                        f"REFERENCES daemon_operations(id) MATCH {mode}",
                    )
                    self._rebuild_table(
                        database,
                        "operation_sequence_continuations",
                        self._CONTINUATION_COLUMNS,
                        ddl,
                    )
                    with sqlite3.connect(database) as connection:
                        reported_modes = {
                            str(row[7]).casefold()
                            for row in connection.execute(
                                "PRAGMA foreign_key_list("
                                "operation_sequence_continuations)"
                            )
                        }
                    self.assertEqual({"none"}, reported_modes)
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertEqual(
                        ("required-foreign-key-invalid",), report.error_codes
                    )

    def test_authority_contract_rejects_each_weakened_check(self) -> None:
        cases = (
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "cassette_sequence > 0", "cassette_sequence >= 0"),
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "layout_epoch > 0", "layout_epoch >= 0"),
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "length(layout_fingerprint_sha256) = 64", "length(layout_fingerprint_sha256) >= 63"),
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "length(expected_label) = 6", "length(expected_label) <= 6"),
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "expected_operation = 'format'", "expected_operation IN ('format','append')"),
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "reuse_registered IN (0,1)", "reuse_registered IN (0,1,2)"),
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True), "length(request_sha256) = 64", "length(request_sha256) >= 1"),
            (37, "automatic_sequence_state", self._STATE_COLUMNS, self._STATE_DDL,
             "state IN ('disabled','enabled','pause_pending','completed')", "state IN ('disabled','enabled','completed')"),
            (37, "automatic_sequence_state", self._STATE_COLUMNS, self._STATE_DDL,
             "layout_epoch > 0", "layout_epoch >= 0"),
            (37, "automatic_sequence_state", self._STATE_COLUMNS, self._STATE_DDL,
             "length(layout_fingerprint_sha256) = 64", "length(layout_fingerprint_sha256) >= 1"),
            (37, "automatic_sequence_state", self._STATE_COLUMNS, self._STATE_DDL,
             "revision > 0", "revision >= 0"),
            (38, "operation_sequence_continuations", self._CONTINUATION_COLUMNS,
             self._CONTINUATION_DDL, "cassette_sequence > 0", "cassette_sequence >= 0"),
            (38, "operation_sequence_continuations", self._CONTINUATION_COLUMNS,
             self._CONTINUATION_DDL, "layout_epoch > 0", "layout_epoch >= 0"),
            (38, "operation_sequence_continuations", self._CONTINUATION_COLUMNS,
             self._CONTINUATION_DDL, "length(layout_fingerprint_sha256) = 64", "length(layout_fingerprint_sha256) >= 1"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (version, table, columns, ddl, old, new) in enumerate(cases):
                with self.subTest(table=table, mutation=old):
                    database = root / f"check-{index}.db"
                    self._real_schema(database, version)
                    self._rebuild_table(database, table, columns, ddl.replace(old, new))
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn("required-check-constraint-invalid", report.error_codes)

    def test_all_columns_without_state_constraints_is_rejected_before_rows_violate(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "state-without-constraints.db"
            self._real_schema(database, 37)
            ddl = """
                CREATE TABLE {table} (
                    job_id TEXT, state TEXT, layout_epoch INTEGER,
                    layout_fingerprint_sha256 TEXT, revision INTEGER,
                    enabled_by TEXT, enabled_at TEXT, updated_at TEXT
                )
            """
            self._rebuild_table(
                database,
                "automatic_sequence_state",
                self._STATE_COLUMNS,
                ddl,
            )
            with sqlite3.connect(database) as connection:
                self.assertEqual([], list(connection.execute("PRAGMA foreign_key_check")))
            report = self._report(database)
            self.assertFalse(report.accepted)
            self.assertIn("required-primary-key-invalid", report.error_codes)
            self.assertIn("required-foreign-key-invalid", report.error_codes)
            self.assertIn("required-check-constraint-invalid", report.error_codes)
            self.assertIn("required-collation-invalid", report.error_codes)

    def test_required_child_collations_are_declared_nocase(self) -> None:
        cases = (
            (37, "automatic_format_authorizations", self._AUTHORITY_COLUMNS,
             self._authority_ddl(epoch_unique=True)),
            (37, "automatic_sequence_state", self._STATE_COLUMNS, self._STATE_DDL),
            (38, "operation_sequence_continuations", self._CONTINUATION_COLUMNS,
             self._CONTINUATION_DDL),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (version, table, columns, ddl) in enumerate(cases):
                with self.subTest(table=table):
                    database = root / f"collation-{index}.db"
                    self._real_schema(database, version)
                    self._rebuild_table(
                        database,
                        table,
                        columns,
                        ddl.replace(" COLLATE NOCASE", "", 1),
                    )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn("required-collation-invalid", report.error_codes)

    def test_quoted_collate_tokens_do_not_declare_a_collation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, quoted_keyword in enumerate(
                ('"COLLATE"', "`COLLATE`", "[COLLATE]")
            ):
                with self.subTest(quoted_keyword=quoted_keyword):
                    database = root / f"quoted-collate-{index}.db"
                    self._real_schema(database, 38)
                    ddl = self._CONTINUATION_DDL.replace(
                        "job_id TEXT NOT NULL COLLATE NOCASE",
                        f"job_id TEXT {quoted_keyword} NOCASE NOT NULL",
                    )
                    self._rebuild_table(
                        database,
                        "operation_sequence_continuations",
                        self._CONTINUATION_COLUMNS,
                        ddl,
                    )
                    self._seed_continuation(database)
                    with sqlite3.connect(database) as connection:
                        lower_case_matches = connection.execute(
                            "SELECT COUNT(*) FROM operation_sequence_continuations "
                            "WHERE job_id='job-migration'"
                        ).fetchone()[0]
                    self.assertEqual(0, lower_case_matches)
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertEqual(
                        ("required-collation-invalid",), report.error_codes
                    )

    def test_quoted_check_constraint_names_do_not_act_as_keywords(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, quoted_keyword in enumerate(
                ('"CHECK"', "`CHECK`", "[CHECK]")
            ):
                with self.subTest(quoted_keyword=quoted_keyword):
                    database = root / f"quoted-check-{index}.db"
                    self._real_schema(database, 38)
                    ddl = self._STATE_DDL.replace(
                        "CHECK(revision > 0)",
                        f"CONSTRAINT {quoted_keyword} CHECK(revision > 0)",
                    )
                    self._rebuild_table(
                        database,
                        "automatic_sequence_state",
                        self._STATE_COLUMNS,
                        ddl,
                    )
                    with sqlite3.connect(database) as connection:
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(
                                "UPDATE automatic_sequence_state SET revision=0"
                            )
                    report = self._report(database)
                    self.assertTrue(report.accepted, report.error_codes)

    def test_required_parent_key_collations_are_declared_nocase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (table, old, new) in enumerate(
                (
                    (
                        "automatic_jobs",
                        "id TEXT PRIMARY KEY COLLATE NOCASE",
                        "id TEXT PRIMARY KEY COLLATE BINARY",
                    ),
                    (
                        "job_layout_epochs",
                        "job_id TEXT NOT NULL COLLATE NOCASE",
                        "job_id TEXT NOT NULL COLLATE BINARY",
                    ),
                )
            ):
                with self.subTest(table=table):
                    database = root / f"parent-collation-{index}.db"
                    self._real_schema(database, 38)
                    with sqlite3.connect(database) as connection:
                        original = connection.execute(
                            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                            (table,),
                        ).fetchone()[0]
                        altered = original.replace(old, new)
                        self.assertNotEqual(original, altered)
                        connection.execute("PRAGMA writable_schema=ON")
                        connection.execute(
                            "UPDATE sqlite_master SET sql=? "
                            "WHERE type='table' AND name=?",
                            (altered, table),
                        )
                        connection.execute("PRAGMA writable_schema=OFF")
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertIn("required-collation-invalid", report.error_codes)

    def test_required_binary_parent_key_collations_reject_nocase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                (
                    36,
                    "automatic_cassettes",
                    "job_id TEXT NOT NULL",
                    "job_id TEXT NOT NULL COLLATE NOCASE",
                ),
                (
                    36,
                    "format_confirmations",
                    "operation_id TEXT PRIMARY KEY",
                    "operation_id TEXT PRIMARY KEY COLLATE NOCASE",
                ),
                (
                    36,
                    "automatic_format_authorizations",
                    "authorization_id TEXT PRIMARY KEY",
                    "authorization_id TEXT PRIMARY KEY COLLATE NOCASE",
                ),
                (
                    38,
                    "daemon_operations",
                    "id TEXT PRIMARY KEY",
                    "id TEXT PRIMARY KEY COLLATE NOCASE",
                ),
            )
            for index, (version, table, old, new) in enumerate(cases):
                with self.subTest(version=version, table=table):
                    database = root / f"binary-parent-{index}.db"
                    self._real_schema(database, version)
                    with sqlite3.connect(database) as connection:
                        original = connection.execute(
                            "SELECT sql FROM sqlite_master "
                            "WHERE type='table' AND name=?",
                            (table,),
                        ).fetchone()[0]
                        altered = original.replace(old, new, 1)
                        self.assertNotEqual(original, altered)
                        connection.execute("PRAGMA writable_schema=ON")
                        connection.execute(
                            "UPDATE sqlite_master SET sql=? "
                            "WHERE type='table' AND name=?",
                            (altered, table),
                        )
                        connection.execute("PRAGMA writable_schema=OFF")
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertEqual(
                        ("required-collation-invalid",), report.error_codes
                    )

    def test_formatting_equivalent_authority_ddl_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "formatting.db"
            self._real_schema(database, 37)
            ddl = """
                cReAtE TABLE {table} (
                    `authorization_id` TEXT PRIMARY KEY,
                    [job_id] TEXT NOT NULL coLLaTe nocase,
                    "cassette_sequence" INTEGER NOT NULL,
                    layout_epoch INTEGER NOT NULL,
                    layout_fingerprint_sha256 TEXT NOT NULL,
                    expected_label TEXT NOT NULL,
                    expected_operation TEXT NOT NULL,
                    reuse_registered INTEGER NOT NULL,
                    authorized_by TEXT NOT NULL,
                    authorized_at TEXT NOT NULL,
                    request_sha256 TEXT NOT NULL,
                    /* identity is epoch-aware */
                    UNIQUE([job_id],"cassette_sequence",expected_label,layout_epoch),
                    FOREIGN KEY([job_id],layout_epoch)
                        REFERENCES job_layout_epochs(job_id,epoch_number),
                    CHECK(0 < layout_epoch),
                    CHECK(length(request_sha256)==64),
                    CHECK(reuse_registered IN (1, 0)),
                    CHECK(expected_operation='format'),
                    CHECK(length(expected_label)=6),
                    CHECK(length(layout_fingerprint_sha256)=64),
                    CHECK(cassette_sequence>0),
                    FOREIGN KEY([job_id],"cassette_sequence")
                        REFERENCES automatic_cassettes(job_id,sequence)
                ) -- harmless trailing comment
            """
            self._rebuild_table(
                database,
                "automatic_format_authorizations",
                self._AUTHORITY_COLUMNS,
                ddl,
            )
            report = self._report(database)
            self.assertTrue(report.accepted, report.error_codes)

    def test_unsupported_check_rewrite_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "unsupported-check.db"
            self._real_schema(database, 37)
            self._rebuild_table(
                database,
                "automatic_sequence_state",
                self._STATE_COLUMNS,
                self._STATE_DDL.replace("revision > 0", "NOT revision <= 0"),
            )
            report = self._report(database)
            self.assertFalse(report.accepted)
            self.assertIn("required-check-constraint-invalid", report.error_codes)
            self.assertNotIn("required-collation-invalid", report.error_codes)

    def test_schema_38_requires_continuation_table_and_both_immutable_triggers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, trigger in enumerate(self._CONTINUATION_TRIGGERS):
                with self.subTest(trigger=trigger):
                    database = root / f"continuation-trigger-{index}.db"
                    self._real_schema(database, 38)
                    with sqlite3.connect(database) as connection:
                        connection.execute(f"DROP TRIGGER {trigger}")
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertEqual(
                        ("required-trigger-missing",), report.error_codes
                    )

    def test_schema_38_rejects_each_noncanonical_update_trigger_axis(self) -> None:
        marker = "immutable_operation_sequence_continuation"
        cases = (
            (
                "wrong-table",
                "BEFORE UPDATE ON automatic_sequence_state "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            ),
            (
                "wrong-timing",
                "AFTER UPDATE ON operation_sequence_continuations "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            ),
            (
                "wrong-event",
                "BEFORE INSERT ON operation_sequence_continuations "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            ),
            (
                "wrong-mode",
                "BEFORE UPDATE ON operation_sequence_continuations "
                f"BEGIN SELECT RAISE(FAIL,'{marker}'); END",
            ),
            (
                "conditional",
                "BEFORE UPDATE ON operation_sequence_continuations "
                "WHEN NEW.linked_at=OLD.linked_at "
                f"BEGIN SELECT RAISE(ABORT,'{marker}'); END",
            ),
            (
                "marker-string-no-op",
                "BEFORE UPDATE ON operation_sequence_continuations "
                f"BEGIN SELECT '{marker}'; END",
            ),
            (
                "marker-comment-no-op",
                "BEFORE UPDATE ON operation_sequence_continuations "
                f"BEGIN SELECT 1; /* {marker} */ END",
            ),
            (
                "extra-statement",
                "BEFORE UPDATE ON operation_sequence_continuations "
                f"BEGIN SELECT 1; SELECT RAISE(ABORT,'{marker}'); END",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = "trg_operation_sequence_continuations_no_update"
            for index, (label, declaration) in enumerate(cases):
                with self.subTest(label=label):
                    database = root / f"trigger-axis-{index}.db"
                    self._real_schema(database, 38)
                    self._replace_trigger(
                        database,
                        name,
                        f"CREATE TRIGGER {name} {declaration}",
                    )
                    report = self._report(database)
                    self.assertFalse(report.accepted)
                    self.assertEqual(("required-trigger-invalid",), report.error_codes)

    def test_schema_38_accepts_formatting_equivalent_enforcing_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "formatted-trigger.db"
            self._real_schema(database, 38)
            self._seed_continuation(database)
            name = "trg_operation_sequence_continuations_no_update"
            marker = "immutable_operation_sequence_continuation"
            self._replace_trigger(
                database,
                name,
                f'''CrEaTe TrIgGeR "{name}" BeFoRe UpDaTe
                    ON [operation_sequence_continuations] FOR EACH ROW
                    BEGIN
                        /* enforcement remains unconditional */
                        SeLeCt RaIsE ( AbOrT , '{marker}' ) ;
                    END;''',
            )
            report = self._report(database)
            self.assertTrue(report.accepted, report.error_codes)
            with sqlite3.connect(database) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, marker):
                    connection.execute(
                        "UPDATE operation_sequence_continuations "
                        "SET linked_at='2026-08-31T09:03:00+00:00'"
                    )

    def test_schema_38_trigger_validation_proves_update_and_delete_immutability(
        self,
    ) -> None:
        marker = "immutable_operation_sequence_continuation"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid_database = root / "valid.db"
            self._real_schema(valid_database, 38)
            self._seed_continuation(valid_database)
            self.assertTrue(self._report(valid_database).accepted)
            with sqlite3.connect(valid_database) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, marker):
                    connection.execute(
                        "UPDATE operation_sequence_continuations "
                        "SET linked_at='2026-08-31T09:01:00+00:00'"
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, marker):
                    connection.execute(
                        "DELETE FROM operation_sequence_continuations"
                    )

            for event in ("update", "delete"):
                with self.subTest(event=event):
                    database = root / f"mutable-{event}.db"
                    self._real_schema(database, 38)
                    self._seed_continuation(database)
                    name = f"trg_operation_sequence_continuations_no_{event}"
                    self._replace_trigger(
                        database,
                        name,
                        f"CREATE TRIGGER {name} BEFORE {event.upper()} "
                        "ON operation_sequence_continuations "
                        f"BEGIN SELECT '{marker}'; END",
                    )
                    report = self._report(database)
                    self.assertEqual(("required-trigger-invalid",), report.error_codes)
                    with sqlite3.connect(database) as connection:
                        if event == "update":
                            connection.execute(
                                "UPDATE operation_sequence_continuations "
                                "SET linked_at='2026-08-31T09:02:00+00:00'"
                            )
                            observed = connection.execute(
                                "SELECT linked_at FROM "
                                "operation_sequence_continuations"
                            ).fetchone()[0]
                            self.assertEqual("2026-08-31T09:02:00+00:00", observed)
                        else:
                            connection.execute(
                                "DELETE FROM operation_sequence_continuations"
                            )
                            remaining = connection.execute(
                                "SELECT COUNT(*) FROM "
                                "operation_sequence_continuations"
                            ).fetchone()[0]
                            self.assertEqual(0, remaining)

    def test_schema_thirty_three_acceptance_preserves_imported_assignment_digest(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            reports = []
            cassette_digests = []
            for schema_version in (30, 31, 32, 33, 34):
                database = root / f"schema-{schema_version}.db"
                build_frozen_job_fixture(
                    database, completed=3, total=20, schema_version=25
                )
                with sqlite3.connect(database) as connection:
                    connection.row_factory = sqlite3.Row
                    connection.execute(
                        "UPDATE metadata SET value=? WHERE key='schema_version'",
                        (str(schema_version),),
                    )
                    sequences = tuple(
                        int(row[0])
                        for row in connection.execute(
                            "SELECT DISTINCT sequence FROM automatic_cassette_items "
                            "WHERE job_id='JOB-MIGRATION' ORDER BY sequence"
                        )
                    )
                    cassette_digests.append(
                        tuple(
                            canonical_sequence_manifest_sha256(
                                connection, "JOB-MIGRATION", sequence
                            )
                            for sequence in sequences
                        )
                    )
                with ReadOnlyCatalog(database) as catalog:
                    reports.append(MigrationValidator.inspect(catalog, "JOB-MIGRATION"))

            for report in reports:
                self.assertTrue(report.accepted, report.error_codes)
                self.assertEqual(reports[0].assignment_sha256, report.assignment_sha256)
            for digest in cassette_digests:
                self.assertEqual(cassette_digests[0], digest)


class SchemaFortyOneValidatorTests(unittest.TestCase):
    def test_claimed_schema_41_without_change_time_columns_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=40)
                catalog.connection.execute(
                    "UPDATE metadata SET value='41' WHERE key='schema_version'"
                )
                catalog.connection.commit()
                report = validate_catalog_contract(catalog.connection, 41)
            self.assertFalse(report.valid)
            self.assertIn("required-column-missing", report.error_codes)

    def test_claimed_schema_41_without_policy_checks_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=40)
                catalog.connection.execute(
                    "ALTER TABLE file_versions ADD COLUMN source_change_ns INTEGER"
                )
                catalog.connection.execute(
                    "ALTER TABLE application_settings ADD COLUMN "
                    "source_change_detection_policy TEXT NOT NULL "
                    "DEFAULT 'size_mtime_change'"
                )
                catalog.connection.execute(
                    "UPDATE metadata SET value='41' WHERE key='schema_version'"
                )
                catalog.connection.commit()
                report = validate_catalog_contract(catalog.connection, 41)
            self.assertFalse(report.valid)
            self.assertIn("required-check-constraint-invalid", report.error_codes)



if __name__ == "__main__":
    unittest.main()
