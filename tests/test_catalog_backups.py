from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.errors import CatalogError
from tests.fixtures import make_public_schema_14_fixture
from tests.test_catalog import (
    POPULATED_TABLES,
    canonical_row_snapshot,
    foreign_key_violations,
    integrity_check,
    make_populated_schema_13_catalog,
    read_schema_version,
)


class CatalogBackupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_default_retention_keeps_one_verified_ordinary_backup(self):
        manager = BackupManager(self.root / "catalog.db", self.root / "backups")
        manager.prepare_and_initialize()
        protected = manager.create("migration", protected=True)
        old = manager.create("before-cassette-1")
        latest = manager.create("before-cassette-2")
        self.assertFalse(old.exists())
        self.assertEqual({protected, latest}, set(manager.backup_directory.glob("*.sqlite3")))
        self.assertEqual(["ok"], integrity_check(latest))

    def test_new_verified_backup_does_not_rescan_discarded_catalogs(self):
        manager = BackupManager(self.root / "catalog.db", self.root / "backups", retention=1)
        manager.prepare_and_initialize()
        old = manager.create("before-cassette-1")
        # Observe actual SQLite opens, not mocked verification outcomes. Reopening
        # an obsolete 9GB catalog is the production I/O regression being guarded.
        opened = []
        connect = sqlite3.connect
        def recording_connect(path, *args, **kwargs):
            opened.append(str(path))
            return connect(path, *args, **kwargs)
        with patch("sqlite3.connect", side_effect=recording_connect):
            latest = manager.create("before-cassette-2")
        self.assertNotIn(str(old), opened)
        self.assertEqual(1, opened.count(str(latest)))
        self.assertFalse(old.exists())
        self.assertEqual(["ok"], integrity_check(latest))

    def test_failed_new_backup_keeps_previous_verified_copy(self):
        manager = BackupManager(self.root / "catalog.db", self.root / "backups", retention=1)
        manager.prepare_and_initialize()
        old = manager.create("before-cassette-1")
        with patch.object(Catalog, "backup_to", side_effect=OSError("disk full")):
            with self.assertRaisesRegex(OSError, "disk full"):
                manager.create("before-cassette-2")
        self.assertEqual({old}, set(manager.backup_directory.glob("*.sqlite3")))
        self.assertEqual(["ok"], integrity_check(old))

    def test_retention_ignores_unknown_files_and_symlink_targets(self):
        manager = BackupManager(self.root / "catalog.db", self.root / "backups")
        manager.prepare_and_initialize()
        old = manager.create("old")
        unrelated = manager.backup_directory / "catalog-latest.db"
        unrelated.write_bytes(b"not owned by ordinary backup retention")
        link = manager.backup_directory / "20200101T000000000000Z-aaaaaaaaaaaa-o-v40-aaaaaaaaaaaaaaaa.sqlite3"
        link.symlink_to(unrelated)
        latest = manager.create("new")
        self.assertFalse(old.exists())
        self.assertTrue(latest.exists())
        self.assertTrue(link.is_symlink())
        self.assertEqual(b"not owned by ordinary backup retention", unrelated.read_bytes())

    def test_failed_integrity_verification_keeps_previous_copy(self):
        manager = BackupManager(self.root / "catalog.db", self.root / "backups")
        manager.prepare_and_initialize()
        old = manager.create("old")
        verify = manager._verify_database
        def reject_new(path):
            if path == old:
                return verify(path)
            raise CatalogError("new backup corrupt")
        with patch.object(manager, "_verify_database", side_effect=reject_new):
            with self.assertRaisesRegex(CatalogError, "new backup corrupt"):
                manager.create("new")
        self.assertEqual({old}, set(manager.backup_directory.glob("*.sqlite3")))
        self.assertEqual(["ok"], integrity_check(old))

    def test_delayed_retention_never_deletes_a_newer_published_backup(self):
        manager = BackupManager(self.root / "catalog.db", self.root / "backups", retention=2)
        manager.prepare_and_initialize()
        older = manager.create("older")
        newest = manager.create("newest")
        manager.retention = 1
        # Deterministic ordering of overlapping create completions: an older
        # writer reaches retention after a newer writer has already published.
        manager._prune(verified_new=older)
        self.assertTrue(newest.exists(), "An older writer discarded the newer backup")
        manager._prune(verified_new=newest)
        self.assertEqual({newest}, set(manager.backup_directory.glob("*.sqlite3")))
        self.assertEqual(["ok"], integrity_check(newest))

    def test_schema_upgrade_creates_protected_backup_before_initialize(self) -> None:
        database_path = make_populated_schema_13_catalog(self.root / "catalog.db")
        before = canonical_row_snapshot(database_path, POPULATED_TABLES)
        manager = BackupManager(database_path, self.root / "backups", retention=5)

        manager.prepare_and_initialize()
        manager.prepare_and_initialize()

        protected = manager.list_backups(protected=True)
        self.assertEqual(
            set(range(13, SCHEMA_VERSION)),
            {record.schema_version for record in protected},
        )
        self.assertTrue(all(record.verified for record in protected))
        schema_thirteen = next(
            record for record in protected if record.schema_version == 13
        )
        schema_fourteen = next(
            record for record in protected if record.schema_version == 14
        )
        self.assertEqual(
            before,
            canonical_row_snapshot(schema_thirteen.path, POPULATED_TABLES),
        )
        self.assertTrue(
            all(integrity_check(record.path) == ["ok"] for record in protected)
        )
        self.assertTrue(
            all(not foreign_key_violations(record.path) for record in protected)
        )
        with closing(sqlite3.connect(schema_fourteen.path)) as backup:
            frozen_recovery_table = backup.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='imported_recovery_lineage_receipts'"
            ).fetchone()
        self.assertIsNone(frozen_recovery_table)
        self.assertEqual(str(SCHEMA_VERSION), read_schema_version(database_path))
        self.assertEqual(["ok"], integrity_check(database_path))
        self.assertEqual([], foreign_key_violations(database_path))
        with closing(sqlite3.connect(database_path)) as db:
            release_table = db.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='table'
                  AND name='hardware_command_release_authorizations'
                """
            ).fetchone()
            release_index = db.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type='index'
                  AND name='hardware_command_release_authorizations_permit_unique'
                """
            ).fetchone()
        self.assertIsNotNone(release_table)
        self.assertIsNotNone(release_index)

    def test_public_schema_fourteen_upgrades_to_current_with_protected_backups(
        self,
    ) -> None:
        database_path = make_public_schema_14_fixture(self.root / "catalog.db")
        manager = BackupManager(database_path, self.root / "backups", retention=5)

        manager.prepare_and_initialize()

        self.assertEqual(str(SCHEMA_VERSION), read_schema_version(database_path))
        protected = manager.list_backups(protected=True)
        self.assertEqual(
            set(range(14, SCHEMA_VERSION)),
            {item.schema_version for item in protected},
        )
        self.assertTrue(all(item.verified for item in protected))
        schema_fourteen = next(item for item in protected if item.schema_version == 14)
        with closing(sqlite3.connect(database_path)) as connection:
            lineage_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(imported_recovery_lineage_receipts)"
                )
            }
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            event_count = connection.execute(
                "SELECT COUNT(*) FROM events WHERE action='schema.fourteen.fixture'"
            ).fetchone()[0]
        self.assertIn("command_observations_json", lineage_columns)
        self.assertIn("imported_cassette_commit_receipts", tables)
        self.assertIn("imported_recovery_resolution_receipts", tables)
        self.assertEqual(1, event_count)
        self.assertEqual(["ok"], integrity_check(database_path))
        self.assertEqual([], foreign_key_violations(database_path))
        with closing(sqlite3.connect(schema_fourteen.path)) as backup:
            legacy_lineage = backup.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='imported_recovery_lineage_receipts'"
            ).fetchone()
        self.assertIsNone(legacy_lineage)

    def test_fresh_catalog_initializes_directly_at_current_schema(self) -> None:
        database_path = self.root / "catalog.db"
        manager = BackupManager(database_path, self.root / "backups", retention=5)

        manager.prepare_and_initialize()
        manager.prepare_and_initialize()

        self.assertEqual(str(SCHEMA_VERSION), read_schema_version(database_path))
        self.assertEqual((), manager.list_backups(protected=True))
        with closing(sqlite3.connect(database_path)) as connection:
            columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(imported_recovery_lineage_receipts)"
                )
            }
        self.assertIn("command_observations_json", columns)
        self.assertEqual(["ok"], integrity_check(database_path))
        self.assertEqual([], foreign_key_violations(database_path))

    def test_schema_fourteen_migration_failure_rolls_back_and_keeps_backup(
        self,
    ) -> None:
        database_path = make_public_schema_14_fixture(self.root / "catalog.db")
        manager = BackupManager(database_path, self.root / "backups", retention=5)

        migrate = Catalog._migrate_v14_to_v15

        def fail_after_transactional_ddl(catalog, db):
            migrate(catalog, db)
            db.execute("CREATE TABLE migration_failure_probe(id INTEGER)")
            raise CatalogError("injected schema 15 failure")

        with (
            patch.object(
                Catalog,
                "_migrate_v14_to_v15",
                autospec=True,
                side_effect=fail_after_transactional_ddl,
            ),
            self.assertRaisesRegex(CatalogError, "injected schema 15 failure"),
        ):
            manager.prepare_and_initialize()

        self.assertEqual("14", read_schema_version(database_path))
        with closing(sqlite3.connect(database_path)) as connection:
            probe = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='migration_failure_probe'"
            ).fetchone()
            event_count = connection.execute(
                "SELECT COUNT(*) FROM events WHERE action='schema.fourteen.fixture'"
            ).fetchone()[0]
        self.assertIsNone(probe)
        self.assertEqual(1, event_count)
        protected = manager.list_backups(protected=True)
        self.assertEqual(1, len(protected))
        self.assertEqual(14, protected[0].schema_version)
        self.assertTrue(protected[0].verified)
        self.assertEqual(["ok"], integrity_check(database_path))
        self.assertEqual([], foreign_key_violations(database_path))

    def test_pruning_keeps_all_protected_and_only_retention_ordinary_backups(
        self,
    ) -> None:
        database_path = self.root / "catalog.db"
        manager = BackupManager(database_path, self.root / "backups", retention=2)
        manager.prepare_and_initialize()
        protected = manager.create("protected-baseline", protected=True)
        for index in range(4):
            manager.create(f"ordinary-{index}")

        records = manager.list_backups()

        self.assertIn(protected, {record.path for record in records})
        self.assertEqual(1, len([record for record in records if record.protected]))
        self.assertEqual(2, len([record for record in records if not record.protected]))

    def test_directory_fsync_failure_keeps_published_backup_and_reports_durability(
        self,
    ) -> None:
        database_path = self.root / "catalog.db"
        manager = BackupManager(database_path, self.root / "backups", retention=2)
        manager.prepare_and_initialize()
        real_fsync = os.fsync

        def fail_directory_fsync(descriptor: int) -> None:
            if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise OSError("injected directory fsync failure")
            real_fsync(descriptor)

        with (
            patch(
                "ltobackup.catalog.os.fsync", side_effect=fail_directory_fsync
            ),
            self.assertRaisesRegex(CatalogError, "published.*durability"),
        ):
            manager.create("durability-boundary")

        published = list((self.root / "backups").glob("*.sqlite3"))
        self.assertEqual(1, len(published))
        self.assertEqual(["ok"], integrity_check(published[0]))
        self.assertEqual(0o600, stat.S_IMODE(published[0].stat().st_mode))


if __name__ == "__main__":
    unittest.main()
