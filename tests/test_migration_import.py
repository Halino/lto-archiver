"""Contract tests for the sanitized frozen-job migration fixture."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest import mock

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.frozen_job import FrozenJobPlan
from ltobackup.linux_settings import LinuxPaths
from ltobackup.migration import importer as importer_module
from ltobackup.migration.archive import (
    canonical_json,
    checksum_lines,
    read_bundle,
    sha256_bytes,
    write_canonical_bundle,
)
from ltobackup.migration.importer import MigrationImporter, PathMappings
from ltobackup.migration.models import MigrationRejected
from ltobackup.migration.validator import (
    MigrationValidator,
    ReadOnlyCatalog,
    canonical_cassette_plan_sha256,
)
from tests.fixtures import build_frozen_job_fixture

_SOURCE_MEMBER_NAMES = (
    "catalog-closed-consistent.db",
    "catalog-closed-source.db",
    "catalog-export.json",
    "config.json",
    "lto-backup.log",
    "ltfs-mount.log",
)


def _assignment_rows(path: Path) -> tuple[tuple[object, ...], ...]:
    with sqlite3.connect(path) as connection:
        return tuple(
            connection.execute(
                """
                SELECT job_id, sequence, item_sequence, library_id,
                       relative_path, size, mtime_ns
                FROM automatic_cassette_items
                WHERE job_id='JOB-MIGRATION'
                ORDER BY sequence, item_sequence
                """
            )
        )


def _preserved_catalog_rows(
    path: Path,
) -> dict[str, tuple[tuple[object, ...], ...]]:
    queries = {
        "automatic_cassettes": (
            "SELECT * FROM automatic_cassettes "
            "WHERE job_id='JOB-MIGRATION' ORDER BY sequence"
        ),
        "automatic_cassette_items": (
            "SELECT job_id,sequence,item_sequence,library_id,relative_path,size,mtime_ns "
            "FROM automatic_cassette_items "
            "WHERE job_id='JOB-MIGRATION' ORDER BY sequence, item_sequence"
        ),
        "blocks": "SELECT * FROM blocks ORDER BY id",
        "tapes": "SELECT * FROM tapes ORDER BY id",
    }
    with sqlite3.connect(path) as connection:
        # Compare historical columns across the additive schema-41 migration.
        # The new nullable source_change_ns is tested by the migration suite.
        columns = [
            row[1] for row in connection.execute("PRAGMA table_info(file_versions)")
            if row[1] != "source_change_ns"
        ]
        queries["file_versions"] = (
            "SELECT " + ",".join(f'"{column}"' for column in columns)
            + " FROM file_versions ORDER BY id"
        )
        return {
            name: tuple(connection.execute(query)) for name, query in queries.items()
        }


def _canonical_bundle_for_catalog(
    database: Path,
    destination: Path,
    *,
    acceptance: object | None = None,
) -> Path:
    if acceptance is None:
        with ReadOnlyCatalog(database) as catalog:
            acceptance = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
        acceptance.require_valid()
    catalog_bytes = database.read_bytes()
    catalog_sha256 = sha256_bytes(catalog_bytes)
    source_hashes = {
        name: hashlib.sha256(f"sanitized:{name}".encode("ascii")).hexdigest()
        for name in _SOURCE_MEMBER_NAMES
    }
    source_hashes["catalog-closed-consistent.db"] = catalog_sha256
    members = {
        "acceptance.json": canonical_json(asdict(acceptance)),
        "catalog.db": catalog_bytes,
        "provenance.json": canonical_json(
            {
                "format_version": 1,
                "source_archive_sha256": hashlib.sha256(
                    b"sanitized-source-archive"
                ).hexdigest(),
                "authoritative_catalog_sha256": catalog_sha256,
                "source_catalog_sha256": source_hashes["catalog-closed-source.db"],
                "source_member_sha256": source_hashes,
                "capture_summary_sha256": hashlib.sha256(
                    b"sanitized-summary"
                ).hexdigest(),
                "capture_checksums_sha256": hashlib.sha256(
                    b"sanitized-checksums"
                ).hexdigest(),
            }
        ),
    }
    members["SHA256SUMS"] = checksum_lines(members)
    return write_canonical_bundle(destination, members)


class MigrationValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.database = self.root / "migration.db"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def inspect(self):
        with ReadOnlyCatalog(self.database) as catalog:
            return MigrationValidator.inspect(catalog, "JOB-MIGRATION")

    def inspect_immutably(self, database: Path | None = None):
        database = database or self.database
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        with ReadOnlyCatalog(database) as catalog:
            report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
        self.assertEqual(before, hashlib.sha256(database.read_bytes()).hexdigest())
        return report

    def test_accepts_three_completed_and_fourth_untouched_for_supported_schemas(
        self,
    ):
        for schema_version in (13, 14, 15):
            with self.subTest(schema_version=schema_version):
                database = self.root / f"schema-{schema_version}.db"
                build_frozen_job_fixture(
                    database, completed=3, total=20, schema_version=schema_version
                )
                with sqlite3.connect(database) as connection:
                    completed_manifest_rows = connection.execute(
                        "SELECT COUNT(*) FROM automatic_cassette_items "
                        "WHERE job_id=? AND sequence<=3",
                        ("JOB-MIGRATION",),
                    ).fetchone()[0]
                self.assertEqual(0, completed_manifest_rows)
                before = hashlib.sha256(database.read_bytes()).hexdigest()
                with ReadOnlyCatalog(database) as catalog:
                    report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                self.assertTrue(report.accepted)
                self.assertEqual(4, report.next_sequence)
                self.assertEqual(20, report.total_cassettes)
                self.assertEqual((1, 2, 3), report.completed_sequences)
                self.assertRegex(report.assignment_sha256, r"^[0-9a-f]{64}$")
                self.assertEqual((), report.media_accesses)
                self.assertEqual(
                    before, hashlib.sha256(database.read_bytes()).hexdigest()
                )

    def test_report_require_valid_raises_machine_readable_rejection(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET status='writing' WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertIn("cassette-4-not-untouched", report.error_codes)
        with self.assertRaisesRegex(MigrationRejected, "cassette-4-not-untouched"):
            report.require_valid()

    def test_rejects_completed_count_other_than_exactly_three(self):
        for completed in (2, 4):
            with self.subTest(completed=completed):
                database = self.root / f"completed-{completed}.db"
                build_frozen_job_fixture(
                    database, completed=completed, total=20, schema_version=13
                )
                with ReadOnlyCatalog(database) as catalog:
                    report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
                self.assertFalse(report.accepted)
                self.assertIn("completed-cassettes-invalid", report.error_codes)

    def test_rejects_non_waiting_job_and_provisional_blocks(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_jobs SET status='writing' WHERE id=?",
                ("JOB-MIGRATION",),
            )
            connection.execute(
                "UPDATE automatic_cassettes SET block_id='BLOCK-PROVISIONAL' WHERE job_id=? AND sequence=5",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertIn("job-not-waiting", report.error_codes)
        self.assertIn("provisional-block", report.error_codes)

    def test_rejects_real_provisional_block_and_file_version_records(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE blocks SET status='copying', completed_at=NULL WHERE id='BLOCK01'"
            )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("provisional-block-record", report.error_codes)
        self.assertIn("provisional-file-version-record", report.error_codes)

    def test_rejects_completed_cassette_with_inconsistent_block_manifest_totals_and_times(
        self,
    ):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET copied_bytes=999, completed_at=NULL "
                "WHERE job_id=? AND sequence=1",
                ("JOB-MIGRATION",),
            )
            connection.execute(
                "UPDATE blocks SET planned_bytes=999, completed_at=NULL WHERE id='BLOCK01'"
            )
            connection.execute(
                "UPDATE file_versions SET tape_relative_path='not-the-manifest' "
                "WHERE block_id='BLOCK01'"
            )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("completed-cassette-block-invalid", report.error_codes)
        self.assertIn("completed-cassette-total-invalid", report.error_codes)
        self.assertIn("completed-cassette-timestamp-invalid", report.error_codes)
        self.assertIn("completed-cassette-manifest-invalid", report.error_codes)

    def test_rejects_completed_file_version_not_exactly_matching_snapshot_manifest(
        self,
    ):
        mutations = (
            ("tape_relative_path", "archive/cassette-1/other.bin"),
            ("relative_path", "cassette-1/other.bin"),
            ("size", 99),
            ("sha256", "A" * 64),
            ("sha256", "g" * 64),
            ("sha256", "0" * 63),
        )
        for index, (column, value) in enumerate(mutations):
            with self.subTest(column=column, value=value):
                database = self.root / f"completed-{column}-{index}.db"
                build_frozen_job_fixture(
                    database, completed=3, total=20, schema_version=14
                )
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        f"UPDATE file_versions SET {column}=? WHERE block_id='BLOCK01'",
                        (value,),
                    )
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn("completed-cassette-manifest-invalid", report.error_codes)

        library_database = self.root / "completed-library.db"
        build_frozen_job_fixture(
            library_database, completed=3, total=20, schema_version=14
        )
        secondary_source = self.root / "secondary-source"
        secondary_source.mkdir()
        with Catalog(library_database) as catalog:
            catalog.add_library("LIB2", "Secondary library", str(secondary_source))
        with sqlite3.connect(library_database) as connection:
            connection.execute(
                "UPDATE file_versions SET library_id='LIB2' WHERE block_id='BLOCK01'"
            )
        report = self.inspect_immutably(library_database)
        self.assertFalse(report.accepted)
        self.assertIn("completed-cassette-manifest-invalid", report.error_codes)

    def test_accepts_completed_cassettes_with_multiple_catalog_blocks(self):
        build_frozen_job_fixture(
            self.database,
            completed=3,
            total=20,
            schema_version=13,
            blocks_per_cassette=2,
            library_ids=("LIB1", "LIB2"),
        )
        with sqlite3.connect(self.database) as connection:
            completed_rows = connection.execute(
                "SELECT block_id FROM automatic_cassettes "
                "WHERE job_id=? AND sequence<=3 ORDER BY sequence",
                ("JOB-MIGRATION",),
            ).fetchall()
            completed_manifest_count = connection.execute(
                "SELECT COUNT(*) FROM automatic_cassette_items "
                "WHERE job_id=? AND sequence<=3",
                ("JOB-MIGRATION",),
            ).fetchone()[0]
        self.assertTrue(all("," in row[0] for row in completed_rows))
        self.assertEqual(0, completed_manifest_count)
        report = self.inspect_immutably()
        self.assertTrue(report.accepted, report.error_codes)

    def test_rejects_pending_or_completed_library_outside_job_assignment(self):
        for scope in ("pending", "completed", "completed-type"):
            with self.subTest(scope=scope):
                database = self.root / f"unassigned-{scope}.db"
                build_frozen_job_fixture(database, schema_version=13)
                secondary_source = self.root / f"unassigned-source-{scope}"
                secondary_source.mkdir()
                with Catalog(database) as catalog:
                    catalog.add_library(
                        "LIB2", "Unassigned library", str(secondary_source)
                    )
                with sqlite3.connect(database) as connection:
                    if scope == "pending":
                        connection.execute(
                            "UPDATE automatic_cassette_items SET library_id='LIB2' "
                            "WHERE job_id=? AND sequence=4 AND item_sequence=1",
                            ("JOB-MIGRATION",),
                        )
                    elif scope == "completed":
                        connection.execute(
                            "UPDATE blocks SET library_id='LIB2' WHERE id='BLOCK01'"
                        )
                        connection.execute(
                            "UPDATE file_versions SET library_id='LIB2' "
                            "WHERE block_id='BLOCK01'"
                        )
                    else:
                        connection.execute(
                            "UPDATE blocks SET library_id=x'00ff' WHERE id='BLOCK01'"
                        )
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn("job-library-assignment-invalid", report.error_codes)

    def test_rejects_missing_malformed_null_or_duplicate_job_library_assignments(self):
        mutations = ("missing", "bad-sequence", "null-library", "duplicate-library")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                database = self.root / f"job-library-{mutation}.db"
                build_frozen_job_fixture(database, schema_version=13)
                with sqlite3.connect(database) as connection:
                    if mutation == "missing":
                        connection.execute(
                            "DELETE FROM automatic_job_libraries WHERE job_id=?",
                            ("JOB-MIGRATION",),
                        )
                    elif mutation == "bad-sequence":
                        connection.execute(
                            "UPDATE automatic_job_libraries SET sequence='bad' "
                            "WHERE job_id=?",
                            ("JOB-MIGRATION",),
                        )
                    elif mutation == "duplicate-library":
                        connection.execute(
                            "INSERT INTO automatic_job_libraries(job_id, library_id, sequence) "
                            "VALUES(?, ?, ?)",
                            ("JOB-MIGRATION", "lib1", 2),
                        )
                    else:
                        connection.execute(
                            "ALTER TABLE automatic_job_libraries "
                            "RENAME TO automatic_job_libraries_strict"
                        )
                        connection.execute(
                            "CREATE TABLE automatic_job_libraries"
                            "(job_id, library_id, sequence)"
                        )
                        connection.execute(
                            "INSERT INTO automatic_job_libraries VALUES(?, NULL, 1)",
                            ("JOB-MIGRATION",),
                        )
                        connection.execute("DROP TABLE automatic_job_libraries_strict")
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn("job-library-assignment-invalid", report.error_codes)

    def test_rejects_completed_block_or_tape_reused_by_another_cassette(self):
        tape_database = self.root / "reused-tape.db"
        build_frozen_job_fixture(tape_database, schema_version=13)
        with sqlite3.connect(tape_database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET tape_id='TAPE01' "
                "WHERE job_id=? AND sequence=2",
                ("JOB-MIGRATION",),
            )
            connection.execute("UPDATE blocks SET tape_id='TAPE01' WHERE id='BLOCK02'")
            connection.execute(
                "UPDATE file_versions SET tape_id='TAPE01' WHERE block_id='BLOCK02'"
            )
        report = self.inspect_immutably(tape_database)
        self.assertFalse(report.accepted)
        self.assertIn("completed-tape-reused", report.error_codes)

        block_database = self.root / "reused-block.db"
        build_frozen_job_fixture(block_database, schema_version=13)
        with sqlite3.connect(block_database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET block_id='BLOCK01', "
                "planned_files=1, planned_bytes=1, copied_files=1, copied_bytes=1 "
                "WHERE job_id=? AND sequence=2",
                ("JOB-MIGRATION",),
            )
        report = self.inspect_immutably(block_database)
        self.assertFalse(report.accepted)
        self.assertIn("completed-block-reused", report.error_codes)

    def test_rejects_completed_tape_not_bound_to_physical_label(self):
        build_frozen_job_fixture(self.database, schema_version=13)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE tapes SET cassette_number='OTHER-LABEL' WHERE id='TAPE01'"
            )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("completed-media-identity-invalid", report.error_codes)

    def test_accepts_case_equivalent_tape_ids_using_catalog_collation(self):
        build_frozen_job_fixture(self.database, schema_version=13)
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE blocks SET tape_id=lower(tape_id) WHERE id='BLOCK01'"
            )
            connection.execute(
                "UPDATE file_versions SET tape_id=lower(tape_id) "
                "WHERE block_id='BLOCK01'"
            )
        report = self.inspect_immutably()
        self.assertTrue(report.accepted, report.error_codes)

    def test_rejects_blank_or_case_duplicate_cassette_identity_fields(self):
        mutations = (
            (1, "physical_label", ""),
            (1, "tape_serial", ""),
            (2, "tape_serial", "serial01"),
        )
        for sequence, column, value in mutations:
            with self.subTest(column=column, value=value):
                database = self.root / f"cassette-identity-{column}-{sequence}.db"
                build_frozen_job_fixture(database, schema_version=13)
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        f"UPDATE automatic_cassettes SET {column}=? "
                        "WHERE job_id=? AND sequence=?",
                        (value, "JOB-MIGRATION", sequence),
                    )
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn("cassette-identity-invalid", report.error_codes)

    def test_accepts_fourth_waiting_for_media_without_write_progress(self):
        build_frozen_job_fixture(
            self.database,
            completed=3,
            total=20,
            schema_version=13,
            fourth_status="waiting_media",
        )
        report = self.inspect_immutably()
        self.assertTrue(report.accepted, report.error_codes)
        self.assertEqual(4, report.next_sequence)

    def test_accepts_empty_future_reserved_cassette(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM automatic_cassette_items WHERE job_id=? AND sequence=20",
                ("JOB-MIGRATION",),
            )
            connection.execute(
                "UPDATE automatic_cassettes SET planned_files=0, planned_bytes=0 "
                "WHERE job_id=? AND sequence=20",
                ("JOB-MIGRATION",),
            )
        report = self.inspect_immutably()
        self.assertTrue(report.accepted, report.error_codes)

    def test_rejects_completed_block_library_and_counters_not_bound_to_catalog_files(
        self,
    ):
        mutations = (
            ("library_id", "LIB2"),
            ("copied_files", 0),
            ("copied_bytes", 0),
        )
        for column, value in mutations:
            with self.subTest(column=column):
                database = self.root / f"completed-block-{column}.db"
                build_frozen_job_fixture(
                    database, completed=3, total=20, schema_version=14
                )
                if column == "library_id":
                    secondary_source = self.root / "secondary-block-source"
                    secondary_source.mkdir(exist_ok=True)
                    with Catalog(database) as catalog:
                        catalog.add_library(
                            "LIB2", "Secondary library", str(secondary_source)
                        )
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        f"UPDATE blocks SET {column}=? WHERE id='BLOCK01'",
                        (value,),
                    )
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn("completed-cassette-block-invalid", report.error_codes)

    def test_rejects_embedded_nul_in_each_catalog_relative_path(self):
        mutations = (
            (
                "manifest",
                (
                    "UPDATE automatic_cassette_items SET relative_path=? "
                    "WHERE job_id='JOB-MIGRATION' AND sequence=4 AND item_sequence=1"
                ),
                "cassette-4/file\x00.bin",
                "manifest-path-invalid",
            ),
            (
                "block-root",
                "UPDATE blocks SET tape_relative_root=? WHERE id='BLOCK01'",
                "archive\x00",
                "completed-cassette-manifest-invalid",
            ),
            (
                "file-relative",
                "UPDATE file_versions SET relative_path=? WHERE block_id='BLOCK01'",
                "cassette-1/file\x00.bin",
                "completed-cassette-manifest-invalid",
            ),
            (
                "file-tape-relative",
                "UPDATE file_versions SET tape_relative_path=? WHERE block_id='BLOCK01'",
                "archive/cassette-1/file\x00.bin",
                "completed-cassette-manifest-invalid",
            ),
        )
        for name, statement, value, error_code in mutations:
            with self.subTest(path=name):
                database = self.root / f"nul-{name}.db"
                build_frozen_job_fixture(
                    database, completed=3, total=20, schema_version=14
                )
                with sqlite3.connect(database) as connection:
                    connection.execute(statement, (value,))
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn(error_code, report.error_codes)

    def test_allows_unrelated_provisional_block_and_file_version(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        secondary_source = self.root / "secondary-source"
        secondary_source.mkdir()
        with Catalog(self.database) as catalog:
            catalog.add_library("LIB2", "Secondary library", str(secondary_source))
            catalog.register_tape(
                "OTHER-TAPE", "OTHER-SERIAL", "OTHER-TAPE", "LTFS", "/synthetic/mount"
            )
            catalog.create_block("OTHER-BLOCK", "LIB2", "OTHER-TAPE", "archive", 1, 1)
            catalog.record_file_version(
                "LIB2",
                "OTHER-BLOCK",
                "OTHER-TAPE",
                "other.bin",
                "archive/other.bin",
                1,
                1,
                "0" * 64,
            )
        report = self.inspect_immutably()
        self.assertTrue(report.accepted)

    def test_rejects_current_sequence_other_than_four(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_jobs SET current_sequence=5 WHERE id=?",
                ("JOB-MIGRATION",),
            )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("current-sequence-invalid", report.error_codes)

    def test_rejects_nonpristine_future_cassette_progress_and_identity(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET tape_id='STALE-TAPE', copied_files=1, "
                "copied_bytes=5, started_at='2026-08-21T00:00:00Z', error='stale' "
                "WHERE job_id=? AND sequence=5",
                ("JOB-MIGRATION",),
            )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("cassette-not-pristine", report.error_codes)

    def test_rejects_missing_future_cassette_before_twenty(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=19, schema_version=14
        )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("cassette-count-invalid", report.error_codes)

    def test_rejects_noncontiguous_manifest_item_sequence(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassette_items SET item_sequence=2 "
                "WHERE job_id=? AND sequence=4 AND item_sequence=1",
                ("JOB-MIGRATION",),
            )
        report = self.inspect_immutably()
        self.assertFalse(report.accepted)
        self.assertIn("manifest-sequence-invalid", report.error_codes)

    def test_rejects_unsafe_paths_and_noninteger_manifest_values(self):
        path_cases = (
            ".",
            "/absolute",
            "C:drive-relative",
            r"\\\\server\\share",
            "../escape",
        )
        for index, unsafe_path in enumerate(path_cases):
            with self.subTest(path=unsafe_path):
                database = self.root / f"path-{index}.db"
                build_frozen_job_fixture(
                    database, completed=3, total=20, schema_version=14
                )
                with sqlite3.connect(database) as connection:
                    connection.execute(
                        "UPDATE automatic_cassette_items SET relative_path=? "
                        "WHERE job_id=? AND sequence=4 AND item_sequence=1",
                        (unsafe_path, "JOB-MIGRATION"),
                    )
                report = self.inspect_immutably(database)
                self.assertFalse(report.accepted)
                self.assertIn("manifest-path-invalid", report.error_codes)

        numeric_database = self.root / "fractional-size.db"
        build_frozen_job_fixture(
            numeric_database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(numeric_database) as connection:
            connection.execute(
                "UPDATE automatic_cassette_items SET size=1.5 "
                "WHERE job_id=? AND sequence=4 AND item_sequence=1",
                ("JOB-MIGRATION",),
            )
        report = self.inspect_immutably(numeric_database)
        self.assertFalse(report.accepted)
        self.assertIn("manifest-value-invalid", report.error_codes)

    def test_rejects_missing_or_mismatched_manifest(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM automatic_cassette_items WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertIn("manifest-missing", report.error_codes)

        mismatch = self.root / "mismatch.db"
        build_frozen_job_fixture(mismatch, completed=3, total=20, schema_version=13)
        with sqlite3.connect(mismatch) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET planned_bytes=999 WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        with ReadOnlyCatalog(mismatch) as catalog:
            report = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
        self.assertIn("manifest-bytes-mismatch", report.error_codes)

    def test_rejects_malformed_manifest_values_without_crashing_hash_calculation(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassette_items SET mtime_ns='not-a-number' WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertFalse(report.accepted)
        self.assertIn("manifest-value-invalid", report.error_codes)

    def test_rejects_malformed_cassette_plan_values_without_crashing(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET planned_bytes='not-a-number' WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertFalse(report.accepted)
        self.assertIn("cassette-value-invalid", report.error_codes)

    def test_rejects_binary_manifest_values_without_crashing_hash_calculation(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_cassette_items SET size=x'00ff' WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertFalse(report.accepted)
        self.assertIn("manifest-value-invalid", report.error_codes)

    def test_rejects_sequence_gap_and_invalid_relative_path(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "DELETE FROM automatic_cassettes WHERE job_id=? AND sequence=7",
                ("JOB-MIGRATION",),
            )
            connection.execute(
                "UPDATE automatic_cassette_items SET relative_path='../escape' WHERE job_id=? AND sequence=4 AND item_sequence=1",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertIn("cassette-sequence-gap", report.error_codes)
        self.assertIn("manifest-path-invalid", report.error_codes)

    def test_fixture_schema_rejects_duplicate_assignment_before_validation(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=14
        )
        with (
            sqlite3.connect(self.database) as connection,
            self.assertRaises(sqlite3.IntegrityError),
        ):
            connection.execute(
                "INSERT INTO automatic_cassette_items(job_id, sequence, item_sequence, library_id, relative_path, size, mtime_ns) VALUES(?, ?, ?, ?, ?, ?, ?)",
                ("JOB-MIGRATION", 5, 99, "LIB1", "cassette-5/file-1.bin", 0, 1),
            )

    def test_rejects_total_schema_and_foreign_key_tampering_fail_closed(self):
        build_frozen_job_fixture(
            self.database, completed=3, total=20, schema_version=13
        )
        with sqlite3.connect(self.database) as connection:
            connection.execute(
                "UPDATE automatic_jobs SET total_cassettes=19 WHERE id=?",
                ("JOB-MIGRATION",),
            )
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='schema_version'",
                (str(SCHEMA_VERSION + 1),),
            )
            connection.execute("PRAGMA foreign_keys=OFF")
            connection.execute(
                "UPDATE automatic_cassette_items SET library_id='MISSING' WHERE job_id=? AND sequence=4",
                ("JOB-MIGRATION",),
            )
        report = self.inspect()
        self.assertIn("schema-unsupported", report.error_codes)
        self.assertIn("cassette-count-mismatch", report.error_codes)
        self.assertIn("catalog-foreign-key-failed", report.error_codes)


class MigrationImporterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.windows_catalog = build_frozen_job_fixture(
            self.root / "windows.db", schema_version=14
        )
        self.bundle_path = _canonical_bundle_for_catalog(
            self.windows_catalog, self.root / "migration.bundle.zip"
        )
        self.paths = LinuxPaths.for_root(
            self.root / "linux-state", self.root / "run" / "daemon.sock"
        )
        self.target_source = self.root / "linux-source"
        self.target_source.mkdir()
        self.mappings = PathMappings(
            library_roots={
                str(self.root / "source-lib1"): self.target_source,
            },
            device_names={
                "synthetic-drive": "/dev/tape/by-id/synthetic-drive",
            },
            mount_paths={
                "/synthetic/mount": "/mnt/lto-archiver/tape",
            },
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_import_remaps_only_platform_paths_and_preserves_assignments(self) -> None:
        before_assignments = _assignment_rows(self.windows_catalog)
        before_rows = _preserved_catalog_rows(self.windows_catalog)
        before_bundle = hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()

        report = MigrationImporter().import_bundle(
            self.bundle_path, self.paths, self.mappings
        )

        self.assertEqual(before_assignments, _assignment_rows(self.paths.catalog_file))
        self.assertEqual(before_rows, _preserved_catalog_rows(self.paths.catalog_file))
        self.assertEqual(4, report.next_sequence)
        self.assertEqual((), report.media_accesses)
        self.assertEqual(
            before_bundle, hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()
        )
        with Catalog(self.paths.catalog_file) as catalog:
            library = catalog.connection.execute(
                "SELECT source_root FROM libraries WHERE id='LIB1'"
            ).fetchone()
            job = catalog.get_automatic_job("JOB-MIGRATION")
            tape_mounts = {
                row[0]
                for row in catalog.connection.execute(
                    "SELECT DISTINCT mount_hint FROM tapes"
                )
            }
            policy = catalog.get_import_policy("JOB-MIGRATION")
            receipt = catalog.connection.execute(
                """
                SELECT bundle_sha256, assignment_sha256, cassette_plan_sha256
                FROM migration_receipts WHERE job_id='JOB-MIGRATION'
                """
            ).fetchone()
            cassette_plan = canonical_cassette_plan_sha256(
                catalog.connection,
                "JOB-MIGRATION",
                assignment_sha256=report.assignment_sha256,
            )
        self.assertEqual(str(self.target_source), library[0])
        self.assertEqual("/dev/tape/by-id/synthetic-drive", job["device_name"])
        self.assertEqual("/mnt/lto-archiver/tape", job["mount_path"])
        self.assertEqual({"/synthetic/mount"}, tape_mounts)
        self.assertIsNotNone(policy)
        self.assertEqual("frozen-allocation", policy.policy_kind)
        self.assertEqual("pre_cutover", policy.authority_state)
        self.assertEqual("resumable", policy.windows_authority)
        self.assertTrue(policy.rollback_allowed)
        self.assertEqual(cassette_plan, policy.cassette_plan_sha256)
        self.assertIsNone(policy.activated_by_operation)
        self.assertIsNone(policy.activated_at)
        self.assertEqual(
            (before_bundle, report.assignment_sha256, cassette_plan), tuple(receipt)
        )
        self.assertEqual(SCHEMA_VERSION, _schema_version(self.paths.catalog_file))
        protected = BackupManager(
            self.paths.catalog_file, self.paths.backup_dir, retention=5
        ).list_backups(protected=True)
        self.assertEqual(
            set(range(14, SCHEMA_VERSION + 1)),
            {record.schema_version for record in protected},
        )
        self.assertTrue(all(record.verified for record in protected))
        self.assertEqual(0o600, stat.S_IMODE(self.paths.catalog_file.stat().st_mode))
        self.assertTrue(
            all(
                stat.S_IMODE(record.path.stat().st_mode) == 0o600
                for record in protected
            )
        )

    def test_import_clears_legacy_reuse_only_from_untouched_format_cassettes(
        self,
    ) -> None:
        database = build_frozen_job_fixture(
            self.root / "legacy-reuse.db", schema_version=14
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET reuse_registered=1 "
                "WHERE job_id='JOB-MIGRATION'"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        bundle = _canonical_bundle_for_catalog(
            database, self.root / "legacy-reuse.bundle.zip"
        )

        MigrationImporter().import_bundle(bundle, self.paths, self.mappings)

        with ReadOnlyCatalog(self.paths.catalog_file) as catalog:
            imported = tuple(
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT sequence, status, reuse_registered "
                    "FROM automatic_cassettes WHERE job_id='JOB-MIGRATION' "
                    "ORDER BY sequence"
                )
            )
        with sqlite3.connect(database) as source:
            source_reuse = tuple(
                source.execute(
                    "SELECT reuse_registered FROM automatic_cassettes "
                    "WHERE job_id='JOB-MIGRATION' ORDER BY sequence"
                )
            )

        self.assertEqual(
            ((1, "completed", 1), (2, "completed", 1), (3, "completed", 1)),
            imported[:3],
        )
        self.assertEqual(
            tuple((sequence, "pending", 0) for sequence in range(4, 21)),
            imported[3:],
        )
        self.assertEqual(tuple((1,) for _ in range(20)), source_reuse)
        with ReadOnlyCatalog(self.paths.catalog_file) as catalog:
            plan = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
        self.assertEqual(
            tuple(range(1, 21)), tuple(row.sequence for row in plan.cassettes)
        )

    def test_import_canonicalizes_waiting_format_cassette_as_untouched(
        self,
    ) -> None:
        database = build_frozen_job_fixture(
            self.root / "legacy-waiting.db",
            schema_version=14,
            fourth_status="waiting_media",
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE automatic_cassettes SET reuse_registered=1 "
                "WHERE job_id='JOB-MIGRATION' AND sequence>=4"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        bundle = _canonical_bundle_for_catalog(
            database, self.root / "legacy-waiting.bundle.zip"
        )

        MigrationImporter().import_bundle(bundle, self.paths, self.mappings)

        with ReadOnlyCatalog(self.paths.catalog_file) as catalog:
            fourth = tuple(
                catalog.connection.execute(
                    "SELECT status, started_at, reuse_registered "
                    "FROM automatic_cassettes WHERE job_id='JOB-MIGRATION' "
                    "AND sequence=4"
                ).fetchone()
            )
        self.assertEqual(("waiting_media", None, 0), fourth)
        with ReadOnlyCatalog(self.paths.catalog_file) as catalog:
            plan = FrozenJobPlan.load(catalog, "JOB-MIGRATION")
        self.assertEqual("waiting_media", plan.cassettes[3].status)

    def test_acceptance_receipt_is_copublished_and_catalog_bound(self) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )

        report = MigrationImporter().import_bundle(
            self.bundle_path,
            self.paths,
            self.mappings,
            acceptance_receipt=receipt,
        )

        receipt_path = self.paths.migration_dir / "windows-import-acceptance.json"
        self.assertEqual(receipt, receipt_path.read_bytes())
        self.assertEqual(0o600, stat.S_IMODE(receipt_path.stat().st_mode))
        payload = json.loads(receipt)
        self.assertEqual(report.assignment_sha256, payload["assignment_sha256"])
        self.assertEqual(
            hashlib.sha256(report.job_id.encode("utf-8")).hexdigest(),
            payload["job_id_sha256"],
        )
        self.assertEqual("frozen-allocation", payload["policy_kind"])
        self.assertEqual("pre_cutover", payload["authority_state"])
        self.assertEqual("resumable", payload["windows_authority"])
        self.assertTrue(payload["rollback_allowed"])
        with sqlite3.connect(self.paths.catalog_file) as connection:
            catalog_receipt = connection.execute(
                "SELECT bundle_sha256, assignment_sha256 FROM migration_receipts "
                "WHERE job_id=?",
                (report.job_id,),
            ).fetchone()
            policy = connection.execute(
                "SELECT policy_kind, authority_state, windows_authority, "
                "rollback_allowed FROM imported_job_policies WHERE job_id=?",
                (report.job_id,),
            ).fetchone()
        self.assertEqual(
            (payload["bundle_sha256"], payload["assignment_sha256"]),
            tuple(catalog_receipt),
        )
        self.assertEqual(
            (
                payload["policy_kind"],
                payload["authority_state"],
                payload["windows_authority"],
                int(payload["rollback_allowed"]),
            ),
            tuple(policy),
        )

    def test_acceptance_receipt_failure_leaves_target_absent_and_retry_succeeds(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        with (
            mock.patch.object(
                importer_module,
                "_write_acceptance_receipt",
                side_effect=OSError("injected receipt failure"),
                create=True,
            ),
            self.assertRaises(OSError),
        ):
            MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )

        self.assertFalse(self.paths.state_dir.exists())
        report = MigrationImporter().import_bundle(
            self.bundle_path,
            self.paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        self.assertEqual(4, report.next_sequence)
        self.assertEqual(
            receipt,
            (self.paths.migration_dir / "windows-import-acceptance.json").read_bytes(),
        )

    def test_post_rename_parent_sync_failure_reports_matching_published_state(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        with mock.patch.object(
            importer_module,
            "_sync_published_parent",
            side_effect=OSError("injected final parent sync failure"),
            create=True,
        ) as sync_parent:
            report = MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )

        sync_parent.assert_called_once()
        self.assertEqual(4, report.next_sequence)
        self.assertEqual(
            receipt,
            (self.paths.migration_dir / "windows-import-acceptance.json").read_bytes(),
        )

    def test_idempotent_retry_rejects_final_state_directory_identity_swap(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        MigrationImporter().import_bundle(
            self.bundle_path,
            self.paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        moved = self.root / "moved-valid-state"
        attacker = self.root / "attacker-state"
        attacker.mkdir()
        marker = attacker / "preserve"
        marker.write_text("attacker-owned", encoding="utf-8")
        original = importer_module._require_receipt_catalog_binding
        swapped = False

        def swap_after_catalog_check(*args, **kwargs):
            nonlocal swapped
            result = original(*args, **kwargs)
            if not swapped:
                swapped = True
                os.rename(self.paths.state_dir, moved)
                os.rename(attacker, self.paths.state_dir)
            return result

        try:
            with (
                mock.patch.object(
                    importer_module,
                    "_require_receipt_catalog_binding",
                    side_effect=swap_after_catalog_check,
                ),
                self.assertRaisesRegex(MigrationRejected, "state-not-empty"),
            ):
                MigrationImporter().import_bundle(
                    self.bundle_path,
                    self.paths,
                    self.mappings,
                    acceptance_receipt=receipt,
                )
        finally:
            if self.paths.state_dir.exists():
                os.rename(self.paths.state_dir, attacker)
            if moved.exists():
                os.rename(moved, self.paths.state_dir)

        self.assertEqual("attacker-owned", marker.read_text(encoding="utf-8"))

    def test_idempotent_retry_rejects_tampered_protected_backup(self) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        MigrationImporter().import_bundle(
            self.bundle_path,
            self.paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        backup = next(self.paths.backup_dir.iterdir())
        backup.write_bytes(b"not a verified sqlite backup")
        backup.chmod(0o600)

        with self.assertRaisesRegex(MigrationRejected, "state-not-empty"):
            MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )

    def test_idempotent_retry_rejects_catalog_path_mapping_tamper(self) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        MigrationImporter().import_bundle(
            self.bundle_path,
            self.paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        other_source = self.root / "other-source"
        other_source.mkdir()
        with sqlite3.connect(self.paths.catalog_file) as connection:
            connection.execute(
                "UPDATE libraries SET source_root=? WHERE id='LIB1'",
                (str(other_source),),
            )

        with self.assertRaisesRegex(MigrationRejected, "state-not-empty"):
            MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )

    def test_receipt_low_level_failures_leave_target_absent_and_retry_succeeds(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        real_mkdir = os.mkdir
        real_open = os.open
        real_close = os.close
        real_fsync = os.fsync

        def failing_mkdir(path, *args, **kwargs):
            if path == "migrations":
                raise OSError("injected receipt mkdir failure")
            return real_mkdir(path, *args, **kwargs)

        def failing_open(path, *args, **kwargs):
            if path == "windows-import-acceptance.json":
                raise OSError("injected receipt open failure")
            return real_open(path, *args, **kwargs)

        def failing_receipt_fsync(descriptor: int):
            target = os.readlink(f"/proc/self/fd/{descriptor}")
            if target.endswith("/windows-import-acceptance.json"):
                raise OSError("injected receipt fsync failure")
            return real_fsync(descriptor)

        cases = (
            ("mkdir", mock.patch.object(importer_module.os, "mkdir", failing_mkdir)),
            ("open", mock.patch.object(importer_module.os, "open", failing_open)),
            ("write", mock.patch.object(importer_module.os, "write", return_value=0)),
            (
                "fsync",
                mock.patch.object(
                    importer_module.os,
                    "fsync",
                    side_effect=failing_receipt_fsync,
                ),
            ),
        )
        for name, failure in cases:
            with self.subTest(name=name):
                paths = LinuxPaths.for_root(
                    self.root / f"receipt-{name}-state",
                    self.root / "run" / f"receipt-{name}.sock",
                )
                with failure, self.assertRaises(OSError):
                    MigrationImporter().import_bundle(
                        self.bundle_path,
                        paths,
                        self.mappings,
                        acceptance_receipt=receipt,
                    )
                self.assertFalse(paths.state_dir.exists())
                report = MigrationImporter().import_bundle(
                    self.bundle_path,
                    paths,
                    self.mappings,
                    acceptance_receipt=receipt,
                )
                self.assertEqual(4, report.next_sequence)

        close_paths = LinuxPaths.for_root(
            self.root / "receipt-close-state",
            self.root / "run" / "receipt-close.sock",
        )
        receipt_descriptor: int | None = None

        def capture_open(path, *args, **kwargs):
            nonlocal receipt_descriptor
            descriptor = real_open(path, *args, **kwargs)
            if path == "windows-import-acceptance.json":
                receipt_descriptor = descriptor
            return descriptor

        def failing_close(descriptor: int):
            nonlocal receipt_descriptor
            if descriptor == receipt_descriptor:
                receipt_descriptor = None
                real_close(descriptor)
                raise OSError("injected receipt close failure")
            return real_close(descriptor)

        with (
            mock.patch.object(importer_module.os, "open", side_effect=capture_open),
            mock.patch.object(importer_module.os, "close", side_effect=failing_close),
            self.assertRaises(OSError),
        ):
            MigrationImporter().import_bundle(
                self.bundle_path,
                close_paths,
                self.mappings,
                acceptance_receipt=receipt,
            )
        self.assertFalse(close_paths.state_dir.exists())
        report = MigrationImporter().import_bundle(
            self.bundle_path,
            close_paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        self.assertEqual(4, report.next_sequence)

    def test_receipt_write_handles_eintr_and_short_progress_before_publish(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        real_write = os.write
        calls = 0

        def interrupted_then_short(descriptor: int, payload) -> int:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise InterruptedError
            return real_write(descriptor, payload[:7])

        with mock.patch.object(
            importer_module.os,
            "write",
            side_effect=interrupted_then_short,
        ):
            report = MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )

        self.assertEqual(4, report.next_sequence)
        self.assertGreater(calls, 2)
        self.assertEqual(
            receipt,
            (self.paths.migration_dir / "windows-import-acceptance.json").read_bytes(),
        )

    def test_staged_receipt_tampering_is_rejected_before_publish_and_retry_succeeds(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        original = importer_module._write_acceptance_receipt

        def tamper(stage_fd: int, payload: bytes) -> None:
            original(stage_fd, payload)
            path = (
                Path(f"/proc/self/fd/{stage_fd}")
                / "migrations"
                / "windows-import-acceptance.json"
            )
            changed = bytearray(payload)
            changed[0] = ord("[")
            path.write_bytes(changed)

        with (
            mock.patch.object(
                importer_module,
                "_write_acceptance_receipt",
                side_effect=tamper,
            ),
            self.assertRaisesRegex(MigrationRejected, "acceptance-receipt-changed"),
        ):
            MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )
        self.assertFalse(self.paths.state_dir.exists())
        report = MigrationImporter().import_bundle(
            self.bundle_path,
            self.paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        self.assertEqual(4, report.next_sequence)

    def test_descriptor_close_error_after_complete_publish_does_not_report_failure(
        self,
    ) -> None:
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )
        real_sync = importer_module._sync_published_parent
        real_close = os.close
        published_stage_fd: int | None = None

        def capture_stage(staging) -> None:
            nonlocal published_stage_fd
            published_stage_fd = staging.stage_fd
            real_sync(staging)

        def fail_published_stage_close(descriptor: int) -> None:
            nonlocal published_stage_fd
            if descriptor == published_stage_fd:
                published_stage_fd = None
                real_close(descriptor)
                raise OSError("injected post-publish close failure")
            real_close(descriptor)

        with (
            mock.patch.object(
                importer_module,
                "_sync_published_parent",
                side_effect=capture_stage,
            ),
            mock.patch.object(
                importer_module.os,
                "close",
                side_effect=fail_published_stage_close,
            ),
        ):
            report = MigrationImporter().import_bundle(
                self.bundle_path,
                self.paths,
                self.mappings,
                acceptance_receipt=receipt,
            )

        self.assertEqual(4, report.next_sequence)
        self.assertEqual(
            receipt,
            (self.paths.migration_dir / "windows-import-acceptance.json").read_bytes(),
        )

    def test_schema_thirteen_retains_protected_pre_migration_and_import_backups(
        self,
    ) -> None:
        database = build_frozen_job_fixture(
            self.root / "schema-13.db", schema_version=13
        )
        bundle = _canonical_bundle_for_catalog(
            database, self.root / "schema-13.bundle.zip"
        )
        paths = LinuxPaths.for_root(
            self.root / "schema-13-state", self.root / "run" / "schema-13.sock"
        )
        before_rows = _preserved_catalog_rows(database)

        report = MigrationImporter().import_bundle(bundle, paths, self.mappings)

        self.assertEqual(4, report.next_sequence)
        self.assertEqual(before_rows, _preserved_catalog_rows(paths.catalog_file))
        protected = BackupManager(
            paths.catalog_file, paths.backup_dir, retention=5
        ).list_backups(protected=True)
        self.assertEqual(
            set(range(13, SCHEMA_VERSION + 1)),
            {record.schema_version for record in protected},
        )
        self.assertTrue(all(record.verified for record in protected))
        for record in protected:
            with sqlite3.connect(record.path) as connection:
                connection.execute("PRAGMA foreign_keys=ON")
                self.assertEqual(
                    [], list(connection.execute("PRAGMA foreign_key_check"))
                )
                if record.schema_version == 14:
                    source_root = connection.execute(
                        "SELECT source_root FROM libraries WHERE id='LIB1'"
                    ).fetchone()[0]
                    job_paths = connection.execute(
                        "SELECT device_name, mount_path FROM automatic_jobs "
                        "WHERE id='JOB-MIGRATION'"
                    ).fetchone()
                    policy_count = connection.execute(
                        "SELECT COUNT(*) FROM imported_job_policies"
                    ).fetchone()[0]
                    receipt_count = connection.execute(
                        "SELECT COUNT(*) FROM migration_receipts"
                    ).fetchone()[0]
                    self.assertEqual(str(self.root / "source-lib1"), source_root)
                    self.assertEqual(
                        ("synthetic-drive", "/synthetic/mount"), tuple(job_paths)
                    )
                    self.assertEqual(0, policy_count)
                    self.assertEqual(0, receipt_count)
        self.assertEqual(SCHEMA_VERSION, _schema_version(paths.catalog_file))

    def test_schema_fifteen_bundle_keeps_each_exact_import_backup(self) -> None:
        database = build_frozen_job_fixture(
            self.root / "schema-15.db", schema_version=15
        )
        bundle = _canonical_bundle_for_catalog(
            database, self.root / "schema-15.bundle.zip"
        )
        paths = LinuxPaths.for_root(
            self.root / "schema-15-state", self.root / "run" / "schema-15.sock"
        )

        report = MigrationImporter().import_bundle(bundle, paths, self.mappings)

        self.assertEqual(4, report.next_sequence)
        self.assertEqual(SCHEMA_VERSION, _schema_version(paths.catalog_file))
        protected = BackupManager(
            paths.catalog_file, paths.backup_dir, retention=5
        ).list_backups(protected=True)
        self.assertEqual(
            set(range(15, SCHEMA_VERSION + 1)),
            {record.schema_version for record in protected},
        )
        self.assertTrue(all(record.verified for record in protected))

    def test_protected_backup_contract_requires_every_schema_boundary(self) -> None:
        database = build_frozen_job_fixture(
            self.root / "backup-contract.db", schema_version=13
        )
        manager = BackupManager(database, self.root / "backup-contract", retention=5)
        manager.prepare_and_initialize()
        manager.create("before-windows-import", protected=True)
        schema_fourteen = next(
            record
            for record in manager.list_backups(protected=True)
            if record.schema_version == 14
        )
        schema_fourteen.path.unlink()

        with self.assertRaisesRegex(MigrationRejected, "protected-backups-invalid"):
            importer_module._require_protected_backups(manager, 13)

    def test_import_has_no_media_or_process_boundary(self) -> None:
        paths = LinuxPaths.for_root(
            self.root / "no-media-state", self.root / "run" / "no-media.sock"
        )
        with (
            mock.patch(
                "ltobackup.volume.inspect_volume",
                side_effect=AssertionError("media inspection is forbidden"),
            ) as inspect_volume,
            mock.patch(
                "subprocess.Popen",
                side_effect=AssertionError("process launch is forbidden"),
            ) as popen,
        ):
            report = MigrationImporter().import_bundle(
                read_bundle(self.bundle_path), paths, self.mappings
            )

        self.assertEqual((), report.media_accesses)
        inspect_volume.assert_not_called()
        popen.assert_not_called()

    def test_import_refuses_any_existing_state_without_touching_bundle(self) -> None:
        self.paths.state_dir.mkdir()
        marker = self.paths.state_dir / "operator-state"
        marker.write_text("preserve", encoding="utf-8")
        before = hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()

        with self.assertRaisesRegex(MigrationRejected, "state-not-empty"):
            MigrationImporter().import_bundle(
                self.bundle_path, self.paths, self.mappings
            )

        self.assertEqual("preserve", marker.read_text(encoding="utf-8"))
        self.assertEqual(
            before, hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()
        )

    def test_import_requires_exact_complete_path_mappings(self) -> None:
        cases = (
            (
                "missing-library",
                PathMappings(
                    library_roots={},
                    device_names=self.mappings.device_names,
                    mount_paths=self.mappings.mount_paths,
                ),
                "library-root-mappings-not-exact",
            ),
            (
                "extra-device",
                PathMappings(
                    library_roots=self.mappings.library_roots,
                    device_names={
                        **self.mappings.device_names,
                        "unused-drive": "/dev/tape/by-id/unused",
                    },
                    mount_paths=self.mappings.mount_paths,
                ),
                "device-name-mapping-not-exact",
            ),
            (
                "missing-source",
                PathMappings(
                    library_roots={
                        str(self.root / "source-lib1"): self.root / "absent-source"
                    },
                    device_names=self.mappings.device_names,
                    mount_paths=self.mappings.mount_paths,
                ),
                "library-root-unavailable",
            ),
            (
                "relative-mount",
                PathMappings(
                    library_roots=self.mappings.library_roots,
                    device_names=self.mappings.device_names,
                    mount_paths={"/synthetic/mount": "relative/mount"},
                ),
                "mount-path-mapping-invalid",
            ),
        )
        before = hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()
        for name, mappings, error in cases:
            with self.subTest(name=name):
                paths = LinuxPaths.for_root(
                    self.root / f"state-{name}", self.root / "run" / f"{name}.sock"
                )
                with self.assertRaisesRegex(MigrationRejected, error):
                    MigrationImporter().import_bundle(self.bundle_path, paths, mappings)
                self.assertFalse(paths.state_dir.exists())
                self.assertEqual(
                    before, hashlib.sha256(self.bundle_path.read_bytes()).hexdigest()
                )

    def test_import_maps_each_windows_library_root_without_prefix_rewriting(
        self,
    ) -> None:
        database = build_frozen_job_fixture(
            self.root / "windows-paths.db",
            schema_version=14,
            blocks_per_cassette=3,
            library_ids=("FILM", "ANIME", "TELEFILM"),
        )
        windows_roots = {
            "FILM": r"Z:\Film",
            "ANIME": r"Z:\Anime",
            "TELEFILM": r"Z:\Telefilm",
        }
        with sqlite3.connect(database) as connection:
            connection.executemany(
                "UPDATE libraries SET source_root=? WHERE id=?",
                [(root, library_id) for library_id, root in windows_roots.items()],
            )
            connection.execute(
                "UPDATE automatic_jobs SET device_name='TAPE0', mount_path='L:' "
                "WHERE id='JOB-MIGRATION'"
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        bundle = _canonical_bundle_for_catalog(
            database, self.root / "windows-paths.bundle.zip"
        )
        linux_roots = {
            root: self.root / "sources" / library_id.casefold()
            for library_id, root in windows_roots.items()
        }
        for target in linux_roots.values():
            target.mkdir(parents=True)
        mappings = PathMappings(
            library_roots=linux_roots,
            device_names={"TAPE0": "/dev/tape/by-id/configured-drive"},
            mount_paths={"L:": "/mnt/lto-archiver/tape"},
        )
        paths = LinuxPaths.for_root(
            self.root / "windows-path-state", self.root / "run" / "windows.sock"
        )
        before = _preserved_catalog_rows(database)

        MigrationImporter().import_bundle(bundle, paths, mappings)

        with sqlite3.connect(paths.catalog_file) as connection:
            actual_roots = dict(
                connection.execute("SELECT id, source_root FROM libraries ORDER BY id")
            )
            job_paths = connection.execute(
                "SELECT device_name, mount_path FROM automatic_jobs "
                "WHERE id='JOB-MIGRATION'"
            ).fetchone()
        self.assertEqual(
            {
                library_id: str(linux_roots[windows_root])
                for library_id, windows_root in windows_roots.items()
            },
            actual_roots,
        )
        self.assertEqual(
            ("/dev/tape/by-id/configured-drive", "/mnt/lto-archiver/tape"),
            tuple(job_paths),
        )
        self.assertEqual(before, _preserved_catalog_rows(paths.catalog_file))

    def test_import_refuses_bundle_newer_than_installed_runtime(self) -> None:
        database = build_frozen_job_fixture(self.root / "newer.db", schema_version=14)
        with ReadOnlyCatalog(database) as catalog:
            acceptance = MigrationValidator.inspect(catalog, "JOB-MIGRATION")
        acceptance.require_valid()
        with sqlite3.connect(database) as connection:
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='schema_version'",
                (str(SCHEMA_VERSION + 1),),
            )
            connection.commit()
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        bundle = _canonical_bundle_for_catalog(
            database,
            self.root / "newer.bundle.zip",
            acceptance=acceptance,
        )
        before = hashlib.sha256(bundle.read_bytes()).hexdigest()
        paths = LinuxPaths.for_root(
            self.root / "newer-state", self.root / "run" / "newer.sock"
        )

        with self.assertRaisesRegex(
            MigrationRejected, "bundle-schema-newer-than-runtime"
        ):
            MigrationImporter().import_bundle(bundle, paths, self.mappings)

        self.assertFalse(paths.state_dir.exists())
        self.assertEqual(before, hashlib.sha256(bundle.read_bytes()).hexdigest())

    def test_atomic_publish_failure_leaves_destination_absent_and_retry_succeeds(
        self,
    ) -> None:
        with (
            mock.patch.object(
                importer_module,
                "_rename_noreplace",
                side_effect=OSError("injected publish failure"),
                create=True,
            ),
            self.assertRaisesRegex(MigrationRejected, "state-activation-failed"),
        ):
            MigrationImporter().import_bundle(
                self.bundle_path, self.paths, self.mappings
            )

        self.assertFalse(self.paths.state_dir.exists())
        report = MigrationImporter().import_bundle(
            self.bundle_path, self.paths, self.mappings
        )
        self.assertEqual(4, report.next_sequence)

    def test_target_symlink_race_never_replaces_or_writes_victim(self) -> None:
        victim = self.root / "target-race-victim"
        victim.mkdir()
        original = importer_module._rename_noreplace

        def inject_target(parent_fd: int, source: str, destination: str) -> None:
            os.symlink(victim, destination, dir_fd=parent_fd)
            original(parent_fd, source, destination)

        with (
            mock.patch.object(
                importer_module,
                "_rename_noreplace",
                side_effect=inject_target,
            ),
            self.assertRaisesRegex(MigrationRejected, "state-not-empty"),
        ):
            MigrationImporter().import_bundle(
                self.bundle_path, self.paths, self.mappings
            )

        self.assertEqual([], list(victim.iterdir()))
        self.assertTrue(self.paths.state_dir.is_symlink())
        self.paths.state_dir.unlink()
        report = MigrationImporter().import_bundle(
            self.bundle_path, self.paths, self.mappings
        )
        self.assertEqual(4, report.next_sequence)

    def test_parent_symlink_swap_never_writes_attacker_destination(self) -> None:
        state_parent = self.root / "state-parent"
        moved_parent = self.root / "state-parent-moved"
        victim = self.root / "victim"
        state_parent.mkdir()
        victim.mkdir()
        paths = LinuxPaths.for_root(
            state_parent / "state", self.root / "run" / "swap.sock"
        )
        original = importer_module._require_protected_backups
        receipt = importer_module.build_import_acceptance_receipt(
            read_bundle(self.bundle_path), self.mappings
        )

        def swap_parent(*args, **kwargs):
            protected = original(*args, **kwargs)
            os.rename(state_parent, moved_parent)
            state_parent.symlink_to(victim, target_is_directory=True)
            return protected

        try:
            with (
                mock.patch.object(
                    importer_module,
                    "_require_protected_backups",
                    side_effect=swap_parent,
                ),
                self.assertRaises(MigrationRejected),
            ):
                MigrationImporter().import_bundle(
                    self.bundle_path,
                    paths,
                    self.mappings,
                    acceptance_receipt=receipt,
                )
        finally:
            if state_parent.is_symlink():
                state_parent.unlink()
            if moved_parent.exists():
                os.rename(moved_parent, state_parent)

        self.assertFalse((victim / "state").exists())
        self.assertFalse(paths.state_dir.exists())
        report = MigrationImporter().import_bundle(
            self.bundle_path,
            paths,
            self.mappings,
            acceptance_receipt=receipt,
        )
        self.assertEqual(4, report.next_sequence)

    def test_import_persists_resolved_source_when_symlink_is_retargeted(self) -> None:
        first = self.root / "source-real-first"
        second = self.root / "source-real-second"
        configured = self.root / "source-configured"
        first.mkdir()
        second.mkdir()
        configured.symlink_to(first, target_is_directory=True)
        mappings = PathMappings(
            library_roots={str(self.root / "source-lib1"): configured},
            device_names=self.mappings.device_names,
            mount_paths=self.mappings.mount_paths,
        )

        MigrationImporter().import_bundle(self.bundle_path, self.paths, mappings)
        configured.unlink()
        configured.symlink_to(second, target_is_directory=True)

        with sqlite3.connect(self.paths.catalog_file) as connection:
            persisted = connection.execute(
                "SELECT source_root FROM libraries WHERE id='LIB1'"
            ).fetchone()[0]
        self.assertEqual(str(first.resolve()), persisted)
        self.assertNotEqual(str(configured), persisted)


def _schema_version(path: Path) -> int:
    with sqlite3.connect(path) as connection:
        return int(
            connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()[0]
        )
