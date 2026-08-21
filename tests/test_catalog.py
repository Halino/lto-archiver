from __future__ import annotations

import tempfile
import unittest
import sqlite3
from contextlib import closing
from pathlib import Path

from ltobackup.catalog import Catalog, SCHEMA_VERSION
from ltobackup.errors import CatalogError, ValidationError


class CatalogTests(unittest.TestCase):
    def test_registered_tape_reuse_requires_override_and_is_purged_only_on_format_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "OLD", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("OLD-BLOCK", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1", "OLD-BLOCK", "AB1234", "old.bin", "old/files/old.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.update_automatic_cassette(
                    "OLD", 1, "completed", tape_id="AB1234", block_id="OLD-BLOCK",
                    copied_files=1, copied_bytes=10,
                )
                catalog.update_automatic_job("OLD", "completed", current_sequence=1)

                with self.assertRaisesRegex(CatalogError, "gia registrata"):
                    catalog.create_automatic_job(
                        "SAFE", "LIB1", "TAPE0", "L:\\",
                        [("AB1234", "AB1234", 1, 10)], force_format=True,
                    )

                catalog.create_automatic_job(
                    "REUSE", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
                    allow_registered_reuse=True,
                )
                queued = catalog.list_automatic_cassettes("REUSE")[0]
                self.assertEqual(1, queued["reuse_registered"])
                self.assertIsNotNone(catalog.get_tape("AB1234"))
                self.assertIn("old.bin", catalog.latest_versions("LIB1"))

                result = catalog.commit_registered_tape_reformat("REUSE", 1)

                self.assertEqual({"tapes": 1, "blocks": 1, "files": 1, "jobs": 1}, result)
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
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 2, 30)], force_format=True,
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
                            row["library_id"], row["relative_path"],
                            row["size"], row["mtime_ns"],
                        )
                        for row in catalog.list_automatic_cassette_manifest("JOB1", 1)
                    ],
                )

    def test_schema_nine_cassette_queue_is_migrated_to_safe_format_operations(self) -> None:
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

            with Catalog(database) as catalog:
                catalog.initialize()
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
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234L5", "AB1234", 1, 10)],
                    force_format=True,
                    media_key="LTO-5",
                )

                self.assertEqual("LTO-5", catalog.get_automatic_job("JOB1")["media_key"])

    def test_automatic_job_can_be_renamed_without_changing_identity_or_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
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
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("DONE01", "DONE01", 1, 10), ("LIVE02", "LIVE02", 1, 8)],
                    force_format=True,
                )
                catalog.create_automatic_job(
                    "JOB2", "LIB2", "TAPE1", "M:\\",
                    [("KEEP03", "KEEP03", 0, 0)],
                    force_format=True,
                )
                for tape_id in ("DONE01", "LIVE02"):
                    catalog.register_tape(
                        tape_id, tape_id, tape_id, "LTFS", "L:\\",
                        cassette_number=tape_id,
                    )
                catalog.create_block("BLOCK-DONE", "LIB1", "DONE01", "done", 1, 10)
                catalog.record_file_version(
                    "LIB1", "BLOCK-DONE", "DONE01", "done.bin", "done/done.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("BLOCK-DONE")
                catalog.create_block("BLOCK-LIVE", "LIB1", "LIVE02", "live", 1, 8)
                catalog.record_file_version(
                    "LIB1", "BLOCK-LIVE", "LIVE02", "partial.bin", "live/partial.bin",
                    8, 2, "b" * 64,
                )
                catalog.update_automatic_cassette(
                    "JOB1", 1, "completed", tape_id="DONE01", block_id="BLOCK-DONE",
                    copied_files=1, copied_bytes=10,
                )
                catalog.update_automatic_cassette(
                    "JOB1", 2, "writing", tape_id="LIVE02", block_id="BLOCK-LIVE",
                    copied_files=1, copied_bytes=8,
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
                blocks = {row["id"]: row for row in catalog.list_blocks()}
                self.assertEqual("completed", blocks["BLOCK-DONE"]["status"])
                self.assertEqual("failed", blocks["BLOCK-LIVE"]["status"])
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
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB-LEGACY", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
                )
            with closing(sqlite3.connect(database)) as connection:
                columns = {
                    row[1] for row in connection.execute("PRAGMA table_info(automatic_jobs)")
                }
                if "display_name" in columns:
                    connection.execute("ALTER TABLE automatic_jobs DROP COLUMN display_name")
                connection.execute(
                    "UPDATE metadata SET value='7' WHERE key='schema_version'"
                )
                connection.commit()

            with Catalog(database) as catalog:
                catalog.initialize()
                job = catalog.get_automatic_job("JOB-LEGACY")
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertEqual("LTO-6", job["media_key"])
                self.assertEqual("JOB-LEGACY", job["display_name"])

    def test_reset_automatic_cassette_discards_only_its_attempt_and_pauses_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            source = Path(temporary) / "source"
            source.mkdir()
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("DONE01", "DONE01", 1, 10), ("LIVE02", "LIVE02", 2, 20)],
                    force_format=True,
                )
                for tape_id in ("DONE01", "LIVE02"):
                    catalog.register_tape(
                        tape_id, tape_id, tape_id, "LTFS", "L:\\",
                        cassette_number=tape_id,
                    )
                catalog.create_block("BLOCK-DONE", "LIB1", "DONE01", "done", 1, 10)
                catalog.record_file_version(
                    "LIB1", "BLOCK-DONE", "DONE01", "done.bin", "done/done.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("BLOCK-DONE")
                catalog.update_automatic_cassette(
                    "JOB1", 1, "completed", tape_id="DONE01", block_id="BLOCK-DONE",
                    copied_files=1, copied_bytes=10,
                )
                catalog.create_block("BLOCK-LIVE", "LIB1", "LIVE02", "live", 2, 20)
                catalog.record_file_version(
                    "LIB1", "BLOCK-LIVE", "LIVE02", "partial.bin", "live/partial.bin",
                    8, 2, "b" * 64,
                )
                catalog.update_automatic_job("JOB1", "writing", current_sequence=2)
                catalog.update_automatic_cassette(
                    "JOB1", 2, "writing", tape_id="LIVE02", block_id="BLOCK-LIVE",
                    copied_files=1, copied_bytes=8,
                )

                result = catalog.reset_automatic_cassette("JOB1", 2, "Interrotta dall'operatore")

                self.assertEqual({"blocks": 1, "files": 1, "tapes": 1}, result)
                self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
                cassettes = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("completed", cassettes[0]["status"])
                self.assertEqual("pending", cassettes[1]["status"])
                self.assertIsNone(cassettes[1]["tape_id"])
                self.assertEqual(0, cassettes[1]["copied_bytes"])
                self.assertEqual(["BLOCK-DONE"], [row["id"] for row in catalog.list_blocks()])
                self.assertEqual(["DONE01"], [row["id"] for row in catalog.list_tapes()])
                self.assertEqual(["done.bin"], list(catalog.latest_versions("LIB1")))

    def test_distinct_ltfs_labels_can_share_the_storeopen_win32_serial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.register_tape("IR1821", "00007AF3", "IR1821", "LTFS", "L:\\")
                catalog.register_tape("IR1822", "00007AF3", "IR1822", "LTFS", "L:\\")

                self.assertEqual(
                    [("IR1821", "00007AF3"), ("IR1822", "00007AF3")],
                    [(row["id"], row["volume_serial"]) for row in catalog.list_tapes()],
                )
                with self.assertRaisesRegex(CatalogError, "(?i)etichetta LTFS IR1822"):
                    catalog.register_tape("IR1823", "DIFFERENT", "ir1822", "LTFS", "M:\\")

                indexes = {
                    row[1] for row in catalog.connection.execute("PRAGMA index_list(tapes)")
                }
                self.assertNotIn("ux_tapes_volume_serial", indexes)
                self.assertIn("ux_tapes_ltfs_volume_label", indexes)

    def test_schema_twelve_migrates_from_win32_serial_identity_to_ltfs_label_identity(self) -> None:
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
                        'IR1821', 'IR1821', '00007AF3', 'IR1821', 'LTFS', 'L:\\',
                        'active', '2026-08-20T10:55:56+00:00', '2026-08-20T17:21:41+00:00'
                    );
                    CREATE UNIQUE INDEX ux_tapes_volume_serial
                        ON tapes(volume_serial COLLATE NOCASE);
                    """
                )

            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "IR1822", "00007AF3", "IR1822", "LTFS", "L:\\",
                    cassette_number="IR1822",
                )
                version = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                indexes = {
                    row[1] for row in catalog.connection.execute("PRAGMA index_list(tapes)")
                }

                self.assertEqual(str(SCHEMA_VERSION), version)
                self.assertNotIn("ux_tapes_volume_serial", indexes)
                self.assertIn("ux_tapes_ltfs_volume_label", indexes)

    def test_reregistering_same_ltfs_label_refreshes_diagnostic_win32_serial(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with Catalog(Path(temporary) / "catalog.db") as catalog:
                catalog.initialize()
                catalog.register_tape("IR1821", "00007AF3", "IR1821", "LTFS", "L:\\")

                catalog.register_tape("IR1821", "A1B2C3D4", "ir1821", "LTFS", "M:\\")

                tape = catalog.get_tape("IR1821")
                self.assertEqual("A1B2C3D4", tape["volume_serial"])
                self.assertEqual("M:\\", tape["mount_hint"])

    def test_schema_one_is_migrated_and_existing_tape_keeps_a_cassette_number(self) -> None:
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

            with Catalog(database) as catalog:
                catalog.initialize()
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
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0042")
                catalog.register_tape("TAPE2", "SERIAL2", "Tape 2", "LTFS", "L:\\", "CASS-0043")
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 10)
                catalog.record_file_version(
                    "LIB1", "block1", "TAPE1", "film/video.mxf", ".lto-backup/block1/video.mxf", 10, 1, "a" * 64
                )
                catalog.complete_block("block1")
                catalog.create_block("block2", "LIB1", "TAPE2", ".lto-backup/block2", 1, 20)
                catalog.record_file_version(
                    "LIB1", "block2", "TAPE2", "film/video.mxf", ".lto-backup/block2/video.mxf", 20, 2, "b" * 64
                )
                catalog.complete_block("block2")

                current = catalog.search_files("video")
                history = catalog.search_files("video", include_history=True)

                self.assertEqual(1, len(current))
                self.assertEqual("CASS-0043", current[0]["cassette_number"])
                self.assertEqual(".lto-backup/block2/video.mxf", current[0]["tape_relative_path"])
                self.assertEqual(["CASS-0043", "CASS-0042"], [row["cassette_number"] for row in history])

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
                self.assertEqual([], catalog.search_files("failed.bin", include_history=True))

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
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 10)
                catalog.record_file_version(
                    "LIB1", "block1", "TAPE1", "file.bin", ".lto-backup/block1/file.bin", 10, 1, "a" * 64
                )
                catalog.complete_block("block1")

                catalog.forget_block("block1")
                self.assertEqual([], catalog.list_blocks())
                self.assertEqual(1, len(catalog.list_blocks(include_forgotten=True)))
                self.assertEqual({}, catalog.latest_versions("LIB1"))

                block = catalog.list_blocks(include_forgotten=True)[0]
                self.assertEqual(0, block["visible"])
                self.assertEqual("TAPE1", block["tape_id"])

    def test_library_deletion_removes_only_its_catalog_data(self) -> None:
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
                    catalog.create_block(block_id, library_id, "TAPE1", f".lto-backup/{block_id}", 1, 3)
                    catalog.record_file_version(
                        library_id, block_id, "TAPE1", path,
                        f".lto-backup/{block_id}/files/{path}", 3, 1, "a" * 64,
                    )
                    catalog.complete_block(block_id)
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 2, 6)],
                    library_ids=["LIB1", "LIB2"],
                )
                catalog.update_automatic_job("JOB1", "completed")

                result = catalog.delete_library("LIB1")

                self.assertEqual(["LIB2"], [row["id"] for row in catalog.list_libraries(True)])
                self.assertEqual([], catalog.list_blocks("LIB1", include_forgotten=True))
                self.assertEqual({}, catalog.latest_versions("LIB1"))
                self.assertEqual(["block2"], [row["id"] for row in catalog.list_blocks("LIB2")])
                self.assertEqual(["TAPE1"], [row["id"] for row in catalog.list_tapes()])
                job = catalog.get_automatic_job("JOB1")
                self.assertEqual("LIB2", job["library_id"])
                self.assertEqual(
                    ["LIB2"],
                    [row["library_id"] for row in catalog.list_automatic_job_libraries("JOB1")],
                )
                self.assertTrue(physical_one.is_file())
                self.assertTrue(physical_two.is_file())
                self.assertEqual(1, result["catalog_files_deleted"])
                self.assertEqual(1, result["catalog_blocks_deleted"])

    def test_library_deletion_refuses_an_unfinished_automatic_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library 1", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 3)],
                )

                with self.assertRaisesRegex(CatalogError, "job non concluso JOB1"):
                    catalog.delete_library("LIB1")

                self.assertEqual("LIB1", catalog.get_library("LIB1")["id"])

    def test_catalog_integrity_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                catalog.add_library("LIB_A", "A", str(source))
                self.assertEqual("ok", catalog.connection.execute("PRAGMA integrity_check").fetchone()[0])
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
                self.assertEqual("ok", copied.connection.execute("PRAGMA integrity_check").fetchone()[0])
                self.assertEqual(["LIB_A"], [row["id"] for row in copied.list_libraries()])

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
                count = catalog.connection.execute("SELECT COUNT(*) FROM events").fetchone()[0]
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
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 4, 1000), ("CD5678L6", "CD5678", 2, 500)],
                    library_ids=["LIB1", "LIB2"],
                )
                catalog.update_automatic_job("JOB1", "waiting_media", current_sequence=1)
                catalog.update_automatic_cassette("JOB1", 1, "formatting")

            with Catalog(root / "catalog.db") as catalog:
                catalog.initialize()
                self.assertEqual("waiting_media", catalog.get_automatic_job("JOB1")["status"])
                queue = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual(["AB1234", "CD5678L6"], [row["physical_label"] for row in queue])
                self.assertEqual("formatting", queue[0]["status"])
                self.assertEqual(
                    ["LIB1", "LIB2"],
                    [row["library_id"] for row in catalog.list_automatic_job_libraries("JOB1")],
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
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.connection.execute("DELETE FROM automatic_job_libraries")
                catalog.connection.execute(
                    "UPDATE metadata SET value='3' WHERE key='schema_version'"
                )
                catalog.connection.commit()

            with Catalog(database) as catalog:
                catalog.initialize()
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
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100")
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 3, 60)
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
                        "LIB1", "block1", "TAPE1", path,
                        f".lto-backup/block1/files/{path}", size, 30, "a" * 64,
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
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 10)
                catalog.record_file_version(
                    "LIB1", "block1", "TAPE1", "old/folder/file.bin",
                    ".lto-backup/block1/files/old/folder/file.bin", 10, 1, "a" * 64,
                )
                catalog.complete_block("block1")
                catalog.connection.execute("UPDATE metadata SET value='4' WHERE key='schema_version'")
                catalog.connection.commit()

            with Catalog(database) as catalog:
                catalog.initialize()
                row = catalog.latest_versions("LIB1")["old/folder/file.bin"]

                self.assertEqual(str(SCHEMA_VERSION), catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0])
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

            with Catalog(database) as catalog:
                catalog.initialize()
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

            with Catalog(database) as catalog:
                catalog.initialize()
                job = catalog.get_automatic_job("LEGACY")
                schema = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]

                self.assertEqual(str(SCHEMA_VERSION), schema)
                self.assertEqual(0, job["force_format"])


if __name__ == "__main__":
    unittest.main()
