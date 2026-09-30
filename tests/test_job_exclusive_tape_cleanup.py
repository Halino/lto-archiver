from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from ltobackup.catalog import Catalog


class ExclusiveJobTapeCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.catalog = Catalog(self.root / "catalog.db")
        self.addCleanup(self.catalog.close)
        self.catalog.initialize()
        self.catalog.add_library("LIB1", "First library", str(self.root))
        self.catalog.add_library("LIB2", "Second library", str(self.root))
        self.catalog.create_automatic_job(
            "JOB1", "LIB1", "TAPE0", "/tape",
            [("ONE001", "ONE001", 1, 7), ("TWO002", "TWO002", 0, 0)],
            library_ids=["LIB2"], force_format=True,
        )
        self.catalog.update_automatic_job("JOB1", "completed")

    def register(self, tape_id):
        self.catalog.register_tape(
            tape_id, tape_id, tape_id, "LTFS", "/tape", cassette_number=tape_id,
        )

    def block(self, block_id, tape_id="ONE001", library_id="LIB1"):
        self.catalog.create_block(block_id, library_id, tape_id, block_id, 1, 7)
        self.catalog.record_file_version(
            library_id, block_id, tape_id, block_id + ".bin",
            block_id + "/file.bin", 7, 1, "a" * 64,
        )
        self.catalog.complete_block(block_id)

    def bind_legacy(self, block_id="BLOCK1", tape_id="ONE001", job_id="JOB1"):
        self.catalog.update_automatic_cassette(
            job_id, 1, "completed", tape_id=tape_id, block_id=block_id,
            copied_files=1, copied_bytes=7,
        )

    def bind_layout(self, block_id, epoch=1):
        with self.catalog.transaction() as db:
            if epoch > 1:
                self.catalog._insert_layout_epoch_tx(
                    db, "JOB1", kind="extension", plan_id=None,
                    plan_digest_sha256="b" * 64,
                    created_at="2026-09-06T00:00:00+00:00",
                    target_sequences=(1,), target_operations=("append",),
                )
            target = db.execute(
                "SELECT * FROM job_layout_targets WHERE job_id='JOB1' "
                "AND epoch_number=? AND target_sequence=1", (epoch,),
            ).fetchone()
            db.execute(
                "INSERT INTO job_layout_target_blocks(job_id,epoch_number,"
                "plan_sequence,target_sequence,segment_id,operation_id,block_id,"
                "created_at) VALUES(?,?,?,?,?,?,?,?)",
                ("JOB1", epoch, target["plan_sequence"], 1, target["segment_id"],
                 "operation-" + block_id, block_id, "2026-09-06T00:00:00+00:00"),
            )

    def cleanup(self):
        rows = self.catalog.connection.execute(
            "SELECT payload_json FROM job_management_history "
            "WHERE job_id='JOB1' AND action='job.catalog_cleanup' ORDER BY id"
        ).fetchall()
        self.assertEqual(1, len(rows), "retirement must record one cleanup result")
        return json.loads(rows[0][0])

    def assert_integrity(self):
        self.assertEqual([], self.catalog.connection.execute("PRAGMA foreign_key_check").fetchall())

    def test_retirement_removes_exclusive_catalog_but_keeps_physical_data_and_history(self):
        self.register("ONE001")
        self.register("KEEP03")
        self.block("BLOCK1")
        self.block("OTHER", "KEEP03", "LIB2")
        self.bind_legacy()
        physical = self.root / "physical-tape-payload"
        physical.write_bytes(b"unchanged")
        cassettes = [tuple(row) for row in self.catalog.list_automatic_cassettes("JOB1")]
        cartridges = list(self.catalog.connection.execute("SELECT * FROM cartridges"))

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["KEEP03"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual({}, self.catalog.latest_versions("LIB1"))
        self.assertEqual([], self.catalog.library_tape_distribution("LIB1"))
        self.assertEqual(["OTHER.bin"], list(self.catalog.latest_versions("LIB2")))
        self.assertEqual(b"unchanged", physical.read_bytes())
        self.assertEqual(cartridges, list(self.catalog.connection.execute("SELECT * FROM cartridges")))
        self.assertEqual(cassettes[0], tuple(self.catalog.list_automatic_cassettes("JOB1")[0]))
        self.assertEqual({
            "deleted_tapes": ["ONE001"], "preserved_tapes": [],
            "deleted_blocks": 1, "deleted_files": 1, "tape_data_deleted": False,
        }, self.cleanup())
        self.assert_integrity()

    def test_all_layout_epochs_and_libraries_are_removed_together(self):
        self.register("ONE001")
        self.block("ORIGINAL")
        self.bind_layout("ORIGINAL")
        self.block("APPENDED", library_id="LIB2")
        self.bind_layout("APPENDED", epoch=2)
        self.bind_legacy("APPENDED")
        layout = [tuple(row) for row in self.catalog.connection.execute(
            "SELECT * FROM job_layout_target_blocks ORDER BY block_id")]

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual([], self.catalog.list_tapes())
        self.assertEqual(2, self.cleanup()["deleted_blocks"])
        self.assertEqual(2, self.cleanup()["deleted_files"])
        self.assertEqual(layout, [tuple(row) for row in self.catalog.connection.execute(
            "SELECT * FROM job_layout_target_blocks ORDER BY block_id")])
        self.assert_integrity()

    def test_unowned_block_preserves_entire_tape_and_both_file_indexes(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        self.block("MANUAL", library_id="LIB2")

        self.catalog.retire_managed_job("JOB1")

        result = self.cleanup()
        self.assertEqual([], result["deleted_tapes"])
        self.assertEqual("ONE001", result["preserved_tapes"][0]["tape_id"])
        self.assertTrue(result["preserved_tapes"][0]["reason"])
        self.assertEqual(["BLOCK1.bin"], list(self.catalog.latest_versions("LIB1")))
        self.assertEqual(["MANUAL.bin"], list(self.catalog.latest_versions("LIB2")))
        self.assert_integrity()

    def test_other_job_reference_preserves_tape_even_when_all_blocks_look_owned(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        self.catalog.create_automatic_job(
            "JOB2", "LIB1", "TAPE1", "/other",
            [("ONE001", "ONE001", 0, 0)], allow_registered_reuse=True,
        )
        self.bind_legacy(job_id="JOB2")
        self.catalog.update_automatic_job("JOB2", "completed")
        with self.catalog.transaction() as db:
            db.execute("UPDATE job_management_state SET retired_at='past' WHERE job_id='JOB2'")

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assertEqual(0, self.cleanup()["deleted_files"])
        self.assert_integrity()

    def test_pending_label_without_written_ownership_does_not_delete_registered_tape(self):
        self.register("TWO002")
        self.block("UNRELATED", "TWO002")

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["TWO002"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assertEqual(["UNRELATED.bin"], list(self.catalog.latest_versions("LIB1")))
        self.assert_integrity()

    def test_other_job_using_legacy_tape_id_alias_preserves_shared_tape(self):
        self.catalog.register_tape(
            "LEGACY", "SERIAL1", "ONE001", "LTFS", "/tape", cassette_number="ONE001",
        )
        self.block("BLOCK1", "LEGACY")
        self.bind_legacy(tape_id="LEGACY")
        self.catalog.create_automatic_job(
            "JOB2", "LIB1", "TAPE1", "/other", [("LEGACY", "LEGACY", 0, 0)],
            allow_registered_reuse=True,
        )

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["LEGACY"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assert_integrity()

    def test_retired_cassette_with_legacy_suffix_preserves_shared_tape(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        self.catalog.create_automatic_job(
            "JOB2", "LIB1", "TAPE1", "/other", [("ONE001L6", "ONE001L6", 0, 0)],
        )
        self.catalog.update_automatic_job("JOB2", "completed")
        with self.catalog.transaction() as db:
            db.execute("UPDATE job_management_state SET retired_at='past' WHERE job_id='JOB2'")

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assert_integrity()

    def test_historical_layout_with_legacy_suffix_preserves_shared_tape(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        self.catalog.create_automatic_job(
            "JOB2", "LIB1", "TAPE1", "/other", [("ONE001L6", "ONE001L6", 1, 7)],
        )
        self.catalog.delete_automatic_job("JOB2")
        self.assertEqual([], self.catalog.list_automatic_cassettes("JOB2"))

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assert_integrity()

    def test_preexisting_orphan_file_is_preserved_as_unproven_ownership(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        orphan = self.catalog.record_file_version(
            "LIB1", "BLOCK1", "ONE001", "orphan.bin", "orphan/file.bin",
            7, 1, "b" * 64,
        )
        # Represent a legacy damaged index without removing its unknown file.
        db = self.catalog.connection
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("UPDATE file_versions SET block_id='ABSENT' WHERE id=?", (orphan,))
        db.commit()
        db.execute("PRAGMA foreign_keys=ON")
        violations = [tuple(row) for row in db.execute("PRAGMA foreign_key_check")]
        self.assertEqual(1, len(violations))

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assertEqual(violations, [tuple(row) for row in db.execute("PRAGMA foreign_key_check")])

    def test_global_operation_without_job_identity_preserves_tape_catalog(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        with self.catalog.transaction() as db:
            db.execute(
                "INSERT INTO daemon_operations(id,kind,state,idempotency_key,"
                "principal,owner_generation,started_at) "
                "VALUES('maintenance','media.inspect','running','maintenance-key',"
                "'admin',1,'2026-09-06T00:00:00+00:00')"
            )

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([{"tape_id": "ONE001", "reason": "operation_active"}],
                         self.cleanup()["preserved_tapes"])
        self.assertIsNotNone(self.catalog.job_management_state("JOB1")["retired_at"])
        self.assert_integrity()

    def test_nonquiescent_command_after_operation_finishes_preserves_tape_catalog(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        with self.catalog.transaction() as db:
            db.execute(
                "INSERT INTO daemon_operations(id,kind,state,idempotency_key,"
                "principal,owner_generation,started_at) "
                "VALUES('maintenance','media.inspect','succeeded','maintenance-key',"
                "'admin',1,'2026-09-06T00:00:00+00:00')"
            )
            db.execute(
                "INSERT INTO hardware_command_executions(id,operation_id,issued_generation,"
                "command_kind,argv_sha256,mount_path_sha256,tape_device_identity_sha256,"
                "scsi_device_identity_sha256,expected_media_scope_sha256,state,created_at) "
                "VALUES('command','maintenance',1,'identify',?,?,?,?,?,'launch_reserved',"
                "'2026-09-06T00:00:00+00:00')", ("a" * 64,) * 5,
            )

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([{"tape_id": "ONE001", "reason": "operation_active"}],
                         self.cleanup()["preserved_tapes"])
        self.assertIsNotNone(self.catalog.job_management_state("JOB1")["retired_at"])
        self.assert_integrity()

    def test_cleanup_preserves_format_grants_and_reuse_needs_fresh_job_authority(self):
        old_epoch = self.catalog.latest_layout_epoch("JOB1")
        old_grants = self.catalog.authorize_automatic_format_sequence(
            "JOB1", expected_revision=0,
            layout_fingerprint_sha256=old_epoch["layout_fingerprint_sha256"],
            actor="admin", idempotency_key="old-authority",
            authorized_at="2026-09-06T00:00:00+00:00",
        )
        self.assertTrue(old_grants)
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        authorization_tables = (
            "automatic_format_authorizations", "operation_format_authorizations",
            "format_confirmations",
        )
        before = {
            table: [tuple(row) for row in self.catalog.connection.execute(f"SELECT * FROM {table}")]
            for table in authorization_tables
        }

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual([], self.catalog.list_tapes())
        self.assertEqual(before, {
            table: [tuple(row) for row in self.catalog.connection.execute(f"SELECT * FROM {table}")]
            for table in authorization_tables
        })
        self.catalog.create_automatic_job(
            "NEWJOB", "LIB1", "TAPE0", "/tape", [("ONE001", "ONE001", 1, 7)],
            force_format=True,
        )
        self.catalog.enable_automatic_sequence_for_start(
            "NEWJOB", actor="admin", enabled_at="2026-09-06T01:00:00+00:00",
        )
        self.assertIsNone(self.catalog.format_sequence_authorization("NEWJOB", 1))
        epoch = self.catalog.latest_layout_epoch("NEWJOB")
        new_grants = self.catalog.authorize_automatic_format_sequence(
            "NEWJOB", expected_revision=0,
            layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
            actor="admin", idempotency_key="new-authority",
            authorized_at="2026-09-06T01:00:00+00:00",
        )
        self.assertTrue(new_grants)
        self.assertTrue(set(old_grants).isdisjoint(new_grants))
        self.assertEqual("NEWJOB", self.catalog.format_sequence_authorization("NEWJOB", 1)["job_id"])
        self.assertEqual([], list(self.catalog.connection.execute("SELECT * FROM operation_format_authorizations")))
        self.assert_integrity()

    def test_repeated_retirement_has_one_cleanup_record(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        self.catalog.retire_managed_job("JOB1")
        self.catalog.retire_managed_job("JOB1")
        self.assertEqual(["ONE001"], self.cleanup()["deleted_tapes"])
        self.assert_integrity()

    def test_append_ownership_is_archived_before_deleting_its_block(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        with self.catalog.transaction() as db:
            db.execute(
                "INSERT INTO daemon_operations(id,kind,state,idempotency_key,"
                "principal,owner_generation,job_id,cassette_sequence,started_at) "
                "VALUES('append-op','archive.native','succeeded','append-key',"
                "'admin',1,'JOB1',1,'2026-09-06T00:00:00+00:00')"
            )
            db.execute(
                "INSERT INTO automatic_operation_blocks(block_id,operation_id,job_id,"
                "cassette_sequence,created_at) VALUES('BLOCK1','append-op','JOB1',1,"
                "'2026-09-06T00:00:00+00:00')"
            )

        self.catalog.retire_managed_job("JOB1", actor="admin")

        self.assertEqual([], self.catalog.list_tapes())
        self.assertEqual([], list(self.catalog.connection.execute("SELECT * FROM automatic_operation_blocks")))
        archived = self.catalog.connection.execute(
            "SELECT block_id,job_id,disposition FROM automatic_operation_block_tombstones"
        ).fetchone()
        self.assertEqual(("BLOCK1", "JOB1", "job_deleted"), tuple(archived))
        self.assertEqual("admin", self.catalog.connection.execute(
            "SELECT actor FROM job_management_history WHERE action='job.catalog_cleanup'"
        ).fetchone()[0])
        self.assert_integrity()

    def test_ambiguous_legacy_physical_identity_preserves_both_tapes(self):
        self.register("ONE001")
        self.register("ONE001L6")
        self.block("BLOCK1")
        self.bind_legacy()

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001", "ONE001L6"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assertEqual(2, len(self.cleanup()["preserved_tapes"]))
        self.assert_integrity()

    def test_imported_immutable_receipt_keeps_tape_without_mutating_receipt(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        self.catalog.create_automatic_job(
            "FROZEN", "LIB1", "TAPE1", "/other", [("OTHER1", "OTHER1", 0, 0)],
        )
        with self.catalog.transaction() as db:
            db.execute(
                "INSERT INTO imported_job_policies(job_id,assignment_sha256,bundle_sha256,"
                "authority_state,windows_authority,rollback_allowed,frozen_at) "
                "VALUES('FROZEN',?,?,'pre_cutover','resumable',1,'2026-09-06')",
                ("a" * 64, "b" * 64),
            )
            db.execute(
                "INSERT INTO daemon_operations(id,kind,state,idempotency_key,"
                "principal,owner_generation,job_id,started_at) "
                "VALUES('import-op','archive.resume','succeeded','import-key',"
                "'admin',1,'FROZEN','2026-09-06T00:00:00+00:00')"
            )
            receipt = {
                "job_id": "FROZEN", "sequence": 5, "operation_id": "import-op",
                "owner_generation": 1, "tape_id": "ONE001",
                "block_ids_json": '["BLOCK1"]', "command_ids_json": '[]',
                "committed_at": "2026-09-06T00:00:00+00:00",
            }
            for field in (
                "authority_sha256", "evidence_sha256", "manifest_sha256",
                "command_evidence_sha256", "commit_binding_sha256",
                "observed_media_identity_sha256", "mount_path_sha256",
                "tape_device_identity_sha256", "scsi_device_identity_sha256",
                "expected_media_scope_sha256",
            ):
                receipt[field] = "a" * 64
            db.execute(
                "INSERT INTO imported_runtime_cassette_commit_receipts("
                + ",".join(receipt) + ") VALUES(" + ",".join("?" for _ in receipt) + ")",
                tuple(receipt.values()),
            )
        before = tuple(self.catalog.connection.execute(
            "SELECT * FROM imported_runtime_cassette_commit_receipts"
        ).fetchone())

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assertEqual(before, tuple(self.catalog.connection.execute(
            "SELECT * FROM imported_runtime_cassette_commit_receipts"
        ).fetchone()))
        self.assert_integrity()

    def test_saved_restore_plan_keeps_its_tape_catalog_available(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        version = self.catalog.latest_versions("LIB1")["BLOCK1.bin"]
        restore = self.catalog.create_restore_plan(
            [version["id"]], str(self.root / "restore"), actor="admin",
            idempotency_key="restore-plan", request_sha256="a" * 64,
        )

        self.catalog.retire_managed_job("JOB1")

        self.assertEqual(["ONE001"], [row["id"] for row in self.catalog.list_tapes()])
        self.assertEqual([], self.cleanup()["deleted_tapes"])
        self.assertEqual(restore, self.catalog.get_restore_plan(restore["id"]))
        self.assertEqual(version["id"], self.catalog.latest_versions("LIB1")["BLOCK1.bin"]["id"])
        self.assert_integrity()

    def test_second_tape_delete_failure_rolls_back_first_tape_and_retirement(self):
        self.register("ONE001")
        self.register("TWO002")
        self.block("BLOCK1")
        self.bind_legacy()
        self.block("BLOCK2", "TWO002")
        self.catalog.update_automatic_cassette(
            "JOB1", 2, "completed", tape_id="TWO002", block_id="BLOCK2",
            copied_files=1, copied_bytes=7,
        )
        with self.catalog.transaction() as db:
            db.execute("CREATE TRIGGER reject_second_tape BEFORE DELETE "
                       "ON tapes WHEN OLD.id='TWO002' "
                       "BEGIN SELECT RAISE(ABORT,'second tape delete failed'); END")
        before = "\n".join(self.catalog.connection.iterdump())

        with self.assertRaisesRegex(sqlite3.IntegrityError, "second tape delete failed"):
            self.catalog.retire_managed_job("JOB1")

        self.assertEqual(before, "\n".join(self.catalog.connection.iterdump()))
        self.assert_integrity()

    def test_append_archive_failure_rolls_back_all_index_changes(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        with self.catalog.transaction() as db:
            db.execute(
                "INSERT INTO daemon_operations(id,kind,state,idempotency_key,"
                "principal,owner_generation,job_id,cassette_sequence,started_at) "
                "VALUES('append-op','archive.native','succeeded','append-key',"
                "'admin',1,'JOB1',1,'2026-09-06T00:00:00+00:00')"
            )
            db.execute(
                "INSERT INTO automatic_operation_blocks(block_id,operation_id,job_id,"
                "cassette_sequence,created_at) VALUES('BLOCK1','append-op','JOB1',1,"
                "'2026-09-06T00:00:00+00:00')"
            )
            db.execute("CREATE TRIGGER reject_archive BEFORE INSERT "
                       "ON automatic_operation_block_tombstones "
                       "BEGIN SELECT RAISE(ABORT,'archive failed'); END")
        before = "\n".join(self.catalog.connection.iterdump())

        with self.assertRaisesRegex(sqlite3.IntegrityError, "archive failed"):
            self.catalog.retire_managed_job("JOB1")

        self.assertEqual(before, "\n".join(self.catalog.connection.iterdump()))
        self.assert_integrity()

    def test_cleanup_history_failure_rolls_back_deletion_and_retirement(self):
        self.register("ONE001")
        self.block("BLOCK1")
        self.bind_legacy()
        with self.catalog.transaction() as db:
            db.execute("CREATE TRIGGER reject_cleanup_history BEFORE INSERT "
                       "ON job_management_history WHEN NEW.action='job.catalog_cleanup' "
                       "BEGIN SELECT RAISE(ABORT,'cleanup audit failed'); END")
        before = "\n".join(self.catalog.connection.iterdump())

        with self.assertRaisesRegex(sqlite3.IntegrityError, "cleanup audit failed"):
            self.catalog.retire_managed_job("JOB1")

        self.assertEqual(before, "\n".join(self.catalog.connection.iterdump()))
        self.assert_integrity()
