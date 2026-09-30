"""Terminal cassette-boundary completion without a fabricated suffix plan."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.daemon.boundary_coordinator import (
    BoundaryReplanCoordinator,
    BoundarySources,
)
from ltobackup.daemon.boundary_store import BoundaryStore
from ltobackup.errors import CatalogError, ValidationError


class TerminalBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "old").write_bytes(b"olddata")
        os.utime(self.source / "old", ns=(1, 1))
        self.database = self.root / "catalog.db"
        self.factory = lambda: Catalog(self.database)
        self.verify_calls = 0
        self.changed_identity_at: int | None = None
        policy = {
            "settings_revision": 1,
            "selected_media_profile": "LTO-6",
            "default_media_profile": "LTO-6",
            "capacity_reserve_bytes": 100_000_000,
            "minimum_source_file_age_seconds": 0,
            "tape_root_directory": "lto",
            "content_verification_policy": "metadata",
        }
        encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        with self.factory() as catalog:
            catalog.initialize()
            catalog.add_library("LIB1", "Library", str(self.source))
            catalog.create_automatic_job(
                "JOB1",
                "LIB1",
                "TAPE0",
                "AUTO",
                [("TAPE01", "TAPE01", 1, 7)],
                force_format=True,
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB1", 1, [("LIB1", "old", 7, 1)]
            )
            epoch = catalog.latest_layout_epoch("JOB1")
            catalog.authorize_automatic_format_sequence(
                "JOB1",
                expected_revision=0,
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="admin",
                idempotency_key="grant",
                authorized_at="2026-09-12T10:00:00+00:00",
            )
            state = catalog.automatic_sequence_state("JOB1")
            catalog.set_automatic_sequence_enabled(
                "JOB1",
                expected_revision=state["revision"],
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="admin",
                enabled_at="2026-09-12T10:00:00+00:00",
            )
            self.generation = catalog.claim_daemon_owner("owner").generation
            catalog.register_tape("TAPE01", "TAPE01", "Tape", "LTFS", "/tape")
            catalog.create_block("BLOCK1", "LIB1", "TAPE01", "blocks/BLOCK1", 1, 7)
            catalog.record_file_version(
                "LIB1",
                "BLOCK1",
                "TAPE01",
                "old",
                "blocks/BLOCK1/files/old",
                7,
                1,
                "a" * 64,
            )
            catalog.complete_block("BLOCK1")
            catalog.update_automatic_cassette(
                "JOB1",
                1,
                "completed",
                tape_id="TAPE01",
                block_id="BLOCK1",
                copied_files=1,
                copied_bytes=7,
            )
            with catalog.transaction() as db:
                now = "2026-09-12T10:10:00+00:00"
                db.execute(
                    "UPDATE automatic_jobs SET status='completed',current_sequence=1,completed_at=? WHERE id='JOB1'",
                    (now,),
                )
                db.execute(
                    "UPDATE automatic_sequence_state SET state='completed' WHERE job_id='JOB1'"
                )
                db.execute(
                    "INSERT INTO job_policy_snapshots(job_id,settings_revision,policy_json,policy_sha256,created_at) VALUES('JOB1',1,?,?,?)",
                    (encoded, hashlib.sha256(encoded.encode()).hexdigest(), now),
                )
                db.execute(
                    "INSERT INTO daemon_operations(id,kind,state,idempotency_key,principal,owner_generation,job_id,cassette_sequence,started_at,finished_at) VALUES('OP1','archive.native','succeeded','op-key','admin',?,'JOB1',1,'2026-09-12T10:00:00+00:00',?)",
                    (self.generation, now),
                )
                for index, (kind, code) in enumerate(
                    (("unload", 0), ("probe_media", 3)), 1
                ):
                    at = f"2026-09-12T10:1{index}:00+00:00"
                    db.execute(
                        "INSERT INTO hardware_command_executions(id,operation_id,issued_generation,command_kind,argv_sha256,mount_path_sha256,tape_device_identity_sha256,scsi_device_identity_sha256,expected_media_scope_sha256,state,exit_outcome,created_at,exit_observed_at,quiesced_at,terminal_exit_code) VALUES(?,'OP1',?,?,?,?,?,?,?,'quiesced','completed',?,?,?,?)",
                        (
                            f"CMD{index}",
                            self.generation,
                            kind,
                            *(["a" * 64] * 5),
                            at,
                            at,
                            at,
                            code,
                        ),
                    )

    @contextmanager
    def sources(self, snapshot, *, phase, plan_id):
        self.assertEqual("plan", phase)
        with self.factory() as catalog:
            lease = catalog.connection.execute(
                "SELECT run_id FROM job_incremental_scan_leases WHERE job_id='JOB1'"
            ).fetchone()
            self.assertEqual(snapshot.run_id, lease[0])

        def verify(_library):
            self.verify_calls += 1
            if self.verify_calls == self.changed_identity_at:
                changed = self.root / "changed"
                changed.mkdir(exist_ok=True)
                return str(changed), "b" * 64
            return str(self.source), "a" * 64

        yield BoundarySources(verify_library=verify)

    def refresh(self) -> dict:
        return BoundaryReplanCoordinator(
            self.factory,
            daemon_generation=self.generation,
            source_context=self.sources,
        ).refresh("JOB1")

    def rows(self, table: str) -> list[tuple]:
        with self.factory() as catalog:
            return [
                tuple(row)
                for row in catalog.connection.execute(
                    f"SELECT * FROM {table} ORDER BY rowid"
                )
            ]

    def history(self) -> list[tuple[str, str, dict]]:
        with self.factory() as catalog:
            return [
                (row["action"], row["checkpoint"], json.loads(row["payload_json"]))
                for row in catalog.connection.execute(
                    "SELECT action,checkpoint,payload_json FROM job_management_history WHERE job_id='JOB1' ORDER BY id"
                )
            ]

    def test_empty_scan_after_final_cassette_records_no_change_without_plan_or_epoch(
        self,
    ) -> None:
        immutable_tables = (
            "automatic_cassettes",
            "automatic_cassette_items",
            "blocks",
            "file_versions",
            "job_layout_epochs",
            "job_layout_targets",
            "automatic_format_authorizations",
        )
        before = {table: self.rows(table) for table in immutable_tables}

        result = self.refresh()

        self.assertEqual("applied", result["state"])
        self.assertEqual("no_change", result["outcome"])
        self.assertIsNone(result["next_sequence"])
        self.assertNotIn("creation_plan_id", result)
        self.assertEqual(before, {table: self.rows(table) for table in immutable_tables})
        with self.factory() as catalog:
            self.assertEqual("completed", catalog.get_automatic_job("JOB1")["status"])
            self.assertEqual(
                "completed", catalog.automatic_sequence_state("JOB1")["state"]
            )
            self.assertEqual([], catalog.connection.execute("SELECT * FROM job_plan_drafts").fetchall())
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT 1 FROM job_incremental_scan_leases WHERE job_id='JOB1'"
                ).fetchone()
            )
        applied = [row for row in self.history() if row[0] == "job.boundary_replan.applied"]
        self.assertEqual(1, len(applied))
        self.assertEqual("boundary_no_change", applied[0][1])
        self.assertEqual("no_change", applied[0][2]["outcome"])
        with self.assertRaisesRegex(CatalogError, "already_applied"):
            BoundaryStore(self.factory, self.generation).capture("JOB1")

    def test_new_file_after_final_cassette_retains_overflow(self) -> None:
        (self.source / "new").write_bytes(b"new data!")
        epoch_before = self.rows("job_layout_epochs")

        result = self.refresh()

        self.assertEqual("waiting_labels", result["state"])
        self.assertEqual(1, result["required_additional_labels"])
        pending = BoundaryStore(self.factory, self.generation).pending("JOB1")
        self.assertEqual(
            ["new"],
            [
                item["relative_path"]
                for batch in pending["plan"]["unassigned_batches"]
                for item in batch["items"]
            ],
        )
        self.assertEqual(epoch_before, self.rows("job_layout_epochs"))
        self.assertFalse(
            any(row[0] == "job.boundary_replan.applied" for row in self.history())
        )

    def test_missing_source_after_final_cassette_records_failure_not_applied(self) -> None:
        self.source.rename(self.root / "unavailable")

        with self.assertRaises((OSError, ValidationError)):
            self.refresh()

        boundary = [row for row in self.history() if row[0].startswith("job.boundary_replan.")]
        self.assertEqual(
            ["job.boundary_replan.claimed", "job.boundary_replan.failed"],
            [row[0] for row in boundary],
        )
        self.assertEqual("boundary_refresh_failed", boundary[-1][1])
        self.assertFalse(any(row[0] == "job.boundary_replan.applied" for row in boundary))

    def test_terminal_no_change_reverifies_root_before_recording_success(self) -> None:
        # scan_boundary_sources verifies this single root three times; terminal
        # completion must verify it once more while the scan lease is still held.
        self.changed_identity_at = 4

        with self.assertRaisesRegex(ValidationError, "source root changed"):
            self.refresh()

        self.assertEqual(4, self.verify_calls)
        self.assertFalse(
            any(row[0] == "job.boundary_replan.applied" for row in self.history())
        )

    def test_terminal_no_change_preserves_acknowledged_pause_and_disabled_state(
        self,
    ) -> None:
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
            db.execute(
                "UPDATE automatic_sequence_state SET state='disabled' WHERE job_id='JOB1'"
            )
            db.execute(
                "UPDATE job_management_state SET pause_requested_at='2026-09-12T10:20:00+00:00',pause_acknowledged_at='2026-09-12T10:21:00+00:00',current_checkpoint='unloaded' WHERE job_id='JOB1'"
            )

        result = self.refresh()

        self.assertEqual("no_change", result["outcome"])
        with self.factory() as catalog:
            self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
            self.assertEqual(
                "disabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
            management = catalog.job_management_state("JOB1")
            self.assertEqual(
                "2026-09-12T10:20:00+00:00", management["pause_requested_at"]
            )
            self.assertEqual(
                "2026-09-12T10:21:00+00:00", management["pause_acknowledged_at"]
            )


if __name__ == "__main__":
    unittest.main()
