"""Real SQLite checks for the boundary-only suffix transaction."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.daemon.boundary_replan import BoundaryAssignment, BoundaryPlan
from ltobackup.daemon.boundary_store import BoundaryStore
from ltobackup.errors import CatalogError
from ltobackup.models import ScanItem, TapeBatch


class BoundaryStoreTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "catalog.db"
        self.factory = lambda: Catalog(self.database)
        with self.factory() as catalog:
            catalog.initialize(target_version=getattr(self, "catalog_target_version", None))
            catalog.add_library("LIB1", "Library", str(self.root))
            catalog.create_automatic_job(
                "JOB1",
                "LIB1",
                "TAPE0",
                "AUTO",
                [
                    ("TAPE01", "TAPE01", 1, 7),
                    ("TAPE02", "TAPE02", 1, 7),
                    ("TAPE03", "TAPE03", 0, 0),
                ],
                force_format=True,
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB1", 1, [("LIB1", "old", 7, 1)]
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB1", 2, [("LIB1", "obsolete", 7, 1)]
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
                db.execute(
                    "UPDATE automatic_jobs SET status='waiting_media',current_sequence=2 WHERE id='JOB1'"
                )
                db.execute(
                    "UPDATE automatic_cassettes SET status='waiting_media' WHERE job_id='JOB1' AND sequence=2"
                )
                db.execute(
                    "INSERT INTO daemon_operations(id,kind,state,idempotency_key,principal,owner_generation,job_id,cassette_sequence,started_at,finished_at) VALUES('OP1','archive.native','succeeded','op-key','admin',?,'JOB1',1,'2026-09-12T10:00:00+00:00','2026-09-12T10:10:00+00:00')",
                    (self.generation,),
                )
                for index, (kind, code) in enumerate(
                    (("unload", 0), ("probe_media", 3)), 1
                ):
                    at = f"2026-09-12T10:0{index}:00+00:00"
                    db.execute(
                        "INSERT INTO hardware_command_executions(id,operation_id,issued_generation,command_kind,argv_sha256,mount_path_sha256,tape_device_identity_sha256,scsi_device_identity_sha256,expected_media_scope_sha256,state,exit_outcome,created_at,exit_observed_at,quiesced_at,terminal_exit_code) VALUES(?,'OP1',?,?,?, ?,?,?,?,'quiesced','completed',?,?,?,?)",
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
        self.store = BoundaryStore(self.factory, self.generation)

    def ready_draft(self, snapshot, plan):
        created = datetime.now(UTC)
        with self.factory() as catalog:
            evidence = catalog.job_extension_evidence("JOB1")
            catalog.create_job_plan_draft(
                plan_id="PLAN1",
                kind="extend",
                creator="boundary-coordinator",
                library_ids=("LIB1",),
                media_key="LTO-6",
                created_at=created.isoformat(),
                expires_at=(created + timedelta(days=1)).isoformat(),
                base_job_id="JOB1",
                base_job_revision=evidence["revision"],
                base_job_fingerprint_sha256=evidence["fingerprint_sha256"],
            )
            payload = {
                "canonical_json_version": 1,
                "plan_schema_version": 1,
                "planner_version": "automatic-ltfs-v1",
                "application_settings_revision": 0,
                "application_settings_fingerprint_sha256": "a" * 64,
                "libraries": [
                    {
                        "sequence": 1,
                        "library_id": "LIB1",
                        "source_root": str(self.root),
                        "scan_revision": 0,
                        "scan_fingerprint_sha256": "a" * 64,
                    }
                ],
                "cassettes": [
                    {
                        "sequence": index,
                        "operation": "format",
                        "objects": len(assignment.items),
                        "payload_bytes": sum(item.size for item in assignment.items),
                        "allocation_bytes": sum(item.size for item in assignment.items),
                        "capacity_utilization": 0.01,
                        "items": [
                            {
                                "item_sequence": n,
                                "library_id": item.library_id,
                                "relative_path": item.relative_path,
                                "size": item.size,
                                "mtime_ns": item.mtime_ns,
                            }
                            for n, item in enumerate(assignment.items, 1)
                        ],
                    }
                    for index, assignment in enumerate(plan.assignments, 1)
                ],
            }
            canonical_payload = {
                "kind": "extend",
                "media_key": "LTO-6",
                "base_job": {
                    "fingerprint_sha256": evidence["fingerprint_sha256"],
                    "id": "JOB1",
                    "revision": evidence["revision"],
                },
                "canonical_json_version": 1,
                "plan_schema_version": 1,
                "planner_version": "automatic-ltfs-v1",
                "library_ids": ["LIB1"],
                "application_settings": {"revision": 0, "fingerprint_sha256": "a" * 64},
                "libraries": [
                    {key: value for key, value in row.items() if key != "sequence"}
                    for row in payload["libraries"]
                ],
                "cassettes": [
                    {
                        **row,
                        "items": [
                            {
                                key: value
                                for key, value in item.items()
                                if key != "item_sequence"
                            }
                            for item in row["items"]
                        ],
                    }
                    for row in payload["cassettes"]
                ],
            }
            canonical = json.dumps(
                canonical_payload, sort_keys=True, separators=(",", ":")
            )
            catalog.complete_job_plan_draft(
                "PLAN1",
                {
                    **payload,
                    "canonical_json": canonical,
                    "digest_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
                },
            )

    def plan(self):
        item = ScanItem(
            source_path=self.root / "new",
            relative_path="new",
            size=9,
            mtime_ns=2,
            library_id="LIB1",
        )
        return BoundaryPlan(
            1,
            (
                BoundaryAssignment(2, "TAPE02", (item,)),
                BoundaryAssignment(3, "TAPE03", ()),
            ),
            (),
        )

    def fingerprint(self):
        with self.factory() as catalog:
            return [
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT * FROM automatic_cassette_items ORDER BY sequence,item_sequence"
                )
            ], catalog.latest_layout_epoch("JOB1")

    def test_commit_changes_only_unstarted_suffix_and_keeps_authority_enabled(self):
        with self.factory() as catalog:
            prefix = tuple(catalog.list_automatic_cassettes("JOB1")[0])
            history = [
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT * FROM job_manifest_history"
                )
            ]
            old_epoch = catalog.latest_layout_epoch("JOB1")
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        result = self.store.commit(
            snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
        )
        self.assertEqual(2, result["epoch_number"])
        with self.factory() as catalog:
            self.assertEqual(prefix, tuple(catalog.list_automatic_cassettes("JOB1")[0]))
            self.assertEqual(
                history,
                [
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM job_manifest_history"
                    )
                ],
            )
            self.assertEqual(
                "new",
                catalog.list_automatic_cassette_manifest("JOB1", 2)[0]["relative_path"],
            )
            self.assertEqual(
                "enabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
            self.assertEqual(
                2, catalog.format_sequence_authorization("JOB1", 2)["layout_epoch"]
            )
            self.assertEqual(
                old_epoch,
                dict(
                    catalog.connection.execute(
                        "SELECT * FROM job_layout_epochs WHERE epoch_number=1"
                    ).fetchone()
                ),
            )
            self.assertFalse(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchall()
            )
            self.assertFalse(
                catalog.connection.execute("PRAGMA foreign_key_check").fetchall()
            )

    def test_status_alone_is_not_finalization_proof(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE hardware_command_executions SET terminal_exit_code=0 WHERE command_kind='probe_media'"
            )
        with self.assertRaises(CatalogError):
            self.store.capture("JOB1")

    def reassigned_suffix_plan(self, *, swap):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_cassettes SET planned_files=1,planned_bytes=7 "
                "WHERE job_id='JOB1' AND sequence=3"
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB1", 3, [("LIB1", "later", 7, 1)]
            )
        later = ScanItem(self.root / "later", "later", 7, 1, library_id="LIB1")
        earlier = ScanItem(self.root / "obsolete", "obsolete", 7, 1, library_id="LIB1")
        return BoundaryPlan(
            1,
            (
                BoundaryAssignment(2, "TAPE02", (later,)),
                BoundaryAssignment(3, "TAPE03", (earlier,) if swap else ()),
            ),
            (),
        )

    def boundary_persisted_state(self):
        tables = (
            "automatic_cassettes", "automatic_cassette_items", "blocks", "file_versions",
            "job_manifest_history", "job_layout_epochs", "job_layout_targets",
            "automatic_sequence_state", "automatic_format_authorizations",
            "job_management_state", "job_management_history", "job_plan_drafts",
            "job_incremental_scan_leases",
        )
        with self.factory() as catalog:
            return {
                table: [tuple(row) for row in catalog.connection.execute(
                    f"SELECT * FROM {table} ORDER BY rowid"
                )]
                for table in tables
            }

    def assert_suffix_reassignment(self, *, swap):
        plan = self.reassigned_suffix_plan(swap=swap)
        before = self.boundary_persisted_state()
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, plan)
        self.store.commit(snapshot, plan, creation_plan_id="PLAN1", managed_evidence={})
        after = self.boundary_persisted_state()
        for table in ("blocks", "file_versions", "job_manifest_history"):
            self.assertEqual(before[table], after[table], table)
        self.assertEqual(before["automatic_cassettes"][0], after["automatic_cassettes"][0])
        self.assertEqual(before["job_layout_epochs"][0], after["job_layout_epochs"][0])
        with self.factory() as catalog:
            expected = [(2, "later")]
            if swap:
                expected.append((3, "obsolete"))
            self.assertEqual(expected, [tuple(row) for row in catalog.connection.execute(
                "SELECT sequence,relative_path FROM automatic_cassette_items "
                "WHERE job_id='JOB1' ORDER BY sequence,item_sequence"
            )])
            self.assertEqual(2, catalog.latest_layout_epoch("JOB1")["epoch_number"])
            self.assertEqual("enabled", catalog.automatic_sequence_state("JOB1")["state"])
            self.assertFalse(catalog.connection.execute("PRAGMA foreign_key_check").fetchall())

    def test_later_unused_file_can_move_to_earlier_cassette(self):
        self.assert_suffix_reassignment(swap=False)

    def test_unused_cassettes_can_swap_existing_files(self):
        self.assert_suffix_reassignment(swap=True)

    def test_later_insert_failure_restores_entire_original_suffix(self):
        plan = self.reassigned_suffix_plan(swap=True)
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, plan)
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "CREATE TRIGGER fail_later_suffix_insert BEFORE INSERT ON automatic_cassette_items "
                "WHEN NEW.job_id='JOB1' AND NEW.sequence=3 "
                "BEGIN SELECT RAISE(ABORT,'injected later suffix failure'); END"
            )
        before = self.boundary_persisted_state()
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected later suffix failure"):
            self.store.commit(snapshot, plan, creation_plan_id="PLAN1", managed_evidence={})
        self.assertEqual(before, self.boundary_persisted_state())

    def test_prior_attempt_prevents_suffix_rewrite(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "INSERT INTO daemon_operations(id,kind,state,idempotency_key,principal,owner_generation,job_id,cassette_sequence,started_at,finished_at) VALUES('OP2','archive.native','failed','op-key2','admin',?,'JOB1',2,'2026-09-12T11:00:00+00:00','2026-09-12T11:01:00+00:00')",
                (self.generation,),
            )
        with self.assertRaises(CatalogError):
            self.store.capture("JOB1")

    def test_concurrent_revision_change_rolls_back_and_release_is_explicit(self):
        snapshot = self.store.capture("JOB1")
        before = self.fingerprint()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE job_management_state SET revision=revision+1 WHERE job_id='JOB1'"
            )
        with self.assertRaises(CatalogError):
            self.store.commit(
                snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
            )
        self.assertEqual(before, self.fingerprint())
        self.store.release(snapshot, "stale_state")
        with self.factory() as catalog:
            self.assertFalse(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchall()
            )

    def test_boundary_is_applied_only_once(self):
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        self.store.commit(
            snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
        )
        before = self.fingerprint()
        with self.assertRaisesRegex(CatalogError, "already_applied"):
            self.store.capture("JOB1")
        self.assertEqual(before, self.fingerprint())

    def test_shared_lease_blocks_second_capture(self):
        snapshot = self.store.capture("JOB1")
        with self.assertRaises(CatalogError):
            self.store.capture("JOB1")
        self.store.release(snapshot, "source_unavailable")
        self.assertNotEqual(snapshot.run_id, self.store.capture("JOB1").run_id)

    def test_explicit_pause_is_not_cleared(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
            db.execute(
                "UPDATE automatic_sequence_state SET state='disabled' WHERE job_id='JOB1'"
            )
            db.execute(
                "UPDATE job_management_state SET pause_requested_at='2026-09-12T11:00:00+00:00',pause_acknowledged_at='2026-09-12T11:00:00+00:00' WHERE job_id='JOB1'"
            )
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        self.store.commit(
            snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
        )
        with self.factory() as catalog:
            self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
            self.assertEqual(
                "disabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
            self.assertIsNotNone(
                catalog.job_management_state("JOB1")["pause_requested_at"]
            )

    def test_missing_old_authority_rejects_without_minting_consent(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_cassettes SET reuse_registered=1 WHERE sequence=2"
            )
        with self.assertRaises(CatalogError):
            self.store.capture("JOB1")

    def test_fence_change_invalidates_capture(self):
        snapshot = self.store.capture("JOB1")
        with self.factory() as catalog:
            catalog.claim_daemon_owner("replacement-owner")
        before = self.fingerprint()
        with self.assertRaises(CatalogError):
            self.store.commit(
                snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
            )
        self.assertEqual(before, self.fingerprint())

    def test_label_mapping_change_is_rejected(self):
        snapshot = self.store.capture("JOB1")
        plan = BoundaryPlan(
            1,
            (BoundaryAssignment(2, "OTHER1", ()), BoundaryAssignment(3, "TAPE03", ())),
            (),
        )
        before = self.fingerprint()
        with self.assertRaises(CatalogError):
            self.store.commit(
                snapshot, plan, creation_plan_id="PLAN1", managed_evidence={}
            )
        self.assertEqual(before, self.fingerprint())

    def test_transaction_failure_restores_old_manifest_epoch_and_lease(self):
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        before = self.fingerprint()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "CREATE TRIGGER fail_boundary_history BEFORE INSERT ON job_management_history WHEN NEW.action='job.boundary_replan.applied' BEGIN SELECT RAISE(ABORT,'injected ledger failure'); END"
            )
        with self.assertRaisesRegex(sqlite3.IntegrityError, "injected ledger"):
            self.store.commit(
                snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
            )
        self.assertEqual(before, self.fingerprint())
        with self.factory() as catalog:
            self.assertEqual("ready", catalog.get_job_plan("PLAN1")["state"])
            self.assertEqual(
                snapshot.run_id,
                catalog.connection.execute(
                    "SELECT run_id FROM job_incremental_scan_leases"
                ).fetchone()[0],
            )

    def test_failed_terminal_operation_is_not_success_boundary(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE daemon_operations SET state='failed' WHERE id='OP1'")
        with self.assertRaises(CatalogError):
            self.store.capture("JOB1")

    def test_completed_status_without_catalog_data_is_not_a_boundary(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE blocks SET visible=0 WHERE id='BLOCK1'")
        with self.assertRaisesRegex(CatalogError, "catalog"):
            self.store.capture("JOB1")

    def test_pause_pending_is_not_advanced_to_another_cassette(self):
        with self.factory() as catalog:
            catalog.request_job_pause("JOB1", "admin")
        with self.assertRaisesRegex(CatalogError, "pause_pending"):
            self.store.capture("JOB1")

    def test_source_metadata_changed_after_snapshot_prevents_commit(self):
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE libraries SET source_root=? WHERE id='LIB1'",
                (str(self.root / "changed"),),
            )
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            self.store.commit(
                snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
            )

    def test_label_deficit_retains_every_item_and_blocks_old_layout_admission(self):
        snapshot = self.store.capture("JOB1")
        extra = ScanItem(
            self.root / "overflow",
            "overflow",
            15,
            2,
            library_id="LIB1",
            source_identity=(1, 2, 3, 15, 2),
        )
        plan = BoundaryPlan(1, self.plan().assignments, (TapeBatch(3, (extra,), 100),))
        self.assertTrue(
            hasattr(self.store, "retain_pending"), "durable deficit retention missing"
        )
        result = self.store.retain_pending(snapshot, plan)
        self.assertEqual("waiting_labels", result["state"])
        self.assertEqual(1, result["required_additional_labels"])
        with self.factory() as catalog:
            rows = [
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT relative_path,size FROM automatic_cassette_items WHERE job_id='JOB1'"
                )
            ]
            self.assertEqual([("obsolete", 7)], rows)
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertEqual(
                snapshot.run_id,
                catalog.connection.execute(
                    "SELECT run_id FROM job_incremental_scan_leases WHERE job_id='JOB1'"
                ).fetchone()[0],
            )
        pending = BoundaryStore(self.factory, self.generation).pending("JOB1")
        self.assertEqual(snapshot.state_json, pending["snapshot"]["state_json"])
        self.assertEqual(
            "new", pending["plan"]["assignments"][0]["items"][0]["relative_path"]
        )
        overflow = pending["plan"]["unassigned_batches"][0]["items"][0]
        self.assertEqual(
            ("overflow", 15, [1, 2, 3, 15, 2]),
            (overflow["relative_path"], overflow["size"], overflow["source_identity"]),
        )

    def test_stale_snapshot_cannot_publish_a_waiting_label_candidate(self):
        snapshot = self.store.capture("JOB1")
        plan = BoundaryPlan(
            1,
            self.plan().assignments,
            (TapeBatch(3, self.plan().assignments[0].items, 100),),
        )
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE libraries SET enabled=0 WHERE id='LIB1'")
        self.assertTrue(
            hasattr(self.store, "retain_pending"), "durable deficit retention missing"
        )
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            self.store.retain_pending(snapshot, plan)

    def test_pending_deficit_blocks_resume_even_after_daemon_reclaims_scan_leases(self):
        from ltobackup.daemon.models import (
            HardwareTargetBinding,
            MutationAdmissionClosed,
        )
        from ltobackup.daemon.operations import OperationManager
        from tests.test_sequence_coordinator import _HoldingExecutor

        snapshot = self.store.capture("JOB1")
        extra = ScanItem(self.root / "extra", "extra", 15, 2, library_id="LIB1")
        self.store.retain_pending(
            snapshot,
            BoundaryPlan(1, self.plan().assignments, (TapeBatch(3, (extra,), 100),)),
        )
        with self.factory() as catalog:
            owner = catalog.claim_daemon_owner("replacement")
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchone()
            )
        manager = OperationManager(self.factory, owner, executor=_HoldingExecutor())
        with self.assertRaises(MutationAdmissionClosed):
            manager.start(
                "archive.native",
                "pending-manual-resume",
                "admin",
                lambda _context: None,
                job_id="JOB1",
                cassette_sequence=2,
                hardware_target=HardwareTargetBinding.from_verified_inputs(
                    self.root / "tape",
                    "tape",
                    "scsi",
                    ("archive.native", "JOB1", "2", "TAPE02", "", ""),
                ),
            )
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())

    def test_unresolved_deficit_cannot_be_overwritten_by_ready_candidate(self):
        snapshot = self.store.capture("JOB1")
        plan = self.plan()
        self.store.retain_pending(
            snapshot,
            BoundaryPlan(
                1, plan.assignments, (TapeBatch(3, plan.assignments[0].items, 100),)
            ),
        )
        retained = self.store.pending("JOB1")
        self.ready_draft(snapshot, plan)
        with self.assertRaisesRegex(
            CatalogError, "boundary_pending_resolution_required"
        ):
            self.store.commit(
                snapshot, plan, creation_plan_id="PLAN1", managed_evidence={}
            )
        self.assertEqual(retained, self.store.pending("JOB1"))

    def test_restart_cannot_rescan_over_unresolved_deficit(self):
        snapshot = self.store.capture("JOB1")
        plan = self.plan()
        self.store.retain_pending(
            snapshot,
            BoundaryPlan(
                1, plan.assignments, (TapeBatch(3, plan.assignments[0].items, 100),)
            ),
        )
        retained = self.store.pending("JOB1")
        with self.factory() as catalog:
            owner = catalog.claim_daemon_owner("replacement")
        restarted = BoundaryStore(self.factory, owner.generation)
        with self.assertRaisesRegex(
            CatalogError, "boundary_pending_resolution_required"
        ):
            restarted.capture("JOB1")
        self.assertEqual(retained, restarted.pending("JOB1"))

    def test_pending_retry_cannot_drop_retained_overflow_at_commit(self):
        original = self.store.capture("JOB1")
        plan = self.plan()
        extra = ScanItem(self.root / "extra", "extra", 15, 2, library_id="LIB1")
        self.store.retain_pending(
            original,
            BoundaryPlan(1, plan.assignments, (TapeBatch(3, (extra,), 100),)),
        )
        snapshot, pending = self.store.claim_pending("JOB1")
        self.ready_draft(snapshot, plan)
        with self.assertRaisesRegex(CatalogError, "pending_items_changed"):
            self.store.commit(
                snapshot, plan, creation_plan_id="PLAN1", managed_evidence={}
            )
        self.assertEqual(pending, self.store.pending("JOB1"))

    def test_terminal_boundary_can_continue_into_existing_authorized_reserve(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_sequence_state SET state='completed' WHERE job_id='JOB1'"
            )
            db.execute(
                "UPDATE automatic_jobs SET status='completed',current_sequence=1 WHERE id='JOB1'"
            )
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        self.store.commit(
            snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
        )
        with self.factory() as catalog:
            self.assertEqual(
                "enabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
            self.assertIsNotNone(catalog.next_automatic_sequence_candidate())

    def test_ordinary_extension_cannot_consume_boundary_owned_draft(self):
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        with self.factory() as catalog:
            draft = catalog.get_job_plan("PLAN1")
            with self.assertRaisesRegex(CatalogError, "boundary_plan_reserved"):
                catalog.consume_extension_plan(
                    plan_id="PLAN1",
                    digest_sha256=draft["digest_sha256"],
                    labels=(),
                    idempotency_key="steal",
                    request_sha256="b" * 64,
                    job_id="JOB1",
                    consumed_at=datetime.now(UTC).isoformat(),
                    expected_revision=snapshot.revision,
                    actor="admin",
                    authorize_automatic_formatting=True,
                )

    def test_job_creation_cannot_consume_boundary_owned_draft(self):
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        with self.factory() as catalog:
            draft = catalog.get_job_plan("PLAN1")
            with self.assertRaisesRegex(CatalogError, "boundary_plan_reserved"):
                catalog.consume_job_plan(
                    plan_id="PLAN1",
                    digest_sha256=draft["digest_sha256"],
                    labels=("TAPE02", "TAPE03"),
                    idempotency_key="steal-create",
                    request_sha256="b" * 64,
                    job_id="OTHER",
                    display_name="Other",
                    device_name="TAPE0",
                    mount_path="AUTO",
                    actor="admin",
                    consumed_at=datetime.now(UTC).isoformat(),
                    authorize_automatic_formatting=True,
                )
            self.assertEqual("ready", catalog.get_job_plan("PLAN1")["state"])
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT id FROM automatic_jobs WHERE id='OTHER'"
                ).fetchone()
            )

    def test_terminal_boundary_does_not_invent_enable_authority(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_sequence_state SET state='completed',enabled_by=NULL,enabled_at=NULL WHERE job_id='JOB1'"
            )
            db.execute(
                "UPDATE automatic_jobs SET status='completed',current_sequence=1 WHERE id='JOB1'"
            )
        snapshot = self.store.capture("JOB1")
        self.ready_draft(snapshot, self.plan())
        self.store.commit(
            snapshot, self.plan(), creation_plan_id="PLAN1", managed_evidence={}
        )
        with self.factory() as catalog:
            self.assertEqual(
                "disabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
