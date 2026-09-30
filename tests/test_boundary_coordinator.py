"""One real filesystem scan through canonical publication and SQLite commit."""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import sqlite3
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from unittest.mock import patch

from ltobackup.daemon import boundary_replan
from ltobackup.errors import CatalogError, ValidationError
from tests import test_boundary_store


class BoundaryCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_store.BoundaryStoreTests()
        self.fixture.catalog_target_version = getattr(self, "catalog_target_version", None)
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.source = self.fixture.root / "source"
        self.source.mkdir()
        # The catalog fixture's completed version is seven bytes at mtime 1.
        (self.source / "old").write_bytes(b"olddata")
        os.utime(self.source / "old", ns=(1, 1))
        (self.source / "new").write_bytes(b"new data!")
        self.policy = {
            "settings_revision": 1,
            "selected_media_profile": "LTO-6",
            "default_media_profile": "LTO-6",
            "capacity_reserve_bytes": getattr(
                self, "capacity_reserve_bytes", 100_000_000
            ),
            "minimum_source_file_age_seconds": 0,
            "tape_root_directory": "lto",
            "content_verification_policy": "metadata",
        }
        policy_json = json.dumps(self.policy, sort_keys=True, separators=(",", ":"))
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE libraries SET source_root=? WHERE id='LIB1'",
                (str(self.source),),
            )
            db.execute(
                "INSERT INTO job_policy_snapshots(job_id,settings_revision,policy_json,policy_sha256,created_at) VALUES('JOB1',1,?,?,?)",
                (
                    policy_json,
                    hashlib.sha256(policy_json.encode()).hexdigest(),
                    datetime.now(UTC).isoformat(),
                ),
            )
        self.on_save = lambda: None
        self.root_info = self.source.stat()

    def module(self):
        name = "ltobackup.daemon.boundary_coordinator"
        self.assertIsNotNone(
            importlib.util.find_spec(name), "boundary coordinator missing"
        )
        return importlib.import_module(name)

    @contextmanager
    def sources(self, snapshot, *, phase, plan_id):
        with self.factory() as catalog:
            lease = catalog.connection.execute(
                "SELECT run_id FROM job_incremental_scan_leases WHERE job_id='JOB1'"
            ).fetchone()
            self.assertEqual(
                snapshot.run_id, lease[0], "filesystem I/O must be fenced first"
            )
            if phase == "save":
                self.assertEqual("building", catalog.get_job_plan(plan_id)["state"])
        if phase == "save":
            self.on_save()

        def verify(library):
            root = self.source.stat()
            if (root.st_dev, root.st_ino) != (
                self.root_info.st_dev,
                self.root_info.st_ino,
            ):
                raise ValidationError("source identity changed")
            return str(self.source), "a" * 64

        yield self.module().BoundarySources(verify_library=verify)

    def refresh(self):
        return (
            self.module()
            .BoundaryReplanCoordinator(
                self.factory,
                daemon_generation=self.fixture.generation,
                source_context=self.sources,
            )
            .refresh("JOB1")
        )

    def manifest(self):
        with self.factory() as catalog:
            return [
                tuple(row)
                for row in catalog.connection.execute(
                    "SELECT sequence,relative_path,size FROM automatic_cassette_items WHERE job_id='JOB1' ORDER BY sequence,item_sequence"
                )
            ]

    def test_one_scan_publishes_suffix_and_preserves_completed_catalog(self):
        with self.factory() as catalog:
            versions_before = [
                tuple(row)
                for row in catalog.connection.execute("SELECT * FROM file_versions")
            ]
        calls = 0
        analyze = boundary_replan.analyze_library

        def once(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise AssertionError("publication must not scan a second time")
            return analyze(*args, **kwargs)

        with patch.object(boundary_replan, "analyze_library", once):
            result = self.refresh()
        # Normal completion has already cleared the old working manifest;
        # its immutable blocks/file versions above must remain unchanged.
        self.assertEqual([(2, "new", 9)], self.manifest())
        self.assertEqual(2, result["next_sequence"])
        with self.factory() as catalog:
            self.assertEqual(
                versions_before,
                [
                    tuple(row)
                    for row in catalog.connection.execute("SELECT * FROM file_versions")
                ],
            )
            self.assertEqual(
                "consumed", catalog.get_job_plan(result["creation_plan_id"])["state"]
            )
            self.assertEqual(
                2, catalog.next_automatic_sequence_candidate()["cassette_sequence"]
            )
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchone()
            )

    def test_failed_publications_retire_only_their_abandoned_drafts(self):
        before = self.manifest()
        with self.factory() as catalog, catalog.transaction() as db:
            archived = [tuple(row) for row in db.execute("SELECT * FROM file_versions")]
            db.execute(
                "CREATE TRIGGER reject_publication BEFORE INSERT ON job_management_history "
                "WHEN NEW.action='job.boundary_replan.applied' "
                "BEGIN SELECT RAISE(ABORT,'publication unavailable'); END"
            )
        for _ in range(3):
            with self.assertRaisesRegex(sqlite3.IntegrityError, "publication unavailable"):
                self.refresh()
            with self.factory() as catalog:
                self.assertEqual(0, catalog.connection.execute(
                    "SELECT COUNT(*) FROM job_plan_drafts"
                ).fetchone()[0], "failed retries must not retain complete manifests")
                self.assertEqual(0, catalog.connection.execute(
                    "SELECT COUNT(*) FROM job_plan_items"
                ).fetchone()[0])
                self.assertEqual(archived, [tuple(row) for row in catalog.connection.execute(
                    "SELECT * FROM file_versions"
                )])
            self.assertEqual(before, self.manifest())
        with self.factory() as catalog:
            retired = [json.loads(row[0]) for row in catalog.connection.execute(
                "SELECT payload_json FROM job_management_history "
                "WHERE action='job.boundary_replan.draft_retired'"
            )]
            self.assertEqual(3, len(retired))
            self.assertTrue(all(len(row['digest_sha256']) == 64 for row in retired))
            self.assertTrue(all(row['files'] == 1 for row in retired))
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("DROP TRIGGER reject_publication")
        result = self.refresh()
        with self.factory() as catalog:
            self.assertEqual('consumed', catalog.get_job_plan(result['creation_plan_id'])['state'])
        self.assertEqual([(2, 'new', 9)], self.manifest())

    def test_refresh_then_normal_admission_uses_new_epoch_and_manifest(self):
        from ltobackup.daemon.models import HardwareTargetBinding
        from ltobackup.daemon.operations import OperationManager
        from ltobackup.daemon.sequence_coordinator import NativeSequenceCoordinator
        from tests.test_sequence_coordinator import _HoldingExecutor

        with self.factory() as catalog:
            fence = catalog.current_daemon_fence()
            old_fingerprint = catalog.latest_layout_epoch("JOB1")[
                "layout_fingerprint_sha256"
            ]
        manager = OperationManager(self.factory, fence, executor=_HoldingExecutor())
        refresh_result = []

        def refresh_boundary():
            refresh_result.append(self.refresh())
            return True

        def admit(candidate):
            return manager.start(
                "archive.native",
                candidate.idempotency_key,
                "sequence-coordinator",
                lambda _context: self.fail("test must never write hardware"),
                job_id=candidate.job_id,
                cassette_sequence=candidate.cassette_sequence,
                hardware_target=HardwareTargetBinding.from_verified_inputs(
                    self.fixture.root / "tape",
                    "tape-one",
                    "scsi-one",
                    ("archive.native", "JOB1", "2", "TAPE02", "", ""),
                ),
                sequence_authorization_id=candidate.authorization_id,
                sequence_layout_fingerprint_sha256=candidate.layout_fingerprint_sha256,
            )

        coordinator = NativeSequenceCoordinator(
            self.factory,
            daemon_generation=fence.generation,
            admit=admit,
            reconcile_boundary=refresh_boundary,
        )
        operation = coordinator.reconcile_once()
        self.assertIsNotNone(operation)
        self.assertEqual(2, operation.cassette_sequence)
        self.assertNotEqual(
            old_fingerprint, refresh_result[0]["layout_fingerprint_sha256"]
        )
        self.assertEqual([(2, "new", 9)], self.manifest())
        self.assertIsNone(coordinator.reconcile_once())
        self.assertEqual(1, len(refresh_result))
        with self.factory() as catalog:
            rows = catalog.connection.execute(
                "SELECT cassette_sequence FROM daemon_operations WHERE state='running'"
            ).fetchall()
            self.assertEqual([(2,)], [tuple(row) for row in rows])

    def test_file_changed_after_scan_does_not_replace_layout(self):
        before = self.manifest()
        self.on_save = lambda: (self.source / "new").write_bytes(b"changed")
        with self.assertRaisesRegex(ValidationError, "source.*changed"):
            self.refresh()
        self.assertEqual(before, self.manifest())
        with self.factory() as catalog:
            self.assertIsNone(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchone()
            )

    def test_pending_pause_never_enters_filesystem_scan(self):
        with self.factory() as catalog:
            catalog.request_job_pause("JOB1", "admin")
        with self.assertRaisesRegex(CatalogError, "pause_pending"):
            self.refresh()

    def test_missing_root_does_not_turn_into_empty_success(self):
        before = self.manifest()
        self.source.rename(self.fixture.root / "unavailable")
        with self.assertRaises(OSError):
            self.refresh()
        self.assertEqual(before, self.manifest())

    def test_empty_success_preserves_completed_prefix_and_finishes_job(self):
        (self.source / "new").unlink()
        result = self.refresh()
        self.assertEqual([], self.manifest())
        self.assertIsNone(result["next_sequence"])
        with self.factory() as catalog:
            self.assertEqual("completed", catalog.get_automatic_job("JOB1")["status"])

    def test_archived_only_refresh_does_not_collect_discarded_metadata(self):
        (self.source / "new").unlink()
        with patch(
            "ltobackup.scanner.collect_file_metadata",
            side_effect=AssertionError("unused metadata read"),
        ):
            result = self.refresh()
        self.assertIsNone(result["next_sequence"])

    def test_pause_requested_during_scan_preserves_original_pending_layout(self):
        before = self.manifest()

        def pause():
            with self.factory() as catalog:
                catalog.request_job_pause("JOB1", "admin")

        self.on_save = pause
        with self.assertRaisesRegex(CatalogError, "pause_pending"):
            self.refresh()
        self.assertEqual(before, self.manifest())
        with self.factory() as catalog:
            self.assertEqual(
                "pause_pending", catalog.automatic_sequence_state("JOB1")["state"]
            )

    def test_job_scan_lease_loss_prevents_publication_commit(self):
        before = self.manifest()

        def lose_lease():
            with self.factory() as catalog, catalog.transaction() as db:
                db.execute(
                    "DELETE FROM job_incremental_scan_leases WHERE job_id='JOB1'"
                )

        self.on_save = lose_lease
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            self.refresh()
        self.assertEqual(before, self.manifest())

    def test_network_scan_publication_and_commit_preserve_original_job_pins(self):
        from tests import test_boundary_sources

        network = test_boundary_sources.BoundarySourceTests()
        network.setUp()
        self.addCleanup(network.doCleanups)
        local = network.fixture.root / "local"
        local.mkdir()
        (network.fixture.root / "net1" / "first").write_bytes(b"first")
        (network.fixture.root / "net2" / "second").write_bytes(b"second")
        encoded = json.dumps(self.policy, sort_keys=True, separators=(",", ":"))
        with network.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE libraries SET source_root=? WHERE id='LIB1'", (str(local),)
            )
            db.execute(
                "INSERT INTO job_policy_snapshots(job_id,settings_revision,policy_json,policy_sha256,created_at) VALUES('JOB1',1,?,?,?)",
                (
                    encoded,
                    hashlib.sha256(encoded.encode()).hexdigest(),
                    datetime.now(UTC).isoformat(),
                ),
            )
            original = [
                tuple(row)
                for row in db.execute(
                    "SELECT * FROM automatic_job_share_evidence ORDER BY library_id"
                )
            ]
        result = (
            self.module()
            .BoundaryReplanCoordinator(
                network.factory,
                daemon_generation=network.fixture.generation,
                source_context=network.provider(),
            )
            .refresh("JOB1")
        )
        with network.factory() as catalog:
            self.assertEqual(
                original,
                [
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM automatic_job_share_evidence ORDER BY library_id"
                    )
                ],
            )
            rows = catalog.connection.execute(
                "SELECT library_id,relative_path,size FROM automatic_cassette_items WHERE job_id='JOB1' AND sequence=2 ORDER BY library_id"
            ).fetchall()
            self.assertEqual(
                [("NET1", "first", 5), ("NET2", "second", 6)],
                [tuple(row) for row in rows],
            )
            pins = catalog.connection.execute(
                "SELECT library_id,evidence_json FROM automatic_cassette_share_evidence WHERE job_id='JOB1' AND cassette_sequence=2 AND creation_plan_id=?",
                (result["creation_plan_id"],),
            ).fetchall()
            self.assertEqual(
                network.evidence,
                {row[0].casefold(): json.loads(row[1]) for row in pins},
            )
        self.assertEqual([], network.leases())


class BoundaryDeficitIntegrationTests(unittest.TestCase):
    def test_real_scan_retains_full_deficit_and_does_not_release_admission_fence(self):
        from ltobackup.daemon.boundary_coordinator import (
            BoundaryReplanCoordinator,
            BoundarySources,
        )
        from ltobackup.daemon.boundary_store import BoundaryStore

        fixture = test_boundary_store.BoundaryStoreTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        source = fixture.root / "source"
        source.mkdir()
        for name in ("a", "b", "c"):
            (source / name).write_bytes(b"new data!")
        # Six MiB accommodates exactly one tiny LTFS file (two allocation
        # units plus four per-library completion units), not two.
        policy = {
            "settings_revision": 1,
            "selected_media_profile": "LTO-6",
            "default_media_profile": "LTO-6",
            "capacity_reserve_bytes": 2_410_000_000_000 - 6 * 1024**2,
            "minimum_source_file_age_seconds": 0,
            "tape_root_directory": "lto",
            "content_verification_policy": "metadata",
        }
        encoded = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        with fixture.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE libraries SET source_root=? WHERE id='LIB1'", (str(source),)
            )
            db.execute(
                "INSERT INTO job_policy_snapshots(job_id,settings_revision,policy_json,policy_sha256,created_at) VALUES('JOB1',1,?,?,?)",
                (
                    encoded,
                    hashlib.sha256(encoded.encode()).hexdigest(),
                    datetime.now(UTC).isoformat(),
                ),
            )

        @contextmanager
        def sources(_snapshot, *, phase, plan_id):
            yield BoundarySources(
                verify_library=lambda library: (str(source), "a" * 64)
            )

        result = BoundaryReplanCoordinator(
            fixture.factory,
            daemon_generation=fixture.generation,
            source_context=sources,
        ).refresh("JOB1")
        self.assertEqual("waiting_labels", result["state"])
        self.assertEqual(1, result["required_additional_labels"])
        pending = BoundaryStore(fixture.factory, fixture.generation).pending("JOB1")
        batches = (
            *pending["plan"]["assignments"],
            *pending["plan"]["unassigned_batches"],
        )
        self.assertEqual(
            ["a", "b", "c"],
            [item["relative_path"] for batch in batches for item in batch["items"]],
        )
        with fixture.factory() as catalog:
            self.assertIsNotNone(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchone()
            )
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertEqual(
                [("obsolete",)],
                [
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT relative_path FROM automatic_cassette_items"
                    )
                ],
            )


if __name__ == "__main__":
    unittest.main()
