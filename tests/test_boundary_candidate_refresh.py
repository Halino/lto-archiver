"""Replace stale scan evidence, never a completed tape or an admitted suffix."""

from __future__ import annotations

import json
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from ltobackup.daemon.boundary_coordinator import (
    BoundaryReplanCoordinator,
    BoundarySources,
)
from ltobackup.daemon.boundary_dispatcher import BoundaryDispatcher
from ltobackup.daemon.boundary_store import BoundaryStore
from ltobackup.errors import CatalogError, ValidationError
from tests import test_boundary_pending


class BoundaryCandidateRefreshTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_pending.BoundaryPendingTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.store = self.fixture.store
        self.pending = self.store.pending("JOB1")
        with self.factory() as catalog:
            catalog.activate_boundary_replanning()

    def discard(self, reason="expired"):
        return self.store.discard_pending(
            "JOB1", candidate_sha256=self.pending["candidate_sha256"], reason=reason,
        )

    def future(self):
        clock = patch("ltobackup.daemon.boundary_store.datetime", wraps=datetime)
        mocked = clock.start()
        self.addCleanup(clock.stop)
        mocked.now.return_value = datetime.now(UTC) + timedelta(days=2)
        return mocked

    def test_expired_discard_preserves_history_layout_and_admission_fence(self):
        self.future()
        self.discard()
        self.assertIsNone(self.store.pending("JOB1"))
        self.assertEqual([(2, "obsolete", 7)], self.fixture.fixture.manifest())
        with self.factory() as catalog:
            self.assertEqual(1, catalog.latest_layout_epoch("JOB1")["epoch_number"])
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertTrue(catalog.boundary_replan_required("JOB1", 2))
            history = catalog.connection.execute(
                "SELECT payload_json FROM job_management_history WHERE action='job.boundary_replan.waiting_labels' ORDER BY id DESC LIMIT 1",
            ).fetchone()
            self.assertEqual(self.pending, json.loads(history[0]))

    def test_unexpired_candidate_cannot_be_discarded_as_expired(self):
        with self.assertRaisesRegex(CatalogError, "not_expired"):
            self.discard()
        self.assertEqual(self.pending, self.store.pending("JOB1"))

    def test_busy_hardware_prevents_discard(self):
        self.future()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE hardware_command_executions SET state='released',quiesced_at=NULL WHERE id='CMD1'")
        with self.assertRaisesRegex(CatalogError, "hardware_busy"):
            self.discard()
        self.assertEqual(self.pending, self.store.pending("JOB1"))

    def test_discard_cannot_steal_claimed_retry_lease(self):
        claimed, _ = self.store.claim_pending("JOB1")
        self.future()
        with self.assertRaisesRegex(CatalogError, "scan_busy"):
            self.discard()
        with self.factory() as catalog:
            self.assertEqual(claimed.run_id, catalog.connection.execute(
                "SELECT run_id FROM job_incremental_scan_leases WHERE job_id='JOB1'",
            ).fetchone()[0])

    def test_old_owner_cannot_discard_after_restart(self):
        self.future()
        with self.factory() as catalog:
            catalog.claim_daemon_owner("replacement-owner")
        with self.assertRaisesRegex(CatalogError, "owner_changed"):
            self.discard()
        self.assertIsNotNone(self.store.pending("JOB1"))

    def test_discard_does_not_repin_a_changed_source_configuration(self):
        self.future()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE libraries SET source_root='/different-source' WHERE id='LIB1'")
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            self.discard()
        self.assertIsNotNone(self.store.pending("JOB1"))

    def test_expired_wait_rescans_without_requiring_extra_label_click(self):
        self.future()
        for name in ("c", "d"):
            (self.fixture.source / name).unlink()
        dispatcher = BoundaryDispatcher(
            self.factory, daemon_generation=self.fixture.generation,
            coordinator=self.fixture.coordinator,
        )
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "a", 9), (3, "b", 9)], self.fixture.fixture.manifest())
        self.assertIsNone(self.store.pending("JOB1"))

    def test_changed_pending_file_is_rescanned_after_labels_are_added(self):
        self.fixture.add_labels(("TAPE04", "TAPE05"))
        (self.fixture.source / "a").write_bytes(b"a new version")
        result = self.fixture.coordinator.resume_pending("JOB1")
        self.assertEqual(2, result["next_sequence"])
        manifest = self.fixture.fixture.manifest()
        self.assertEqual(4, len(manifest))
        self.assertIn((2, "a", 13), manifest)
        self.assertIsNone(self.store.pending("JOB1"))

    def test_missing_source_root_is_not_treated_as_changed_or_deleted_files(self):
        self.fixture.add_labels(("TAPE04", "TAPE05"))
        self.fixture.source.rename(self.fixture.source.with_name("missing"))
        with self.assertRaises(OSError):
            self.fixture.coordinator.resume_pending("JOB1")
        self.assertIsNotNone(self.store.pending("JOB1"))
        self.assertEqual([(2, "obsolete", 7)], self.fixture.fixture.manifest())

    def test_expired_deliberate_pause_waits_for_explicit_resume(self):
        self.future()
        with self.factory() as catalog, catalog.transaction() as db:
            catalog.request_job_pause("JOB1", "admin")
            catalog.acknowledge_job_pause("JOB1", "unloaded")
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
        dispatcher = BoundaryDispatcher(
            self.factory, daemon_generation=self.fixture.generation,
            coordinator=self.fixture.coordinator,
        )
        self.assertTrue(dispatcher.reconcile_once())
        self.assertEqual(self.pending, self.store.pending("JOB1"))
        accepted = self.store.request_resume("JOB1", actor="admin", idempotency_key="expired-pause")
        self.assertEqual("accepted", accepted["state"])
        self.assertIsNone(self.store.pending("JOB1"))
        self.assertFalse(dispatcher.reconcile_once())
        retained = self.store.pending("JOB1")
        self.assertEqual(2, retained["required_additional_labels"])
        self.assertGreater(retained["expires_at"], self.pending["expires_at"])

    def test_expired_refresh_missing_root_keeps_old_layout_fenced(self):
        self.future()
        self.fixture.source.rename(self.fixture.source.with_name("unavailable"))
        dispatcher = BoundaryDispatcher(
            self.factory, daemon_generation=self.fixture.generation,
            coordinator=self.fixture.coordinator,
        )
        self.assertTrue(dispatcher.reconcile_once())
        self.assertEqual([(2, "obsolete", 7)], self.fixture.fixture.manifest())
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertEqual(1, catalog.latest_layout_epoch("JOB1")["epoch_number"])
            self.assertEqual(1, catalog.connection.execute("SELECT COUNT(*) FROM file_versions").fetchone()[0])
            self.assertEqual("job.boundary_replan.deferred", catalog.connection.execute(
                "SELECT action FROM job_management_history ORDER BY id DESC LIMIT 1",
            ).fetchone()[0])

    def test_wrong_label_rolls_back_expired_candidate_discard(self):
        self.future()
        with self.assertRaisesRegex(CatalogError, "confirmation_mismatch"):
            self.store.request_resume(
                "JOB1", actor="admin", idempotency_key="expired-wrong-label", confirmation_label="TAPE79",
            )
        self.assertEqual(self.pending, self.store.pending("JOB1"))

    def test_discard_to_capture_gap_cannot_adopt_changed_source_configuration(self):
        self.future()
        self.discard()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE libraries SET source_root='/different-source' WHERE id='LIB1'")
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            self.store.capture("JOB1")
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())

    def test_unpinned_local_root_replacement_is_not_an_ordinary_file_change(self):
        self.fixture.add_labels(("TAPE04", "TAPE05"))
        self.fixture.source.rename(self.fixture.source.with_name("original-root"))
        self.fixture.source.mkdir()
        for name in ("a", "b", "c", "d"):
            (self.fixture.source / name).write_bytes(b"new data!")

        @contextmanager
        def unpinned_verifier(_snapshot, *, phase, plan_id):
            # The legacy verifier can accept a path without a stored inode pin.
            # The boundary's retained root evidence must still prevent a rebind.
            yield BoundarySources(verify_library=lambda _library: (str(self.fixture.source), "a" * 64))

        coordinator = BoundaryReplanCoordinator(
            self.factory, daemon_generation=self.fixture.generation,
            source_context=unpinned_verifier,
        )
        with self.assertRaisesRegex(ValidationError, "root.*changed"):
            coordinator.resume_pending("JOB1")
        self.assertIsNotNone(self.store.pending("JOB1"))
        self.assertEqual([(2, "obsolete", 7)], self.fixture.fixture.manifest())

    def test_restart_after_discard_preserves_source_baseline(self):
        self.future()
        self.discard()
        with self.factory() as catalog:
            generation = catalog.claim_daemon_owner("replacement-owner").generation
        replacement = BoundaryStore(self.factory, daemon_generation=generation)
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE libraries SET source_root='/different-source' WHERE id='LIB1'")
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            replacement.capture("JOB1")

    def test_expired_discard_preserves_local_root_identity_for_fresh_scan(self):
        self.future()
        self.discard()
        self.fixture.source.rename(self.fixture.source.with_name("original-root"))
        self.fixture.source.mkdir()

        @contextmanager
        def unpinned_verifier(_snapshot, *, phase, plan_id):
            yield BoundarySources(verify_library=lambda _library: (str(self.fixture.source), "a" * 64))

        coordinator = BoundaryReplanCoordinator(
            self.factory, daemon_generation=self.fixture.generation,
            source_context=unpinned_verifier,
        )
        with self.assertRaisesRegex(ValidationError, "root.*changed"):
            coordinator.refresh("JOB1")
        self.assertEqual([(2, "obsolete", 7)], self.fixture.fixture.manifest())
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
