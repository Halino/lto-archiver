"""Durable explicit Resume queues source refresh, never a premature tape write."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from ltobackup.daemon.boundary_coordinator import BoundaryReplanCoordinator
from ltobackup.daemon.boundary_dispatcher import BoundaryDispatcher
from ltobackup.daemon.boundary_store import BoundaryStore
from ltobackup.errors import CatalogError
from tests import test_boundary_coordinator, test_boundary_pending


class BoundaryResumeRequestTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_coordinator.BoundaryCoordinatorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.generation = self.fixture.fixture.generation
        self.store = BoundaryStore(self.factory, self.generation)
        self.pause(self.factory)

    @staticmethod
    def pause(factory):
        with factory() as catalog, catalog.transaction() as db:
            catalog.activate_boundary_replanning()
            catalog.request_job_pause("JOB1", "admin")
            catalog.acknowledge_job_pause("JOB1", "unloaded")
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")

    def request(self, *, key="resume-request"):
        return self.store.request_resume("JOB1", actor="admin", idempotency_key=key)

    def pending_pause(self):
        with self.factory() as catalog, catalog.transaction() as db:
            catalog.clear_job_pause("JOB1", "admin")
            epoch = catalog.latest_layout_epoch("JOB1")
            state = catalog.automatic_sequence_state("JOB1")
            catalog.set_automatic_sequence_enabled(
                "JOB1", expected_revision=state["revision"],
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="admin", enabled_at=datetime.now(UTC).isoformat(),
            )
            db.execute("UPDATE automatic_jobs SET status='waiting_media' WHERE id='JOB1'")
            catalog.request_job_pause("JOB1", "admin")

    def test_resume_reconciles_unacknowledged_pause_at_verified_completed_boundary(self):
        self.pending_pause()
        with self.factory() as catalog:
            before = [dict(row) for row in catalog.list_automatic_cassettes("JOB1")]
        result = self.request()
        self.assertEqual("accepted", result["state"])
        self.assertEqual(result, self.request())
        with self.factory() as catalog:
            self.assertEqual("enabled", catalog.automatic_sequence_state("JOB1")["state"])
            self.assertIsNone(catalog.job_management_state("JOB1")["pause_requested_at"])
            self.assertEqual(before, [dict(row) for row in catalog.list_automatic_cassettes("JOB1")])
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertEqual(1, catalog.connection.execute("SELECT COUNT(*) FROM daemon_operations").fetchone()[0])

    def assert_pending_pause_rejected(self, sql, error, parameters=()):
        self.pending_pause()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(sql, parameters)
        with self.assertRaisesRegex(CatalogError, error):
            self.request()
        with self.factory() as catalog:
            self.assertEqual("pause_pending", catalog.automatic_sequence_state("JOB1")["state"])
            self.assertIsNone(catalog.job_management_state("JOB1")["pause_acknowledged_at"])

    def test_pending_pause_stays_blocked_while_hardware_is_busy(self):
        self.assert_pending_pause_rejected(
            "UPDATE hardware_command_executions SET state='released',quiesced_at=NULL WHERE id='CMD1'",
            "hardware_busy",
        )

    def test_pending_pause_stays_blocked_without_completed_eject_evidence(self):
        self.assert_pending_pause_rejected(
            "DELETE FROM hardware_command_executions WHERE command_kind='probe_media'", "eject_unproven",
        )

    def test_pending_pause_stays_blocked_if_layout_changed(self):
        self.assert_pending_pause_rejected(
            "UPDATE automatic_sequence_state SET layout_fingerprint_sha256=? WHERE job_id='JOB1'",
            "layout_conflict", ("f" * 64,),
        )

    def test_background_capture_does_not_clear_pending_pause(self):
        self.pending_pause()
        with self.assertRaisesRegex(CatalogError, "boundary_pause_pending"):
            self.store.capture("JOB1")
        with self.factory() as catalog:
            self.assertEqual("pause_pending", catalog.automatic_sequence_state("JOB1")["state"])

    def test_explicit_resume_queues_refresh_then_automatic_dispatch_consumes_it(self):
        result = self.request()
        self.assertEqual("boundary.refresh", result["kind"])
        self.assertEqual("accepted", result["state"])
        self.assertEqual("JOB1", result["job_id"])
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())
        with self.factory() as catalog:
            self.assertEqual("waiting_media", catalog.get_automatic_job("JOB1")["status"])
            self.assertEqual("enabled", catalog.automatic_sequence_state("JOB1")["state"])
            self.assertEqual("admin", catalog.automatic_sequence_state("JOB1")["enabled_by"])
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertEqual(1, catalog.connection.execute("SELECT COUNT(*) FROM daemon_operations").fetchone()[0])
        dispatcher = BoundaryDispatcher(
            self.factory, daemon_generation=self.generation,
            coordinator=BoundaryReplanCoordinator(
                self.factory, daemon_generation=self.generation, source_context=self.fixture.sources,
            ),
        )
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.manifest())
        self.assertTrue(dispatcher.reconcile_once())
        with self.factory() as catalog:
            self.assertIsNotNone(catalog.next_automatic_sequence_candidate())

    def test_duplicate_resume_has_no_second_state_transition(self):
        first = self.request()
        with self.factory() as catalog:
            sequence = dict(catalog.automatic_sequence_state("JOB1"))
            history = catalog.connection.execute("SELECT COUNT(*) FROM job_management_history").fetchone()[0]
        self.assertEqual(first, self.request())
        with self.factory() as catalog:
            self.assertEqual(sequence, dict(catalog.automatic_sequence_state("JOB1")))
            self.assertEqual(history, catalog.connection.execute("SELECT COUNT(*) FROM job_management_history").fetchone()[0])

    def test_busy_hardware_cannot_be_unpaused_by_queued_resume(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE hardware_command_executions SET state='released',quiesced_at=NULL WHERE id='CMD1'")
        with self.assertRaisesRegex(CatalogError, "hardware_busy"):
            self.request()
        with self.factory() as catalog:
            self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
            self.assertEqual("disabled", catalog.automatic_sequence_state("JOB1")["state"])

    def test_resume_rebinds_pending_candidate_without_losing_files_or_expiry(self):
        pending = test_boundary_pending.BoundaryPendingTests()
        pending.setUp()
        self.addCleanup(pending.doCleanups)
        before = pending.store.pending("JOB1")
        self.pause(pending.factory)
        result = pending.store.request_resume("JOB1", actor="admin", idempotency_key="pending-resume")
        self.assertEqual("accepted", result["state"])
        after = pending.store.pending("JOB1")
        self.assertEqual(before["plan"], after["plan"])
        self.assertEqual(before["expires_at"], after["expires_at"])
        pending.add_labels(("TAPE04", "TAPE05"))
        pending.resume()
        self.assertEqual(4, len(pending.fixture.manifest()))

    def test_click_during_existing_scan_does_not_invalidate_snapshot(self):
        self.request()
        snapshot = self.store.capture("JOB1")
        self.assertEqual("accepted", self.request(key="second-click")["state"])
        self.store.release(snapshot, "test_finished")
        # Invalidation would force an additional scan: snapshot must still be
        # the exact current state after the second accepted request.
        with self.factory() as catalog:
            self.assertEqual(snapshot.revision, catalog.job_management_state("JOB1")["revision"])

    def test_initial_or_attempted_resume_is_not_redirected_to_boundary_refresh(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_cassettes SET started_at='2026-09-12T12:00:00+00:00' WHERE job_id='JOB1' AND sequence=2")
        self.assertIsNone(self.request())

    def test_nonboundary_busy_resume_keeps_legacy_admission_path(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_cassettes SET started_at='2026-09-12T12:00:00+00:00' WHERE job_id='JOB1' AND sequence=2")
            db.execute("UPDATE daemon_operations SET state='running',finished_at=NULL WHERE id='OP1'")
        self.assertIsNone(self.request())

    def test_enabled_resume_replaces_expired_candidate_with_fenced_refresh_request(self):
        pending = test_boundary_pending.BoundaryPendingTests()
        pending.setUp()
        self.addCleanup(pending.doCleanups)
        with pending.factory() as catalog:
            catalog.activate_boundary_replanning()
        before = pending.store.pending("JOB1")
        with patch("ltobackup.daemon.boundary_store.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime.now(UTC) + timedelta(days=2)
            result = pending.store.request_resume("JOB1", actor="admin", idempotency_key="expired-resume")
        self.assertEqual("accepted", result["state"])
        self.assertIsNone(pending.store.pending("JOB1"))
        with pending.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertIn(before["candidate_sha256"], catalog.connection.execute(
                "SELECT payload_json FROM job_management_history WHERE action='job.boundary_replan.discarded' ORDER BY id DESC LIMIT 1",
            ).fetchone()[0])
