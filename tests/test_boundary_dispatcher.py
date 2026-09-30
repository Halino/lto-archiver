"""Automatic boundary dispatch using real catalog and source refresh."""

from __future__ import annotations

import importlib
import json
import unittest
from datetime import UTC, datetime
from unittest.mock import patch

from ltobackup.daemon.boundary_coordinator import BoundaryReplanCoordinator
from ltobackup.daemon.boundary_store import BoundaryStore
from ltobackup.errors import CatalogError
from tests import test_boundary_coordinator, test_boundary_pending


class BoundaryDispatcherTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_coordinator.BoundaryCoordinatorTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.generation = self.fixture.fixture.generation
        self.now = 0.0
        with self.factory() as catalog:
            catalog.activate_boundary_replanning()

    def dispatcher(self, *, fixture=None):
        fixture = fixture or self.fixture
        module = "ltobackup.daemon.boundary_dispatcher"
        self.assertIsNotNone(
            importlib.util.find_spec(module), "boundary dispatcher missing"
        )
        return importlib.import_module(module).BoundaryDispatcher(
            fixture.factory,
            daemon_generation=self.generation,
            coordinator=BoundaryReplanCoordinator(
                fixture.factory,
                daemon_generation=self.generation,
                source_context=fixture.sources,
            ),
            clock=lambda: self.now,
        )

    def test_refreshes_once_and_persists_boundary_identity_across_restart(self):
        dispatcher = self.dispatcher()
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.manifest())
        with patch(
            "ltobackup.daemon.boundary_replan.analyze_library",
            side_effect=AssertionError("duplicate scan"),
        ):
            self.assertTrue(self.dispatcher().reconcile_once())

    def test_busy_hardware_does_not_scan_or_change_layout(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE daemon_operations SET state='running',finished_at=NULL WHERE id='OP1'"
            )
        self.assertFalse(self.dispatcher().reconcile_once())
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())

    def test_initial_start_and_deliberate_pause_do_not_trigger_scan(self):
        for status, sequence_state in (("planned", "enabled"), ("paused", "disabled")):
            with self.subTest(status=status):
                with self.factory() as catalog, catalog.transaction() as db:
                    db.execute(
                        "UPDATE automatic_jobs SET status=? WHERE id='JOB1'", (status,)
                    )
                    db.execute(
                        "UPDATE automatic_sequence_state SET state=? WHERE job_id='JOB1'",
                        (sequence_state,),
                    )
                self.assertTrue(self.dispatcher().reconcile_once())
                self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())

    def test_attempted_suffix_is_not_replanned(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_cassettes SET started_at='2026-09-12T10:10:00+00:00' WHERE job_id='JOB1' AND sequence=2"
            )
        self.assertTrue(self.dispatcher().reconcile_once())
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())

    def test_source_failure_blocks_admission_and_retries_with_backoff(self):
        self.fixture.source.rename(self.fixture.source.with_name("unavailable"))
        dispatcher = self.dispatcher()
        self.assertTrue(dispatcher.reconcile_once())
        with self.factory() as catalog:
            first = catalog.connection.execute(
                "SELECT COUNT(*) FROM job_management_history"
            ).fetchone()[0]
        self.assertTrue(dispatcher.reconcile_once())
        with self.factory() as catalog:
            self.assertEqual(
                first,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM job_management_history"
                ).fetchone()[0],
            )
        self.fixture.source.with_name("unavailable").rename(self.fixture.source)
        self.now = 61.0
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.manifest())
        self.assertTrue(dispatcher.reconcile_once())

    def test_old_daemon_owner_cannot_dispatch(self):
        with self.factory() as catalog:
            catalog.claim_daemon_owner("replacement")
        with self.assertRaisesRegex(CatalogError, "owner_changed"):
            self.dispatcher().reconcile_once()

    def assert_sqlite_failure_is_deferred(self, trigger_statement):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "CREATE TRIGGER fail_boundary_commit BEFORE INSERT ON job_management_history "
                "WHEN NEW.action='job.boundary_replan.applied' BEGIN "
                + trigger_statement + "; END"
            )
        dispatcher = self.dispatcher()
        self.assertTrue(dispatcher.reconcile_once())
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertIsNone(catalog.connection.execute(
                "SELECT * FROM job_incremental_scan_leases"
            ).fetchone())
            events = [tuple(row) for row in catalog.connection.execute(
                "SELECT action,payload_json FROM job_management_history ORDER BY id"
            )]
            self.assertEqual("job.boundary_replan.deferred", events[-1][0])
            self.assertEqual("boundary_catalog_conflict", json.loads(events[-1][1])["error_code"])
            self.assertNotIn("sensitive_sql_detail", events[-1][1])
            self.assertEqual(1, catalog.latest_layout_epoch("JOB1")["epoch_number"])
        self.now = 59.0
        self.assertTrue(dispatcher.reconcile_once())
        with self.factory() as catalog:
            self.assertEqual(events, [tuple(row) for row in catalog.connection.execute(
                "SELECT action,payload_json FROM job_management_history ORDER BY id"
            )])
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("DROP TRIGGER fail_boundary_commit")
        self.now = 61.0
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.manifest())

    def test_sqlite_integrity_failure_is_visible_and_retried_with_backoff(self):
        self.assert_sqlite_failure_is_deferred("SELECT RAISE(ABORT,'sensitive_sql_detail')")

    def test_pending_wait_is_quiet_and_label_addition_reuses_candidate(self):
        pending_fixture = test_boundary_pending.BoundaryPendingTests()
        pending_fixture.setUp()
        self.addCleanup(pending_fixture.doCleanups)
        fixture = pending_fixture.fixture
        dispatcher = self.dispatcher(fixture=fixture)
        with fixture.factory() as catalog:
            before = catalog.connection.execute(
                "SELECT COUNT(*) FROM job_management_history"
            ).fetchone()[0]
        self.assertTrue(dispatcher.reconcile_once())
        with fixture.factory() as catalog:
            self.assertEqual(
                before,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM job_management_history"
                ).fetchone()[0],
            )
        pending_fixture.add_labels(("TAPE04", "TAPE05"))
        with patch(
            "ltobackup.daemon.boundary_replan.analyze_library",
            side_effect=AssertionError("pending rescan"),
        ):
            self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual(4, len(fixture.manifest()))
        self.assertIsNone(
            BoundaryStore(fixture.factory, self.generation).pending("JOB1")
        )

    def test_manual_resume_cannot_bypass_boundary_before_dispatcher_claim(self):
        from ltobackup.daemon.models import (
            HardwareTargetBinding,
            MutationAdmissionClosed,
        )
        from ltobackup.daemon.operations import OperationManager
        from tests.test_sequence_coordinator import _HoldingExecutor

        with self.factory() as catalog:
            owner = catalog.current_daemon_fence()
        manager = OperationManager(self.factory, owner, executor=_HoldingExecutor())
        with self.assertRaisesRegex(MutationAdmissionClosed, "boundary source refresh"):
            manager.start(
                "archive.native",
                "manual-too-early",
                "admin",
                lambda _context: None,
                job_id="JOB1",
                cassette_sequence=2,
                hardware_target=HardwareTargetBinding.from_verified_inputs(
                    self.fixture.fixture.root / "tape",
                    "tape",
                    "scsi",
                    ("archive.native", "JOB1", "2", "TAPE02", "", ""),
                ),
            )

    def test_management_assembly_uses_real_source_verifier_before_refresh(self):
        from ltobackup.application import LtoApplication
        from ltobackup.daemon.management import ManagementService

        management = ManagementService(
            LtoApplication(self.fixture.fixture.root),
            source_roots=(self.fixture.source,),
        )
        dispatcher = management.boundary_dispatcher(self.generation)
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.manifest())
        self.assertTrue(dispatcher.reconcile_once())

    def test_append_destination_is_not_subject_to_suffix_replanning_gate(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_cassettes SET operation='append' WHERE job_id='JOB1' AND sequence=2"
            )
            self.assertFalse(catalog.boundary_replan_required("JOB1", 2))

    def test_historical_completed_jobs_are_not_reopened_on_activation(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_jobs SET status='completed',current_sequence=1 WHERE id='JOB1'"
            )
            db.execute(
                "UPDATE automatic_sequence_state SET state='completed' WHERE job_id='JOB1'"
            )
        self.assertTrue(self.dispatcher().reconcile_once())
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())

    def test_failed_boundary_is_fenced_without_blocking_other_admission(self):
        self.fixture.source.rename(self.fixture.source.with_name("unavailable"))
        dispatcher = self.dispatcher()
        self.assertTrue(dispatcher.reconcile_once())
        self.assertTrue(dispatcher.reconcile_once())
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())

    def test_new_final_boundary_after_activation_can_use_authorized_reserves(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute(
                "UPDATE automatic_jobs SET status='completed',current_sequence=1 WHERE id='JOB1'"
            )
            db.execute(
                "UPDATE automatic_sequence_state SET state='completed' WHERE job_id='JOB1'"
            )
            db.execute(
                "UPDATE daemon_operations SET finished_at=? WHERE id='OP1'",
                (datetime.now(UTC).isoformat(),),
            )
        self.assertFalse(self.dispatcher().reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.manifest())

    def test_reactivation_does_not_move_the_persisted_rollout_boundary(self):
        with self.factory() as catalog:
            first = catalog.activate_boundary_replanning()
        with (
            patch(
                "ltobackup.catalog.utc_now", return_value="2027-01-01T00:00:00+00:00"
            ),
            self.factory() as catalog,
        ):
            self.assertEqual(first, catalog.activate_boundary_replanning())

    def test_completion_earlier_in_activation_second_is_historical(self):
        from ltobackup.catalog import Catalog

        fixture = test_boundary_coordinator.BoundaryCoordinatorTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with (
            patch(
                "ltobackup.catalog.utc_now", return_value="2026-09-12T12:00:00+00:00"
            ),
            patch.object(
                Catalog,
                "_precise_utc_now",
                return_value="2026-09-12T12:00:00.900000+00:00",
            ),
            fixture.factory() as catalog,
            catalog.transaction() as db,
        ):
            catalog.activate_boundary_replanning()
            db.execute(
                "UPDATE automatic_jobs SET status='completed',current_sequence=1 WHERE id='JOB1'"
            )
            db.execute(
                "UPDATE automatic_sequence_state SET state='completed' WHERE job_id='JOB1'"
            )
            db.execute(
                "UPDATE daemon_operations SET finished_at='2026-09-12T12:00:00.100000+00:00' WHERE id='OP1'"
            )
        self.assertTrue(self.dispatcher(fixture=fixture).reconcile_once())
        self.assertEqual([(2, "obsolete", 7)], fixture.manifest())
