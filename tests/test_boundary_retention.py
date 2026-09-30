"""Real failed-publication artifacts and guarded reclamation, without hardware."""

import json
import sqlite3
import unittest
from contextlib import contextmanager

from ltobackup.daemon.boundary_retention import BoundaryDraftRetention
from ltobackup.errors import CatalogError
from tests import test_boundary_coordinator


class BoundaryRetentionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_coordinator.BoundaryCoordinatorTests()
        self.fixture.catalog_target_version = getattr(self, "catalog_target_version", None)
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.generation = self.fixture.fixture.generation
        self.retention = BoundaryDraftRetention(self.factory, self.generation)

    def abandoned(self):
        # Simulate both original publication failure and interrupted cleanup.
        # Removing the triggers leaves the actual persisted artifact to retry.
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("CREATE TRIGGER fail_publication BEFORE INSERT ON job_management_history "
                       "WHEN NEW.action='job.boundary_replan.applied' "
                       "BEGIN SELECT RAISE(ABORT,'original publication failure'); END")
            db.execute("CREATE TRIGGER fail_cleanup BEFORE DELETE ON job_plan_drafts "
                       "BEGIN SELECT RAISE(ABORT,'cleanup failure'); END")
        with (
            self.assertLogs('ltobackup.daemon.boundary_coordinator', level='WARNING'),
            self.assertRaisesRegex(sqlite3.IntegrityError, 'original publication failure'),
        ):
            self.fixture.refresh()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute('DROP TRIGGER fail_publication')
            db.execute('DROP TRIGGER fail_cleanup')
            row = db.execute('SELECT id FROM job_plan_drafts ORDER BY rowid DESC LIMIT 1').fetchone()
            self.assertEqual('ready', catalog.get_job_plan(row[0])['state'])
            return row[0], row[0][len('PLAN-'):]

    def test_cleanup_failure_preserves_error_and_retries_atomically(self):
        plan_id, run_id = self.abandoned()
        with self.factory() as catalog:
            self.assertEqual(0, catalog.connection.execute(
                "SELECT COUNT(*) FROM job_management_history WHERE action='job.boundary_replan.draft_retired'"
            ).fetchone()[0])
        self.assertTrue(self.retention.retire('JOB1', run_id))
        self.assertFalse(self.retention.retire('JOB1', run_id))
        with self.factory() as catalog:
            self.assertIsNone(catalog.connection.execute('SELECT 1 FROM job_plan_drafts WHERE id=?', (plan_id,)).fetchone())
            self.assertEqual(1, catalog.connection.execute(
                "SELECT COUNT(*) FROM job_management_history WHERE action='job.boundary_replan.draft_retired'"
            ).fetchone()[0])

    def test_other_job_and_stale_owner_cannot_retire(self):
        plan_id, run_id = self.abandoned()
        self.assertFalse(self.retention.retire('OTHER', run_id))
        with self.factory() as catalog:
            catalog.claim_daemon_owner('replacement')
        with self.assertRaisesRegex(CatalogError, 'owner_changed'):
            self.retention.retire('JOB1', run_id)
        with self.factory() as catalog:
            self.assertEqual('ready', catalog.get_job_plan(plan_id)['state'])

    def test_scan_lease_defers_retirement(self):
        plan_id, run_id = self.abandoned()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("INSERT INTO job_incremental_scan_leases VALUES('JOB1',?,?,?)",
                       ('other-run', self.generation, '2026-09-12T10:00:00+00:00'))
        self.assertFalse(self.retention.retire('JOB1', run_id))
        with self.factory() as catalog:
            self.assertEqual('ready', catalog.get_job_plan(plan_id)['state'])

    def test_non_fk_pending_reference_preserves_plan(self):
        plan_id, run_id = self.abandoned()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("INSERT INTO job_incremental_pending_extensions VALUES('JOB1',1,?,?,?,1,9,1,?)",
                       ('a'*64, plan_id, 'b'*64, '2026-09-12T10:00:00+00:00'))
        self.assertFalse(self.retention.retire('JOB1', run_id))
        with self.factory() as catalog:
            self.assertEqual('ready', catalog.get_job_plan(plan_id)['state'])

    def test_hashed_source_lease_defers_retirement(self):
        plan_id, run_id = self.abandoned()
        with self.factory() as catalog:
            catalog.create_managed_share(
                'source', 'Source', 'nfs', json.dumps({'kind':'nfs', 'server':'nas.example.test', 'export':'/source'}),
                actor='admin', idempotency_key='source', request_fingerprint_sha256='a'*64,
                desired_state='connected', observed_state='connected',
            )
            with catalog.transaction() as db:
                db.execute("INSERT INTO managed_source_leases VALUES('lease','source','save',?,'owner',?,?)",
                           ('boundary-' + 'd'*32, self.generation, '2026-09-12T10:00:00+00:00'))
        self.assertFalse(self.retention.retire('JOB1', run_id))
        with self.factory() as catalog:
            self.assertEqual('ready', catalog.get_job_plan(plan_id)['state'])

    def test_consumed_plan_and_archived_versions_are_preserved(self):
        result = self.fixture.refresh()
        plan_id = result['creation_plan_id']
        with self.factory() as catalog:
            before = [tuple(row) for row in catalog.connection.execute('SELECT * FROM file_versions')]
        self.assertFalse(self.retention.retire('JOB1', plan_id[len('PLAN-'):]))
        with self.factory() as catalog:
            self.assertEqual('consumed', catalog.get_job_plan(plan_id)['state'])
            self.assertEqual(before, [tuple(row) for row in catalog.connection.execute('SELECT * FROM file_versions')])

    def test_postcommit_context_error_does_not_retire_committed_plan(self):
        from ltobackup.daemon.boundary_coordinator import BoundaryReplanCoordinator

        @contextmanager
        def sources(snapshot, *, phase, plan_id):
            with self.fixture.sources(snapshot, phase=phase, plan_id=plan_id) as source:
                yield source
            if phase == 'save':
                raise OSError('source context close failed')

        coordinator = BoundaryReplanCoordinator(
            self.factory, daemon_generation=self.generation, source_context=sources,
        )
        with self.assertRaisesRegex(OSError, 'source context close failed'):
            coordinator.refresh('JOB1')
        self.assertEqual([(2, 'new', 9)], self.fixture.manifest())
        with self.factory() as catalog:
            self.assertEqual([('consumed',)], [tuple(row) for row in catalog.connection.execute('SELECT state FROM job_plan_drafts')])
            self.assertEqual(0, catalog.connection.execute("SELECT COUNT(*) FROM job_management_history WHERE action='job.boundary_replan.draft_retired'").fetchone()[0])

    def test_active_hardware_operation_defers_retirement(self):
        plan_id, run_id = self.abandoned()
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE daemon_operations SET state='running',finished_at=NULL WHERE id='OP1'")
        self.assertFalse(self.retention.retire('JOB1', run_id))
        with self.factory() as catalog:
            self.assertEqual('ready', catalog.get_job_plan(plan_id)['state'])

    def test_bounded_collection_reclaims_old_failures(self):
        first, _ = self.abandoned()
        second, _ = self.abandoned()
        collect = getattr(self.retention, 'collect', None)
        self.assertTrue(callable(collect), 'the application must collect failures left by earlier runs')
        self.assertEqual(1, collect('JOB1', limit=1))
        with self.factory() as catalog:
            self.assertEqual(1, catalog.connection.execute('SELECT COUNT(*) FROM job_plan_drafts WHERE id IN (?,?)', (first, second)).fetchone()[0])
        self.assertEqual(1, collect('JOB1', limit=1))
        self.assertEqual(0, collect('JOB1', limit=1))

    def test_dispatcher_collects_abandoned_drafts_before_new_publication(self):
        from ltobackup.daemon.boundary_coordinator import BoundaryReplanCoordinator
        from ltobackup.daemon.boundary_dispatcher import BoundaryDispatcher

        plan_id, _ = self.abandoned()
        with self.factory() as catalog:
            catalog.activate_boundary_replanning()
        dispatcher = BoundaryDispatcher(
            self.factory, daemon_generation=self.generation,
            coordinator=BoundaryReplanCoordinator(
                self.factory, daemon_generation=self.generation,
                source_context=self.fixture.sources,
            ),
        )
        self.assertFalse(dispatcher.reconcile_once())
        with self.factory() as catalog:
            self.assertIsNone(catalog.connection.execute('SELECT 1 FROM job_plan_drafts WHERE id=?', (plan_id,)).fetchone())
            self.assertEqual([('consumed',)], [tuple(row) for row in catalog.connection.execute('SELECT state FROM job_plan_drafts')])

    def test_paused_job_collects_abandoned_drafts_without_replanning(self):
        from ltobackup.daemon.boundary_coordinator import BoundaryReplanCoordinator
        from ltobackup.daemon.boundary_dispatcher import BoundaryDispatcher

        plan_id, _ = self.abandoned()
        before = self.fixture.manifest()
        with self.factory() as catalog:
            catalog.activate_boundary_replanning()
            catalog.request_job_pause('JOB1', 'admin')
        dispatcher = BoundaryDispatcher(
            self.factory, daemon_generation=self.generation,
            coordinator=BoundaryReplanCoordinator(
                self.factory, daemon_generation=self.generation,
                source_context=self.fixture.sources,
            ),
        )
        self.assertTrue(dispatcher.reconcile_once())
        self.assertEqual(before, self.fixture.manifest())
        with self.factory() as catalog:
            self.assertIsNone(catalog.connection.execute('SELECT 1 FROM job_plan_drafts WHERE id=?', (plan_id,)).fetchone())
            self.assertIsNotNone(catalog.job_management_state('JOB1')['pause_requested_at'])

    def test_claim_records_digest_and_epoch_without_copying_manifest(self):
        snapshot = self.fixture.fixture.store.capture('JOB1')
        with self.factory() as catalog:
            payload = json.loads(catalog.connection.execute(
                "SELECT payload_json FROM job_management_history WHERE action='job.boundary_replan.claimed' ORDER BY id DESC LIMIT 1"
            ).fetchone()[0])
        self.assertNotIn('superseded_manifest', payload)
        self.assertEqual(1, payload['working_manifest_files'])
        self.assertEqual(64, len(payload['working_manifest_sha256']))
        self.assertEqual(snapshot.epoch_number, payload['layout_epoch'])

    def test_protected_candidate_does_not_starve_later_cleanup(self):
        first, _ = self.abandoned()
        second, _ = self.abandoned()
        protected, eligible = sorted((first, second))
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE job_management_state SET creation_plan_id=? WHERE job_id='JOB1'", (protected,))
        collect = self.retention.collect
        self.assertEqual(0, collect('JOB1', limit=1))
        self.assertEqual(1, collect('JOB1', limit=1))
        with self.factory() as catalog:
            self.assertEqual('ready', catalog.get_job_plan(protected)['state'])
            self.assertIsNone(catalog.connection.execute('SELECT 1 FROM job_plan_drafts WHERE id=?', (eligible,)).fetchone())
