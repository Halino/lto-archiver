"""Retained boundary candidates survive label addition without a second scan."""

from __future__ import annotations

import asyncio
import sqlite3
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from ltobackup.application import LtoApplication
from ltobackup.daemon.boundary_coordinator import BoundaryReplanCoordinator
from ltobackup.daemon.boundary_store import BoundaryStore
from ltobackup.daemon.management import ManagementService
from ltobackup.errors import CatalogError
from tests import test_boundary_coordinator


class BoundaryPendingTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_coordinator.BoundaryCoordinatorTests()
        self.fixture.capacity_reserve_bytes = 2_410_000_000_000 - 6 * 1024**2
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.generation = self.fixture.fixture.generation
        self.source = self.fixture.source
        (self.source / "new").unlink()
        for name in ("a", "b", "c", "d"):
            (self.source / name).write_bytes(b"new data!")
        self.coordinator = BoundaryReplanCoordinator(
            self.factory,
            daemon_generation=self.generation,
            source_context=self.fixture.sources,
        )
        self.store = BoundaryStore(self.factory, self.generation)
        self.assertEqual(
            2, self.coordinator.refresh("JOB1")["required_additional_labels"]
        )

    def add_labels(self, labels):
        return self.store.reserve_pending_labels(
            "JOB1",
            labels,
            actor="admin",
            authorize_automatic_formatting=True,
        )

    def resume(self):
        with patch(
            "ltobackup.daemon.boundary_replan.analyze_library",
            side_effect=AssertionError("retained candidate must not rescan"),
        ):
            return self.coordinator.resume_pending("JOB1")

    def test_added_labels_consume_all_retained_files_without_rescan(self):
        before = self.store.pending("JOB1")
        self.add_labels(("TAPE04", "TAPE05"))
        self.assertEqual(before["expires_at"], self.store.pending("JOB1")["expires_at"])
        result = self.resume()
        self.assertEqual(2, result["next_sequence"])
        self.assertIsNone(self.store.pending("JOB1"))
        self.assertEqual(
            [(2, "a", 9), (3, "b", 9), (4, "c", 9), (5, "d", 9)],
            self.fixture.manifest(),
        )
        with self.factory() as catalog:
            sequence = catalog.automatic_sequence_state("JOB1")
            self.assertEqual("enabled", sequence["state"])
            self.assertEqual("admin", sequence["enabled_by"])
            self.assertIsNotNone(catalog.next_automatic_sequence_candidate())

    def test_failed_pending_retry_is_reclaimed_after_candidate_is_consumed(self):
        from ltobackup.daemon.boundary_retention import BoundaryDraftRetention

        self.add_labels(("TAPE04", "TAPE05"))
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("CREATE TRIGGER fail_resume_publication BEFORE INSERT ON job_management_history "
                       "WHEN NEW.action='job.boundary_replan.applied' "
                       "BEGIN SELECT RAISE(ABORT,'resume publication failure'); END")
        with self.assertRaisesRegex(sqlite3.IntegrityError, 'resume publication failure'):
            self.resume()
        self.assertIsNotNone(self.store.pending('JOB1'))
        with self.factory() as catalog, catalog.transaction() as db:
            failed_plan = db.execute("SELECT id FROM job_plan_drafts WHERE state='ready'").fetchone()[0]
            db.execute('DROP TRIGGER fail_resume_publication')
        self.resume()
        self.assertEqual(1, BoundaryDraftRetention(self.factory, self.generation).collect('JOB1'))
        with self.factory() as catalog:
            self.assertIsNone(catalog.connection.execute('SELECT 1 FROM job_plan_drafts WHERE id=?', (failed_plan,)).fetchone())
            self.assertEqual([('consumed',)], [tuple(row) for row in catalog.connection.execute('SELECT state FROM job_plan_drafts')])

    def test_partial_addition_retains_exact_remaining_deficit(self):
        before = self.store.pending("JOB1")
        self.add_labels(("TAPE04",))
        result = self.resume()
        self.assertEqual(1, result["required_additional_labels"])
        retained = self.store.pending("JOB1")
        self.assertEqual(before["expires_at"], retained["expires_at"])
        self.assertEqual(
            "d", retained["plan"]["unassigned_batches"][0]["items"][0]["relative_path"]
        )
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())
        self.add_labels(("TAPE05",))
        self.resume()
        self.assertEqual(4, len(self.fixture.manifest()))

    def test_restart_can_reclaim_but_does_not_rescan_candidate(self):
        self.add_labels(("TAPE04", "TAPE05"))
        with self.factory() as catalog:
            owner = catalog.claim_daemon_owner("replacement")
        self.coordinator = BoundaryReplanCoordinator(
            self.factory,
            daemon_generation=owner.generation,
            source_context=self.fixture.sources,
        )
        self.resume()
        self.assertEqual(4, len(self.fixture.manifest()))

    def test_changed_file_cannot_discard_evidence_without_activated_admission_gate(self):
        self.add_labels(("TAPE04", "TAPE05"))
        (self.source / "a").write_bytes(b"changed")
        with self.assertRaisesRegex(CatalogError, "activation_required"):
            self.resume()
        self.assertIsNotNone(self.store.pending("JOB1"))
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())

    def test_unrelated_source_change_cannot_be_hidden_by_label_addition(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE libraries SET enabled=0 WHERE id='LIB1'")
        with self.assertRaisesRegex(CatalogError, "snapshot_stale"):
            self.add_labels(("TAPE04",))
        with self.factory() as catalog:
            self.assertEqual(3, len(catalog.list_automatic_cassettes("JOB1")))

    def test_second_claim_cannot_steal_an_in_progress_pending_retry(self):
        self.store.claim_pending("JOB1")
        with self.assertRaisesRegex(CatalogError, "scan_busy"):
            self.store.claim_pending("JOB1")

    def test_expired_candidate_cannot_be_reclaimed_or_extended(self):
        future = datetime.now(UTC) + timedelta(days=2)
        with patch("ltobackup.daemon.boundary_store.datetime", wraps=datetime) as clock:
            clock.now.return_value = future
            with self.assertRaisesRegex(CatalogError, "pending_expired"):
                self.store.claim_pending("JOB1")
            with self.assertRaisesRegex(CatalogError, "pending_expired"):
                self.add_labels(("TAPE04",))
        self.assertIsNotNone(self.store.pending("JOB1"))

    def test_expiry_during_publication_cannot_be_committed(self):
        self.add_labels(("TAPE04", "TAPE05"))
        with patch("ltobackup.daemon.boundary_store.datetime", wraps=datetime) as clock:
            clock.now.return_value = datetime.now(UTC)

            def expire():
                clock.now.return_value = datetime.now(UTC) + timedelta(days=2)

            self.fixture.on_save = expire
            with self.assertRaisesRegex(CatalogError, "pending_expired"):
                self.resume()
        self.assertIsNotNone(self.store.pending("JOB1"))
        self.assertEqual([(2, "obsolete", 7)], self.fixture.manifest())

    def test_reservation_failure_rolls_back_candidate_claim_and_labels(self):
        pending = self.store.pending("JOB1")
        with self.factory() as catalog:
            lease = dict(
                catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_leases"
                ).fetchone()
            )
        with self.assertRaisesRegex(CatalogError, "authorization_required"):
            self.store.reserve_pending_labels("JOB1", ("TAPE04",), actor="admin")
        self.assertEqual(pending, self.store.pending("JOB1"))
        with self.factory() as catalog:
            self.assertEqual(
                lease,
                dict(
                    catalog.connection.execute(
                        "SELECT * FROM job_incremental_scan_leases"
                    ).fetchone()
                ),
            )
            self.assertEqual(3, len(catalog.list_automatic_cassettes("JOB1")))

    def test_management_failure_rolls_back_labels_and_rebound_evidence_together(self):
        service = ManagementService(LtoApplication(self.fixture.fixture.root))
        pending = self.store.pending("JOB1")
        with (
            patch.object(
                service,
                "_job_projection",
                side_effect=RuntimeError("projection failed"),
            ),
            self.assertRaisesRegex(RuntimeError, "projection failed"),
        ):
            asyncio.run(
                service.reserve_job_labels(
                    "JOB1",
                    ("TAPE04",),
                    actor="admin",
                    idempotency_key="failed-reserve",
                    authorize_automatic_formatting=True,
                )
            )
        self.assertEqual(pending, self.store.pending("JOB1"))
        with self.factory() as catalog:
            self.assertEqual(3, len(catalog.list_automatic_cassettes("JOB1")))

    def test_deliberate_pause_is_preserved_after_reservation_and_replay(self):
        with self.factory() as catalog, catalog.transaction() as db:
            catalog.request_job_pause("JOB1", "admin")
            catalog.acknowledge_job_pause("JOB1", "unloaded")
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
        self.add_labels(("TAPE04", "TAPE05"))
        self.resume()
        with self.factory() as catalog:
            self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
            self.assertEqual(
                "disabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
            self.assertIsNone(catalog.next_automatic_sequence_candidate())

    def test_management_reservation_rebinds_candidate_atomically_and_replays_idempotently(
        self,
    ):
        service = ManagementService(LtoApplication(self.fixture.fixture.root))

        async def reserve():
            return await service.reserve_job_labels(
                "JOB1",
                ("TAPE04", "TAPE05"),
                actor="admin",
                idempotency_key="boundary-labels",
                authorize_automatic_formatting=True,
            )

        first = asyncio.run(reserve())
        self.assertEqual(first, asyncio.run(reserve()))
        with self.factory() as catalog:
            self.assertEqual(5, len(catalog.list_automatic_cassettes("JOB1")))
            self.assertEqual(
                "enabled", catalog.automatic_sequence_state("JOB1")["state"]
            )
        self.resume()
        self.assertEqual(4, len(self.fixture.manifest()))
