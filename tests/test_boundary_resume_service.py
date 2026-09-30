"""Authenticated Resume queues boundary work through the real daemon route."""

from __future__ import annotations

import unittest

from httpx2 import ASGITransport, AsyncClient

from ltobackup.daemon.api import create_app
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.service import (
    DaemonService,
    FormatConfirmationMismatch,
    MutationAdmissionClosed,
    Principal,
)
from ltobackup.linux_settings import LinuxPaths, LinuxSettings
from tests import test_boundary_resume_requests
from tests.test_sequence_coordinator import _HoldingExecutor


class BoundaryResumeServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = test_boundary_resume_requests.BoundaryResumeRequestTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        root = self.fixture.fixture.fixture.root
        self.paths = LinuxPaths.for_root(root, root / "daemon.sock")
        self.settings = LinuxSettings(
            state_dir=root, socket_path=self.paths.socket_path,
            source_roots=(self.fixture.fixture.source,),
        )
        with self.factory() as catalog:
            fence = catalog.current_daemon_fence()
        self.operations = OperationManager(self.factory, fence, executor=_HoldingExecutor())

        def no_early_admission(_job_id):
            raise AssertionError("boundary Resume must not admit tape I/O before refresh")

        self.service = DaemonService(
            self.paths, self.settings,
            BackupManager(self.paths.catalog_file, self.paths.backup_dir),
            self.operations, EventBus(self.factory),
            operation_callbacks={"archive.native": lambda _context: None},
            native_archive_admission=no_early_admission,
        )
        self.service.startup()
        self.addCleanup(lambda: None if self.service.shutdown_requested else self.service.shutdown(0.0))

    def request(self, principal=None):
        return self.service.start_archive("JOB1", "resume-route", principal or Principal("admin"))

    def assert_paused(self):
        with self.factory() as catalog:
            self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])

    def test_resume_accepts_without_synchronous_scan_or_tape_admission(self):
        result = self.request()
        self.assertEqual("boundary.refresh", result.kind)
        self.assertEqual("accepted", result.state)
        self.assertEqual(result, self.request())
        self.assertEqual([(2, "obsolete", 7)], self.fixture.fixture.manifest())
        with self.factory() as catalog:
            self.assertIsNone(catalog.next_automatic_sequence_candidate())
            self.assertEqual(1, catalog.connection.execute("SELECT COUNT(*) FROM daemon_operations").fetchone()[0])

    def test_stopped_daemon_cannot_queue_resume(self):
        self.service.shutdown()
        with self.assertRaises(MutationAdmissionClosed):
            self.request()
        self.assert_paused()

    def test_matching_legacy_label_still_queues_boundary_resume(self):
        result = self.service.start_archive(
            "JOB1", "legacy-label", Principal("admin"), format_confirmation_label="TAPE02",
        )
        self.assertEqual("boundary.refresh", result.kind)
        self.assertEqual("accepted", result.state)

    def test_mismatched_legacy_label_cannot_unpause_boundary(self):
        with self.assertRaises(FormatConfirmationMismatch):
            self.service.start_archive(
                "JOB1", "wrong-label", Principal("admin"), format_confirmation_label="TAPE79",
            )
        self.assert_paused()

    def test_queued_resume_dispatches_with_real_management_source_verifier(self):
        dispatcher = self.service.boundary_dispatcher(self.operations.daemon_fence.generation)
        self.request()
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.fixture.manifest())
        with self.factory() as catalog:
            candidate = catalog.next_automatic_sequence_candidate()
            self.assertIsNotNone(candidate)
            self.assertEqual(2, candidate["cassette_sequence"])

    async def test_untrusted_http_peer_cannot_queue_resume(self):
        app = create_app(self.service)
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/jobs/JOB1/resume", headers={"Idempotency-Key": "untrusted"}, json={},
            )
        self.assertEqual(403, response.status_code)
        self.assert_paused()

    async def test_busy_boundary_is_a_conflict_not_an_internal_server_error(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE hardware_command_executions SET state='released',quiesced_at=NULL WHERE id='CMD1'")
        app = create_app(self.service)
        app.dependency_overrides[self.service.principals.require_operator] = lambda: Principal("admin")
        async with AsyncClient(
            transport=ASGITransport(app=app, raise_app_exceptions=False), base_url="http://test",
        ) as client:
            response = await client.post(
                "/api/v1/jobs/JOB1/resume", headers={"Idempotency-Key": "busy-boundary"}, json={},
            )
        self.assertEqual(409, response.status_code, response.text)
        self.assert_paused()

    async def test_http_resume_returns_typed_acceptance(self):
        app = create_app(self.service)
        app.dependency_overrides[self.service.principals.require_operator] = lambda: Principal("admin")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/jobs/JOB1/resume", headers={"Idempotency-Key": "resume-api"}, json={},
            )
            replay_conflict = await client.post(
                "/api/v1/jobs/JOB1/resume", headers={"Idempotency-Key": "resume-api"},
                json={"format_confirmation_label": "TAPE02"},
            )
        self.assertEqual(202, response.status_code, response.text)
        self.assertEqual("boundary.refresh", response.json()["kind"])
        self.assertEqual("accepted", response.json()["state"])
        self.assertNotIn("id", response.json())
        self.assertEqual(409, replay_conflict.status_code, replay_conflict.text)

    async def test_http_resume_accepts_waiting_media_with_unacknowledged_pause(self):
        self.fixture.pending_pause()
        app = create_app(self.service)
        app.dependency_overrides[self.service.principals.require_operator] = lambda: Principal("admin")
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            response = await client.post(
                "/api/v1/jobs/JOB1/resume", headers={"Idempotency-Key": "resume-pending-pause"}, json={},
            )
        self.assertEqual(202, response.status_code, response.text)
        self.assertEqual("boundary.refresh", response.json()["kind"])
        dispatcher = self.service.boundary_dispatcher(self.operations.daemon_fence.generation)
        self.assertFalse(dispatcher.reconcile_once())
        self.assertEqual([(2, "new", 9)], self.fixture.fixture.manifest())
