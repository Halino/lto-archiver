"""Safe, refreshable status for cassette-boundary replanning."""

from __future__ import annotations

import json
import unittest
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ltobackup.application import LtoApplication
from ltobackup.daemon.api_models import BoundaryRefreshStatusV1, JobDetailV1
from ltobackup.daemon.boundary_status import boundary_refresh_status
from ltobackup.daemon.management import ManagementService
from ltobackup.web.app import _format_integer, _format_storage_size
from tests import test_boundary_store
from tests.web.test_live_ui import LiveWebAppTestCase


class BoundaryStatusProjectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = test_boundary_store.BoundaryStoreTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.store = self.fixture.store
        self.service = ManagementService(LtoApplication(self.fixture.root))

    def project(self) -> JobDetailV1:
        return JobDetailV1.model_validate(self.service._get_job("JOB1"))

    def history(
        self,
        action: str,
        payload: dict[str, object],
        *,
        occurred_at: str = "2026-09-12T11:30:00+00:00",
    ) -> None:
        with self.factory() as catalog, catalog.transaction() as db:
            catalog._job_history_tx(
                db,
                "JOB1",
                "boundary-test",
                action,
                "boundary-test",
                payload,
                occurred_at=occurred_at,
            )

    def test_job_detail_without_boundary_history_remains_compatible(self) -> None:
        detail = self.project()

        self.assertIsNone(detail.boundary_refresh)

    def test_current_claim_and_matching_scan_lease_are_projected_as_scanning(self) -> None:
        snapshot = self.store.capture("JOB1")

        detail = self.project()

        self.assertEqual(
            BoundaryRefreshStatusV1(
                state="scanning",
                completed_sequence=1,
                occurred_at=detail.boundary_refresh.occurred_at,
            ),
            detail.boundary_refresh,
        )
        self.assertNotIn("run_id", detail.boundary_refresh.model_dump())
        self.assertNotIn("superseded_manifest", detail.boundary_refresh.model_dump())
        with self.factory() as catalog:
            direct = boundary_refresh_status(catalog.connection, "JOB1")
        self.assertEqual(snapshot.completed_sequence, direct["completed_sequence"])

    def test_resume_request_is_projected_as_queued(self) -> None:
        self.history(
            "job.boundary_resume.requested",
            {"kind": "boundary.refresh", "state": "accepted", "request_id": "req-1"},
        )

        detail = self.project()

        self.assertEqual("queued", detail.boundary_refresh.state)
        self.assertIsNone(detail.boundary_refresh.completed_sequence)

    def test_old_claim_after_daemon_replacement_is_stale_not_scanning(self) -> None:
        self.store.capture("JOB1")
        with self.factory() as catalog:
            catalog.claim_daemon_owner("replacement-owner")

        detail = self.project()

        self.assertEqual("stale", detail.boundary_refresh.state)

    def test_pause_before_claim_does_not_advertise_queued_work(self) -> None:
        self.history("job.boundary_resume.requested", {"state": "accepted"})
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
        self.assertEqual("paused", self.project().boundary_refresh.state)

    def test_paused_label_wait_retains_deficit_without_advertising_active_work(self) -> None:
        self.history("job.boundary_replan.waiting_labels", {
            "required_additional_labels": 3, "candidate_files": 12,
        })
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
        status = self.project().boundary_refresh
        self.assertEqual("paused", status.state)
        self.assertEqual(3, status.required_additional_labels)

    def test_waiting_for_labels_projects_exact_deficit_and_candidate_quantities(self) -> None:
        snapshot = self.store.capture("JOB1")
        self.history(
            "job.boundary_replan.waiting_labels",
            {
                "completed_sequence": snapshot.completed_sequence,
                "required_additional_labels": 3,
                "candidate_files": 12_345,
                "candidate_bytes": 5 * 1024**3 + 512 * 1024**2,
                "expires_at": "2026-09-13T11:30:00+00:00",
                "candidate_sha256": "a" * 64,
                "plan": {"unassigned_batches": [{"items": [{"source_path": "/secret/photo.raw"}]}]},
            },
        )

        detail = self.project()

        self.assertEqual("waiting_labels", detail.boundary_refresh.state)
        self.assertEqual(3, detail.boundary_refresh.required_additional_labels)
        self.assertEqual(12_345, detail.boundary_refresh.candidate_files)
        self.assertEqual(5 * 1024**3 + 512 * 1024**2, detail.boundary_refresh.candidate_bytes)
        self.assertNotIn("secret", json.dumps(detail.boundary_refresh.model_dump()))

    def test_latest_relevant_failure_is_blocked_and_redacts_raw_evidence(self) -> None:
        self.store.capture("JOB1")
        self.history(
            "job.boundary_replan.deferred",
            {
                "completed_sequence": 1,
                "error_code": "boundary_source_unavailable",
                "raw_exception": "permission denied: /secret/photos",
                "source_evidence": {"path": "/secret/photos"},
            },
            occurred_at="2026-09-12T10:00:00+00:00",
        )
        self.history(
            "job.renamed",
            {"display_name": "A newer unrelated event"},
            occurred_at="2026-09-12T12:00:00+00:00",
        )

        detail = self.project()

        self.assertEqual("blocked", detail.boundary_refresh.state)
        self.assertEqual("boundary_source_unavailable", detail.boundary_refresh.error_code)
        self.assertEqual("2026-09-12T10:00:00+00:00", detail.boundary_refresh.occurred_at)
        encoded = json.dumps(detail.boundary_refresh.model_dump())
        self.assertNotIn("permission denied", encoded)
        self.assertNotIn("/secret", encoded)

    def test_discarded_candidate_is_projected_as_stale_with_safe_reason(self) -> None:
        self.history(
            "job.boundary_replan.discarded",
            {"completed_sequence": 1, "reason": "expired"},
        )

        detail = self.project()

        self.assertEqual("stale", detail.boundary_refresh.state)
        self.assertEqual("expired", detail.boundary_refresh.error_code)

    def test_pause_metadata_takes_precedence_over_a_current_claim(self) -> None:
        self.store.capture("JOB1")
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_jobs SET status='paused' WHERE id='JOB1'")
            db.execute(
                "UPDATE job_management_state SET "
                "pause_requested_at='2026-09-12T11:31:00+00:00',"
                "pause_acknowledged_at='2026-09-12T11:32:00+00:00' "
                "WHERE job_id='JOB1'"
            )

        detail = self.project()

        self.assertEqual("paused", detail.boundary_refresh.state)

    def test_applied_status_does_not_change_published_job_totals(self) -> None:
        before = self.project()
        self.history(
            "job.boundary_replan.applied",
            {"completed_sequence": 1, "candidate_files": 8, "candidate_bytes": 4096},
        )

        detail = self.project()

        self.assertEqual("applied", detail.boundary_refresh.state)
        self.assertEqual(before.manifest_totals, detail.manifest_totals)
        self.assertEqual(before.progress, detail.progress)


class BoundaryStatusRenderingTests(unittest.TestCase):
    def render(self, status: BoundaryRefreshStatusV1) -> str:
        runtime = {
            "live": False,
            "blocked": False,
            "blocked_explanation": None,
            "files_progress": "1 / 1 files",
            "bytes_progress": "7 B / 7 B",
            "cassette_progress": "1 / 3",
            "current_rate": "Not available",
            "current_rate_value": None,
            "effective_rate": "Not available",
            "effective_rate_value": None,
            "sample_freshness": "Sample age unavailable",
            "phase": "Not available",
            "eta": "Not available",
            "telemetry_html": "",
            "refresh_mode": "idle",
            "boundary_refresh": status,
        }
        environment = Environment(
            loader=FileSystemLoader("src/ltobackup/web/templates"),
            autoescape=select_autoescape(("html", "xml"), default_for_string=True),
        )
        environment.globals["format_integer"] = _format_integer
        environment.globals["format_storage_size"] = _format_storage_size
        return environment.get_template("partials/job_runtime.html").render(
            job=SimpleNamespace(id="JOB1"),
            runtime=runtime,
            cassette_cursor=None,
            manifest_cursor=None,
            history_cursor=None,
        )

    def test_runtime_partial_explains_every_boundary_refresh_state_in_english(self) -> None:
        examples = (
            ("queued", "Boundary refresh is queued"),
            ("scanning", "Boundary refresh is scanning"),
            ("blocked", "Boundary refresh is blocked"),
            ("stale", "Boundary refresh evidence is stale"),
            ("applied", "Boundary refresh was applied"),
            ("paused", "Boundary refresh is paused with this job"),
        )
        for state, expected in examples:
            with self.subTest(state=state):
                rendered = self.render(
                    BoundaryRefreshStatusV1(
                        state=state,
                        completed_sequence=1,
                        error_code=(
                            "boundary_source_unavailable"
                            if state in {"blocked", "stale"}
                            else None
                        ),
                        occurred_at="2026-09-12T11:30:00+00:00",
                    )
                )
                self.assertIn(expected, rendered)
                self.assertNotIn("Resume", rendered)
                self.assertNotIn("password", rendered.lower())
                if state == "scanning":
                    self.assertIn("added, changed, or removed", rendered)

    def test_runtime_partial_formats_waiting_label_deficit_files_and_bytes(self) -> None:
        rendered = self.render(
            BoundaryRefreshStatusV1(
                state="waiting_labels",
                completed_sequence=1,
                required_additional_labels=3,
                candidate_files=12_345,
                candidate_bytes=5 * 1024**3 + 512 * 1024**2,
                occurred_at="2026-09-12T11:30:00+00:00",
            )
        )

        self.assertIn("waiting for exactly 3 additional labels", rendered)
        self.assertIn("12,345 candidate files", rendered)
        self.assertIn("5.50 GiB", rendered)

    def test_paused_refresh_keeps_label_deficit_and_candidate_sizes_visible(self) -> None:
        rendered = self.render(BoundaryRefreshStatusV1(
            state="paused", required_additional_labels=3,
            candidate_files=12_345, candidate_bytes=5 * 1024**3 + 512 * 1024**2,
            occurred_at="2026-09-12T11:30:00+00:00",
        ))
        self.assertIn("Boundary refresh is paused with this job", rendered)
        self.assertIn("3 additional labels", rendered)
        self.assertIn("12,345 candidate files", rendered)
        self.assertIn("5.50 GiB", rendered)
        self.assertNotIn("is scanning", rendered)


class BoundaryRuntimeRefreshTests(LiveWebAppTestCase):
    def test_scanning_refresh_overrides_matching_waiting_media_cadence(self) -> None:
        status = self.daemon.status
        assert not isinstance(status, Exception) and status.job is not None
        self.daemon.status = status.model_copy(update={
            "job": status.job.model_copy(update={"id": "JOB1", "state": "waiting_media"}),
            "operation": None,
        })
        self.daemon.job = self.daemon.job.model_copy(update={
            "state": "waiting_media", "boundary_refresh": BoundaryRefreshStatusV1(
                state="scanning", occurred_at="2026-09-12T11:30:00+00:00",
            ),
        })
        self.login()
        response = self.client.get("/partials/jobs/JOB1/runtime")
        self.assertEqual(200, response.status_code, response.text)
        self.assertIn('data-live-refresh-mode="active"', response.text)

    def test_idle_tape_runtime_refreshes_actively_during_boundary_work(self) -> None:
        status = self.daemon.status
        assert not isinstance(status, Exception)
        self.daemon.status = status.model_copy(
            update={"job": None, "operation": None, "expected_media": None}
        )
        self.login()

        for state in ("queued", "scanning"):
            with self.subTest(state=state):
                self.daemon.job = self.daemon.job.model_copy(
                    update={
                        "state": "completed",
                        "boundary_refresh": BoundaryRefreshStatusV1(
                            state=state,
                            completed_sequence=1,
                            occurred_at="2026-09-12T11:30:00+00:00",
                        ),
                    }
                )

                response = self.client.get("/partials/jobs/JOB1/runtime")

                self.assertEqual(200, response.status_code, response.text)
                self.assertIn('data-live-refresh-mode="active"', response.text)


if __name__ == "__main__":
    unittest.main()
