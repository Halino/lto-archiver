from __future__ import annotations

from ltobackup.daemon.api_models import (
    DaemonStatusV1,
    JobCapabilitiesV1,
    JobCassettePageV1,
    JobDetailV1,
    JobHistoryPageV1,
    JobManifestPageV1,
)
from ltobackup.web.app import DashboardView
from tests.web.test_dashboard import WebAppTestCase, authoritative_status


def blocked_waiting_media_status() -> DaemonStatusV1:
    payload = authoritative_status().model_dump()
    payload["accepting_mutations"] = False
    payload["expected_media"].update(sequence=9, label="TAPE09", format_required=True)
    payload["job"].update(state="waiting_media", current_sequence=9)
    payload["operation"].update(
        id="blocked-op-9",
        state="recovery_required",
        phase=None,
        cassette_sequence=9,
        error_class="operator_required",
        error_code="recovery_required",
        error_message="Safe reconciliation is required before another operation.",
    )
    payload["admission_blocker"] = dict(payload["operation"])
    payload["critical_recovery"] = None
    return DaemonStatusV1.model_validate(payload)


class BlockedStatusTests(WebAppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.daemon.status = blocked_waiting_media_status()
        self.daemon.get_job = lambda job_id, **_kwargs: JobDetailV1(
            id=job_id,
            display_name="Archive",
            state="waiting_media",
            library_ids=("LIB1",),
            media_profile="LTO-5",
            cassettes=(),
            requires_format_confirmation=False,
            resumable=True,
            imported=True,
            capabilities=JobCapabilitiesV1(start=True, resume=True),
        )
        self.daemon.get_job_cassettes = lambda *_args, **_kwargs: JobCassettePageV1(
            items=(), next_cursor=None
        )
        self.daemon.get_job_manifest = lambda *_args, **_kwargs: JobManifestPageV1(
            items=(), next_cursor=None
        )
        self.daemon.get_job_history = lambda *_args, **_kwargs: JobHistoryPageV1(
            items=(), next_cursor=None
        )

    def assert_blocked_status_visible(self, html: str) -> None:
        self.assertIn("blocked", html.lower())
        self.assertIn("recovery required", html.lower())
        self.assertNotIn("not writing", html.lower())
        self.assertIn("blocked-op-9", html)
        self.assertIn("recovery_required", html)
        self.assertNotIn("Insert the expected cassette", html)
        self.assertNotIn("already running", html)
        self.assertNotIn("Wait for the current operation", html)
        self.assertNotIn("Wait for the operation to finish", html)
        self.assertNotIn('action="/jobs/JOB1/start"', html)
        self.assertNotIn('action="/jobs/JOB1/resume"', html)

    def test_dashboard_view_recovery_precedes_waiting_media_without_critical_proof(self):
        view = DashboardView.from_status(self.daemon.status)

        self.assert_blocked_status_visible(
            f"{view.operation_title} {view.operation_phase_label} {view.explanation}"
        )
        self.assertFalse(view.can_resume)
        self.assertFalse(view.finalization_active)

    def test_later_phase_recovery_does_not_claim_tape_processes_are_quiescent(self):
        operation = self.daemon.status.operation.model_copy(update={"phase": "writing"})
        status = self.daemon.status.model_copy(
            update={"operation": operation, "admission_blocker": operation}
        )

        view = DashboardView.from_status(status)

        self.assertNotIn("not writing", view.explanation.lower())
        self.assertNotIn("not writing", view.operation_phase_label.lower())
        self.assertNotIn("quiescent", view.explanation.lower())
        self.assertIn("blocked", view.operation_title.lower())

    def test_dashboard_admission_blocker_remains_visible_without_operation(self):
        self.daemon.status = self.daemon.status.model_copy(update={"operation": None})
        self.login()

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assert_blocked_status_visible(response.text)

    def test_dashboard_recovery_operation_remains_visible_without_admission_blocker(self):
        self.daemon.status = self.daemon.status.model_copy(update={"admission_blocker": None})
        self.login()

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assert_blocked_status_visible(response.text)

    def test_dashboard_refresh_replaces_waiting_media_instruction_with_blocker(self):
        blocked = self.daemon.status
        self.daemon.status = blocked.model_copy(
            update={"operation": None, "admission_blocker": None, "accepting_mutations": True}
        )
        self.login()
        waiting = self.client.get("/status-fragment")
        self.assertIn("Insert the expected cassette 9", waiting.text)
        self.daemon.status = blocked

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assert_blocked_status_visible(response.text)

    def test_job_detail_and_runtime_refresh_report_blocked_without_running_claim(self):
        self.login()

        for path in ("/jobs/JOB1", "/partials/jobs/JOB1/runtime"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code)
                self.assert_blocked_status_visible(response.text)

    def test_job_admission_blocker_hides_actions_without_active_operation(self):
        self.daemon.status = self.daemon.status.model_copy(update={"operation": None})
        self.login()

        response = self.client.get("/partials/jobs/JOB1/runtime")

        self.assertEqual(200, response.status_code)
        self.assert_blocked_status_visible(response.text)

    def test_media_reports_recovery_blocker_without_offering_format(self):
        self.login()

        response = self.client.get("/media")

        self.assertEqual(200, response.status_code)
        self.assert_blocked_status_visible(response.text)
        self.assertNotIn('action="/media/9/format"', response.text)
