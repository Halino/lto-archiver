from __future__ import annotations

import re
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

from fastapi.testclient import TestClient

from ltobackup.client import DaemonUnavailable
from ltobackup.daemon.api_models import (
    CriticalRecoveryProofV1,
    DaemonStatusV1,
    DriveStatusV1,
    ExpectedMediaV1,
    JobDetailV1,
    JobSummaryV1,
    OperationResponseV1,
    PhaseDurationsV1,
    ProgressV1,
    TelemetrySampleV1,
    TelemetryV1,
)
from ltobackup.web.app import WebSettings, create_web_app, render_telemetry
from ltobackup.web.auth_store import AuthStore
from tests.web.english_surface import assert_english_document


class _HeadingParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.levels: list[int] = []

    def handle_starttag(self, tag: str, _attrs) -> None:
        if re.fullmatch(r"h[1-6]", tag):
            self.levels.append(int(tag[1]))


def authoritative_status() -> DaemonStatusV1:
    return DaemonStatusV1(
        accepting_mutations=True,
        admission_blocker=None,
        drive=DriveStatusV1(
            state="busy",
            loaded=True,
            display_label="LTO & <drive>",
            cleaning_required=False,
            tape_alert_codes=(),
        ),
        expected_media=ExpectedMediaV1(
            sequence=4,
            label="TAPE<04>",
            format_required=False,
        ),
        job=JobSummaryV1(
            id="JOB1",
            display_name="Archivio <script>alert(1)</script>",
            state="running",
            current_sequence=4,
            total_cassettes=20,
        ),
        operation=OperationResponseV1(
            id="op-1",
            kind="archive",
            state="running",
            phase="finalizing_index",
            idempotency_key="daemon-key",
            principal="admin",
            job_id="JOB1",
            cassette_sequence=4,
            started_at="2026-08-21T12:00:00Z",
            finished_at=None,
            error_class=None,
            error_code=None,
            error_message=None,
        ),
        progress=ProgressV1(
            files_completed=525,
            files_total=35_894,
            bytes_completed=1_073_741_824,
            bytes_total=2_147_483_648,
        ),
        telemetry=TelemetryV1(
            current_mib_per_second=142.5,
            effective_mib_per_second=118.25,
            samples=(),
            durations=PhaseDurationsV1(
                copy_seconds=3600,
                close_seconds=120,
                finalization_seconds=95,
                unmount_seconds=0,
                unload_seconds=0,
            ),
        ),
    )


class FakeDaemonClient:
    def __init__(self, status: DaemonStatusV1 | Exception | None = None) -> None:
        self.status = status if status is not None else authoritative_status()
        self.gets: list[tuple[str, type[DaemonStatusV1]]] = []
        self.mutations: list[dict[str, object]] = []

    def get(
        self,
        path: str,
        *,
        response_model: type[DaemonStatusV1],
        principal: str | None = None,
        role: str | None = None,
    ) -> DaemonStatusV1:
        del principal, role
        self.gets.append((path, response_model))
        if isinstance(self.status, Exception):
            raise self.status
        if path.startswith("/api/v1/critical-recovery/"):
            if self.status.critical_recovery is None:
                raise DaemonUnavailable()
            return self.status.critical_recovery
        return self.status

    def get_critical_recovery(self, operation_id, *, principal, role):
        return self.get(
            f"/api/v1/critical-recovery/{operation_id}",
            response_model=CriticalRecoveryProofV1,
            principal=principal,
            role=role,
        )

    def get_job(self, job_id: str, **_kwargs) -> JobDetailV1:
        # These security fixtures exercise session identity, not an operator pause.
        # Use the actual response model so newly consumed fields remain present.
        return JobDetailV1(
            id=job_id,
            display_name="Backup",
            state="paused",
            library_ids=("LIB1",),
            media_profile="LTO-5",
            cassettes=(),
            requires_format_confirmation=False,
            resumable=True,
            pause_requested=False,
            pause_acknowledged=False,
        )

    def reconcile_critical_recovery(
        self, operation_id, request, idempotency_key, *, principal, role
    ):
        self.mutations.append(
            {
                "path": f"/api/v1/critical-recovery/{operation_id}/reconcile",
                "payload": request.model_dump(mode="json"),
                "idempotency_key": idempotency_key,
                "principal": principal,
                "role": role,
            }
        )
        return self.status.critical_recovery

    def abandon_critical_recovery(
        self, operation_id, request, idempotency_key, *, principal, role
    ):
        self.mutations.append(
            {
                "path": f"/api/v1/critical-recovery/{operation_id}/abandon",
                "payload": request.model_dump(mode="json"),
                "idempotency_key": idempotency_key,
                "principal": principal,
                "role": role,
            }
        )
        return None

    def authorize_critical_replacement(
        self, operation_id, request, idempotency_key, *, principal, role
    ):
        self.mutations.append(
            {
                "path": (
                    f"/api/v1/critical-recovery/{operation_id}/authorize-replacement"
                ),
                "payload": request.model_dump(mode="json"),
                "idempotency_key": idempotency_key,
                "principal": principal,
                "role": role,
            }
        )
        return None

    def post(
        self,
        path: str,
        payload: dict,
        idempotency_key: str,
        *,
        principal: str,
        role: str = "admin",
    ) -> dict[str, object]:
        mutation = {
            "path": path,
            "payload": payload,
            "idempotency_key": idempotency_key,
            "principal": principal,
            "role": role,
        }
        self.mutations.append(mutation)
        return {
            "id": "op-resume",
            "kind": "resume",
            "state": "accepted",
            "phase": None,
            "idempotency_key": idempotency_key,
            "principal": principal,
            "job_id": "JOB1",
            "cassette_sequence": 4,
            "started_at": "2026-08-21T12:01:00Z",
            "finished_at": None,
            "error_class": None,
            "error_code": None,
            "error_message": None,
        }

    def resume_job(
        self,
        job_id,
        request,
        idempotency_key,
        *,
        principal,
        role,
    ):
        self.mutations.append(
            {
                "path": f"/api/v1/jobs/{job_id}/resume",
                "payload": request.model_dump(mode="json"),
                "idempotency_key": idempotency_key,
                "principal": principal,
                "role": role,
            }
        )

    def events(self, after_id: int | None = None, *, last_event_id: int | None = None):
        del after_id, last_event_id
        return iter(())


class WebAppTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = AuthStore(Path(self.temporary.name) / "web-auth.db")
        self.store.create_admin("admin", "-".join(("test", "only", "password")))
        self.daemon = FakeDaemonClient()
        self.app = create_web_app(
            WebSettings(secure_cookies=True),
            self.store,
            self.daemon,
        )
        self.client = TestClient(
            self.app,
            base_url="https://console.example",
            follow_redirects=False,
            client=("127.0.0.1", 50_000),
        )
        self.addCleanup(self.client.close)

    def login(self) -> str:
        login_page = self.client.get("/login")
        self.assertEqual(200, login_page.status_code)
        login_csrf = re.search(
            r'name="login_csrf" value="([A-Za-z0-9_-]+)"', login_page.text
        )
        self.assertIsNotNone(login_csrf)
        assert login_csrf is not None
        response = self.client.post(
            "/login",
            data={
                "username": "".join(("ad", "min")),
                "password": "-".join(("test", "only", "password")),
                "login_csrf": login_csrf.group(1),
            },
        )
        self.assertEqual(303, response.status_code, response.text)
        dashboard = self.client.get("/")
        self.assertEqual(200, dashboard.status_code, dashboard.text)
        match = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', dashboard.text)
        self.assertIsNotNone(match)
        assert match is not None
        return match.group(1)


class DashboardTests(WebAppTestCase):
    def test_telemetry_chart_separates_raw_instantaneous_and_effective_series(self):
        """Collapsing the two rates would make instantaneous and average ambiguous."""
        html = render_telemetry(
            (
                TelemetrySampleV1(
                    event_id=1,
                    occurred_at="2026-08-31T18:18:00Z",
                    mib_per_second=146.625,
                ),
                TelemetrySampleV1(
                    event_id=2,
                    occurred_at="2026-08-31T18:18:01Z",
                    mib_per_second=None,
                ),
            ),
            effective_rate=104.25,
        )

        self.assertIn("Raw instantaneous rate", html)
        self.assertIn("Effective operation rate", html)
        self.assertIn('data-series="instantaneous"', html)
        self.assertIn('data-series="effective-reference"', html)
        self.assertIn("146.625 MiB/s", html)
        self.assertIn("104.250 MiB/s", html)
        self.assertIn('data-gap="true"', html)
        self.assertEqual(1, html.count("Effective operation rate 104.250 MiB/s"))
        self.assertNotIn("data-effective-rate", html)
        self.assertIn('data-raw-rate="146.625"', html)
        self.assertIn('data-presentation-smoothed="true"', html)

    def test_instantaneous_presentation_smoothing_resets_after_a_gap(self):
        """Removing segment-local smoothing would restore the jerky raw geometry."""
        html = render_telemetry(
            (
                TelemetrySampleV1(event_id=1, occurred_at="2026-08-31T18:18:00Z", mib_per_second=10.0),
                TelemetrySampleV1(event_id=2, occurred_at="2026-08-31T18:18:01Z", mib_per_second=30.0),
                TelemetrySampleV1(event_id=3, occurred_at="2026-08-31T18:18:02Z", mib_per_second=None),
                TelemetrySampleV1(event_id=4, occurred_at="2026-08-31T18:18:03Z", mib_per_second=30.0),
            ),
            effective_rate=20.0,
        )

        self.assertIn('data-raw-rate="30.000" data-presentation-rate="17.000"', html)
        self.assertIn('data-raw-rate="30.000" data-presentation-rate="30.000"', html)
        self.assertIn('data-segment-events="1,2"', html)

    def test_live_operation_progress_is_visible_without_a_job_projection(self) -> None:
        """Requiring status.job must not hide valid qualification telemetry."""
        self.daemon.status = authoritative_status().model_copy(update={"job": None})
        self.login()

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assertIn("525 / 35,894 files", response.text)
        self.assertIn("1.00 GiB / 2.00 GiB", response.text)
        self.assertIn("142.50 MiB/s", response.text)
        self.assertIn("118.25 MiB/s", response.text)
        self.assertLess(
            response.text.index('aria-label="Progress and rate"'),
            response.text.index('aria-label="Primary operation status"'),
        )

    def test_dashboard_requires_an_authenticated_session(self) -> None:
        response = self.client.get("/")

        self.assertEqual(303, response.status_code)
        self.assertEqual("/login", response.headers["location"])
        self.assertEqual([], self.daemon.gets)

    def test_dashboard_first_view_contains_authoritative_operation_cards(self) -> None:
        self.login()

        response = self.client.get("/")

        self.assertEqual(200, response.status_code)
        self.assertIn('data-card="drive-status"', response.text)
        self.assertIn('data-card="expected-cassette"', response.text)
        self.assertIn('data-card="active-job"', response.text)
        self.assertIn("LTFS index finalization", response.text)
        self.assertIn("142.50 MiB/s", response.text)
        self.assertIn("118.25 MiB/s", response.text)
        self.assertIn("525 / 35,894 files", response.text)
        self.assertIn("Archivio &lt;script&gt;alert(1)&lt;/script&gt;", response.text)
        assert_english_document(
            self,
            response.text,
            allowed_data=("Archivio <script>alert(1)</script>",),
        )
        self.assertEqual([("/api/v1/status", DaemonStatusV1)] * 2, self.daemon.gets)

    def test_first_file_progress_is_visible_before_any_file_completes(self) -> None:
        """Removing intra-file rendering must hide this first-file observation."""
        status = authoritative_status()
        self.daemon.status = status.model_copy(
            update={
                "progress": ProgressV1(
                    files_completed=0,
                    files_total=112,
                    bytes_completed=64 * 1024**2,
                    bytes_total=16 * 1024**3,
                ),
                "telemetry": TelemetryV1(
                    current_mib_per_second=146.6,
                    effective_mib_per_second=104.0,
                    samples=(
                        TelemetrySampleV1(
                            event_id=1,
                            occurred_at="2026-08-31T18:18:00Z",
                            mib_per_second=146.6,
                        ),
                    ),
                    durations=status.telemetry.durations,
                ),
            }
        )
        self.login()

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assertIn("0 / 112 files", response.text)
        self.assertIn("64.00 MiB / 16.00 GiB", response.text)
        self.assertIn("146.60 MiB/s", response.text)
        self.assertIn("104.00 MiB/s", response.text)
        self.assertIn('data-raw-rate="146.600"', response.text)
        self.assertNotIn("Telemetry unavailable", response.text)
        self.assertEqual([("/api/v1/status", DaemonStatusV1)] * 2, self.daemon.gets)

    def test_dashboard_heading_outline_starts_with_the_page_h1(self) -> None:
        self.login()

        response = self.client.get("/")
        headings = _HeadingParser()
        headings.feed(response.text)

        self.assertGreater(len(headings.levels), 1)
        self.assertEqual(1, headings.levels[0])
        self.assertNotIn(1, headings.levels[1:])

    def test_daemon_fields_are_escaped_and_runtime_assets_are_local(self) -> None:
        self.login()

        response = self.client.get("/")

        self.assertNotIn("<script>alert(1)</script>", response.text)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", response.text)
        self.assertIn("TAPE&lt;04&gt;", response.text)
        self.assertIn('src="/static/htmx.js"', response.text)
        self.assertNotIn("cdn.jsdelivr.net", response.text)

    def test_missing_optional_status_values_are_explicitly_unavailable(self) -> None:
        self.daemon.status = authoritative_status().model_copy(
            update={
                "drive": DriveStatusV1(
                    state="unavailable",
                    loaded=False,
                    display_label="",
                    cleaning_required=False,
                    tape_alert_codes=(),
                ),
                "expected_media": None,
                "job": None,
                "operation": None,
                "telemetry": TelemetryV1(
                    current_mib_per_second=None,
                    effective_mib_per_second=None,
                    samples=(),
                    durations=PhaseDurationsV1(
                        copy_seconds=0,
                        close_seconds=0,
                        finalization_seconds=0,
                        unmount_seconds=0,
                        unload_seconds=0,
                    ),
                ),
            }
        )
        self.login()

        response = self.client.get("/")

        self.assertGreaterEqual(response.text.count("Not available"), 5)
        self.assertNotIn("0.00 MiB/s", response.text)
        self.assertNotIn("Cassette 0", response.text)

    def test_daemon_failure_renders_an_explicit_unavailable_state(self) -> None:
        self.daemon.status = DaemonUnavailable()
        self.login()

        response = self.client.get("/")

        self.assertEqual(200, response.status_code)
        self.assertIn("Daemon unavailable", response.text)
        self.assertGreaterEqual(response.text.count("Not available"), 5)


if __name__ == "__main__":
    unittest.main()
