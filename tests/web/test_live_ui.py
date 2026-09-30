from __future__ import annotations

import asyncio
import json
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.responses import StreamingResponse

from ltobackup.client import DaemonUnavailable
from ltobackup.daemon.api_models import (
    ApplicationSettingsV1,
    DaemonStatusV1,
    DiagnosticSummaryV1,
    HostSettingsV1,
    JobCassettePageV1,
    JobDetailV1,
    JobHistoryPageV1,
    JobListPageV1,
    JobManifestPageV1,
    LibrarySummaryV1,
    LogEntryV1,
    LogsPageV1,
    MediaProfilesV1,
    SettingsSummaryV1,
    SystemLogEntryV1,
    SystemLogsPageV1,
    TelemetrySampleV1,
)
from ltobackup.log_reader.protocol import LogDirection, LogRange, LogSource, Severity
from ltobackup.web.app import render_telemetry
from tests.web.test_dashboard import (
    FakeDaemonClient,
    WebAppTestCase,
    authoritative_status,
)


def _sample(event_id: int, occurred_at: str, rate: float | None) -> TelemetrySampleV1:
    return TelemetrySampleV1(
        event_id=event_id,
        occurred_at=occurred_at,
        mib_per_second=rate,
    )


class LiveFakeDaemon(FakeDaemonClient):
    def __init__(self) -> None:
        super().__init__()
        self.event_requests: list[tuple[int | None, int | None]] = []
        self.event_items: list[dict[str, object]] = []
        self.settings = SettingsSummaryV1(
            source_root_count=3,
            restore_root_count=1,
            buffer_bytes=8 * 1024 * 1024,
            socket_group="lto-web",
            stable_tape_id_configured=True,
            stable_scsi_id_configured=True,
        )
        self.application_settings = ApplicationSettingsV1(
            revision=1,
            capacity_reserve_bytes=1024,
            minimum_source_file_age_seconds=60,
            copy_buffer_bytes=8 * 1024 * 1024,
            content_verification_policy="manifest",
            source_change_detection_policy="size_mtime_change",
            default_media_profile="LTO-9",
            tape_root_directory="archive",
            legacy_tape_capacity_bytes=0,
        )
        self.host_settings = HostSettingsV1(
            daemon_socket_path="/run/lto-archiver/daemon.sock",
            service_group="lto-web",
            state_directory="/var/lib/lto-archiver",
            tape_device_path="/dev/tape/by-id/drive-nst",
            scsi_device_path="/dev/lto-archiver-scsi-drive",
            mount_path="/mnt/lto-archiver/tape",
            managed_source_mount_root="/mnt/lto-archiver/sources",
            source_allowlist=("/srv/source",),
            restore_roots=("/srv/restore",),
            required_restart=False,
        )
        self.job = JobDetailV1.model_validate(
            {
                "id": "JOB1",
                "display_name": "Backup principale",
                "state": "paused",
                "library_ids": ("LIB1",),
                "media_profile": "LTO-9",
                "cassettes": (),
                "requires_format_confirmation": False,
                "resumable": True,
                "revision": 1,
                "capabilities": {"resume": True, "rename": True},
            }
        )
        self.logs = LogsPageV1(
            items=(
                LogEntryV1(
                    id=9,
                    occurred_at="2026-08-21T12:00:00Z",
                    level="warning",
                    code="media_wait",
                    message="Attesa supporto autorizzato",
                    request_id="req-9",
                    operation_id="op-1",
                ),
            ),
            next_after_id=None,
        )
        self.system_log_requests: list[dict[str, object]] = []
        self.system_logs = SystemLogsPageV1(
            source=LogSource.ALL,
            severity=Severity.INFO,
            range=LogRange.ONE_HOUR,
            direction=LogDirection.OLDER,
            search=None,
            limit=100,
            items=(
                SystemLogEntryV1(
                    cursor="s=cursor-2;i=2",
                    occurred_at="2026-08-21T12:00:00Z",
                    severity=Severity.WARNING,
                    source=LogSource.LTFS,
                    unit="lto-archiver-command-broker.service",
                    message="Tape is waiting for authorized media <ready>.",
                    repeat_count=2,
                    truncated=False,
                    pid=321,
                    boot_id="boot-1",
                    operation_id="operation-1",
                    job_id="JOB1",
                    cassette_label="TAPE05",
                    cassette_sequence=5,
                    command_kind="mount",
                    phase="mount",
                    exit_code=5,
                    elapsed_ms=1234,
                ),
            ),
            older_cursor="s=older;i=1",
            newer_cursor="s=newer;i=3",
            cursor_rotated=False,
            live_supported=True,
            unavailable_sources=(),
        )
        self.diagnostic_summary = DiagnosticSummaryV1.model_validate(
            {
                "api_version": 1,
                "health": {
                    "status": "ok",
                    "cleaning_required": False,
                    "tape_alert_codes": [],
                },
                "telemetry": {
                    "files_completed": 0,
                    "bytes_completed": 0,
                    "current_mib_per_second": None,
                    "effective_mib_per_second": None,
                    "samples": [],
                    "phase_durations": {
                        "source_open_seconds": 0,
                        "smb_read_seconds": 0,
                        "ltfs_write_admission_seconds": 0,
                        "copy_seconds": 0,
                        "close_seconds": 0,
                        "manifest_seconds": 0,
                        "snapshot_seconds": 0,
                        "finalization_seconds": 0,
                        "unmount_seconds": 0,
                        "unload_seconds": 0,
                        "retry_seconds": 0,
                        "operator_wait_seconds": 0,
                    },
                    "current_phase": None,
                    "closed": False,
                },
            }
        )

    def get(
        self,
        path: str,
        *,
        response_model,
        principal: str | None = None,
        role: str | None = None,
    ):
        del principal, role
        self.gets.append((path, response_model))
        if path == "/api/v1/status":
            if isinstance(self.status, Exception):
                raise self.status
            return self.status
        if path == "/api/v1/settings":
            return self.settings
        if path == "/api/v1/diagnostics/summary":
            return self.diagnostic_summary
        if path.startswith("/api/v1/logs?"):
            return self.logs
        raise AssertionError(f"unexpected daemon GET: {path}")

    def list_jobs(self, **_kwargs):
        return JobListPageV1(items=(self.job,), next_cursor=None)

    def get_job(self, job_id: str, **_kwargs):
        if job_id != self.job.id:
            raise AssertionError(f"unexpected job id: {job_id}")
        return self.job

    def get_job_cassettes(self, job_id: str, **_kwargs):
        if job_id != self.job.id:
            raise AssertionError(f"unexpected job id: {job_id}")
        return JobCassettePageV1(items=self.job.cassettes, next_cursor=None)

    def get_job_manifest(self, job_id: str, **_kwargs):
        if job_id != self.job.id:
            raise AssertionError(f"unexpected job id: {job_id}")
        return JobManifestPageV1(items=(), next_cursor=None)

    def get_job_history(self, job_id: str, **_kwargs):
        if job_id != self.job.id:
            raise AssertionError(f"unexpected job id: {job_id}")
        return JobHistoryPageV1(items=(), next_cursor=None)

    def list_libraries(self, **_kwargs):
        return (
            LibrarySummaryV1(
                id="LIB1",
                display_name="Primary library",
                source_root="/srv/source/LIB1",
                state="active",
                scan_state="ready",
                last_successful_scan_at="2026-08-25T10:00:00+00:00",
                file_count=2,
                byte_count=7,
                revision=3,
            ),
        )

    def get_application_settings(self, **_kwargs):
        return self.application_settings

    def get_host_settings(self, **_kwargs):
        return self.host_settings

    def get_media_profiles(self, **_kwargs):
        return MediaProfilesV1.model_validate(
            {
                "default_media_profile": "LTO-9",
                "items": (
                    {
                        "key": "LTO-9",
                        "generation": 9,
                        "native_capacity_bytes": 18_000_000_000_000,
                        "ltfs_usable_bytes": 17_550_000_000_000,
                    },
                ),
            }
        )

    def get_system_logs(self, **kwargs):
        self.system_log_requests.append(dict(kwargs))
        if isinstance(self.system_logs, Exception):
            raise self.system_logs
        return self.system_logs

    def events(self, after_id: int | None = None, *, last_event_id: int | None = None):
        self.event_requests.append((after_id, last_event_id))
        return iter(self.event_items)


class LiveWebAppTestCase(WebAppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.close()
        self.daemon = LiveFakeDaemon()
        from ltobackup.web.app import WebSettings, create_web_app

        self.app = create_web_app(
            WebSettings(secure_cookies=True), self.store, self.daemon
        )
        self.client = TestClient(
            self.app,
            base_url="https://console.example",
            follow_redirects=False,
            client=("127.0.0.1", 50_000),
        )
        self.addCleanup(self.client.close)

    def csrf_and_key(self, path: str = "/") -> tuple[str, str]:
        self.login()
        response = self.client.get(path)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', response.text)
        key = re.search(
            r'name="idempotency_key" value="([0-9a-f-]{36})"', response.text
        )
        self.assertIsNotNone(csrf, response.text)
        self.assertIsNotNone(key, response.text)
        assert csrf is not None and key is not None
        return csrf.group(1), key.group(1)

    def csrf_from_read_only_page(self, path: str) -> str:
        self.login()
        response = self.client.get(path)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', response.text)
        self.assertIsNotNone(csrf, response.text)
        self.assertNotIn('name="idempotency_key"', response.text)
        assert csrf is not None
        return csrf.group(1)


class LiveStateTests(LiveWebAppTestCase):
    def test_jobs_and_libraries_expose_authenticated_live_fragments(self) -> None:
        self.login()

        jobs_page = self.client.get("/jobs")
        jobs_fragment = self.client.get("/jobs/status-fragment")
        libraries_page = self.client.get("/libraries")
        libraries_fragment = self.client.get("/libraries/status-fragment")

        for response in (
            jobs_page,
            jobs_fragment,
            libraries_page,
            libraries_fragment,
        ):
            self.assertEqual(200, response.status_code, response.text)
        self.assertIn('id="jobs-live-status"', jobs_page.text)
        self.assertIn('data-live-fragment-url="/jobs/status-fragment"', jobs_page.text)
        self.assertIn('id="jobs-live-status"', jobs_fragment.text)
        self.assertIn('id="libraries-live-status"', libraries_page.text)
        self.assertIn(
            'data-live-fragment-url="/libraries/status-fragment"',
            libraries_page.text,
        )
        self.assertIn('id="libraries-live-status"', libraries_fragment.text)

    def test_live_fragment_routes_require_authentication(self) -> None:
        for path in ("/jobs/status-fragment", "/libraries/status-fragment"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(401, response.status_code)
                self.assertEqual("unauthorized", response.json()["error"]["code"])

    def open_event_stream(self) -> StreamingResponse:
        session_cookie = self.client.cookies.get("lto_archiver_session")
        csrf_cookie = self.client.cookies.get("lto_archiver_csrf")
        self.assertIsNotNone(session_cookie)
        self.assertIsNotNone(csrf_cookie)
        cookie = (
            f"lto_archiver_session={session_cookie}; lto_archiver_csrf={csrf_cookie}"
        )
        request = Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "GET",
                "scheme": "https",
                "path": "/events",
                "raw_path": b"/events",
                "query_string": b"",
                "headers": [(b"cookie", cookie.encode("ascii"))],
                "client": ("127.0.0.1", 50_000),
                "server": ("console.example", 443),
            }
        )
        endpoint = next(
            route.endpoint
            for route in self.app.routes
            if getattr(route, "path", None) == "/events"
        )
        response = asyncio.run(endpoint(request))
        self.assertIsInstance(response, StreamingResponse)
        return response

    @staticmethod
    def first_stream_chunk(response: StreamingResponse) -> str | None:
        async def read() -> str | None:
            try:
                chunk = await anext(response.body_iterator)
            except StopAsyncIteration:
                return None
            return chunk.decode("utf-8") if isinstance(chunk, bytes) else chunk

        return asyncio.run(read())

    def test_events_require_authentication(self) -> None:
        response = self.client.get("/events")

        self.assertEqual(401, response.status_code)
        self.assertEqual([], self.daemon.event_requests)

    def test_open_sse_stream_stops_before_emitting_after_logout(self) -> None:
        self.daemon.event_items = [
            {
                "api_version": 1,
                "id": 1,
                "event": "state.replace",
                "data": authoritative_status().model_dump(mode="json"),
            }
        ]
        csrf = self.login()
        stream = self.open_event_stream()

        logout = self.client.post("/logout", data={"csrf": csrf})

        self.assertEqual(303, logout.status_code)
        self.assertIsNone(self.first_stream_chunk(stream))

    def test_open_sse_stream_stops_before_emitting_after_session_expiry(
        self,
    ) -> None:
        self.daemon.event_items = [
            {
                "api_version": 1,
                "id": 1,
                "event": "state.replace",
                "data": authoritative_status().model_dump(mode="json"),
            }
        ]
        self.login()
        stream = self.open_event_stream()
        with closing(sqlite3.connect(self.store.database)) as connection:
            connection.execute(
                "UPDATE web_sessions SET idle_expires_at = 0, absolute_expires_at = 0"
            )
            connection.commit()

        self.assertIsNone(self.first_stream_chunk(stream))

    def test_sse_reconnect_forwards_header_and_preserves_authoritative_replacement(
        self,
    ) -> None:
        replacement = authoritative_status().model_dump(mode="json")
        self.daemon.event_items = [
            {"api_version": 1, "id": 7, "event": "state.replace", "data": replacement}
        ]
        self.login()

        response = self.client.get("/events", headers={"Last-Event-ID": "4"})

        self.assertEqual(200, response.status_code)
        self.assertEqual(
            "text/event-stream", response.headers["content-type"].split(";")[0]
        )
        self.assertEqual([(None, 4)], self.daemon.event_requests)
        self.assertIn("id: 7\nevent: state.replace\ndata: ", response.text)
        body = json.loads(response.text.split("data: ", 1)[1].split("\n\n", 1)[0])
        self.assertEqual(replacement, body)
        self.assertTrue(response.text.endswith("event: stream.ready\ndata: {}\n\n"))

    def test_sse_query_cursor_is_forwarded_when_header_is_unavailable(self) -> None:
        self.login()

        response = self.client.get("/events", params={"after_id": "41"})

        self.assertEqual(200, response.status_code)
        self.assertEqual([(41, None)], self.daemon.event_requests)

    def test_successful_empty_daemon_stream_emits_browser_ready_signal(self) -> None:
        self.login()

        stream = self.open_event_stream()

        self.assertEqual(
            "event: stream.ready\ndata: {}\n\n",
            self.first_stream_chunk(stream),
        )

    def test_failed_daemon_stream_does_not_emit_browser_ready_signal(self) -> None:
        def unavailable_events(
            after_id: int | None = None,
            *,
            last_event_id: int | None = None,
        ):
            del after_id, last_event_id
            raise DaemonUnavailable()

        self.daemon.events = unavailable_events  # type: ignore[method-assign]
        self.login()

        stream = self.open_event_stream()

        self.assertIsNone(self.first_stream_chunk(stream))

    def test_sse_rejects_state_replace_with_partial_patch_payload(self) -> None:
        self.daemon.event_items = [
            {
                "api_version": 1,
                "id": 1,
                "event": "state.replace",
                "data": {"progress": None},
            }
        ]
        self.login()

        response = self.client.get("/events")

        self.assertEqual(200, response.status_code)
        self.assertEqual("", response.text)

    def test_sse_rejects_state_patch_with_full_replacement_payload(self) -> None:
        self.daemon.event_items = [
            {
                "api_version": 1,
                "id": 1,
                "event": "state.patch",
                "data": authoritative_status().model_dump(mode="json"),
            }
        ]
        self.login()

        response = self.client.get("/events", params={"after_id": "0"})

        self.assertEqual(200, response.status_code)
        self.assertEqual("", response.text)

    def test_sse_rejects_ambiguous_or_invalid_browser_cursors(self) -> None:
        self.login()

        ambiguous = self.client.get(
            "/events?after_id=4", headers={"Last-Event-ID": "5"}
        )
        invalid = self.client.get("/events", headers={"Last-Event-ID": "not-a-number"})

        self.assertEqual(400, ambiguous.status_code)
        self.assertEqual(400, invalid.status_code)
        self.assertEqual([], self.daemon.event_requests)

    def test_status_fragment_fetches_a_fresh_complete_authoritative_state(self) -> None:
        self.login()
        self.daemon.gets.clear()

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assertEqual([("/api/v1/status", DaemonStatusV1)], self.daemon.gets)
        self.assertIn('id="operations"', response.text)
        self.assertIn("LTFS index finalization", response.text)
        self.assertIn('data-finalization-state="active"', response.text)
        self.assertIn(
            "LTFS cassette finalization: index consolidation in progress",
            response.text,
        )
        self.assertIn("1 min 35 s", response.text)
        self.assertIn("data-telemetry-chart", response.text)

    def test_finalization_remains_active_and_fully_named_during_unmount(self) -> None:
        status = self.daemon.status
        assert not isinstance(status, Exception)
        operation = status.operation
        assert operation is not None
        self.daemon.status = status.model_copy(
            update={"operation": operation.model_copy(update={"phase": "unmounting"})}
        )
        self.login()

        response = self.client.get("/status-fragment")

        self.assertEqual(200, response.status_code)
        self.assertIn('data-finalization-state="active"', response.text)
        self.assertIn(
            "LTFS cassette finalization: unmount and release in progress",
            response.text,
        )


class TelemetryChartTests(unittest.TestCase):
    def test_chart_uses_real_time_positions_units_scale_and_explicit_gaps(self) -> None:
        html = render_telemetry(
            (
                _sample(10, "2026-08-21T12:00:00Z", 10),
                _sample(11, "2026-08-21T12:00:30Z", None),
                _sample(12, "2026-08-21T12:02:00Z", 30),
            )
        )

        self.assertIn("0 MiB/s", html)
        self.assertIn("30 MiB/s", html)
        self.assertIn("50%", html)
        self.assertIn('data-gap="true"', html)
        self.assertIn('data-time-offset-seconds="120.000"', html)
        self.assertNotIn('data-time-offset-seconds="60.000"', html)
        self.assertEqual(2, html.count('data-segment="true"'))

    def test_chart_does_not_fabricate_zero_for_an_unavailable_series(self) -> None:
        html = render_telemetry(
            (
                _sample(1, "2026-08-21T12:00:00Z", None),
                _sample(2, "2026-08-21T12:00:05Z", None),
            )
        )

        self.assertIn("Telemetry unavailable", html)
        self.assertNotIn('data-raw-rate="0', html)
        self.assertEqual(2, html.count('data-gap="true"'))


class JobRuntimeIsolationTests(LiveWebAppTestCase):
    def test_scan_is_visible_on_dashboard_job_and_live_fragments(self) -> None:
        from ltobackup.daemon.api_models import BoundaryRefreshStatusV1, JobSequenceStatusV1
        self.daemon.get_job_sequence_status = lambda *_args, **_kwargs: JobSequenceStatusV1(
            authorization_state="authorized", layout_fingerprint_sha256="a" * 64,
            next_expected_sequence=14, next_expected_label="TAPE14", waiting_for_media=True,
        )
        status = self.daemon.status
        self.daemon.status = status.model_copy(update={
            "operation": None,
            "job": status.job.model_copy(update={"state": "waiting_media"}),
        })
        self.daemon.job = self.daemon.job.model_copy(update={
            "state": "waiting_media", "pause_requested": False,
            "boundary_refresh": BoundaryRefreshStatusV1(
                state="scanning", completed_sequence=13,
                occurred_at="2026-09-21T16:53:48+00:00",
            ),
        })
        self.login()
        for path in ("/", "/status-fragment", "/jobs/JOB1", "/partials/jobs/JOB1/runtime"):
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code, response.text)
                self.assertIn("Scanning source libraries", response.text)
                self.assertIn("2026-09-21T16:53:48+00:00", response.text)
                self.assertIn('data-live-refresh-mode="active"', response.text)
                self.assertNotIn(">Resume job</button>", response.text)

    def test_scan_message_transitions_to_preparation_then_disappears_on_write(self) -> None:
        status = self.daemon.status
        operation = status.operation.model_copy(update={"kind": "archive.native", "phase": None})
        self.daemon.status = status.model_copy(update={"operation": operation})
        self.login()
        for path in ("/status-fragment", "/partials/jobs/JOB1/runtime"):
            response = self.client.get(path)
            self.assertIn("Preparing cassette", response.text)
            self.assertIn("Catalog backup and preflight checks", response.text)
            self.assertIn('data-live-refresh-mode="active"', response.text)
        self.daemon.status = status.model_copy(update={
            "operation": operation.model_copy(update={"phase": "writing"})
        })
        self.assertNotIn("Preparing cassette", self.client.get("/status-fragment").text)

    def test_dashboard_survives_unavailable_scan_detail_without_claiming_progress(self) -> None:
        status = self.daemon.status
        self.daemon.status = status.model_copy(update={
            "operation": None,
            "job": status.job.model_copy(update={"state": "waiting_media"}),
        })
        def unavailable_job(*_args, **_kwargs):
            raise DaemonUnavailable()
        self.daemon.get_job = unavailable_job
        self.login()
        response = self.client.get("/status-fragment")
        self.assertEqual(200, response.status_code)
        self.assertIn("Preparation status is temporarily unavailable", response.text)
        self.assertNotIn("Scanning source libraries", response.text)

    def test_dashboard_does_not_fetch_scan_details_while_writing(self) -> None:
        def unexpected_job(*_args, **_kwargs):
            self.fail("Writing refresh must not request the heavier job projection")
        self.daemon.get_job = unexpected_job
        self.login()
        response = self.client.get("/status-fragment")
        self.assertEqual(200, response.status_code)
        self.assertNotIn("Scanning source libraries", response.text)

    def test_preparation_does_not_override_recovery_blocker(self) -> None:
        status = self.daemon.status
        operation = status.operation.model_copy(update={
            "kind": "archive.native", "state": "recovery_required", "phase": None,
        })
        self.daemon.status = status.model_copy(update={
            "operation": operation, "admission_blocker": operation,
        })
        self.login()
        response = self.client.get("/status-fragment")
        self.assertIn("recovery required", response.text)
        self.assertNotIn("Preparing cassette", response.text)

    def test_active_job_detail_renders_only_its_bounded_live_telemetry(self) -> None:
        self.login()

        detail = self.client.get("/jobs/JOB1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn('data-job-runtime', detail.text)
        self.assertIn('data-telemetry-chart', detail.text)
        self.assertIn("Instantaneous rate (raw)", detail.text)
        self.assertIn("Effective rate (operation window)", detail.text)

    def test_runtime_fragment_never_uses_a_different_jobs_telemetry(self) -> None:
        status = self.daemon.status
        assert not isinstance(status, Exception)
        active = status.job
        assert active is not None
        self.daemon.status = status.model_copy(
            update={"job": active.model_copy(update={"id": "OTHER-JOB"})}
        )
        self.login()

        partial = self.client.get("/partials/jobs/JOB1/runtime")

        self.assertEqual(200, partial.status_code, partial.text)
        self.assertIn("No active telemetry for this job", partial.text)
        self.assertNotIn('data-raw-rate="', partial.text)
        self.assertNotIn('data-telemetry-chart', partial.text)


class DedicatedViewsTests(LiveWebAppTestCase):
    def test_authenticated_pages_expose_one_current_item_in_grouped_navigation(
        self,
    ) -> None:
        # A duplicated/missing active item, an unlabelled disclosure control,
        # or navigation moved ahead of the skip link breaks keyboard context.
        self.login()
        expected = {
            "/": "/",
            "/jobs": "/jobs",
            "/media": "/media",
            "/logs": "/logs",
            "/diagnostics": "/diagnostics",
            "/settings": "/settings",
            "/users": "/users",
        }

        for path, current_href in expected.items():
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(200, response.status_code, response.text)
                html = response.text
                self.assertEqual(1, len(re.findall(r"<h1(?:\s|>)", html)))
                self.assertEqual(3, html.count('class="nav-group"'))
                self.assertRegex(
                    html,
                    r'<button[^>]+data-nav-toggle[^>]+'
                    r'aria-controls="app-navigation"[^>]+'
                    r'aria-expanded="false"[^>]*>Menu</button>',
                )
                current = re.findall(
                    r'<a\s+href="([^"]+)"\s+aria-current="page"', html
                )
                self.assertEqual([current_href], current, html)
                self.assertLess(html.index("skip-link"), html.index("site-header"))
                self.assertLess(
                    html.index("site-header"), html.index('id="main-content"')
                )

    def test_settings_validation_associates_the_visible_error_with_its_form(
        self,
    ) -> None:
        # Dropping either side of aria-describedby leaves keyboard and screen
        # reader users without the validation context for the rejected form.
        csrf, key = self.csrf_and_key("/settings")

        response = self.client.post(
            "/settings/application",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "expected_revision": "1",
                "capacity_reserve_bytes": "-1",
                "minimum_source_file_age_seconds": "60",
                "copy_buffer_bytes": str(8 * 1024 * 1024),
                "content_verification_policy": "manifest",
                "default_media_profile": "LTO-9",
                "tape_root_directory": "archive",
            },
        )

        self.assertEqual(422, response.status_code, response.text)
        self.assertIn(
            'id="settings-capacity_reserve_bytes-error" class="field-error"',
            response.text,
        )
        self.assertRegex(
            response.text,
            r'<form action="/settings/application" method="post" '
            r'aria-describedby="settings-capacity_reserve_bytes-error"',
        )

    def test_logs_settings_and_users_are_dedicated_redacted_views(self) -> None:
        self.login()

        logs = self.client.get("/logs?limit=50")
        settings = self.client.get("/settings")
        users = self.client.get("/users")

        self.assertEqual(200, logs.status_code)
        self.assertEqual(200, settings.status_code)
        self.assertEqual(200, users.status_code)
        self.assertIn("Tape is waiting for authorized media", logs.text)
        self.assertIn("TAPE05", logs.text)
        self.assertIn("operation-1", logs.text)
        self.assertIn("LTFS / Tape", logs.text)
        self.assertIn("8388608", settings.text)
        self.assertIn("/var/lib/lto-archiver", settings.text)
        self.assertIn("Daemon socket path", settings.text)
        self.assertNotIn('name="legacy_tape_capacity_bytes"', settings.text)
        self.assertIn("admin", users.text)
        self.assertNotIn("argon2", users.text.casefold())
        self.assertNotRegex(users.text, r'type="password"[^>]+value=')
        self.assertEqual(50, self.daemon.system_log_requests[-1]["limit"])
        self.assertFalse(
            any(path.startswith("/api/v1/logs?") for path, _ in self.daemon.gets)
        )

    def test_log_limit_is_bounded_before_forwarding(self) -> None:
        self.login()

        response = self.client.get("/logs?limit=201")

        self.assertEqual(422, response.status_code)
        self.assertEqual([], self.daemon.system_log_requests)

    def test_log_browser_forwards_closed_filters_and_renders_navigation(self) -> None:
        self.login()

        response = self.client.get(
            "/logs?source=ltfs&severity=warning&range=24h&direction=older"
            "&limit=100&q=TAPE05"
        )

        self.assertEqual(200, response.status_code, response.text)
        request = self.daemon.system_log_requests[-1]
        self.assertEqual(
            {
                "source": "ltfs",
                "severity": "warning",
                "range": "24h",
                "direction": "older",
                "cursor": None,
                "search": "TAPE05",
                "limit": 100,
                "principal": "web-user-1",
                "role": "admin",
            },
            request,
        )
        self.assertIn('name="source"', response.text)
        self.assertIn('name="severity"', response.text)
        self.assertIn('name="range"', response.text)
        self.assertIn('name="direction"', response.text)
        self.assertIn('name="limit"', response.text)
        self.assertIn('name="q"', response.text)
        self.assertIn("operation-1", response.text)
        self.assertIn("TAPE05", response.text)
        self.assertIn("LTFS / Tape", response.text)
        self.assertIn("s%3Dolder%3Bi%3D1", response.text)
        self.assertIn("source=ltfs", response.text)
        self.assertIn("q=TAPE05", response.text)
        self.assertNotIn("hunter2", response.text)

    def test_log_query_rejects_duplicates_unknowns_and_every_closed_bound(self) -> None:
        self.login()
        invalid_queries = (
            "source=all&source=ltfs",
            "unknown=value",
            "source=host",
            "severity=critical",
            "range=forever",
            "direction=sideways",
            "limit=0",
            "limit=201",
            f"q={'x' * 129}",
            "q=line%0Abreak",
            "cursor=%00",
            f"cursor={'x' * 2049}",
        )
        for query in invalid_queries:
            with self.subTest(query=query):
                before = len(self.daemon.system_log_requests)
                response = self.client.get(f"/logs?{query}")
                self.assertEqual(422, response.status_code, response.text)
                self.assertEqual(before, len(self.daemon.system_log_requests))

    def test_log_browser_accepts_an_empty_optional_search_from_the_form(self) -> None:
        self.login()

        response = self.client.get("/logs?q=&limit=100")

        self.assertEqual(200, response.status_code, response.text)
        self.assertIsNone(self.daemon.system_log_requests[-1]["search"])

    def test_log_browser_escapes_message_and_preserves_exact_timestamp(self) -> None:
        self.login()

        response = self.client.get("/logs")

        self.assertEqual(200, response.status_code, response.text)
        self.assertIn("&lt;ready&gt;", response.text)
        self.assertNotIn("<ready>", response.text)
        self.assertIn('datetime="2026-08-21T12:00:00Z"', response.text)
        self.assertIn("2026-08-21T12:00:00Z", response.text)

    def test_log_browser_renders_distinct_rotated_partial_empty_and_upgrade_states(self) -> None:
        self.login()
        cases = (
            (
                self.daemon.system_logs.model_copy(
                    update={
                        "items": (),
                        "older_cursor": None,
                        "newer_cursor": None,
                        "cursor_rotated": True,
                    }
                ),
                "The journal cursor has expired",
            ),
            (
                self.daemon.system_logs.model_copy(
                    update={
                        "items": (),
                        "older_cursor": None,
                        "newer_cursor": None,
                        "unavailable_sources": (LogSource.LTFS,),
                    }
                ),
                "Some sources are temporarily unavailable",
            ),
            (
                self.daemon.system_logs.model_copy(
                    update={
                        "items": (),
                        "older_cursor": None,
                        "newer_cursor": None,
                        "unavailable_sources": tuple(
                            source for source in LogSource if source is not LogSource.ALL
                        ),
                    }
                ),
                "Operational journal unavailable",
            ),
            (
                self.daemon.system_logs.model_copy(
                    update={
                        "items": (),
                        "older_cursor": None,
                        "newer_cursor": None,
                    }
                ),
                "No matching operational events",
            ),
        )
        for page, message in cases:
            with self.subTest(message=message):
                self.daemon.system_logs = page
                response = self.client.get("/logs")
                self.assertEqual(200, response.status_code, response.text)
                self.assertIn(message, response.text)

        from ltobackup.client import DaemonRequestError

        self.daemon.system_logs = DaemonRequestError(404, "not_found")
        response = self.client.get("/logs")
        self.assertEqual(503, response.status_code, response.text)
        self.assertIn("daemon upgrade is required", response.text)

    def test_temporary_log_source_failure_keeps_newest_follow_recovery_active(self) -> None:
        self.login()
        unavailable = self.daemon.system_logs.model_copy(
            update={
                "items": (),
                "older_cursor": None,
                "newer_cursor": None,
                "unavailable_sources": (LogSource.LTFS,),
            }
        )
        self.daemon.system_logs = unavailable

        newest = self.client.get("/logs")
        history = self.client.get(
            "/logs",
            params={"cursor": "s=journal;i=4", "direction": "older"},
        )

        self.assertEqual(200, newest.status_code, newest.text)
        self.assertIn('data-log-follow aria-pressed="true"', newest.text)
        self.assertNotIn('data-log-follow aria-pressed="true" disabled', newest.text)
        self.assertIn('data-live-refresh-mode="active"', newest.text)
        self.assertIn("Some sources are temporarily unavailable", newest.text)
        self.assertEqual(200, history.status_code, history.text)
        self.assertIn('data-log-follow aria-pressed="false" disabled', history.text)
        self.assertIn('data-live-refresh-mode="idle"', history.text)

    def test_log_status_fragment_and_event_stream_are_authenticated(self) -> None:
        self.assertEqual(401, self.client.get("/logs/status-fragment").status_code)
        self.assertEqual(401, self.client.get("/logs/events").status_code)
        self.login()
        self.assertEqual(400, self.client.get("/logs/events?source=ltfs").status_code)

        fragment = self.client.get("/logs/status-fragment")
        self.assertEqual(200, fragment.status_code, fragment.text)
        self.assertIn('id="logs-live-status"', fragment.text)
        self.daemon.event_items = [
            {
                "api_version": 1,
                "id": 8,
                "event": "state.patch",
                "data": {"progress": None},
            }
        ]
        stream = self.client.get("/logs/events")
        self.assertEqual(200, stream.status_code, stream.text)
        self.assertIn("id: 8\nevent: logs.changed\ndata: {}\n\n", stream.text)

    def test_log_event_reconnect_forwards_exact_cursor_and_emits_daemon_ids(self) -> None:
        self.login()
        self.daemon.event_items = [
            {
                "api_version": 1,
                "id": 42,
                "event": "state.patch",
                "data": {"progress": None},
            }
        ]

        header = self.client.get("/logs/events", headers={"Last-Event-ID": "41"})
        query = self.client.get("/logs/events", params={"after_id": "40"})

        self.assertEqual(200, header.status_code, header.text)
        self.assertEqual(200, query.status_code, query.text)
        self.assertEqual([(None, 41), (40, None)], self.daemon.event_requests)
        for response in (header, query):
            self.assertIn("id: 42\nevent: logs.changed\ndata: {}\n\n", response.text)
            self.assertTrue(response.text.endswith("event: stream.ready\ndata: {}\n\n"))

    def test_log_event_reconnect_rejects_invalid_ambiguous_or_duplicate_cursor(self) -> None:
        self.login()

        responses = (
            self.client.get(
                "/logs/events?after_id=4", headers={"Last-Event-ID": "5"}
            ),
            self.client.get("/logs/events", headers={"Last-Event-ID": "invalid"}),
            self.client.get("/logs/events?after_id=1&after_id=1"),
            self.client.get("/logs/events?after_id=-1"),
        )

        self.assertTrue(all(response.status_code == 400 for response in responses))
        self.assertEqual([], self.daemon.event_requests)

    def test_jobs_media_and_diagnostics_use_only_closed_current_state(self) -> None:
        self.login()

        jobs = self.client.get("/jobs")
        media = self.client.get("/media")
        diagnostics = self.client.get("/diagnostics")

        self.assertEqual(200, jobs.status_code)
        self.assertEqual(200, media.status_code)
        self.assertEqual(200, diagnostics.status_code)
        self.assertIn("JOB1", jobs.text)
        self.assertIn("TAPE&lt;04&gt;", media.text)
        self.assertIn("Redacted diagnostic export", diagnostics.text)
        for response in (jobs, media, diagnostics):
            self.assertNotIn("include_catalog", response.text)


class SafeMutationTests(LiveWebAppTestCase):
    def require_format(self) -> None:
        """Exercise format admission with the daemon waiting for media, not writing."""
        status = self.daemon.status
        assert not isinstance(status, Exception)
        expected = status.expected_media
        assert expected is not None
        assert status.job is not None
        self.daemon.status = status.model_copy(
            update={
                "expected_media": expected.model_copy(update={"format_required": True}),
                "operation": None,
                "job": status.job.model_copy(update={"state": "waiting_media"}),
                "drive": status.drive.model_copy(update={"state": "loaded"}),
            }
        )

    def test_native_reset_form_requires_exact_job_id_and_forwards_only_labels(self) -> None:
        status = self.daemon.status
        assert not isinstance(status, Exception)
        assert status.job is not None
        self.daemon.status = status.model_copy(
            update={
                "operation": None,
                "job": status.job.model_copy(
                    update={"labels": ("TAPE01", "TAPE02"), "state": "paused"}
                ),
            }
        )
        csrf, key = self.csrf_and_key("/")
        wrong = self.client.post(
            "/jobs/native",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "display_name": "Backup completo",
                "labels": "tape01\nTAPE02",
                "expected_job_id": "JOB1",
                "typed_job_id": "WRONG",
            },
        )
        self.assertEqual(422, wrong.status_code)
        self.assertEqual([], self.daemon.mutations)

        accepted = self.client.post(
            "/jobs/native",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "display_name": "Backup completo",
                "labels": "tape01\nTAPE02",
                "expected_job_id": "JOB1",
                "typed_job_id": "JOB1",
            },
        )
        self.assertEqual(202, accepted.status_code, accepted.text)
        self.assertEqual("/api/v1/jobs/native", self.daemon.mutations[-1]["path"])
        self.assertEqual(
            {
                "display_name": "Backup completo",
                "labels": ["TAPE01", "TAPE02"],
                "expected_job_id": "JOB1",
                "typed_job_id": "JOB1",
            },
            self.daemon.mutations[-1]["payload"],
        )

    def test_format_requires_exact_expected_sequence_and_label(self) -> None:
        self.require_format()
        csrf, key = self.csrf_and_key("/media")

        wrong = self.client.post(
            "/media/4/format",
            data={"csrf": csrf, "idempotency_key": key, "typed_label": "WRONG"},
        )

        self.assertEqual(422, wrong.status_code)
        self.assertEqual({"error": {"code": "format_label_mismatch"}}, wrong.json())
        self.assertEqual([], self.daemon.mutations)

        accepted = self.client.post(
            "/media/4/format",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "typed_label": "TAPE<04>",
            },
        )
        self.assertEqual(202, accepted.status_code, accepted.text)
        self.assertEqual("/api/v1/media/4/format", self.daemon.mutations[-1]["path"])
        self.assertEqual(
            {"format_confirmation_label": "TAPE<04>"},
            self.daemon.mutations[-1]["payload"],
        )

    def test_operator_never_sees_or_reaches_the_media_format_action(self) -> None:
        self.require_format()
        admin = self.store.get_user_by_login("admin")
        assert admin is not None
        self.store.create_user(
            "operator",
            "-".join(("operator", "test", "password")),
            role="operator",
            actor_user_id=admin.id,
            idempotency_key="create-format-operator",
        )
        self.client.cookies.clear()
        login_page = self.client.get("/login")
        token = re.search(
            r'name="login_csrf" value="([A-Za-z0-9_-]+)"', login_page.text
        )
        assert token is not None
        login = self.client.post(
            "/login",
            data={
                "username": "".join(("oper", "ator")),
                "password": "-".join(("operator", "test", "password")),
                "login_csrf": token.group(1),
            },
        )
        self.assertEqual(303, login.status_code)

        media = self.client.get("/media")
        self.assertNotIn('action="/media/4/format"', media.text)
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', media.text)
        assert csrf is not None
        forbidden = self.client.post(
            "/media/4/format",
            data={
                "csrf": csrf.group(1),
                "idempotency_key": str(uuid4()),
                "typed_label": "TAPE<04>",
            },
        )
        self.assertEqual(403, forbidden.status_code)
        self.assertEqual([], self.daemon.mutations)

    def test_browser_cutover_header_or_form_is_rejected_without_daemon_call(
        self,
    ) -> None:
        self.require_format()
        csrf, key = self.csrf_and_key("/media")

        header = self.client.post(
            "/media/4/format",
            headers={"X-Cutover-Credential": "-".join(("browser", "supplied", "token"))},
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "typed_label": "TAPE<04>",
            },
        )
        form = self.client.post(
            "/media/4/format",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "typed_label": "TAPE<04>",
                "cutover_credential": "-".join(("browser", "supplied", "token")),
            },
        )

        self.assertEqual(422, header.status_code)
        self.assertEqual(422, form.status_code)
        self.assertEqual(
            "cutover_authorization_invalid", header.json()["error"]["code"]
        )
        self.assertEqual("cutover_authorization_invalid", form.json()["error"]["code"])
        self.assertEqual([], self.daemon.mutations)

    def test_generic_retry_is_not_a_webui_surface(self) -> None:
        csrf = self.csrf_from_read_only_page("/diagnostics")
        key = str(uuid4())

        retry = self.client.post(
            "/operations/op-1/retry",
            headers={"X-Authenticated-Principal": "mallory"},
            data={"csrf": csrf, "idempotency_key": key},
        )
        self.assertEqual(404, retry.status_code, retry.text)
        self.assertEqual([], self.daemon.mutations)


_CHROME = shutil.which("google-chrome-stable") or shutil.which("google-chrome")


@unittest.skipUnless(_CHROME, "Chrome is required for the live fallback gate")
class LiveJavascriptBrowserTests(unittest.TestCase):
    def test_sustained_stream_failure_uses_adaptive_polling_and_open_keeps_safety_refresh(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="lto-web-live-", dir=Path.home()
        ) as raw:
            root = Path(raw)
            script = Path("src/ltobackup/web/static/live.js").resolve()
            html = root / "live.html"
            html.write_text(
                f"""<!doctype html><html><body>
                <main id=\"operations\" data-live-refresh-mode=\"active\"><div id=\"connection-banner\" hidden></div>old</main>
                <script>
                window.__result = {{clears: [], timeoutDelays: [], fetches: 0}};
                window.__timers = [];
                window.__realSetTimeout = window.setTimeout.bind(window);
                window.setTimeout = (fn, ms) => {{ __result.timeoutDelays.push(ms); __timers.push(fn); return __timers.length; }};
                window.clearTimeout = id => __result.clears.push(id);
                window.fetch = () => {{ __result.fetches += 1; return Promise.resolve({{
                  ok: true, text: () => Promise.resolve('<main id=\"operations\" data-live-refresh-mode=\"active\" data-polled=\"yes\"><div id=\"connection-banner\" hidden></div>fresh</main>')
                }}); }};
                class FakeEventSource {{
                  constructor(url) {{ this.url=url; this.listeners={{}}; window.__stream=this; }}
                  addEventListener(name, listener) {{ this.listeners[name] = listener; }}
                  close() {{}}
                }}
                window.EventSource = FakeEventSource;
                </script>
                <script src=\"{script.as_uri()}\"></script>
                <script>
                window.addEventListener('load', () => {{
                  __stream.onerror();
                  __result.fetchesImmediately = __result.fetches;
                  __timers[0]();
                  __timers[1]();
                  __realSetTimeout(() => {{
                    __result.bannerVisibleAfterPoll = !document.querySelector('#connection-banner').hidden;
                    __stream.listeners["stream.ready"]({{ data: "{{}}" }});
                    document.documentElement.dataset.result = encodeURIComponent(JSON.stringify({{
                      clears: __result.clears,
                      timeoutDelays: __result.timeoutDelays,
                      fetches: __result.fetches,
                      fetchesImmediately: __result.fetchesImmediately,
                      bannerVisibleAfterPoll: __result.bannerVisibleAfterPoll,
                      polled: document.querySelector('#operations').dataset.polled,
                      bannerHidden: document.querySelector('#connection-banner').hidden
                    }}));
                  }}, 20);
                }});
                </script></body></html>""",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    str(_CHROME),
                    "--headless=new",
                    "--disable-gpu",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    f"--user-data-dir={root / 'profile'}",
                    "--virtual-time-budget=500",
                    "--dump-dom",
                    html.as_uri(),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            match = re.search(r'data-result="([^"]+)"', completed.stdout)
            self.assertIsNotNone(match, completed.stderr + completed.stdout[-2000:])
            assert match is not None
            result = json.loads(unquote(match.group(1)))
            self.assertEqual([15000, 3000, 3000, 3000], result["timeoutDelays"])
            self.assertEqual([3], result["clears"])
            self.assertEqual(0, result["fetchesImmediately"])
            self.assertEqual(1, result["fetches"])
            self.assertTrue(result["bannerVisibleAfterPoll"])
            self.assertEqual("yes", result["polled"])
            self.assertTrue(result["bannerHidden"])


if __name__ == "__main__":
    unittest.main()
