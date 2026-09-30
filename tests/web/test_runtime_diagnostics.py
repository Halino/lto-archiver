from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from ltobackup.client import DaemonProtocolError
from ltobackup.daemon.api_models import DiagnosticSummaryV1
from ltobackup.web.app import WebSettings, create_web_app
from tests.web.test_dashboard import FakeDaemonClient, WebAppTestCase


def _runtime_summary() -> DiagnosticSummaryV1:
    return DiagnosticSummaryV1.model_validate(
        {
            "api_version": 1,
            "health": {
                "status": "attention",
                "cleaning_required": False,
                "tape_alert_codes": [1, 20],
            },
            "telemetry": {
                "files_completed": 12,
                "bytes_completed": 2 * 1024 * 1024,
                "current_mib_per_second": 12.5,
                "effective_mib_per_second": 10.0,
                "samples": [
                    {
                        "event_id": 8,
                        "occurred_at": "2026-08-22T12:00:01Z",
                        "mib_per_second": 10.0,
                    },
                    {
                        "event_id": 9,
                        "occurred_at": "2026-08-22T12:00:02Z",
                        "mib_per_second": 12.5,
                    },
                ],
                "phase_durations": {
                    "source_open_seconds": 1.0,
                    "smb_read_seconds": 2.0,
                    "ltfs_write_admission_seconds": 3.0,
                    "copy_seconds": 4.0,
                    "close_seconds": 5.0,
                    "manifest_seconds": 6.0,
                    "snapshot_seconds": 7.0,
                    "finalization_seconds": 8.0,
                    "unmount_seconds": 9.0,
                    "unload_seconds": 10.0,
                    "retry_seconds": 11.0,
                    "operator_wait_seconds": 12.0,
                },
                "current_phase": "operator_wait",
                "closed": False,
            },
        }
    )


class RuntimeDiagnosticDaemon(FakeDaemonClient):
    def __init__(self) -> None:
        super().__init__()
        self.summary: DiagnosticSummaryV1 | Exception = _runtime_summary()
        self.download_calls = 0
        self.summary_principals: list[str | None] = []
        self.summary_roles: list[str | None] = []
        self.download_principals: list[str] = []
        self.download_roles: list[str] = []

    def get(
        self,
        path: str,
        *,
        response_model,
        principal: str | None = None,
        role: str | None = None,
    ):
        if path == "/api/v1/diagnostics/summary":
            self.gets.append((path, response_model))
            self.summary_principals.append(principal)
            self.summary_roles.append(role)
            if isinstance(self.summary, Exception):
                raise self.summary
            return self.summary
        return super().get(
            path, response_model=response_model, principal=principal, role=role
        )

    def download_diagnostics(self, *, principal: str, role: str) -> bytes:
        self.download_calls += 1
        self.download_principals.append(principal)
        self.download_roles.append(role)
        return b"PK\x03\x04redacted-runtime-diagnostics"


class RuntimeDiagnosticViewsTests(WebAppTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.client.close()
        self.daemon = RuntimeDiagnosticDaemon()
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

    def test_diagnostics_summary_displays_real_runtime_values_with_units_and_utc(
        self,
    ) -> None:
        # Replacing the closed summary with a status placeholder, omitting any
        # phase, or rendering an unqualified time must fail this operator view.
        self.login()

        response = self.client.get("/diagnostics")

        self.assertEqual(200, response.status_code)
        self.assertIn('id="diagnostics-runtime-summary"', response.text)
        self.assertIn('id="connection-banner"', response.text)
        self.assertIn("runtime data may be stale", response.text)
        self.assertNotIn('name="idempotency_key"', response.text)
        self.assertIn("12 files", response.text)
        self.assertIn("2.00 MiB", response.text)
        self.assertIn("12.50 MiB/s", response.text)
        self.assertIn("10.00 MiB/s", response.text)
        self.assertIn("2026-08-22 12:00:02 UTC", response.text)
        self.assertIn("Waiting for operator", response.text)
        self.assertIn("Acquiring", response.text)
        self.assertIn("1.00 s", response.text)
        for label in (
            "Opening source",
            "SMB read",
            "LTFS write admission",
            "Copy",
            "File close",
            "Manifest",
            "Snapshot",
            "LTFS index finalization",
            "LTFS unmount",
            "Unload",
            "Retry",
            "Waiting for operator",
        ):
            self.assertIn(label, response.text)
        self.assertIn(
            ("/api/v1/diagnostics/summary", DiagnosticSummaryV1), self.daemon.gets
        )

    def test_diagnostics_summary_failure_is_redacted_and_fail_closed(self) -> None:
        self.daemon.summary = DaemonProtocolError("SERIAL-PRIVATE-123")
        self.login()

        response = self.client.get("/diagnostics/summary-fragment")

        self.assertEqual(503, response.status_code)
        self.assertEqual({"error": {"code": "daemon_unavailable"}}, response.json())
        self.assertNotIn("SERIAL-PRIVATE-123", response.text)

    def test_diagnostics_summary_fragment_and_export_require_the_authenticated_session(
        self,
    ) -> None:
        fragment = self.client.get("/diagnostics/summary-fragment")
        export = self.client.get("/diagnostics/export")

        self.assertEqual(401, fragment.status_code)
        self.assertEqual(401, export.status_code)
        self.assertEqual([], self.daemon.gets)
        self.assertEqual(0, self.daemon.download_calls)

    def test_authenticated_diagnostic_download_has_fixed_bounded_attachment_headers(
        self,
    ) -> None:
        self.login()

        response = self.client.get("/diagnostics/export")

        self.assertEqual(200, response.status_code)
        self.assertEqual("application/zip", response.headers["content-type"])
        self.assertEqual(
            'attachment; filename="lto-diagnostics.zip"',
            response.headers["content-disposition"],
        )
        self.assertEqual(b"PK\x03\x04redacted-runtime-diagnostics", response.content)
        self.assertEqual(1, self.daemon.download_calls)

    def test_diagnostic_read_principal_is_server_derived_not_a_browser_header(
        self,
    ) -> None:
        self.login()

        summary = self.client.get(
            "/diagnostics",
            headers={"X-Authenticated-Principal": "mallory"},
        )
        export = self.client.get(
            "/diagnostics/export",
            headers={"X-Authenticated-Principal": "mallory"},
        )

        self.assertEqual(200, summary.status_code)
        self.assertEqual(200, export.status_code)
        self.assertEqual(["web-user-1"], self.daemon.summary_principals)
        self.assertEqual(["web-user-1"], self.daemon.download_principals)

    def test_diagnostics_download_never_accepts_browser_parameters_or_csrf_bypass(
        self,
    ) -> None:
        self.login()

        response = self.client.get("/diagnostics/export?include_catalog=true")

        self.assertEqual(200, response.status_code)
        self.assertEqual(1, self.daemon.download_calls)
        self.assertNotIn("include_catalog", response.text)


if __name__ == "__main__":
    unittest.main()
