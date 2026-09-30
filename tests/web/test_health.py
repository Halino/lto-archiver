from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient
from pydantic import ValidationError

from ltobackup.client import (
    ApiCompatibilityError,
    DaemonProtocolError,
    DaemonRequestError,
    DaemonUnavailable,
)
from ltobackup.daemon.api_models import HealthV1
from ltobackup.web.app import WebSettings, create_web_app
from ltobackup.web.auth_store import AuthStore


class _HealthDaemonClient:
    def __init__(self, result: HealthV1 | Exception) -> None:
        self.result = result
        self.calls: list[tuple[str, type[HealthV1], str | None, str | None]] = []

    def get(
        self,
        path: str,
        *,
        response_model: type[HealthV1],
        principal: str | None = None,
        role: str | None = None,
    ) -> HealthV1:
        self.calls.append((path, response_model, principal, role))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _invalid_health_error() -> ValidationError:
    try:
        HealthV1.model_validate(
            {"status": "PRIVATE-VALIDATION-DETAIL", "api_version": 1}
        )
    except ValidationError as exc:
        return exc
    raise AssertionError("invalid health fixture unexpectedly validated")


class WebHealthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = AuthStore(Path(self.temporary.name) / "web-auth.db")

    def _client(
        self, result: HealthV1 | Exception
    ) -> tuple[TestClient, _HealthDaemonClient]:
        daemon = _HealthDaemonClient(result)
        app = create_web_app(WebSettings(), self.store, daemon)
        client = TestClient(
            app,
            base_url="https://console.example",
            follow_redirects=False,
            client=("127.0.0.1", 50_000),
        )
        self.addCleanup(client.close)
        return client, daemon

    def test_health_is_public_and_forwards_the_exact_daemon_contract(self) -> None:
        client, daemon = self._client(HealthV1(status="ok"))

        response = client.get("/api/v1/health")

        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual({"status": "ok", "api_version": 1}, response.json())
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(
            [("/api/v1/health", HealthV1, None, None)],
            daemon.calls,
        )

    def test_health_failures_are_redacted_and_never_report_healthy(self) -> None:
        failures = (
            ApiCompatibilityError(99, 1),
            DaemonProtocolError("PRIVATE-PROTOCOL-DETAIL"),
            DaemonRequestError(500, "PRIVATE-REQUEST-DETAIL"),
            DaemonUnavailable(),
            _invalid_health_error(),
        )

        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                client, daemon = self._client(failure)

                response = client.get("/api/v1/health")

                self.assertEqual(503, response.status_code, response.text)
                self.assertEqual({"status": "unavailable"}, response.json())
                self.assertNotIn("private", response.text.casefold())
                self.assertNotEqual("ok", response.json().get("status"))
                self.assertEqual(
                    [("/api/v1/health", HealthV1, None, None)],
                    daemon.calls,
                )

    def test_health_rejects_post_without_contacting_the_daemon(self) -> None:
        client, daemon = self._client(HealthV1(status="ok"))

        response = client.post("/api/v1/health")

        self.assertEqual(405, response.status_code, response.text)
        self.assertEqual([], daemon.calls)

    def test_health_success_and_failure_responses_are_not_cached(self) -> None:
        for result, expected_status in (
            (HealthV1(status="ok"), 200),
            (DaemonUnavailable(), 503),
        ):
            with self.subTest(result=type(result).__name__):
                client, _daemon = self._client(result)

                response = client.get("/api/v1/health")

                self.assertEqual(expected_status, response.status_code, response.text)
                self.assertEqual("no-store", response.headers["cache-control"])


if __name__ == "__main__":
    unittest.main()
