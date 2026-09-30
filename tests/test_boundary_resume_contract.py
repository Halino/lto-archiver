from __future__ import annotations

import unittest
from pathlib import Path

import httpx

from ltobackup.client import DaemonProtocolError, UnixDaemonClient
from ltobackup.daemon.api_models import JobCommandRequestV1, OperationResponseV1


def _operation_response() -> dict[str, object]:
    return {
        "id": "operation-1",
        "kind": "archive.resume",
        "state": "running",
        "phase": "writing",
        "idempotency_key": "resume-legacy-1",
        "principal": "operator-1",
        "job_id": "JOB-1",
        "cassette_sequence": 2,
        "started_at": "2026-09-12T08:00:00+00:00",
        "finished_at": None,
        "error_class": None,
        "error_code": None,
        "error_message": None,
    }


def _boundary_refresh_response() -> dict[str, object]:
    return {
        "kind": "boundary.refresh",
        "state": "accepted",
        "job_id": "JOB-1",
        "request_id": "boundary-refresh-1",
    }


class BoundaryResumeClientContractTests(unittest.TestCase):
    def _client_returning(
        self, payload: dict[str, object]
    ) -> tuple[UnixDaemonClient, list[httpx.Request]]:
        requests: list[httpx.Request] = []

        def handle(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            if request.url.path == "/api/v1/health":
                return httpx.Response(200, json={"status": "ok", "api_version": 1})
            return httpx.Response(202, json=payload)

        client = UnixDaemonClient(
            Path("/run/lto-archiver/daemon.sock"),
            2.5,
            transport=httpx.MockTransport(handle),
        )
        self.addCleanup(client.close)
        return client, requests

    def test_resume_accepts_queued_boundary_refresh_response(self) -> None:
        client, requests = self._client_returning(_boundary_refresh_response())

        try:
            result = client.resume_job(
                "JOB-1",
                JobCommandRequestV1(),
                "resume-boundary-1",
                principal="operator-1",
                role="operator",
            )
        except DaemonProtocolError as exc:
            self.fail(f"Resume rejected its queued boundary refresh response: {exc}")

        self.assertEqual(
            _boundary_refresh_response(), result.model_dump(mode="json")
        )
        self.assertEqual("BoundaryRefreshAcceptedV1", type(result).__name__)
        self.assertEqual(
            ["/api/v1/health", "/api/v1/jobs/JOB-1/resume"],
            [request.url.path for request in requests],
        )

    def test_resume_preserves_legacy_operation_response(self) -> None:
        client, _requests = self._client_returning(_operation_response())

        result = client.resume_job(
            "JOB-1",
            JobCommandRequestV1(),
            "resume-legacy-1",
            principal="operator-1",
            role="operator",
        )

        self.assertIsInstance(result, OperationResponseV1)
        self.assertEqual(_operation_response(), result.model_dump(mode="json"))

    def test_resume_rejects_invalid_boundary_refresh_response(self) -> None:
        invalid = _boundary_refresh_response()
        invalid["request_id"] = "unsafe/request"
        client, _requests = self._client_returning(invalid)

        with self.assertRaises(DaemonProtocolError):
            client.resume_job(
                "JOB-1",
                JobCommandRequestV1(),
                "resume-boundary-invalid",
                principal="operator-1",
                role="operator",
            )

    def test_start_refuses_boundary_refresh_response(self) -> None:
        client, requests = self._client_returning(_boundary_refresh_response())

        with self.assertRaises(DaemonProtocolError):
            client.start_job(
                "JOB-1",
                JobCommandRequestV1(),
                "start-boundary-invalid",
                principal="operator-1",
                role="operator",
            )

        self.assertEqual(
            ["/api/v1/health", "/api/v1/jobs/JOB-1/start"],
            [request.url.path for request in requests],
        )


if __name__ == "__main__":
    unittest.main()
