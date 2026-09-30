from __future__ import annotations

import unittest
import tempfile
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs

from starlette.requests import Request

from ltobackup.web.app import DashboardView, FormRejected, WebSettings, create_web_app, _read_form, _read_typed_form
from ltobackup.web.auth_store import AuthStore
from tests.web.test_dashboard import authoritative_status
from tests.web import test_management_views as management


class StreamingFormLimitTests(unittest.IsolatedAsyncioTestCase):
    async def test_unauthenticated_login_rejects_before_reading_remaining_chunks(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_web_app(WebSettings(), AuthStore(Path(directory) / "auth.db"),
                                 management.ManagementDaemonFake())
            consumed = 0
            responses = []

            async def receive():
                nonlocal consumed
                consumed += 1
                return {"type": "http.request", "body": b"x" * 8192,
                        "more_body": consumed < 128}

            async def send(message):
                responses.append(message)

            await app({"type": "http", "asgi": {"version": "3.0"},
                       "http_version": "1.1", "method": "POST", "scheme": "https",
                       "path": "/login", "raw_path": b"/login", "query_string": b"",
                       "server": ("console.example", 443), "client": ("127.0.0.1", 1234),
                       "headers": [(b"content-type", b"application/x-www-form-urlencoded")]
                       }, receive, send)
            self.assertEqual(3, consumed)
            self.assertEqual(422, responses[0]["status"])
            self.assertIn(b"Form is too large", b"".join(
                response.get("body", b"") for response in responses))

    async def test_both_parsers_stop_consuming_at_the_body_limit(self):
        for typed in (False, True):
            with self.subTest(typed=typed):
                consumed = 0

                async def receive():
                    nonlocal consumed
                    consumed += 1
                    return {"type": "http.request", "body": b"x" * 8192,
                            "more_body": consumed < 128}

                request = Request({"type": "http", "headers": [
                    (b"content-type", b"application/x-www-form-urlencoded")
                ]}, receive)
                with self.assertRaises(FormRejected) as rejected:
                    if typed:
                        await _read_typed_form(request, {"x"}, set())
                    else:
                        await _read_form(request, {"x"})
                self.assertEqual("form_too_large", rejected.exception.code)
                self.assertEqual(3, consumed, "reject the first excess chunk")
                self.assertFalse(hasattr(request, "_body"), "never buffer an unbounded body")

    async def test_exact_limit_is_accepted_by_both_parsers(self):
        for typed in (False, True):
            body = b"x=" + b"a" * (16384 - 2)

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request = Request({"type": "http", "headers": [
                (b"content-type", b"application/x-www-form-urlencoded")
            ]}, receive)
            result = await _read_typed_form(request, {"x"}, set()) if typed else await _read_form(request, {"x"})
            self.assertEqual("a" * 16382, (result[0] if typed else result)["x"])


class ThroughputMeaningTests(unittest.TestCase):
    def test_stale_sample_is_explicit_and_recent_rate_is_unavailable(self):
        status = authoritative_status()
        view = DashboardView.from_status(status.model_copy(update={
            "telemetry": status.telemetry.model_copy(update={
                "current_mib_per_second": None, "current_sample_age_seconds": 60.0,
                "current_sample_stale": True,
            })
        }))
        self.assertEqual("Not available", view.current_rate)
        self.assertEqual("Stale — last sample 60.0 s ago", view.sample_freshness)

    def test_collapsed_recent_rate_does_not_claim_efficiency_or_cause(self):
        status = authoritative_status()
        for current in (127.0, 10.0, 0.0, None):
            view = DashboardView.from_status(status.model_copy(update={
                "telemetry": status.telemetry.model_copy(update={
                    "current_mib_per_second": current,
                    "effective_mib_per_second": 78.0,
                })
            }))
            self.assertFalse(hasattr(view, "streaming_efficiency"))
            self.assertFalse(hasattr(view, "bottleneck_status"))
            self.assertEqual("78.00 MiB/s", view.effective_rate)
            self.assertEqual("Sample age unavailable", view.sample_freshness)


class ReviewManagementTests(unittest.TestCase):
    setUp = management.ManagementViewTests.setUp
    establish_session = management.ManagementViewTests.establish_session

    def test_catalog_row_checkboxes_submit_their_exact_versions_to_restore_form(self):
        self.establish_session(self.operator)
        page = self.client.get("/catalog")
        document = management._FieldAssociationParser()
        document.feed(page.text)
        forms = [(index, node) for index, node in enumerate(document.nodes)
                 if node["tag"] == "form" and node["attrs"].get("action") == "/catalog/restore-plans"]
        self.assertEqual(1, len(forms))
        form_index, form = forms[0]
        form_id = form["attrs"].get("id")
        selected = []
        values = {}
        for index, node in enumerate(document.nodes):
            attrs = node["attrs"]
            if node["tag"] == "input" and attrs.get("name") == "file_version_ids":
                rows = [row for row, candidate in enumerate(document.nodes)
                        if candidate["tag"] == "tr" and document.is_descendant(index, row)]
                self.assertEqual(1, len(rows), "selection belongs in its metadata row")
                self.assertEqual(form_id, attrs.get("form"))
                selected.append(attrs["value"])
            if node["tag"] == "input" and attrs.get("type") == "hidden" and document.is_descendant(index, form_index):
                values[attrs["name"]] = attrs["value"]
        self.assertEqual(["42", "41"], selected)
        self.assertIsNotNone(form_id)
        values.update(file_version_ids=selected, destination_root="/srv/restore", destination_subdirectory="")
        response = self.client.post("/catalog/restore-plans", content=urlencode(values, doseq=True),
                                    headers={"content-type": "application/x-www-form-urlencoded"})
        self.assertEqual(303, response.status_code, response.text)
        request = next(payload[0] for name, payload in reversed(self.daemon.calls)
                       if name == "create_catalog_restore_plan")
        self.assertEqual((42, 41), request.file_version_ids)

    def test_settings_profile_size_is_readable_but_byte_inputs_remain_exact(self):
        self.establish_session(self.admin)
        page = self.client.get("/settings")
        self.assertIn("33.68 TiB", page.text)
        self.assertIn('name="capacity_reserve_bytes" value="1024"', page.text)
        self.assertIn('title="Usable LTFS: 37,030,000,000,000 B"', page.text)

    def test_media_format_is_unavailable_while_operation_is_active(self):
        self.establish_session(self.admin)
        status = authoritative_status()
        active_status = status.model_copy(update={"expected_media":
            status.expected_media.model_copy(update={"format_required": True})})
        self.daemon.get = lambda *args, **kwargs: active_status
        page = self.client.get("/media")
        self.assertEqual(200, page.status_code)
        self.assertNotIn('type="submit">Format cassette', page.text)
        self.assertIn("Formatting is unavailable while an operation is active", page.text)

    def test_job_fragment_refreshes_checkpoint_sequence_and_actions(self):
        self.establish_session(self.admin)
        self.daemon.job = self.daemon.job.model_copy(update={
            "state": "paused", "current_checkpoint": "ready_to_resume",
            "capabilities": self.daemon.job.capabilities.model_copy(update={
                "start": False, "resume": True, "pause": False}),
        })
        self.daemon.sequence_status["authorization_state"] = "authorized"
        response = self.client.get("/partials/jobs/JOB-1/runtime")
        self.assertEqual(200, response.status_code, response.text)
        self.assertIn("ready_to_resume", response.text)
        self.assertIn("AB1234", response.text)
        self.assertIn('action="/jobs/JOB-1/resume"', response.text)
        self.assertNotIn('action="/jobs/JOB-1/pause"', response.text)
        self.assertIn('data-job-fragment="header"', response.text)

    def test_job_refresh_preserves_independent_pagination_without_reloading_manifest(self):
        self.establish_session(self.admin)
        self.daemon.cassettes = tuple(self.daemon.job.cassettes[0].model_copy(
            update={"sequence": sequence}) for sequence in range(1, 66))
        cursors = {"cassette_cursor": "0", "manifest_cursor": "manifest-2", "history_cursor": "history-3"}
        page = self.client.get("/jobs/JOB-1", params=cursors)
        document = management._FieldAssociationParser()
        document.feed(page.text)
        url = next(node["attrs"]["data-runtime-url"] for node in document.nodes
                   if "data-runtime-url" in node["attrs"])
        self.assertEqual({key: [value] for key, value in cursors.items()}, parse_qs(urlparse(url).query))
        def unexpected_read(*args, **kwargs):
            self.fail("live refresh must not reload immutable manifest/history")
        self.daemon.get_job_manifest = unexpected_read
        self.daemon.get_job_history = unexpected_read
        partial = self.client.get(url)
        self.assertEqual(200, partial.status_code)
        document = management._FieldAssociationParser()
        document.feed(partial.text)
        links = [node["attrs"]["href"] for node in document.nodes
                 if node["tag"] == "a" and "cassette_cursor=" in node["attrs"].get("href", "")]
        self.assertEqual({"cassette_cursor": ["64"], "manifest_cursor": ["manifest-2"],
                          "history_cursor": ["history-3"]}, parse_qs(urlparse(links[0]).query))

    def test_job_refresh_updates_management_capabilities_and_failed_reset(self):
        self.establish_session(self.admin)
        first = self.client.get("/partials/jobs/JOB-1/runtime")
        self.assertIn('action="/jobs/JOB-1/update"', first.text)
        self.daemon.job = self.daemon.job.model_copy(update={"state": "failed", "capabilities":
            self.daemon.job.capabilities.model_copy(update={"rename": False, "extend": False,
                "reserve_label": False, "retire": False, "reset_failed_cassette": True})})
        self.daemon.cassettes = tuple(item.model_copy(update={"state": "failed"}) for item in self.daemon.cassettes)
        response = self.client.get("/partials/jobs/JOB-1/runtime")
        self.assertEqual(200, response.status_code)
        self.assertIn('action="/jobs/JOB-1/failed-cassette/reset"', response.text)
        for action in ("update", "extension-plan", "reserve-labels", "retire"):
            self.assertNotIn(f'action="/jobs/JOB-1/{action}"', response.text)
