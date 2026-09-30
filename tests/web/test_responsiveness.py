from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, TimeoutError
from threading import Event
from unittest.mock import patch

from tests.web.test_live_ui import LiveWebAppTestCase


class ScanReadResponsivenessTests(LiveWebAppTestCase):
    def test_slow_daemon_reads_do_not_block_other_web_requests(self) -> None:
        routes = (
            ("/", "get"),
            ("/status-fragment", "get"),
            ("/libraries", "list_libraries"),
            ("/libraries/status-fragment", "list_libraries"),
            ("/jobs", "list_jobs"),
            ("/jobs/status-fragment", "list_jobs"),
            ("/jobs/JOB1", "get_job"),
            ("/partials/jobs/JOB1/runtime", "get_job"),
        )
        # The context keeps both requests on the same ASGI event loop, as in
        # a single WebUI worker. Without it, TestClient creates separate loops.
        with self.client, ThreadPoolExecutor(max_workers=2) as requests:
            self.login()
            session_cookies = "; ".join(
                f"{name}={value}" for name, value in self.client.cookies.items()
            )
            for path, method_name in routes:
                with self.subTest(path=path):
                    entered = Event()
                    release = Event()
                    original = getattr(self.daemon, method_name)

                    def slow_read(*args, **kwargs):
                        entered.set()
                        if not release.wait(10):
                            raise AssertionError("Blocked daemon read was not released")
                        return original(*args, **kwargs)

                    with patch.object(self.daemon, method_name, slow_read):
                        pending = requests.submit(
                            self.client.get, path, headers={"cookie": session_cookies}
                        )
                        try:
                            self.assertTrue(entered.wait(2), "Route did not read the daemon")
                            login = requests.submit(
                                self.client.get, "/login", headers={"cookie": ""}
                            )
                            try:
                                response = login.result(timeout=2)
                            except TimeoutError:
                                self.fail("A slow daemon read blocked the WebUI event loop")
                            self.assertEqual(200, response.status_code)
                            self.assertIn('name="login_csrf"', response.text)
                            self.assertFalse(pending.done())
                        finally:
                            release.set()
                            completed = pending.result(timeout=2)
                        self.assertEqual(200, completed.status_code, completed.text)
