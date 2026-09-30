from __future__ import annotations

import base64
import json
import os
import re
import select
import shlex
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from collections.abc import Callable
from html import escape
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from jinja2 import Environment, FileSystemLoader

from ltobackup.client import DaemonUnavailable
from ltobackup.daemon.api_models import (
    CreateCatalogRestorePlanRequestV1,
    JobHistoryPageV1,
    JobListPageV1,
    JobManifestPageV1,
    TelemetrySampleV1,
)
from ltobackup.web.app import WebSettings, create_web_app, render_telemetry
from ltobackup.web.auth_store import AuthStore
from tests.web.english_surface import assert_english_document
from tests.web.test_dashboard import WebAppTestCase, authoritative_status
from tests.web.test_live_ui import LiveWebAppTestCase
from tests.web.test_management_views import ManagementDaemonFake, _restore_run
from tests.web.test_runtime_diagnostics import RuntimeDiagnosticDaemon

_CHROMIUM = next(
    (
        executable
        for name in (
            "google-chrome",
            "google-chrome-stable",
            "chromium",
            "chromium-browser",
        )
        if (executable := shutil.which(name)) is not None
    ),
    None,
)


def _fixture_assets(html: str, css_uri: str, live_uri: str | None = None) -> str:
    """Make a saved page self-contained despite deployment asset versions."""
    html = re.sub(
        r'<link rel="stylesheet" href="/static/app\.css(?:\?[^"]*)?">',
        lambda _match: f'<link rel="stylesheet" href="{escape(css_uri, quote=True)}">',
        html,
    )
    return re.sub(
        r'\s*<script defer src="/static/(htmx|live)\.js(?:\?[^"]*)?"[^>]*></script>',
        lambda match: (
            f'<script defer src="{escape(live_uri, quote=True)}"></script>'
            if match.group(1) == "live" and live_uri is not None
            else ""
        ),
        html,
    )


class _DevToolsPipe:
    def __init__(
        self,
        executable: str,
        profile: Path,
        *,
        startup_timeout: float = 30,
    ) -> None:
        browser_read, client_write = os.pipe()
        client_read, browser_write = os.pipe()
        safe_browser_read = os.dup(browser_read)
        safe_browser_write = os.dup(browser_write)
        stderr = tempfile.TemporaryFile()  # noqa: SIM115 - owned until Chrome exits

        try:
            self._process = subprocess.Popen(
                [
                    "/bin/bash",
                    "-c",
                    'exec 3<&"$1" 4>&"$2"; shift 2; exec "$@"',
                    "devtools-pipe",
                    str(safe_browser_read),
                    str(safe_browser_write),
                    executable,
                    "--headless=new",
                    "--disable-dev-shm-usage",
                    "--no-sandbox",
                    "--remote-debugging-pipe",
                    f"--user-data-dir={profile}",
                    "about:blank",
                ],
                pass_fds=(safe_browser_read, safe_browser_write),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=stderr,
            )
        except BaseException:
            os.close(client_write)
            os.close(client_read)
            stderr.close()
            raise
        finally:
            for descriptor in (
                browser_read,
                browser_write,
                safe_browser_read,
                safe_browser_write,
            ):
                os.close(descriptor)

        self._client_write = client_write
        self._client_read = client_read
        self._stderr = stderr
        self._incoming = bytearray()
        self._events: list[dict[str, Any]] = []
        self._next_id = 1
        self._closed = False

        try:
            self.request("Browser.getVersion", timeout=startup_timeout)
        except BaseException as startup_error:
            try:
                self._shutdown(send_browser_close=False)
            except (OSError, subprocess.SubprocessError) as cleanup_error:
                startup_error.add_note(f"Chrome cleanup also failed: {cleanup_error}")
            raise

    def close(self) -> None:
        self._shutdown(send_browser_close=True)

    def _shutdown(self, *, send_browser_close: bool) -> None:
        if self._closed:
            return
        self._closed = True
        if send_browser_close and self._process.poll() is None:
            try:
                self.request("Browser.close", timeout=2)
            except (AssertionError, OSError, RuntimeError, TimeoutError):
                pass
        for descriptor in (self._client_write, self._client_read):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if not send_browser_close and self._process.poll() is None:
            try:
                self._process.terminate()
            except ProcessLookupError:
                pass
        try:
            self._process.communicate(timeout=5 if send_browser_close else 2)
        except subprocess.TimeoutExpired:
            try:
                self._process.terminate()
            except ProcessLookupError:
                pass
            try:
                self._process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    self._process.kill()
                except ProcessLookupError:
                    pass
                self._process.communicate(timeout=2)
        finally:
            self._stderr.close()

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        session_id: str | None = None,
        timeout: float = 10,
    ) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        message: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        if session_id is not None:
            message["sessionId"] = session_id
        os.write(
            self._client_write,
            json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\0",
        )

        deadline = time.monotonic() + timeout
        while True:
            try:
                response = self._read_message(deadline)
            except TimeoutError as error:
                raise TimeoutError(
                    f"DevTools {method} timed out after {timeout:g}s; "
                    f"{self._process_diagnostics()}"
                ) from error
            if response.get("id") == request_id:
                if "error" in response:
                    raise AssertionError(
                        f"DevTools {method} failed: {response['error']}"
                    )
                return response.get("result", {})
            if "method" in response:
                self._events.append(response)

    def wait_for_event(
        self,
        method: str,
        *,
        session_id: str,
        matches: Callable[[dict[str, Any]], bool],
        timeout: float = 10,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            for index, event in enumerate(self._events):
                if (
                    event.get("method") == method
                    and event.get("sessionId") == session_id
                    and matches(event.get("params", {}))
                ):
                    return self._events.pop(index)["params"]
            try:
                event = self._read_message(deadline)
            except TimeoutError as error:
                raise TimeoutError(
                    f"DevTools event {method} timed out after {timeout:g}s; "
                    f"{self._process_diagnostics()}"
                ) from error
            if (
                event.get("method") == method
                and event.get("sessionId") == session_id
                and matches(event.get("params", {}))
            ):
                return event["params"]
            if "method" in event:
                self._events.append(event)

    def _read_message(self, deadline: float) -> dict[str, Any]:
        while b"\0" not in self._incoming:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("timed out waiting for a DevTools response")
            readable, _, _ = select.select([self._client_read], [], [], remaining)
            if not readable:
                raise TimeoutError("timed out waiting for a DevTools response")
            chunk = os.read(self._client_read, 65536)
            if not chunk:
                raise RuntimeError(
                    f"DevTools pipe closed unexpectedly; {self._process_diagnostics()}"
                )
            self._incoming.extend(chunk)
        payload, _, remainder = self._incoming.partition(b"\0")
        self._incoming = bytearray(remainder)
        return json.loads(payload)

    def _process_diagnostics(self) -> str:
        exit_code = self._process.poll()
        if exit_code is None:
            try:
                exit_code = self._process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                process_status = "running"
            else:
                process_status = f"exit={exit_code}"
        else:
            process_status = f"exit={exit_code}"

        try:
            size = os.fstat(self._stderr.fileno()).st_size
            start = max(0, size - 4096)
            stderr_tail = os.pread(self._stderr.fileno(), size - start, start).decode(
                "utf-8", errors="replace"
            )
        except OSError:
            stderr_tail = ""
        return (
            f"process={process_status}; stderr_tail={stderr_tail.strip() or '<empty>'}"
        )


@unittest.skipUnless(_CHROMIUM, "Chromium is required for the DevTools pipe gate")
class DevToolsPipeTests(unittest.TestCase):
    def test_startup_timeout_kills_a_stubborn_process_without_masking_diagnostics(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="lto-web-stubborn-chrome-",
            dir=Path.home(),
        ) as directory:
            test_dir = Path(directory)
            pid_file = test_dir / "stubborn.pid"
            stubborn_chromium = test_dir / "stubborn-chromium"
            stubborn_chromium.write_text(
                "#!/bin/bash\n"
                "trap '' TERM\n"
                f"echo $$ > {shlex.quote(pid_file.as_posix())}\n"
                "while true; do sleep 1; done\n",
                encoding="utf-8",
            )
            stubborn_chromium.chmod(0o700)

            started = time.monotonic()
            with self.assertRaisesRegex(
                TimeoutError,
                r"Browser\.getVersion timed out.*process=running",
            ):
                _DevToolsPipe(
                    stubborn_chromium.as_posix(),
                    test_dir / "profile",
                    startup_timeout=0.1,
                )
            elapsed = time.monotonic() - started

            pid = int(pid_file.read_text(encoding="utf-8"))
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            self.assertLess(elapsed, 8)

    def test_startup_failure_reports_process_exit_and_stderr(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="lto-web-failed-chrome-",
            dir=Path.home(),
        ) as directory:
            test_dir = Path(directory)
            failed_chromium = test_dir / "failed-chromium"
            failed_chromium.write_text(
                "#!/bin/bash\necho 'synthetic cold-start failure' >&2\nexit 23\n",
                encoding="utf-8",
            )
            failed_chromium.chmod(0o700)

            with self.assertRaisesRegex(
                RuntimeError,
                r"exit=23.*synthetic cold-start failure",
            ):
                _DevToolsPipe(failed_chromium.as_posix(), test_dir / "profile")

    def test_cold_chromium_start_has_a_separate_bounded_handshake_budget(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="lto-web-cold-chrome-",
            dir=Path.home(),
        ) as directory:
            test_dir = Path(directory)
            delayed_chromium = test_dir / "delayed-chromium"
            delayed_chromium.write_text(
                f'#!/bin/bash\nsleep 12\nexec {shlex.quote(str(_CHROMIUM))} "$@"\n',
                encoding="utf-8",
            )
            delayed_chromium.chmod(0o700)

            started = time.monotonic()
            devtools = _DevToolsPipe(delayed_chromium.as_posix(), test_dir / "profile")
            try:
                try:
                    version = devtools.request("Browser.getVersion")
                except TimeoutError as error:
                    self.fail(f"cold Chromium start exceeded handshake budget: {error}")
            finally:
                devtools.close()
            elapsed = time.monotonic() - started

            self.assertIn("Chrome/", version["product"])
            self.assertGreaterEqual(elapsed, 11.5)
            self.assertLess(elapsed, 30)


@unittest.skipUnless(_CHROMIUM, "Chromium is required for the 1280x720 layout gate")
class ChromiumLayoutTests(WebAppTestCase):
    def dashboard_layout_at(self, width: int, height: int) -> dict[str, Any]:
        if not self.client.cookies.get("lto_archiver_session"):
            self.login()
        page = self.client.get("/")

        with tempfile.TemporaryDirectory(
            prefix="lto-web-responsive-layout-",
            dir=Path.home(),
        ) as directory:
            test_dir = Path(directory)
            html_path = test_dir / "dashboard.html"
            css_path = test_dir / "app.css"
            shutil.copyfile("src/ltobackup/web/static/app.css", css_path)
            html = _fixture_assets(page.text, css_path.as_uri())
            html_path.write_text(html, encoding="utf-8")

            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                target_id = devtools.request(
                    "Target.createTarget", {"url": "about:blank"}
                )["targetId"]
                session_id = devtools.request(
                    "Target.attachToTarget",
                    {"targetId": target_id, "flatten": True},
                )["sessionId"]
                devtools.request("Page.enable", session_id=session_id)
                devtools.request(
                    "Page.setLifecycleEventsEnabled",
                    {"enabled": True},
                    session_id=session_id,
                )
                devtools.request(
                    "Emulation.setDeviceMetricsOverride",
                    {
                        "width": width,
                        "height": height,
                        "deviceScaleFactor": 1,
                        "mobile": False,
                        "screenWidth": width,
                        "screenHeight": height,
                    },
                    session_id=session_id,
                )
                navigation = devtools.request(
                    "Page.navigate",
                    {"url": html_path.as_uri()},
                    session_id=session_id,
                )
                self.assertNotIn("errorText", navigation, navigation)
                loader_id = navigation["loaderId"]
                devtools.wait_for_event(
                    "Page.lifecycleEvent",
                    session_id=session_id,
                    matches=lambda event: (
                        event.get("name") == "load"
                        and event.get("loaderId") == loader_id
                    ),
                )
                evaluation = devtools.request(
                    "Runtime.evaluate",
                    {
                        "expression": """
                          (() => {
                            const rect = selector => document.querySelector(
                              selector
                            ).getBoundingClientRect().toJSON();
                            return {
                              navDisplay: getComputedStyle(document.querySelector(
                                ".site-nav"
                              )).display,
                              nav: rect(".site-nav"),
                              brand: rect(".brand"),
                              session: rect(".session-summary"),
                              status: rect(".status-grid"),
                              metrics: rect(".metrics-grid"),
                              storage: rect('[data-live-key="storage"]'),
                              storageItems: [...document.querySelectorAll(
                                '[data-live-key="storage"] .status-card, [data-live-key="storage"] dd'
                              )].map(item => ({
                                left: item.getBoundingClientRect().left,
                                right: item.getBoundingClientRect().right,
                                overflow: item.scrollWidth > item.clientWidth + 1,
                              })),
                              metricCards: [...document.querySelectorAll(
                                ".metric-card"
                              )].map(card => ({
                                left: card.getBoundingClientRect().left,
                                valueFontPixels: parseFloat(getComputedStyle(
                                  card.querySelector("p")
                                ).fontSize),
                              })),
                            };
                          })()
                        """,
                        "returnByValue": True,
                    },
                    session_id=session_id,
                )
                self.assertNotIn("exceptionDetails", evaluation, evaluation)
                return evaluation["result"]["value"]
            finally:
                devtools.close()

    def _responsive_fixture(
        self,
        directory: Path,
        *,
        javascript: bool,
        path: str = "/users",
        name: str = "users",
    ) -> Path:
        if not self.client.cookies.get("lto_archiver_session"):
            self.login()
        page = self.client.get(path)
        self.assertEqual(200, page.status_code, page.text)
        html_path = directory / (
            f"{name}-js.html" if javascript else f"{name}-no-js.html"
        )
        css_path = directory / "app.css"
        live_path = Path("src/ltobackup/web/static/live.js").resolve()
        shutil.copyfile("src/ltobackup/web/static/app.css", css_path)
        html = _fixture_assets(
            page.text, css_path.as_uri(), live_path.as_uri() if javascript else None
        )
        html = html.replace(
            "admin",
            "amministratore-con-un-nome-estremamente-lungo-che-deve-andare-a-capo",
        )
        html_path.write_text(html, encoding="utf-8")
        return html_path

    @staticmethod
    def _attach_page(devtools: _DevToolsPipe) -> str:
        target_id = devtools.request("Target.createTarget", {"url": "about:blank"})[
            "targetId"
        ]
        session_id = devtools.request(
            "Target.attachToTarget", {"targetId": target_id, "flatten": True}
        )["sessionId"]
        devtools.request("Page.enable", session_id=session_id)
        devtools.request(
            "Page.setLifecycleEventsEnabled",
            {"enabled": True},
            session_id=session_id,
        )
        return session_id

    def _navigate_fixture(
        self,
        devtools: _DevToolsPipe,
        session_id: str,
        html_path: Path,
        *,
        width: int,
        height: int,
        device_scale_factor: int = 1,
    ) -> None:
        devtools.request(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": width,
                "height": height,
                "deviceScaleFactor": device_scale_factor,
                "mobile": False,
                "screenWidth": width,
                "screenHeight": height,
            },
            session_id=session_id,
        )
        navigation = devtools.request(
            "Page.navigate", {"url": html_path.as_uri()}, session_id=session_id
        )
        self.assertNotIn("errorText", navigation, navigation)
        loader_id = navigation["loaderId"]
        devtools.wait_for_event(
            "Page.lifecycleEvent",
            session_id=session_id,
            matches=lambda event: (
                event.get("name") == "load" and event.get("loaderId") == loader_id
            ),
        )

    @staticmethod
    def _layout_expression() -> str:
        return """
          (() => {
            const visible = element => {
              const rect = element.getBoundingClientRect();
              const style = getComputedStyle(element);
              return rect.width > 0 && rect.height > 0 &&
                style.display !== "none" && style.visibility !== "hidden";
            };
            const rect = selector => document.querySelector(
              selector
            ).getBoundingClientRect().toJSON();
            const targets = [...document.querySelectorAll(
              'a[href], button, input:not([type="hidden"]), select, textarea'
            )].filter(visible).map(element => ({
              label: element.textContent.trim() || element.getAttribute("name"),
              rect: element.getBoundingClientRect().toJSON(),
            }));
            const toolbarOverlaps = [...document.querySelectorAll(
              ".action-toolbar, .danger-toolbar"
            )].flatMap(toolbar => {
              const items = [...toolbar.children].filter(visible);
              return items.flatMap((left, index) => items.slice(index + 1).filter(right => {
                const a = left.getBoundingClientRect();
                const b = right.getBoundingClientRect();
                return a.left < b.right && a.right > b.left &&
                  a.top < b.bottom && a.bottom > b.top;
              }));
            }).length;
            const focusTarget = document.querySelector(
              ".nav-toggle:not([hidden]), .site-nav a"
            );
            focusTarget.focus();
            const focusStyle = getComputedStyle(focusTarget);
            const table = document.querySelector(".summary-table");
            const nav = document.querySelector("#app-navigation");
            const toggle = document.querySelector("[data-nav-toggle]");
            return {
              viewport: [innerWidth, innerHeight],
              desktop: matchMedia("(min-width: 64rem)").matches,
              documentOverflow: document.documentElement.scrollWidth -
                document.documentElement.clientWidth,
              navHidden: nav.hidden,
              navDisplay: getComputedStyle(nav).display,
              navLinksTabbable: [...nav.querySelectorAll("a")].every(
                link => link.getAttribute("tabindex") !== "-1"
              ),
              toggleDisplay: getComputedStyle(toggle).display,
              toggleExpanded: toggle.getAttribute("aria-expanded"),
              rail: rect(".site-header"),
              railPosition: getComputedStyle(document.querySelector(
                ".site-header"
              )).position,
              content: rect("#main-content"),
              minimumTargetWidth: Math.min(...targets.map(item => item.rect.width)),
              minimumTargetHeight: Math.min(...targets.map(item => item.rect.height)),
              targets,
              formsInBounds: [...document.querySelectorAll("form")].every(form => {
                const bounds = form.getBoundingClientRect();
                const scroller = form.closest(".table-scroll");
                if (scroller && table && getComputedStyle(table).display === "table") {
                  return bounds.width <= scroller.scrollWidth;
                }
                return bounds.left >= 0 && bounds.right <= innerWidth;
              }),
              toolbarOverlaps,
              primaryGroups: document.querySelectorAll(".action-toolbar").length,
              dangerGroups: document.querySelectorAll(".danger-toolbar").length,
              dangerInsidePrimary: document.querySelectorAll(
                ".action-toolbar .danger-action"
              ).length,
              summaryDisplay: table ? getComputedStyle(table).display : null,
              summaryRows: table ? [...table.tBodies[0].rows].map(row =>
                getComputedStyle(row).display) : [],
              focusOutline: [focusStyle.outlineStyle, focusStyle.outlineWidth],
              h1Count: document.querySelectorAll("h1").length,
            };
          })()
        """

    def test_management_shell_reflows_across_the_normative_viewport_matrix(
        self,
    ) -> None:
        matrix = (
            (1280, 720, 1),
            (1024, 768, 1),
            (800, 600, 1),
            (390, 844, 1),
            (320, 568, 1),
            (640, 360, 2),
        )
        with tempfile.TemporaryDirectory(
            prefix="lto-web-management-matrix-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            fixtures = {
                "users": self._responsive_fixture(test_dir, javascript=True),
            }
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = self._attach_page(devtools)
                for fixture_name, html_path in fixtures.items():
                    for width, height, scale in matrix:
                        with self.subTest(
                            fixture=fixture_name,
                            width=width,
                            height=height,
                            scale=scale,
                        ):
                            self._navigate_fixture(
                                devtools,
                                session_id,
                                html_path,
                                width=width,
                                height=height,
                                device_scale_factor=scale,
                            )
                            evaluation = devtools.request(
                                "Runtime.evaluate",
                                {
                                    "expression": self._layout_expression(),
                                    "returnByValue": True,
                                },
                                session_id=session_id,
                            )
                            self.assertNotIn("exceptionDetails", evaluation, evaluation)
                            result = evaluation["result"]["value"]
                            self.assertEqual([width, height], result["viewport"])
                            self.assertLessEqual(result["documentOverflow"], 0, result)
                            self.assertTrue(result["formsInBounds"], result)
                            self.assertEqual(0, result["toolbarOverlaps"], result)
                            self.assertEqual(0, result["dangerInsidePrimary"], result)
                            self.assertGreaterEqual(result["primaryGroups"], 1, result)
                            self.assertGreaterEqual(result["dangerGroups"], 1, result)
                            self.assertGreaterEqual(
                                result["minimumTargetHeight"], 44, result
                            )
                            self.assertGreaterEqual(
                                result["minimumTargetWidth"], 44, result
                            )
                            self.assertNotEqual(
                                "none", result["focusOutline"][0], result
                            )
                            self.assertNotEqual(
                                "0px", result["focusOutline"][1], result
                            )
                            self.assertEqual(1, result["h1Count"], result)
                            if width >= 1024:
                                self.assertTrue(result["desktop"], result)
                                self.assertEqual(
                                    "sticky", result["railPosition"], result
                                )
                                self.assertAlmostEqual(
                                    272, result["rail"]["width"], delta=1
                                )
                                self.assertGreaterEqual(
                                    result["content"]["left"], result["rail"]["right"]
                                )
                                self.assertFalse(result["navHidden"], result)
                                self.assertTrue(result["navLinksTabbable"], result)
                                self.assertEqual(
                                    "none", result["toggleDisplay"], result
                                )
                            else:
                                self.assertFalse(result["desktop"], result)
                                self.assertTrue(result["navHidden"], result)
                                self.assertFalse(result["navLinksTabbable"], result)
                                self.assertEqual(
                                    "false", result["toggleExpanded"], result
                                )
                                self.assertNotEqual(
                                    "none", result["toggleDisplay"], result
                                )
                            if width < 672:
                                self.assertEqual(
                                    ["grid"] * len(result["summaryRows"]),
                                    result["summaryRows"],
                                )
            finally:
                devtools.close()

    def test_noscript_navigation_remains_visible_and_tabbable_on_mobile(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="lto-web-management-noscript-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = self._responsive_fixture(test_dir, javascript=False)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = self._attach_page(devtools)
                self._navigate_fixture(
                    devtools, session_id, html_path, width=390, height=844
                )
                evaluation = devtools.request(
                    "Runtime.evaluate",
                    {
                        "expression": """
                          (() => {
                            const nav = document.querySelector("#app-navigation");
                            const toggle = document.querySelector("[data-nav-toggle]");
                            return {
                              navDisplay: getComputedStyle(nav).display,
                              linksTabbable: [...nav.querySelectorAll("a")].every(
                                link => link.getAttribute("tabindex") !== "-1"
                              ),
                              toggleDisplay: getComputedStyle(toggle).display,
                              documentOverflow: document.documentElement.scrollWidth -
                                document.documentElement.clientWidth,
                            };
                          })()
                        """,
                        "returnByValue": True,
                    },
                    session_id=session_id,
                )
            finally:
                devtools.close()

        self.assertNotIn("exceptionDetails", evaluation, evaluation)
        result = evaluation["result"]["value"]
        self.assertNotEqual("none", result["navDisplay"], result)
        self.assertTrue(result["linksTabbable"], result)
        self.assertEqual("none", result["toggleDisplay"], result)
        self.assertLessEqual(result["documentOverflow"], 0, result)

    def test_navigation_groups_have_names_in_the_chromium_accessibility_tree(
        self,
    ) -> None:
        # Removing the semantic group role makes the visible headings disappear
        # as group names from Chromium's accessibility tree.
        with tempfile.TemporaryDirectory(
            prefix="lto-web-navigation-ax-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = self._responsive_fixture(test_dir, javascript=True)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = self._attach_page(devtools)
                self._navigate_fixture(
                    devtools, session_id, html_path, width=1280, height=720
                )
                tree = devtools.request(
                    "Accessibility.getFullAXTree", session_id=session_id
                )
            finally:
                devtools.close()

        named_groups = {
            node.get("name", {}).get("value")
            for node in tree["nodes"]
            if node.get("role", {}).get("value") == "group"
        }
        self.assertTrue(
            {"Management", "Administration", "Diagnostics"}.issubset(named_groups),
            named_groups,
        )

    def test_dashboard_card_groups_have_a_visible_vertical_gutter(self) -> None:
        result = self.dashboard_layout_at(1024, 768)

        self.assertGreaterEqual(
            result["status"]["top"] - result["metrics"]["bottom"],
            8,
            result,
        )

    def test_storage_values_reflow_without_clipping_on_phone_tablet_and_desktop(self) -> None:
        from tests.web.test_storage_dashboard import StorageDashboardTests

        self.daemon.get_storage_summary = lambda **kwargs: StorageDashboardTests.storage(self, **kwargs)
        for width in (360, 768, 1280):
            with self.subTest(width=width):
                result = self.dashboard_layout_at(width, 800)
                panel = result["storage"]
                self.assertGreaterEqual(panel["left"], 0, result)
                self.assertLessEqual(panel["right"], width, result)
                self.assertTrue(result["storageItems"], result)
                for item in result["storageItems"]:
                    self.assertGreaterEqual(item["left"], panel["left"], item)
                    self.assertLessEqual(item["right"], panel["right"], item)
                    self.assertFalse(item["overflow"], item)

    def test_dashboard_metrics_keep_three_balanced_columns_on_wide_screens(self) -> None:
        """Six metrics should not become an unbalanced wall of oversized cards."""
        for width in (1024, 1280):
            with self.subTest(width=width):
                result = self.dashboard_layout_at(width, 768)
                cards = result["metricCards"]
                self.assertEqual(
                    3,
                    len({round(card["left"]) for card in cards}),
                    cards,
                )
                self.assertTrue(
                    all(card["valueFontPixels"] <= 18 for card in cards),
                    cards,
                )

    def test_dashboard_chart_labels_and_legend_stay_inside_their_panel(self) -> None:
        """Axis and legend text must not be clipped by the SVG or panel edges."""
        self.daemon.status = authoritative_status().model_copy(
            update={
                "telemetry": authoritative_status().telemetry.model_copy(
                    update={
                        "samples": (
                            TelemetrySampleV1(
                                event_id=1,
                                occurred_at="2026-08-31T18:18:00Z",
                                mib_per_second=311.4,
                            ),
                            TelemetrySampleV1(
                                event_id=2,
                                occurred_at="2026-08-31T18:18:07Z",
                                mib_per_second=94.3,
                            ),
                        )
                    }
                )
            }
        )
        self.login()

        with tempfile.TemporaryDirectory(
            prefix="lto-web-chart-bounds-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = self._responsive_fixture(
                test_dir,
                javascript=False,
                path="/",
                name="dashboard-chart",
            )
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = self._attach_page(devtools)
                # Linux hosts may resolve system-ui to wider DejaVu glyphs.
                for width, height, font in (
                    (1280, 720, None), (390, 844, None),
                    (1280, 720, '"DejaVu Sans", sans-serif'),
                    (390, 844, '"DejaVu Sans", sans-serif'),
                ):
                    with self.subTest(width=width, font=font):
                        self._navigate_fixture(
                            devtools,
                            session_id,
                            html_path,
                            width=width,
                            height=height,
                        )
                        if font is not None:
                            devtools.request(
                                "Runtime.evaluate",
                                {"expression": (
                                    "document.documentElement.style.fontFamily = "
                                    + json.dumps(font)
                                )},
                                session_id=session_id,
                            )
                        result = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": """
                                  (() => {
                                    const inside = (child, parent) => {
                                      const item = child.getBoundingClientRect();
                                      const bounds = parent.getBoundingClientRect();
                                      return item.left >= bounds.left - 0.5 &&
                                        item.right <= bounds.right + 0.5 &&
                                        item.top >= bounds.top - 0.5 &&
                                        item.bottom <= bounds.bottom + 0.5;
                                    };
                                    const chart = document.querySelector('.telemetry-chart');
                                    const panel = document.querySelector('.telemetry-panel');
                                    const labels = [...chart.querySelectorAll('text')];
                                    const legends = [...document.querySelectorAll(
                                      '.telemetry-legend li'
                                    )];
                                    return {
                                      labelCount: labels.length,
                                      labelsInsideChart: labels.every(label =>
                                        inside(label, chart)
                                      ),
                                      overflowingLabels: labels.filter(label =>
                                        !inside(label, chart)
                                      ).map(label => ({
                                        text: label.textContent,
                                        bounds: label.getBoundingClientRect().toJSON(),
                                        font: getComputedStyle(label).font,
                                      })),
                                      chartBounds: chart.getBoundingClientRect().toJSON(),
                                      legendsInsidePanel: legends.every(legend =>
                                        inside(legend, panel)
                                      ),
                                      chartHeight: chart.getBoundingClientRect().height,
                                    };
                                  })()
                                """,
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )["result"]["value"]
                        self.assertGreater(result["labelCount"], 0, result)
                        self.assertTrue(result["labelsInsideChart"], result)
                        self.assertTrue(result["legendsInsidePanel"], result)
                        if width == 390:
                            self.assertGreaterEqual(result["chartHeight"], 180, result)
            finally:
                devtools.close()

    def test_first_1280x720_viewport_contains_every_timing_value(self) -> None:
        self.login()
        page = self.client.get("/")

        with tempfile.TemporaryDirectory(
            prefix="lto-web-layout-",
            dir=Path.home(),
        ) as directory:
            test_dir = Path(directory)
            screenshot = test_dir / "dashboard.png"
            html_path = test_dir / "dashboard.html"
            css_path = test_dir / "app.css"
            shutil.copyfile("src/ltobackup/web/static/app.css", css_path)
            css_uri = css_path.as_uri()
            html = _fixture_assets(page.text, css_uri)
            html_path.write_text(html, encoding="utf-8")

            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                target_id = devtools.request(
                    "Target.createTarget", {"url": "about:blank"}
                )["targetId"]
                session_id = devtools.request(
                    "Target.attachToTarget",
                    {"targetId": target_id, "flatten": True},
                )["sessionId"]
                devtools.request("Page.enable", session_id=session_id)
                devtools.request(
                    "Page.setLifecycleEventsEnabled",
                    {"enabled": True},
                    session_id=session_id,
                )
                devtools.request(
                    "Emulation.setDeviceMetricsOverride",
                    {
                        "width": 1280,
                        "height": 720,
                        "deviceScaleFactor": 1,
                        "mobile": False,
                        "screenWidth": 1280,
                        "screenHeight": 720,
                    },
                    session_id=session_id,
                )
                navigation = devtools.request(
                    "Page.navigate",
                    {"url": html_path.as_uri()},
                    session_id=session_id,
                )
                self.assertNotIn("errorText", navigation, navigation)
                loader_id = navigation["loaderId"]
                devtools.wait_for_event(
                    "Page.lifecycleEvent",
                    session_id=session_id,
                    matches=lambda event: (
                        event.get("name") == "load"
                        and event.get("loaderId") == loader_id
                    ),
                )
                evaluation = devtools.request(
                    "Runtime.evaluate",
                    {
                        "expression": """
                          (() => {
                            const visible = element => {
                              const rect = element.getBoundingClientRect();
                              const style = getComputedStyle(element);
                              return rect.width > 0 && rect.height > 0 &&
                                rect.top >= 0 && rect.left >= 0 &&
                                rect.bottom <= innerHeight && rect.right <= innerWidth &&
                                style.display !== "none" && style.visibility !== "hidden" &&
                                Number(style.opacity) > 0;
                            };
                            const rows = [...document.querySelectorAll(".timing-grid > div")];
                            const timings = rows.map(row => {
                              const label = row.querySelector("dt");
                              const value = row.querySelector("dd");
                              return {
                                label: label.textContent.trim(),
                                value: value.textContent.trim(),
                                labelVisible: visible(label),
                                valueVisible: visible(value),
                              };
                            });
                            const item = document.querySelector(".finalization-status");
                            return {
                              viewportWidth: innerWidth,
                              viewportHeight: innerHeight,
                              documentHeight: document.documentElement.scrollHeight,
                              timings,
                              allTimingsVisible: timings.every(
                                row => row.labelVisible && row.valueVisible
                              ),
                              finalization: {
                                text: item.textContent.trim(),
                                visible: visible(item),
                                clipped: item.scrollHeight > item.clientHeight ||
                                  item.scrollWidth > item.clientWidth,
                              },
                            };
                          })()
                        """,
                        "returnByValue": True,
                    },
                    session_id=session_id,
                )
                self.assertNotIn("exceptionDetails", evaluation, evaluation)
                result = evaluation["result"]["value"]
                capture = devtools.request(
                    "Page.captureScreenshot",
                    {
                        "format": "png",
                        "fromSurface": True,
                        "captureBeyondViewport": False,
                    },
                    session_id=session_id,
                )
                screenshot.write_bytes(base64.b64decode(capture["data"], validate=True))
            finally:
                devtools.close()

            labels = [row["label"] for row in result["timings"]]
            values = [row["value"] for row in result["timings"]]

            self.assertEqual(
                (1280, 720),
                (result["viewportWidth"], result["viewportHeight"]),
            )
            self.assertEqual(
                [
                    "Copy",
                    "File close",
                    "LTFS index finalization",
                    "Unmount",
                    "Unload",
                ],
                labels,
            )
            self.assertEqual(
                ["1 h 00 min", "2 min 00 s", "1 min 35 s", "0.00 s", "0.00 s"],
                values,
            )
            self.assertTrue(result["allTimingsVisible"], result)
            self.assertIn(
                "LTFS cassette finalization", result["finalization"]["text"]
            )
            self.assertTrue(result["finalization"]["visible"], result)
            self.assertFalse(result["finalization"]["clipped"], result)
            self.assertTrue(screenshot.is_file())
            with screenshot.open("rb") as image:
                self.assertEqual(b"\x89PNG\r\n\x1a\n", image.read(8))
                image.read(8)
                width, height = struct.unpack(">II", image.read(8))
            self.assertEqual((1280, 720), (width, height))


class _ResponsiveManagementDaemon(ManagementDaemonFake):
    def list_jobs(self, **_kwargs):
        return JobListPageV1(
            items=(self.job,), next_cursor="next-jobs", current_job_id=None
        )

    def get_job_manifest(self, _job_id: str, **_kwargs):
        return JobManifestPageV1.model_validate(
            {
                "items": (
                    {
                        "cassette_sequence": 1,
                        "item_sequence": 1,
                        "library_id": "PHOTOS",
                        "relative_path": "album/foto.jpg",
                        "size": 7,
                        "mtime_ns": 1,
                    },
                ),
                "next_cursor": "next-manifest",
            }
        )

    def get_job_history(self, _job_id: str, **_kwargs):
        return JobHistoryPageV1.model_validate(
            {
                "items": (
                    {
                        "id": 1,
                        "occurred_at": "2026-08-25T10:00:00+00:00",
                        "action": "saved",
                        "actor": "admin",
                        "checkpoint": "saved",
                    },
                ),
                "next_cursor": "next-history",
            }
        )


@unittest.skipUnless(_CHROMIUM, "Chromium is required for content target gates")
class ChromiumManagementContentTargetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = AuthStore(Path(self.temporary.name) / "auth.db")
        self.store.create_admin("admin", "correct horse battery staple")
        self.daemon = _ResponsiveManagementDaemon()
        self.app = create_web_app(WebSettings(), self.store, self.daemon)
        self.client = TestClient(
            self.app,
            base_url="https://console.example",
            follow_redirects=False,
        )
        self.addCleanup(self.client.close)
        login_page = self.client.get("/login")
        token = re.search(
            r'name="login_csrf" value="([A-Za-z0-9_-]+)"', login_page.text
        )
        assert token is not None
        response = self.client.post(
            "/login",
            data={
                "username": "admin",
                "password": "correct horse battery staple",
                "login_csrf": token.group(1),
            },
        )
        self.assertEqual(303, response.status_code, response.text)

    @staticmethod
    def _fixture(
        directory: Path, name: str, html: str, *, javascript: bool = False
    ) -> Path:
        css_path = directory / "app.css"
        if not css_path.exists():
            shutil.copyfile("src/ltobackup/web/static/app.css", css_path)
        html_path = directory / f"{name}.html"
        live_uri = Path("src/ltobackup/web/static/live.js").resolve().as_uri() if javascript else None
        html = _fixture_assets(html, css_path.as_uri(), live_uri)
        html_path.write_text(html, encoding="utf-8")
        return html_path

    def _library_form_evaluation(
        self, expression: str, *, javascript: bool = True
    ) -> dict[str, Any]:
        page = self.client.get("/libraries")
        self.assertEqual(200, page.status_code, page.text)
        with tempfile.TemporaryDirectory(
            prefix="lto-web-library-form-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            fixture = self._fixture(
                test_dir, "libraries", page.text, javascript=javascript
            )
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                ChromiumLayoutTests._navigate_fixture(
                    self,
                    devtools,
                    session_id,
                    fixture,
                    width=1280,
                    height=720,
                )
                return devtools.request(
                    "Runtime.evaluate",
                    {"expression": expression, "returnByValue": True},
                    session_id=session_id,
                )
            finally:
                devtools.close()

    def test_libraries_table_wraps_without_desktop_horizontal_scrolling(self) -> None:
        """Long library names and source paths must leave every column visible."""
        self.daemon.libraries = (
            self.daemon.libraries[0].model_copy(
                update={
                    "id": "FILM-ARCHIVE-WITH-A-LONG-IDENTIFIER",
                    "display_name": "Film archive with a deliberately long display name",
                    "source_root": (
                        "/mnt/lto-archiver/sources/smb-media/film/"
                        "feature-films-and-documentaries"
                    ),
                    "file_count": 35_894,
                    "byte_count": 2_409_544_728_948,
                }
            ),
        )
        page = self.client.get("/libraries")
        self.assertEqual(200, page.status_code, page.text)

        with tempfile.TemporaryDirectory(
            prefix="lto-web-library-table-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = self._fixture(test_dir, "libraries-table", page.text)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                ChromiumLayoutTests._navigate_fixture(
                    self,
                    devtools,
                    session_id,
                    html_path,
                    width=1280,
                    height=720,
                )
                result = devtools.request(
                    "Runtime.evaluate",
                    {
                        "expression": """
                          (() => {
                            const scroller = document.querySelector(
                              '#libraries-live-status .table-scroll'
                            );
                            const table = scroller.querySelector('table');
                            const cells = [...table.querySelectorAll('th, td')];
                            return {
                              overflow: table.scrollWidth - scroller.clientWidth,
                              cellsInside: cells.every(cell => {
                                const item = cell.getBoundingClientRect();
                                const bounds = scroller.getBoundingClientRect();
                                return item.left >= bounds.left - 0.5 &&
                                  item.right <= bounds.right + 0.5;
                              }),
                            };
                          })()
                        """,
                        "returnByValue": True,
                    },
                    session_id=session_id,
                )["result"]["value"]
            finally:
                devtools.close()

        self.assertLessEqual(result["overflow"], 0, result)
        self.assertTrue(result["cellsInside"], result)

    def test_library_form_shows_only_the_selected_source_fields(self) -> None:
        # Removing the library form controller exposes incompatible local and
        # network fields together and submits irrelevant required controls.
        evaluation = self._library_form_evaluation(
            """
              (() => {
                const form = document.querySelector('[data-library-form]');
                const local = form.querySelector(
                  '[data-library-source-panel="configured_path"]'
                );
                const network = form.querySelector(
                  '[data-library-source-panel="managed_share"]'
                );
                const localInput = form.querySelector('[name="source_root"]');
                const shareSelect = form.querySelector('[name="share_id"]');
                const initial = {
                  localHidden: local.hidden,
                  networkHidden: network.hidden,
                  localRequired: localInput.required,
                  shareRequired: shareSelect.required,
                };
                form.querySelector(
                  '[name="source_kind"][value="managed_share"]'
                ).click();
                const selected = {
                  localHidden: local.hidden,
                  networkHidden: network.hidden,
                  localRequired: localInput.required,
                  shareRequired: shareSelect.required,
                };
                return {initial, selected};
              })()
            """
        )

        self.assertNotIn("exceptionDetails", evaluation, evaluation)
        self.assertEqual(
            {
                "initial": {
                    "localHidden": False,
                    "networkHidden": True,
                    "localRequired": True,
                    "shareRequired": False,
                },
                "selected": {
                    "localHidden": True,
                    "networkHidden": False,
                    "localRequired": False,
                    "shareRequired": True,
                },
            },
            evaluation["result"]["value"],
        )

    def test_library_form_keeps_both_source_modes_usable_without_javascript(
        self,
    ) -> None:
        # Server-rendered fallback must not trap a no-JavaScript administrator
        # in whichever source mode happened to be selected on page load.
        evaluation = self._library_form_evaluation(
            """
              (() => {
                const form = document.querySelector('[data-library-form]');
                const local = form.querySelector(
                  '[data-library-source-panel="configured_path"]'
                );
                const network = form.querySelector(
                  '[data-library-source-panel="managed_share"]'
                );
                const advanced = form.querySelector('.advanced-fields');
                const identifier = form.querySelector('[name="library_id"]');
                const visible = element => getComputedStyle(element).display !== 'none';
                return {
                  localVisible: visible(local),
                  networkVisible: visible(network),
                  localRequired: form.querySelector('[name="source_root"]').required,
                  shareRequired: form.querySelector('[name="share_id"]').required,
                  advancedOpen: advanced.open,
                  identifierVisible: visible(identifier),
                };
              })()
            """,
            javascript=False,
        )

        self.assertNotIn("exceptionDetails", evaluation, evaluation)
        self.assertEqual(
            {
                "localVisible": True,
                "networkVisible": True,
                "localRequired": False,
                "shareRequired": False,
                "advancedOpen": True,
                "identifierVisible": True,
            },
            evaluation["result"]["value"],
        )

    def test_library_form_proposes_an_editable_identifier_from_the_name(self) -> None:
        # Removing identifier suggestion forces users to understand an internal
        # key before they can configure their first library.
        evaluation = self._library_form_evaluation(
            """
              (() => {
                const form = document.querySelector('[data-library-form]');
                const name = form.querySelector('[name="display_name"]');
                const identifier = form.querySelector('[name="library_id"]');
                name.value = 'Film e città 2026';
                name.dispatchEvent(new Event('input', {bubbles: true}));
                const proposed = identifier.value;
                identifier.value = 'ARCHIVIO-CUSTOM';
                identifier.dispatchEvent(new Event('input', {bubbles: true}));
                name.value = 'Name cambiato';
                name.dispatchEvent(new Event('input', {bubbles: true}));
                return {proposed, afterManualEdit: identifier.value};
              })()
            """
        )

        self.assertNotIn("exceptionDetails", evaluation, evaluation)
        self.assertEqual(
            {
                "proposed": "FILM-E-CITTA-2026",
                "afterManualEdit": "ARCHIVIO-CUSTOM",
            },
            evaluation["result"]["value"],
        )

    def test_job_plan_capacity_cards_do_not_overflow_supported_viewports(
        self,
    ) -> None:
        page = self.client.get("/jobs/plans/PLAN-1")
        self.assertEqual(200, page.status_code, page.text)
        matrix = ((1280, 720), (800, 600), (390, 844), (320, 568))
        with tempfile.TemporaryDirectory(
            prefix="lto-web-job-capacity-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            fixture = self._fixture(test_dir, "job-plan-capacity", page.text)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                for width, height in matrix:
                    with self.subTest(width=width, height=height):
                        ChromiumLayoutTests._navigate_fixture(
                            self,
                            devtools,
                            session_id,
                            fixture,
                            width=width,
                            height=height,
                            device_scale_factor=1,
                        )
                        evaluation = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": ChromiumLayoutTests._layout_expression(),
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )
                        self.assertNotIn("exceptionDetails", evaluation, evaluation)
                        result = evaluation["result"]["value"]
                        self.assertLessEqual(result["documentOverflow"], 0, result)
                        self.assertTrue(result["formsInBounds"], result)
                        self.assertEqual(1, result["h1Count"], result)
                        capacity = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": """
                                  (() => {
                                    const cards = [...document.querySelectorAll(
                                      '.capacity-card'
                                    )];
                                    return {
                                      count: cards.length,
                                      inBounds: cards.every(card => {
                                        const bounds = card.getBoundingClientRect();
                                        return bounds.left >= 0 &&
                                          bounds.right <= innerWidth &&
                                          card.scrollWidth <= card.clientWidth;
                                      }),
                                    };
                                  })()
                                """,
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )["result"]["value"]
                        self.assertGreater(capacity["count"], 0, capacity)
                        self.assertTrue(capacity["inBounds"], capacity)
            finally:
                devtools.close()

    def test_restore_runtime_layout_is_bounded_on_phone_tablet_and_desktop(self) -> None:
        run = _restore_run(conflict=True)
        telemetry = render_telemetry(
            (
                TelemetrySampleV1(
                    event_id=1,
                    occurred_at="2026-08-31T18:18:00Z",
                    mib_per_second=123.5,
                ),
            ),
            effective_rate=98.25,
        )
        restore_surface = Environment(
            loader=FileSystemLoader("src/ltobackup/web/templates"),
            autoescape=True,
        ).get_template("partials/restore_status.html").render(
            run=run,
            current_cassette=run.cassettes[0],
            current_rate="123.50 MiB/s",
            current_rate_value=123.5,
            effective_rate="98.25 MiB/s",
            effective_rate_value=98.25,
            phase="Recovery required",
            bytes_progress="0 B / 1.00 KiB",
            recent_admin=True,
            csrf="csrf-token",
            new_idempotency_key=lambda: "idempotency-key",
            telemetry_html=telemetry,
            refresh_mode="waiting",
        )
        html = (
            '<!doctype html><html lang="en"><head><meta name="viewport" '
            'content="width=device-width, initial-scale=1"><link rel="stylesheet" '
            'href="/static/app.css"></head><body>'
            f'<main class="page-shell">{restore_surface}</main></body></html>'
        )
        with tempfile.TemporaryDirectory(prefix="lto-web-restore-static-") as directory:
            test_dir = Path(directory)
            fixture = self._fixture(test_dir, "restore-runtime", html)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                # Keep identity bounds independent of the host's default font.
                for width, height, font in (
                    (390, 844, None), (768, 900, None), (1280, 720, None),
                    (390, 844, '"DejaVu Sans", sans-serif'),
                    (768, 900, '"DejaVu Sans", sans-serif'),
                    (1280, 720, '"DejaVu Sans", sans-serif'),
                ):
                    with self.subTest(width=width, font=font):
                        ChromiumLayoutTests._navigate_fixture(
                            self,
                            devtools,
                            session_id,
                            fixture,
                            width=width,
                            height=height,
                        )
                        if font is not None:
                            devtools.request(
                                "Runtime.evaluate",
                                {"expression": (
                                    "document.documentElement.style.fontFamily = "
                                    + json.dumps(font)
                                )},
                                session_id=session_id,
                            )
                        result = devtools.request(
                            "Runtime.evaluate",
                            {"expression": """(() => {
                              const head = document.querySelector('.restore-status-head');
                              const chart = document.querySelector('.telemetry-chart');
                              const controls = [...document.querySelectorAll('.restore-actions button, .restore-conflict button')];
                              const identity = [...document.querySelectorAll('[data-label="Label"], [data-label="Destination"]')];
                              const cassette = document.querySelector('.cassette-callout');
                              const bounded = element => { const rect = element.getBoundingClientRect(); const style = getComputedStyle(element); return rect.width > 0 && rect.height > 0 && rect.left >= 0 && rect.right <= innerWidth && style.display !== 'none' && style.visibility !== 'hidden'; };
                              const overlaps = (a, b) => { const left = a.getBoundingClientRect(); const right = b.getBoundingClientRect(); return left.left < right.right && left.right > right.left && left.top < right.bottom && left.bottom > right.top; };
                              return {
                                overflow: document.documentElement.scrollWidth - innerWidth,
                                columns: getComputedStyle(head).gridTemplateColumns.split(' ').length,
                                chartRight: chart.getBoundingClientRect().right,
                                chartWidth: chart.getBoundingClientRect().width,
                                controlCount: controls.length,
                                controlsBounded: controls.every(bounded),
                                controlsOverlap: controls.some((control, index) => controls.slice(index + 1).some(other => overlaps(control, other))),
                                cassetteBounded: bounded(cassette),
                                identityCount: identity.length,
                                identityBounded: identity.every(bounded),
                                overflowingIdentity: identity.filter(element => !bounded(element))
                                  .map(element => ({label: element.dataset.label,
                                    bounds: element.getBoundingClientRect().toJSON(),
                                    tableWidth: element.closest('table').getBoundingClientRect().width})),
                                overflowElements: [...document.querySelectorAll('*')]
                                  .filter(element => element.getBoundingClientRect().right > innerWidth)
                                  .map(element => `${element.tagName}.${element.className}`)
                                  .slice(0, 10),
                              };
                            })()""", "returnByValue": True},
                            session_id=session_id,
                        )["result"]["value"]
                        self.assertLessEqual(result["overflow"], 0, result)
                        self.assertLessEqual(result["chartRight"], width, result)
                        self.assertGreater(result["chartWidth"], 0, result)
                        self.assertEqual(1 if width == 390 else 2, result["columns"], result)
                        self.assertGreaterEqual(result["controlCount"], 2, result)
                        self.assertTrue(result["controlsBounded"], result)
                        self.assertFalse(result["controlsOverlap"], result)
                        self.assertTrue(result["cassetteBounded"], result)
                        self.assertGreaterEqual(result["identityCount"], 2, result)
                        self.assertTrue(result["identityBounded"], result)
                        if width == 390:
                            accessibility = devtools.request(
                                "Accessibility.getFullAXTree",
                                session_id=session_id,
                            )
                            accessible_tables = {
                                node.get("name", {}).get("value")
                                for node in accessibility["nodes"]
                                if node.get("role", {}).get("value") == "table"
                            }
                            self.assertIn(
                                "Exact authoritative rate values",
                                accessible_tables,
                                accessible_tables,
                            )
            finally:
                devtools.close()

    def test_every_visible_management_content_link_and_action_is_at_least_44px(
        self,
    ) -> None:
        # Removing the content-link target rule makes table links, pagination,
        # job cursors and the New estimate recovery link shorter than 44px.
        self.daemon.plan = self.daemon.plan.model_copy(update={"state": "failed"})
        pages = {
            "libraries": self.client.get("/libraries"),
            "shares": self.client.get("/shares"),
            "share-detail": self.client.get("/shares/smb-media"),
            "jobs": self.client.get("/jobs"),
            "job-detail": self.client.get("/jobs/JOB-1"),
            "job-plan": self.client.get("/jobs/plans/PLAN-1"),
        }
        for page in pages.values():
            self.assertEqual(200, page.status_code, page.text)

        with tempfile.TemporaryDirectory(
            prefix="lto-web-content-targets-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            fixtures = {
                name: self._fixture(test_dir, name, page.text)
                for name, page in pages.items()
            }
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                for width, height in ((1280, 720), (390, 844), (320, 568)):
                    for name, html_path in fixtures.items():
                        with self.subTest(page=name, width=width, height=height):
                            ChromiumLayoutTests._navigate_fixture(
                                self,
                                devtools,
                                session_id,
                                html_path,
                                width=width,
                                height=height,
                            )
                            evaluation = devtools.request(
                                "Runtime.evaluate",
                                {
                                    "expression": """
                                      (() => [...document.querySelectorAll(
                                        'main.page-shell a[href], main.page-shell button'
                                      )].filter(element => {
                                        const rect = element.getBoundingClientRect();
                                        const style = getComputedStyle(element);
                                        return rect.width > 0 && rect.height > 0 &&
                                          style.display !== 'none' &&
                                          style.visibility !== 'hidden';
                                      }).map(element => ({
                                        label: element.textContent.trim(),
                                        width: element.getBoundingClientRect().width,
                                        height: element.getBoundingClientRect().height,
                                      })))()
                                    """,
                                    "returnByValue": True,
                                },
                                session_id=session_id,
                            )
                            self.assertNotIn("exceptionDetails", evaluation, evaluation)
                            targets = evaluation["result"]["value"]
                            self.assertTrue(targets, (name, targets))
                            undersized = [
                                target
                                for target in targets
                                if target["width"] < 44 or target["height"] < 44
                            ]
                            self.assertEqual([], undersized)
            finally:
                devtools.close()

    def test_management_route_matrix_has_no_overflow_and_accessible_controls(
        self,
    ) -> None:
        restore_plan = self.daemon.create_catalog_restore_plan(
            CreateCatalogRestorePlanRequestV1(
                file_version_ids=(42,), destination_root="/srv/restore"
            ),
            "layout-restore-1",
            principal="web-user-1",
            role="operator",
        )
        pages = {
            "libraries": self.client.get("/libraries"),
            "library-detail": self.client.get("/libraries/PHOTOS"),
            "shares": self.client.get("/shares"),
            "share-new": self.client.get("/shares/new?protocol=nfs"),
            "jobs": self.client.get("/jobs"),
            "job-new": self.client.get("/jobs/new"),
            "job-detail": self.client.get("/jobs/JOB-1"),
            "job-plan": self.client.get("/jobs/plans/PLAN-1"),
            "settings": self.client.get("/settings"),
            "users": self.client.get("/users"),
            "account": self.client.get("/account"),
            "catalog": self.client.get("/catalog?q=example"),
            "catalog-detail": self.client.get("/catalog/file-versions/42"),
            "restore-plan": self.client.get(f"/restore-plans/{restore_plan.id}"),
        }
        restore_plan.identity_state = "legacy_invalid"
        restore_plan.invalidation_reason = "legacy_physical_identity_ambiguous"
        restore_plan.cassettes[0].physical_label = None
        restore_plan.items[0].physical_label = None
        invalid_restore = self.client.get(f"/restore-plans/{restore_plan.id}")
        self.assertIn(
            'data-error-code="legacy_physical_identity_ambiguous"',
            invalid_restore.text,
        )
        pages["restore-plan-invalid"] = invalid_restore
        self.daemon.failure = DaemonUnavailable()
        degraded = self.client.get("/catalog")
        self.daemon.failure = None
        self.assertEqual(503, degraded.status_code, degraded.text)
        pages["catalog-degraded"] = degraded
        catalog_page = pages["catalog"]
        csrf = re.search(r'name="csrf" value="([A-Za-z0-9_-]+)"', catalog_page.text)
        idempotency_key = re.search(
            r'name="idempotency_key" value="([A-Za-z0-9_-]+)"',
            catalog_page.text,
        )
        assert csrf is not None
        assert idempotency_key is not None
        self.daemon.mutation_failure = DaemonUnavailable()
        retry = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": csrf.group(1),
                "idempotency_key": idempotency_key.group(1),
                "destination_root": "/srv/restore",
                "file_version_ids": ["42", "41"],
            },
        )
        self.daemon.mutation_failure = None
        self.assertEqual(503, retry.status_code, retry.text)
        pages["restore-plan-ambiguous"] = retry
        allowed_user_data = {
            "libraries": ("Foto <famiglia>", "Video"),
            "library-detail": ("Foto <famiglia>",),
            "shares": ("SMB media", "NFS media"),
            "share-new": (),
            "jobs": ("Backup foto",),
            "job-new": ("Foto <famiglia>", "Video"),
            "job-detail": ("Backup foto", "album/foto.jpg"),
            "job-plan": (),
            "settings": (),
            "users": ("admin",),
            "account": ("admin",),
            "catalog": ("Foto <famiglia>", "Backup foto"),
            "catalog-detail": ("Foto <famiglia>", "Backup foto"),
            "restore-plan": (),
            "restore-plan-invalid": (),
            "catalog-degraded": (),
            "restore-plan-ambiguous": ("Foto <famiglia>", "Backup foto"),
        }
        self.assertEqual(set(pages), set(allowed_user_data))
        for name, page in pages.items():
            with self.subTest(page=name, surface="English copy"):
                self.assertIn(page.status_code, (200, 503), page.text)
                assert_english_document(
                    self,
                    page.text,
                    allowed_data=allowed_user_data[name],
                )

        matrix = (
            (1280, 720),
            (1024, 768),
            (800, 600),
            (390, 844),
            (320, 568),
        )
        with tempfile.TemporaryDirectory(
            prefix="lto-web-route-matrix-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            fixtures = {
                name: self._fixture(test_dir, name, page.text)
                for name, page in pages.items()
            }
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                for name, fixture in fixtures.items():
                    for width, height in matrix:
                        with self.subTest(page=name, width=width, height=height):
                            ChromiumLayoutTests._navigate_fixture(
                                self,
                                devtools,
                                session_id,
                                fixture,
                                width=width,
                                height=height,
                            )
                            evaluation = devtools.request(
                                "Runtime.evaluate",
                                {
                                    "expression": """
                                      (() => {
                                        const visible = element => {
                                          const rect = element.getBoundingClientRect();
                                          const style = getComputedStyle(element);
                                          return rect.width > 0 && rect.height > 0 &&
                                            style.display !== 'none' &&
                                            style.visibility !== 'hidden';
                                        };
                                        const controls = [...document.querySelectorAll(
                                          'input:not([type=hidden]), select, textarea'
                                        )].filter(visible);
                                        const associated = control => {
                                          if (control.getAttribute('aria-label') ||
                                              control.getAttribute('aria-labelledby')) {
                                            return true;
                                          }
                                          if (control.closest('label')) return true;
                                          return control.id && document.querySelector(
                                            `label[for="${CSS.escape(control.id)}"]`
                                          );
                                        };
                                        const errors = [...document.querySelectorAll(
                                          '[data-field-error]'
                                        )];
                                        const errorAssociated = error =>
                                          [...document.querySelectorAll(
                                            '[aria-errormessage]'
                                          )].some(control => control.getAttribute(
                                            'aria-errormessage'
                                          ).split(/\\s+/).includes(error.id));
                                        const interactive = [
                                          ...document.querySelectorAll(
                                            'a[href], button, input:not([type=hidden]), ' +
                                            'select, textarea'
                                          )
                                        ].filter(visible);
                                        const layout = """
                                    + ChromiumLayoutTests._layout_expression()
                                    + """;
                                        return {
                                          overflow: document.documentElement.scrollWidth -
                                            document.documentElement.clientWidth,
                                          controlsAssociated: controls.every(associated),
                                          errorsAssociated: errors.every(errorAssociated),
                                          interactiveTabbable: interactive.every(
                                            element => !element.disabled && element.tabIndex >= 0
                                          ),
                                          toolbarOverlaps: layout.toolbarOverlaps,
                                          dangerInsidePrimary: layout.dangerInsidePrimary,
                                          formsInBounds: layout.formsInBounds,
                                          h1Count: layout.h1Count,
                                        };
                                      })()
                                    """,
                                    "returnByValue": True,
                                },
                                session_id=session_id,
                            )
                            self.assertNotIn("exceptionDetails", evaluation, evaluation)
                            result = evaluation["result"]["value"]
                            self.assertLessEqual(result["overflow"], 0, result)
                            self.assertTrue(result["controlsAssociated"], result)
                            self.assertTrue(result["errorsAssociated"], result)
                            self.assertTrue(result["interactiveTabbable"], result)
                            self.assertTrue(result["formsInBounds"], result)
                            self.assertEqual(0, result["toolbarOverlaps"], result)
                            self.assertEqual(0, result["dangerInsidePrimary"], result)
                            self.assertEqual(1, result["h1Count"], result)

                    ChromiumLayoutTests._navigate_fixture(
                        self,
                        devtools,
                        session_id,
                        fixture,
                        width=1280,
                        height=720,
                    )
                    devtools.request(
                        "Runtime.evaluate",
                        {"expression": "document.documentElement.style.zoom = '2'"},
                        session_id=session_id,
                    )
                    zoomed = devtools.request(
                        "Runtime.evaluate",
                        {
                            "expression": (
                                "(() => ({zoom: getComputedStyle("
                                "document.documentElement).zoom, "
                                "layout: "
                                + ChromiumLayoutTests._layout_expression()
                                + "}))()"
                            ),
                            "returnByValue": True,
                        },
                        session_id=session_id,
                    )["result"]["value"]
                    with self.subTest(page=name, zoom="200%"):
                        self.assertEqual("2", zoomed["zoom"], zoomed)
                        self.assertLessEqual(
                            zoomed["layout"]["documentOverflow"], 0, zoomed
                        )
                        self.assertTrue(zoomed["layout"]["formsInBounds"], zoomed)
            finally:
                devtools.close()

    def test_share_detail_reflows_across_the_normative_viewport_matrix(self) -> None:
        page = self.client.get("/shares/smb-media")
        self.assertEqual(200, page.status_code, page.text)
        matrix = (
            (1280, 720, 1),
            (1024, 768, 1),
            (800, 600, 1),
            (390, 844, 1),
            (320, 568, 1),
            (640, 360, 2),
        )
        with tempfile.TemporaryDirectory(
            prefix="lto-web-share-matrix-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = self._fixture(test_dir, "share-detail", page.text)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                for width, height, scale in matrix:
                    with self.subTest(width=width, height=height, scale=scale):
                        ChromiumLayoutTests._navigate_fixture(
                            self,
                            devtools,
                            session_id,
                            html_path,
                            width=width,
                            height=height,
                            device_scale_factor=scale,
                        )
                        evaluation = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": ChromiumLayoutTests._layout_expression(),
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )
                        self.assertNotIn("exceptionDetails", evaluation, evaluation)
                        result = evaluation["result"]["value"]
                        self.assertLessEqual(result["documentOverflow"], 0, result)
                        self.assertTrue(result["formsInBounds"], result)
                        self.assertEqual(0, result["toolbarOverlaps"], result)
                        self.assertEqual(0, result["dangerInsidePrimary"], result)
                        self.assertGreaterEqual(
                            result["minimumTargetWidth"], 44, result
                        )
                        self.assertGreaterEqual(
                            result["minimumTargetHeight"], 44, result
                        )
                        self.assertEqual(1, result["h1Count"], result)
                        live_region = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": "document.querySelectorAll('[aria-live=polite]').length",
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )
                        self.assertGreaterEqual(live_region["result"]["value"], 1)
            finally:
                devtools.close()

    def test_share_detail_reflows_at_true_200_percent_page_zoom(self) -> None:
        page = self.client.get("/shares/smb-media")
        self.assertEqual(200, page.status_code, page.text)
        with tempfile.TemporaryDirectory(
            prefix="lto-web-share-zoom-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = self._fixture(test_dir, "share-detail-zoom", page.text)
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                ChromiumLayoutTests._navigate_fixture(
                    self,
                    devtools,
                    session_id,
                    html_path,
                    width=1280,
                    height=720,
                    device_scale_factor=1,
                )
                devtools.request(
                    "Runtime.evaluate",
                    {"expression": "document.documentElement.style.zoom = '2'"},
                    session_id=session_id,
                )
                evaluation = devtools.request(
                    "Runtime.evaluate",
                    {
                        "expression": (
                            "(() => ({zoom: getComputedStyle(document.documentElement).zoom, "
                            "dpr: devicePixelRatio, layout: "
                            + ChromiumLayoutTests._layout_expression()
                            + "}))()"
                        ),
                        "returnByValue": True,
                    },
                    session_id=session_id,
                )
            finally:
                devtools.close()

        self.assertNotIn("exceptionDetails", evaluation, evaluation)
        result = evaluation["result"]["value"]
        self.assertEqual("2", result["zoom"], result)
        self.assertEqual(1, result["dpr"], result)
        layout = result["layout"]
        self.assertLessEqual(layout["documentOverflow"], 0, layout)
        self.assertTrue(layout["formsInBounds"], layout)
        self.assertEqual(0, layout["toolbarOverlaps"], layout)
        self.assertEqual(0, layout["dangerInsidePrimary"], layout)
        self.assertEqual(1, layout["h1Count"], layout)

    def test_no_javascript_protocol_preview_reflows_in_both_directions(self) -> None:
        nfs_initial = self.client.get("/shares/nfs-media")
        self.assertEqual(200, nfs_initial.status_code, nfs_initial.text)
        nfs_csrf = re.search(r'name="csrf" value="([^"]+)"', nfs_initial.text)
        assert nfs_csrf is not None
        nfs_to_smb = self.client.post(
            "/shares/nfs-media/update-preview",
            data={
                "csrf": nfs_csrf.group(1),
                "expected_revision": "4",
                "display_name": "NFS media",
                "protocol": "smb",
                "server": "secret-nfs.example",
                "remote_resource": "/private/export",
                "nfs_version": "4.2",
                "timeout_seconds": "60",
                "retransmissions": "2",
                "lifecycle": "active",
            },
        )
        self.assertEqual(200, nfs_to_smb.status_code, nfs_to_smb.text)

        self.daemon.shares = (
            self.daemon.shares[0].model_copy(
                update={
                    "desired_state": "disconnected",
                    "observed_state": "disconnected",
                    "mount_identity_sha256": None,
                    "mounted_config_revision": None,
                    "mounted_credential_generation": None,
                }
            ),
            self.daemon.shares[1],
        )
        smb_initial = self.client.get("/shares/smb-media")
        self.assertEqual(200, smb_initial.status_code, smb_initial.text)
        smb_csrf = re.search(r'name="csrf" value="([^"]+)"', smb_initial.text)
        assert smb_csrf is not None
        smb_to_nfs = self.client.post(
            "/shares/smb-media/update-preview",
            data={
                "csrf": smb_csrf.group(1),
                "expected_revision": "4",
                "display_name": "SMB media",
                "protocol": "nfs",
                "server": "secret-nas.example",
                "remote_resource": "private-media",
                "dialect": "3.1.1",
                "lifecycle": "active",
            },
        )
        self.assertEqual(200, smb_to_nfs.status_code, smb_to_nfs.text)
        self.assertFalse(self.daemon.calls)

        pages = {
            "nfs-initial": (nfs_initial, "update-preview", "nfs"),
            "smb-preview": (nfs_to_smb, "update", "smb"),
            "smb-initial": (smb_initial, "update-preview", "smb"),
            "nfs-preview": (smb_to_nfs, "update", "nfs"),
        }
        with tempfile.TemporaryDirectory(
            prefix="lto-web-share-no-js-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            fixtures = {
                name: self._fixture(test_dir, name, page.text)
                for name, (page, _action, _protocol) in pages.items()
            }
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                for name, (_page, action, protocol) in pages.items():
                    with self.subTest(page=name):
                        ChromiumLayoutTests._navigate_fixture(
                            self,
                            devtools,
                            session_id,
                            fixtures[name],
                            width=390,
                            height=844,
                        )
                        evaluation = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": f"""
                                  (() => {{
                                    const form = [...document.forms].find(candidate =>
                                      candidate.action.endsWith('/{action}'));
                                    const names = [...form.elements].map(element => element.name);
                                    return {{
                                      scriptCount: document.scripts.length,
                                      protocol: form.elements.protocol.value,
                                      hasNfs: names.includes('nfs_version') &&
                                        names.includes('timeout_seconds') &&
                                        names.includes('retransmissions'),
                                      hasSmb: names.includes('dialect'),
                                      layout: {ChromiumLayoutTests._layout_expression()},
                                    }};
                                  }})()
                                """,
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )
                        self.assertNotIn("exceptionDetails", evaluation, evaluation)
                        result = evaluation["result"]["value"]
                        self.assertEqual(0, result["scriptCount"], result)
                        self.assertEqual(protocol, result["protocol"], result)
                        self.assertEqual(protocol == "nfs", result["hasNfs"], result)
                        self.assertEqual(protocol == "smb", result["hasSmb"], result)
                        self.assertLessEqual(
                            result["layout"]["documentOverflow"], 0, result
                        )
                        self.assertTrue(result["layout"]["formsInBounds"], result)
                        self.assertGreaterEqual(
                            result["layout"]["minimumTargetHeight"], 44, result
                        )
                        self.assertEqual(1, result["layout"]["h1Count"], result)
            finally:
                devtools.close()


@unittest.skipUnless(_CHROMIUM, "Chromium is required for the 1280x720 layout gate")
class ChromiumRuntimeDiagnosticsLayoutTests(WebAppTestCase):
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

    def test_diagnostics_1280x720_keeps_runtime_values_and_stale_banner_in_bounds(
        self,
    ) -> None:
        self.login()
        page = self.client.get("/diagnostics")

        with tempfile.TemporaryDirectory(
            prefix="lto-web-diagnostics-layout-",
            dir=Path.home(),
        ) as directory:
            test_dir = Path(directory)
            html_path = test_dir / "diagnostics.html"
            css_path = test_dir / "app.css"
            shutil.copyfile("src/ltobackup/web/static/app.css", css_path)
            html = _fixture_assets(page.text, css_path.as_uri())
            html_path.write_text(html, encoding="utf-8")

            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                target_id = devtools.request(
                    "Target.createTarget", {"url": "about:blank"}
                )["targetId"]
                session_id = devtools.request(
                    "Target.attachToTarget",
                    {"targetId": target_id, "flatten": True},
                )["sessionId"]
                devtools.request("Page.enable", session_id=session_id)
                devtools.request(
                    "Page.setLifecycleEventsEnabled",
                    {"enabled": True},
                    session_id=session_id,
                )
                devtools.request(
                    "Emulation.setDeviceMetricsOverride",
                    {
                        "width": 1280,
                        "height": 720,
                        "deviceScaleFactor": 1,
                        "mobile": False,
                        "screenWidth": 1280,
                        "screenHeight": 720,
                    },
                    session_id=session_id,
                )
                navigation = devtools.request(
                    "Page.navigate",
                    {"url": html_path.as_uri()},
                    session_id=session_id,
                )
                self.assertNotIn("errorText", navigation, navigation)
                loader_id = navigation["loaderId"]
                devtools.wait_for_event(
                    "Page.lifecycleEvent",
                    session_id=session_id,
                    matches=lambda event: (
                        event.get("name") == "load"
                        and event.get("loaderId") == loader_id
                    ),
                )
                evaluation = devtools.request(
                    "Runtime.evaluate",
                    {
                        "expression": """
                          (() => {
                            const visible = element => {
                              const rect = element.getBoundingClientRect();
                              const style = getComputedStyle(element);
                              return rect.width > 0 && rect.height > 0 &&
                                rect.top >= 0 && rect.left >= 0 &&
                                rect.bottom <= innerHeight && rect.right <= innerWidth &&
                                style.display !== "none" && style.visibility !== "hidden";
                            };
                            const timings = [...document.querySelectorAll(
                              ".diagnostics-timing-grid > div"
                            )].map(row => ({
                              label: row.querySelector("dt").textContent.trim(),
                              value: row.querySelector("dd").textContent.trim(),
                              visible: visible(row.querySelector("dt")) &&
                                visible(row.querySelector("dd")),
                            }));
                            const banner = document.querySelector("#connection-banner");
                            const exportLink = document.querySelector(
                              'a[href="/diagnostics/export"]'
                            );
                            banner.hidden = false;
                            return {
                              viewport: [innerWidth, innerHeight],
                              documentHeight: document.documentElement.scrollHeight,
                              summaryVisible: visible(document.querySelector(
                                "#diagnostics-runtime-summary"
                              )),
                              exportVisible: visible(exportLink),
                              exportRect: exportLink.getBoundingClientRect().toJSON(),
                              banner: {
                                hidden: banner.hidden,
                                text: banner.textContent.trim(),
                                visible: visible(banner),
                                rect: banner.getBoundingClientRect().toJSON(),
                              },
                              timings,
                            };
                          })()
                        """,
                        "returnByValue": True,
                    },
                    session_id=session_id,
                )
            finally:
                devtools.close()

        self.assertNotIn("exceptionDetails", evaluation, evaluation)
        result = evaluation["result"]["value"]
        self.assertEqual([1280, 720], result["viewport"])
        self.assertLessEqual(result["documentHeight"], 720, result)
        self.assertTrue(result["summaryVisible"], result)
        self.assertTrue(result["exportVisible"], result)
        self.assertGreaterEqual(result["exportRect"]["width"], 44, result)
        self.assertGreaterEqual(result["exportRect"]["height"], 44, result)
        self.assertFalse(result["banner"]["hidden"])
        self.assertIn("runtime data may be stale", result["banner"]["text"])
        self.assertTrue(result["banner"]["visible"], result)
        banner_rect = result["banner"]["rect"]
        self.assertGreater(banner_rect["width"], 0, result)
        self.assertGreater(banner_rect["height"], 0, result)
        self.assertGreaterEqual(banner_rect["left"], 0, result)
        self.assertGreaterEqual(banner_rect["top"], 0, result)
        self.assertLessEqual(banner_rect["right"], 1280, result)
        self.assertLessEqual(banner_rect["bottom"], 720, result)
        self.assertEqual(12, len(result["timings"]))
        self.assertTrue(all(row["visible"] for row in result["timings"]), result)

@unittest.skipUnless(_CHROMIUM, "Chromium is required for the operational log layout gate")
class OperationalLogLayoutTests(LiveWebAppTestCase):
    def test_operational_log_is_accessible_and_bounded_at_supported_widths(self) -> None:
        entry = self.daemon.system_logs.items[0].model_copy(
            update={"message": "W" * 4096}
        )
        self.daemon.system_logs = self.daemon.system_logs.model_copy(
            update={"items": (entry,)}
        )
        self.login()
        page = self.client.get("/logs")
        self.assertEqual(200, page.status_code, page.text)

        with tempfile.TemporaryDirectory(
            prefix="lto-web-log-layout-", dir=Path.home()
        ) as directory:
            test_dir = Path(directory)
            html_path = test_dir / "logs.html"
            css_path = test_dir / "app.css"
            shutil.copyfile("src/ltobackup/web/static/app.css", css_path)
            html = _fixture_assets(page.text, css_path.as_uri())
            html_path.write_text(html, encoding="utf-8")
            devtools = _DevToolsPipe(str(_CHROMIUM), test_dir / "profile")
            try:
                session_id = ChromiumLayoutTests._attach_page(devtools)
                for width, height in ((390, 844), (768, 900), (1280, 720)):
                    with self.subTest(width=width):
                        ChromiumLayoutTests._navigate_fixture(
                            self, devtools, session_id, html_path, width=width, height=height
                        )
                        evaluation = devtools.request(
                            "Runtime.evaluate",
                            {
                                "expression": """
                                  (() => {
                                    const controls = [...document.querySelectorAll(
                                      '.logs-filter-panel select, .logs-filter-panel input, .logs-filter-panel button'
                                    )];
                                    const overlaps = controls.some((control, index) => {
                                      const a = control.getBoundingClientRect();
                                      return controls.slice(index + 1).some(other => {
                                        const b = other.getBoundingClientRect();
                                        return a.left < b.right && a.right > b.left &&
                                          a.top < b.bottom && a.bottom > b.top;
                                      });
                                    });
                                    const row = document.querySelector('.operational-log-row');
                                    const rowBounds = row.getBoundingClientRect();
                                    const message = document.querySelector('.log-message');
                                    const details = document.querySelector('.log-details');
                                    const primary = document.querySelector('.log-row-primary');
                                    return {
                                      documentOverflow: document.documentElement.scrollWidth -
                                        document.documentElement.clientWidth,
                                      overlaps,
                                      controlsNamed: controls.every(control =>
                                        control.labels?.length || control.textContent.trim()
                                      ),
                                      listName: document.querySelector('[data-log-list]').getAttribute('aria-label'),
                                      paginationFocusable: [...document.querySelectorAll('.logs-pagination a')]
                                        .every(link => link.tabIndex >= 0),
                                      followFocusable: document.querySelector('[data-log-follow]').tabIndex >= 0,
                                      severityText: document.querySelector('.log-severity').textContent.trim(),
                                      sourceText: document.querySelector('.log-source').textContent.trim(),
                                      messageWrapped: message.scrollWidth <= message.clientWidth + 1,
                                      detailsBounded: details.getBoundingClientRect().right <= rowBounds.right + 1,
                                      filterDisplay: getComputedStyle(document.querySelector('.logs-filter-panel')).display,
                                      primaryDisplay: getComputedStyle(primary).display,
                                      primaryColumns: getComputedStyle(primary).gridTemplateColumns,
                                      phoneSourceLabel: getComputedStyle(
                                        document.querySelector('.log-source'), '::before'
                                      ).content,
                                    };
                                  })()
                                """,
                                "returnByValue": True,
                            },
                            session_id=session_id,
                        )
                        self.assertNotIn("exceptionDetails", evaluation, evaluation)
                        values = evaluation["result"]["value"]
                        self.assertLessEqual(values["documentOverflow"], 0, values)
                        self.assertFalse(values["overlaps"], values)
                        self.assertTrue(values["controlsNamed"], values)
                        self.assertEqual("Operational log entries", values["listName"], values)
                        self.assertTrue(values["paginationFocusable"], values)
                        self.assertTrue(values["followFocusable"], values)
                        self.assertEqual("Warning", values["severityText"], values)
                        self.assertEqual("LTFS / Tape", values["sourceText"], values)
                        self.assertTrue(values["messageWrapped"], values)
                        self.assertTrue(values["detailsBounded"], values)
                        self.assertEqual("grid", values["filterDisplay"], values)
                        self.assertEqual("grid", values["primaryDisplay"], values)
                        if width == 390:
                            self.assertEqual('"Source"', values["phoneSourceLabel"], values)
                        else:
                            self.assertGreaterEqual(
                                len(values["primaryColumns"].split()), 4, values
                            )
            finally:
                devtools.close()


if __name__ == "__main__":
    unittest.main()
