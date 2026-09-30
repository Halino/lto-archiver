from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

_CHROME = shutil.which("google-chrome-stable") or shutil.which("google-chrome")


@unittest.skipUnless(_CHROME, "Chrome is required for the runtime diagnostics gate")
class LiveRuntimeDiagnosticsBrowserTests(unittest.TestCase):
    def test_sse_patch_refreshes_the_runtime_diagnostic_summary(self) -> None:
        # Removing the diagnostics fragment refresh would leave displayed phase
        # timings stale while the authenticated runtime stream advances.
        with tempfile.TemporaryDirectory(prefix="lto-web-runtime-") as raw:
            root = Path(raw)
            script = Path("src/ltobackup/web/static/live.js").resolve()
            html = root / "runtime.html"
            html.write_text(
                f"""<!doctype html><html><body>
                <section id="diagnostics-runtime-summary">old summary</section>
                <script>
                window.__result = {{fetches: []}};
                window.fetch = url => {{
                  __result.fetches.push(url);
                  return Promise.resolve({{ok: true, text: () => Promise.resolve(
                    '<section id="diagnostics-runtime-summary" data-runtime="fresh">fresh summary</section>'
                  )}});
                }};
                class FakeEventSource {{
                  constructor(url) {{ this.url=url; this.listeners={{}}; window.__stream=this; }}
                  addEventListener(name, listener) {{ this.listeners[name] = listener; }}
                  close() {{}}
                }}
                window.EventSource = FakeEventSource;
                </script>
                <script src="{script.as_uri()}"></script>
                <script>
                window.addEventListener('load', () => {{
                  __stream.listeners['state.patch']({{data: '{{}}'}});
                  setTimeout(() => {{
                    document.documentElement.dataset.result = encodeURIComponent(JSON.stringify({{
                      url: __stream.url,
                      fetches: __result.fetches,
                      refreshed: document.querySelector('#diagnostics-runtime-summary').dataset.runtime
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

        self.assertEqual("/events", result["url"])
        self.assertEqual(["/diagnostics/summary-fragment"], result["fetches"])
        self.assertEqual("fresh", result["refreshed"])


if __name__ == "__main__":
    unittest.main()
