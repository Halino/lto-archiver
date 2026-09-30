"""Real browser check of boundary runtime patching and narrow layout."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import unquote

from ltobackup.daemon.api_models import BoundaryRefreshStatusV1
from tests import test_boundary_status

_CHROME = shutil.which("google-chrome-stable") or shutil.which("google-chrome")


@unittest.skipUnless(_CHROME, "Chrome is required for boundary runtime rendering")
class BoundaryStatusBrowserTests(unittest.TestCase):
    def test_live_patch_preserves_panel_and_paused_deficit_in_narrow_layout(self):
        renderer = test_boundary_status.BoundaryStatusRenderingTests()
        queued = renderer.render(BoundaryRefreshStatusV1(
            state="queued", occurred_at="2026-09-12T17:00:00+00:00",
        ))
        paused = renderer.render(BoundaryRefreshStatusV1(
            state="paused", required_additional_labels=3,
            candidate_files=12_345, candidate_bytes=5 * 1024**3 + 512 * 1024**2,
            occurred_at="2026-09-12T17:00:00+00:00",
        ))
        assets = Path("src/ltobackup/web/static").resolve()
        with tempfile.TemporaryDirectory(prefix="lto-boundary-browser-") as raw:
            root = Path(raw)
            page = root / "boundary.html"
            page.write_text(f"""<!doctype html><html><head>
              <link rel="stylesheet" href="{(assets / 'app.css').as_uri()}">
              </head><body><main style="width:360px;max-width:100%;margin:0">{queued}</main>
              <script>
              window.fetch = () => Promise.resolve({{ok:true,text:()=>Promise.resolve({json.dumps(paused)})}});
              window.EventSource = class {{ addEventListener() {{}} close() {{}} }};
              </script><script src="{(assets / 'live.js').as_uri()}"></script>
              <script>
              window.addEventListener('load', async () => {{
                const panel = document.querySelector('[data-job-runtime]');
                const metrics = panel.querySelector('[data-live-key="job-runtime-metrics"]').textContent;
                const patched = await __ltoLiveTestHooks.refreshJobRuntime('JOB1');
                const status = panel.querySelector('[data-live-key="job-boundary-refresh"]');
                const box = status.getBoundingClientRect();
                const outer = panel.getBoundingClientRect();
                document.documentElement.dataset.result = encodeURIComponent(JSON.stringify({{
                  patched, panelRetained: panel === document.querySelector('[data-job-runtime]'),
                  metricsUnchanged: metrics === panel.querySelector('[data-live-key="job-runtime-metrics"]').textContent,
                  text: status.textContent, fits: status.scrollWidth <= status.clientWidth + 1,
                  bounded: box.left >= outer.left && box.right <= outer.right,
                  visible: box.height > 0
                }}));
              }});
              </script></body></html>""", encoding="utf-8")
            result = subprocess.run([
                str(_CHROME), "--headless=new", "--disable-gpu", "--no-sandbox",
                "--disable-dev-shm-usage", f"--user-data-dir={root / 'profile'}",
                "--virtual-time-budget=1000", "--dump-dom", page.as_uri(),
            ], capture_output=True, text=True, check=True, timeout=30)
            match = re.search(r'data-result="([^"]+)"', result.stdout)
            self.assertIsNotNone(match, result.stderr + result.stdout[-1500:])
            observed = json.loads(unquote(match.group(1)))
        for key in ("patched", "panelRetained", "metricsUnchanged", "fits", "bounded", "visible"):
            self.assertTrue(observed[key], observed)
        for text in ("paused with this job", "3 additional labels", "12,345 candidate files", "5.50 GiB"):
            self.assertIn(text, observed["text"])
        self.assertNotIn("is queued", observed["text"])
