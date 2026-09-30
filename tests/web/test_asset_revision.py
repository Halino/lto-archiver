from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from ltobackup.web.app import WebSettings, create_web_app
from ltobackup.web.auth_store import AuthStore
from tests.web.test_dashboard import FakeDaemonClient


class AssetRevisionTests(unittest.TestCase):
    def test_changed_asset_has_new_url_and_serves_exact_new_content(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ("app.css", "live.js", "htmx.js", "resume.js", "protected-action.js"):
                (root / name).write_text("/* initial fixture */")
            store = AuthStore(root / "auth.db")
            urls = []
            for content in ("body { color: red; }", "body { color: blue; }"):
                (root / "app.css").write_text(content)
                with patch("ltobackup.web.app._STATIC_DIR", root):
                    app = create_web_app(WebSettings(), store, FakeDaemonClient())
                    with TestClient(app) as client:
                        page = client.get("/login")
                        url = re.search(r'href="([^"]*app\.css[^\"]*)"', page.text).group(1)
                        urls.append(url)
                        self.assertEqual(client.get(url).text, content)
            self.assertNotEqual(urls[0], urls[1], "changed CSS must invalidate the browser cache")

    def test_resume_script_change_invalidates_the_shared_asset_revision(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for name in ("app.css", "live.js", "htmx.js", "resume.js", "protected-action.js"):
                (root / name).write_text("/* initial fixture */")
            store = AuthStore(root / "auth.db")
            urls = []
            for content in ("/* first resume dialog */", "/* updated resume dialog */"):
                (root / "resume.js").write_text(content)
                with patch("ltobackup.web.app._STATIC_DIR", root):
                    app = create_web_app(WebSettings(), store, FakeDaemonClient())
                    with TestClient(app) as client:
                        page = client.get("/login")
                        url = re.search(r'href="([^"]*app\.css[^\"]*)"', page.text).group(1)
                        resume_url = url.replace("app.css", "resume.js")
                        urls.append(resume_url)
                        self.assertEqual(content, client.get(resume_url).text)
            self.assertNotEqual(urls[0], urls[1])


if __name__ == "__main__":
    unittest.main()
