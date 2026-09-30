import unittest

from tests.web import test_layout_chromium as layout


class LayoutFixtureAssetTests(unittest.TestCase):
    def test_static_fixture_localizes_versioned_css_and_removes_app_scripts(self):
        for suffix in ("", "?v=0123456789abcdef"):
            with self.subTest(suffix=suffix):
                source = (
                    f'<link rel="stylesheet" href="/static/app.css{suffix}">'
                    f'<script defer src="/static/htmx.js{suffix}" integrity="hash"></script>'
                    f'<script defer src="/static/live.js{suffix}"></script>'
                )
                result = layout._fixture_assets(source, "file:///tmp/fixture/app.css")
                self.assertEqual('<link rel="stylesheet" href="file:///tmp/fixture/app.css">', result)

    def test_scripted_fixture_localizes_versioned_live_script_and_preserves_other_content(self):
        source = (
            '<link rel="stylesheet" href="/static/app.css?v=0123456789abcdef">'
            '<script defer src="/static/htmx.js"></script>'
            '<script defer src="/static/live.js?v=0123456789abcdef"></script>'
            '<script src="/other.js"></script><p>Keep this content</p>'
        )
        result = layout._fixture_assets(source, "file:///tmp/app.css", "file:///tmp/live.js")
        self.assertEqual(
            '<link rel="stylesheet" href="file:///tmp/app.css">'
            '<script defer src="file:///tmp/live.js"></script>'
            '<script src="/other.js"></script><p>Keep this content</p>', result,
        )
