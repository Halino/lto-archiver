"""Current public documentation agrees with the packaged release contract."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PublicDocumentationTests(unittest.TestCase):
    def test_current_tuple_matches_package_and_schema(self) -> None:
        spec = (ROOT / "packaging/rpm/lto-archiver.spec").read_text()
        catalog = (ROOT / "src/ltobackup/catalog.py").read_text()
        self.assertRegex(spec, r"(?m)^Version:\s+0\.11\.29$")
        self.assertRegex(spec, r"(?m)^Release:\s+155%")
        self.assertIn("lto-archiver-python-runtime = 0.11.27-3", spec)
        self.assertTrue("lto-ltfs = 0.1.1-22" in spec, "current spec requires driver 22")
        self.assertRegex(catalog, r"(?m)^SCHEMA_VERSION = 41$")
        for relative in ("README.md", "docs/en/index.md", "docs/en/installation.md"):
            with self.subTest(path=relative):
                text = re.sub(
                    r"\s+", " ", (ROOT / relative).read_text().replace("*", "")
                )
                for expected in ("0.11.29-155", "runtime 3", "driver 22", "schema 41"):
                    self.assertIn(expected, text)

    def test_public_support_and_security_do_not_route_to_private_gitlab(self) -> None:
        for relative in ("SUPPORT.md", "SECURITY.md"):
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text()
                self.assertNotRegex(text, r"(?i)(private GitLab|\.gitlab-ci\.yml)")
                self.assertIn("GitHub", text)

    def test_release_process_keeps_publication_separate_from_installation(self) -> None:
        text = (ROOT / "docs/en/release-process.md").read_text()
        self.assertIn("GitHub Releases is a download channel, not a DNF", text)
        self.assertIn("disposable RHEL 9 host", text)
        self.assertIn("final approval", text)

    def test_public_install_manual_does_not_present_historical_runner_as_155_upgrade(self) -> None:
        manual = re.sub(r"\s+", " ", (ROOT / "docs/linux/installation-rhel9.md").read_text())
        self.assertIn("0.11.27-144/driver 21", manual)
        self.assertIn("not a supported 0.11.29-155/driver 22 upgrade path", manual)
        self.assertIn("fresh, restorable disposable RHEL 9 VM only", manual[:1500])
        self.assertIn("No upgrade, catalog migration, backup/restore or physical-tape claim", manual[:1600])
        self.assertNotIn("sudo systemctl reset-failed", manual)


    def test_developer_and_cli_guides_use_current_public_contract(self) -> None:
        development = (ROOT / "docs/en/development.md").read_text()
        cli = (ROOT / "docs/en/cli-reference.md").read_text()
        security = (ROOT / "docs/en/security.md").read_text()
        self.assertIn("schema 41", development)
        self.assertIn("0.11.29-155", cli)
        for relative, text in (
            ("development", development),
            ("cli", cli),
            ("security", security),
        ):
            with self.subTest(path=relative):
                self.assertNotIn("private release process", text.lower())
                self.assertNotIn("GitLab", text)
                self.assertNotIn("schema 40", text)



    def test_third_party_notice_describes_linux_runtime_not_removed_windows_build(self) -> None:
        text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text()
        self.assertIn("packaging/python-runtime/THIRD_PARTY_NOTICES.md", text)
        self.assertIn("src/ltobackup/web/static/HTMX-LICENSE.txt", text)
        self.assertNotIn("PyInstaller", text)
        self.assertNotIn("Windows executables", text)


    def test_public_physical_guide_is_non_authorizing(self) -> None:
        guide = (ROOT / "docs/qualification/physical-ltfs-runbook.md").read_text()
        for required in ("not an authorization", "MAM", "quiescent", "finalization", "readback"):
            self.assertIn(required, guide)
        self.assertNotIn("sudo ", guide)
        self.assertNotRegex(guide, r"(?i)\\bIR[0-9]{4}\\b")


    def test_current_manual_links_resolve_inside_snapshot(self) -> None:
        for relative in (
            "README.md",
            "docs/en/index.md",
            "docs/en/installation.md",
            "SUPPORT.md",
            "SECURITY.md",
        ):
            page = ROOT / relative
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", page.read_text()):
                if "://" in target or target.startswith("#"):
                    continue
                with self.subTest(page=relative, target=target):
                    destination = target.split("#", 1)[0]
                    self.assertTrue((page.parent / destination).is_file())


    def test_all_public_markdown_links_resolve(self) -> None:
        public_paths = (ROOT / "public-files.txt").read_text().splitlines()
        for relative in public_paths:
            page = ROOT / relative
            if page.suffix != ".md":
                continue
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", page.read_text()):
                destination = target.split("#", 1)[0]
                if not destination or "://" in destination or destination.startswith("mailto:"):
                    continue
                with self.subTest(page=page.relative_to(ROOT).as_posix(), target=target):
                    self.assertTrue((page.parent / destination).is_file())



    def test_operator_guides_do_not_present_historical_release_as_current(self) -> None:
        admin = (ROOT / "docs/en/administration.md").read_text()
        current_admin = admin.split("## Constrained operational-log reader", 1)[0]
        self.assertIn("0.11.29-155", current_admin)
        self.assertIn("schema 41", current_admin)
        self.assertNotIn("Installed release141", current_admin)
        self.assertIn("quiescent", current_admin)
        self.assertIn("rollback", current_admin)
        for relative in (
            "docs/en/user-guide.md",
            "docs/linux/installation-rhel9.md",
            "docs/linux/catalog-search.md",
            "docs/en/ltfs-operations.md",
        ):
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text()
                self.assertIn("schema 41", text[:700])


if __name__ == "__main__":
    unittest.main()
