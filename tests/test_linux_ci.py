from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "packaging/scripts/test-linux-release.sh"


class LinuxCiTests(unittest.TestCase):
    def _run_fixture(self, *, failing: bool = False, mismatched_commit: bool = False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            files = {
                ".gitattributes": (ROOT / ".gitattributes").read_text(),
                "src/fixture_module.py": "VALUE = 'committed'\n",
                "src/ltobackup/gui.py": "forbidden_reintroduction = True\n",
                "src/ltobackup/winio.py": "forbidden_reintroduction = True\n",
                "tests/test_gui.py": "forbidden_reintroduction = True\n",
                "tests/test_cli.py": "forbidden_reintroduction = True\n",
                ".superpowers/sentinel": "excluded\n",
                "docs/superpowers/sentinel": "excluded\n",
                "authority.asc": "public fixture\n",
                "tests/test_linux.py": (
                    "import pathlib, stat, unittest, fixture_module\n"
                    "class ExportTest(unittest.TestCase):\n"
                    "    def test_export(self):\n"
                    "        self.assertEqual('committed', fixture_module.VALUE)\n"
                    "        self.assertFalse(pathlib.Path('tests/test_gui.py').exists())\n"
                    "        self.assertFalse(pathlib.Path('tests/test_cli.py').exists())\n"
                    "        self.assertFalse(pathlib.Path('src/ltobackup/gui.py').exists())\n"
                    "        self.assertFalse(pathlib.Path('src/ltobackup/winio.py').exists())\n"
                    "        self.assertFalse(pathlib.Path('.superpowers').exists())\n"
                    "        self.assertFalse(pathlib.Path('docs/superpowers').exists())\n"
                    "        self.assertEqual(0o644, stat.S_IMODE(pathlib.Path('authority.asc').stat().st_mode))\n"
                    f"        self.assertFalse({failing!r}, 'deliberate fixture failure')\n"
                ),
            }
            for name, content in files.items():
                target = repository / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
            for argv in (
                ("init", "-q"),
                ("add", "."),
                (
                    "-c",
                    "user.name=Fixture",
                    "-c",
                    "user.email=fixture@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "fixture",
                ),
            ):
                subprocess.run(
                    ("git", *argv), cwd=repository, check=True, capture_output=True
                )
            # CI must test the committed release export, not a changed checkout
            # or an editable package from the inherited Python search path.
            (repository / "src/fixture_module.py").write_text("VALUE = 'dirty'\n")
            commit = subprocess.check_output(
                ("git", "rev-parse", "HEAD"), cwd=repository, text=True
            ).strip()
            result = subprocess.run(
                ("/bin/bash", str(RUNNER), sys.executable),
                cwd=repository,
                env={
                    **os.environ,
                    "TMPDIR": str(root),
                    "PYTHONPATH": "/missing",
                    "CI_COMMIT_SHA": "0" * 40 if mismatched_commit else commit,
                },
                umask=0o002,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                "VALUE = 'dirty'\n", (repository / "src/fixture_module.py").read_text()
            )
            self.assertEqual([], list(root.glob("lto-linux-test.*")))
            return result

    def test_ci_executes_linux_export_with_safe_modes_and_local_imports(self):
        result = self._run_fixture()
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("Ran 1 test", result.stderr)
        self.assertIn("OK", result.stderr)

    def test_ci_propagates_test_failure_and_cleans_only_its_export(self):
        result = self._run_fixture(failing=True)
        self.assertEqual(1, result.returncode, result.stderr)
        self.assertIn("deliberate fixture failure", result.stderr)

    def test_ci_rejects_checkout_that_does_not_match_pipeline_commit(self):
        result = self._run_fixture(mismatched_commit=True)
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertNotIn("Ran 1 test", result.stderr)


if __name__ == "__main__":
    unittest.main()
