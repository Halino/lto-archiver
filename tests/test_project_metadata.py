from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProjectMetadataTests(unittest.TestCase):
    def test_license_uses_setuptools_65_compatible_pep621_table(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertEqual({"text": "Apache-2.0"}, metadata["project"]["license"])

    def test_web_runtime_dependencies_are_declared(self) -> None:
        metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

        self.assertIn("argon2-cffi>=25.1,<26", metadata["project"]["dependencies"])
        self.assertIn("httpx>=0.28,<1", metadata["project"]["dependencies"])


if __name__ == "__main__":
    unittest.main()
