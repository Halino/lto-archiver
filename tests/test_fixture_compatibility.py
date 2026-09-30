from __future__ import annotations

import unittest
from pathlib import Path


class FixtureCompatibilityTests(unittest.TestCase):
    def test_python_fixtures_do_not_require_sqlite_335_column_drop(self) -> None:
        tests_root = Path(__file__).resolve().parent
        unsupported_statement = "DROP" + " COLUMN"

        for source in tests_root.rglob("*.py"):
            with self.subTest(source=source.relative_to(tests_root)):
                self.assertNotIn(
                    unsupported_statement.casefold(),
                    source.read_text(encoding="utf-8").casefold(),
                )


if __name__ == "__main__":
    unittest.main()
