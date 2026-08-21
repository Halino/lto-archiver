from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ltobackup.errors import ValidationError
from ltobackup.settings import AppPaths, load_settings, upgrade_legacy_settings


class SettingsTests(unittest.TestCase):
    def test_invalid_json_is_an_operator_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = AppPaths(Path(temporary))
            paths.create()
            paths.config_file.write_text("{not-json", encoding="utf-8")

            with self.assertRaisesRegex(ValidationError, "configurazione"):
                load_settings(paths)

    def test_unknown_setting_is_an_operator_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = AppPaths(Path(temporary))
            paths.create()
            paths.config_file.write_text('{"unknown_option": true}', encoding="utf-8")

            with self.assertRaisesRegex(ValidationError, "unknown_option"):
                upgrade_legacy_settings(paths)

    def test_setting_with_wrong_value_type_is_an_operator_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = AppPaths(Path(temporary))
            paths.create()
            paths.config_file.write_text('{"reserve_bytes": "invalid"}', encoding="utf-8")

            with self.assertRaisesRegex(ValidationError, "Configurazione"):
                load_settings(paths)


if __name__ == "__main__":
    unittest.main()
