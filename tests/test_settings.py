from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from ltobackup.errors import ValidationError
from ltobackup.settings import (
    AppPaths,
    Settings,
    load_settings,
    upgrade_legacy_settings,
)


class SettingsTests(unittest.TestCase):
    def test_default_media_key_is_backward_compatible_and_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = AppPaths(Path(temporary))
            paths.create()
            original = '{"min_age_seconds": 0, "tape_root_directory": ".lto-backup"}\n'
            paths.config_file.write_text(original, encoding="utf-8")

            settings = load_settings(paths)

            self.assertEqual("LTO-6", settings.default_media_key)
            self.assertEqual(original, paths.config_file.read_text(encoding="utf-8"))
            for media_key in ("lto-9", "LTO10", "lto10_pa"):
                with self.subTest(media_key=media_key):
                    candidate = Settings(default_media_key=media_key)
                    candidate.validate()

    def test_application_policy_values_have_finite_safe_bounds(self) -> None:
        valid = Settings(
            reserve_bytes=1,
            min_age_seconds=31 * 24 * 60 * 60,
            buffer_bytes=64 * 1024**2,
            default_media_key="LTO-10 PA",
            tape_root_directory=".lto-backup",
        )
        valid.validate()

        for candidate in (
            Settings(min_age_seconds=31 * 24 * 60 * 60 + 1),
            Settings(buffer_bytes=1024**2 - 1),
            Settings(default_media_key="LTO-11"),
            Settings(
                default_media_key="LTO-5",
                reserve_bytes=1_430_000_000_000,
            ),
            Settings(tape_root_directory="."),
            Settings(tape_root_directory=".."),
            Settings(tape_root_directory="archive/path"),
        ):
            with self.subTest(candidate=candidate), self.assertRaises(ValidationError):
                candidate.validate()

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
