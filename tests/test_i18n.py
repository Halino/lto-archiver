from __future__ import annotations

import ast
import tempfile
import unittest
from pathlib import Path

from ltobackup.i18n import TRANSLATIONS, Translator, load_language, save_language


class I18nTests(unittest.TestCase):
    def test_every_static_gui_label_is_translated_in_all_supported_locales(self) -> None:
        gui_source = Path(__file__).parents[1] / "src" / "ltobackup" / "gui.py"
        tree = ast.parse(gui_source.read_text(encoding="utf-8"))
        technical_tokens = {
            "ARCHIVER", "AUTO", "LTO", "LTO-6", "TAPE0", "L:\\", "tape operations",
        }
        labels: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if (
                    keyword.arg in {"text", "value"}
                    and isinstance(keyword.value, ast.Constant)
                    and isinstance(keyword.value.value, str)
                    and len(keyword.value.value) > 2
                ):
                    labels.add(keyword.value.value)

        for language, translations in TRANSLATIONS.items():
            missing = sorted(labels - translations.keys() - technical_tokens)
            self.assertEqual([], missing, f"Etichette GUI mancanti per {language}")
    def test_translator_supports_italian_and_english_with_fallback(self) -> None:
        self.assertEqual("Job automatici", Translator("it")("Job automatici"))
        self.assertEqual("Saved jobs", Translator("en")("Job automatici"))
        self.assertEqual("Tâches enregistrées", Translator("fr")("Job automatici"))
        self.assertEqual("Gespeicherte Jobs", Translator("de")("Job automatici"))
        self.assertEqual("Trabajos guardados", Translator("es")("Job automatici"))
        self.assertEqual("Unmapped", Translator("en")("Unmapped"))

    def test_language_preference_is_persisted_and_invalid_values_fall_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            self.assertEqual("it", load_language(state))
            save_language(state, "en")
            self.assertEqual("en", load_language(state))
            for language in ("fr", "de", "es"):
                save_language(state, language)
                self.assertEqual(language, load_language(state))
            (state / "ui-preferences.json").write_text(
                '{"language": "xx"}', encoding="utf-8"
            )
            self.assertEqual("it", load_language(state))
