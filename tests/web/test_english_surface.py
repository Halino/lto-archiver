from __future__ import annotations

import unittest
from html import escape

from jinja2 import Environment, FileSystemLoader

from ltobackup.daemon.api_models import TelemetrySampleV1
from ltobackup.web.app import render_telemetry
from tests.web.restore_fixture import restore_run

from tests.web.english_surface import (
    DERIVED_FORMER_ITALIAN_UI_PHRASES,
    FORMER_SURFACE_DERIVATION_ALLOWLIST,
    assert_english_document,
    extract_visible_and_accessible_text,
)


class EnglishSurfaceOracleTests(unittest.TestCase):
    def test_oracle_covers_visible_accessible_copy_but_not_scripts_or_styles(self):
        document = """
            <html lang="en"><body>
              Visible
              <input aria-label="Accessible" placeholder="Prompt">
              <table><td data-label="Responsive">Value</td></table>
              <svg><title>Graphic title</title><desc>Graphic description</desc></svg>
              <script>Panoramica</script><style>.Panoramica { color: red; }</style>
            </body></html>
        """

        surface = extract_visible_and_accessible_text(document)

        self.assertIn("Visible", surface)
        self.assertIn("Accessible", surface)
        self.assertIn("Prompt", surface)
        self.assertIn("Responsive", surface)
        self.assertIn("Graphic title", surface)
        self.assertIn("Graphic description", surface)
        assert_english_document(self, document)

    def test_allowing_one_dynamic_value_does_not_hide_static_italian_copy(self):
        document = """
            <html lang="en"><body>
              <p data-user-value>Panoramica</p>
              <nav aria-label="Panoramica">Home</nav>
            </body></html>
        """

        with self.assertRaises(AssertionError):
            assert_english_document(self, document, allowed_data=("Panoramica",))

    def test_oracle_rejects_italian_copy_regardless_of_case(self):
        document = """
            <html lang="en"><body>
              <h1>pAnOrAmIcA</h1>
            </body></html>
        """

        with self.assertRaises(AssertionError):
            assert_english_document(self, document)

    def test_oracle_covers_broader_management_vocabulary(self):
        document = """
            <html lang="en"><body>
              <p>rIsUlTaTi DeL cAtAlOgO</p>
            </body></html>
        """

        with self.assertRaises(AssertionError):
            assert_english_document(self, document)

    def test_oracle_rejects_former_copy_across_maintained_routes(self):
        former_copy = (
            "Crea nuova libreria",
            "Nuova condivisione",
            "Riserva capacità in byte",
            "Riautenticazione amministratore",
            "Telemetria runtime redatta",
            "Operazione già attiva",
        )

        for phrase in former_copy:
            with self.subTest(phrase=phrase), self.assertRaises(AssertionError):
                assert_english_document(
                    self,
                    f'<html lang="en"><body><p>{phrase}</p></body></html>',
                )

    def test_oracle_rejects_former_base_navigation_accessibility_copy(self):
        document = """
            <html lang="en"><body>
              <button aria-label="Apri o chiudi il menu principale">Menu</button>
            </body></html>
        """

        with self.assertRaises(AssertionError):
            assert_english_document(self, document)

    def test_oracle_rejects_every_derived_former_literal_and_case_mutation(self):
        self.assertIn(
            "Apri o chiudi il menu principale",
            DERIVED_FORMER_ITALIAN_UI_PHRASES,
        )
        for phrase in DERIVED_FORMER_ITALIAN_UI_PHRASES:
            for mutation in (phrase, phrase.swapcase()):
                with (
                    self.subTest(phrase=phrase, mutation=mutation),
                    self.assertRaises(AssertionError),
                ):
                    assert_english_document(
                        self,
                        '<html lang="en"><body><p>'
                        f"{escape(mutation)}"
                        "</p></body></html>",
                    )

    def test_derivation_allowlist_keeps_shared_data_and_protocol_copy_valid(self):
        for value in FORMER_SURFACE_DERIVATION_ALLOWLIST:
            with self.subTest(value=value):
                assert_english_document(
                    self,
                    '<html lang="en"><body><p>'
                    f"{escape(value)}"
                    "</p></body></html>",
                )

    def test_dynamic_user_data_allowance_is_case_insensitive(self):
        document = """
            <html lang="en"><body>
              <p>pAnOrAmIcA</p>
            </body></html>
        """

        assert_english_document(
            self,
            document,
            allowed_data=("Panoramica",),
        )

    def test_restore_and_telemetry_accessibility_copy_remains_english(self):
        run = restore_run(conflict=True)
        telemetry = render_telemetry(
            (
                TelemetrySampleV1(
                    event_id=1,
                    occurred_at="2026-08-31T18:18:00Z",
                    mib_per_second=123.5,
                ),
            ),
            effective_rate=98.25,
        )
        rendered = Environment(
            loader=FileSystemLoader("src/ltobackup/web/templates"),
            autoescape=True,
        ).get_template("partials/restore_status.html").render(
            run=run,
            current_cassette=run.cassettes[0],
            current_rate="123.50 MiB/s",
            current_rate_value=123.5,
            effective_rate="98.25 MiB/s",
            effective_rate_value=98.25,
            phase="Restoring",
            bytes_progress="1.00 KiB / 2.00 KiB",
            recent_admin=True,
            csrf="csrf-token",
            new_idempotency_key=lambda: "idempotency-key",
            telemetry_html=telemetry,
            refresh_mode="active",
        )
        document = f'<html lang="en"><body>{rendered}</body></html>'
        self.assertIn("Authorize exact replacement", document)
        self.assertIn("Effective operation rate", document)
        assert_english_document(self, document)
        with self.assertRaises(AssertionError):
            assert_english_document(
                self,
                document.replace("Insert cassette", "Inserisci cassetta"),
            )


if __name__ == "__main__":
    unittest.main()
