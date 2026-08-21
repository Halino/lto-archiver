from __future__ import annotations

import re
import unittest
from pathlib import Path


class DocumentationTests(unittest.TestCase):
    def test_technical_manuals_cover_required_public_contracts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        names = (
            "cli-reference.md",
            "troubleshooting.md",
            "security.md",
            "development.md",
            "release-process.md",
            "faq.md",
        )
        for language in ("en", "it"):
            for name in names:
                self.assertTrue((root / "docs" / language / name).is_file(), f"{language}/{name}")
            cli = (root / "docs" / language / "cli-reference.md").read_text(encoding="utf-8")
            self.assertIn("--json-progress", cli)
            self.assertIn("catalog check", cli)
            troubleshooting = (root / "docs" / language / "troubleshooting.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("FUSE4WinSvc", troubleshooting)
            self.assertIn("Clean requested", troubleshooting)

    def test_technical_manuals_preserve_cli_mutation_progress_and_release_tool_contracts(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        for language in ("en", "it"):
            docs = root / "docs" / language
            cli = (docs / "cli-reference.md").read_text(encoding="utf-8")
            troubleshooting = (docs / "troubleshooting.md").read_text(encoding="utf-8")
            development = (docs / "development.md").read_text(encoding="utf-8")
            release = (docs / "release-process.md").read_text(encoding="utf-8")

            for event in (
                "strategy.selected",
                "hash.complete",
                "catalog.backup.warning",
                "catalog.snapshot.warning",
            ):
                self.assertIn(event, cli, f"{language} missing {event}")
            for group in ("library", "tape", "block", "automatic", "restore", "catalog"):
                self.assertIn(f"`{group}`", cli, f"{language} missing group {group}")
            self.assertIn("--help", cli)
            self.assertIn("exit 2" if language == "en" else "uscita 2", cli)
            self.assertIn("initialize", cli.casefold())
            self.assertIn("log", cli.casefold())

            for heading in (
                "No cache samples",
                "Wrong tape",
                "Full tape",
                "Release verification",
            ) if language == "en" else (
                "Nessun campione cache",
                "Nastro errato",
                "Nastro pieno",
                "Verifica release",
            ):
                self.assertIn(heading, troubleshooting, f"{language} missing {heading}")
            for marker in (
                "Safe observation",
                "Forbidden concurrent actions",
                "Escalation",
            ) if language == "en" else (
                "Osservazione sicura",
                "Azioni concorrenti vietate",
                "Escalation",
            ):
                self.assertIn(marker, troubleshooting, f"{language} missing {marker}")

            for text in (
                "verify-release.ps1 -Version 0.11.27 -ReleaseDirectory",
                "build-public-snapshot.py",
                "--manifest public-files.txt",
                "audit-public-content.py",
                "--git-history",
                "windows-latest",
                "actions/checkout@v4",
            ):
                self.assertIn(text, development + release, f"{language} missing {text}")

    def test_technical_manuals_define_safe_diagnostics_event_fields_and_release_commands(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        for language in ("en", "it"):
            docs = root / "docs" / language
            cli = (docs / "cli-reference.md").read_text(encoding="utf-8")
            troubleshooting = (docs / "troubleshooting.md").read_text(encoding="utf-8")
            release_text = "\n".join(
                (docs / name).read_text(encoding="utf-8")
                for name in ("development.md", "release-process.md")
            )

            for text in (
                "Copy-Item -LiteralPath $stateDirectory -Destination $diagnosticRoot -Recurse",
                "--state-dir $diagnosticStateDirectory",
                "Never run the diagnostic against the preserved"
                if language == "en"
                else "Non eseguire mai la diagnostica contro",
                "init" if language == "en" else "init",
                "telemetry",
                "read.pending",
                "read.complete",
                "close_queue.pending",
                "close_queue.complete",
                "flush.pending",
                "flush.complete",
                "`event`",
                "`at`",
                "`index`",
                "`relative_path`",
                "`block_id`",
                "`error`",
                "`phase`",
                "`copied_bytes`",
                "`pending_bytes`",
                "`io_mode`",
                "`hash_complete_seconds`",
            ):
                self.assertIn(text, cli + troubleshooting, f"{language} missing {text}")

            for text in (
                "release/LTO-Archiver-0.11.27.zip",
                "release/LTO-Archiver-0.11.27.zip.sha256",
                "exit 0" if language == "en" else "uscita 0",
                "gh release create $env:GITHUB_REF_NAME",
                '"release/LTO-Archiver-$version.zip"',
                '"release/LTO-Archiver-$version.zip.sha256"',
                '--title "LTO Archiver $version"',
                '--notes-file "docs/release-notes-$version.md"',
                "--verify-tag",
                "YAML",
            ):
                self.assertIn(text, release_text, f"{language} missing {text}")
            self.assertNotIn("NOTICE, THIRD_PARTY_NOTICES, metadata, README versione/licenza. Il builder", release_text)

    def test_technical_manuals_require_fresh_diagnostic_copies_and_conditional_zip_audits(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        for language in ("en", "it"):
            docs = root / "docs" / language
            troubleshooting = (docs / "troubleshooting.md").read_text(encoding="utf-8")
            release_text = "\n".join(
                (docs / name).read_text(encoding="utf-8")
                for name in ("development.md", "release-process.md")
            )
            diagnostic = troubleshooting.split("## Job saved but not started", 1)[0]
            for text in (
                "[guid]::NewGuid()",
                "New-Item -ItemType Directory -Path $diagnosticRoot -ErrorAction Stop",
                "Copy-Item -LiteralPath $stateDirectory -Destination $diagnosticRoot -Recurse -ErrorAction Stop",
                "$diagnosticStateDirectory = Join-Path $diagnosticRoot 'LtoBackupManager'",
            ):
                self.assertIn(text, diagnostic, f"{language} missing {text}")
            self.assertNotIn("-Force", diagnostic, f"{language} reuses diagnostic copy")
            normalized_release = release_text.replace("\n", " ")
            for text in (
                "final 0.11.27 public tree after Tasks 7–9" if language == "en"
                else "albero pubblico finale 0.11.27 dopo Tasks 7–9",
                "current intermediate checkout" if language == "en"
                else "worktree intermedio corrente",
                "exit 0" if language == "en" else "uscita 0",
                "nonzero" if language == "en" else "nonzero",
            ):
                self.assertIn(text, normalized_release, f"{language} missing {text}")
            self.assertIn(
                "audit-public-content.py `\n  'release\\LTO-Archiver-0.11.27.zip'",
                release_text,
                f"{language} missing ZIP audit",
            )

    def test_operator_manuals_exist_in_both_languages(self) -> None:
        root = Path(__file__).resolve().parents[1]
        names = ("index.md", "installation.md", "user-guide.md", "administration.md", "ltfs-operations.md")
        for name in names:
            english = (root / "docs" / "en" / name).read_text(encoding="utf-8")
            italian = (root / "docs" / "it" / name).read_text(encoding="utf-8")
            self.assertIn("0.11.27", english, name)
            self.assertIn("0.11.27", italian, name)
        for language in ("en", "it"):
            text = (root / "docs" / language / "user-guide.md").read_text(encoding="utf-8")
            self.assertIn("NUOVA", text)
            self.assertIn("APPEND", text)
            self.assertIn("close.complete", text)

    def test_operator_manuals_do_not_invent_driver_versions_or_omit_stop_safety(
        self,
    ) -> None:
        root = Path(__file__).resolve().parents[1]
        for language in ("en", "it"):
            installation = (root / "docs" / language / "installation.md").read_text(
                encoding="utf-8"
            )
            self.assertNotIn("HPE LTO driver 1.0.9.4", installation)
            self.assertNotIn("driver HPE LTO 1.0.9.4", installation)

        italian = " ".join(
            (root / "docs" / "it" / "user-guide.md")
            .read_text(encoding="utf-8")
            .split()
        )
        self.assertIn("cassetta non e completa finche il suo indice rimane non committed", italian)
        self.assertIn("attendere l'espulsione", italian)
        self.assertIn("non inserire la cassetta successiva", italian)
        self.assertIn("interrompere durante l'attesa del supporto", italian)

    def test_public_landing_pages_are_bilingual_and_release_aware(self) -> None:
        root = Path(__file__).resolve().parents[1]
        english = (root / "README.md").read_text(encoding="utf-8")
        italian = (root / "README.it.md").read_text(encoding="utf-8")
        changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")

        self.assertIn("[Italiano](README.it.md)", english)
        self.assertIn("[English](README.md)", italian)
        self.assertIn("0.11.27", english)
        self.assertIn("0.11.27", italian)
        self.assertIn("Apache-2.0", english)
        self.assertIn("docs/en/index.md", english)
        self.assertIn("docs/it/index.md", italian)
        self.assertIn("## [0.11.27]", changelog)

    def test_relative_markdown_links_resolve(self) -> None:
        root = Path(__file__).resolve().parents[1]
        documents = [root / "README.md", *(root / "docs").glob("*.md")]
        public_files = frozenset(
            (root / "public-files.txt").read_text(encoding="utf-8").splitlines()
        )

        for document in documents:
            text = document.read_text(encoding="utf-8")
            for target in re.findall(r"\[[^]]+\]\(([^)]+)\)", text):
                if target.startswith(("http://", "https://", "#")):
                    continue
                relative = target.split("#", 1)[0]
                resolved = (document.parent / relative).resolve()
                self.assertTrue(
                    resolved.exists(),
                    f"{document}: collegamento mancante {target}",
                )
                self.assertIn(
                    resolved.relative_to(root.resolve()).as_posix(),
                    public_files,
                    f"{document}: collegamento escluso dallo snapshot pubblico {target}",
                )

    def test_current_release_and_storeopen_heartbeat_are_documented(self) -> None:
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        installation = (root / "docs" / "installation-windows.md").read_text(
            encoding="utf-8"
        )
        documentation_index = (root / "docs" / "README.md").read_text(
            encoding="utf-8"
        )
        development = (root / "docs" / "development.md").read_text(
            encoding="utf-8"
        )
        operations = (root / "docs" / "operations.md").read_text(encoding="utf-8")
        architecture = (root / "docs" / "architecture.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("0.11.27", readme)
        self.assertIn("0.11.27", installation)
        self.assertIn("0.11.27", documentation_index)
        self.assertIn("0.11.27", development)
        release_notes = (root / "docs" / "release-notes-0.11.27.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("seriale Win32", release_notes)
        self.assertIn("schema 13", release_notes)
        self.assertIn("Heartbeat StoreOpen", operations)
        self.assertIn("write.pending", architecture)
        self.assertIn("non incrementa i byte", readme)
        self.assertIn("Media effettiva cassetta", readme)
        self.assertIn("campioni regolari di un secondo", readme)
        self.assertIn("manifest", readme.casefold())
        self.assertIn("windows_copyfileex_parallel_hash", architecture)
        self.assertIn("senza `FlushFileBuffers`", architecture)
        self.assertIn("CopyFileEx", architecture)
        self.assertIn("close.complete", architecture)
        self.assertIn("unmount.progress", architecture)
        self.assertIn("APPEND - conserva i dati", readme)
        self.assertIn("operation=format|append", architecture)

    def test_long_ltfs_close_diagnostic_is_actionable_and_non_destructive(self) -> None:
        root = Path(__file__).resolve().parents[1]
        troubleshooting = (root / "docs" / "troubleshooting.md").read_text(
            encoding="utf-8"
        )

        self.assertIn("semaforo esclusivo", troubleshooting)
        self.assertIn("Clean requested", troubleshooting)
        self.assertIn("support ticket", troubleshooting)
        self.assertIn("C7978A", troubleshooting)
        self.assertIn("non interrogare direttamente il device", troubleshooting)
