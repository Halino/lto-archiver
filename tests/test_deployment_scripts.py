from __future__ import annotations

import hashlib
import os
import subprocess
import tempfile
import unittest
import uuid
import zipfile
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify-release.ps1"
PUBLIC_MANUALS = (
    "administration.md",
    "cli-reference.md",
    "development.md",
    "faq.md",
    "index.md",
    "installation.md",
    "ltfs-operations.md",
    "release-process.md",
    "security.md",
    "troubleshooting.md",
    "user-guide.md",
)
REQUIRED_RELEASE_FILES = (
    "CHANGELOG.md",
    "LICENSE",
    "LtoBackupManager.exe",
    "LtoBackupManager.exe.sha256",
    "LtoBackupManagerCli.exe",
    "LtoBackupManagerCli.exe.sha256",
    "NOTICE",
    "README.it.md",
    "README.md",
    "THIRD_PARTY_NOTICES.md",
    "configure-controlled-folder-access.ps1",
    "install-lto-backup-manager.ps1",
    *(f"docs/{language}/{name}" for language in ("en", "it") for name in PUBLIC_MANUALS),
)
NATIVE_WINDOWS_POWERSHELL = os.name == "nt" and not Path(
    r"C:\windows\system32\wineboot.exe"
).exists()


def _write_release_archive(
    release_directory: Path,
    *,
    version: str = "0.11.27",
    extra_files: dict[str, bytes] | None = None,
    omitted_files: frozenset[str] = frozenset(),
) -> None:
    files = {
        name: (b"placeholder executable" if name.endswith(".exe") else b"public release fixture\n")
        for name in REQUIRED_RELEASE_FILES
        if name not in omitted_files and not name.endswith(".sha256")
    }
    for executable in ("LtoBackupManager.exe", "LtoBackupManagerCli.exe"):
        if executable in files:
            digest = hashlib.sha256(files[executable]).hexdigest().upper()
            hash_name = f"{executable}.sha256"
            if hash_name not in omitted_files:
                files[hash_name] = f"{digest}  {executable}\n".encode("ascii")
    files.update(extra_files or {})

    archive = release_directory / f"LTO-Archiver-{version}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as package:
        for name, content in sorted(files.items()):
            package.writestr(name, content)
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest().upper()
    archive.with_suffix(".zip.sha256").write_bytes(
        f"{archive_digest}  {archive.name}\n".encode("ascii"),
    )


def _windows_powershell_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if key.casefold() != "psmodulepath"
    }


def _run_release_verifier(release_directory: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(VERIFIER),
            "-Version",
            "0.11.27",
            "-ReleaseDirectory",
            str(release_directory),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=_windows_powershell_environment(),
        check=False,
        timeout=30,
    )


class DeploymentScriptTests(unittest.TestCase):
    def test_windows_powershell_subprocess_drops_inherited_module_path(self) -> None:
        with mock.patch.dict(os.environ, {"PSModulePath": "pwsh-only-modules"}):
            environment = _windows_powershell_environment()

        self.assertFalse(
            any(key.casefold() == "psmodulepath" for key in environment)
        )

    def test_release_fixture_has_a_platform_independent_lf_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_directory = Path(temporary)
            _write_release_archive(release_directory)

            checksum = release_directory / "LTO-Archiver-0.11.27.zip.sha256"
            record = checksum.read_bytes()

        self.assertTrue(record.endswith(b"\n"))
        self.assertFalse(record.endswith(b"\r\n"))

    def test_release_01127_is_declared_consistently(self) -> None:
        root = Path(__file__).resolve().parents[1]
        expected = "0.11.27"
        self.assertIn(f'version = "{expected}"', (root / "pyproject.toml").read_text())
        self.assertIn(f'__version__ = "{expected}"', (root / "src/ltobackup/__init__.py").read_text())
        for name in ("version_info.txt", "version_info_cli.txt"):
            text = (root / "packaging" / name).read_text()
            self.assertIn("filevers=(0, 11, 27, 0)", text)
            self.assertIn("prodvers=(0, 11, 27, 0)", text)
            self.assertIn("FileVersion', '0.11.27", text)
            self.assertIn("ProductVersion', '0.11.27", text)
    def test_public_release_package_includes_legal_and_bilingual_docs(self) -> None:
        builder = (ROOT / "scripts" / "build-release.ps1").read_text(
            encoding="utf-8"
        )
        verifier = VERIFIER.read_text(encoding="utf-8")

        for name in (
            "LICENSE",
            "NOTICE",
            "THIRD_PARTY_NOTICES.md",
            "README.md",
            "README.it.md",
            "CHANGELOG.md",
        ):
            self.assertIn(name, builder)
            self.assertIn(name, verifier)
        self.assertIn("docs\\en", builder)
        self.assertIn("docs\\it", builder)
        self.assertIn("LTO-Archiver-$Version.zip.sha256", verifier)
        self.assertNotIn("'docs\\*'", builder)
        self.assertNotIn("INSTALLAZIONE.md", builder)

    def test_release_verifier_declares_the_complete_exact_file_contract(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")

        for name in REQUIRED_RELEASE_FILES:
            self.assertIn(name.replace("/", "\\"), verifier, name)
        for token in (
            "Get-FileHash",
            "Expand-Archive",
            "--version",
            "*.db",
            "*.log",
            ".env*",
            "*.lzt",
            "PRIVATE KEY",
            "Unsafe archive entry",
            "finally",
        ):
            self.assertIn(token, verifier)

    def test_release_verifier_validates_the_complete_raw_checksum_record(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")

        self.assertNotIn("(Get-Content -LiteralPath $Path -Raw).Trim()", verifier)
        self.assertIn("'\\A(?<hash>", verifier)
        self.assertIn("(?:\\r\\n|\\n)?\\z'", verifier)
        self.assertIn("$record -cnotmatch $pattern", verifier)

    def test_release_verifier_delimits_variables_before_colons(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")

        self.assertIn("${binary}: exit=", verifier)
        self.assertNotIn("$binary: exit=", verifier)

    def test_release_verifier_retries_transient_scanner_locks_during_cleanup(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")

        self.assertIn("function Remove-OwnedTemporaryDirectory", verifier)
        self.assertIn("[int]$MaximumAttempts = 20", verifier)
        self.assertIn("Start-Sleep -Milliseconds 250", verifier)
        self.assertIn("Remove-OwnedTemporaryDirectory -Path $temporaryDirectory", verifier)
        self.assertIn("throw", verifier.split("function Remove-OwnedTemporaryDirectory", 1)[1])

    def test_release_verifier_waits_for_gui_process_tree_before_cleanup(self) -> None:
        verifier = VERIFIER.read_text(encoding="utf-8")

        self.assertIn("function Invoke-ReleaseBinaryVersion", verifier)
        self.assertIn("Start-Process", verifier)
        self.assertIn("-Wait -PassThru", verifier)
        self.assertIn("$process.Dispose()", verifier)
        self.assertIn("Invoke-ReleaseBinaryVersion -BinaryPath $binaryPath", verifier)
        self.assertNotIn("$versionLines = @(& $binaryPath '--version' 2>&1)", verifier)

    @unittest.skipUnless(
        NATIVE_WINDOWS_POWERSHELL,
        "requires native Windows PowerShell; Wine returns success without executing -File",
    )
    def test_release_verifier_rejects_checksum_whitespace_blank_lines_and_extra_records(self) -> None:
        for label, invalid_record in (
            ("leading space", lambda record: b" " + record),
            ("trailing space", lambda record: record + b" \n"),
            ("bare CR", lambda record: record + b"\r"),
            ("blank line", lambda record: record + b"\n\n"),
            ("extra record", lambda record: record + b"\n" + record + b"\n"),
            (
                "filename case",
                lambda record: record.replace(b"LTO-Archiver", b"lto-archiver"),
            ),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                release_directory = Path(temporary)
                _write_release_archive(release_directory)
                checksum = release_directory / "LTO-Archiver-0.11.27.zip.sha256"
                record = checksum.read_bytes().removesuffix(b"\n")
                checksum.write_bytes(invalid_record(record))

                completed = _run_release_verifier(release_directory)

                output = completed.stdout + completed.stderr
                self.assertNotEqual(0, completed.returncode, output)
                self.assertIn("Invalid SHA-256 file format", output)

    @unittest.skipUnless(
        NATIVE_WINDOWS_POWERSHELL,
        "requires native Windows PowerShell; Wine returns success without executing -File",
    )
    def test_release_verifier_accepts_only_exact_checksum_terminal_newlines(self) -> None:
        for label, terminator in (("none", b""), ("LF", b"\n"), ("CRLF", b"\r\n")):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                release_directory = Path(temporary)
                _write_release_archive(
                    release_directory,
                    extra_files={"catalog.db": b"forbidden after checksum validation"},
                )
                checksum = release_directory / "LTO-Archiver-0.11.27.zip.sha256"
                record = checksum.read_bytes().removesuffix(b"\n")
                checksum.write_bytes(record + terminator)

                completed = _run_release_verifier(release_directory)

                output = completed.stdout + completed.stderr
                self.assertNotEqual(0, completed.returncode, output)
                self.assertNotIn("Invalid SHA-256 file format", output)
                self.assertIn("Forbidden release content", output)

    @unittest.skipUnless(
        NATIVE_WINDOWS_POWERSHELL,
        "requires native Windows PowerShell; Wine returns success without executing -File",
    )
    def test_release_verifier_rejects_archive_path_escape_without_writing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_directory = Path(temporary) / "release"
            release_directory.mkdir()
            escaped = Path(temporary) / "escaped.txt"
            _write_release_archive(
                release_directory,
                extra_files={"../escaped.txt": b"must never be extracted"},
            )
            completed = _run_release_verifier(release_directory)

            output = completed.stdout + completed.stderr
            self.assertNotEqual(0, completed.returncode, output)
            self.assertIn("Unsafe archive entry", output)
            self.assertFalse(escaped.exists())

    @unittest.skipUnless(
        NATIVE_WINDOWS_POWERSHELL,
        "requires native Windows PowerShell; Wine returns success without executing -File",
    )
    def test_release_verifier_rejects_forbidden_content_and_cleans_its_temp_directory(self) -> None:
        forbidden_cases = {
            "catalog.db": b"sqlite fixture",
            "application.log": b"operator log fixture",
            ".env.production": b"TOKEN=not-a-real-token",
            "notes.txt": b"-----BEGIN OPENSSH PRIVATE KEY-----\nfixture",
            "support-ticket.lzt": b"support ticket fixture",
            "helper.exe": b"unexpected executable fixture",
        }

        for name, content in forbidden_cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                release_directory = Path(temporary)
                _write_release_archive(release_directory, extra_files={name: content})
                temp_root = Path(tempfile.gettempdir())
                before = set(temp_root.glob("LTO-Archiver-verify-*"))
                sentinel = temp_root / f"LTO-Archiver-verifier-sentinel-{uuid.uuid4()}"
                sentinel.mkdir()
                try:
                    completed = _run_release_verifier(release_directory)
                    output = completed.stdout + completed.stderr
                    self.assertNotEqual(0, completed.returncode, output)
                    self.assertIn("Forbidden release content", output)
                    self.assertTrue(sentinel.is_dir())
                    self.assertEqual(before, set(temp_root.glob("LTO-Archiver-verify-*")))
                finally:
                    sentinel.rmdir()

    @unittest.skipUnless(
        NATIVE_WINDOWS_POWERSHELL,
        "requires native Windows PowerShell; Wine returns success without executing -File",
    )
    def test_release_verifier_rejects_an_incomplete_file_set_and_cleans_up(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_directory = Path(temporary)
            _write_release_archive(
                release_directory,
                omitted_files=frozenset({"NOTICE"}),
            )
            temp_root = Path(tempfile.gettempdir())
            before = set(temp_root.glob("LTO-Archiver-verify-*"))
            completed = _run_release_verifier(release_directory)

        output = completed.stdout + completed.stderr
        self.assertNotEqual(0, completed.returncode, output)
        self.assertIn("Release content mismatch", output)
        self.assertEqual(before, set(temp_root.glob("LTO-Archiver-verify-*")))

    def test_installer_protects_state_and_declares_public_build_dependencies(self) -> None:
        root = Path(__file__).resolve().parents[1]
        installer = (root / "scripts" / "install-lto-backup-manager.ps1").read_text(
            encoding="utf-8"
        )

        self.assertIn("icacls.exe", installer)
        self.assertIn("takeown.exe", installer)
        self.assertIn("S-1-5-32-544", installer)
        self.assertIn("/setowner '*S-1-5-32-544' /T /C /Q", installer)
        self.assertIn("[System.IO.File]::Open", installer)
        self.assertIn("'*S-1-5-18:F' '*S-1-5-32-544:F'", installer)
        self.assertIn("Verifica post-installazione", installer)
