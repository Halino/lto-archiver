from __future__ import annotations

import ast
import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

REMOVED_PATHS = (
    "src/ltobackup/gui.py",
    "src/lto_backup_gui_entry.py",
    "src/lto_backup_entry.py",
    "src/pyi_rth_tkinter_local.py",
    "LtoBackupManager.spec",
    "hooks/hook-_tkinter.py",
    "hooks/pre_find_module_path/hook-tkinter.py",
    "requirements-build.txt",
    "packaging/version_info.txt",
    "packaging/version_info_cli.txt",
    "scripts/build-release.ps1",
    "scripts/verify-release.ps1",
    "scripts/install-lto-backup-manager.ps1",
    "scripts/configure-controlled-folder-access.ps1",
    "tests/test_gui.py",
    "tests/test_gui_english.py",
    "tests/test_cfa_installer.py",
    "tests/test_deployment_scripts.py",
    "tests/test_entry.py",
    "docs/installation-windows.md",
    "scripts/field-tools/README.md",
    "scripts/field-tools/read-only/diagnose-live-io-detailed.ps1",
    "scripts/field-tools/read-only/diagnose-live-io.ps1",
    "scripts/field-tools/read-only/diagnose-live-job.ps1",
    "scripts/field-tools/read-only/diagnose-storeopen-mappings.ps1",
    "scripts/field-tools/read-only/inspect-antivirus-state.ps1",
    "scripts/field-tools/read-only/inspect-cfa-policy.ps1",
    "scripts/field-tools/read-only/inspect-defender-events.ps1",
    "scripts/field-tools/read-only/inspect-plan-state.ps1",
    "scripts/field-tools/read-only/inspect-run-lock.ps1",
    "scripts/field-tools/read-only/inspect-runtime-capabilities.ps1",
    "scripts/field-tools/read-only/inspect-storeopen-installation.ps1",
    "scripts/field-tools/read-only/inspect-storeopen-tools.ps1",
    "scripts/field-tools/read-only/inspect-tape-pnp-and-storeopen.ps1",
    "scripts/field-tools/read-only/probe-system-telemetry.ps1",
    "src/ltobackup/winio.py",
    "src/ltobackup/volume_probe.py",
    "src/ltobackup/cli.py",
    "src/ltobackup/__main__.py",
    "src/ltobackup/legacy_guard.py",
    "src/ltobackup/security.py",
    "tests/test_cli.py",
    "tests/test_security.py",
)

REMOVED_MODULES = frozenset(
    {
        "ltobackup.cli",
        "ltobackup.__main__",
        "ltobackup.gui",
        "ltobackup.legacy_guard",
        "ltobackup.security",
        "ltobackup.volume_probe",
        "ltobackup.winio",
    }
)


def _imported_modules(source: str, *, package: str) -> set[str]:
    imported: set[str] = set()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = "." * node.level + (node.module or "")
                resolved = importlib.util.resolve_name(base, package)
            else:
                resolved = node.module or ""
            if node.module:
                imported.add(resolved)
            imported.update(f"{resolved}.{alias.name}" for alias in node.names)
    return imported


def _imports_from(path: Path) -> set[str]:
    package = ".".join(path.relative_to(ROOT / "src").parent.parts)
    return _imported_modules(path.read_text(encoding="utf-8"), package=package)


class LinuxSourceBoundaryTests(unittest.TestCase):
    def test_import_parser_covers_direct_relative_and_from_package_forms(self) -> None:
        imported = _imported_modules(
            """
import ltobackup.security
from .legacy_guard import ensure_legacy_allowed
from . import volume_probe
from ltobackup import winio
""",
            package="ltobackup",
        )
        self.assertTrue(
            {
                "ltobackup.security",
                "ltobackup.legacy_guard",
                "ltobackup.volume_probe",
                "ltobackup.winio",
            }.issubset(imported)
        )

    def test_windows_only_leaves_are_absent_from_source_checkout(self) -> None:
        for relative in REMOVED_PATHS:
            with self.subTest(path=relative):
                self.assertFalse((ROOT / relative).exists())

    def test_surviving_runtime_does_not_import_removed_modules(self) -> None:
        removed_files = {ROOT / relative for relative in REMOVED_PATHS}
        for path in sorted((ROOT / "src/ltobackup").rglob("*.py")):
            if path in removed_files:
                continue
            imported = _imports_from(path)
            forbidden = {
                module
                for module in imported
                if any(
                    module == removed or module.startswith(f"{removed}.")
                    for removed in REMOVED_MODULES
                )
            }
            with self.subTest(path=path.relative_to(ROOT)):
                self.assertEqual(set(), forbidden)


if __name__ == "__main__":
    unittest.main()
