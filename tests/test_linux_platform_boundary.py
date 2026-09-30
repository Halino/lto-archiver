from __future__ import annotations

import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = PROJECT_ROOT / "src" / "ltobackup"


class LinuxPlatformBoundaryTests(unittest.TestCase):
    def test_windows_runtime_modules_are_absent(self) -> None:
        for module_name in ("winio.py", "volume_probe.py"):
            with self.subTest(module_name=module_name):
                self.assertFalse((PACKAGE_ROOT / module_name).exists())

    def test_platform_modules_do_not_reference_native_windows_runtime(self) -> None:
        forbidden_fragments = (
            "ctypes",
            "WinDLL",
            "windll",
            "wintypes",
            "kernel32",
            "advapi32",
            "CREATE_NO_WINDOW",
            "taskkill",
            "PROGRAMDATA",
            "msvcrt",
            "volume_probe",
            ".winio",
        )
        for module_name in ("util.py", "filemeta.py", "volume.py", "settings.py"):
            source = (PACKAGE_ROOT / module_name).read_text(encoding="utf-8")
            for fragment in forbidden_fragments:
                with self.subTest(module_name=module_name, fragment=fragment):
                    if fragment in source:
                        self.fail(f"{module_name} still references {fragment!r}")


if __name__ == "__main__":
    unittest.main()
