from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from ltobackup.security import ensure_controlled_folder_access


class ControlledFolderAccessTests(unittest.TestCase):
    def test_enabled_cfa_adds_only_the_two_installed_executables(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary) / "Owner's Tape"
            install.mkdir()
            gui = install / "LtoBackupManager.exe"
            cli = install / "LtoBackupManagerCli.exe"
            gui.write_bytes(b"gui")
            cli.write_bytes(b"cli")
            responses = iter([
                subprocess.CompletedProcess([], 0, json.dumps({"mode": 1, "allowed": []}), ""),
                subprocess.CompletedProcess([], 0, "", ""),
                subprocess.CompletedProcess(
                    [], 0, json.dumps({"mode": 1, "allowed": [str(gui), str(cli)]}), ""
                ),
            ])
            calls: list[list[str]] = []

            def run(command, **_kwargs):
                calls.append(command)
                return next(responses)

            result = ensure_controlled_folder_access(gui, run=run, platform_name="nt")

        self.assertEqual("allowed", result.status)
        self.assertEqual(3, len(calls))
        command = " ".join(calls[1])
        self.assertIn("Add-MpPreference -ControlledFolderAccessAllowedApplications", command)
        self.assertIn(str(gui).replace("'", "''"), command)
        self.assertIn(str(cli).replace("'", "''"), command)
        self.assertNotIn("ExclusionPath", command)
        self.assertNotIn("DisableRealtimeMonitoring", command)
        self.assertNotIn("Set-MpPreference", command)
        self.assertNotIn("-EncodedCommand", calls[1])

    def test_already_allowed_cfa_does_not_request_another_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary)
            gui = install / "LtoBackupManager.exe"
            cli = install / "LtoBackupManagerCli.exe"
            gui.write_bytes(b"gui")
            cli.write_bytes(b"cli")
            calls: list[list[str]] = []

            def run(command, **_kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(
                    command,
                    0,
                    json.dumps({"mode": 1, "allowed": [str(gui), str(cli)]}),
                    "",
                )

            result = ensure_controlled_folder_access(gui, run=run, platform_name="nt")

        self.assertEqual("already_allowed", result.status)
        self.assertEqual(1, len(calls))

    def test_disabled_cfa_is_left_disabled_without_changing_defender(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install = Path(temporary)
            gui = install / "LtoBackupManager.exe"
            cli = install / "LtoBackupManagerCli.exe"
            gui.write_bytes(b"gui")
            cli.write_bytes(b"cli")
            calls: list[list[str]] = []

            def run(command, **_kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(
                    command, 0, json.dumps({"mode": 0, "allowed": []}), ""
                )

            result = ensure_controlled_folder_access(gui, run=run, platform_name="nt")

        self.assertEqual("disabled", result.status)
        self.assertEqual(1, len(calls))


if __name__ == "__main__":
    unittest.main()
