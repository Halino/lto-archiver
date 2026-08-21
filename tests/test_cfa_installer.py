from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIGURATOR = ROOT / "scripts" / "configure-controlled-folder-access.ps1"


def _ps_literal(value: str | Path) -> str:
    return "'" + str(value).replace("'", "''") + "'"


class ControlledFolderAccessInstallerTests(unittest.TestCase):
    def _run_wrapper(self, body: str) -> dict:
        with tempfile.TemporaryDirectory() as temporary:
            wrapper = Path(temporary) / "run-test.ps1"
            wrapper.write_text(
                "$ErrorActionPreference = 'Stop'\n" + body,
                encoding="utf-8-sig",
            )
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(wrapper),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=30,
            )
        self.assertEqual(0, completed.returncode, completed.stderr or completed.stdout)
        return json.loads(completed.stdout.lstrip("\ufeff"))

    def test_active_cfa_adds_and_verifies_only_missing_application_paths(self) -> None:
        gui = r"C:\Program Files\LtoBackupManager\LtoBackupManager.exe"
        cli = r"C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe"
        result = self._run_wrapper(
            f"""
$global:Allowed = @({_ps_literal(gui)})
$global:Added = @()
function Get-MpPreference {{
    [pscustomobject]@{{
        EnableControlledFolderAccess = 1
        ControlledFolderAccessAllowedApplications = @($global:Allowed)
    }}
}}
function Add-MpPreference {{
    param([string[]]$ControlledFolderAccessAllowedApplications)
    $global:Added = @($ControlledFolderAccessAllowedApplications)
    $global:Allowed += @($ControlledFolderAccessAllowedApplications)
}}
$result = & {_ps_literal(CONFIGURATOR)} -ApplicationPaths @({_ps_literal(gui)}, {_ps_literal(cli)})
[ordered]@{{
    status = $result.Status
    added = @($global:Added)
    allowed = @($global:Allowed)
}} | ConvertTo-Json -Compress
"""
        )

        self.assertEqual("configured", result["status"])
        self.assertEqual([cli], result["added"])
        self.assertEqual([gui, cli], result["allowed"])

    def test_already_allowed_paths_do_not_change_defender_again(self) -> None:
        gui = r"C:\Program Files\LtoBackupManager\LtoBackupManager.exe"
        cli = r"C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe"
        result = self._run_wrapper(
            f"""
$global:Allowed = @({_ps_literal(gui)}, {_ps_literal(cli)})
function Get-MpPreference {{
    [pscustomobject]@{{
        EnableControlledFolderAccess = 1
        ControlledFolderAccessAllowedApplications = @($global:Allowed)
    }}
}}
function Add-MpPreference {{ throw 'Add-MpPreference non doveva essere chiamato' }}
$result = & {_ps_literal(CONFIGURATOR)} -ApplicationPaths @({_ps_literal(gui)}, {_ps_literal(cli)})
[ordered]@{{ status = $result.Status }} | ConvertTo-Json -Compress
"""
        )

        self.assertEqual("already_configured", result["status"])

    def test_explicit_skip_does_not_query_or_change_defender(self) -> None:
        gui = r"C:\Program Files\LtoBackupManager\LtoBackupManager.exe"
        cli = r"C:\Program Files\LtoBackupManager\LtoBackupManagerCli.exe"
        result = self._run_wrapper(
            f"""
function Get-MpPreference {{ throw 'Defender non doveva essere interrogato' }}
function Add-MpPreference {{ throw 'Defender non doveva essere modificato' }}
$result = & {_ps_literal(CONFIGURATOR)} -ApplicationPaths @({_ps_literal(gui)}, {_ps_literal(cli)}) -Skip
[ordered]@{{ status = $result.Status }} | ConvertTo-Json -Compress
"""
        )

        self.assertEqual("skipped", result["status"])


if __name__ == "__main__":
    unittest.main()
