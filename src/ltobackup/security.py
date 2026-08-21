from __future__ import annotations

import json
import ntpath
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


PowerShellRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ControlledFolderAccessResult:
    status: str
    detail: str = ""


_POWERSHELL = str(
    Path(os.environ.get("SystemRoot", r"C:\Windows"))
    / "System32"
    / "WindowsPowerShell"
    / "v1.0"
    / "powershell.exe"
)


def _powershell_command(script: str, *arguments: str) -> list[str]:
    return [
        _POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
        *arguments,
    ]


def _run_powershell(
    script: str,
    *arguments: str,
    run: PowerShellRunner,
) -> subprocess.CompletedProcess[str]:
    return run(
        _powershell_command(script, *arguments),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _path_key(value: str | Path) -> str:
    return ntpath.normcase(ntpath.normpath(str(value).strip().strip('"')))


def _powershell_literal(value: str | Path) -> str:
    text = str(value)
    if any(character in text for character in ("\x00", "\r", "\n")):
        raise ValueError("Percorso eseguibile non valido")
    return "'" + text.replace("'", "''") + "'"


def _query_cfa(run: PowerShellRunner) -> tuple[int, set[str]]:
    script = (
        "$ErrorActionPreference='Stop'; $p=Get-MpPreference; "
        "[ordered]@{mode=[int]$p.EnableControlledFolderAccess;"
        "allowed=@($p.ControlledFolderAccessAllowedApplications)} | "
        "ConvertTo-Json -Compress"
    )
    completed = _run_powershell(script, run=run)
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
        raise RuntimeError(f"lettura Controlled Folder Access fallita: {detail}")
    payload = json.loads(completed.stdout.lstrip("\ufeff"))
    allowed = payload.get("allowed") or []
    if isinstance(allowed, str):
        allowed = [allowed]
    return int(payload.get("mode") or 0), {_path_key(value) for value in allowed}


def ensure_controlled_folder_access(
    gui_executable: Path | None = None,
    *,
    run: PowerShellRunner = subprocess.run,
    platform_name: str = os.name,
) -> ControlledFolderAccessResult:
    """Allow only the installed GUI and CLI through Defender CFA when enabled.

    The packaged GUI already requests administrative elevation through its
    manifest. Defender remains enabled and no scan or folder exclusion is made.
    """

    if platform_name != "nt":
        return ControlledFolderAccessResult("not_applicable")
    gui = Path(gui_executable or sys.executable)
    if gui.name.casefold() != "ltobackupmanager.exe":
        return ControlledFolderAccessResult("not_installed")
    cli = gui.with_name("LtoBackupManagerCli.exe")
    if not gui.is_file() or not cli.is_file():
        return ControlledFolderAccessResult(
            "failed", "Eseguibili installati incompleti: autorizzazione CFA non applicata"
        )

    requested = {_path_key(gui), _path_key(cli)}
    try:
        mode, allowed = _query_cfa(run)
        if mode != 1:
            return ControlledFolderAccessResult("disabled")
        if requested.issubset(allowed):
            return ControlledFolderAccessResult("already_allowed")

        paths = ",".join(_powershell_literal(path) for path in (gui, cli))
        script = (
            f"$Paths=@({paths}); $ErrorActionPreference='Stop'; "
            "Add-MpPreference -ControlledFolderAccessAllowedApplications $Paths"
        )
        completed = _run_powershell(script, run=run)
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
            return ControlledFolderAccessResult(
                "failed", f"autorizzazione Controlled Folder Access fallita: {detail}"
            )
        verified_mode, verified = _query_cfa(run)
        if verified_mode == 1 and requested.issubset(verified):
            return ControlledFolderAccessResult("allowed")
        return ControlledFolderAccessResult(
            "failed", "Defender non ha confermato l'autorizzazione Controlled Folder Access"
        )
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        return ControlledFolderAccessResult("failed", str(exc))
