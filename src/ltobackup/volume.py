from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple

from .errors import ValidationError
from .models import VolumeInfo


class _ProbeResult(NamedTuple):
    returncode: int
    stdout: str
    stderr: str


def _volume_probe_command(root: Path) -> list[str]:
    if getattr(sys, "frozen", False):
        helper = Path(sys.executable).with_name("LtoBackupManagerCli.exe")
        return [str(helper), "--internal-volume-probe", str(root)]
    return [sys.executable, "-m", "ltobackup.volume_probe", str(root)]


def _terminate_probe_tree(process: subprocess.Popen[str]) -> str | None:
    """Terminate the frozen probe bootloader and all of its descendants."""
    try:
        terminated = subprocess.run(
            ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        try:
            process.kill()
        except OSError:
            pass
        return f"arresto dell'albero del probe non riuscito: {exc}"
    if terminated.returncode:
        detail = (terminated.stderr or terminated.stdout or "errore non specificato").strip()
        try:
            process.kill()
        except OSError:
            pass
        return f"arresto dell'albero del probe non riuscito: {detail}"
    return None


def _run_volume_probe(command: list[str], timeout_seconds: float) -> _ProbeResult:
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as exc:
        cleanup_error = _terminate_probe_tree(process)
        try:
            process.communicate(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass
        suffix = f"; {cleanup_error}" if cleanup_error else ""
        raise ValidationError(
            f"Il probe del volume non risponde entro {timeout_seconds:g} secondi{suffix}"
        ) from exc
    return _ProbeResult(int(process.returncode or 0), stdout, stderr)


def volume_root(path: Path) -> Path:
    absolute = Path(os.path.abspath(path))
    if os.name == "nt":
        if not absolute.drive:
            raise ValidationError(f"Il mount LTFS deve avere una lettera di unità: {path}")
        return Path(absolute.drive + "\\")
    return absolute


def inspect_volume(path: Path, timeout_seconds: float = 30) -> VolumeInfo:
    root = volume_root(path)
    if os.name == "nt":
        command = _volume_probe_command(root)
        try:
            completed = _run_volume_probe(command, timeout_seconds)
        except ValidationError as exc:
            raise ValidationError(
                f"Il volume {root} non risponde entro {timeout_seconds:g} secondi. "
                f"Dettaglio: {exc}"
            ) from exc
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
            raise ValidationError(
                f"Impossibile leggere le informazioni del volume {root}: {detail}"
            )
        try:
            payload = json.loads(completed.stdout.strip())
            return VolumeInfo(
                root=root,
                filesystem=str(payload["filesystem"]).upper(),
                label=str(payload["label"]),
                serial=str(payload["serial"]),
                total_bytes=int(payload["total_bytes"]),
                free_bytes=int(payload["free_bytes"]),
                ltfs_data_total_bytes=(
                    int(payload["ltfs_data_total_bytes"])
                    if payload.get("ltfs_data_total_bytes") is not None else None
                ),
                ltfs_data_free_bytes=(
                    int(payload["ltfs_data_free_bytes"])
                    if payload.get("ltfs_data_free_bytes") is not None else None
                ),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValidationError(
                f"Risposta non valida durante l'ispezione del volume {root}"
            ) from exc

    if not root.exists():
        raise ValidationError(f"Mount non accessibile: {root}")
    usage = shutil.disk_usage(root)

    return VolumeInfo(
        root=root,
        filesystem="UNKNOWN",
        label=root.name,
        serial="UNKNOWN",
        total_bytes=usage.total,
        free_bytes=usage.free,
    )


def require_ltfs(volume: VolumeInfo) -> None:
    if volume.filesystem.upper() != "LTFS":
        raise ValidationError(
            f"Il volume {volume.root} usa {volume.filesystem}, non LTFS. Nessun dato è stato scritto."
        )


def assert_registered_tape(tape: object, volume: VolumeInfo) -> None:
    expected_label = str(tape["volume_label"])  # sqlite3.Row or mapping
    expected_filesystem = str(tape["filesystem"])
    if (
        expected_filesystem.casefold() == "ltfs"
        and volume.filesystem.casefold() == "ltfs"
        and expected_label.strip()
    ):
        if expected_label.casefold() != volume.label.casefold():
            raise ValidationError(
                f"Nastro errato: attesa etichetta LTFS {expected_label}, "
                f"montata {volume.label} (seriale Win32 {volume.serial})"
            )
        return
    expected_serial = str(tape["volume_serial"])
    if expected_serial != volume.serial:
        raise ValidationError(
            f"Nastro errato: atteso seriale {expected_serial}, "
            f"montato {volume.serial} ({volume.label})"
        )
