from __future__ import annotations

import os
import shutil
from pathlib import Path

from .errors import ValidationError
from .models import VolumeInfo


def volume_root(path: Path) -> Path:
    return Path(os.path.abspath(path))


def inspect_volume(path: Path, timeout_seconds: float = 30) -> VolumeInfo:
    root = volume_root(path)
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
