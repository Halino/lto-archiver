#!/usr/bin/python3.11
"""Relabel the closed set of stable generic-SCSI aliases."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from collections.abc import Callable, Sequence
from pathlib import Path

RESTORECON = "/usr/sbin/restorecon"
_ALIAS_PREFIX = "lto-archiver-scsi-"
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        metadata.st_ctime_ns,
    )


def relabel_device_aliases(
    device_root: Path = Path("/dev"),
    *,
    run_command: Callable[..., subprocess.CompletedProcess[object]] = subprocess.run,
) -> None:
    """Relabel direct stable aliases and reject ambiguous matching entries."""

    if not isinstance(device_root, Path) or not device_root.is_absolute():
        raise RuntimeError("device root must be an absolute path")

    directory_fd = -1
    try:
        directory_fd = os.open(device_root, _DIRECTORY_FLAGS)
        names = sorted(os.listdir(directory_fd))
        aliases: list[tuple[str, os.stat_result]] = []
        for name in names:
            if not name.startswith(_ALIAS_PREFIX):
                continue
            if name == _ALIAS_PREFIX or "/" in name:
                raise RuntimeError("invalid stable device alias")

            before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISLNK(before.st_mode):
                raise RuntimeError("stable device alias is not a link")
            aliases.append((name, before))

        for name, before in aliases:
            alias = device_root / name
            completed = run_command((RESTORECON, "-F", "--", str(alias)), check=True)
            if completed.returncode != 0:
                raise RuntimeError("stable device alias relabel command failed")

            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if _identity(after) != _identity(before):
                raise RuntimeError("stable device alias changed during relabel")
    except (OSError, subprocess.SubprocessError, TypeError, ValueError) as error:
        raise RuntimeError("stable device alias relabel failed") from error
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = tuple(sys.argv[1:] if argv is None else argv)
    if arguments:
        print("usage: relabel-device-aliases.py", file=sys.stderr)
        return 2
    try:
        relabel_device_aliases()
    except RuntimeError:
        print("stable device alias relabel failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
