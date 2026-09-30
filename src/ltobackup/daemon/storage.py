"""Cached storage metadata for three configured local destinations.

No directory enumeration, database connection, file content read or source scan
is needed for this projection. Filesystem availability is not restore admission.
"""

from __future__ import annotations

import os
import stat
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Literal

from .api_models import StorageFilesystemV1, StorageSummaryV1

StorageRole = Literal["state", "backups", "scratch"]


def _file_size(path: Path, *, missing: int | None = None) -> int | None:
    try:
        details = path.stat(follow_symlinks=False)
    except FileNotFoundError:
        return missing
    except OSError:
        return None
    return details.st_size if stat.S_ISREG(details.st_mode) else None


def _filesystem(path: Path) -> tuple[int | None, int | None, int | None]:
    # A not-yet-created backup directory belongs to its nearest existing parent.
    # Walk only this configured path's ancestors, with a fixed upper bound.
    for _ in range(32):
        try:
            details = path.stat()
        except FileNotFoundError:
            if path.parent == path:
                break
            path = path.parent
            continue
        except OSError:
            break
        if not stat.S_ISDIR(details.st_mode):
            break
        try:
            usage = os.statvfs(path)
        except OSError:
            return details.st_dev, None, None
        total = max(0, usage.f_blocks * usage.f_frsize)
        available = min(total, max(0, usage.f_bavail * usage.f_frsize))
        return details.st_dev, total, available
    return None, None, None


class StorageMonitor:
    def __init__(
        self,
        *,
        catalog_path: Path,
        storage_paths: Mapping[StorageRole, Path],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if set(storage_paths) != {"state", "backups", "scratch"}:
            raise ValueError("storage destinations must be exact")
        self._catalog_path = catalog_path
        self._storage_paths = dict(storage_paths)
        self._clock = clock
        self._lock = Lock()
        self._cached: StorageSummaryV1 | None = None
        self._expires_at = 0.0

    def snapshot(self) -> StorageSummaryV1:
        with self._lock:
            now = self._clock()
            if self._cached is not None and now < self._expires_at:
                return self._cached
            filesystems: dict[int | str, StorageFilesystemV1] = {}
            for role, path in self._storage_paths.items():
                device, total, available = _filesystem(path)
                key = role if device is None else device
                previous = filesystems.get(key)
                roles = (role,) if previous is None else (*previous.roles, role)
                filesystems[key] = StorageFilesystemV1(
                    roles=roles, total_bytes=total, available_bytes=available,
                )
            self._cached = StorageSummaryV1(
                measured_at=datetime.now(UTC).isoformat(timespec="seconds"),
                filesystems=tuple(filesystems.values()),
                catalog_bytes=_file_size(self._catalog_path),
                wal_bytes=_file_size(
                    self._catalog_path.with_name(self._catalog_path.name + "-wal"),
                    missing=0,
                ),
            )
            self._expires_at = self._clock() + 15.0
            return self._cached
