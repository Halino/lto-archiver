from __future__ import annotations

from pathlib import Path
from typing import Any


def usable_change_ns(value: object) -> int | None:
    return value if type(value) is int and value > 0 else None


def collect_file_metadata(path: Path, source_stat=None) -> dict[str, Any]:
    """Collect portable metadata without making backup depend on it."""
    details = source_stat or path.stat()
    return {
        "created_ns": int(getattr(details, "st_birthtime_ns", details.st_ctime_ns)),
        "source_change_ns": usable_change_ns(getattr(details, "st_ctime_ns", None)),
        "accessed_ns": int(details.st_atime_ns),
        "source_mode": int(details.st_mode),
        "windows_attributes": None,
        "owner_name": None,
        "owner_sid": None,
        "security_descriptor": None,
        "alternate_streams": [],
        "metadata_state": "complete",
        "metadata_error": None,
    }
