from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class VolumeInfo:
    root: Path
    filesystem: str
    label: str
    serial: str
    total_bytes: int
    free_bytes: int
    ltfs_data_total_bytes: int | None = None
    ltfs_data_free_bytes: int | None = None


@dataclass(frozen=True)
class ScanItem:
    source_path: Path
    relative_path: str
    size: int
    mtime_ns: int
    library_id: str | None = None
    metadata: dict[str, Any] | None = None
    source_identity: tuple[int, int, int, int, int] | None = None
    tape_relative_path: str | None = None


@dataclass(frozen=True)
class ScanPlan:
    library_id: str
    source_root: Path
    items: tuple[ScanItem, ...]
    skipped_unchanged: int = 0
    skipped_too_recent: int = 0
    source_files: int = 0
    source_bytes: int = 0
    total_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "total_bytes", sum(item.size for item in self.items))


@dataclass(frozen=True)
class TapeBatch:
    slot: int
    items: tuple[ScanItem, ...]
    usable_bytes: int
    capacity_used_bytes: int | None = None
    total_bytes: int = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "total_bytes", sum(item.size for item in self.items))
        if self.capacity_used_bytes is None:
            object.__setattr__(self, "capacity_used_bytes", self.total_bytes)

    @property
    def remaining_bytes(self) -> int:
        assert self.capacity_used_bytes is not None
        return self.usable_bytes - self.capacity_used_bytes


@dataclass(frozen=True)
class InventoryEntry:
    relative_path: str
    size: int
    mtime_ns: int
    status: str
    tape_id: str | None = None
    cassette_number: str | None = None


@dataclass(frozen=True)
class LibraryAnalysis:
    library_id: str
    source_root: Path
    entries: tuple[InventoryEntry, ...]
    pending_items: tuple[ScanItem, ...]
    total_files: int
    total_bytes: int
    archived_files: int
    archived_bytes: int
    too_recent_files: int
    too_recent_bytes: int
    extension_counts: tuple[tuple[str, int, int], ...]
    listing_truncated: bool = False
    legacy_uncovered_files: int = 0


@dataclass(frozen=True)
class BackupResult:
    block_id: str
    tape_id: str
    library_id: str
    copied_files: int
    copied_bytes: int
    tape_relative_root: str
    remaining_files: int = 0
    remaining_bytes: int = 0
    estimated_remaining_tapes: int = 0


@dataclass(frozen=True)
class RestoreTapePlan:
    tape_id: str
    file_count: int
    total_bytes: int
