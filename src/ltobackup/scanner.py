from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from .catalog import Catalog
from .errors import ValidationError
from .filemeta import collect_file_metadata, usable_change_ns
from .models import InventoryEntry, LibraryAnalysis, ScanItem, ScanPlan
from .util import sha256_file


def scan_library(
    catalog: Catalog,
    library_id: str,
    min_age_seconds: int,
    now_ns: int | None = None,
    verify_unchanged_content: bool = False,
    buffer_bytes: int = 16 * 1024**2,
    *,
    source_change_detection_policy: str = "size_mtime",
) -> ScanPlan:
    analysis = analyze_library(
        catalog,
        library_id,
        min_age_seconds,
        now_ns=now_ns,
        source_change_detection_policy=source_change_detection_policy,
        listing_limit=0,
        verify_unchanged_content=verify_unchanged_content,
        buffer_bytes=buffer_bytes,
    )
    return ScanPlan(
        library_id=library_id,
        source_root=analysis.source_root,
        items=analysis.pending_items,
        skipped_unchanged=analysis.archived_files,
        skipped_too_recent=analysis.too_recent_files,
        source_files=analysis.total_files,
        source_bytes=analysis.total_bytes,
    )


def analyze_library(
    catalog: Catalog,
    library_id: str,
    min_age_seconds: int,
    now_ns: int | None = None,
    listing_limit: int = 5000,
    verify_unchanged_content: bool = False,
    buffer_bytes: int = 16 * 1024**2,
    persist_catalog_updates: bool = True,
    *,
    source_change_detection_policy: str = "size_mtime",
) -> LibraryAnalysis:
    if source_change_detection_policy not in {"size_mtime", "size_mtime_change"}:
        raise ValidationError("invalid source change detection policy")
    if listing_limit < 0:
        raise ValidationError("listing_limit non puo essere negativo")
    library = catalog.get_library(library_id)
    source_root = Path(library["source_root"])
    if not source_root.is_dir():
        raise ValidationError(f"Sorgente libreria non accessibile: {source_root}")

    latest = catalog.latest_versions(library_id)
    threshold_ns = (now_ns if now_ns is not None else time.time_ns()) - min_age_seconds * 1_000_000_000
    tape_locations = {row["id"]: row["cassette_number"] for row in catalog.list_tapes()}
    items: list[ScanItem] = []
    entries: list[InventoryEntry] = []
    total_files = 0
    total_bytes = 0
    archived_files = 0
    archived_bytes = 0
    too_recent_files = 0
    too_recent_bytes = 0
    legacy_uncovered_files = 0
    extensions: dict[str, list[int]] = {}
    seen_casefold: dict[str, str] = {}
    metadata_updates: list[tuple[int, dict]] = []

    def on_error(error: OSError) -> None:
        raise ValidationError(f"Errore leggendo la sorgente {source_root}: {error}") from error

    for directory, directory_names, file_names in os.walk(source_root, topdown=True, onerror=on_error):
        directory_path = Path(directory)
        directory_names[:] = [
            name
            for name in directory_names
            if not (directory_path / name).is_symlink()
        ]
        for file_name in file_names:
            source_path = directory_path / file_name
            if source_path.is_symlink():
                continue
            try:
                source_stat = source_path.stat()
            except OSError as exc:
                raise ValidationError(f"Impossibile leggere {source_path}: {exc}") from exc
            if not stat.S_ISREG(source_stat.st_mode):
                continue
            relative_path = source_path.relative_to(source_root).as_posix()
            folded = relative_path.casefold()
            if folded in seen_casefold and seen_casefold[folded] != relative_path:
                raise ValidationError(
                    f"Collisione maiuscole/minuscole non portabile: "
                    f"{seen_casefold[folded]} e {relative_path}"
                )
            seen_casefold[folded] = relative_path
            total_files += 1
            total_bytes += source_stat.st_size
            suffix = source_path.suffix.lower() or "(senza estensione)"
            extension = extensions.setdefault(suffix, [0, 0])
            extension[0] += 1
            extension[1] += source_stat.st_size
            previous = latest.get(relative_path)
            unchanged_metadata = bool(
                previous
                and previous["size"] == source_stat.st_size
                and previous["mtime_ns"] == source_stat.st_mtime_ns
            )
            if unchanged_metadata and source_change_detection_policy == "size_mtime_change":
                archived_change = usable_change_ns(previous["source_change_ns"])
                observed_change = usable_change_ns(getattr(source_stat, "st_ctime_ns", None))
                if archived_change is not None and observed_change is not None:
                    unchanged_metadata = archived_change == observed_change
            file_metadata = None
            if source_stat.st_mtime_ns > threshold_ns:
                status = "too_recent"
                too_recent_files += 1
                too_recent_bytes += source_stat.st_size
            elif unchanged_metadata and (
                not verify_unchanged_content
                or sha256_file(source_path, buffer_bytes) == previous["sha256"]
            ):
                status = "archived"
                archived_files += 1
                archived_bytes += source_stat.st_size
                if source_change_detection_policy == "size_mtime_change" and (
                    usable_change_ns(previous["source_change_ns"]) is None
                    or usable_change_ns(getattr(source_stat, "st_ctime_ns", None)) is None
                ):
                    legacy_uncovered_files += 1
                if persist_catalog_updates and previous["metadata_state"] == "legacy":
                    metadata_updates.append(
                        (previous["id"], collect_file_metadata(source_path, source_stat))
                    )
            else:
                status = "pending"
                file_metadata = collect_file_metadata(source_path, source_stat)
                items.append(ScanItem(
                    source_path=source_path,
                    relative_path=relative_path,
                    size=source_stat.st_size,
                    mtime_ns=source_stat.st_mtime_ns,
                    metadata=file_metadata,
                ))
            if listing_limit and len(entries) < listing_limit:
                entries.append(InventoryEntry(
                    relative_path=relative_path,
                    size=source_stat.st_size,
                    mtime_ns=source_stat.st_mtime_ns,
                    status=status,
                    tape_id=previous["tape_id"] if status == "archived" else None,
                    cassette_number=tape_locations.get(previous["tape_id"]) if status == "archived" else None,
                ))

    if persist_catalog_updates:
        catalog.update_file_metadata_batch(metadata_updates)
    items.sort(key=lambda item: item.relative_path.casefold())
    entries.sort(key=lambda item: item.relative_path.casefold())
    extension_counts = tuple(
        (extension, values[0], values[1])
        for extension, values in sorted(
            extensions.items(), key=lambda pair: (-pair[1][1], pair[0].casefold())
        )
    )
    if persist_catalog_updates:
        catalog.update_library_scan(library_id, total_files, total_bytes)
    return LibraryAnalysis(
        library_id=library_id,
        source_root=source_root,
        entries=tuple(entries),
        pending_items=tuple(items),
        total_files=total_files,
        total_bytes=total_bytes,
        archived_files=archived_files,
        archived_bytes=archived_bytes,
        too_recent_files=too_recent_files,
        too_recent_bytes=too_recent_bytes,
        extension_counts=extension_counts,
        listing_truncated=listing_limit > 0 and total_files > listing_limit,
        legacy_uncovered_files=legacy_uncovered_files,
    )
