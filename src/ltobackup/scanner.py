from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from .catalog import Catalog
from .errors import ValidationError
from .filemeta import collect_file_metadata
from .models import InventoryEntry, LibraryAnalysis, ScanItem, ScanPlan
from .util import sha256_file


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def scan_library(
    catalog: Catalog,
    library_id: str,
    min_age_seconds: int,
    now_ns: int | None = None,
    verify_unchanged_content: bool = False,
    buffer_bytes: int = 16 * 1024**2,
) -> ScanPlan:
    analysis = analyze_library(
        catalog,
        library_id,
        min_age_seconds,
        now_ns=now_ns,
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
) -> LibraryAnalysis:
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
            if not _is_reparse_point(directory_path / name)
        ]
        for file_name in file_names:
            source_path = directory_path / file_name
            if source_path.is_symlink() or _is_reparse_point(source_path):
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
                    f"Collisione maiuscole/minuscole non rappresentabile su Windows: "
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
            file_metadata = None
            if source_stat.st_mtime_ns > threshold_ns:
                status = "too_recent"
                too_recent_files += 1
                too_recent_bytes += source_stat.st_size
            elif (
                previous
                and previous["size"] == source_stat.st_size
                and previous["mtime_ns"] == source_stat.st_mtime_ns
                and (
                    not verify_unchanged_content
                    or sha256_file(source_path, buffer_bytes) == previous["sha256"]
                )
            ):
                status = "archived"
                archived_files += 1
                archived_bytes += source_stat.st_size
                if previous["metadata_state"] == "legacy":
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

    catalog.update_file_metadata_batch(metadata_updates)
    items.sort(key=lambda item: item.relative_path.casefold())
    entries.sort(key=lambda item: item.relative_path.casefold())
    extension_counts = tuple(
        (extension, values[0], values[1])
        for extension, values in sorted(
            extensions.items(), key=lambda pair: (-pair[1][1], pair[0].casefold())
        )
    )
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
    )
