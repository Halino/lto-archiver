"""Side-effect-free planning of the never-started suffix at a tape boundary.

This module has no hardware or catalog mutation interface. Its result is a
candidate, not permission to replace a manifest: the boundary coordinator must
prove quiescence, source identity, snapshot freshness and authority at commit.
"""

from __future__ import annotations

import stat
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from ..catalog import Catalog
from ..errors import ValidationError
from ..models import ScanItem, TapeBatch
from ..planner import capacity_model_for_media, plan_tape_batches
from ..scanner import analyze_library
from ..util import validate_source_relative_path


@dataclass(frozen=True)
class BoundaryCassette:
    sequence: int
    label: str
    status: str
    operation: str
    attempted: bool = False


@dataclass(frozen=True)
class BoundaryAssignment:
    sequence: int
    label: str
    items: tuple[ScanItem, ...]


@dataclass(frozen=True)
class BoundaryPlan:
    completed_sequence: int
    assignments: tuple[BoundaryAssignment, ...]
    unassigned_batches: tuple[TapeBatch, ...]

    @property
    def required_additional_labels(self) -> int:
        return len(self.unassigned_batches)

    @property
    def ready(self) -> bool:
        return not self.unassigned_batches


def _source_key(item: ScanItem) -> tuple[str, str]:
    if not isinstance(item.library_id, str) or not item.library_id:
        raise ValidationError("boundary scan item has no library")
    validate_source_relative_path(item.relative_path)
    if type(item.size) is not int or item.size < 0 or type(item.mtime_ns) is not int:
        raise ValidationError("boundary scan item metadata is invalid")
    return item.library_id.casefold(), item.relative_path.casefold()


def _version(item: ScanItem) -> tuple[str, str, int, int]:
    return (*_source_key(item), item.size, item.mtime_ns)


def plan_pending_suffix(
    *,
    cassettes: tuple[BoundaryCassette, ...],
    scanned_items: tuple[ScanItem, ...],
    completed_versions: tuple[ScanItem, ...],
    usable_bytes: int,
    nominal_capacity_bytes: int,
) -> BoundaryPlan:
    """Map fresh eligible versions to existing labels without dropping overflow.

    The caller must provide a complete, successfully verified scan. A failed
    scan is not an empty scan. Completed versions must come from committed
    catalog/history, never from the disappearing current-manifest rows.
    """
    if not cassettes or cassettes[0].status != "completed":
        raise ValidationError("boundary requires a completed prefix")
    seen_labels: set[str] = set()
    previous = 0
    completed_sequence = 0
    pending: list[BoundaryCassette] = []
    for cassette in cassettes:
        if (
            type(cassette.sequence) is not int
            or cassette.sequence <= previous
            or not cassette.label
            or cassette.label != cassette.label.strip()
            or cassette.label.casefold() in seen_labels
        ):
            raise ValidationError("boundary cassette sequence or label is invalid")
        previous = cassette.sequence
        seen_labels.add(cassette.label.casefold())
        if cassette.status == "completed":
            if pending:
                raise ValidationError("completed cassettes must form a prefix")
            completed_sequence = cassette.sequence
        else:
            if cassette.attempted or cassette.status not in {
                "pending",
                "waiting_media",
            }:
                raise ValidationError("started cassette cannot be replanned")
            if cassette.operation != "format":
                # An append destination already contains data and is not a
                # never-started, full-capacity replacement cartridge.
                raise ValidationError(
                    "boundary suffix must contain unused format targets"
                )
            pending.append(cassette)

    completed = {_version(value) for value in completed_versions}
    source_keys: set[tuple[str, str]] = set()
    eligible = []
    for value in scanned_items:
        key = _source_key(value)
        if key in source_keys:
            raise ValidationError("boundary scan contains duplicate source paths")
        source_keys.add(key)
        if _version(value) not in completed:
            eligible.append(value)
    batches = plan_tape_batches(
        eligible,
        usable_bytes,
        capacity_model=capacity_model_for_media(nominal_capacity_bytes),
    )
    return BoundaryPlan(
        completed_sequence=completed_sequence,
        assignments=tuple(
            BoundaryAssignment(
                cassette.sequence,
                cassette.label,
                batches[index].items if index < len(batches) else (),
            )
            for index, cassette in enumerate(pending)
        ),
        unassigned_batches=batches[len(pending) :],
    )


def scan_boundary_sources(
    catalog: Catalog,
    library_ids: tuple[str, ...],
    *,
    verify_library: Callable[[dict], tuple[str, str]],
    minimum_age_seconds: int,
    verify_unchanged_content: bool = False,
    buffer_bytes: int = 16 * 1024**2,
) -> tuple[ScanItem, ...]:
    """Observe all selected roots without updating catalog or tape state.

    The caller holds the boundary scan lease and managed-source leases. The
    verifier must check each library against the job's pinned identity, not
    simply accept its current path. A failed root invalidates the whole result.
    `analyze_library` excludes already archived versions according to the
    selected content policy; therefore pass no additional metadata-only
    completed-version filter to `plan_pending_suffix` for these results.
    """
    if (
        not library_ids
        or len({key.casefold() for key in library_ids}) != len(library_ids)
        or type(minimum_age_seconds) is not int
        or minimum_age_seconds < 0
    ):
        raise ValidationError("invalid boundary scan selection or file-age policy")
    observed = []
    items = []

    def inspect(library: dict) -> tuple[tuple[str, str], tuple[int, int]]:
        if library.get("status", "active") != "active" or not library.get(
            "enabled", True
        ):
            raise ValidationError("boundary source library is not active")
        identity = verify_library(library)
        root = Path(library["source_root"])
        info = root.lstat()
        if not stat.S_ISDIR(info.st_mode) or root.resolve() != Path(identity[0]):
            raise ValidationError("boundary source root is not the admitted directory")
        return identity, (info.st_dev, info.st_ino)

    for library_id in library_ids:
        library = dict(catalog.get_library(library_id))
        identity = inspect(library)
        analysis = analyze_library(
            catalog,
            library_id,
            minimum_age_seconds,
            listing_limit=0,
            verify_unchanged_content=verify_unchanged_content,
            buffer_bytes=buffer_bytes,
            persist_catalog_updates=False,
        )
        if inspect(library) != identity:
            raise ValidationError("boundary source changed during scan")
        observed.append((library, identity))
        items.extend(
            replace(value, library_id=library_id) for value in analysis.pending_items
        )
    # A slow scan of another root must not hide loss/replacement of an earlier
    # share. All identities are rechecked before publishing any candidate.
    for library, identity in observed:
        if inspect(library) != identity:
            raise ValidationError("boundary source changed before scan completion")
    frozen = []
    roots = {
        str(library["id"]).casefold(): Path(library["source_root"])
        for library, _identity in observed
    }
    for value in items:
        root = roots[str(value.library_id).casefold()]
        current = root
        for part in Path(value.relative_path).parts:
            current = current / part
            if current.is_symlink():
                raise ValidationError("boundary source path contains a symlink")
        info = current.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_size != value.size
            or info.st_mtime_ns != value.mtime_ns
        ):
            raise ValidationError("boundary source file changed before scan completion")
        frozen.append(
            replace(
                value,
                source_identity=(
                    info.st_dev,
                    info.st_ino,
                    info.st_ctime_ns,
                    info.st_size,
                    info.st_mtime_ns,
                ),
            )
        )
    return tuple(frozen)
