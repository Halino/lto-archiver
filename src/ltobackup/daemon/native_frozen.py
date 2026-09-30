"""Immutable native cassette checkpoint reader used by recovery execution."""

from __future__ import annotations

import json
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from ..catalog import Catalog
from ..errors import CatalogError, ValidationError
from ..filemeta import collect_file_metadata
from ..managed_sources import ManagedSourceAdmissionError
from ..models import ScanItem, ScanPlan
from ..tape.models import ExpectedMedia
from ..util import safe_join, utc_now, validate_source_relative_path
from .sequence_coordinator import SequenceCandidate


class NativeSourceCheckpoint:
    """Persist next-cassette diagnostics without holding a transaction during I/O."""

    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        *,
        daemon_generation: int,
        verify_library: Callable[[SequenceCandidate, dict], tuple[str, str]],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._catalog_factory = catalog_factory
        self._generation = daemon_generation
        self._verify_library = verify_library
        self._clock = clock
        self._retry: tuple[SequenceCandidate, float] | None = None

    def _current(self, catalog: Catalog, candidate: SequenceCandidate) -> bool:
        owner = catalog.current_daemon_fence()
        row = catalog.next_automatic_sequence_candidate()
        return bool(
            owner is not None and owner.generation == self._generation
            and row is not None
            and str(row["job_id"]) == candidate.job_id
            and int(row["cassette_sequence"]) == candidate.cassette_sequence
            and str(row["layout_fingerprint_sha256"]) == candidate.layout_fingerprint_sha256
            and row["authorization_id"] == candidate.authorization_id
        )

    def __call__(self, candidate: SequenceCandidate) -> bool:
        if (self._retry is not None and self._retry[0] == candidate
                and self._clock() < self._retry[1]):
            return False
        with self._catalog_factory() as catalog:
            if not self._current(catalog, candidate):
                return False
            report = inspect_cassette_sources(
                catalog, candidate.job_id, candidate.cassette_sequence,
                verify_library=lambda row: self._verify_library(candidate, row),
            )
            payload = {**report, "layout_fingerprint_sha256": candidate.layout_fingerprint_sha256}
            with catalog.transaction() as db:
                if not self._current(catalog, candidate):
                    return False
                prior = db.execute(
                    "SELECT payload_json FROM job_management_history "
                    "WHERE job_id=? AND action='job.source_check' ORDER BY id DESC LIMIT 1",
                    (candidate.job_id,),
                ).fetchone()
                if prior is None or json.loads(prior["payload_json"]) != payload:
                    catalog._job_history_tx(
                        db, candidate.job_id, "sequence-coordinator", "job.source_check",
                        "source_" + report["state"], payload, occurred_at=utc_now(),
                    )
        ready = report["state"] == "ready"
        self._retry = None if ready else (candidate, self._clock() + 30.0)
        return ready

    @staticmethod
    def latest(catalog: Catalog, job_id: str) -> dict | None:
        row = catalog.connection.execute(
            "SELECT payload_json,occurred_at FROM job_management_history "
            "WHERE job_id=? AND action='job.source_check' ORDER BY id DESC LIMIT 1",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        report = json.loads(row["payload_json"])
        epoch = catalog.latest_layout_epoch(job_id)
        if epoch is None or report.pop("layout_fingerprint_sha256") != epoch["layout_fingerprint_sha256"]:
            return None
        return {**report, "checked_at": str(row["occurred_at"])}


def inspect_cassette_sources(
    catalog: Catalog,
    job_id: str,
    sequence: int,
    *,
    verify_library: Callable[[dict], tuple[str, str]],
) -> dict:
    """Observe only a frozen cassette's metadata, never scan or change its layout.

    Library identity is checked on both sides of each group. A disappearing
    share invalidates the group's observations rather than inventing deletions.
    This early diagnostic does not replace the worker's leased source admission
    or its before/after-copy identity checks.
    """
    if catalog.get_import_policy(job_id) is not None:
        raise ValidationError("imported jobs cannot use native source inspection")
    cassettes = [row for row in catalog.list_automatic_cassettes(job_id)
                 if int(row["sequence"]) == sequence]
    manifest = tuple(catalog.list_automatic_cassette_manifest(job_id, sequence))
    if (
        len(cassettes) != 1
        or len(manifest) != int(cassettes[0]["planned_files"])
        or sum(int(row["size"]) for row in manifest) != int(cassettes[0]["planned_bytes"])
        or tuple(int(row["item_sequence"]) for row in manifest)
        != tuple(range(1, len(manifest) + 1))
    ):
        raise CatalogError("native source inspection manifest is inexact")
    linked = {str(row["library_id"]) for row in catalog.list_automatic_job_libraries(job_id)}
    groups: dict[str, list] = {}
    for row in manifest:
        try:
            validate_source_relative_path(row["relative_path"])
        except ValidationError as exc:
            raise CatalogError("native source inspection manifest path is invalid") from exc
        library_id = str(row["library_id"])
        if library_id not in linked:
            raise CatalogError("native source inspection library is not admitted")
        groups.setdefault(library_id, []).append(row)
    report = {
        "cassette_sequence": sequence,
        "state": "ready",
        "checked_files": 0,
        "missing_files": 0,
        "changed_files": 0,
        "unavailable_libraries": 0,
        "issues": [],
    }
    for library_id, rows in groups.items():
        issues = []
        missing = changed = 0
        library = dict(catalog.get_library(library_id))
        try:
            identity = verify_library(library)
            root = Path(identity[0])
            root_stat = root.lstat()
            if not stat.S_ISDIR(root_stat.st_mode):
                raise ValidationError("source root is not a directory")
            for row in rows:
                relative = str(row["relative_path"])
                # Inspect each component without following a source symlink.
                source = safe_join(root, relative)
                code = None
                try:
                    component = root
                    for part in PurePosixPath(relative.replace("\\", "/")).parts:
                        component = component / part
                        mode = component.lstat().st_mode
                        if stat.S_ISLNK(mode) or (component != source and not stat.S_ISDIR(mode)):
                            code = "source_changed"
                            break
                    if code is None:
                        observed = source.lstat()
                        if (
                            not stat.S_ISREG(observed.st_mode)
                            or observed.st_size != int(row["size"])
                            or observed.st_mtime_ns != int(row["mtime_ns"])
                        ):
                            code = "source_changed"
                except FileNotFoundError:
                    code = "source_missing"
                except NotADirectoryError:
                    code = "source_changed"
                if code is not None:
                    missing += code == "source_missing"
                    changed += code == "source_changed"
                    if len(issues) < 100:
                        issues.append({"library_id": library_id, "relative_path": relative,
                                       "code": code})
            after = root.lstat()
            if (
                verify_library(library) != identity
                or (after.st_dev, after.st_ino) != (root_stat.st_dev, root_stat.st_ino)
            ):
                raise ValidationError("source identity changed during inspection")
        except (CatalogError, ValidationError, ManagedSourceAdmissionError, OSError):
            report["unavailable_libraries"] += 1
            issues = [{"library_id": library_id, "relative_path": None,
                       "code": "source_unavailable"}]
        else:
            report["checked_files"] += len(rows)
            report["missing_files"] += missing
            report["changed_files"] += changed
        report["issues"].extend(issues[: max(0, 100 - len(report["issues"]))])
    if report["unavailable_libraries"]:
        report["state"] = "source_unavailable"
    elif report["missing_files"] or report["changed_files"]:
        report["state"] = "blocked"
    return report


@dataclass(frozen=True)
class FrozenNativeCassettePlan:
    """One native cassette reconstructed only from its durable manifest."""

    job_id: str
    sequence: int
    physical_label: str
    tape_serial: str
    operation: str
    items: tuple[ScanItem, ...]
    job_library_ids: tuple[str, ...]
    library_ids: tuple[str, ...]
    plans_by_library: dict[str, ScanPlan]

    @property
    def expected_media(self) -> ExpectedMedia:
        return ExpectedMedia(
            "archive.native",
            self.job_id,
            self.sequence,
            self.physical_label,
            None,
            None,
        )

    @classmethod
    def load(
        cls,
        catalog: Catalog,
        job_id: str,
        sequence: int,
    ) -> FrozenNativeCassettePlan:
        if catalog.get_import_policy(job_id) is not None:
            raise ValidationError("imported jobs cannot use native frozen recovery")
        job = catalog.get_automatic_job(job_id)
        if job is None:
            raise CatalogError("native recovery job is unavailable")
        cassettes = tuple(
            row
            for row in catalog.list_automatic_cassettes(job_id)
            if int(row["sequence"]) == int(sequence)
        )
        if len(cassettes) != 1:
            raise CatalogError("native recovery cassette is unavailable")
        cassette = cassettes[0]
        if cassette["operation"] not in {"format", "append"}:
            raise CatalogError("native recovery cassette operation is invalid")
        manifest = tuple(catalog.list_automatic_cassette_manifest(job_id, sequence))
        if len(manifest) != int(cassette["planned_files"]) or sum(
            int(row["size"]) for row in manifest
        ) != int(cassette["planned_bytes"]):
            raise CatalogError("native recovery frozen manifest is inexact")
        if tuple(int(row["item_sequence"]) for row in manifest) != tuple(
            range(1, len(manifest) + 1)
        ):
            raise CatalogError("native recovery manifest ordering is inexact")

        linked_libraries = tuple(
            str(row["library_id"])
            for row in catalog.list_automatic_job_libraries(job_id)
        )
        roots = {
            library_id: Path(catalog.get_library(library_id)["source_root"])
            for library_id in linked_libraries
        }
        if any(str(row["library_id"]) not in roots for row in manifest):
            raise CatalogError("native recovery manifest library is not admitted")
        manifest_library_ids: list[str] = []
        completed_library_ids: set[str] = set()
        current_library_id: str | None = None
        for row in manifest:
            library_id = str(row["library_id"])
            if library_id == current_library_id:
                continue
            if library_id.casefold() in completed_library_ids:
                raise CatalogError("native recovery manifest library ordering is inexact")
            if current_library_id is not None:
                completed_library_ids.add(current_library_id.casefold())
            manifest_library_ids.append(library_id)
            current_library_id = library_id
        admitted_items = []
        for row in manifest:
            library_id = str(row["library_id"])
            root = roots[library_id]
            relative_path = str(row["relative_path"])
            tape_relative_path = str(row["tape_relative_path"])
            if not tape_relative_path:
                raise CatalogError("native recovery frozen tape path is missing")
            source_path = safe_join(root, relative_path)
            try:
                if root.is_symlink():
                    raise ValidationError("native frozen source root is a symlink")
                component = root
                for part in PurePosixPath(relative_path.replace("\\", "/")).parts:
                    component = component / part
                    if component.is_symlink():
                        raise ValidationError(
                            "native frozen source path contains a symlink"
                        )
                source_stat = source_path.lstat()
            except OSError as exc:
                raise ValidationError(
                    f"native frozen source is unavailable: {source_path}"
                ) from exc
            if source_path.is_symlink() or not stat.S_ISREG(source_stat.st_mode):
                raise ValidationError("native frozen source is not a regular file")
            if (
                source_stat.st_size != int(row["size"])
                or source_stat.st_mtime_ns != int(row["mtime_ns"])
            ):
                raise ValidationError("native frozen source metadata changed")
            admitted_items.append(
                ScanItem(
                    source_path=source_path,
                    relative_path=relative_path,
                    size=int(row["size"]),
                    mtime_ns=int(row["mtime_ns"]),
                    library_id=library_id,
                    metadata=collect_file_metadata(source_path, source_stat),
                    source_identity=(
                        int(source_stat.st_dev),
                        int(source_stat.st_ino),
                        int(source_stat.st_ctime_ns),
                        int(source_stat.st_size),
                        int(source_stat.st_mtime_ns),
                    ),
                    tape_relative_path=tape_relative_path,
                )
            )
        items = tuple(admitted_items)
        plans = {
            library_id: ScanPlan(
                library_id=library_id,
                source_root=roots[library_id],
                items=tuple(
                    item for item in items if item.library_id == library_id
                ),
                source_files=sum(item.library_id == library_id for item in items),
                source_bytes=sum(
                    item.size for item in items if item.library_id == library_id
                ),
            )
            for library_id in manifest_library_ids
        }
        return cls(
            job_id=str(job["id"]),
            sequence=int(cassette["sequence"]),
            physical_label=str(cassette["physical_label"]),
            tape_serial=str(cassette["tape_serial"]),
            operation=str(cassette["operation"]),
            items=items,
            job_library_ids=linked_libraries,
            library_ids=tuple(manifest_library_ids),
            plans_by_library=plans,
        )


__all__ = ["FrozenNativeCassettePlan"]
