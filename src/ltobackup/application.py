from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .automation import normalize_cassette_labels
from .catalog import Catalog
from .daemon.backups import BackupManager
from .engine import BackupEngine
from .errors import (
    CapacityError,
    CatalogError,
    NoNewSourceFiles,
    OperationCancelled,
    ValidationError,
)
from .filemeta import usable_change_ns
from .managed_sources import canonical_managed_source_evidence
from .media import LtoMediaProfile, require_ltfs_profile
from .models import ScanPlan, TapeBatch, VolumeInfo
from .planner import capacity_model_for_media, plan_tape_batches, select_tape_batch
from .scanner import analyze_library
from .settings import (
    DEFAULT_RESERVE_BYTES,
    AppPaths,
    Settings,
    load_settings,
    save_settings,
    upgrade_legacy_settings,
)
from .util import (
    RunLock,
    human_bytes,
    ltfs_tape_relative_path,
    safe_join,
    write_json_atomic,
)

ProgressCallback = Callable[[dict], None]


def _canonical_managed_plan_contexts(
    value: Mapping[str, Mapping[str, Any]] | None,
) -> dict[str, dict[str, Any]]:
    """Validate and case-fold managed contexts before any source traversal."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValidationError("invalid managed source context")
    normalized: dict[str, dict[str, Any]] = {}
    for library_id, context in value.items():
        if not isinstance(library_id, str) or not library_id:
            raise ValidationError("invalid managed source context")
        folded_id = library_id.casefold()
        if folded_id in normalized or not isinstance(context, Mapping):
            raise ValidationError("invalid managed source context")
        if set(context) != {"evidence", "lease_id", "reverify"}:
            raise ValidationError("invalid managed source context")
        lease_id = context.get("lease_id")
        reverify = context.get("reverify")
        evidence = context.get("evidence")
        if (
            not isinstance(lease_id, str)
            or not lease_id
            or not callable(reverify)
            or not isinstance(evidence, Mapping)
        ):
            raise ValidationError("invalid managed source context")
        normalized[folded_id] = {
            "evidence": canonical_managed_source_evidence(evidence),
            "lease_id": lease_id,
            "reverify": reverify,
        }
    return normalized


def _source_identity(source_root: str | Path) -> tuple[str, str]:
    """Return canonical path and stable directory identity without logging either."""

    resolved = Path(source_root).resolve(strict=True)
    metadata = resolved.stat()
    payload = json.dumps(
        {
            "canonical_root": str(resolved),
            "device": int(metadata.st_dev),
            "inode": int(metadata.st_ino),
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return str(resolved), hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _canonical_scan_fingerprint(
    library_id: str,
    source_root: str,
    *,
    total_files: int,
    total_bytes: int,
    archived_files: int,
    too_recent_files: int,
    pending_items: list,
    source_change_detection_policy: str = "size_mtime",
) -> str:
    payload = {
        "archived_files": archived_files,
        "items": [
            {
                "mtime_ns": int(item.mtime_ns),
                "relative_path": item.relative_path,
                "size": int(item.size),
                **(
                    {"source_change_ns": usable_change_ns(item.metadata.get("source_change_ns"))}
                    if source_change_detection_policy == "size_mtime_change"
                    and item.metadata
                    and usable_change_ns(item.metadata.get("source_change_ns")) is not None
                    else {}
                ),
            }
            for item in pending_items
        ],
        "library_id": library_id,
        "pending_bytes": sum(int(item.size) for item in pending_items),
        "pending_files": len(pending_items),
        "source_root": source_root,
        "too_recent_files": too_recent_files,
        "total_bytes": total_bytes,
        "total_files": total_files,
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _plan_ltfs_batches(
    items, usable_bytes: int, *, nominal_capacity_bytes: int
) -> tuple[TapeBatch, ...]:
    return plan_tape_batches(
        items,
        usable_bytes,
        capacity_model=capacity_model_for_media(
            nominal_capacity_bytes
        ),
    )


def _select_ltfs_batch(
    items, usable_bytes: int, *, nominal_capacity_bytes: int
) -> TapeBatch:
    return select_tape_batch(
        items,
        usable_bytes,
        capacity_model=capacity_model_for_media(
            nominal_capacity_bytes
        ),
    )


def _ltfs_batch_bytes(items, nominal_capacity_bytes: int) -> int:
    capacity_model = capacity_model_for_media(nominal_capacity_bytes)
    if capacity_model is None:
        return sum(item.size for item in items)
    return capacity_model.batch_bytes(items)


class LtoApplication:
    """Thread-safe application boundary shared by the GUI and tests.

    Each operation opens its own SQLite connection so worker threads never share
    a connection created by the graphical thread.
    """

    def __init__(self, state_dir: Path):
        self.paths = AppPaths(Path(state_dir).resolve())

    @staticmethod
    def _usable_tape_bytes(settings: Settings) -> int:
        settings.validate()
        usable = settings.tape_capacity_bytes - settings.reserve_bytes
        if usable <= 0:
            raise ValidationError(
                "La capacita utilizzabile per nastro deve essere maggiore di zero"
            )
        return usable

    @staticmethod
    def _media_tape_capacity(settings: Settings, profile: LtoMediaProfile) -> int:
        # Automatic plans are media-specific: every generation, including
        # LTO-6, uses its documented LTFS data-partition capacity.
        del settings
        assert profile.ltfs_usable_bytes is not None
        return profile.ltfs_usable_bytes

    @classmethod
    def _media_usable_tape_bytes(
        cls, settings: Settings, profile: LtoMediaProfile
    ) -> int:
        usable = cls._media_tape_capacity(settings, profile) - settings.reserve_bytes
        if usable <= 0:
            raise ValidationError(
                f"Il margine configurato supera la capacita LTFS disponibile per {profile.key}"
            )
        return usable

    @staticmethod
    def _mounted_usable_tape_bytes(settings: Settings, volume: VolumeInfo) -> int:
        if (
            volume.ltfs_data_total_bytes is not None
            and volume.ltfs_data_free_bytes is not None
        ):
            physical_used = max(
                0, volume.ltfs_data_total_bytes - volume.ltfs_data_free_bytes
            )
        else:
            physical_used = max(0, volume.total_bytes - volume.free_bytes)
        candidates = [
            settings.tape_capacity_bytes - physical_used - settings.reserve_bytes,
            volume.free_bytes - settings.reserve_bytes,
        ]
        if volume.ltfs_data_free_bytes is not None:
            candidates.append(volume.ltfs_data_free_bytes - settings.reserve_bytes)
        return max(0, min(candidates))

    @staticmethod
    def _completed_tape_capacity_bytes(
        catalog: Catalog, tape_id: str, nominal_capacity_bytes: int
    ) -> int:
        capacity_model = capacity_model_for_media(nominal_capacity_bytes)
        if capacity_model is None:
            return catalog.completed_tape_bytes(tape_id)
        rows = catalog.completed_tape_file_layout(tape_id)
        blocks = {str(row["block_id"]) for row in rows}
        return (
            sum(capacity_model.file_bytes(int(row["size"])) for row in rows)
            + len(blocks) * capacity_model.block_bytes
        )

    def ensure_initialized(
        self,
        reserve_gib: int = DEFAULT_RESERVE_BYTES // 1024**3,
        buffer_mib: int = 16,
        min_age_seconds: int = 900,
    ) -> None:
        with RunLock(self.paths.lock_file):
            if not self.paths.config_file.exists():
                settings = Settings(
                    reserve_bytes=reserve_gib * 1024**3,
                    buffer_bytes=buffer_mib * 1024**2,
                    min_age_seconds=min_age_seconds,
                )
                save_settings(self.paths, settings)
            else:
                settings = upgrade_legacy_settings(self.paths)
            BackupManager(
                self.paths.catalog_file,
                self.paths.catalog_backup_file(
                    settings.catalog_backup_directory
                ).parent,
            ).prepare_and_initialize()
            with Catalog(self.paths.catalog_file) as catalog:
                if not catalog.connection.execute(
                    "SELECT 1 FROM events WHERE action='application.init' LIMIT 1"
                ).fetchone():
                    catalog.event(
                        "application.init", {"version": __version__, "interface": "gui"}
                    )

    def snapshot(self) -> dict:
        settings = load_settings(self.paths)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            automatic_jobs = []
            for row in catalog.list_automatic_jobs():
                job = dict(row)
                job["library_ids"] = [
                    item["library_id"]
                    for item in catalog.list_automatic_job_libraries(row["id"])
                ]
                automatic_jobs.append(job)
            return {
                "settings": asdict(settings),
                "libraries": [
                    dict(row) for row in catalog.list_libraries(include_retired=True)
                ],
                "tapes": [dict(row) for row in catalog.list_tapes()],
                "blocks": [
                    dict(row) for row in catalog.list_blocks(include_forgotten=True)
                ],
                "automatic_jobs": automatic_jobs,
                "automatic_cassettes": [
                    dict(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM automatic_cassettes ORDER BY job_id, sequence"
                    )
                ],
            }

    def automatic_job_creation_context(
        self,
        library_ids: str | list[str],
        device_name: str,
    ) -> dict:
        """Describe unfinished jobs that affect creation without implying a FIFO scheduler."""

        requested = self._normalize_library_ids(library_ids)
        normalized_device = device_name.strip().upper()
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            canonical_ids = [str(catalog.get_library(item)["id"]) for item in requested]
            requested_by_key = {item.casefold(): item for item in canonical_ids}
            conflicting_jobs: list[dict] = []
            saved_on_device: list[dict] = []
            for row in catalog.list_automatic_jobs():
                if row["status"] == "completed":
                    continue
                job = dict(row)
                job["library_ids"] = [
                    str(item["library_id"])
                    for item in catalog.list_automatic_job_libraries(row["id"])
                ]
                job["overlapping_libraries"] = [
                    requested_by_key[item.casefold()]
                    for item in job["library_ids"]
                    if item.casefold() in requested_by_key
                ]
                if job["overlapping_libraries"]:
                    conflicting_jobs.append(job)
                elif str(job["device_name"]).casefold() == normalized_device.casefold():
                    saved_on_device.append(job)
        return {
            "library_ids": canonical_ids,
            "device_name": normalized_device,
            "conflicting_jobs": conflicting_jobs,
            "saved_on_device": saved_on_device,
        }

    def automatic_job_start_context(self, job_id: str) -> dict:
        """Describe the explicit start target and other saved jobs sharing its drive."""

        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            job = dict(catalog.get_automatic_job(job_id))
            job["library_ids"] = [
                str(item["library_id"])
                for item in catalog.list_automatic_job_libraries(job_id)
            ]
            cassettes = [dict(row) for row in catalog.list_automatic_cassettes(job_id)]
            next_cassette = next(
                (
                    row
                    for row in cassettes
                    if row["status"] != "completed"
                    and (int(row["planned_files"]) > 0 or int(row["planned_bytes"]) > 0)
                ),
                None,
            )
            other_jobs = []
            for row in catalog.list_automatic_jobs():
                if (
                    str(row["id"]).casefold() == job_id.casefold()
                    or row["status"] == "completed"
                    or str(row["device_name"]).casefold()
                    != str(job["device_name"]).casefold()
                ):
                    continue
                other = dict(row)
                other["library_ids"] = [
                    str(item["library_id"])
                    for item in catalog.list_automatic_job_libraries(row["id"])
                ]
                other_jobs.append(other)
        return {
            "job": job,
            "next_cassette": next_cassette,
            "other_jobs_on_device": other_jobs,
        }

    def create_automatic_job(
        self,
        library_ids: str | list[str],
        labels: list[str],
        device_name: str = "TAPE0",
        mount: Path = Path("AUTO"),
        destructive_confirmed: bool = False,
        media_key: str = "LTO-6",
        allow_registered_reuse: bool = False,
    ) -> dict:
        if not destructive_confirmed:
            raise ValidationError(
                "Confermare esplicitamente la formattazione automatica delle cassette"
            )
        selected_library_ids = self._normalize_library_ids(library_ids)
        profile = require_ltfs_profile(media_key)
        cassettes = normalize_cassette_labels(labels, media_key=profile.key)
        normalized_device = device_name.strip().upper()
        if not re.fullmatch(r"TAPE\d+", normalized_device):
            raise ValidationError("Il drive deve avere il formato TAPE0, TAPE1, ecc.")
        creation_context = self.automatic_job_creation_context(
            selected_library_ids, normalized_device
        )
        if creation_context["conflicting_jobs"]:
            conflict = creation_context["conflicting_jobs"][0]
            libraries = ", ".join(conflict["overlapping_libraries"])
            raise ValidationError(
                f"Le librerie {libraries} appartengono gia al job non concluso "
                f"{conflict['id']}. Selezionare quel job e usare Avvia / riprendi, "
                "oppure completarlo o eliminarlo prima di creare un nuovo piano."
            )
        settings = load_settings(self.paths)
        combined_items = []
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            engine = BackupEngine(catalog, settings, self.paths)
            for library_id in selected_library_ids:
                plan = engine.scan(library_id)
                combined_items.extend(
                    replace(item, library_id=library_id) for item in plan.items
                )
        usable = self._media_usable_tape_bytes(settings, profile)
        nominal = self._media_tape_capacity(settings, profile)
        batches = (
            _plan_ltfs_batches(
                combined_items, usable, nominal_capacity_bytes=nominal
            )
            if combined_items
            else ()
        )
        estimated = len(batches)
        if estimated == 0:
            raise NoNewSourceFiles(
                "Le librerie selezionate non contengono file nuovi da copiare"
            )
        if len(cassettes) < estimated:
            raise ValidationError(
                f"Il piano richiede almeno {estimated} cassette; ne sono state indicate {len(cassettes)}"
            )
        mount_text = str(mount).strip().upper().rstrip("\\/")
        if mount_text in {"AUTO", "AUTOMATICA", "AUTOMATICO"}:
            normalized_mount = Path("AUTO")
        else:
            if not re.fullmatch(r"[D-Z]:", mount_text):
                raise ValidationError(
                    "Il mount LTFS deve essere AUTO oppure una lettera di unita tra D: e Z:"
                )
            normalized_mount = Path(mount_text + "\\")
        job_id = (
            "AUTO-"
            + datetime.now(UTC).strftime("%Y%m%d-%H%M%S-")
            + uuid.uuid4().hex[:6]
        )
        rows = []
        for index, cassette in enumerate(cassettes):
            batch = batches[index] if index < len(batches) else None
            rows.append(
                (
                    cassette.physical_label,
                    cassette.tape_serial,
                    len(batch.items) if batch else 0,
                    batch.total_bytes if batch else 0,
                )
            )
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.create_automatic_job(
                job_id,
                selected_library_ids[0],
                normalized_device,
                str(normalized_mount),
                rows,
                library_ids=selected_library_ids,
                force_format=True,
                media_key=profile.key,
                allow_registered_reuse=allow_registered_reuse,
            )
            for sequence, batch in enumerate(batches, 1):
                catalog.replace_automatic_cassette_manifest(
                    job_id,
                    sequence,
                    self._cassette_manifest_items(batch.items),
                )
        return self.automatic_job(job_id)

    def _automatic_plan_snapshot(
        self,
        library_ids: str | list[str],
        progress: ProgressCallback | None = None,
        media_key: str = "LTO-6",
        *,
        settings: Settings | None = None,
        source_identities: Mapping[str, tuple[str, str]] | None = None,
        managed_source_contexts: Mapping[str, Mapping[str, Any]] | None = None,
        source_change_detection_policy: str = "size_mtime",
    ) -> tuple[dict, tuple[TapeBatch, ...], list]:
        """Build the same cumulative, optimized tape plan used by an automatic job."""
        selected_library_ids = self._normalize_library_ids(library_ids)
        managed_contexts = _canonical_managed_plan_contexts(managed_source_contexts)
        profile = require_ltfs_profile(media_key)
        settings = load_settings(self.paths) if settings is None else settings
        combined_items = []
        library_rows: list[dict] = []
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            selected_libraries = [
                catalog.get_named_library(library_id)
                for library_id in selected_library_ids
            ]
            expected_managed_ids = {
                str(library["id"]).casefold()
                for library in selected_libraries
                if str(library["source_kind"]) == "network"
            }
            if set(managed_contexts) != expected_managed_ids:
                raise ValidationError("invalid managed source context cardinality")
            for library in selected_libraries:
                folded_id = str(library["id"]).casefold()
                if folded_id not in expected_managed_ids:
                    continue
                binding = catalog.get_library_share_binding(str(library["id"]))
                binding_evidence = catalog.get_library_share_binding_evidence(
                    str(library["id"])
                )
                evidence = managed_contexts[folded_id]["evidence"]
                if (
                    str(binding["share_id"]) != str(evidence["share_id"])
                    or str(binding["relative_subpath"])
                    != str(evidence["relative_subpath"])
                    or binding_evidence != evidence
                ):
                    raise ValidationError("invalid managed source context identity")
            total_libraries = len(selected_library_ids)
            for index, (library_id, library) in enumerate(
                zip(selected_library_ids, selected_libraries, strict=True), 1
            ):
                if progress:
                    progress(
                        {
                            "event": "library.scan.start",
                            "library_id": library_id,
                            "index": index,
                            "total": total_libraries,
                        }
                    )
                if library["status"] != "active" or not bool(library["enabled"]):
                    raise ValidationError("La libreria selezionata non e attiva")
                previous_scan = (
                    library["last_scan_files"],
                    library["last_scan_bytes"],
                    library["last_scanned_at"],
                )
                expected_source_identity = (
                    None
                    if source_identities is None
                    else source_identities.get(str(library["id"]).casefold())
                )
                managed_context = managed_contexts.get(str(library["id"]).casefold())
                actual_source_identity: tuple[str, str] | None = None
                try:
                    if managed_context is not None:
                        reverified = managed_context["reverify"]()
                        if reverified != expected_source_identity:
                            raise ValidationError("La sorgente libreria e cambiata")
                    actual_source_identity = _source_identity(library["source_root"])
                    if (
                        expected_source_identity is not None
                        and actual_source_identity != expected_source_identity
                    ):
                        raise ValidationError("La sorgente libreria e cambiata")
                    analysis = analyze_library(
                        catalog,
                        library_id,
                        settings.min_age_seconds,
                        listing_limit=0,
                        persist_catalog_updates=False,
                        source_change_detection_policy=source_change_detection_policy,
                    )
                    pending_items = [
                        replace(item, library_id=library_id)
                        for item in analysis.pending_items
                    ]
                    pending_bytes = sum(item.size for item in pending_items)
                    if (
                        _source_identity(library["source_root"])
                        != actual_source_identity
                    ):
                        raise ValidationError("La sorgente libreria e cambiata")
                    if managed_context is not None:
                        reverified = managed_context["reverify"]()
                        if reverified != actual_source_identity:
                            raise ValidationError("La sorgente libreria e cambiata")
                    evidence_root, evidence_identity = actual_source_identity
                    scan_fingerprint = _canonical_scan_fingerprint(
                        str(library["id"]),
                        evidence_root,
                        total_files=analysis.total_files,
                        total_bytes=analysis.total_bytes,
                        archived_files=analysis.archived_files,
                        too_recent_files=analysis.too_recent_files,
                        pending_items=pending_items,
                        source_change_detection_policy=source_change_detection_policy,
                    )
                    scan_evidence = catalog.complete_named_library_scan(
                        str(library["id"]),
                        total_files=analysis.total_files,
                        total_bytes=analysis.total_bytes,
                        scan_fingerprint_sha256=scan_fingerprint,
                        source_canonical_root=evidence_root,
                        source_identity_sha256=evidence_identity,
                        managed_source_evidence=(
                            None
                            if managed_context is None
                            else managed_context["evidence"]
                        ),
                        managed_source_lease_id=(
                            None
                            if managed_context is None
                            else str(managed_context["lease_id"])
                        ),
                        release_managed_source_lease=False,
                    )
                except Exception:
                    comparison_identity = (
                        expected_source_identity or actual_source_identity
                    )
                    try:
                        source_changed = (
                            comparison_identity is None
                            or _source_identity(library["source_root"])
                            != comparison_identity
                        )
                    except (OSError, RuntimeError, ValueError):
                        source_changed = True
                    catalog.fail_named_library_scan(
                        str(library["id"]),
                        invalidate_ready_plans=source_changed,
                        previous_scan=previous_scan,
                    )
                    raise
                combined_items.extend(pending_items)
                library_rows.append(
                    {
                        "library_id": library_id,
                        "name": library["name"],
                        "source_root": evidence_root,
                        "scan_revision": int(scan_evidence["scan_revision"]),
                        "scan_fingerprint_sha256": str(
                            scan_evidence["scan_fingerprint_sha256"]
                        ),
                        "total_files": analysis.total_files,
                        "total_bytes": analysis.total_bytes,
                        "total_human": human_bytes(analysis.total_bytes),
                        "pending_files": len(pending_items),
                        "pending_bytes": pending_bytes,
                        "pending_human": human_bytes(pending_bytes),
                        "archived_files": analysis.archived_files,
                        "too_recent_files": analysis.too_recent_files,
                    }
                )
                if progress:
                    progress(
                        {
                            "event": "library.scan.complete",
                            "library_id": library_id,
                            "index": index,
                            "total": total_libraries,
                            "files": len(pending_items),
                            "bytes": pending_bytes,
                        }
                    )

        tape_capacity = self._media_tape_capacity(settings, profile)
        usable = self._media_usable_tape_bytes(settings, profile)
        batches = (
            _plan_ltfs_batches(
                combined_items, usable, nominal_capacity_bytes=tape_capacity
            )
            if combined_items
            else ()
        )
        cassette_rows: list[dict] = []
        for batch in batches:
            by_library: dict[str, list[int]] = {}
            for item in batch.items:
                values = by_library.setdefault(item.library_id or "", [0, 0])
                values[0] += 1
                values[1] += item.size
            cassette_rows.append(
                {
                    "sequence": batch.slot,
                    "file_count": len(batch.items),
                    "total_bytes": batch.total_bytes,
                    "human": human_bytes(batch.total_bytes),
                    "capacity_used_bytes": batch.capacity_used_bytes,
                    "capacity_used_human": human_bytes(batch.capacity_used_bytes or 0),
                    "ltfs_overhead_bytes": (batch.capacity_used_bytes or 0)
                    - batch.total_bytes,
                    "ltfs_overhead_human": human_bytes(
                        (batch.capacity_used_bytes or 0) - batch.total_bytes
                    ),
                    "remaining_bytes": batch.remaining_bytes,
                    "remaining_human": human_bytes(batch.remaining_bytes),
                    "utilization_percent": round(
                        (batch.capacity_used_bytes or 0) * 100 / usable, 1
                    ),
                    "libraries": [
                        {
                            "library_id": library_id,
                            "file_count": by_library[library_id][0],
                            "total_bytes": by_library[library_id][1],
                            "human": human_bytes(by_library[library_id][1]),
                        }
                        for library_id in selected_library_ids
                        if library_id in by_library
                    ],
                }
            )

        pending_bytes = sum(item.size for item in combined_items)
        summary = {
            "library_ids": selected_library_ids,
            "total_libraries": len(selected_library_ids),
            "total_files": sum(row["total_files"] for row in library_rows),
            "total_bytes": sum(row["total_bytes"] for row in library_rows),
            "total_human": human_bytes(sum(row["total_bytes"] for row in library_rows)),
            "pending_files": len(combined_items),
            "pending_bytes": pending_bytes,
            "pending_human": human_bytes(pending_bytes),
            "estimated_tapes": len(batches),
            "media_key": profile.key,
            "media_generation": profile.generation,
            "barcode_suffix": profile.barcode_suffix,
            "native_tape_bytes": profile.native_capacity_bytes,
            "native_tape_tb": profile.native_capacity_tb,
            "compressed_tape_bytes": profile.compressed_capacity_bytes,
            "compressed_tape_tb": profile.compressed_capacity_tb,
            "nominal_tape_bytes": tape_capacity,
            "nominal_tape_human": human_bytes(tape_capacity),
            "nominal_tape_tb": tape_capacity / 1_000_000_000_000,
            "reserve_bytes": settings.reserve_bytes,
            "reserve_human": human_bytes(settings.reserve_bytes),
            "usable_tape_bytes": usable,
            "usable_tape_human": human_bytes(usable),
            "libraries": library_rows,
            "cassettes": cassette_rows,
        }
        return summary, batches, combined_items

    def plan_automatic_job(
        self,
        library_ids: str | list[str],
        progress: ProgressCallback | None = None,
        media_key: str = "LTO-6",
    ) -> dict:
        """Build the same cumulative, optimized tape plan used by an automatic job."""

        summary, _batches, _items = self._automatic_plan_snapshot(
            library_ids,
            progress=progress,
            media_key=media_key,
        )
        return summary

    def freeze_automatic_job_plan(
        self,
        library_ids: str | list[str],
        *,
        kind: str = "create",
        progress: ProgressCallback | None = None,
        media_key: str = "LTO-6",
        base_job_id: str | None = None,
        base_job_revision: int | None = None,
        base_job_fingerprint_sha256: str | None = None,
        source_identities: Mapping[str, tuple[str, str]] | None = None,
        settings: Settings | None = None,
        application_settings_revision: int = 0,
        content_verification_policy: str = "none",
        managed_source_contexts: Mapping[str, Mapping[str, Any]] | None = None,
        source_change_detection_policy: str = "size_mtime",
    ) -> dict:
        """Freeze one automatic-planner pass as canonical, digest-bound evidence."""

        if kind not in {"create", "extend"}:
            raise ValidationError("Tipo piano non valido")
        if kind == "extend" and (
            base_job_id is None
            or type(base_job_revision) is not int
            or base_job_revision < 0
            or not isinstance(base_job_fingerprint_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", base_job_fingerprint_sha256)
        ):
            raise ValidationError(
                "Il piano di estensione richiede lo stato base congelato"
            )
        explicit_application_settings = settings is not None
        settings = load_settings(self.paths) if settings is None else settings
        if (
            type(application_settings_revision) is not int
            or application_settings_revision < 0
            or content_verification_policy not in {"none", "manifest", "full"}
            or source_change_detection_policy not in {"size_mtime", "size_mtime_change"}
        ):
            raise ValidationError("Snapshot impostazioni applicazione non valido")
        managed_contexts = _canonical_managed_plan_contexts(managed_source_contexts)
        summary, batches, combined_items = self._automatic_plan_snapshot(
            library_ids,
            progress=progress,
            media_key=media_key,
            settings=settings,
            source_identities=source_identities,
            managed_source_contexts=managed_contexts,
            source_change_detection_policy=source_change_detection_policy,
        )
        if not batches:
            raise NoNewSourceFiles(
                "Le librerie selezionate non contengono file nuovi da copiare"
            )

        extension_evidence: dict | None = None
        extension_residual_bytes = 0
        existing_reserve_labels: list[str] = []
        completed_assignments: list[dict] = []
        planned_operations: list[tuple[str, TapeBatch]] = [
            ("format", batch) for batch in batches
        ]
        if kind == "extend":
            assert base_job_id is not None
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.initialize()
                extension_evidence = catalog.job_extension_evidence(base_job_id)
                if (
                    extension_evidence["retired"]
                    or extension_evidence["imported"]
                    or extension_evidence["revision"] != base_job_revision
                    or extension_evidence["fingerprint_sha256"]
                    != base_job_fingerprint_sha256
                    or extension_evidence["libraries"] != list(summary["library_ids"])
                    or extension_evidence["media_key"] != summary["media_key"]
                ):
                    raise ValidationError("Lo stato base del job e cambiato")
                completed_assignments = [
                    {
                        "copied_bytes": row["copied_bytes"],
                        "copied_files": row["copied_files"],
                        "physical_label": row["physical_label"],
                        "sequence": row["sequence"],
                        "tape_id": row["tape_id"],
                    }
                    for row in extension_evidence["cassettes"]
                    if row["status"] == "completed"
                ]
                existing_reserve_labels = [
                    str(row["physical_label"])
                    for row in extension_evidence["cassettes"]
                    if row["status"] == "pending"
                    and row["planned_files"] == 0
                    and row["planned_bytes"] == 0
                ]
                append_target = next(
                    (
                        row
                        for row in reversed(extension_evidence["cassettes"])
                        if row["status"] == "completed" and row["tape_id"] is not None
                    ),
                    None,
                )
                nominal_bytes = self._media_tape_capacity(
                    settings, require_ltfs_profile(media_key)
                )
                usable_bytes = int(summary["usable_tape_bytes"])
                remaining_items = list(combined_items)
                planned_operations = []
                if append_target is not None:
                    occupied = self._completed_tape_capacity_bytes(
                        catalog, str(append_target["tape_id"]), nominal_bytes
                    )
                    extension_residual_bytes = max(0, usable_bytes - occupied)
                    if extension_residual_bytes > 0:
                        try:
                            append_batch = _select_ltfs_batch(
                                remaining_items,
                                extension_residual_bytes,
                                nominal_capacity_bytes=nominal_bytes,
                            )
                        except CapacityError:
                            append_batch = None
                        if append_batch is not None:
                            planned_operations.append(("append", append_batch))
                            selected = {
                                (
                                    str(item.library_id).casefold(),
                                    item.relative_path.casefold(),
                                )
                                for item in append_batch.items
                            }
                            remaining_items = [
                                item
                                for item in remaining_items
                                if (
                                    str(item.library_id).casefold(),
                                    item.relative_path.casefold(),
                                )
                                not in selected
                            ]
                format_batches = (
                    list(
                        _plan_ltfs_batches(
                            remaining_items,
                            usable_bytes,
                            nominal_capacity_bytes=nominal_bytes,
                        )
                    )
                    if remaining_items
                    else []
                )
                reserve_count = min(len(existing_reserve_labels), len(format_batches))
                planned_operations.extend(
                    ("reserve" if index < reserve_count else "format", batch)
                    for index, batch in enumerate(format_batches)
                )

        profile = require_ltfs_profile(media_key)
        policy_snapshot = {
            "capacity_reserve_bytes": settings.reserve_bytes,
            "default_media_profile": require_ltfs_profile(
                settings.default_media_key
            ).key,
            "minimum_source_file_age_seconds": settings.min_age_seconds,
            "selected_media_profile": profile.key,
            "settings_revision": application_settings_revision,
            "tape_root_directory": settings.tape_root_directory,
        }
        if explicit_application_settings:
            policy_snapshot["source_change_detection_policy"] = source_change_detection_policy
        settings_json = json.dumps(
            policy_snapshot if explicit_application_settings else asdict(settings),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        settings_fingerprint = hashlib.sha256(settings_json.encode("utf-8")).hexdigest()
        frozen_libraries: list[dict] = []
        canonical_libraries: list[dict] = []
        summary_by_library = {row["library_id"]: row for row in summary["libraries"]}
        for sequence, library_id in enumerate(summary["library_ids"], 1):
            library = summary_by_library[library_id]
            evidence = {
                "library_id": library_id,
                "scan_fingerprint_sha256": library["scan_fingerprint_sha256"],
                "scan_revision": library["scan_revision"],
                "source_root": library["source_root"],
            }
            canonical_libraries.append(evidence)
            frozen_libraries.append({"sequence": sequence, **evidence})

        canonical_cassettes: list[dict] = []
        frozen_cassettes: list[dict] = []
        usable_bytes = int(summary["usable_tape_bytes"])
        for sequence, (operation, batch) in enumerate(planned_operations, 1):
            canonical_items = [
                {
                    "library_id": str(item.library_id),
                    "mtime_ns": int(item.mtime_ns),
                    "relative_path": item.relative_path,
                    "tape_relative_path": ltfs_tape_relative_path(
                        item.relative_path
                    ),
                    "size": int(item.size),
                }
                for item in batch.items
            ]
            allocation_bytes = int(batch.capacity_used_bytes or 0)
            canonical_cassette = {
                "allocation_bytes": allocation_bytes,
                "capacity_utilization": allocation_bytes / usable_bytes,
                "items": canonical_items,
                "objects": len(canonical_items),
                "operation": operation,
                "payload_bytes": int(batch.total_bytes),
                "sequence": sequence,
            }
            canonical_cassettes.append(canonical_cassette)
            frozen_cassettes.append(
                {
                    **canonical_cassette,
                    "items": [
                        {"item_sequence": item_sequence, **item}
                        for item_sequence, item in enumerate(canonical_items, 1)
                    ],
                }
            )

        canonical_payload = {
            "application_settings": {
                "fingerprint_sha256": settings_fingerprint,
                "revision": application_settings_revision,
            },
            "base_job": (
                {
                    "fingerprint_sha256": base_job_fingerprint_sha256,
                    "id": base_job_id,
                    "revision": base_job_revision,
                }
                if kind == "extend"
                else None
            ),
            "canonical_json_version": 1,
            "cassettes": canonical_cassettes,
            "kind": kind,
            "libraries": canonical_libraries,
            "library_ids": list(summary["library_ids"]),
            "media_key": summary["media_key"],
            "plan_schema_version": 1,
            "planner_version": "automatic-ltfs-v1",
        }
        managed_sources = [
            {
                "library_id": library_id,
                "evidence": dict(context["evidence"]),
            }
            for library_id in summary["library_ids"]
            if (context := managed_contexts.get(str(library_id).casefold())) is not None
        ]
        if managed_sources:
            canonical_payload["managed_sources"] = managed_sources
        if kind == "extend":
            canonical_payload.update(
                {
                    "completed_assignments": completed_assignments,
                    "existing_reserve_labels": existing_reserve_labels,
                    "residual_append_capacity_bytes": extension_residual_bytes,
                }
            )
        canonical_json = json.dumps(
            canonical_payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        frozen_plan = {
            "canonical_json": canonical_json,
            "digest_sha256": hashlib.sha256(canonical_json.encode("utf-8")).hexdigest(),
            "canonical_json_version": 1,
            "plan_schema_version": 1,
            "planner_version": "automatic-ltfs-v1",
            "application_settings_revision": application_settings_revision,
            "application_settings_fingerprint_sha256": settings_fingerprint,
            "libraries": frozen_libraries,
            "cassettes": frozen_cassettes,
            "completed_assignments": completed_assignments,
            "existing_reserve_labels": existing_reserve_labels,
            "residual_append_capacity_bytes": extension_residual_bytes,
        }
        if explicit_application_settings:
            frozen_plan["policy_snapshot"] = policy_snapshot
        if managed_sources:
            frozen_plan["managed_sources"] = managed_sources
        return frozen_plan

    def frozen_job_plan_sources_are_current(self, plan: Mapping[str, object]) -> bool:
        """Re-stat frozen items; new ctime policy also rechecks metadata-only scan."""

        libraries = {
            str(row["library_id"]): {
                "root": Path(str(row["source_root"])),
                "revision": int(row["scan_revision"]),
                "fingerprint": str(row["scan_fingerprint_sha256"]),
            }
            for row in plan.get("libraries", ())  # type: ignore[union-attr]
        }
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.initialize()
                for library_id, evidence in libraries.items():
                    current = catalog.get_named_library(library_id)
                    current_root, current_identity = _source_identity(
                        current["source_root"]
                    )
                    if (
                        current["status"] != "active"
                        or not bool(current["enabled"])
                        or Path(current_root) != evidence["root"]
                        or (
                            current["source_identity_sha256"] is not None
                            and current_identity
                            != str(current["source_identity_sha256"])
                        )
                        or int(current["scan_revision"]) != evidence["revision"]
                        or str(current["scan_fingerprint_sha256"])
                        != evidence["fingerprint"]
                    ):
                        return False
                policy = plan.get("policy_snapshot")
                if policy is None and plan.get("id") is not None:
                    plan_id = str(plan["id"])
                    has_snapshot = catalog.connection.execute(
                        "SELECT 1 FROM job_plan_policy_snapshots WHERE plan_id=?",
                        (plan_id,),
                    ).fetchone()
                    if has_snapshot:
                        policy = catalog.get_job_plan_policy_snapshot(plan_id)
                if policy is not None and not isinstance(policy, Mapping):
                    return False
                source_policy = (
                    policy.get("source_change_detection_policy", "size_mtime")
                    if policy is not None else "size_mtime"
                )
                if source_policy not in {"size_mtime", "size_mtime_change"}:
                    return False
                if source_policy == "size_mtime_change":
                    minimum_age = int(policy["minimum_source_file_age_seconds"])
                    for library_id, evidence in libraries.items():
                        analysis = analyze_library(
                            catalog,
                            library_id,
                            minimum_age,
                            listing_limit=0,
                            persist_catalog_updates=False,
                            source_change_detection_policy=source_policy,
                        )
                        fingerprint = _canonical_scan_fingerprint(
                            library_id,
                            str(evidence["root"]),
                            total_files=analysis.total_files,
                            total_bytes=analysis.total_bytes,
                            archived_files=analysis.archived_files,
                            too_recent_files=analysis.too_recent_files,
                            pending_items=list(analysis.pending_items),
                            source_change_detection_policy=source_policy,
                        )
                        if fingerprint != evidence["fingerprint"]:
                            return False
            for cassette in plan.get("cassettes", ()):  # type: ignore[union-attr]
                for item in cassette["items"]:
                    evidence = libraries.get(str(item["library_id"]))
                    if evidence is None:
                        return False
                    root = evidence["root"]
                    source = safe_join(root, str(item["relative_path"]))
                    if source.is_symlink():
                        return False
                    metadata = source.stat()
                    if (
                        not source.is_file()
                        or metadata.st_size != int(item["size"])
                        or metadata.st_mtime_ns != int(item["mtime_ns"])
                    ):
                        return False
        except (CatalogError, KeyError, OSError, TypeError, ValueError, ValidationError):
            return False
        return True

    @staticmethod
    def _normalize_library_ids(library_ids: str | list[str]) -> list[str]:
        candidates = (
            [library_ids] if isinstance(library_ids, str) else list(library_ids)
        )
        selected: list[str] = []
        seen: set[str] = set()
        for library_id in candidates:
            normalized = library_id.strip()
            if normalized and normalized.casefold() not in seen:
                selected.append(normalized)
                seen.add(normalized.casefold())
        if not selected:
            raise ValidationError(
                "Selezionare almeno una libreria per il job automatico"
            )
        return selected

    @staticmethod
    def _cassette_manifest_items(
        items: tuple | list,
    ) -> list[tuple[str, str, int, int]]:
        return [
            (
                str(item.library_id or ""),
                item.relative_path,
                int(item.size),
                int(item.mtime_ns),
            )
            for item in items
        ]

    def automatic_job(self, job_id: str) -> dict:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            result = dict(catalog.get_automatic_job(job_id))
            result["library_ids"] = [
                row["library_id"]
                for row in catalog.list_automatic_job_libraries(job_id)
            ]
            result["cassettes"] = [
                dict(row) for row in catalog.list_automatic_cassettes(job_id)
            ]
            return result

    def rename_automatic_job(self, job_id: str, display_name: str) -> dict:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.rename_automatic_job(job_id, display_name)
        return self.automatic_job(job_id)

    def delete_automatic_job(self, job_id: str) -> dict:
        with (
            RunLock(self.paths.state_dir / "automatic-job.lock"),
            RunLock(self.paths.lock_file),
            Catalog(self.paths.catalog_file) as catalog,
        ):
            catalog.initialize()
            return catalog.delete_automatic_job(job_id)

    def reset_failed_automatic_cassette(self, job_id: str, sequence: int) -> dict:
        with (
            RunLock(self.paths.state_dir / "automatic-job.lock"),
            RunLock(self.paths.lock_file),
            Catalog(self.paths.catalog_file) as catalog,
        ):
            catalog.initialize()
            job = catalog.get_automatic_job(job_id)
            if job["status"] != "failed":
                raise ValidationError(f"Il job {job_id} non e in errore")
            cassette = next(
                (
                    row
                    for row in catalog.list_automatic_cassettes(job_id)
                    if int(row["sequence"]) == int(sequence)
                ),
                None,
            )
            if cassette is None:
                raise ValidationError(
                    f"Cassetta {sequence} non trovata nel job {job_id}"
                )
            if cassette["status"] != "failed":
                raise ValidationError(f"La cassetta {sequence} non e in errore")
            discarded = catalog.reset_automatic_cassette(
                job_id,
                int(sequence),
                "Reimpostazione richiesta dalla GUI per riprovare la cassetta",
            )
        result = self.automatic_job(job_id)
        result["discarded"] = discarded
        return result

    def prepare_automatic_job_run(self, job_id: str) -> dict:
        """Plan new files on the last completed tape, then on unused reserves."""

        settings = load_settings(self.paths)
        combined_items = []
        append_candidate: dict | None = None
        append_assignment: tuple[int, int] | None = None
        append_items: tuple = ()
        legacy_manifests: list[tuple[int, tuple]] = []
        extended_active_manifests: list[tuple[int, tuple]] = []
        active_plan_unchanged = False
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            job = catalog.get_automatic_job(job_id)
            profile = require_ltfs_profile(job["media_key"])
            rows = catalog.list_automatic_cassettes(job_id)
            active_rows = [
                row
                for row in rows
                if row["status"] != "completed"
                and (int(row["planned_files"]) > 0 or int(row["planned_bytes"]) > 0)
            ]
            manifest_counts = [
                len(
                    catalog.list_automatic_cassette_manifest(
                        job_id, int(row["sequence"])
                    )
                )
                for row in active_rows
            ]
            active_manifests_complete = bool(active_rows) and all(manifest_counts)
            if active_rows and any(manifest_counts) and not all(manifest_counts):
                raise ValidationError(
                    "Il piano persistente del job e incompleto: alcune cassette hanno un "
                    "manifest e altre no. Non avviare la scrittura."
                )
            reserves = [
                row
                for row in rows
                if row["status"] == "pending"
                and int(row["planned_files"]) == 0
                and int(row["planned_bytes"]) == 0
            ]
            library_ids = [
                row["library_id"]
                for row in catalog.list_automatic_job_libraries(job_id)
            ]
            engine = BackupEngine(catalog, settings, self.paths)
            for library_id in library_ids:
                plan = engine.scan(library_id)
                combined_items.extend(
                    replace(item, library_id=library_id) for item in plan.items
                )
            if active_manifests_complete:
                queue_rows = [row for row in rows if row["status"] != "completed"]
                manifests = {
                    int(row["sequence"]): [
                        dict(item)
                        for item in catalog.list_automatic_cassette_manifest(
                            job_id, int(row["sequence"])
                        )
                    ]
                    for row in queue_rows
                }
                available = {
                    (
                        str(item.library_id or "").casefold(),
                        item.relative_path.casefold(),
                    ): item
                    for item in combined_items
                }
                planned_keys: set[tuple[str, str]] = set()
                for manifest in manifests.values():
                    for item in manifest:
                        key = (
                            str(item["library_id"]).casefold(),
                            str(item["relative_path"]).casefold(),
                        )
                        planned_keys.add(key)
                        source_item = available.get(key)
                        if source_item is None:
                            raise ValidationError(
                                "Un file gia pianificato non e piu disponibile: "
                                f"{item['library_id']}/{item['relative_path']}"
                            )
                        if source_item.size != int(
                            item["size"]
                        ) or source_item.mtime_ns != int(item["mtime_ns"]):
                            raise ValidationError(
                                "Un file gia pianificato e stato modificato: "
                                f"{item['library_id']}/{item['relative_path']}"
                            )
                new_items = [
                    item
                    for item in combined_items
                    if (
                        str(item.library_id or "").casefold(),
                        item.relative_path.casefold(),
                    )
                    not in planned_keys
                ]
                if not new_items:
                    active_plan_unchanged = True
                else:
                    usable = self._media_usable_tape_bytes(settings, profile)
                    nominal = self._media_tape_capacity(settings, profile)
                    oversized = next(
                        (item for item in new_items if item.size > usable), None
                    )
                    if oversized is not None:
                        raise CapacityError(
                            f"Il nuovo file {oversized.relative_path} "
                            f"({human_bytes(oversized.size)}) supera la capacita utilizzabile "
                            f"di una cassetta ({human_bytes(usable)})."
                        )
                    assignment_items: dict[int, list] = {
                        sequence: [
                            available[
                                (
                                    str(item["library_id"]).casefold(),
                                    str(item["relative_path"]).casefold(),
                                )
                            ]
                            for item in manifest
                        ]
                        for sequence, manifest in manifests.items()
                    }
                    unassigned = []
                    for item in sorted(
                        new_items,
                        key=lambda value: (
                            -value.size,
                            (value.library_id or "").casefold(),
                            value.relative_path.casefold(),
                            value.relative_path,
                        ),
                    ):
                        target = None
                        for row in queue_rows:
                            sequence = int(row["sequence"])
                            base_used = 0
                            if row["operation"] == "append" and row["tape_id"]:
                                base_used = self._completed_tape_capacity_bytes(
                                    catalog, str(row["tape_id"]), nominal
                                )
                            candidate = assignment_items[sequence] + [item]
                            if (
                                base_used + _ltfs_batch_bytes(candidate, nominal)
                                <= usable
                            ):
                                target = sequence
                                break
                        if target is None:
                            unassigned.append(item)
                            continue
                        assignment_items[target].append(item)
                    if unassigned:
                        raise ValidationError(
                            f"{len(unassigned)} nuovi file non entrano nello spazio residuo "
                            "della coda; aggiungere cassette allo stesso job prima di riprendere."
                        )
                    extended_active_manifests = [
                        (
                            int(row["sequence"]),
                            tuple(assignment_items[int(row["sequence"])]),
                        )
                        for row in queue_rows
                    ]
            elif active_rows:
                remaining = list(combined_items)
                usable = self._media_usable_tape_bytes(settings, profile)
                nominal = self._media_tape_capacity(settings, profile)
                queue_rows = [row for row in rows if row["status"] != "completed"]
                for row in queue_rows:
                    if not remaining:
                        legacy_manifests.append((int(row["sequence"]), ()))
                        continue
                    capacity = usable
                    if row["operation"] == "append" and row["tape_id"]:
                        capacity = max(
                            0,
                            usable
                            - self._completed_tape_capacity_bytes(
                                catalog, str(row["tape_id"]), nominal
                            ),
                        )
                    try:
                        recovered = _select_ltfs_batch(
                            remaining, capacity, nominal_capacity_bytes=nominal
                        )
                    except CapacityError as exc:
                        raise ValidationError(
                            f"Impossibile congelare il manifest della cassetta "
                            f"{row['sequence']}: {exc}"
                        ) from exc
                    legacy_manifests.append((int(row["sequence"]), recovered.items))
                    recovered_keys = {
                        (
                            str(item.library_id or "").casefold(),
                            item.relative_path.casefold(),
                        )
                        for item in recovered.items
                    }
                    remaining = [
                        item
                        for item in remaining
                        if (
                            str(item.library_id or "").casefold(),
                            item.relative_path.casefold(),
                        )
                        not in recovered_keys
                    ]
                if remaining:
                    raise ValidationError(
                        f"Il piano persistente richiede altre cassette per {len(remaining)} file; "
                        "aggiungere etichette prima di riprendere il job."
                    )
                combined_items = []
            if active_rows:
                append_candidate = None
            else:
                append_candidate = next(
                    (
                        dict(row)
                        for row in reversed(rows)
                        if row["status"] == "completed" and row["tape_id"]
                    ),
                    None,
                )
            if append_candidate and combined_items:
                usable = self._media_usable_tape_bytes(settings, profile)
                nominal = self._media_tape_capacity(settings, profile)
                used = self._completed_tape_capacity_bytes(
                    catalog, str(append_candidate["tape_id"]), nominal
                )
                residual = max(0, usable - used)
                if residual:
                    try:
                        selected = _select_ltfs_batch(
                            combined_items, residual, nominal_capacity_bytes=nominal
                        )
                    except CapacityError:
                        selected = None
                    if selected is not None:
                        append_items = selected.items
                        append_assignment = (len(selected.items), selected.total_bytes)
                        selected_keys = {
                            (str(item.library_id or ""), item.relative_path)
                            for item in selected.items
                        }
                        combined_items = [
                            item
                            for item in combined_items
                            if (str(item.library_id or ""), item.relative_path)
                            not in selected_keys
                        ]

        if active_plan_unchanged:
            return self.automatic_job(job_id)

        if extended_active_manifests:
            with (
                RunLock(self.paths.lock_file),
                Catalog(self.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                catalog.replace_automatic_pending_plan(
                    job_id,
                    [
                        (sequence, self._cassette_manifest_items(items))
                        for sequence, items in extended_active_manifests
                    ],
                )
            return self.automatic_job(job_id)

        if legacy_manifests:
            with (
                RunLock(self.paths.lock_file),
                Catalog(self.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                catalog.replace_automatic_pending_plan(
                    job_id,
                    [
                        (sequence, self._cassette_manifest_items(items))
                        for sequence, items in legacy_manifests
                    ],
                )
            return self.automatic_job(job_id)

        if not combined_items and append_assignment is None:
            raise ValidationError(
                "Il job non contiene nuovi file da copiare; le cassette di riserva restano inutilizzate"
            )
        batches = (
            _plan_ltfs_batches(
                combined_items,
                self._media_usable_tape_bytes(settings, profile),
                nominal_capacity_bytes=self._media_tape_capacity(settings, profile),
            )
            if combined_items
            else ()
        )
        if len(batches) > len(reserves):
            missing = len(batches) - len(reserves)
            raise ValidationError(
                f"I nuovi dati richiedono {len(batches)} cassette, ma il job ne ha "
                f"{len(reserves)} in riserva; aggiungere almeno {missing} cassette"
            )
        assignments = [(len(batch.items), batch.total_bytes) for batch in batches]
        reserve_sequences = [int(row["sequence"]) for row in reserves[: len(batches)]]
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.activate_automatic_reserves(job_id, assignments)
            if append_candidate and append_assignment:
                catalog.activate_automatic_append(
                    job_id,
                    int(append_candidate["sequence"]),
                    append_assignment[0],
                    append_assignment[1],
                )
                catalog.replace_automatic_cassette_manifest(
                    job_id,
                    int(append_candidate["sequence"]),
                    self._cassette_manifest_items(append_items),
                )
            for sequence, batch in zip(reserve_sequences, batches):
                catalog.replace_automatic_cassette_manifest(
                    job_id, sequence, self._cassette_manifest_items(batch.items)
                )
        return self.automatic_job(job_id)

    def extend_automatic_job(
        self,
        job_id: str,
        labels: list[str],
        destructive_confirmed: bool = False,
        allow_registered_reuse: bool = False,
    ) -> dict:
        if not destructive_confirmed:
            raise ValidationError(
                "Confermare esplicitamente la formattazione automatica delle cassette"
            )
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            existing_job = catalog.get_automatic_job(job_id)
            existing_profile = require_ltfs_profile(existing_job["media_key"])
        if existing_job["status"] in {"planned", "paused", "waiting_media"}:
            active_cassettes = normalize_cassette_labels(
                labels, media_key=existing_profile.key
            )
            active_rows = [
                (cassette.physical_label, cassette.tape_serial, 0, 0)
                for cassette in active_cassettes
            ]
            with (
                RunLock(self.paths.lock_file),
                Catalog(self.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                catalog.append_automatic_cassettes(
                    job_id,
                    active_rows,
                    force_format=True,
                    allow_active=True,
                    allow_registered_reuse=allow_registered_reuse,
                )
            return self.prepare_automatic_job_run(job_id)
        settings = load_settings(self.paths)
        combined_items = []
        append_candidate: dict | None = None
        append_assignment: tuple[int, int] | None = None
        append_items: tuple = ()
        append_used_bytes = 0
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            job = catalog.get_automatic_job(job_id)
            profile = require_ltfs_profile(job["media_key"])
            cassettes = normalize_cassette_labels(labels, media_key=profile.key)
            if job["status"] not in {"completed", "failed"}:
                raise ValidationError(
                    "Si possono aggiungere cassette solo a un job concluso"
                )
            existing = catalog.list_automatic_cassettes(job_id)
            unfinished = next(
                (
                    row
                    for row in existing
                    if row["status"] != "completed"
                    and not (
                        row["status"] == "pending"
                        and int(row["planned_files"]) == 0
                        and int(row["planned_bytes"]) == 0
                    )
                ),
                None,
            )
            if unfinished:
                raise ValidationError(
                    f"La cassetta {unfinished['sequence']} non e completata; "
                    "risolvere prima la coda esistente"
                )
            append_candidate = next(
                (
                    dict(row)
                    for row in reversed(existing)
                    if row["status"] == "completed" and row["tape_id"]
                ),
                None,
            )
            if append_candidate:
                append_used_bytes = self._completed_tape_capacity_bytes(
                    catalog,
                    str(append_candidate["tape_id"]),
                    self._media_tape_capacity(settings, profile),
                )
            library_ids = [
                row["library_id"]
                for row in catalog.list_automatic_job_libraries(job_id)
            ]
            engine = BackupEngine(catalog, settings, self.paths)
            for library_id in library_ids:
                plan = engine.scan(library_id)
                combined_items.extend(
                    replace(item, library_id=library_id) for item in plan.items
                )
        usable = self._media_usable_tape_bytes(settings, profile)
        nominal = self._media_tape_capacity(settings, profile)
        if append_candidate and combined_items:
            residual = max(0, usable - append_used_bytes)
            if residual:
                try:
                    selected = _select_ltfs_batch(
                        combined_items, residual, nominal_capacity_bytes=nominal
                    )
                except CapacityError:
                    selected = None
                if selected is not None:
                    append_items = selected.items
                    append_assignment = (len(selected.items), selected.total_bytes)
                    selected_keys = {
                        (str(item.library_id or ""), item.relative_path)
                        for item in selected.items
                    }
                    combined_items = [
                        item
                        for item in combined_items
                        if (str(item.library_id or ""), item.relative_path)
                        not in selected_keys
                    ]
        batches = (
            _plan_ltfs_batches(
                combined_items, usable, nominal_capacity_bytes=nominal
            )
            if combined_items
            else ()
        )
        estimated = len(batches)
        if estimated == 0 and append_assignment is None:
            raise NoNewSourceFiles(
                "Le librerie del job non contengono file nuovi da copiare"
            )
        reserve_count = sum(
            row["status"] == "pending"
            and int(row["planned_files"]) == 0
            and int(row["planned_bytes"]) == 0
            for row in existing
        )
        if reserve_count + len(cassettes) < estimated:
            missing = estimated - reserve_count
            raise ValidationError(
                f"Il nuovo piano richiede almeno {estimated} cassette; il job ne ha "
                f"{reserve_count} in riserva e servono almeno {missing} nuove etichette"
            )
        rows = [
            (
                cassette.physical_label,
                cassette.tape_serial,
                0,
                0,
            )
            for cassette in cassettes
        ]
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.append_automatic_cassettes(
                job_id,
                rows,
                force_format=True,
                allow_registered_reuse=allow_registered_reuse,
            )
            reserve_sequences = [
                int(row["sequence"])
                for row in catalog.list_automatic_cassettes(job_id)
                if row["status"] == "pending"
                and int(row["planned_files"]) == 0
                and int(row["planned_bytes"]) == 0
            ][: len(batches)]
            catalog.activate_automatic_reserves(
                job_id,
                [(len(batch.items), batch.total_bytes) for batch in batches],
            )
            if append_candidate and append_assignment:
                catalog.activate_automatic_append(
                    job_id,
                    int(append_candidate["sequence"]),
                    append_assignment[0],
                    append_assignment[1],
                )
                catalog.replace_automatic_cassette_manifest(
                    job_id,
                    int(append_candidate["sequence"]),
                    self._cassette_manifest_items(append_items),
                )
            for sequence, batch in zip(reserve_sequences, batches):
                catalog.replace_automatic_cassette_manifest(
                    job_id, sequence, self._cassette_manifest_items(batch.items)
                )
        return self.automatic_job(job_id)

    def add_library(self, library_id: str, name: str, source_root: str) -> None:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.add_library(library_id, name, source_root)

    def list_named_libraries(self) -> list[dict]:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return [dict(row) for row in catalog.list_named_libraries()]

    def get_named_library(self, library_id: str) -> dict:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return dict(catalog.get_named_library(library_id))

    def create_named_library(
        self,
        library_id: str,
        display_name: str,
        source_root: str,
        source_canonical_root: str,
        source_identity_sha256: str,
    ) -> dict:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.add_named_library(
                library_id,
                display_name,
                source_root,
                source_canonical_root,
                source_identity_sha256,
            )
            return dict(catalog.get_named_library(library_id))

    def update_named_library(
        self,
        library_id: str,
        *,
        display_name: str | None = None,
        source_root: str | None = None,
        source_canonical_root: str | None = None,
        source_identity_sha256: str | None = None,
        requested_state: str | None = None,
    ) -> dict:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return dict(
                catalog.update_named_library(
                    library_id,
                    display_name=display_name,
                    source_root=source_root,
                    source_canonical_root=source_canonical_root,
                    source_identity_sha256=source_identity_sha256,
                    requested_state=requested_state,
                )
            )

    def retire_named_library(self, library_id: str) -> dict:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return dict(catalog.retire_named_library(library_id))

    def scan_named_library(
        self,
        library_id: str,
        *,
        expected_source_identity: tuple[str, str],
        min_age_seconds: int = 0,
        buffer_bytes: int = 16 * 1024**2,
        managed_source_evidence: Mapping[str, Any] | None = None,
        managed_source_lease_id: str | None = None,
        reverify_managed_source: Callable[[], tuple[str, str]] | None = None,
    ) -> dict:
        """Scan one validated source without entering the hardware operation path."""

        if (
            reverify_managed_source is not None
            and reverify_managed_source() != expected_source_identity
        ):
            raise ValidationError("La sorgente libreria e cambiata")
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            library = dict(catalog.get_named_library(library_id))
            if _source_identity(library["source_root"]) != expected_source_identity:
                raise ValidationError("La sorgente libreria e cambiata")
            analysis = analyze_library(
                catalog,
                str(library["id"]),
                min_age_seconds,
                listing_limit=0,
                buffer_bytes=buffer_bytes,
                persist_catalog_updates=False,
            )
        if _source_identity(library["source_root"]) != expected_source_identity:
            raise ValidationError("La sorgente libreria e cambiata")
        if (
            reverify_managed_source is not None
            and reverify_managed_source() != expected_source_identity
        ):
            raise ValidationError("La sorgente libreria e cambiata")
        canonical_root, identity_sha256 = expected_source_identity
        fingerprint = _canonical_scan_fingerprint(
            str(library["id"]),
            canonical_root,
            total_files=analysis.total_files,
            total_bytes=analysis.total_bytes,
            archived_files=analysis.archived_files,
            too_recent_files=analysis.too_recent_files,
            pending_items=list(analysis.pending_items),
        )
        final_guard = (
            RunLock(self.paths.lock_file)
            if managed_source_evidence is None
            else nullcontext()
        )
        with final_guard, Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            current = catalog.get_named_library(library_id)
            if (
                managed_source_evidence is None
                and _source_identity(current["source_root"]) != expected_source_identity
            ):
                raise ValidationError("La sorgente libreria e cambiata")
            return dict(
                catalog.complete_named_library_scan(
                    str(current["id"]),
                    total_files=analysis.total_files,
                    total_bytes=analysis.total_bytes,
                    scan_fingerprint_sha256=fingerprint,
                    source_canonical_root=canonical_root,
                    source_identity_sha256=identity_sha256,
                    managed_source_evidence=managed_source_evidence,
                    managed_source_lease_id=managed_source_lease_id,
                )
            )

    def configure_content_verification(self, enabled: bool) -> dict:
        settings = load_settings(self.paths)
        updated = replace(settings, verify_unchanged_content=bool(enabled))
        save_settings(self.paths, updated)
        return asdict(updated)

    def delete_library(self, library_id: str) -> dict:
        """Compatibility alias for soft retirement; catalog history is immutable."""

        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return dict(catalog.retire_named_library(library_id))

    def register_tape(
        self,
        tape_id: str,
        cassette_number: str,
        mount: Path,
        known_volume: VolumeInfo | None = None,
        settings: Settings | None = None,
    ) -> dict:
        settings = load_settings(self.paths) if settings is None else settings
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            volume = BackupEngine(catalog, settings, self.paths).register_tape(
                tape_id,
                Path(mount),
                cassette_number=cassette_number,
                known_volume=known_volume,
            )
            return {
                "tape_id": tape_id,
                "cassette_number": cassette_number,
                "mount": str(volume.root),
                "label": volume.label,
                "serial": volume.serial,
                "filesystem": volume.filesystem,
                "free_bytes": volume.free_bytes,
                "free_human": human_bytes(volume.free_bytes),
            }

    def search_files(
        self,
        query: str,
        library_id: str | None = None,
        include_history: bool = False,
        limit: int = 500,
    ) -> list[dict]:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            rows = []
            for row in catalog.search_files(
                query,
                library_id=library_id,
                include_history=include_history,
                limit=limit,
            ):
                item = dict(row)
                try:
                    item["alternate_streams"] = json.loads(
                        item.get("alternate_streams_json") or "[]"
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    item["alternate_streams"] = []
                rows.append(item)
            return rows

    def browse_backup_children(
        self, library_id: str, parent_path: str = ""
    ) -> list[dict]:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.browse_backup_children(library_id, parent_path)

    def scan(self, library_id: str, min_age_seconds: int | None = None) -> dict:
        settings = load_settings(self.paths)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            plan = BackupEngine(catalog, settings, self.paths).scan(
                library_id, min_age_seconds
            )
            return {
                "library_id": plan.library_id,
                "source_root": str(plan.source_root),
                "files": len(plan.items),
                "bytes": plan.total_bytes,
                "human": human_bytes(plan.total_bytes),
                "source_files": plan.source_files,
                "source_bytes": plan.source_bytes,
                "source_human": human_bytes(plan.source_bytes),
                "skipped_unchanged": plan.skipped_unchanged,
                "skipped_too_recent": plan.skipped_too_recent,
            }

    def scan_all_libraries(
        self,
        progress: ProgressCallback | None = None,
        min_age_seconds: int | None = None,
    ) -> dict:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            library_ids = [row["id"] for row in catalog.list_libraries()]
        total = len(library_ids)
        results: list[dict] = []
        for index, library_id in enumerate(library_ids, 1):
            if progress:
                progress(
                    {
                        "event": "library.scan.start",
                        "library_id": library_id,
                        "index": index,
                        "total": total,
                    }
                )
            result = self.scan(library_id, min_age_seconds=min_age_seconds)
            results.append(result)
            if progress:
                progress(
                    {
                        "event": "library.scan.complete",
                        "library_id": library_id,
                        "index": index,
                        "total": total,
                        "files": result["files"],
                        "bytes": result["bytes"],
                    }
                )
        total_files = sum(int(row["files"]) for row in results)
        total_bytes = sum(int(row["bytes"]) for row in results)
        source_files = sum(int(row["source_files"]) for row in results)
        source_bytes = sum(int(row["source_bytes"]) for row in results)
        return {
            "total_libraries": total,
            "completed_libraries": len(results),
            "total_files": total_files,
            "total_bytes": total_bytes,
            "total_human": human_bytes(total_bytes),
            "source_files": source_files,
            "source_bytes": source_bytes,
            "source_human": human_bytes(source_bytes),
            "libraries": results,
        }

    def analyze_library(self, library_id: str, listing_limit: int = 5000) -> dict:
        settings = load_settings(self.paths)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                source_policy = catalog.get_application_settings()[
                    "source_change_detection_policy"
                ]
            except CatalogError as exc:
                if str(exc) != "application_settings_uninitialized":
                    raise
                source_policy = "size_mtime"
            analysis = analyze_library(
                catalog,
                library_id,
                settings.min_age_seconds,
                listing_limit=listing_limit,
                verify_unchanged_content=settings.verify_unchanged_content,
                buffer_bytes=settings.buffer_bytes,
                source_change_detection_policy=source_policy,
            )
            usable = self._usable_tape_bytes(settings)
            batches = (
                _plan_ltfs_batches(
                    analysis.pending_items,
                    usable,
                    nominal_capacity_bytes=settings.tape_capacity_bytes,
                )
                if analysis.pending_items
                else ()
            )
            distribution = catalog.library_tape_distribution(library_id)
            return {
                "library_id": library_id,
                "source_root": str(analysis.source_root),
                "total_files": analysis.total_files,
                "total_bytes": analysis.total_bytes,
                "total_human": human_bytes(analysis.total_bytes),
                "archived_files": analysis.archived_files,
                "legacy_uncovered_files": analysis.legacy_uncovered_files,
                "source_change_detection_policy": source_policy,
                "source_change_detection_assurance": "best_effort_metadata",
                "archived_bytes": analysis.archived_bytes,
                "archived_human": human_bytes(analysis.archived_bytes),
                "pending_files": len(analysis.pending_items),
                "pending_bytes": sum(item.size for item in analysis.pending_items),
                "pending_human": human_bytes(
                    sum(item.size for item in analysis.pending_items)
                ),
                "too_recent_files": analysis.too_recent_files,
                "too_recent_bytes": analysis.too_recent_bytes,
                "listing_truncated": analysis.listing_truncated,
                "listing": [asdict(entry) for entry in analysis.entries],
                "extensions": [
                    {
                        "extension": extension,
                        "file_count": count,
                        "total_bytes": size,
                        "human": human_bytes(size),
                    }
                    for extension, count, size in analysis.extension_counts
                ],
                "nominal_tape_bytes": settings.tape_capacity_bytes,
                "nominal_tape_human": human_bytes(settings.tape_capacity_bytes),
                "reserve_bytes": settings.reserve_bytes,
                "reserve_human": human_bytes(settings.reserve_bytes),
                "usable_tape_bytes": usable,
                "usable_tape_human": human_bytes(usable),
                "estimated_tapes": len(batches),
                "planned_batches": [
                    {
                        "slot": batch.slot,
                        "file_count": len(batch.items),
                        "total_bytes": batch.total_bytes,
                        "human": human_bytes(batch.total_bytes),
                        "capacity_used_bytes": batch.capacity_used_bytes,
                        "capacity_used_human": human_bytes(
                            batch.capacity_used_bytes or 0
                        ),
                        "ltfs_overhead_bytes": (batch.capacity_used_bytes or 0)
                        - batch.total_bytes,
                        "ltfs_overhead_human": human_bytes(
                            (batch.capacity_used_bytes or 0) - batch.total_bytes
                        ),
                        "remaining_bytes": batch.remaining_bytes,
                        "remaining_human": human_bytes(batch.remaining_bytes),
                        "utilization_percent": round(
                            (batch.capacity_used_bytes or 0) * 100 / usable, 1
                        ),
                    }
                    for batch in batches
                ],
                "tape_distribution": [
                    {
                        **dict(row),
                        "human": human_bytes(row["total_bytes"]),
                    }
                    for row in distribution
                ],
            }

    def backup(
        self,
        library_id: str,
        tape_id: str,
        mount: Path,
        progress: ProgressCallback | None = None,
        dry_run: bool = False,
        only_relative_paths: set[str] | None = None,
        stop_requested: Callable[[], bool] | None = None,
        known_volume: VolumeInfo | None = None,
        known_plan: ScanPlan | None = None,
        tape_capacity_bytes: int | None = None,
        defer_completion: bool = False,
        write_catalog_snapshot: bool = True,
        settings: Settings | None = None,
        automatic_operation_id: str | None = None,
        automatic_job_id: str | None = None,
        automatic_cassette_sequence: int | None = None,
        frozen_manifest: bool = False,
    ) -> dict:
        settings = load_settings(self.paths) if settings is None else settings
        if tape_capacity_bytes is not None:
            settings = replace(settings, tape_capacity_bytes=tape_capacity_bytes)
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            result = BackupEngine(catalog, settings, self.paths).backup(
                library_id,
                tape_id,
                Path(mount),
                progress=progress,
                dry_run=dry_run,
                only_relative_paths=only_relative_paths,
                stop_requested=stop_requested,
                known_volume=known_volume,
                known_plan=known_plan,
                defer_completion=defer_completion,
                write_catalog_snapshot=write_catalog_snapshot,
                automatic_operation_id=automatic_operation_id,
                automatic_job_id=automatic_job_id,
                automatic_cassette_sequence=automatic_cassette_sequence,
                frozen_manifest=frozen_manifest,
            )
            if result is None:
                return {"status": "nothing-to-copy", "library_id": library_id}
            return {
                "status": (
                    "dry-run"
                    if dry_run
                    else "pending-commit"
                    if defer_completion
                    else "completed"
                ),
                "block_id": result.block_id,
                "library_id": result.library_id,
                "tape_id": result.tape_id,
                "copied_files": result.copied_files,
                "copied_bytes": result.copied_bytes,
                "copied_human": human_bytes(result.copied_bytes),
                "tape_relative_root": result.tape_relative_root,
                "remaining_files": result.remaining_files,
                "remaining_bytes": result.remaining_bytes,
                "remaining_human": human_bytes(result.remaining_bytes),
                "estimated_remaining_tapes": result.estimated_remaining_tapes,
            }

    def backup_automatic_batch(
        self,
        library_ids: list[str],
        tape_id: str,
        mount: Path,
        progress: ProgressCallback | None = None,
        stop_requested: Callable[[], bool] | None = None,
        known_volume: VolumeInfo | None = None,
        tape_capacity_bytes: int | None = None,
        automatic_job_id: str | None = None,
        settings: Settings | None = None,
        frozen_plans_by_library: Mapping[str, ScanPlan] | None = None,
        automatic_operation_id: str | None = None,
        automatic_cassette_sequence: int | None = None,
        source_change_detection_policy: str = "size_mtime",
    ) -> dict:
        settings = load_settings(self.paths) if settings is None else settings
        if tape_capacity_bytes is not None:
            settings = replace(settings, tape_capacity_bytes=tape_capacity_bytes)
        combined_items = []
        plans_by_library: dict[str, ScanPlan] = {}
        current_manifest: list[dict] = []
        pending_manifest: list[dict] = []
        current_sequence: int | None = None
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            engine = BackupEngine(
                catalog, settings, self.paths,
                source_change_detection_policy=source_change_detection_policy,
            )
            if known_volume is None:
                _tape, volume = engine.validate_tape(tape_id, Path(mount))
            else:
                _tape = catalog.get_tape(tape_id)
                volume = known_volume
            if frozen_plans_by_library is not None and set(
                frozen_plans_by_library
            ) != set(library_ids):
                raise ValidationError(
                    "I piani congelati non corrispondono alle librerie"
                )
            for index, library_id in enumerate(library_ids, start=1):
                if stop_requested and stop_requested():
                    raise OperationCancelled("Backup interrotto dall'operatore")
                if progress and frozen_plans_by_library is None:
                    progress(
                        {
                            "event": "batch.scan.start",
                            "library_id": library_id,
                            "index": index,
                            "total": len(library_ids),
                        }
                    )
                plan = (
                    engine.scan(library_id)
                    if frozen_plans_by_library is None
                    else frozen_plans_by_library[library_id]
                )
                if plan.library_id != library_id:
                    raise ValidationError(
                        "Il piano congelato appartiene a un'altra libreria"
                    )
                plans_by_library[library_id] = plan
                combined_items.extend(
                    replace(item, library_id=library_id) for item in plan.items
                )
                if progress and frozen_plans_by_library is None:
                    progress(
                        {
                            "event": "batch.scan.complete",
                            "library_id": library_id,
                            "index": index,
                            "total": len(library_ids),
                            "files": len(plan.items),
                            "bytes": plan.total_bytes,
                        }
                    )
            if automatic_job_id:
                cassette = next(
                    (
                        row
                        for row in catalog.list_automatic_cassettes(automatic_job_id)
                        if str(row["physical_label"]).casefold()
                        == str(tape_id).casefold()
                        and row["status"] != "completed"
                    ),
                    None,
                )
                if cassette is None:
                    raise ValidationError(
                        f"La cassetta {tape_id} non appartiene alla coda attiva del job "
                        f"{automatic_job_id}"
                    )
                current_sequence = int(cassette["sequence"])
                current_manifest = [
                    dict(row)
                    for row in catalog.list_automatic_cassette_manifest(
                        automatic_job_id, current_sequence
                    )
                ]
                pending_manifest = [
                    dict(row)
                    for row in catalog.list_pending_automatic_manifest(automatic_job_id)
                ]
        if not combined_items and not automatic_job_id:
            return {
                "status": "nothing-to-copy",
                "block_ids": [],
                "copied_files": 0,
                "copied_bytes": 0,
                "remaining_files": 0,
                "remaining_bytes": 0,
                "estimated_remaining_tapes": 0,
            }
        nominal_usable = self._usable_tape_bytes(settings)
        if automatic_job_id:
            if not current_manifest:
                raise ValidationError(
                    f"Manifest file assente per la cassetta {current_sequence} del job "
                    f"{automatic_job_id}"
                )
            available = {
                (
                    str(item.library_id or "").casefold(),
                    item.relative_path.casefold(),
                ): item
                for item in combined_items
            }
            selected_items = []
            changed: list[str] = []
            missing: list[str] = []
            for row in current_manifest:
                key = (
                    str(row["library_id"]).casefold(),
                    str(row["relative_path"]).casefold(),
                )
                item = available.get(key)
                display = f"{row['library_id']}/{row['relative_path']}"
                if item is None:
                    missing.append(display)
                    continue
                if item.size != int(row["size"]) or item.mtime_ns != int(
                    row["mtime_ns"]
                ):
                    changed.append(display)
                    continue
                selected_items.append(item)
            if missing or changed:
                details = []
                if missing:
                    details.append(f"mancanti: {', '.join(missing[:5])}")
                if changed:
                    details.append(f"modificati: {', '.join(changed[:5])}")
                raise ValidationError(
                    "Il manifest della cassetta non coincide piu con le sorgenti ("
                    + "; ".join(details)
                    + "). Ripristinare i file pianificati o creare un nuovo ciclo."
                )
            available_bytes = self._mounted_usable_tape_bytes(settings, volume)
            selected_capacity_bytes = _ltfs_batch_bytes(
                selected_items, settings.tape_capacity_bytes
            )
            if selected_capacity_bytes > available_bytes:
                raise CapacityError(
                    f"Il manifest richiede {human_bytes(selected_capacity_bytes)} di spazio LTFS "
                    f"(file e metadati), ma sulla cassetta "
                    f"sono utilizzabili {human_bytes(available_bytes)}."
                )
            selected = TapeBatch(
                slot=current_sequence or 1,
                items=tuple(selected_items),
                usable_bytes=available_bytes,
                capacity_used_bytes=selected_capacity_bytes,
            )
        else:
            selected = _select_ltfs_batch(
                combined_items,
                self._mounted_usable_tape_bytes(settings, volume),
                nominal_capacity_bytes=settings.tape_capacity_bytes,
            )
        selected_by_library: dict[str, set[str]] = {
            library_id: set() for library_id in library_ids
        }
        for item in selected.items:
            if item.library_id:
                selected_by_library[item.library_id].add(item.relative_path)

        results: list[dict] = []
        try:
            for library_id in library_ids:
                if stop_requested and stop_requested():
                    raise OperationCancelled("Backup interrotto dall'operatore")
                paths = selected_by_library[library_id]
                if not paths:
                    continue
                result = self.backup(
                    library_id,
                    tape_id,
                    Path(mount),
                    progress=progress,
                    only_relative_paths=paths,
                    stop_requested=stop_requested,
                    known_volume=known_volume,
                    known_plan=plans_by_library[library_id],
                    tape_capacity_bytes=tape_capacity_bytes,
                    defer_completion=True,
                    write_catalog_snapshot=False,
                    settings=settings,
                    automatic_operation_id=automatic_operation_id,
                    automatic_job_id=(
                        automatic_job_id
                        if automatic_operation_id is not None
                        else None
                    ),
                    automatic_cassette_sequence=(
                        automatic_cassette_sequence
                        if automatic_operation_id is not None
                        else None
                    ),
                    frozen_manifest=frozen_plans_by_library is not None,
                )
                if result["status"] != "nothing-to-copy":
                    results.append(result)
        except BaseException as exc:
            staged_ids = [row["block_id"] for row in results]
            if staged_ids:
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.fail_blocks(staged_ids, str(exc))
            raise

        selected_keys = {
            (str(item.library_id or ""), item.relative_path) for item in selected.items
        }
        if automatic_job_id:
            remaining_manifest = [
                row
                for row in pending_manifest
                if int(row["sequence"]) != int(current_sequence or 0)
            ]
            remaining_items = []
            remaining_files = len(remaining_manifest)
            remaining_bytes = sum(int(row["size"]) for row in remaining_manifest)
            estimated_remaining_tapes = len(
                {int(row["sequence"]) for row in remaining_manifest}
            )
        else:
            remaining_items = [
                item
                for item in combined_items
                if (str(item.library_id or ""), item.relative_path) not in selected_keys
            ]
            remaining_batches = (
                _plan_ltfs_batches(
                    remaining_items,
                    nominal_usable,
                    nominal_capacity_bytes=settings.tape_capacity_bytes,
                )
                if remaining_items
                else ()
            )
            remaining_files = len(remaining_items)
            remaining_bytes = sum(item.size for item in remaining_items)
            estimated_remaining_tapes = len(remaining_batches)
        block_ids = [row["block_id"] for row in results]
        if block_ids:
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.initialize()
                try:
                    BackupEngine(catalog, settings, self.paths).write_catalog_snapshot(
                        volume.root, block_ids[-1]
                    )
                except Exception as snapshot_error:
                    catalog.event(
                        "catalog.snapshot.warning",
                        {"block_ids": block_ids, "error": str(snapshot_error)},
                    )
                    if progress:
                        progress(
                            {
                                "event": "catalog.snapshot.warning",
                                "block_id": block_ids[-1],
                                "error": str(snapshot_error),
                            }
                        )
        return {
            "status": "pending-commit",
            "commit_required": True,
            "block_id": ",".join(block_ids),
            "block_ids": block_ids,
            "copied_files": sum(int(row["copied_files"]) for row in results),
            "copied_bytes": sum(int(row["copied_bytes"]) for row in results),
            "remaining_files": remaining_files,
            "remaining_bytes": remaining_bytes,
            "estimated_remaining_tapes": estimated_remaining_tapes,
        }

    def restore_plan(self, library_id: str) -> list[dict]:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.get_library(library_id, include_retired=True)
            return [
                {
                    "tape_id": row["tape_id"],
                    "file_count": row["file_count"],
                    "total_bytes": row["total_bytes"],
                    "human": human_bytes(row["total_bytes"]),
                }
                for row in catalog.restore_plan(library_id)
            ]

    def restore(
        self,
        library_id: str,
        tape_id: str,
        mount: Path,
        destination: Path,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> dict:
        settings = load_settings(self.paths)
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            files, total_bytes = BackupEngine(catalog, settings, self.paths).restore(
                library_id,
                tape_id,
                Path(mount),
                Path(destination),
                overwrite=overwrite,
                progress=progress,
            )
            return {
                "restored_files": files,
                "restored_bytes": total_bytes,
                "restored_human": human_bytes(total_bytes),
            }

    def forget_block(self, block_id: str) -> None:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.forget_block(block_id)

    def catalog_check(self) -> dict:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            schema_row = catalog.connection.execute(
                "SELECT value FROM metadata WHERE key='schema_version'"
            ).fetchone()
            return {
                "schema_version": int(schema_row[0]) if schema_row else 0,
                "integrity": catalog.connection.execute(
                    "PRAGMA integrity_check"
                ).fetchone()[0],
                "foreign_key_errors": [
                    dict(row)
                    for row in catalog.connection.execute("PRAGMA foreign_key_check")
                ],
                "pending_blocks": [
                    dict(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM blocks WHERE status='copying' ORDER BY started_at"
                    )
                ],
                "missing_cassette_numbers": catalog.connection.execute(
                    "SELECT COUNT(*) FROM tapes "
                    "WHERE cassette_number IS NULL OR trim(cassette_number)=''"
                ).fetchone()[0],
                "uncommitted_visible_files": catalog.connection.execute(
                    """
                    SELECT COUNT(*) FROM file_versions fv
                    JOIN blocks b ON b.id=fv.block_id
                    WHERE fv.visible=1 AND b.status<>'completed'
                    """
                ).fetchone()[0],
            }

    def doctor(self, tape_id: str, mount: Path) -> dict:
        if not tape_id or str(mount).strip() in {"", "."}:
            raise ValidationError("Selezionare un nastro e indicare il mount LTFS")
        settings = load_settings(self.paths)
        result = self.catalog_check()
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            tape, volume = BackupEngine(catalog, settings, self.paths).validate_tape(
                tape_id, Path(mount)
            )
            result["volume"] = {
                "tape_id": tape_id,
                "cassette_number": tape["cassette_number"],
                "root": str(volume.root),
                "filesystem": volume.filesystem,
                "label": volume.label,
                "serial": volume.serial,
                "free_bytes": volume.free_bytes,
                "free_human": human_bytes(volume.free_bytes),
                "reserve_bytes": settings.reserve_bytes,
                "reserve_human": human_bytes(settings.reserve_bytes),
                "reserve_kind": "margine applicativo configurabile",
                "usable_bytes": self._mounted_usable_tape_bytes(settings, volume),
                "usable_human": human_bytes(
                    self._mounted_usable_tape_bytes(settings, volume)
                ),
            }
        return result

    def export_catalog(self, destination: Path) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            write_json_atomic(Path(destination), catalog.export())
