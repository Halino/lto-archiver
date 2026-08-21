from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Callable
import re
import uuid

from . import __version__
from .catalog import Catalog
from .automation import AutomaticJobRunner, normalize_cassette_labels
from .engine import BackupEngine
from .errors import CapacityError, OperationCancelled, ValidationError
from .media import LtoMediaProfile, require_ltfs_profile
from .models import ScanPlan, TapeBatch, VolumeInfo
from .planner import capacity_model_for_media, plan_tape_batches, select_tape_batch
from .scanner import analyze_library
from .settings import (
    AppPaths,
    DEFAULT_RESERVE_BYTES,
    Settings,
    load_settings,
    save_settings,
    upgrade_legacy_settings,
)
from .util import RunLock, human_bytes, write_json_atomic


ProgressCallback = Callable[[dict], None]


def _plan_ltfs_batches(
    items, usable_bytes: int, nominal_capacity_bytes: int | None = None
) -> tuple[TapeBatch, ...]:
    return plan_tape_batches(
        items,
        usable_bytes,
        capacity_model=capacity_model_for_media(
            usable_bytes if nominal_capacity_bytes is None else nominal_capacity_bytes
        ),
    )


def _select_ltfs_batch(
    items, usable_bytes: int, nominal_capacity_bytes: int | None = None
) -> TapeBatch:
    return select_tape_batch(
        items,
        usable_bytes,
        capacity_model=capacity_model_for_media(
            usable_bytes if nominal_capacity_bytes is None else nominal_capacity_bytes
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
            raise ValidationError("La capacita utilizzabile per nastro deve essere maggiore di zero")
        return usable

    @staticmethod
    def _media_tape_capacity(settings: Settings, profile: LtoMediaProfile) -> int:
        # Automatic plans are media-specific: every generation, including
        # LTO-6, uses its documented LTFS data-partition capacity.
        del settings
        assert profile.ltfs_usable_bytes is not None
        return profile.ltfs_usable_bytes

    @classmethod
    def _media_usable_tape_bytes(cls, settings: Settings, profile: LtoMediaProfile) -> int:
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
                save_settings(
                    self.paths,
                    Settings(
                        reserve_bytes=reserve_gib * 1024**3,
                        buffer_bytes=buffer_mib * 1024**2,
                        min_age_seconds=min_age_seconds,
                    ),
                )
            else:
                upgrade_legacy_settings(self.paths)
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.initialize()
                if not catalog.connection.execute(
                    "SELECT 1 FROM events WHERE action='application.init' LIMIT 1"
                ).fetchone():
                    catalog.event("application.init", {"version": __version__, "interface": "gui"})

    def snapshot(self) -> dict:
        settings = load_settings(self.paths)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            automatic_jobs = []
            for row in catalog.list_automatic_jobs():
                job = dict(row)
                job["library_ids"] = [
                    item["library_id"] for item in catalog.list_automatic_job_libraries(row["id"])
                ]
                automatic_jobs.append(job)
            return {
                "settings": asdict(settings),
                "libraries": [dict(row) for row in catalog.list_libraries(include_retired=True)],
                "tapes": [dict(row) for row in catalog.list_tapes()],
                "blocks": [dict(row) for row in catalog.list_blocks(include_forgotten=True)],
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
                    row for row in cassettes
                    if row["status"] != "completed"
                    and (
                        int(row["planned_files"]) > 0
                        or int(row["planned_bytes"]) > 0
                    )
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
            raise ValidationError("Confermare esplicitamente la formattazione automatica delle cassette")
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
        batches = _plan_ltfs_batches(combined_items, usable) if combined_items else ()
        estimated = len(batches)
        if estimated == 0:
            raise ValidationError("Le librerie selezionate non contengono file nuovi da copiare")
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
        job_id = "AUTO-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
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

    def plan_automatic_job(
        self,
        library_ids: str | list[str],
        progress: ProgressCallback | None = None,
        media_key: str = "LTO-6",
    ) -> dict:
        """Build the same cumulative, optimized tape plan used by an automatic job."""
        selected_library_ids = self._normalize_library_ids(library_ids)
        profile = require_ltfs_profile(media_key)
        settings = load_settings(self.paths)
        combined_items = []
        library_rows: list[dict] = []
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            total_libraries = len(selected_library_ids)
            for index, library_id in enumerate(selected_library_ids, 1):
                if progress:
                    progress(
                        {
                            "event": "library.scan.start",
                            "library_id": library_id,
                            "index": index,
                            "total": total_libraries,
                        }
                    )
                library = catalog.get_library(library_id)
                analysis = analyze_library(
                    catalog,
                    library_id,
                    settings.min_age_seconds,
                    listing_limit=0,
                )
                pending_items = [
                    replace(item, library_id=library_id)
                    for item in analysis.pending_items
                ]
                pending_bytes = sum(item.size for item in pending_items)
                combined_items.extend(pending_items)
                library_rows.append(
                    {
                        "library_id": library_id,
                        "name": library["name"],
                        "source_root": library["source_root"],
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
        batches = _plan_ltfs_batches(combined_items, usable) if combined_items else ()
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
                    "ltfs_overhead_bytes": (batch.capacity_used_bytes or 0) - batch.total_bytes,
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
        return {
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

    @staticmethod
    def _normalize_library_ids(library_ids: str | list[str]) -> list[str]:
        candidates = [library_ids] if isinstance(library_ids, str) else list(library_ids)
        selected: list[str] = []
        seen: set[str] = set()
        for library_id in candidates:
            normalized = library_id.strip()
            if normalized and normalized.casefold() not in seen:
                selected.append(normalized)
                seen.add(normalized.casefold())
        if not selected:
            raise ValidationError("Selezionare almeno una libreria per il job automatico")
        return selected

    @staticmethod
    def _cassette_manifest_items(items: tuple | list) -> list[tuple[str, str, int, int]]:
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
                row["library_id"] for row in catalog.list_automatic_job_libraries(job_id)
            ]
            result["cassettes"] = [dict(row) for row in catalog.list_automatic_cassettes(job_id)]
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
                    row for row in catalog.list_automatic_cassettes(job_id)
                    if int(row["sequence"]) == int(sequence)
                ),
                None,
            )
            if cassette is None:
                raise ValidationError(f"Cassetta {sequence} non trovata nel job {job_id}")
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
                row for row in rows
                if row["status"] != "completed"
                and (int(row["planned_files"]) > 0 or int(row["planned_bytes"]) > 0)
            ]
            manifest_counts = [
                len(catalog.list_automatic_cassette_manifest(job_id, int(row["sequence"])))
                for row in active_rows
            ]
            active_manifests_complete = bool(active_rows) and all(manifest_counts)
            if active_rows and any(manifest_counts) and not all(manifest_counts):
                raise ValidationError(
                    "Il piano persistente del job e incompleto: alcune cassette hanno un "
                    "manifest e altre no. Non avviare la scrittura."
                )
            reserves = [
                row for row in rows
                if row["status"] == "pending"
                and int(row["planned_files"]) == 0
                and int(row["planned_bytes"]) == 0
            ]
            library_ids = [
                row["library_id"] for row in catalog.list_automatic_job_libraries(job_id)
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
                    (str(item.library_id or "").casefold(), item.relative_path.casefold()): item
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
                        if (
                            source_item.size != int(item["size"])
                            or source_item.mtime_ns != int(item["mtime_ns"])
                        ):
                            raise ValidationError(
                                "Un file gia pianificato e stato modificato: "
                                f"{item['library_id']}/{item['relative_path']}"
                            )
                new_items = [
                    item for item in combined_items
                    if (
                        str(item.library_id or "").casefold(),
                        item.relative_path.casefold(),
                    ) not in planned_keys
                ]
                if not new_items:
                    active_plan_unchanged = True
                else:
                    usable = self._media_usable_tape_bytes(settings, profile)
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
                                    catalog, str(row["tape_id"]), usable
                                )
                            candidate = assignment_items[sequence] + [item]
                            if base_used + _ltfs_batch_bytes(candidate, usable) <= usable:
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
                        (int(row["sequence"]), tuple(assignment_items[int(row["sequence"])]))
                        for row in queue_rows
                    ]
            elif active_rows:
                remaining = list(combined_items)
                usable = self._media_usable_tape_bytes(settings, profile)
                queue_rows = [row for row in rows if row["status"] != "completed"]
                for row in queue_rows:
                    if not remaining:
                        legacy_manifests.append((int(row["sequence"]), ()))
                        continue
                    capacity = usable
                    if row["operation"] == "append" and row["tape_id"]:
                        capacity = max(
                            0,
                            usable - self._completed_tape_capacity_bytes(
                                catalog, str(row["tape_id"]), usable
                            ),
                        )
                    try:
                        recovered = _select_ltfs_batch(
                            remaining, capacity, nominal_capacity_bytes=usable
                        )
                    except CapacityError as exc:
                        raise ValidationError(
                            f"Impossibile congelare il manifest della cassetta "
                            f"{row['sequence']}: {exc}"
                        ) from exc
                    legacy_manifests.append((int(row["sequence"]), recovered.items))
                    recovered_keys = {
                        (str(item.library_id or "").casefold(), item.relative_path.casefold())
                        for item in recovered.items
                    }
                    remaining = [
                        item for item in remaining
                        if (str(item.library_id or "").casefold(), item.relative_path.casefold())
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
                        dict(row) for row in reversed(rows)
                        if row["status"] == "completed" and row["tape_id"]
                    ),
                    None,
                )
            if append_candidate and combined_items:
                usable = self._media_usable_tape_bytes(settings, profile)
                used = self._completed_tape_capacity_bytes(
                    catalog, str(append_candidate["tape_id"]), usable
                )
                residual = max(0, usable - used)
                if residual:
                    try:
                        selected = _select_ltfs_batch(
                            combined_items, residual, nominal_capacity_bytes=usable
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
                            item for item in combined_items
                            if (str(item.library_id or ""), item.relative_path) not in selected_keys
                        ]

        if active_plan_unchanged:
            return self.automatic_job(job_id)

        if extended_active_manifests:
            with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
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
            with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
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
                combined_items, self._media_usable_tape_bytes(settings, profile)
            )
            if combined_items else ()
        )
        if len(batches) > len(reserves):
            missing = len(batches) - len(reserves)
            raise ValidationError(
                f"I nuovi dati richiedono {len(batches)} cassette, ma il job ne ha "
                f"{len(reserves)} in riserva; aggiungere almeno {missing} cassette"
            )
        assignments = [(len(batch.items), batch.total_bytes) for batch in batches]
        reserve_sequences = [int(row["sequence"]) for row in reserves[:len(batches)]]
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
            raise ValidationError("Confermare esplicitamente la formattazione automatica delle cassette")
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
            with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
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
                raise ValidationError("Si possono aggiungere cassette solo a un job concluso")
            existing = catalog.list_automatic_cassettes(job_id)
            unfinished = next(
                (
                    row for row in existing
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
                    dict(row) for row in reversed(existing)
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
                row["library_id"] for row in catalog.list_automatic_job_libraries(job_id)
            ]
            engine = BackupEngine(catalog, settings, self.paths)
            for library_id in library_ids:
                plan = engine.scan(library_id)
                combined_items.extend(
                    replace(item, library_id=library_id) for item in plan.items
                )
        usable = self._media_usable_tape_bytes(settings, profile)
        if append_candidate and combined_items:
            residual = max(0, usable - append_used_bytes)
            if residual:
                try:
                    selected = _select_ltfs_batch(
                        combined_items, residual, nominal_capacity_bytes=usable
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
                        item for item in combined_items
                        if (str(item.library_id or ""), item.relative_path) not in selected_keys
                    ]
        batches = _plan_ltfs_batches(combined_items, usable) if combined_items else ()
        estimated = len(batches)
        if estimated == 0 and append_assignment is None:
            raise ValidationError("Le librerie del job non contengono file nuovi da copiare")
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
            ][:len(batches)]
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

    def run_automatic_job(
        self,
        job_id: str,
        progress: ProgressCallback | None = None,
        stop_requested: Callable[[], bool] = lambda: False,
    ) -> dict:
        settings = load_settings(self.paths)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            job = catalog.get_automatic_job(job_id)
            profile = require_ltfs_profile(job["media_key"])
        job_capacity = self._media_tape_capacity(settings, profile)

        def backup(
            library_ids: list[str],
            label: str,
            mounted: Path | VolumeInfo,
            callback: ProgressCallback | None,
            copy_stop_requested: Callable[[], bool],
        ) -> dict:
            known_volume = mounted if isinstance(mounted, VolumeInfo) else None
            mount = known_volume.root if known_volume else Path(mounted)
            self.register_tape(label, label, mount, known_volume=known_volume)
            return self.backup_automatic_batch(
                library_ids,
                label,
                mount,
                progress=callback,
                stop_requested=copy_stop_requested,
                known_volume=known_volume,
                tape_capacity_bytes=job_capacity,
                automatic_job_id=job_id,
            )

        with RunLock(self.paths.state_dir / "automatic-job.lock"):
            self.prepare_automatic_job_run(job_id)
            AutomaticJobRunner(
                self.paths,
                settings,
                backup=backup,
            ).run(job_id, progress=progress, stop_requested=stop_requested)
        return self.automatic_job(job_id)

    def add_library(self, library_id: str, name: str, source_root: str) -> None:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.add_library(library_id, name, source_root)

    def configure_content_verification(self, enabled: bool) -> dict:
        settings = load_settings(self.paths)
        updated = replace(settings, verify_unchanged_content=bool(enabled))
        save_settings(self.paths, updated)
        return asdict(updated)

    def delete_library(self, library_id: str) -> dict:
        with RunLock(self.paths.lock_file), Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.delete_library(library_id)

    def register_tape(
        self,
        tape_id: str,
        cassette_number: str,
        mount: Path,
        known_volume: VolumeInfo | None = None,
    ) -> dict:
        settings = load_settings(self.paths)
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

    def browse_backup_children(self, library_id: str, parent_path: str = "") -> list[dict]:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.browse_backup_children(library_id, parent_path)

    def scan(self, library_id: str, min_age_seconds: int | None = None) -> dict:
        settings = load_settings(self.paths)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            plan = BackupEngine(catalog, settings, self.paths).scan(library_id, min_age_seconds)
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
            analysis = analyze_library(
                catalog,
                library_id,
                settings.min_age_seconds,
                listing_limit=listing_limit,
                verify_unchanged_content=settings.verify_unchanged_content,
                buffer_bytes=settings.buffer_bytes,
            )
            usable = self._usable_tape_bytes(settings)
            batches = _plan_ltfs_batches(analysis.pending_items, usable) if analysis.pending_items else ()
            distribution = catalog.library_tape_distribution(library_id)
            return {
                "library_id": library_id,
                "source_root": str(analysis.source_root),
                "total_files": analysis.total_files,
                "total_bytes": analysis.total_bytes,
                "total_human": human_bytes(analysis.total_bytes),
                "archived_files": analysis.archived_files,
                "archived_bytes": analysis.archived_bytes,
                "archived_human": human_bytes(analysis.archived_bytes),
                "pending_files": len(analysis.pending_items),
                "pending_bytes": sum(item.size for item in analysis.pending_items),
                "pending_human": human_bytes(sum(item.size for item in analysis.pending_items)),
                "too_recent_files": analysis.too_recent_files,
                "too_recent_bytes": analysis.too_recent_bytes,
                "listing_truncated": analysis.listing_truncated,
                "listing": [asdict(entry) for entry in analysis.entries],
                "extensions": [
                    {"extension": extension, "file_count": count, "total_bytes": size, "human": human_bytes(size)}
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
                        "capacity_used_human": human_bytes(batch.capacity_used_bytes or 0),
                        "ltfs_overhead_bytes": (batch.capacity_used_bytes or 0) - batch.total_bytes,
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
    ) -> dict:
        settings = load_settings(self.paths)
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
            )
            if result is None:
                return {"status": "nothing-to-copy", "library_id": library_id}
            return {
                "status": (
                    "dry-run" if dry_run else
                    "pending-commit" if defer_completion else
                    "completed"
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
    ) -> dict:
        settings = load_settings(self.paths)
        if tape_capacity_bytes is not None:
            settings = replace(settings, tape_capacity_bytes=tape_capacity_bytes)
        combined_items = []
        plans_by_library: dict[str, ScanPlan] = {}
        current_manifest: list[dict] = []
        pending_manifest: list[dict] = []
        current_sequence: int | None = None
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            engine = BackupEngine(catalog, settings, self.paths)
            if known_volume is None:
                _tape, volume = engine.validate_tape(tape_id, Path(mount))
            else:
                _tape = catalog.get_tape(tape_id)
                volume = known_volume
            for index, library_id in enumerate(library_ids, start=1):
                if stop_requested and stop_requested():
                    raise OperationCancelled("Backup interrotto dall'operatore")
                if progress:
                    progress({
                        "event": "batch.scan.start", "library_id": library_id,
                        "index": index, "total": len(library_ids),
                    })
                plan = engine.scan(library_id)
                plans_by_library[library_id] = plan
                combined_items.extend(
                    replace(item, library_id=library_id) for item in plan.items
                )
                if progress:
                    progress({
                        "event": "batch.scan.complete", "library_id": library_id,
                        "index": index, "total": len(library_ids),
                        "files": len(plan.items), "bytes": plan.total_bytes,
                    })
            if automatic_job_id:
                cassette = next(
                    (
                        row for row in catalog.list_automatic_cassettes(automatic_job_id)
                        if str(row["physical_label"]).casefold() == str(tape_id).casefold()
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
                    dict(row) for row in catalog.list_automatic_cassette_manifest(
                        automatic_job_id, current_sequence
                    )
                ]
                pending_manifest = [
                    dict(row) for row in catalog.list_pending_automatic_manifest(
                        automatic_job_id
                    )
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
                (str(item.library_id or "").casefold(), item.relative_path.casefold()): item
                for item in combined_items
            }
            selected_items = []
            changed: list[str] = []
            missing: list[str] = []
            for row in current_manifest:
                key = (str(row["library_id"]).casefold(), str(row["relative_path"]).casefold())
                item = available.get(key)
                display = f"{row['library_id']}/{row['relative_path']}"
                if item is None:
                    missing.append(display)
                    continue
                if item.size != int(row["size"]) or item.mtime_ns != int(row["mtime_ns"]):
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
        selected_by_library: dict[str, set[str]] = {library_id: set() for library_id in library_ids}
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
                row for row in pending_manifest
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
                item for item in combined_items
                if (str(item.library_id or ""), item.relative_path) not in selected_keys
            ]
            remaining_batches = (
                _plan_ltfs_batches(remaining_items, nominal_usable) if remaining_items else ()
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
                        progress({
                            "event": "catalog.snapshot.warning",
                            "block_id": block_ids[-1],
                            "error": str(snapshot_error),
                        })
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
                "integrity": catalog.connection.execute("PRAGMA integrity_check").fetchone()[0],
                "foreign_key_errors": [
                    dict(row) for row in catalog.connection.execute("PRAGMA foreign_key_check")
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
            tape, volume = BackupEngine(catalog, settings, self.paths).validate_tape(tape_id, Path(mount))
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
                "usable_human": human_bytes(self._mounted_usable_tape_bytes(settings, volume)),
            }
        return result

    def export_catalog(self, destination: Path) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            write_json_atomic(Path(destination), catalog.export())
