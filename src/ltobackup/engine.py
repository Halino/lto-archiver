from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Callable

from .catalog import Catalog
from .errors import CapacityError, CopyError, OperationCancelled, ValidationError
from .models import BackupResult, ScanPlan, TapeBatch, VolumeInfo
from .planner import capacity_model_for_media, plan_tape_batches, select_tape_batch
from .scanner import scan_library
from .settings import AppPaths, Settings
from .util import (
    LTFS_SLOW_CLOSE_SECONDS,
    copy_and_hash,
    human_bytes,
    ltfs_tape_relative_path,
    native_path,
    safe_join,
    sha256_file,
    utc_now,
    write_json_atomic,
)
from .volume import assert_registered_tape, inspect_volume, require_ltfs

ProgressCallback = Callable[[dict], None]
StopRequested = Callable[[], bool]
VolumeProvider = Callable[[Path], VolumeInfo]


class BackupEngine:
    def __init__(
        self,
        catalog: Catalog,
        settings: Settings,
        paths: AppPaths,
        volume_provider: VolumeProvider = inspect_volume,
        enforce_ltfs: bool = True,
        *,
        source_change_detection_policy: str = "size_mtime",
    ):
        self.catalog = catalog
        self.settings = settings
        self.paths = paths
        self.volume_provider = volume_provider
        self.enforce_ltfs = enforce_ltfs
        if source_change_detection_policy not in {"size_mtime", "size_mtime_change"}:
            raise ValidationError("invalid source change detection policy")
        self.source_change_detection_policy = source_change_detection_policy

    def scan(self, library_id: str, min_age_seconds: int | None = None) -> ScanPlan:
        return scan_library(
            self.catalog,
            library_id,
            self.settings.min_age_seconds if min_age_seconds is None else min_age_seconds,
            verify_unchanged_content=self.settings.verify_unchanged_content,
            buffer_bytes=self.settings.buffer_bytes,
            source_change_detection_policy=self.source_change_detection_policy,
        )

    def register_tape(
        self,
        tape_id: str,
        mount: Path,
        cassette_number: str | None = None,
        known_volume: VolumeInfo | None = None,
    ) -> VolumeInfo:
        volume = known_volume or self.volume_provider(mount)
        if self.enforce_ltfs:
            require_ltfs(volume)
        self.catalog.register_tape(
            tape_id=tape_id,
            volume_serial=volume.serial,
            volume_label=volume.label,
            filesystem=volume.filesystem,
            mount_hint=str(volume.root),
            cassette_number=cassette_number,
        )
        return volume

    def validate_tape(self, tape_id: str, mount: Path) -> tuple[object, VolumeInfo]:
        tape = self.catalog.get_tape(tape_id)
        volume = self.volume_provider(mount)
        if self.enforce_ltfs:
            require_ltfs(volume)
        assert_registered_tape(tape, volume)
        return tape, volume

    def backup(
        self,
        library_id: str,
        tape_id: str,
        mount: Path,
        min_age_seconds: int | None = None,
        progress: ProgressCallback | None = None,
        dry_run: bool = False,
        only_relative_paths: set[str] | None = None,
        stop_requested: StopRequested | None = None,
        known_volume: VolumeInfo | None = None,
        known_plan: ScanPlan | None = None,
        defer_completion: bool = False,
        write_catalog_snapshot: bool = True,
        automatic_operation_id: str | None = None,
        automatic_job_id: str | None = None,
        automatic_cassette_sequence: int | None = None,
        frozen_manifest: bool = False,
    ) -> BackupResult | None:
        if stop_requested and stop_requested():
            raise OperationCancelled("Backup interrotto dall'operatore")
        self.catalog.get_library(library_id)
        if known_volume is None:
            _, volume = self.validate_tape(tape_id, mount)
        else:
            tape = self.catalog.get_tape(tape_id)
            volume = known_volume
            if self.enforce_ltfs:
                require_ltfs(volume)
            assert_registered_tape(tape, volume)
        if known_plan is not None and known_plan.library_id != library_id:
            raise ValidationError(
                f"Il piano {known_plan.library_id} non appartiene alla libreria {library_id}"
            )
        plan = known_plan or self.scan(library_id, min_age_seconds)
        if only_relative_paths is not None:
            plan = ScanPlan(
                library_id=plan.library_id,
                source_root=plan.source_root,
                items=tuple(
                    item for item in plan.items if item.relative_path in only_relative_paths
                ),
                skipped_unchanged=plan.skipped_unchanged,
                skipped_too_recent=plan.skipped_too_recent,
                source_files=plan.source_files,
                source_bytes=plan.source_bytes,
            )
        if not plan.items:
            self._emit(
                progress,
                "plan",
                files=0,
                bytes=0,
                pending_files=0,
                pending_bytes=0,
                estimated_tapes=0,
                skipped_unchanged=plan.skipped_unchanged,
                skipped_too_recent=plan.skipped_too_recent,
            )
            return None
        usable_bytes = self._application_free_bytes(volume)
        if usable_bytes <= 0:
            self._check_capacity(volume, 1)
        nominal_usable_bytes = self.settings.tape_capacity_bytes - self.settings.reserve_bytes
        capacity_model = capacity_model_for_media(self.settings.tape_capacity_bytes)
        if frozen_manifest:
            if known_plan is None:
                raise ValidationError("Il manifest congelato richiede un piano persistito")
            capacity_used_bytes = (
                capacity_model.batch_bytes(plan.items)
                if capacity_model
                else plan.total_bytes
            )
            if capacity_used_bytes > usable_bytes:
                raise CapacityError(
                    f"Il manifest richiede {human_bytes(capacity_used_bytes)} di spazio LTFS "
                    f"(file e metadati), ma sulla cassetta "
                    f"sono utilizzabili {human_bytes(usable_bytes)}."
                )
            selected = TapeBatch(
                slot=automatic_cassette_sequence or 1,
                items=plan.items,
                usable_bytes=usable_bytes,
                capacity_used_bytes=capacity_used_bytes,
            )
        else:
            # Validate that every file can fit a blank cartridge, then fill only
            # the currently mounted (possibly partially used) cartridge.
            plan_tape_batches(
                plan.items, nominal_usable_bytes, capacity_model=capacity_model
            )
            selected = select_tape_batch(
                plan.items, usable_bytes, capacity_model=capacity_model
            )
        batch_plan = ScanPlan(
            library_id=plan.library_id,
            source_root=plan.source_root,
            items=selected.items,
            skipped_unchanged=plan.skipped_unchanged,
            skipped_too_recent=plan.skipped_too_recent,
            source_files=plan.source_files,
            source_bytes=plan.source_bytes,
        )
        remaining_files = len(plan.items) - len(batch_plan.items)
        remaining_bytes = plan.total_bytes - batch_plan.total_bytes
        if frozen_manifest:
            remaining_batches = ()
        else:
            selected_paths = {item.relative_path for item in batch_plan.items}
            remaining_items = tuple(
                item
                for item in plan.items
                if item.relative_path not in selected_paths
            )
            remaining_batches = (
                plan_tape_batches(
                    remaining_items,
                    nominal_usable_bytes,
                    capacity_model=capacity_model,
                )
                if remaining_items
                else ()
            )
        self._emit(
            progress,
            "plan",
            files=len(batch_plan.items),
            bytes=batch_plan.total_bytes,
            pending_files=len(plan.items),
            pending_bytes=plan.total_bytes,
            estimated_tapes=1 + len(remaining_batches),
            skipped_unchanged=plan.skipped_unchanged,
            skipped_too_recent=plan.skipped_too_recent,
        )
        self._emit(
            progress,
            "tape.capacity",
            total_bytes=volume.total_bytes,
            free_bytes=volume.free_bytes,
            usable_bytes=usable_bytes,
            reserve_bytes=self.settings.reserve_bytes,
            application_limit_bytes=(
                self.settings.tape_capacity_bytes - self.settings.reserve_bytes
            ),
            ltfs_data_total_bytes=volume.ltfs_data_total_bytes,
            ltfs_data_free_bytes=volume.ltfs_data_free_bytes,
            planned_payload_bytes=batch_plan.total_bytes,
            planned_capacity_bytes=selected.capacity_used_bytes,
            ltfs_overhead_bytes=(selected.capacity_used_bytes or 0) - batch_plan.total_bytes,
        )
        self._check_capacity(volume, selected.capacity_used_bytes or batch_plan.total_bytes)
        if dry_run:
            return BackupResult(
                block_id="DRY-RUN",
                tape_id=tape_id,
                library_id=library_id,
                copied_files=0,
                copied_bytes=0,
                tape_relative_root="",
                remaining_files=remaining_files,
                remaining_bytes=remaining_bytes,
                estimated_remaining_tapes=len(remaining_batches),
            )

        block_id = uuid.uuid4().hex
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        relative_root = PurePosixPath(self.settings.tape_root_directory) / "libraries" / library_id / "blocks" / (
            timestamp + "_" + block_id[:8]
        )
        block_root = volume.root.joinpath(*relative_root.parts)
        files_root = block_root / "files"
        files_root.mkdir(parents=True, exist_ok=False)
        self.catalog.create_block(
            block_id=block_id,
            library_id=library_id,
            tape_id=tape_id,
            tape_relative_root=relative_root.as_posix(),
            planned_files=len(batch_plan.items),
            planned_bytes=batch_plan.total_bytes,
            automatic_operation_id=automatic_operation_id,
            automatic_job_id=automatic_job_id,
            automatic_cassette_sequence=automatic_cassette_sequence,
        )

        manifest_records: list[dict] = []
        copied_files = 0
        copied_bytes = 0
        remaining_usable_bytes = usable_bytes - (
            capacity_model.block_bytes if capacity_model else 0
        )

        try:
            for index, item in enumerate(batch_plan.items, start=1):
                if stop_requested and stop_requested():
                    raise OperationCancelled("Backup interrotto dall'operatore")
                item_capacity_bytes = (
                    capacity_model.item_bytes(item) if capacity_model else item.size
                )
                if remaining_usable_bytes < item_capacity_bytes:
                    raise CapacityError(
                        "Spazio LTFS insufficiente durante il lotto: "
                        f"disponibili {human_bytes(remaining_usable_bytes)}, "
                        f"allocazione richiesta {human_bytes(item_capacity_bytes)}."
                    )
                mapped_relative_path = (
                    item.tape_relative_path
                    if item.tape_relative_path is not None
                    else ltfs_tape_relative_path(item.relative_path)
                )
                destination = safe_join(files_root, mapped_relative_path)
                self._emit(
                    progress,
                    "file.start",
                    index=index,
                    total_files=len(batch_plan.items),
                    relative_path=item.relative_path,
                    size=item.size,
                )
                if item.source_identity is None:
                    before = item.source_path.stat()
                    if (
                        before.st_size != item.size
                        or before.st_mtime_ns != item.mtime_ns
                    ):
                        raise CopyError(
                            f"Il file è cambiato dopo la scansione: {item.source_path}"
                        )

                def copy_activity(activity: dict) -> None:
                    self._emit(
                        progress,
                        "file.activity",
                        index=index,
                        relative_path=item.relative_path,
                        **activity,
                    )
                    if activity.get("phase") == "timing.complete":
                        try:
                            self.catalog.event(
                                "file.copy.timing",
                                {
                                    "block_id": block_id,
                                    "library_id": library_id,
                                    "tape_id": tape_id,
                                    "relative_path": item.relative_path,
                                    "io_mode": str(activity.get("io_mode") or ""),
                                    "data_complete_seconds": float(
                                        activity.get("data_complete_seconds") or 0.0
                                    ),
                                    "copy_return_seconds": float(
                                        activity.get("copy_return_seconds") or 0.0
                                    ),
                                    "close_elapsed_seconds": float(
                                        activity.get("close_elapsed_seconds") or 0.0
                                    ),
                                    "hash_complete_seconds": float(
                                        activity.get("hash_complete_seconds") or 0.0
                                    ),
                                    "slow_close": float(
                                        activity.get("close_elapsed_seconds") or 0.0
                                    ) >= LTFS_SLOW_CLOSE_SECONDS,
                                },
                            )
                        except Exception:
                            # Timing is observational and cannot invalidate data.
                            pass

                try:
                    digest = copy_and_hash(
                        item.source_path,
                        destination,
                        self.settings.buffer_bytes,
                        progress=lambda value, i=index, rel=item.relative_path: self._emit(
                            progress,
                            "file.progress",
                            index=i,
                            relative_path=rel,
                            copied_bytes=value,
                            file_bytes=item.size,
                        ),
                        activity=copy_activity,
                        durable=False,
                        stop_requested=stop_requested,
                        expected_mtime_ns=item.mtime_ns,
                        source_root=(
                            batch_plan.source_root
                            if item.source_identity is not None
                            else None
                        ),
                        source_relative_path=(
                            item.relative_path
                            if item.source_identity is not None
                            else None
                        ),
                        expected_source_identity=item.source_identity,
                    )
                    if item.source_identity is None:
                        after = item.source_path.stat()
                        if (
                            after.st_size != item.size
                            or after.st_mtime_ns != item.mtime_ns
                        ):
                            raise CopyError(
                                f"Il file è cambiato durante la copia: {item.source_path}"
                            )
                except BaseException:
                    try:
                        destination.unlink(missing_ok=True)
                    except OSError:
                        pass
                    raise
                tape_relative_path = (
                    relative_root
                    / "files"
                    / PurePosixPath(mapped_relative_path)
                ).as_posix()
                self.catalog.record_file_version(
                    library_id=library_id,
                    block_id=block_id,
                    tape_id=tape_id,
                    relative_path=item.relative_path,
                    tape_relative_path=tape_relative_path,
                    size=item.size,
                    mtime_ns=item.mtime_ns,
                    sha256=digest,
                    metadata=item.metadata,
                )
                record = {
                    "relative_path": item.relative_path,
                    "tape_relative_path": tape_relative_path,
                    "size": item.size,
                    "mtime_ns": item.mtime_ns,
                    "sha256": digest,
                    "metadata": item.metadata,
                }
                manifest_records.append(record)
                copied_files += 1
                copied_bytes += item.size
                remaining_usable_bytes = max(
                    0, remaining_usable_bytes - item_capacity_bytes
                )
                self._emit(
                    progress,
                    "file.complete",
                    index=index,
                    total_files=len(batch_plan.items),
                    relative_path=item.relative_path,
                    copied_bytes=copied_bytes,
                    total_bytes=batch_plan.total_bytes,
                    sha256=digest,
                )

            if stop_requested and stop_requested():
                raise OperationCancelled("Backup interrotto dall'operatore")
            self._write_manifest(block_root, block_id, library_id, tape_id, batch_plan, manifest_records)
            if not defer_completion:
                self.catalog.complete_block(block_id)
                try:
                    self.catalog.backup_to(
                        self.paths.catalog_backup_file(
                            self.settings.catalog_backup_directory
                        )
                    )
                except Exception as backup_error:
                    self.catalog.event(
                        "catalog.backup.warning",
                        {"block_id": block_id, "error": str(backup_error)},
                    )
                    self._emit(
                        progress,
                        "catalog.backup.warning",
                        block_id=block_id,
                        error=str(backup_error),
                    )
            if write_catalog_snapshot:
                try:
                    self.write_catalog_snapshot(volume.root, block_id)
                except Exception as snapshot_error:
                    self.catalog.event(
                        "catalog.snapshot.warning",
                        {"block_id": block_id, "error": str(snapshot_error)},
                    )
                    self._emit(
                        progress,
                        "catalog.snapshot.warning",
                        block_id=block_id,
                        error=str(snapshot_error),
                    )
            self.catalog.touch_tape(tape_id, str(volume.root))
            self._emit(
                progress,
                "block.staged" if defer_completion else "block.complete",
                block_id=block_id,
                files=copied_files,
                bytes=copied_bytes,
            )
            return BackupResult(
                block_id=block_id,
                tape_id=tape_id,
                library_id=library_id,
                copied_files=copied_files,
                copied_bytes=copied_bytes,
                tape_relative_root=relative_root.as_posix(),
                remaining_files=remaining_files,
                remaining_bytes=remaining_bytes,
                estimated_remaining_tapes=len(remaining_batches),
            )
        except BaseException as exc:
            self.catalog.fail_block(block_id, str(exc))
            self._emit(progress, "block.failed", block_id=block_id, error=str(exc))
            raise

    def restore(
        self,
        library_id: str,
        tape_id: str,
        mount: Path,
        destination_root: Path,
        overwrite: bool = False,
        progress: ProgressCallback | None = None,
    ) -> tuple[int, int]:
        self.catalog.get_library(library_id, include_retired=True)
        _, volume = self.validate_tape(tape_id, mount)
        rows = self.catalog.restore_files_for_tape(library_id, tape_id)
        if not rows:
            raise ValidationError(f"Nessun file corrente della libreria {library_id} sul nastro {tape_id}")
        destination_root.mkdir(parents=True, exist_ok=True)
        restored_files = 0
        restored_bytes = 0
        for index, row in enumerate(rows, start=1):
            source = safe_join(volume.root, row["tape_relative_path"])
            destination = safe_join(destination_root, row["relative_path"])
            if not source.is_file():
                raise CopyError(f"File mancante sul nastro: {row['tape_relative_path']}")
            if destination.exists() and not overwrite:
                if destination.stat().st_size == row["size"] and sha256_file(
                    destination, self.settings.buffer_bytes
                ) == row["sha256"]:
                    self._emit(progress, "restore.skip", relative_path=row["relative_path"])
                    continue
                raise CopyError(f"Destinazione già esistente e diversa: {destination}")
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.with_name(destination.name + ".partial-" + uuid.uuid4().hex[:8])
            try:
                digest = copy_and_hash(source, temporary, self.settings.buffer_bytes)
                if digest != row["sha256"]:
                    raise CopyError(
                        f"SHA-256 errato ripristinando {row['relative_path']}: "
                        f"atteso {row['sha256']}, letto {digest}"
                    )
                if temporary.stat().st_size != row["size"]:
                    raise CopyError(f"Dimensione errata ripristinando {row['relative_path']}")
                os.replace(native_path(temporary), native_path(destination))
            finally:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass
            os.utime(destination, ns=(row["mtime_ns"], row["mtime_ns"]))
            restored_files += 1
            restored_bytes += row["size"]
            self._emit(
                progress,
                "restore.complete",
                index=index,
                total_files=len(rows),
                relative_path=row["relative_path"],
                restored_bytes=restored_bytes,
            )
        self.catalog.event(
            "restore.complete",
            {
                "library_id": library_id,
                "tape_id": tape_id,
                "destination": str(destination_root),
                "files": restored_files,
                "bytes": restored_bytes,
            },
        )
        return restored_files, restored_bytes

    def _application_free_bytes(self, volume: VolumeInfo) -> int:
        if (
            volume.ltfs_data_total_bytes is not None
            and volume.ltfs_data_free_bytes is not None
        ):
            physical_used = max(
                0, volume.ltfs_data_total_bytes - volume.ltfs_data_free_bytes
            )
        else:
            physical_used = max(0, volume.total_bytes - volume.free_bytes)
        application_remaining = (
            self.settings.tape_capacity_bytes
            - self.settings.reserve_bytes
            - physical_used
        )
        physical_remaining = volume.free_bytes - self.settings.reserve_bytes
        candidates = [application_remaining, physical_remaining]
        if volume.ltfs_data_free_bytes is not None:
            candidates.append(volume.ltfs_data_free_bytes - self.settings.reserve_bytes)
        return max(0, min(candidates))

    def _check_capacity(self, volume: VolumeInfo, required_bytes: int) -> None:
        usable = self._application_free_bytes(volume)
        if usable < required_bytes:
            raise CapacityError(
                "Spazio LTFS insufficiente: "
                f"liberi {human_bytes(volume.free_bytes)}, margine extra {human_bytes(self.settings.reserve_bytes)}, "
                f"scrittura richiesta {human_bytes(required_bytes)}. Nessun nuovo file è stato avviato."
            )

    def _write_manifest(
        self,
        block_root: Path,
        block_id: str,
        library_id: str,
        tape_id: str,
        plan: ScanPlan,
        records: list[dict],
    ) -> None:
        self.paths.temp_dir.mkdir(parents=True, exist_ok=True)
        handle, temporary_name = tempfile.mkstemp(prefix=block_id + "-", suffix=".jsonl", dir=self.paths.temp_dir)
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                for record in records:
                    stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            manifest_destination = block_root / "manifest.jsonl"
            manifest_partial = block_root / ("manifest.jsonl.partial-" + uuid.uuid4().hex[:8])
            try:
                copy_and_hash(Path(temporary_name), manifest_partial, self.settings.buffer_bytes)
                os.replace(native_path(manifest_partial), native_path(manifest_destination))
            finally:
                try:
                    manifest_partial.unlink(missing_ok=True)
                except OSError:
                    pass
        finally:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass

        metadata = {
            "format": "lto-library-backup-block-v1",
            "block_id": block_id,
            "library_id": library_id,
            "tape_id": tape_id,
            "completed_at": utc_now(),
            "file_count": len(records),
            "total_bytes": plan.total_bytes,
            "copy_mode": "direct-files-no-tar",
            "sha256_recorded_during_source_stream": True,
        }
        write_json_atomic(block_root / "block.json", metadata)

    def write_catalog_snapshot(self, tape_root: Path, block_id: str) -> None:
        snapshot_directory = tape_root / self.settings.tape_root_directory / "catalog-snapshots"
        snapshot_directory.mkdir(parents=True, exist_ok=True)
        local_snapshot = self.paths.temp_dir / ("catalog-" + block_id + ".json")
        write_json_atomic(local_snapshot, self.catalog.export(include_events=False))
        destination = snapshot_directory / (
            datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "_" + block_id[:8] + ".json"
        )
        temporary = destination.with_name(destination.name + ".partial")
        try:
            copy_and_hash(local_snapshot, temporary, self.settings.buffer_bytes)
            os.replace(native_path(temporary), native_path(destination))
        finally:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
            try:
                local_snapshot.unlink()
            except OSError:
                pass

    @staticmethod
    def _emit(callback: ProgressCallback | None, event: str, **payload: object) -> None:
        if callback:
            callback({"event": event, "at": utc_now(), **payload})
