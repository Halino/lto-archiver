from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from .catalog import Catalog
from .errors import CapacityError, CopyError, OperationCancelled, ValidationError
from .models import VolumeInfo
from .media import get_lto_media_profile
from .settings import AppPaths, Settings
from .volume import assert_registered_tape, inspect_volume, require_ltfs


ProgressCallback = Callable[[dict], None]
StopRequested = Callable[[], bool]
BackupCallback = Callable[
    [list[str], str, Path | VolumeInfo, ProgressCallback | None, StopRequested], dict
]


@dataclass(frozen=True)
class CassetteLabel:
    physical_label: str
    tape_serial: str


def normalize_cassette_labels(
    values: list[str] | tuple[str, ...],
    *,
    media_key: str = "LTO-6",
) -> list[CassetteLabel]:
    profile = get_lto_media_profile(media_key)
    suffix = profile.barcode_suffix
    result: list[CassetteLabel] = []
    serials: set[str] = set()
    labels: set[str] = set()
    for raw in values:
        label = raw.strip().upper()
        if not label:
            continue
        if re.fullmatch(r"[A-Z0-9]{6}", label):
            serial = label
        elif re.fullmatch(rf"[A-Z0-9]{{6}}{re.escape(suffix)}", label):
            serial = label[:6]
        elif re.fullmatch(r"[A-Z0-9]{6}(?:L[0-9A-Z]|P[0-9A-Z])", label):
            raise ValidationError(
                f"Etichetta {label}: il suffisso deve essere {suffix} per una cassetta {profile.key}"
            )
        else:
            raise ValidationError(
                f"Etichetta {label or raw!r} non valida: usare 6 caratteri A-Z/0-9 "
                f"oppure il barcode a 8 caratteri terminante in {suffix}"
            )
        if label in labels or serial in serials:
            raise ValidationError(f"Etichetta o seriale LTFS duplicata: {label}")
        labels.add(label)
        serials.add(serial)
        result.append(CassetteLabel(label, serial))
    if not result:
        raise ValidationError("Indicare almeno un'etichetta cassetta")
    return result


class TapeController(Protocol):
    def wait_for_media(self, stop_requested: StopRequested) -> bool: ...
    def format(self, cassette: CassetteLabel) -> None: ...
    def mount(self, stop_requested: StopRequested) -> Path: ...
    def unmount_and_eject(self) -> None: ...


class TapeWriteProgress:
    """Enrich backup events with live, cassette-wide write telemetry."""

    def __init__(
        self,
        *,
        job_id: str,
        sequence: int,
        physical_label: str,
        cassette_planned_bytes: int,
        job_copied_bytes: int,
        job_planned_bytes: int,
        callback: ProgressCallback | None,
        operation: str = "format",
        clock: Callable[[], float] = time.monotonic,
    ):
        self.job_id = job_id
        self.sequence = sequence
        self.physical_label = physical_label
        self.operation = operation
        self.cassette_planned_bytes = max(0, cassette_planned_bytes)
        self.job_copied_before = max(0, job_copied_bytes)
        self.job_planned_bytes = max(0, job_planned_bytes)
        self.callback = callback
        self.clock = clock
        self.cassette_copied_bytes = 0
        self.cassette_copied_files = 0
        self.current_file_bytes = 0
        self.started_at: float | None = None
        self.last_at: float | None = None
        self.last_total = 0
        self.write_bps = 0.0
        self.average_write_bps = 0.0
        self.tape_total_bytes = 0
        self.tape_initial_free_bytes = 0
        self.tape_usable_bytes = 0
        self.tape_reserve_bytes = 0
        self.tape_application_limit_bytes = 0
        self.tape_ltfs_overhead_bytes = 0

    def __call__(self, event: dict) -> None:
        enriched = dict(event)
        kind = str(event.get("event") or "")
        now: float | None = None
        if kind == "tape.capacity":
            self.tape_total_bytes = max(0, int(event.get("total_bytes") or 0))
            self.tape_initial_free_bytes = max(
                0,
                int(
                    event.get("ltfs_data_free_bytes")
                    if event.get("ltfs_data_free_bytes") is not None
                    else event.get("free_bytes") or 0
                ),
            )
            self.tape_usable_bytes = max(0, int(event.get("usable_bytes") or 0))
            self.tape_reserve_bytes = max(0, int(event.get("reserve_bytes") or 0))
            self.tape_application_limit_bytes = max(
                0, int(event.get("application_limit_bytes") or 0)
            )
            self.tape_ltfs_overhead_bytes = max(
                0, int(event.get("ltfs_overhead_bytes") or 0)
            )
        elif kind == "file.start":
            self.current_file_bytes = 0
            if self.started_at is None:
                now = self.clock()
                self.started_at = now
                self.last_at = now
        elif kind == "file.progress":
            current = max(0, int(event.get("copied_bytes") or 0))
            delta = max(0, current - self.current_file_bytes)
            self.current_file_bytes = current
            self.cassette_copied_bytes += delta
            now = self.clock()
            if self.started_at is None:
                self.started_at = now
                self.last_at = now
            interval = now - (self.last_at if self.last_at is not None else now)
            if interval > 0:
                self.write_bps = (self.cassette_copied_bytes - self.last_total) / interval
            elapsed = now - self.started_at
            if elapsed > 0:
                self.average_write_bps = self.cassette_copied_bytes / elapsed
            self.last_at = now
            self.last_total = self.cassette_copied_bytes
        elif kind == "file.complete":
            self.cassette_copied_files += 1

        # The effective cassette rate deliberately includes LTFS close/flush
        # time and gaps between files.  Refresh it on every event emitted while
        # the cassette is active, not only when another byte-progress callback
        # happens to arrive.
        if self.started_at is not None:
            if now is None:
                now = self.clock()
            cassette_elapsed = max(0.0, now - self.started_at)
            self.average_write_bps = (
                self.cassette_copied_bytes / cassette_elapsed
                if cassette_elapsed > 0 and self.cassette_copied_bytes > 0
                else 0.0
            )
        else:
            cassette_elapsed = 0.0

        job_copied = self.job_copied_before + self.cassette_copied_bytes
        job_percent = (
            min(100.0, job_copied * 100.0 / self.job_planned_bytes)
            if self.job_planned_bytes else 0.0
        )
        tape_consumed = self.tape_ltfs_overhead_bytes + self.cassette_copied_bytes
        tape_remaining = max(0, self.tape_usable_bytes - tape_consumed)
        tape_percent = (
            min(100.0, tape_consumed * 100.0 / self.tape_usable_bytes)
            if self.tape_usable_bytes else 0.0
        )
        cassette_eta = (
            max(0, self.cassette_planned_bytes - self.cassette_copied_bytes)
            / self.average_write_bps
            if self.average_write_bps > 0 else None
        )
        job_eta = (
            max(0, self.job_planned_bytes - job_copied) / self.average_write_bps
            if self.average_write_bps > 0 else None
        )
        enriched.update(
            job_id=self.job_id,
            sequence=self.sequence,
            physical_label=self.physical_label,
            operation=self.operation,
            cassette_planned_bytes=self.cassette_planned_bytes,
            cassette_copied_bytes=self.cassette_copied_bytes,
            cassette_copied_files=self.cassette_copied_files,
            job_planned_bytes=self.job_planned_bytes,
            job_copied_bytes=job_copied,
            job_progress_percent=job_percent,
            write_bps=self.write_bps,
            average_write_bps=self.average_write_bps,
            cassette_elapsed_seconds=cassette_elapsed,
            cassette_eta_seconds=cassette_eta,
            job_eta_seconds=job_eta,
            tape_total_bytes=self.tape_total_bytes,
            tape_initial_free_bytes=self.tape_initial_free_bytes,
            tape_usable_bytes=self.tape_usable_bytes,
            tape_remaining_bytes=tape_remaining,
            tape_reserve_bytes=self.tape_reserve_bytes,
            tape_application_limit_bytes=self.tape_application_limit_bytes,
            tape_ltfs_overhead_bytes=self.tape_ltfs_overhead_bytes,
            tape_used_percent=tape_percent,
        )
        if self.callback:
            self.callback(enriched)


class AutomaticJobRunner:
    def __init__(
        self,
        paths: AppPaths,
        settings: Settings,
        *,
        controller: TapeController,
        backup: BackupCallback,
    ):
        self.paths = paths
        self.settings = settings
        self.controller = controller
        self.backup = backup

    def run(
        self,
        job_id: str,
        *,
        progress: ProgressCallback | None = None,
        stop_requested: StopRequested,
        stop_after_cassette: bool = False,
    ) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            job = dict(catalog.get_automatic_job(job_id))
            library_ids = [
                row["library_id"] for row in catalog.list_automatic_job_libraries(job_id)
            ]
        controller = self.controller
        while True:
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.initialize()
                step_row = catalog.next_automatic_cassette(job_id)
                if step_row is None:
                    catalog.update_automatic_job(job_id, "completed")
                    self._emit(progress, "automatic.completed", job_id=job_id)
                    return
                step = dict(step_row)
                cassette_rows = [dict(row) for row in catalog.list_automatic_cassettes(job_id)]
                job_planned_bytes = sum(int(row["planned_bytes"]) for row in cassette_rows)
                job_copied_bytes = sum(
                    int(row["copied_bytes"])
                    for row in cassette_rows
                    if row["status"] == "completed"
                )
                if step["status"] not in {"pending", "waiting_media"}:
                    message = (
                        f"La cassetta {step['physical_label']} e rimasta nello stato incerto "
                        f"{step['status']}; non viene riformattata automaticamente"
                    )
                    catalog.update_automatic_job(job_id, "failed", current_sequence=step["sequence"], error=message)
                    raise CopyError(message)
                catalog.update_automatic_job(job_id, "waiting_media", current_sequence=step["sequence"])
                catalog.update_automatic_cassette(job_id, step["sequence"], "waiting_media")
            self._emit(
                progress,
                "automatic.waiting_media",
                job_id=job_id,
                sequence=step["sequence"],
                total=job["total_cassettes"],
                physical_label=step["physical_label"],
                operation=step.get("operation", "format"),
            )
            if not controller.wait_for_media(stop_requested):
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_job(job_id, "paused", current_sequence=step["sequence"])
                self._emit(progress, "automatic.paused", job_id=job_id)
                return
            if stop_requested():
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_job(job_id, "paused", current_sequence=step["sequence"])
                return

            cassette = CassetteLabel(step["physical_label"], step["tape_serial"])
            active_tape_progress: TapeWriteProgress | None = None
            set_unmount_progress = getattr(controller, "set_unmount_progress", None)
            if callable(set_unmount_progress):
                def forward_unmount(event: dict) -> None:
                    payload = dict(event)
                    name = str(payload.pop("event", "unmount.progress"))
                    if payload.get("status") == "complete":
                        try:
                            with Catalog(self.paths.catalog_file) as timing_catalog:
                                timing_catalog.initialize()
                                timing_catalog.event(
                                    "automatic.unmount.timing",
                                    {
                                        "job_id": job_id,
                                        "sequence": int(step["sequence"]),
                                        "physical_label": cassette.physical_label,
                                        "stage": str(payload.get("stage") or ""),
                                        "elapsed_seconds": max(
                                            0.0,
                                            float(payload.get("elapsed_seconds") or 0.0),
                                        ),
                                    },
                                )
                        except Exception:
                            # Timing history is diagnostic and must not block unmount.
                            pass
                    if active_tape_progress is not None:
                        active_tape_progress({"event": name, **payload})
                    else:
                        self._emit(
                            progress,
                            name,
                            job_id=job_id,
                            sequence=int(step["sequence"]),
                            physical_label=cassette.physical_label,
                            **payload,
                        )

                set_unmount_progress(forward_unmount)
            result: dict | None = None
            try:
                operation = str(step.get("operation") or "format")
                if operation == "format":
                    self._state(job_id, step["sequence"], "formatting", progress, cassette)
                    controller.format(cassette)
                    if bool(step.get("reuse_registered", 0)):
                        with Catalog(self.paths.catalog_file) as catalog:
                            catalog.initialize()
                            catalog.commit_registered_tape_reformat(
                                job_id, int(step["sequence"])
                            )
                self._state(job_id, step["sequence"], "mounting", progress, cassette)
                mounted_path = controller.mount(stop_requested)
                mounted_volume = getattr(controller, "mounted_volume", None)
                if operation == "append":
                    if mounted_volume is None:
                        mounted_volume = inspect_volume(mounted_path)
                    require_ltfs(mounted_volume)
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        tape_id = str(step.get("tape_id") or cassette.physical_label)
                        tape = catalog.get_tape(tape_id)
                        if str(tape["cassette_number"]).casefold() != cassette.physical_label.casefold():
                            raise ValidationError(
                                f"Cassetta errata: attesa {cassette.physical_label}, "
                                f"catalogata {tape['cassette_number']}"
                            )
                        assert_registered_tape(tape, mounted_volume)
                        if str(tape["volume_label"]).casefold() != mounted_volume.label.casefold():
                            raise ValidationError(
                                f"Etichetta LTFS errata: attesa {tape['volume_label']}, "
                                f"montata {mounted_volume.label}"
                            )
                self._state(job_id, step["sequence"], "writing", progress, cassette)
                tape_progress = TapeWriteProgress(
                    job_id=job_id,
                    sequence=int(step["sequence"]),
                    physical_label=cassette.physical_label,
                    operation=operation,
                    cassette_planned_bytes=int(step["planned_bytes"]),
                    job_copied_bytes=job_copied_bytes,
                    job_planned_bytes=job_planned_bytes,
                    callback=progress,
                )
                active_tape_progress = tape_progress
                result = self.backup(
                    library_ids,
                    cassette.physical_label,
                    mounted_volume or mounted_path,
                    tape_progress,
                    stop_requested,
                )
                self._state(job_id, step["sequence"], "unmounting", progress, cassette)
                controller.unmount_and_eject()
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    if result.get("commit_required"):
                        catalog.complete_blocks(list(result.get("block_ids", [])))
                        try:
                            catalog.backup_to(
                                self.paths.catalog_backup_file(
                                    self.settings.catalog_backup_directory
                                )
                            )
                        except Exception as backup_error:
                            catalog.event(
                                "catalog.backup.warning",
                                {
                                    "block_ids": list(result.get("block_ids", [])),
                                    "error": str(backup_error),
                                },
                            )
                            self._emit(
                                progress,
                                "catalog.backup.warning",
                                job_id=job_id,
                                error=str(backup_error),
                            )
                    catalog.update_automatic_cassette(
                        job_id,
                        step["sequence"],
                        "completed",
                        tape_id=cassette.physical_label,
                        block_id=result.get("block_id") or ",".join(result.get("block_ids", [])),
                        copied_files=int(result.get("copied_files", 0)),
                        copied_bytes=int(result.get("copied_bytes", 0)),
                    )
                self._emit(
                    progress,
                    "automatic.ejected",
                    job_id=job_id,
                    sequence=step["sequence"],
                    physical_label=cassette.physical_label,
                    operation=operation,
                )
                if bool(getattr(controller, "pause_acknowledged", False)):
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_job(
                            job_id,
                            "paused",
                            current_sequence=step["sequence"],
                        )
                    self._emit(
                        progress,
                        "automatic.paused",
                        job_id=job_id,
                        sequence=step["sequence"],
                        safe_checkpoint="unloaded",
                    )
                    return
                if stop_requested():
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_job(
                            job_id, "paused", current_sequence=step["sequence"]
                        )
                    self._emit(progress, "automatic.paused", job_id=job_id)
                    return
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    next_sequence = catalog.advance_automatic_job_after_eject(
                        job_id, int(step["sequence"])
                    )
                if stop_after_cassette:
                    self._emit(
                        progress,
                        "automatic.cassette_completed",
                        job_id=job_id,
                        sequence=step["sequence"],
                        physical_label=cassette.physical_label,
                        operation=operation,
                        next_sequence=next_sequence,
                    )
                    return
                if next_sequence is None:
                    self._emit(progress, "automatic.completed", job_id=job_id)
                    return
                continue
            except CapacityError as exc:
                if operation != "append":
                    try:
                        controller.unmount_and_eject()
                    except Exception as cleanup_exc:
                        exc.add_note(f"Smontaggio/espulsione non riusciti: {cleanup_exc}")
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_cassette(
                            job_id, step["sequence"], "failed", error=str(exc)
                        )
                        catalog.update_automatic_job(
                            job_id, "failed", current_sequence=step["sequence"], error=str(exc)
                        )
                    raise
                try:
                    self._state(job_id, step["sequence"], "unmounting", progress, cassette)
                    controller.unmount_and_eject()
                except Exception as cleanup_exc:
                    detail = f"{exc} | smontaggio/espulsione non riusciti: {cleanup_exc}"
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_cassette(
                            job_id, step["sequence"], "failed", error=detail
                        )
                        catalog.update_automatic_job(
                            job_id, "failed", current_sequence=step["sequence"], error=detail
                        )
                    raise CopyError(detail) from cleanup_exc
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_cassette(
                        job_id,
                        step["sequence"],
                        "completed",
                        copied_files=0,
                        copied_bytes=0,
                    )
                    next_step = catalog.next_automatic_cassette(job_id)
                    needs_more_media = next_step is None
                    if needs_more_media:
                        missing_message = (
                            "Lo spazio reale della cassetta APPEND e esaurito e restano file "
                            "da copiare. Aggiungere cassette allo stesso job."
                        )
                        catalog.update_automatic_job(
                            job_id,
                            "failed",
                            current_sequence=step["sequence"],
                            error=missing_message,
                        )
                    else:
                        next_sequence = catalog.advance_automatic_job_after_eject(
                            job_id, int(step["sequence"])
                        )
                self._emit(
                    progress,
                    "automatic.append_full",
                    job_id=job_id,
                    sequence=step["sequence"],
                    physical_label=cassette.physical_label,
                    detail=str(exc),
                    operation=operation,
                )
                if needs_more_media:
                    self._emit(
                        progress,
                        "automatic.failed",
                        job_id=job_id,
                        error=missing_message,
                    )
                    return
                if stop_after_cassette:
                    self._emit(
                        progress,
                        "automatic.cassette_completed",
                        job_id=job_id,
                        sequence=step["sequence"],
                        physical_label=cassette.physical_label,
                        operation=operation,
                        next_sequence=next_sequence,
                    )
                    return
                continue
            except OperationCancelled as exc:
                try:
                    controller.unmount_and_eject()
                except Exception as cleanup_exc:
                    detail = f"{exc} | smontaggio/espulsione non riusciti: {cleanup_exc}"
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_cassette(
                            job_id, step["sequence"], "failed", error=detail
                        )
                        catalog.update_automatic_job(
                            job_id, "failed", current_sequence=step["sequence"], error=detail
                        )
                    self._emit(progress, "automatic.failed", job_id=job_id, error=detail)
                    raise CopyError(detail) from cleanup_exc
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    if result and result.get("commit_required"):
                        catalog.fail_blocks(list(result.get("block_ids", [])), str(exc))
                    catalog.reset_automatic_cassette(job_id, step["sequence"], str(exc))
                self._emit(
                    progress,
                    "automatic.paused",
                    job_id=job_id,
                    sequence=step["sequence"],
                    physical_label=cassette.physical_label,
                    restart_cassette=True,
                    operation=operation,
                )
                return
            except BaseException as exc:
                cleanup_error = ""
                try:
                    controller.unmount_and_eject()
                except Exception as cleanup_exc:
                    cleanup_error = f" | smontaggio/espulsione non riusciti: {cleanup_exc}"
                detail = f"{exc}{cleanup_error}"
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    if result and result.get("commit_required"):
                        catalog.fail_blocks(list(result.get("block_ids", [])), detail)
                    catalog.update_automatic_cassette(
                        job_id, step["sequence"], "failed", error=detail
                    )
                    catalog.update_automatic_job(
                        job_id, "failed", current_sequence=step["sequence"], error=detail
                    )
                self._emit(progress, "automatic.failed", job_id=job_id, error=detail)
                raise
    def _state(
        self,
        job_id: str,
        sequence: int,
        status: str,
        progress: ProgressCallback | None,
        cassette: CassetteLabel,
    ) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.update_automatic_job(job_id, status, current_sequence=sequence)
            catalog.update_automatic_cassette(job_id, sequence, status)
            operation = next(
                row["operation"]
                for row in catalog.list_automatic_cassettes(job_id)
                if int(row["sequence"]) == int(sequence)
            )
        self._emit(
            progress,
            f"automatic.{status}",
            job_id=job_id,
            sequence=sequence,
            physical_label=cassette.physical_label,
            operation=operation,
        )

    @staticmethod
    def _emit(callback: ProgressCallback | None, event: str, **payload: object) -> None:
        if callback:
            callback({"event": event, **payload})
