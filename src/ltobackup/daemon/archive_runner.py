"""One-cassette hardware-free orchestration for an imported frozen job."""

from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Callable
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol

from ..catalog import Catalog
from ..errors import ValidationError
from ..operational_log import (
    NullOperationalEventSink,
    OperationalEventSink,
    OperationalPhaseTracker,
    closed_operational_correlation,
)
from ..tape.command_supervisor import CommandFailed
from ..tape.copier import CopyRequest, CopyResult, copy_frozen_file
from ..tape.linux_ltfs import LinuxLtfsBackend
from ..tape.manifests import (
    BlockManifest,
    FileManifestRecord,
    ManifestWriter,
)
from ..tape.models import ExpectedMedia, MountedTape
from ..util import ltfs_tape_relative_path, utc_now
from .backups import BackupManager
from .frozen_job import FrozenCassette, FrozenItem, FrozenJobPlan
from .models import RecoveryCommandFence
from .operations import OperationContext


class FrozenSourceValidationFailed(RuntimeError):
    code = "frozen_source_validation_failed"


class MediaWaitStopped(RuntimeError):
    code = "media_wait_stopped"


@dataclass(frozen=True)
class ArchiveOutcome:
    state: Literal["succeeded", "recovery_required"]
    phase: str
    next_state: Literal["waiting_media", "completed", "recovery_required"]
    sequence: int
    error_class: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class AutomaticCassetteRetryCheckpoint:
    """The authorized, non-scanning cassette checkpoint selected for recovery."""

    job_id: str
    cassette_sequence: int
    physical_label: str
    operation: Literal["format", "append"]
    format_allowed: bool
    invalidated_blocks: int
    invalidated_files: int
    invalidated_tapes: int


def prepare_automatic_cassette_retry(
    catalog: Catalog,
    fence: RecoveryCommandFence,
) -> AutomaticCassetteRetryCheckpoint:
    """Invalidate only an exact native cassette attempt without rescanning.

    The catalog transaction derives identity and format authority from the
    current recovery lineage, a current-generation probe command, the media
    binding, and the original format confirmation.  This seam deliberately has
    no source library, planner, formatter, mount, writer, or unload dependency.
    """
    invalidated = catalog.reset_automatic_cassette_for_recovery(
        fence, "automatic_recovery"
    )
    with catalog.transaction() as db:
        operation_row = db.execute(
            "SELECT job_id,cassette_sequence FROM daemon_operations WHERE id=?",
            (fence.operation_id,),
        ).fetchone()
        if operation_row is None:
            raise ValidationError("native recovery checkpoint is unavailable")
        cassette = db.execute(
            "SELECT physical_label FROM automatic_cassettes "
            "WHERE job_id=? AND sequence=?",
            (operation_row["job_id"], operation_row["cassette_sequence"]),
        ).fetchone()
        if cassette is None:
            raise ValidationError("native recovery checkpoint is unavailable")
    return AutomaticCassetteRetryCheckpoint(
        str(operation_row["job_id"]),
        int(operation_row["cassette_sequence"]),
        str(cassette["physical_label"]),
        str(invalidated["operation"]),
        bool(invalidated["format_allowed"]),
        int(invalidated["blocks"]),
        int(invalidated["files"]),
        int(invalidated["tapes"]),
    )


class _CatalogFactory(Protocol):
    def __call__(self) -> Catalog: ...


class _ManifestWriterFactory(Protocol):
    def __call__(self, **kwargs) -> ManifestWriter: ...


class TelemetrySink(Protocol):
    """Best-effort daemon telemetry boundary; it never authorizes tape work."""

    def record_file(self, byte_count: int) -> object: ...

    def begin_window(self) -> object: ...

    def record_progress(self, byte_count: int) -> object: ...

    def complete_file(self) -> object: ...

    def add_duration(self, phase: str, seconds: float) -> object: ...

    def start_phase(self, phase: str) -> object: ...

    def finish_phase(self, phase: str) -> object: ...


class _NoopTelemetrySink:
    def record_file(self, _byte_count: int) -> None:
        return None

    def begin_window(self) -> None:
        return None

    def record_progress(self, _byte_count: int) -> None:
        return None

    def complete_file(self) -> None:
        return None

    def add_duration(self, _phase: str, _seconds: float) -> None:
        return None

    def start_phase(self, _phase: str) -> None:
        return None

    def finish_phase(self, _phase: str) -> None:
        return None


@dataclass(frozen=True)
class _BlockPlan:
    block_id: str
    library_id: str
    tape_relative_root: str
    items: tuple[FrozenItem, ...]

    @property
    def planned_files(self) -> int:
        return len(self.items)

    @property
    def planned_bytes(self) -> int:
        return sum(item.size for item in self.items)

    def catalog_tuple(self) -> tuple[str, str, str, int, int]:
        return (
            self.block_id,
            self.library_id,
            self.tape_relative_root,
            self.planned_files,
            self.planned_bytes,
        )


class _PersistedUnmountObserver:
    def __init__(
        self,
        catalog: Catalog,
        context: OperationContext,
        clock: Callable[[], str],
        phases: OperationalPhaseTracker,
    ) -> None:
        self._catalog = catalog
        self._context = context
        self._clock = clock
        self._phases = phases
        self.finalization_started_at: str | None = None
        self.unmounting_started_at: str | None = None

    def finalization_started(self) -> None:
        self.finalization_started_at = self._clock()
        self._catalog.record_imported_unmount_boundary(
            self._context.fence,
            phase="finalizing_index",
            started_at=self.finalization_started_at,
        )
        self._catalog.transition_imported_cassette_phase(
            self._context.fence, "finalizing_index"
        )
        self._phases.start("finalizing_index")

    def mount_release_started(self) -> None:
        self.unmounting_started_at = self._clock()
        self._catalog.record_imported_unmount_boundary(
            self._context.fence,
            phase="unmounting",
            started_at=self.unmounting_started_at,
        )
        self._catalog.transition_imported_cassette_phase(
            self._context.fence, "unmounting"
        )
        self._phases.start("unmount")

    def require_started(self) -> tuple[str, str]:
        if self.finalization_started_at is None or self.unmounting_started_at is None:
            raise RuntimeError("backend did not report the unmount phase boundaries")
        return self.finalization_started_at, self.unmounting_started_at


class ArchiveRunner:
    """Resume exactly the immutable next cassette and no other source set."""

    def __init__(
        self,
        *,
        catalog_factory: _CatalogFactory,
        backups: BackupManager,
        backend: LinuxLtfsBackend,
        host_staging_root: Path,
        buffer_bytes: int,
        plan_loader: Callable[[Catalog, str], FrozenJobPlan] = FrozenJobPlan.load,
        copy_file: Callable[[CopyRequest], CopyResult] = copy_frozen_file,
        manifest_writer_factory: _ManifestWriterFactory = ManifestWriter,
        clock: Callable[[], str] = utc_now,
        telemetry_sink: TelemetrySink | None = None,
        managed_source_admission: Callable[[str, str, int], tuple[str, ...]] = (
            lambda _job_id, _operation_id, _generation: ()
        ),
        managed_source_release: Callable[[tuple[str, ...], int], None] = (
            lambda _leases, _generation: None
        ),
        event_sink: OperationalEventSink | None = None,
    ) -> None:
        if isinstance(buffer_bytes, bool) or not isinstance(buffer_bytes, int):
            raise ValidationError("archive copy buffer must be an integer")
        if buffer_bytes <= 0:
            raise ValidationError("archive copy buffer must be positive")
        self.catalog_factory = catalog_factory
        self.backups = backups
        self.backend = backend
        self.host_staging_root = Path(host_staging_root)
        self.buffer_bytes = buffer_bytes
        self.plan_loader = plan_loader
        self.copy_file = copy_file
        self.manifest_writer_factory = manifest_writer_factory
        self.clock = clock
        self.telemetry_sink = telemetry_sink or _NoopTelemetrySink()
        self.managed_source_admission = managed_source_admission
        self.managed_source_release = managed_source_release
        self.event_sink = event_sink or NullOperationalEventSink()

    def resume(
        self,
        job_id: str,
        context: OperationContext,
        stop_requested: Callable[[], bool],
    ) -> ArchiveOutcome:
        if (
            context.record.kind != "archive.resume"
            or context.record.job_id != job_id
            or context.record.cassette_sequence is None
        ):
            raise ValidationError("archive context does not match the frozen job")
        leases = self.managed_source_admission(
            job_id, context.record.id, context.fence.owner_generation
        )
        try:
            return self._resume_admitted(job_id, context, stop_requested)
        finally:
            self.managed_source_release(leases, context.fence.owner_generation)

    def _resume_admitted(
        self,
        job_id: str,
        context: OperationContext,
        stop_requested: Callable[[], bool],
    ) -> ArchiveOutcome:
        if (
            context.record.kind != "archive.resume"
            or context.record.job_id != job_id
            or context.record.cassette_sequence is None
        ):
            raise ValidationError("archive context does not match the frozen job")
        with self.catalog_factory() as catalog:
            plan = self.plan_loader(catalog, job_id)
            cassette = plan.next_cassette()
            if (
                cassette.sequence < 4
                or cassette.sequence > 20
                or cassette.sequence != context.record.cassette_sequence
            ):
                raise ValidationError("archive context is not the frozen next cassette")
            validation = plan.validate_sources()
            if validation.blocked:
                raise FrozenSourceValidationFailed(validation.error_code)
            expected = ExpectedMedia(
                "archive.resume",
                job_id,
                cassette.sequence,
                cassette.physical_label,
                None,
                None,
            )
            if self.backend.fence != context.fence or self.backend.expected != expected:
                raise ValidationError(
                    "archive backend is not bound to the admitted operation target"
                )
            context.assert_current()
            self.backups.create_for_operation(
                context.fence, f"before-cassette-{cassette.sequence}"
            )
            catalog.transition_imported_cassette_phase(
                context.fence, "identifying_media"
            )
            correlation = closed_operational_correlation(
                operation_id=context.record.id,
                job_id=job_id,
                cassette_label=cassette.physical_label,
                cassette_sequence=cassette.sequence,
                daemon_generation=context.fence.owner_generation,
            )
            phases = OperationalPhaseTracker(self.event_sink, correlation)
            phases.start("identify")
            phase = "identifying_media"
            error_code = "media_wait_failed"
            unmount_dispatched = False
            observer: _PersistedUnmountObserver | None = None
            try:
                if cassette.operation == "format":
                    error_code = "format_authorization_failed"
                    catalog.require_consumed_format_confirmation(
                        context.fence,
                        job_id,
                        cassette.sequence,
                        cassette.physical_label,
                    )
                    if not self.backend.wait_for_preformat_media(
                        expected, stop_requested
                    ):
                        raise MediaWaitStopped()
                    phases.succeed("identify")
                    catalog.transition_imported_cassette_phase(
                        context.fence, "formatting_media"
                    )
                    phase = "formatting_media"
                    error_code = "format_failed"
                    phases.start("format")
                    self.backend.format(expected)
                    phases.succeed("format")
                elif not self.backend.wait_for_media(expected, stop_requested):
                    raise MediaWaitStopped()
                else:
                    phases.succeed("identify")
                error_code = "mount_failed"
                catalog.transition_imported_cassette_phase(context.fence, "mounting")
                phase = "mounting"
                phases.start("mount")
                mounted = self.backend.mount(read_only=False)
                phases.succeed("mount")
                block_plans = self._block_plans(context, cassette)
                error_code = "staging_failed"
                tape_id = catalog.stage_imported_cassette(
                    context.fence,
                    mount_hint=str(mounted.path),
                    blocks=tuple(block.catalog_tuple() for block in block_plans),
                )
                catalog.transition_imported_cassette_phase(context.fence, "writing")
                phase = "writing"
                block_ids = tuple(block.block_id for block in block_plans)
                error_code = "copy_or_manifest_failed"
                phases.start("copy")
                self._copy_and_write_manifests(
                    catalog,
                    context,
                    cassette,
                    mounted,
                    tape_id,
                    block_plans,
                    stop_requested,
                )
                phases.succeed("copy")
                phases.start("sync")
                phase = "writing_manifest"
                error_code = "unmount_failed"
                observer = _PersistedUnmountObserver(
                    catalog, context, self.clock, phases
                )
                unmount_dispatched = True
                unmount_result = self.backend.unmount(mounted, observer)
                finalization_started_at, unmounting_started_at = (
                    observer.require_started()
                )
                phase = "unmounting"
                catalog.record_imported_ltfs_terminal(
                    context.fence,
                    finalization_started_at=finalization_started_at,
                    unmounting_started_at=unmounting_started_at,
                    unmount_result=unmount_result,
                )
                phases.succeed("sync")
                phases.succeed("finalizing_index")
                phases.succeed("unmount")
                self._telemetry(
                    "add_duration", "finalization", unmount_result.finalization_seconds
                )
                self._telemetry(
                    "add_duration", "unmount", unmount_result.mount_release_seconds
                )
                error_code = "commit_failed"
                catalog.transition_imported_cassette_phase(context.fence, "committing")
                phase = "committing"
                phases.start("commit")
                if cassette.sequence == 4:
                    catalog.commit_imported_cassette_authority(
                        context.fence, tape_id, block_ids
                    )
                    next_state: Literal["waiting_media", "completed"] = "waiting_media"
                else:
                    next_state = catalog.commit_imported_cassette(
                        context.fence, tape_id, block_ids
                    )
                phases.succeed("commit")
            except BaseException:  # noqa: BLE001 - hardware started; block admission.
                phases.fail_open()
                if unmount_dispatched:
                    self._recover_committed_terminal(catalog, context)
                return self._recovery_required(
                    catalog,
                    context,
                    cassette.sequence,
                    error_code,
                    phase=phase,
                )

            try:
                self.backups.create_for_operation(
                    context.fence, f"after-cassette-{cassette.sequence}"
                )
            except BaseException:  # noqa: BLE001 - commit crossed the rollback boundary.
                return self._recovery_required(
                    catalog,
                    context,
                    cassette.sequence,
                    "postcommit_backup_failed",
                )

            catalog.transition_imported_cassette_phase(context.fence, "unloading")
            phases.start("eject")
            self._telemetry("start_phase", "unload")
            try:
                self.backend.unload()
            except BaseException:  # noqa: BLE001 - committed media needs recovery.
                phases.fail("eject")
                self._telemetry("finish_phase", "unload")
                return self._recovery_required(
                    catalog, context, cassette.sequence, "unload_failed"
                )
            self._telemetry("finish_phase", "unload")
            if not _physical_eject_proven(self.backend):
                phases.fail("eject")
                return self._recovery_required(
                    catalog,
                    context,
                    cassette.sequence,
                    "postcommit_eject_unproven",
                )
            try:
                catalog.attest_imported_postcommit_unload(
                    context.fence, no_media_proven=True
                )
            except BaseException:  # noqa: BLE001 - evidence failure is safety-critical.
                phases.fail("eject")
                return self._recovery_required(
                    catalog,
                    context,
                    cassette.sequence,
                    "postcommit_attestation_failed",
                )
            phases.succeed("eject")
            return ArchiveOutcome(
                state="succeeded",
                phase="unloading",
                next_state=next_state,
                sequence=cassette.sequence,
            )

    def _copy_and_write_manifests(
        self,
        catalog: Catalog,
        context: OperationContext,
        cassette: FrozenCassette,
        mounted: MountedTape,
        tape_id: str,
        blocks: tuple[_BlockPlan, ...],
        stop_requested: Callable[[], bool],
    ) -> None:
        staging_directory = self.host_staging_root / context.record.id
        staging_directory.mkdir(parents=True, exist_ok=True)
        with ExitStack() as stack:
            writers: list[tuple[_BlockPlan, ManifestWriter]] = []
            telemetry_window_started = False
            for block in blocks:
                context.assert_current()
                root = mounted.path / Path(block.tape_relative_root)
                files_root = root / "files"
                files_root.mkdir(parents=True, exist_ok=True)
                writer = stack.enter_context(
                    self.manifest_writer_factory(
                        catalog=catalog,
                        host_staging_path=staging_directory
                        / f"{block.block_id}.manifest.jsonl",
                        tape_manifest_path=root / "manifest.jsonl",
                        block_path=root / "block.json",
                        snapshot_path=mounted.path
                        / ".lto-backup"
                        / "catalog-snapshots"
                        / f"{block.block_id}.sqlite3",
                        tape_root=mounted.path,
                        buffer_bytes=self.buffer_bytes,
                    )
                )
                writers.append((block, writer))
                for item in block.items:
                    context.assert_current()
                    if not telemetry_window_started:
                        self._telemetry("begin_window")
                        telemetry_window_started = True
                    source = Path(catalog.get_library(item.library_id)["source_root"])
                    destination = files_root / Path(
                        ltfs_tape_relative_path(item.relative_path)
                    )
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    result = self.copy_file(
                        CopyRequest(
                            source=source / Path(item.relative_path),
                            destination=destination,
                            expected_size=item.size,
                            expected_mtime_ns=item.mtime_ns,
                            buffer_bytes=self.buffer_bytes,
                            stop_requested=stop_requested,
                            fence_check=context.assert_current,
                        )
                    )
                    self._telemetry("record_file", result.bytes_copied)
                    self._telemetry("add_duration", "smb_read", result.read_seconds)
                    self._telemetry("add_duration", "copy", result.write_seconds)
                    self._telemetry("add_duration", "close", result.close_seconds)
                    tape_relative_path = destination.relative_to(
                        mounted.path
                    ).as_posix()
                    catalog.stage_imported_file(
                        context.fence,
                        item_sequence=item.item_sequence,
                        block_id=block.block_id,
                        tape_relative_path=tape_relative_path,
                        sha256=result.sha256,
                    )
                    writer.append(
                        FileManifestRecord(
                            library_id=item.library_id,
                            relative_path=item.relative_path,
                            tape_relative_path=tape_relative_path,
                            size=result.bytes_copied,
                            mtime_ns=item.mtime_ns,
                            sha256=result.sha256,
                        )
                    )
            catalog.transition_imported_cassette_phase(
                context.fence, "writing_manifest"
            )
            for block, writer in writers:
                context.assert_current()
                writer.finalize(
                    BlockManifest(
                        block_id=block.block_id,
                        library_id=block.library_id,
                        tape_id=tape_id,
                        completed_at=self.clock(),
                        file_count=block.planned_files,
                        total_bytes=block.planned_bytes,
                    )
                )

    @staticmethod
    def _block_plans(
        context: OperationContext, cassette: FrozenCassette
    ) -> tuple[_BlockPlan, ...]:
        by_library: dict[str, list[FrozenItem]] = defaultdict(list)
        for item in cassette.items:
            by_library[item.library_id].append(item)
        plans = []
        for library_id, items in by_library.items():
            digest = hashlib.sha256(
                f"{context.record.id}\0{cassette.sequence}\0{library_id}".encode()
            ).hexdigest()[:24]
            block_id = f"block-{cassette.sequence:02d}-{digest}"
            plans.append(
                _BlockPlan(
                    block_id,
                    library_id,
                    f"libraries/{library_id}/blocks/{block_id}",
                    tuple(items),
                )
            )
        if not plans:
            raise ValidationError("frozen cassette has no assigned files")
        return tuple(plans)

    def _recover_committed_terminal(
        self, catalog: Catalog, context: OperationContext
    ) -> None:
        """Best-effort import under the still-current original operation fence."""

        try:
            finalization = self.backend.recover_pending_ltfs_session()
            if finalization is not None:
                catalog.recover_imported_ltfs_terminal_and_commit(
                    context.fence, finalization
                )
        except BaseException:  # noqa: BLE001 - preserve the durable recovery blocker.
            return

    @staticmethod
    def _recovery_required(
        catalog: Catalog,
        context: OperationContext,
        sequence: int,
        error_code: str,
        *,
        phase: str = "unloading",
    ) -> ArchiveOutcome:
        operation = catalog.get_operation(context.fence.operation_id)
        durable_phase = (
            operation["phase"]
            if operation is not None and isinstance(operation["phase"], str)
            else phase
        )
        catalog.finish_operation(
            context.fence,
            "recovery_required",
            error_class="operator_required",
            error_code=error_code,
        )
        return ArchiveOutcome(
            state="recovery_required",
            phase=durable_phase,
            next_state="recovery_required",
            sequence=sequence,
            error_class="operator_required",
            error_code=error_code,
        )

    def _telemetry(self, method: str, *args: object) -> None:
        """Telemetry faults never weaken the existing archive recovery fence."""

        try:
            getattr(self.telemetry_sink, method)(*args)
        except BaseException:  # noqa: BLE001 - diagnostics never alter recovery.
            return


def _physical_eject_proven(backend: object) -> bool:
    try:
        backend.media_identity_probe.identify_unmounted()
    except BaseException as exc:  # noqa: BLE001 - observational proof only
        return (
            type(exc) is CommandFailed
            and exc.kind == "probe_media"
            and exc.returncode == 3
        )
    return False
