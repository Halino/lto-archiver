"""Production one-cassette execution for native Linux archive jobs."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from pathlib import Path

from ..application import LtoApplication
from ..automation import AutomaticJobRunner, CassetteLabel
from ..broker.client import LtfsSessionApi
from ..catalog import Catalog
from ..errors import OperationCancelled
from ..linux_settings import LinuxPaths, LinuxSettings
from ..media import require_ltfs_profile
from ..models import VolumeInfo
from ..operational_log import (
    NullOperationalEventSink,
    OperationalCorrelation,
    OperationalEvent,
    OperationalSeverity,
    OperationalSource,
    OperationalEventSink,
    OperationalPhaseTracker,
    closed_operational_correlation,
    emit_operational_phase,
)
from ..settings import AppPaths, Settings
from ..tape.command_supervisor import (
    BrokeredCgroupExecutionScopeManager,
    CommandFailed,
    ReadOnlyCgroupPrivilegeBoundary,
)
from ..tape.linux_ltfs import LinuxLtfsBackend, SysfsDeviceIdentityProvider
from ..tape.models import ExpectedMedia, MountedTape
from .archive_runner import TelemetrySink
from .archive_runtime import (
    ArchiveResumeAdmission,
    BrokeredLtfsInfoMediaIdentityProbe,
    _production_supervisor,
    _trusted_ltfs_info_binary,
)
from .backups import BackupManager
from .native_frozen import FrozenNativeCassettePlan
from .operations import OperationContext


def _operation_correlation(
    context: object, *, label: str | None = None
) -> OperationalCorrelation:
    record = getattr(context, "record", None)
    fence = getattr(context, "fence", None)
    return closed_operational_correlation(
        operation_id=getattr(record, "id", None),
        job_id=getattr(record, "job_id", None),
        cassette_label=label,
        cassette_sequence=getattr(record, "cassette_sequence", None),
        daemon_generation=getattr(fence, "owner_generation", None),
    )


class _UnmountObserver:
    def __init__(
        self,
        context: OperationContext,
        event_sink: OperationalEventSink,
        correlation: OperationalCorrelation,
    ) -> None:
        self._context = context
        self._event_sink = event_sink
        self._correlation = correlation
        self.finalization_was_started = False
        self.unmount_was_started = False

    def finalization_started(self) -> None:
        self._context.transition_phase("finalizing_index")
        self.finalization_was_started = True
        emit_operational_phase(
            self._event_sink, self._correlation, "finalizing_index", "started"
        )

    def mount_release_started(self) -> None:
        self._context.transition_phase("unmounting")
        self.unmount_was_started = True
        emit_operational_phase(
            self._event_sink, self._correlation, "unmount", "started"
        )


def _proven_quiescent_pre_media_retry(
    catalog: Catalog, record: object, owner_generation: int
) -> bool:
    """Never retry a pre-media fault if the durable ledger could hide tape effects."""
    operation_id = str(getattr(record, "id"))
    operation = catalog.get_operation(operation_id)
    owner = catalog.current_daemon_fence()
    if owner is None or owner.generation != owner_generation:
        return False
    if (
        operation is None
        or operation["state"] != "running"
        or operation["owner_generation"] != owner_generation
        or operation["phase"] is not None
        or catalog.observed_media_binding(operation_id) is not None
    ):
        return False
    cassette = catalog.connection.execute(
        "SELECT status FROM automatic_cassettes WHERE job_id=? AND sequence=?",
        (getattr(record, "job_id"), getattr(record, "cassette_sequence")),
    ).fetchone()
    if cassette is None or cassette["status"] != "waiting_media":
        return False
    unsafe = catalog.connection.execute(
        "SELECT 1 FROM hardware_command_executions command "
        "LEFT JOIN hardware_command_release_authorizations authorization "
        "ON authorization.command_id=command.id "
        "WHERE command.operation_id=? AND (command.state<>'quiesced' "
        "OR command.issued_generation<>? OR command.exit_outcome IS NULL "
        "OR command.command_kind NOT IN ('identify','probe_media') "
        "OR COALESCE(authorization.release_status,'') NOT IN ('','aborted','released')) LIMIT 1",
        (operation_id, owner_generation),
    ).fetchone()
    return unsafe is None


class _LinuxAutomaticController:
    """Present one admitted Linux backend as the legacy one-cassette controller."""

    def __init__(
        self,
        backend: LinuxLtfsBackend,
        expected: ExpectedMedia,
        context: OperationContext,
        *,
        safe_checkpoint: Callable[[str], bool] = lambda _checkpoint: False,
        pre_media_retry_proof: Callable[[], bool] = lambda: False,
        retry_sleep: Callable[[float], None] = time.sleep,
        event_sink: OperationalEventSink | None = None,
        correlation: OperationalCorrelation | None = None,
    ) -> None:
        self._backend = backend
        self._expected = expected
        self._context = context
        self._mounted: MountedTape | None = None
        self._media_admitted = False
        self._completed = False
        self._safe_checkpoint = safe_checkpoint
        self._pre_media_retry_proof = pre_media_retry_proof
        self._retry_sleep = retry_sleep
        self._event_sink = event_sink or NullOperationalEventSink()
        self._correlation = correlation or _operation_correlation(
            context, label=expected.volume_label
        )
        self.pause_acknowledged = False
        self.mounted_volume = None

    def wait_for_media(self, stop_requested: Callable[[], bool]) -> bool:
        if self._completed:
            return False
        with Catalog(self._backend.catalog.path) as catalog:
            cassette = catalog.connection.execute(
                "SELECT operation FROM automatic_cassettes "
                "WHERE job_id=? AND sequence=?",
                (self._expected.job_id, self._expected.cassette_sequence),
            ).fetchone()
        if cassette is None:
            return False

        def stop_waiting() -> bool:
            if stop_requested() or self.pause_acknowledged:
                return True
            # The wait predicate runs between completed identify commands, never
            # after accepting media or while formatting, mounted, or writing.
            if self._mounted is None and not self._media_admitted:
                self.pause_acknowledged = bool(
                    self._safe_checkpoint("waiting_media")
                )
            return self.pause_acknowledged

        emit_operational_phase(
            self._event_sink, self._correlation, "identify", "started"
        )
        try:
            retry_failures = 0
            while not stop_waiting():
                try:
                    if cassette["operation"] == "format":
                        available = self._backend.wait_for_preformat_media(
                            self._expected, stop_waiting
                        )
                    else:
                        available = self._backend.wait_for_media(
                            self._expected, stop_waiting
                        )
                except Exception as exc:
                    if stop_waiting():
                        break
                    if isinstance(exc, OperationCancelled) or not self._pre_media_retry_proof():
                        raise
                    retry_failures = min(retry_failures + 1, 5)
                    if retry_failures & (retry_failures - 1) == 0:
                        try:
                            self._event_sink.emit(OperationalEvent(
                                source=OperationalSource.LTFS,
                                severity=OperationalSeverity.WARNING,
                                code="ltfs.identify.deferred",
                                message="Pre-media identification deferred after a safely quiesced error.",
                                operation_id=self._correlation.operation_id,
                                job_id=self._correlation.job_id,
                                cassette_label=self._correlation.cassette_label,
                                cassette_sequence=self._correlation.cassette_sequence,
                                daemon_generation=self._correlation.daemon_generation,
                                phase="identify",
                            ))
                        except BaseException:
                            pass  # Diagnostics cannot change the admitted operation.
                    self._retry_sleep(min(2.0 ** retry_failures, 30.0))
                    continue
                retry_failures = 0
                if available:
                    self._media_admitted = True
                    emit_operational_phase(
                        self._event_sink,
                        self._correlation,
                        "identify",
                        "succeeded",
                    )
                    return True
        except BaseException:
            emit_operational_phase(
                self._event_sink, self._correlation, "identify", "failed"
            )
            raise
        emit_operational_phase(
            self._event_sink, self._correlation, "identify", "failed"
        )
        return False

    def format(self, cassette: CassetteLabel) -> None:
        if cassette.physical_label != self._expected.volume_label:
            raise RuntimeError("native format label changed after admission")
        self._context.transition_phase("formatting_media")
        emit_operational_phase(
            self._event_sink, self._correlation, "format", "started"
        )
        try:
            self._backend.format(self._expected)
        except BaseException:
            emit_operational_phase(
                self._event_sink, self._correlation, "format", "failed"
            )
            raise
        emit_operational_phase(
            self._event_sink, self._correlation, "format", "succeeded"
        )

    def mount(self, stop_requested: Callable[[], bool]) -> Path:
        if stop_requested():
            raise OperationCancelled("native archive stopped before LTFS mount")
        self._context.transition_phase("mounting")
        emit_operational_phase(
            self._event_sink, self._correlation, "mount", "started"
        )
        try:
            self._mounted = self._backend.mount(read_only=False)
        except BaseException:
            emit_operational_phase(
                self._event_sink, self._correlation, "mount", "failed"
            )
            raise
        emit_operational_phase(
            self._event_sink, self._correlation, "mount", "succeeded"
        )
        usage = shutil.disk_usage(self._mounted.path)
        receipt = self._mounted.session_receipt
        self.mounted_volume = VolumeInfo(
            root=self._mounted.path,
            filesystem="LTFS",
            label=receipt.observed_volume_label,
            serial=receipt.observed_volume_uuid,
            total_bytes=usage.total,
            free_bytes=usage.free,
        )
        return self._mounted.path

    def set_unmount_progress(self, _callback) -> None:
        return None

    def unmount_and_eject(self) -> None:
        if self._mounted is None and not self._media_admitted:
            return
        if self._mounted is not None:
            emit_operational_phase(
                self._event_sink, self._correlation, "sync", "started"
            )
            observer = _UnmountObserver(
                self._context, self._event_sink, self._correlation
            )
            try:
                self._backend.unmount(self._mounted, observer)
            except BaseException:
                emit_operational_phase(
                    self._event_sink, self._correlation, "sync", "failed"
                )
                if observer.finalization_was_started:
                    emit_operational_phase(
                        self._event_sink,
                        self._correlation,
                        "finalizing_index",
                        "failed",
                    )
                if observer.unmount_was_started:
                    emit_operational_phase(
                        self._event_sink, self._correlation, "unmount", "failed"
                    )
                raise
            emit_operational_phase(
                self._event_sink,
                self._correlation,
                "finalizing_index",
                "succeeded",
            )
            emit_operational_phase(
                self._event_sink, self._correlation, "sync", "succeeded"
            )
            emit_operational_phase(
                self._event_sink, self._correlation, "unmount", "succeeded"
            )
            self._mounted = None
        self._context.transition_phase("unloading")
        emit_operational_phase(
            self._event_sink, self._correlation, "eject", "started"
        )
        try:
            self._backend.unload()
        except BaseException:
            emit_operational_phase(
                self._event_sink, self._correlation, "eject", "failed"
            )
            raise
        terminal_probe_exact = False
        try:
            self._backend.media_identity_probe.identify_unmounted()
        except CommandFailed as exc:
            terminal_probe_exact = exc.kind == "probe_media" and exc.returncode == 3
        except BaseException:  # noqa: BLE001 - terminal observation is best-effort
            terminal_probe_exact = False
        if not terminal_probe_exact:
            emit_operational_phase(
                self._event_sink, self._correlation, "eject", "failed"
            )
            raise RuntimeError("native final eject state is ambiguous")
        emit_operational_phase(
            self._event_sink, self._correlation, "eject", "succeeded"
        )
        self._media_admitted = False
        self._completed = True
        self.pause_acknowledged = bool(self._safe_checkpoint("unloaded"))


def _native_backup_callback(
    application: LtoApplication,
    context: OperationContext,
    settings: Settings,
    *,
    tape_capacity_bytes: int,
    job_id: str | None,
    event_sink: OperationalEventSink | None = None,
    source_change_detection_policy: str = "size_mtime",
):
    """Bind one admitted settings snapshot through every application seam."""

    def backup(libraries, label, mounted, progress, stop_requested):
        context.transition_phase("writing")
        sink = event_sink or NullOperationalEventSink()
        correlation = _operation_correlation(context, label=label)
        phases = OperationalPhaseTracker(sink, correlation)
        phases.start("copy")
        try:
            known_volume = mounted if hasattr(mounted, "filesystem") else None
            mount = known_volume.root if known_volume is not None else Path(mounted)
            application.register_tape(
                label,
                label,
                mount,
                known_volume=known_volume,
                settings=settings,
            )
            result = application.backup_automatic_batch(
                libraries,
                label,
                mount,
                progress=progress,
                stop_requested=stop_requested,
                known_volume=known_volume,
                tape_capacity_bytes=tape_capacity_bytes,
                automatic_job_id=job_id,
                settings=settings,
                source_change_detection_policy=source_change_detection_policy,
                automatic_operation_id=(
                    context.record.id if job_id is not None else None
                ),
                automatic_cassette_sequence=(
                    context.record.cassette_sequence if job_id is not None else None
                ),
            )
        except BaseException:
            phases.fail("copy")
            raise
        phases.succeed("copy")
        return result

    return backup


def _native_frozen_backup_callback(
    application: LtoApplication,
    context: OperationContext,
    settings: Settings,
    plan: FrozenNativeCassettePlan,
    *,
    tape_capacity_bytes: int,
    event_sink: OperationalEventSink | None = None,
):
    """Execute only the already-durable native manifest; never scan a root."""

    def backup(libraries, label, mounted, progress, stop_requested):
        if (
            len(libraries) != len(plan.job_library_ids)
            or {str(library_id).casefold() for library_id in libraries}
            != {library_id.casefold() for library_id in plan.job_library_ids}
            or label != plan.physical_label
        ):
            raise RuntimeError("native frozen checkpoint changed during execution")
        context.transition_phase("writing")
        sink = event_sink or NullOperationalEventSink()
        correlation = _operation_correlation(context, label=label)
        phases = OperationalPhaseTracker(sink, correlation)
        phases.start("copy")
        try:
            known_volume = mounted if hasattr(mounted, "filesystem") else None
            mount = known_volume.root if known_volume is not None else Path(mounted)
            application.register_tape(
                label, label, mount, known_volume=known_volume, settings=settings
            )
            result = application.backup_automatic_batch(
                list(plan.library_ids),
                label,
                mount,
                progress=progress,
                stop_requested=stop_requested,
                known_volume=known_volume,
                tape_capacity_bytes=tape_capacity_bytes,
                automatic_job_id=plan.job_id,
                settings=settings,
                frozen_plans_by_library=plan.plans_by_library,
                automatic_operation_id=context.record.id,
                automatic_cassette_sequence=context.record.cassette_sequence,
            )
        except BaseException:
            phases.fail("copy")
            raise
        phases.succeed("copy")
        return result

    return backup


class ProductionNativeArchive:
    """Admit and execute exactly one cassette from a native planned job."""

    def __init__(
        self,
        *,
        paths: LinuxPaths,
        settings: LinuxSettings,
        backups: BackupManager,
        telemetry_sink: Callable[[], TelemetrySink],
        stop_requested: Callable[[], bool],
        scope_manager: BrokeredCgroupExecutionScopeManager,
        ltfs_sessions: LtfsSessionApi,
        privilege_boundary: ReadOnlyCgroupPrivilegeBoundary,
        ltfs_info_binary: Path,
        managed_source_admission: Callable[[str, str, int], tuple[str, ...]] = (
            lambda _job_id, _operation_id, _generation: ()
        ),
        managed_source_release: Callable[[tuple[str, ...], int], None] = (
            lambda _leases, _generation: None
        ),
        event_sink: OperationalEventSink | None = None,
    ) -> None:
        self._paths = paths
        self._settings = settings
        self._backups = backups
        self._telemetry_sink = telemetry_sink
        self._stop_requested = stop_requested
        self._scope_manager = scope_manager
        self._ltfs_sessions = ltfs_sessions
        self._privilege_boundary = privilege_boundary
        self._ltfs_info_binary = _trusted_ltfs_info_binary(ltfs_info_binary)
        self._catalog_factory = lambda: Catalog(self._paths.catalog_file)
        self._device_identities = SysfsDeviceIdentityProvider()
        self._managed_source_admission = managed_source_admission
        self._managed_source_release = managed_source_release
        self._event_sink = event_sink or NullOperationalEventSink()

    def admit(self, job_id: str) -> ArchiveResumeAdmission:
        with self._catalog_factory() as catalog:
            if catalog.get_import_policy(job_id) is not None:
                raise RuntimeError("imported jobs cannot use native execution")
            cassette = catalog.next_automatic_cassette(job_id)
            if cassette is None:
                raise RuntimeError("native job has no pending cassette")
            expected = self._expected(job_id, cassette)
        target = LinuxLtfsBackend.target_binding_from(
            self._settings, expected, self._device_identities
        )
        return ArchiveResumeAdmission(job_id, int(cassette["sequence"]), target)

    @staticmethod
    def _settings_for_admitted_job(
        context: OperationContext,
        catalog: Catalog,
        job_id: str,
        *,
        catalog_backup_directory: str = "",
    ) -> Settings:
        policy = catalog.get_job_policy_snapshot(job_id)
        selected_profile = require_ltfs_profile(str(policy["selected_media_profile"]))
        if selected_profile.ltfs_usable_bytes is None:
            raise RuntimeError("native job media policy is not LTFS compatible")
        settings = Settings(
            reserve_bytes=int(policy["capacity_reserve_bytes"]),
            tape_capacity_bytes=selected_profile.ltfs_usable_bytes,
            buffer_bytes=context.admitted_copy_buffer_bytes(),
            min_age_seconds=int(policy["minimum_source_file_age_seconds"]),
            tape_root_directory=str(policy["tape_root_directory"]),
            catalog_backup_directory=catalog_backup_directory,
            verify_unchanged_content=(policy["content_verification_policy"] == "full"),
            default_media_key=str(policy["default_media_profile"]),
        )
        settings.validate()
        return settings

    def __call__(self, context: OperationContext) -> None:
        self._execute(context, frozen=True)

    def run_frozen_recovery(self, context: OperationContext) -> None:
        self._execute(context, frozen=True)

    def _execute(self, context: OperationContext, *, frozen: bool) -> None:
        record = context.record
        if (
            record.kind != "archive.native"
            or record.job_id is None
            or record.cassette_sequence is None
        ):
            raise RuntimeError("native archive callback is not cassette-bound")
        leases = self._managed_source_admission(
            record.job_id, record.id, context.fence.owner_generation
        )
        try:
            self._run_admitted(context, frozen=frozen)
        finally:
            self._managed_source_release(leases, context.fence.owner_generation)

    def _run_admitted(
        self, context: OperationContext, *, frozen: bool = False
    ) -> None:
        record = context.record
        if (
            record.kind != "archive.native"
            or record.job_id is None
            or record.cassette_sequence is None
        ):
            raise RuntimeError("native archive callback is not cassette-bound")
        catalog = self._catalog_factory()
        try:
            cassette = catalog.next_automatic_cassette(record.job_id)
            if (
                cassette is None
                or int(cassette["sequence"]) != record.cassette_sequence
            ):
                raise RuntimeError("native next cassette changed after admission")
            expected = self._expected(record.job_id, cassette)
            admitted_target = catalog.hardware_target_binding(record.id)
            observed_target = LinuxLtfsBackend.target_binding_from(
                self._settings, expected, self._device_identities
            )
            if admitted_target != observed_target:
                raise RuntimeError("native hardware target differs from admission")
            daemon_fence = catalog.current_daemon_fence()
            if (
                daemon_fence is None
                or daemon_fence.generation != context.fence.owner_generation
            ):
                raise RuntimeError("native daemon fence is no longer current")
            event_sink = getattr(self, "_event_sink", NullOperationalEventSink())
            supervisor = _production_supervisor(
                catalog,
                daemon_fence,
                self._scope_manager,
                self._privilege_boundary,
                event_sink=event_sink,
                operation_context=closed_operational_correlation(
                    operation_id=record.id,
                    job_id=record.job_id,
                    cassette_label=expected.volume_label,
                    cassette_sequence=record.cassette_sequence,
                    daemon_generation=context.fence.owner_generation,
                ),
            )
            probe = BrokeredLtfsInfoMediaIdentityProbe(
                supervisor, context, self._settings, self._ltfs_info_binary
            )
            backend = LinuxLtfsBackend(
                settings=self._settings,
                expected=expected,
                fence=context.fence,
                catalog=catalog,
                supervisor=supervisor,
                ltfs_sessions=self._ltfs_sessions,
                device_identities=self._device_identities,
                media_identity_probe=probe,
            )

            def pre_media_retry_proof() -> bool:
                return _proven_quiescent_pre_media_retry(catalog, record, context.fence.owner_generation)

            controller = _LinuxAutomaticController(
                backend,
                expected,
                context,
                safe_checkpoint=lambda checkpoint: catalog.acknowledge_job_pause(
                    record.job_id, checkpoint, fence=context.fence
                ),
                pre_media_retry_proof=pre_media_retry_proof,
                event_sink=event_sink,
            )
            application = LtoApplication(self._paths.state_dir)
            app_paths = AppPaths(self._paths.state_dir)
            legacy_settings = self._settings_for_admitted_job(
                context,
                catalog,
                record.job_id,
                catalog_backup_directory=str(self._backups.backup_directory),
            )
            profile = require_ltfs_profile(
                str(catalog.get_automatic_job(record.job_id)["media_key"])
            )
            tape_capacity = application._media_tape_capacity(legacy_settings, profile)
            if frozen:
                frozen_plan = FrozenNativeCassettePlan.load(
                    catalog, record.job_id, record.cassette_sequence
                )
                backup = _native_frozen_backup_callback(
                    application,
                    context,
                    legacy_settings,
                    frozen_plan,
                    tape_capacity_bytes=tape_capacity,
                    event_sink=event_sink,
                )
            else:
                backup = _native_backup_callback(
                    application,
                    context,
                    legacy_settings,
                    tape_capacity_bytes=tape_capacity,
                    job_id=record.job_id,
                    event_sink=event_sink,
                    source_change_detection_policy=catalog.get_job_policy_snapshot(
                        record.job_id
                    ).get("source_change_detection_policy", "size_mtime"),
                )

            self._backups.create_for_operation(
                context.fence,
                f"before-native-cassette-{record.cassette_sequence}",
            )
            runner = AutomaticJobRunner(
                app_paths,
                legacy_settings,
                controller=controller,
                backup=backup,
            )
            telemetry = self._telemetry_sink()
            current_file_size = 0
            current_file_progress = 0
            telemetry_window_started = False

            def emit_telemetry(method: str, *args: object) -> None:
                """Live diagnostics must never alter the admitted tape operation."""

                try:
                    getattr(telemetry, method)(*args)
                except BaseException:  # noqa: BLE001 - telemetry is best-effort.
                    return

            def progress(event: dict) -> None:
                nonlocal current_file_progress, current_file_size
                nonlocal telemetry_window_started
                kind = str(event.get("event") or "")
                if kind == "file.start":
                    current_file_size = max(0, int(event.get("size") or 0))
                    current_file_progress = 0
                elif kind == "file.progress":
                    if not telemetry_window_started:
                        emit_telemetry("begin_window")
                        telemetry_window_started = True
                    observed = max(0, int(event.get("copied_bytes") or 0))
                    delta = max(0, observed - current_file_progress)
                    current_file_progress = max(current_file_progress, observed)
                    if delta:
                        emit_telemetry("record_progress", delta)
                elif kind == "file.activity":
                    activity_phase = str(event.get("phase") or "")
                    if activity_phase == "write.pending" and not telemetry_window_started:
                        emit_telemetry("begin_window")
                        telemetry_window_started = True
                    elif activity_phase == "timing.complete":
                        emit_telemetry(
                            "add_duration",
                            "copy",
                            max(
                                0.0,
                                float(event.get("data_complete_seconds") or 0.0),
                            ),
                        )
                        emit_telemetry(
                            "add_duration",
                            "close",
                            max(
                                0.0,
                                float(event.get("close_elapsed_seconds") or 0.0),
                            ),
                        )
                elif kind == "file.complete":
                    remainder = max(0, current_file_size - current_file_progress)
                    if remainder:
                        emit_telemetry("record_progress", remainder)
                    emit_telemetry("complete_file")
                    current_file_size = 0
                    current_file_progress = 0

            runner.run(
                record.job_id,
                progress=progress,
                stop_requested=self._stop_requested,
                stop_after_cassette=True,
            )
        finally:
            catalog.close()

    @staticmethod
    def _expected(job_id: str, cassette) -> ExpectedMedia:
        return ExpectedMedia(
            "archive.native",
            job_id,
            int(cassette["sequence"]),
            str(cassette["physical_label"]),
            None,
            None,
        )
