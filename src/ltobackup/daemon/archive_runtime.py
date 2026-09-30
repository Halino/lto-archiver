"""Production admission and execution boundary for ``archive.resume``.

This module deliberately composes only the production Linux backend.  It does
not provide a permissive runner: unavailable stable device identities or an
unconfigured command privilege broker abort admission/execution before tape
commands can run.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

from ..broker.client import LtfsSessionApi
from ..catalog import Catalog
from ..errors import ValidationError
from ..linux_settings import LinuxPaths, LinuxSettings
from ..operational_log import (
    NullOperationalEventSink,
    OperationalCorrelation,
    OperationalEventSink,
    closed_operational_correlation,
)
from ..tape.command_supervisor import (
    BrokeredCgroupExecutionScopeManager,
    BrokeredCgroupScopeToken,
    CommandError,
    CommandFailed,
    ExecutionScopeIdentity,
    ForkExecCommandLauncher,
    LinuxProcessProbe,
    LtfsFinalizationReceipt,
    PosixProcessTerminator,
    ReadOnlyCgroupPrivilegeBoundary,
    TrackedCommandSupervisor,
    _parse_proc_stat,
    _read_boot_id,
    _read_proc_text,
)
from ..tape.linux_ltfs import (
    BackendUnavailable,
    LinuxLtfsBackend,
    MediaIdentityFields,
    MediaProbeUnavailable,
    ProcMountInfoProbe,
    SysfsDeviceIdentityProvider,
)
from ..tape.models import ExpectedMedia, MediaIdentity
from .archive_runner import ArchiveRunner, TelemetrySink, _physical_eject_proven
from .backups import BackupManager
from .frozen_job import FrozenJobPlan
from .models import (
    CommandExitEvidence,
    CommandQuiescenceReceipt,
    DaemonFence,
    HardwareTargetBinding,
    OperationRecord,
    RecoveryCommandFence,
    RecoveryEffectReceipt,
    SafeRecoveryResolution,
    VerifiedPhysicalQuiescence,
    media_identity_sha256,
)
from .native_frozen import FrozenNativeCassettePlan
from .operations import OperationContext, OperationManager
from .recovery import (
    AggregateRecoveryProbe,
    CatalogRecoveryStateSource,
    DurableOperation,
)


@dataclass(frozen=True)
class ArchiveResumeAdmission:
    """The exact next cassette and hardware identity to persist at admission."""

    job_id: str
    cassette_sequence: int
    hardware_target: HardwareTargetBinding


class ProductionArchiveResume:
    """Build one exact backend/runner only after a durable operation admission."""

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
        broker_ready: Callable[[], None],
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
        self._broker_ready = broker_ready
        self._catalog_factory = lambda: Catalog(self._paths.catalog_file)
        self._device_identities = SysfsDeviceIdentityProvider()
        self._managed_source_admission = managed_source_admission
        self._managed_source_release = managed_source_release
        self._event_sink = event_sink or NullOperationalEventSink()

    def validate_readiness(self) -> None:
        """Fail daemon startup before any archive admission is exposed."""

        self._broker_ready()
        self._privilege_boundary.validate_supervisor()

    def admit(self, job_id: str) -> ArchiveResumeAdmission:
        """Resolve only the frozen next cassette and stable hardware identity.

        This happens before ``OperationManager.start`` so the catalog's
        admission transaction stores the hardware target it authorized.  The
        resolver reads no mutable user path and raises when by-id/SCSI identity
        evidence is missing, which is the required fail-closed behavior.
        """

        with self._catalog_factory() as catalog:
            cassette = FrozenJobPlan.load(catalog, job_id).next_cassette()
        expected = _expected_media(job_id, cassette.sequence, cassette.physical_label)
        target = LinuxLtfsBackend.target_binding_from(
            self._settings, expected, self._device_identities
        )
        return ArchiveResumeAdmission(job_id, cassette.sequence, target)

    def cutover_environment(self, job_id: str) -> tuple[str, str]:
        """Resolve the current host and stable drive binding for authorization."""

        host_id = Path("/etc/machine-id").read_text(encoding="ascii").strip()
        if (
            not host_id
            or len(host_id) > 128
            or any(character not in "0123456789abcdef" for character in host_id)
        ):
            raise RuntimeError("the local host identity is unavailable")
        admission = self.admit(job_id)
        return host_id, admission.hardware_target.tape_device_identity_sha256

    def __call__(self, context: OperationContext) -> None:
        record = context.record
        if (
            record.kind != "archive.resume"
            or record.job_id is None
            or record.cassette_sequence is None
        ):
            raise RuntimeError("archive callback received an unbound operation")
        admission = getattr(
            self, "_managed_source_admission", lambda _job, _operation, _generation: ()
        )
        release = getattr(
            self, "_managed_source_release", lambda _leases, _generation: None
        )
        leases = admission(record.job_id, record.id, context.fence.owner_generation)
        try:
            self._run_admitted(context)
        finally:
            release(leases, context.fence.owner_generation)

    def _run_admitted(self, context: OperationContext) -> None:
        record = context.record
        if (
            record.kind != "archive.resume"
            or record.job_id is None
            or record.cassette_sequence is None
        ):
            raise RuntimeError("archive callback received an unbound operation")

        with self._catalog_factory() as catalog:
            plan = FrozenJobPlan.load(catalog, record.job_id)
            cassette = plan.next_cassette()
            if cassette.sequence != record.cassette_sequence:
                raise RuntimeError(
                    "archive operation no longer matches frozen next cassette"
                )
            expected = _expected_media(
                record.job_id,
                cassette.sequence,
                cassette.physical_label,
            )
            admitted_target = catalog.hardware_target_binding(record.id)
            observed_target = LinuxLtfsBackend.target_binding_from(
                self._settings, expected, self._device_identities
            )
            if admitted_target != observed_target:
                raise RuntimeError("archive hardware target differs from admission")
            daemon_fence = catalog.current_daemon_fence()
            if (
                daemon_fence is None
                or daemon_fence.generation != context.fence.owner_generation
            ):
                raise RuntimeError("archive daemon fence is no longer current")
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
                    cassette_label=cassette.physical_label,
                    cassette_sequence=cassette.sequence,
                    daemon_generation=context.fence.owner_generation,
                ),
            )
            media_probe = BrokeredLtfsInfoMediaIdentityProbe(
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
                media_identity_probe=media_probe,
            )
            runner = ArchiveRunner(
                catalog_factory=self._catalog_factory,
                backups=self._backups,
                backend=backend,
                host_staging_root=self._paths.state_dir / "archive-staging",
                buffer_bytes=context.admitted_copy_buffer_bytes(),
                telemetry_sink=self._telemetry_sink(),
                event_sink=event_sink,
            )
            outcome = runner.resume(record.job_id, context, self._stop_requested)
            if outcome.state == "succeeded":
                with self._catalog_factory() as pause_catalog:
                    if pause_catalog.acknowledge_job_pause(record.job_id, "unloaded"):
                        pause_catalog.update_automatic_job(
                            record.job_id,
                            "paused",
                            current_sequence=record.cassette_sequence,
                        )

    def reconcile_pending_ltfs_startup(self, operations: OperationManager) -> None:
        """Retry only exact in-memory LTFS cleanup during startup reconciliation."""

        for blocker in operations.reconcile_admission_blockers():
            if (
                blocker.kind == "archive.resume"
                and blocker.state == "recovery_required"
            ):
                self.reconcile_pending_ltfs_operation(
                    blocker.id,
                    RecoveryCommandFence(
                        blocker.id, operations.daemon_fence.generation
                    ),
                )

    def reconcile_pending_ltfs_operation(
        self,
        operation_id: str,
        fence: RecoveryCommandFence,
    ) -> LtfsFinalizationReceipt | None:
        """Finalize one exact pending LTFS session under catalog recovery authority.

        A successful LTFS finalization does not resolve the durable operation
        blocker: the existing physical-reconciliation workflow must still prove
        the complete command ledger, drive, media, and mount state before it can
        cancel the recovery-required operation.
        """

        if (
            type(operation_id) is not str
            or type(fence) is not RecoveryCommandFence
            or fence.operation_id != operation_id
        ):
            raise BackendUnavailable("an exact LTFS recovery operation is required")
        with self._catalog_factory() as catalog:
            catalog.assert_command_fence(fence)
            operation = catalog.get_operation(operation_id)
            if (
                operation is None
                or operation["state"] != "recovery_required"
                or operation["kind"] != "archive.resume"
                or type(operation["job_id"]) is not str
                or type(operation["cassette_sequence"]) is not int
            ):
                raise BackendUnavailable("LTFS recovery operation is unavailable")
            plan = FrozenJobPlan.load(catalog, operation["job_id"])
            cassette = plan.cassette_for_recovery(operation["cassette_sequence"])
            expected = _expected_media(
                operation["job_id"],
                cassette.sequence,
                cassette.physical_label,
            )
            admitted_target = catalog.hardware_target_binding(operation_id)
            observed_target = LinuxLtfsBackend.target_binding_from(
                self._settings, expected, self._device_identities
            )
            if admitted_target != observed_target:
                raise BackendUnavailable(
                    "LTFS recovery hardware target differs from admission"
                )
            daemon_fence = catalog.current_daemon_fence()
            if (
                daemon_fence is None
                or daemon_fence.generation != fence.owner_generation
            ):
                raise BackendUnavailable(
                    "LTFS recovery daemon fence is no longer current"
                )
            supervisor = _production_supervisor(
                catalog,
                daemon_fence,
                self._scope_manager,
                self._privilege_boundary,
                event_sink=getattr(self, "_event_sink", NullOperationalEventSink()),
                operation_context=closed_operational_correlation(
                    operation_id=operation_id,
                    job_id=operation["job_id"],
                    cassette_label=cassette.physical_label,
                    cassette_sequence=cassette.sequence,
                    daemon_generation=fence.owner_generation,
                ),
            )
            backend = LinuxLtfsBackend(
                settings=self._settings,
                expected=expected,
                fence=fence,
                catalog=catalog,
                supervisor=supervisor,
                ltfs_sessions=self._ltfs_sessions,
                device_identities=self._device_identities,
            )
            finalization_receipt = backend.recover_pending_ltfs_session()
            if finalization_receipt is None:
                return None
            catalog.recover_imported_ltfs_terminal_and_commit(
                fence, finalization_receipt
            )
            return finalization_receipt


class ProductionRecoveryRuntime:
    """Fenced physical observation and narrow effects for automatic recovery."""

    def __init__(
        self,
        archive: ProductionArchiveResume,
        operations: OperationManager,
        native_archive=None,
        replacement_admission_factory: Callable[
            [], Callable[[OperationRecord], None]
        ]
        | None = None,
    ) -> None:
        self._archive = archive
        self._operations = operations
        self._native_archive = native_archive
        self._replacement_admission_factory = replacement_admission_factory

    def _assert_pre_media_commands_clear(self, commands) -> None:
        """Prove managed command absence and an unmounted target without probing.

        This is bounded to the exact registered ledger and broker-owned scopes,
        whose recursive emptiness and durable close are checked by the caller.
        Manually privileged LTFS processes outside that ownership are not part
        of this proof; unrelated /proc domains need not be readable by the daemon.
        """
        # systemd ReadWritePaths creates a local-filesystem bind at this path
        # even with no tape mounted. Check the entire stack for FUSE/LTFS,
        # including covered mounts, rather than treating that bind as media.
        if ProcMountInfoProbe().has_fuse_mount(self._archive._settings.mount_path):
            raise BackendUnavailable("pre-media reset requires an unmounted target")
        processes = tuple(command.process for command in commands if command.process is not None)
        if processes:
            boot_id = _read_boot_id()
            for process in set(processes):
                if process.boot_id != boot_id:
                    continue
                # The general snapshot may skip inaccessible unrelated domains.
                # An unreadable known PID is never evidence of its absence.
                try:
                    stat_text = _read_proc_text(Path(f"/proc/{process.pid}/stat"), "ascii")
                except (FileNotFoundError, ProcessLookupError):
                    continue
                try:
                    observed = _parse_proc_stat(process.pid, stat_text, boot_id).identity
                except ValueError as exc:
                    raise BackendUnavailable("known identification process is unreadable") from exc
                if observed == process or observed.process_group_id == process.process_group_id:
                    # Includes exact zombies: reset does not reap or signal them.
                    raise BackendUnavailable("an identification process is still present")
        if not all(LinuxProcessProbe().identities_and_groups_absent(processes)):
            raise BackendUnavailable("an identification process is still present")

    def reconcile_pre_media_commands(
        self, operation: OperationRecord, daemon_fence: DaemonFence,
    ) -> CommandQuiescenceReceipt:
        """Close exact already-empty pre-media command scopes, without signalling."""
        with self._archive._catalog_factory() as catalog:
            proof = catalog.pre_media_reset_proof(operation.id, daemon_fence)
            plan = FrozenNativeCassettePlan.load(catalog, proof["job_id"], proof["cassette_sequence"])
            observed_target = LinuxLtfsBackend.target_binding_from(
                self._archive._settings, plan.expected_media, self._archive._device_identities,
            )
            if observed_target != catalog.hardware_target_binding(operation.id):
                raise BackendUnavailable("pre-media hardware target changed")
            commands = catalog.hardware_commands_for_operation(operation.id)
            self._assert_pre_media_commands_clear(commands)
            supervisor = self._recovery_supervisor(
                catalog, daemon_fence, RecoveryCommandFence(operation.id, daemon_fence.generation),
                job_id=operation.job_id, cassette_sequence=operation.cassette_sequence,
            )
            for command in commands:
                if command.state == "quiesced":
                    continue
                identity = ExecutionScopeIdentity(command.id, command.issued_generation)
                scope = supervisor.launcher.open_scope(identity)
                if scope.identity != identity or scope.is_populated():
                    raise BackendUnavailable("pre-media scope is mismatched or populated")
                if command.release_status == "ambiguous":
                    if command.process is None or command.release_permit_sha256 is None:
                        raise BackendUnavailable("pre-media release evidence is unavailable")
                    claim = TrackedCommandSupervisor._exact_release_claim(
                        command, scope, command.release_permit_sha256,
                        scope.claim_unreleased(command.process.pid, command.release_permit_sha256),
                    )
                    if not claim.released:
                        raise CommandError("pre-media reset requires the exact released permit")
                    self._assert_pre_media_commands_clear(commands)
                    if scope.is_populated():
                        raise BackendUnavailable("pre-media scope became populated")
                # Broker release checks emptiness again and durably closes the
                # scope. Any missing/ambiguous acknowledgement keeps the blocker.
                scope.close()
                catalog.pre_media_reset_proof(operation.id, daemon_fence)
                durable = catalog.command(command.id)
                if durable != command:
                    raise BackendUnavailable("pre-media reservation changed while closing its scope")
                self._assert_pre_media_commands_clear(commands)
                catalog.acknowledge_command_quiescence(
                    command.id, daemon_fence,
                    CommandExitEvidence(
                        command.id, command.process,
                        "terminated" if command.release_status == "ambiguous" else "launch_aborted",
                        catalog._precise_utc_now(),
                    ),
                )
            self._assert_pre_media_commands_clear(catalog.hardware_commands_for_operation(operation.id))
            catalog.pre_media_reset_proof(operation.id, daemon_fence)
            return catalog.create_command_quiescence_receipt(operation.id, daemon_fence)

    def _recovery_supervisor(
        self,
        catalog: Catalog,
        daemon_fence: DaemonFence,
        fence: RecoveryCommandFence,
        *,
        job_id: object = None,
        cassette_label: object = None,
        cassette_sequence: object = None,
    ) -> TrackedCommandSupervisor:
        event_sink = getattr(
            self._archive, "_event_sink", NullOperationalEventSink()
        )
        return _production_supervisor(
            catalog,
            daemon_fence,
            self._archive._scope_manager,
            self._archive._privilege_boundary,
            event_sink=event_sink,
            operation_context=closed_operational_correlation(
                operation_id=fence.operation_id,
                job_id=job_id,
                cassette_label=cassette_label,
                cassette_sequence=cassette_sequence,
                daemon_generation=fence.owner_generation,
            ),
        )

    @staticmethod
    def _identify_recovery_media(
        media_probe,
        *,
        mounted: bool,
        mount_path: Path,
        cassette_operation: str,
    ) -> MediaIdentityFields:
        if mounted:
            return media_probe.identify_mounted(mount_path)
        if cassette_operation == "format":
            return media_probe.identify_preformat()
        return media_probe.identify_unmounted()

    def inspect(
        self,
        operation: DurableOperation,
        fence: RecoveryCommandFence,
        catalog: Catalog,
    ) -> AggregateRecoveryProbe:
        catalog.assert_command_fence(fence)
        row = catalog.get_operation(operation.operation_id)
        if (
            row is None
            or row["job_id"] is None
            or row["cassette_sequence"] is None
        ):
            raise BackendUnavailable("recovery media coordinates are unavailable")
        if operation.kind == "archive.native":
            native_plan = FrozenNativeCassettePlan.load(
                catalog,
                str(row["job_id"]),
                int(row["cassette_sequence"]),
            )
            cassette = native_plan
            expected = native_plan.expected_media
        else:
            plan = FrozenJobPlan.load(catalog, str(row["job_id"]))
            cassette = plan.cassette_for_recovery(int(row["cassette_sequence"]))
            expected = _expected_media(
                str(row["job_id"]), cassette.sequence, cassette.physical_label
            )
        observed_target = LinuxLtfsBackend.target_binding_from(
            self._archive._settings,
            expected,
            self._archive._device_identities,
        )
        if observed_target != operation.target:
            raise BackendUnavailable("recovery hardware target differs from admission")
        daemon_fence = catalog.current_daemon_fence()
        if (
            daemon_fence is None
            or daemon_fence.generation != fence.owner_generation
        ):
            raise BackendUnavailable("recovery daemon fence is no longer current")
        supervisor = self._recovery_supervisor(
            catalog,
            daemon_fence,
            fence,
            job_id=row["job_id"],
            cassette_label=cassette.physical_label,
            cassette_sequence=cassette.sequence,
        )
        mount_probe = ProcMountInfoProbe()
        mounted = mount_probe.is_mounted(
            self._archive._settings.mount_path,
            filesystem_type="fuse.ltfs",
            source="ltfs",
        )
        if not mounted and mount_probe.has_fuse_mount(
            self._archive._settings.mount_path
        ):
            raise BackendUnavailable("recovery mount identity is unavailable")
        if operation.kind == "archive.native" and operation.phase is None and not mounted:
            commands = catalog.hardware_commands_for_operation(operation.operation_id)
            pending = tuple(command for command in commands if command.state != "quiesced")
            if pending and all(
                command.kind == "identify"
                and command.state == "launch_reserved"
                and command.process is None
                and command.issued_generation < fence.owner_generation
                for command in pending
            ):
                # This only retires a never-launched reservation. Its exact
                # broker-owned scope must be empty and is rechecked on close;
                # it neither signals processes nor releases a tape command.
                # A machine-wide /proc scan is not authority for this scope
                # and is deliberately unavailable in the confined daemon.
                # Keep the mount check above and all subsequent media and
                # command-ledger checks. Explicit pre-media reset retains its
                # separate, stronger host-clear requirement.
                for command in pending:
                    supervisor.reconcile_empty_identify_reservation(command.id, fence)
        command_kind = (
            "identify" if operation.media_binding is None else "probe_media"
        )
        media_probe = BrokeredLtfsInfoMediaIdentityProbe(
            supervisor,
            SimpleNamespace(fence=fence),
            self._archive._settings,
            self._archive._ltfs_info_binary,
            command_kind=command_kind,
        )
        media_loaded = True
        observed_media = None
        fields = None
        try:
            fields = self._identify_recovery_media(
                media_probe,
                mounted=mounted,
                mount_path=self._archive._settings.mount_path,
                cassette_operation=str(getattr(cassette, "operation", "")),
            )
            if not self._native_media_label_exact(
                str(getattr(cassette, "operation", "")),
                str(cassette.physical_label),
                (
                    expected.volume_serial
                    if operation.kind == "archive.native"
                    else str(cassette.tape_serial)
                ),
                fields,
            ):
                raise BackendUnavailable("recovery media label is not exact")
            drive = self._archive._device_identities.resolve(
                self._archive._settings.scsi_device_path
            )
            observed_media = media_identity_sha256(
                MediaIdentity(
                    drive_serial=drive.serial_token,
                    mam_barcode=fields.mam_barcode,
                    mam_volume_serial=fields.mam_volume_serial,
                    ltfs_volume_label=fields.ltfs_volume_label,
                    ltfs_volume_uuid=fields.ltfs_volume_uuid,
                ).canonical_fields()
            )
        except CommandFailed as exc:
            if exc.kind != command_kind or exc.returncode != 3:
                raise
            media_loaded = False
        if fields is not None and operation.media_binding is None:
            assert observed_media is not None
            catalog.bind_recovery_observed_media_identity(fence, observed_media)
        process_probe = LinuxProcessProbe()
        processes = tuple(
            command.process
            for command in catalog.hardware_commands_for_operation(operation.operation_id)
            if command.process is not None
        )
        absent = process_probe.identities_and_groups_absent(processes)
        correlated = tuple(
            process for process, is_absent in zip(processes, absent, strict=True)
            if not is_absent
        )
        return AggregateRecoveryProbe(
            target=observed_target,
            observed_media_identity_sha256=observed_media,
            configured_mount_source_identity_sha256=(
                observed_target.tape_device_identity_sha256
            ),
            configured_mount_fstype="fuse.ltfs",
            mounted=mounted,
            mounted_source_identity_sha256=(
                observed_target.tape_device_identity_sha256 if mounted else None
            ),
            mounted_fstype="fuse.ltfs" if mounted else None,
            media_loaded=media_loaded,
            drive_busy=bool(correlated),
            correlated_processes=correlated,
        )

    @staticmethod
    def _native_media_label_exact(
        operation: str,
        physical_label: str,
        tape_serial: str | None,
        fields: MediaIdentityFields,
    ) -> bool:
        if operation == "append":
            return (
                fields.mam_barcode == physical_label
                and fields.ltfs_volume_label == physical_label
            )
        return (
            operation == "format"
            # Native plans store a logical label, not the manufacturer's MAM
            # serial. The observed physical identity is sealed separately.
            and isinstance(fields.mam_volume_serial, str)
            and 0 < len(fields.mam_volume_serial) <= 32
            and fields.mam_volume_serial == fields.mam_volume_serial.strip()
            and fields.mam_volume_serial.isascii()
            and fields.mam_volume_serial.isprintable()
            and (tape_serial is None or fields.mam_volume_serial == tape_serial)
            and fields.mam_barcode in (None, physical_label)
            and fields.ltfs_volume_label in (None, physical_label)
        )

    def observe_command(
        self, blocker, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        with self._archive._catalog_factory() as catalog:
            daemon_fence = catalog.current_daemon_fence()
            if daemon_fence is None or daemon_fence.generation != fence.owner_generation:
                raise BackendUnavailable("recovery daemon fence is no longer current")
            command = self._recovery_supervisor(
                catalog,
                daemon_fence,
                fence,
                job_id=blocker.job_id,
                cassette_sequence=blocker.cassette_sequence,
            ).reconcile(blocker.id, daemon_fence)
            commands = catalog.hardware_commands_for_operation(blocker.id)
            if not commands or any(item.state != "quiesced" for item in commands):
                raise BackendUnavailable("command reconciliation proof is unavailable")
            return RecoveryEffectReceipt(
                "reconcile_commands", blocker.id, fence.owner_generation, command.id
            )

    def reconcile_commit(self, blocker, fence: RecoveryCommandFence) -> RecoveryEffectReceipt:
        self._archive.reconcile_pending_ltfs_operation(blocker.id, fence)
        with self._archive._catalog_factory() as catalog:
            evidence = catalog.recovery_commit_evidence(blocker.id)
            if evidence is None:
                raise BackendUnavailable("commit reconciliation proof is unavailable")
        return RecoveryEffectReceipt(
            "reconcile_commit", blocker.id, fence.owner_generation, repr(evidence)
        )

    def retry_identification(self, blocker, fence: RecoveryCommandFence) -> RecoveryEffectReceipt:
        with self._archive._catalog_factory() as catalog:
            target = catalog.hardware_target_binding(blocker.id)
            if target is None:
                raise BackendUnavailable("recovery target is unavailable")
            source = CatalogRecoveryStateSource(
                catalog,
                expected_mount_source_identity_sha256=(
                    target.tape_device_identity_sha256
                ),
                expected_mount_fstype="fuse.ltfs",
            )
            self.inspect(source.operation(blocker.id), fence, catalog)
            binding = catalog.observed_media_binding(blocker.id)
            if binding is None:
                raise BackendUnavailable("identification proof is unavailable")
            return RecoveryEffectReceipt(
                "retry_identification", blocker.id, fence.owner_generation, binding
            )

    def retry_current_cassette(self, blocker, fence: RecoveryCommandFence):
        if self._native_archive is None:
            raise BackendUnavailable("native frozen recovery is unavailable")
        on_admitted = (
            None
            if self._replacement_admission_factory is None
            else self._replacement_admission_factory()
        )
        replacement = self._operations.retry_native_recovery(
            blocker,
            fence,
            self._native_archive.run_frozen_recovery,
            on_admitted=on_admitted,
        )
        return RecoveryEffectReceipt(
            "retry_current_cassette",
            blocker.id,
            fence.owner_generation,
            replacement.id,
        )

    def retry_unload(self, blocker, fence: RecoveryCommandFence) -> RecoveryEffectReceipt:
        with self._archive._catalog_factory() as catalog:
            try:
                unload_evidence = catalog.attest_imported_postcommit_unload(
                    fence, require_durable_no_media=True
                )
            except ValidationError:
                backend = self._recovery_backend(blocker.id, fence, catalog)
                backend.unload()
                if not _physical_eject_proven(backend):
                    raise BackendUnavailable(
                        "unload recovery did not prove that media is absent"
                    )
                unload_evidence = catalog.attest_imported_postcommit_unload(
                    fence, no_media_proven=True
                )
        self.safe_release(blocker, fence)
        with self._archive._catalog_factory() as catalog:
            resolved = catalog.get_operation(blocker.id)
            if resolved is None or resolved["state"] != "cancelled":
                raise BackendUnavailable("unload recovery was not durably resolved")
        return RecoveryEffectReceipt(
            "retry_unload", blocker.id, fence.owner_generation, unload_evidence
        )

    def prove_incomplete(
        self, action, blocker, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt | None:
        """Read only the durable postcondition for the recorded prior action."""
        with self._archive._catalog_factory() as catalog:
            if action.value == "reconcile_commands":
                commands = catalog.hardware_commands_for_operation(blocker.id)
                if commands and all(item.state == "quiesced" for item in commands):
                    proof = ",".join(item.id for item in commands)
                else:
                    return None
            elif action.value == "reconcile_commit":
                evidence = catalog.recovery_commit_evidence(blocker.id)
                if evidence is None:
                    return None
                proof = repr(evidence)
            elif action.value == "retry_identification":
                proof = catalog.observed_media_binding(blocker.id)
                if proof is None:
                    return None
            elif action.value == "retry_current_cassette":
                replay_key = f"recovery-native-{blocker.id}-{fence.owner_generation}"
                replacement = catalog.find_operation_by_key(replay_key)
                if (
                    replacement is None
                    or replacement["kind"] != "archive.native"
                    or replacement["job_id"] != blocker.job_id
                    or replacement["cassette_sequence"] != blocker.cassette_sequence
                    or replacement["principal"] != blocker.principal
                ):
                    return None
                proof = str(replacement["id"])
            elif action.value == "retry_unload":
                operation = catalog.get_operation(blocker.id)
                resolution = catalog.recovery_resolution_evidence(blocker.id)
                if operation is None or operation["state"] != "cancelled" or resolution is None:
                    return None
                proof = str(resolution["physical_receipt_id"])
            else:
                return None
        return RecoveryEffectReceipt(
            action.value, blocker.id, fence.owner_generation, proof
        )

    def safe_release(self, blocker, fence: RecoveryCommandFence) -> RecoveryEffectReceipt:
        with self._archive._catalog_factory() as catalog:
            target = catalog.hardware_target_binding(blocker.id)
            if target is None:
                raise BackendUnavailable("recovery target is unavailable")
            source = CatalogRecoveryStateSource(
                catalog,
                expected_mount_source_identity_sha256=(
                    target.tape_device_identity_sha256
                ),
                expected_mount_fstype="fuse.ltfs",
            )
            operation = source.operation(blocker.id)
            probe = self.inspect(operation, fence, catalog)
            if (
                probe.mounted
                or probe.media_loaded
                or probe.drive_busy
                or probe.correlated_processes
            ):
                raise BackendUnavailable("recovery target is not safely released")
            daemon_fence = catalog.current_daemon_fence()
            if daemon_fence is None or daemon_fence.generation != fence.owner_generation:
                raise BackendUnavailable("recovery daemon fence is no longer current")
            supervisor = self._recovery_supervisor(
                catalog,
                daemon_fence,
                fence,
                job_id=blocker.job_id,
                cassette_sequence=blocker.cassette_sequence,
            )
            command = supervisor.reconcile(blocker.id, daemon_fence)
            physical = catalog.create_physical_reconciliation_receipt(
                blocker.id,
                daemon_fence,
                command.id,
                VerifiedPhysicalQuiescence(
                    target=target,
                    observed_media_identity_sha256=(
                        operation.observed_media_identity_sha256
                    ),
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
        resolved = self._operations.resolve_recovery(
            blocker.id,
            SafeRecoveryResolution(
                "automatic_recovery_safe_release", command.id, physical.id
            ),
        )
        if resolved.state != "cancelled":
            raise BackendUnavailable("safe release was not durably resolved")
        return RecoveryEffectReceipt(
            "safe_release", blocker.id, fence.owner_generation, physical.id
        )

    def _recovery_backend(
        self,
        operation_id: str,
        fence: RecoveryCommandFence,
        catalog: Catalog,
    ) -> LinuxLtfsBackend:
        catalog.assert_command_fence(fence)
        row = catalog.get_operation(operation_id)
        if (
            row is None
            or row["kind"] != "archive.resume"
            or row["job_id"] is None
            or row["cassette_sequence"] is None
        ):
            raise BackendUnavailable("unload recovery operation is unavailable")
        cassette = FrozenJobPlan.load(catalog, str(row["job_id"])).cassette_for_recovery(
            int(row["cassette_sequence"])
        )
        expected = _expected_media(
            str(row["job_id"]), cassette.sequence, cassette.physical_label
        )
        daemon_fence = catalog.current_daemon_fence()
        if daemon_fence is None or daemon_fence.generation != fence.owner_generation:
            raise BackendUnavailable("recovery daemon fence is no longer current")
        supervisor = self._recovery_supervisor(
            catalog,
            daemon_fence,
            fence,
            job_id=row["job_id"],
            cassette_label=cassette.physical_label,
            cassette_sequence=cassette.sequence,
        )
        media_probe = BrokeredLtfsInfoMediaIdentityProbe(
            supervisor,
            SimpleNamespace(fence=fence),
            self._archive._settings,
            self._archive._ltfs_info_binary,
        )
        return LinuxLtfsBackend(
            settings=self._archive._settings,
            expected=expected,
            fence=fence,
            catalog=catalog,
            supervisor=supervisor,
            ltfs_sessions=self._archive._ltfs_sessions,
            device_identities=self._archive._device_identities,
            media_identity_probe=media_probe,
        )


def _expected_media(job_id: str, sequence: int, label: str) -> ExpectedMedia:
    return ExpectedMedia("archive.resume", job_id, sequence, label, None, None)


def _production_supervisor(
    catalog: Catalog,
    daemon_fence: DaemonFence,
    scope_manager: BrokeredCgroupExecutionScopeManager,
    privilege_boundary: ReadOnlyCgroupPrivilegeBoundary,
    *,
    event_sink: OperationalEventSink | None = None,
    operation_context: OperationalCorrelation | None = None,
) -> TrackedCommandSupervisor:
    process_probe = LinuxProcessProbe()
    return TrackedCommandSupervisor(
        catalog=catalog,
        daemon_fence=daemon_fence,
        launcher=ForkExecCommandLauncher(scope_manager, privilege_boundary),
        process_probe=process_probe,
        process_terminator=PosixProcessTerminator(process_probe),
        event_sink=event_sink,
        operation_context=operation_context,
    )


class BrokeredLtfsInfoMediaIdentityProbe:
    """Read media identity only through the admitted brokered command fence."""

    def __init__(
        self,
        supervisor: TrackedCommandSupervisor,
        context: OperationContext,
        settings: LinuxSettings,
        binary: Path,
        *,
        command_kind: str = "probe_media",
    ) -> None:
        self._supervisor, self._context, self._settings = supervisor, context, settings
        try:
            configured_binary = Path(binary)
        except (OSError, TypeError):
            configured_binary = None
        if configured_binary is None:
            raise MediaProbeUnavailable()
        self._binary = configured_binary
        if command_kind not in {"identify", "probe_media"}:
            raise MediaProbeUnavailable()
        self._command_kind = command_kind
        pinned = self._open_validated_binary()
        if pinned is None:
            raise MediaProbeUnavailable()
        descriptor, status = pinned
        closed = self._close_descriptor(descriptor)
        if not closed:
            raise MediaProbeUnavailable()
        self._binary_identity = (status.st_dev, status.st_ino)

    def preflight(self) -> None:
        return None

    def identify_unmounted(self) -> MediaIdentityFields:
        return self._query("unmounted")

    def identify_preformat(self) -> MediaIdentityFields:
        return self._query("pre-format")

    def identify_mounted(self, path: Path) -> MediaIdentityFields:
        if path != self._settings.mount_path:
            raise BackendUnavailable("ltfs-info target is invalid")
        return self._query("mounted")

    def _query(self, mode: str) -> MediaIdentityFields:
        pinned = self._open_validated_binary()
        if pinned is None:
            raise MediaProbeUnavailable()
        descriptor, status = pinned
        if (status.st_dev, status.st_ino) != self._binary_identity:
            self._close_descriptor(descriptor)
            raise MediaProbeUnavailable()
        result = None
        pin_error = False
        command_error: CommandError | None = None
        try:
            result = self._supervisor.run(
                self._context.fence,
                self._command_kind,
                (
                    f"/proc/self/fd/{descriptor}",
                    "--json",
                    "--mode",
                    mode,
                ),
                30.0,
                pass_fds=(descriptor,),
            )
        except (OSError, TypeError):
            pin_error = True
        except CommandError as exc:
            command_error = exc
        finally:
            closed = self._close_descriptor(descriptor)
        if not closed or pin_error:
            raise MediaProbeUnavailable()
        if command_error is not None:
            raise command_error
        assert result is not None
        try:
            if len(result.stdout.encode("utf-8")) > 4096:
                raise ValueError
            payload = json.loads(result.stdout)
            required = {
                "schema",
                "media_state",
                "tape_by_id",
                "scsi_by_id",
                "drive_serial",
                "mam_barcode",
                "mam_volume_serial",
                "ltfs_volume_label",
                "ltfs_volume_uuid",
                "index_generation",
            }
            if (
                type(payload) is not dict
                or frozenset(payload) != required
                or payload["schema"] != 2
                or payload["tape_by_id"] != str(self._settings.tape_device_path)
                or payload["scsi_by_id"] != str(self._settings.scsi_device_path)
                or type(payload["drive_serial"]) is not str
                or not payload["drive_serial"]
            ):
                raise ValueError
            identity_fields = {
                "mam_barcode",
                "mam_volume_serial",
                "ltfs_volume_label",
                "ltfs_volume_uuid",
                "index_generation",
            }
            fields = {key: payload[key] for key in identity_fields}
            generation = fields["index_generation"]
            if generation is not None and (
                type(generation) is not int or not 0 < generation < 1 << 64
            ):
                raise ValueError
            if payload["media_state"] == "ltfs":
                if any(fields[key] is None for key in identity_fields):
                    raise ValueError
            elif payload["media_state"] == "unidentified":
                if mode == "mounted" or any(
                    fields[key] is not None
                    for key in (
                        "ltfs_volume_label",
                        "ltfs_volume_uuid",
                        "index_generation",
                    )
                ):
                    raise ValueError
            else:
                raise ValueError
            return MediaIdentityFields(**fields)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BackendUnavailable("ltfs-info identity is unavailable") from None

    def _open_validated_binary(self) -> tuple[int, os.stat_result] | None:
        try:
            descriptor = os.open(
                self._binary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
        except (OSError, TypeError):
            return None
        try:
            status = os.fstat(descriptor)
        except (OSError, TypeError):
            self._close_descriptor(descriptor)
            return None
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or stat.S_IMODE(status.st_mode) != 0o755
            or type(status.st_dev) is not int
            or type(status.st_ino) is not int
        ):
            self._close_descriptor(descriptor)
            return None
        return descriptor, status

    @staticmethod
    def _close_descriptor(descriptor: int) -> bool:
        try:
            os.close(descriptor)
        except (OSError, TypeError):
            return False
        return True


def _trusted_ltfs_info_binary(value: Path) -> Path:
    path = Path(value)
    try:
        status = path.stat(follow_symlinks=False)
        if (
            not path.is_absolute()
            or path.is_symlink()
            or not stat.S_ISREG(status.st_mode)
            or status.st_uid != 0
            or stat.S_IMODE(status.st_mode) != 0o755
        ):
            raise ValueError
    except (OSError, ValueError):
        raise ValidationError("ltfs-info binary is unavailable") from None
    return path


def load_broker_capability(path: os.PathLike[str] | str) -> BrokeredCgroupScopeToken:
    """Read exactly one daemon credential without following attacker paths."""

    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) & 0o077
        ):
            raise ValidationError("command broker capability is unavailable")
        value = os.read(descriptor, 33)
        if len(value) != 32 or os.read(descriptor, 1):
            raise ValidationError("command broker capability is unavailable")
        return BrokeredCgroupScopeToken(value)
    except (OSError, ValueError) as exc:
        raise ValidationError("command broker capability is unavailable") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
