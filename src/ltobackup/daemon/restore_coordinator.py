"""Hardware-free sequencing for durable read-only restore cassettes."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from threading import Event, Lock, RLock, Thread, current_thread
from typing import Any, Protocol

from ..catalog import Catalog
from ..operational_log import (
    NullOperationalEventSink,
    closed_operational_correlation,
)
from ..tape.command_supervisor import CommandFailed, LinuxProcessProbe
from ..tape.linux_ltfs import LinuxLtfsBackend, ProcMountInfoProbe
from ..tape.models import ExpectedMedia, MediaIdentity, expected_media_from_catalog
from .archive_runtime import BrokeredLtfsInfoMediaIdentityProbe, _production_supervisor
from .models import (
    DaemonFence,
    HardwareTargetBinding,
    OperationRecord,
    RecoveryCommandFence,
    RecoveryEffectReceipt,
    SafeRecoveryResolution,
    VerifiedPhysicalQuiescence,
    media_identity_sha256,
)
from .operations import OperationContext, OperationManager
from .recovery import (
    AggregateRecoveryProbe,
    CatalogRecoveryStateSource,
    DurableOperation,
    RecoveryAction,
)
from .restore_destination import RestoreDestinationVerifier
from .restore_runner import RestoreCassetteRunner


class _Runner(Protocol):
    def run(
        self,
        run_id: str,
        context: OperationContext,
        stop_requested: Callable[[], bool],
    ) -> object: ...


class RestoreSequenceCoordinator:
    """Admit exactly one durable restore candidate at a time."""

    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        *,
        operations: OperationManager,
        runner: RestoreCassetteRunner | _Runner,
        hardware_target: Callable[
            [Mapping[str, Any], Mapping[str, Any]], HardwareTargetBinding
        ],
        prepare_replacement_admission: Callable[
            [str, int], Callable[[OperationRecord], None]
        ]
        | None = None,
        poll_interval_seconds: float = 1.0,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if poll_interval_seconds <= 0:
            raise ValueError("restore coordinator poll interval must be positive")
        self._catalog_factory = catalog_factory
        self._operations = operations
        self._runner = runner
        self._hardware_target = hardware_target
        self._prepare_replacement_admission = prepare_replacement_admission
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._on_error = on_error
        self._wake_event = Event()
        self._stopped = Event()
        self._reconciling = Lock()
        self._lifecycle_lock = RLock()
        self._thread: Thread | None = None

    def start(self) -> None:
        """Start processing durable restore candidates."""

        with self._lifecycle_lock:
            if self._thread is not None:
                return
            if self._stopped.is_set():
                raise RuntimeError("restore coordinator cannot restart after stop")
            thread = Thread(
                target=self._run,
                name="ltobackup-restore-sequence-coordinator",
                daemon=True,
            )
            self._thread = thread
            thread.start()
        self.wake()

    def wake(self) -> None:
        """Signal that a restore candidate or state change is available."""

        if not self._stopped.is_set():
            self._wake_event.set()

    def request_cancel(
        self, run_id: str, actor: str, idempotency_key: str | None = None
    ) -> dict[str, object]:
        """Request file-boundary cancellation and return the durable run."""

        with self._catalog_factory() as catalog:
            run = catalog.request_restore_run_cancel(
                run_id, actor=actor, idempotency_key=idempotency_key
            )
        self.wake()
        return run

    def request_pause(
        self, run_id: str, actor: str, idempotency_key: str | None = None
    ) -> dict[str, object]:
        """Request a file-boundary pause and return the durable run."""

        with self._catalog_factory() as catalog:
            run = catalog.request_restore_run_pause(
                run_id, actor=actor, idempotency_key=idempotency_key
            )
        self.wake()
        return run

    def resume(
        self, run_id: str, actor: str, idempotency_key: str | None = None
    ) -> dict[str, object]:
        """Resume one exact paused checkpoint without weakening recovery."""

        with self._catalog_factory() as catalog:
            run = catalog.resume_restore_run(
                run_id, actor=actor, idempotency_key=idempotency_key
            )
        self.wake()
        return run

    def stop(self, timeout_seconds: float) -> None:
        """Stop and join the coordinator without abandoning active evidence."""

        if timeout_seconds < 0:
            raise ValueError("restore coordinator stop timeout cannot be negative")
        self._stopped.set()
        self._wake_event.set()
        with self._lifecycle_lock:
            thread = self._thread
        if thread is current_thread():
            raise RuntimeError("restore coordinator cannot join its own worker")
        if thread is not None:
            thread.join(timeout=timeout_seconds)
            if thread.is_alive():
                raise RuntimeError("restore coordinator worker did not stop")
            with self._lifecycle_lock:
                if self._thread is thread:
                    self._thread = None

    def shutdown(self) -> None:
        """Service lifecycle adapter using a bounded coordinator-owned timeout."""

        self.stop(max(1.0, self._poll_interval_seconds * 2.0))

    def reconcile_once(self) -> OperationRecord | None:
        if self._stopped.is_set() or not self._reconciling.acquire(blocking=False):
            return None
        try:
            with self._catalog_factory() as catalog:
                row = catalog.next_restore_sequence_candidate()
                if row is None:
                    return None
                run = catalog.restore_run(str(row["run_id"]))
            sequence = int(row["cassette_sequence"])
            attempt = int(row["attempt_number"])
            continuation_kind = str(row["continuation_kind"])
            cassette = next(
                item for item in run["cassettes"] if item["sequence"] == sequence
            )
            run_id = str(run["id"])
            key = hashlib.sha256(
                f"restore.cassette\0{run_id}\0{sequence}\0{attempt}".encode()
            ).hexdigest()
            def stop_requested() -> bool:
                with self._catalog_factory() as catalog:
                    if not (
                        catalog.restore_run_cancel_requested(run_id)
                        or catalog.restore_run_pause_requested(run_id)
                    ):
                        return False
                    current = catalog.restore_run(run_id)
                cassette_items = tuple(
                    item
                    for item in current["items"]
                    if item["cassette_sequence"] == sequence
                )
                current_cassette = next(
                    item
                    for item in current["cassettes"]
                    if item["sequence"] == sequence
                )
                if current_cassette["state"] not in {"waiting_media", "restoring"}:
                    return False
                return not any(
                    item["state"] == "restoring" for item in cassette_items
                )

            def execute(context: OperationContext) -> None:
                self._runner.run(run_id, context, stop_requested)

            on_admitted = None
            if (
                continuation_kind == "recovery_retry"
                and self._prepare_replacement_admission is not None
            ):
                # The service snapshots telemetry while no replacement ID is
                # visible, then its callback publishes the admitted ID.
                on_admitted = self._prepare_replacement_admission(run_id, sequence)

            return self._operations.start(
                "restore.cassette",
                key,
                "restore-coordinator",
                execute,
                job_id=run_id,
                cassette_sequence=sequence,
                hardware_target=self._hardware_target(run, cassette),
                on_admitted=on_admitted,
                on_complete=self._operation_complete,
                restore_sequence_candidate=row,
            )
        finally:
            self._reconciling.release()

    def _operation_complete(self, record: OperationRecord) -> None:
        # Completion callbacks are only wakeups.  They have no release receipt
        # and therefore no authority to terminalize pause or cancellation.
        self.wake()

    def _run(self) -> None:
        while not self._stopped.is_set():
            self._wake_event.wait(self._poll_interval_seconds)
            self._wake_event.clear()
            if self._stopped.is_set():
                return
            try:
                self.reconcile_once()
            except Exception as exc:
                if self._on_error is not None:
                    self._on_error(exc)


__all__ = ["RestoreSequenceCoordinator"]


class SequenceCoordinatorGroup:
    """Expose one service lifecycle for independent native/restore sequencers."""

    def __init__(self, *coordinators: object) -> None:
        self._coordinators = coordinators

    def start(self) -> None:
        for coordinator in self._coordinators:
            coordinator.start()

    def wake(self) -> None:
        for coordinator in self._coordinators:
            coordinator.wake()

    def shutdown(self) -> None:
        for coordinator in reversed(self._coordinators):
            coordinator.shutdown()


class ProductionRestoreRuntime:
    """Construct only read-only restore backends after durable admission."""

    def __init__(
        self,
        archive_runtime: object,
        operations: OperationManager | None = None,
    ) -> None:
        self._archive = archive_runtime
        self._operations = operations
        self._catalog_factory = archive_runtime._catalog_factory
        self._destination_verifier = RestoreDestinationVerifier()

    def _recovery_supervisor(
        self,
        catalog: Catalog,
        daemon_fence: DaemonFence,
        fence: RecoveryCommandFence,
        *,
        job_id: object = None,
        cassette_label: object = None,
        cassette_sequence: object = None,
    ):
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
    def _expected(run: Mapping[str, Any], cassette: Mapping[str, Any]) -> ExpectedMedia:
        return expected_media_from_catalog(
            "restore.cassette",
            str(run["id"]),
            int(cassette["sequence"]),
            str(cassette["physical_label"]),
            None
            if cassette["volume_serial"] is None
            else str(cassette["volume_serial"]),
            None
            if cassette["volume_uuid"] is None
            else str(cassette["volume_uuid"]),
        )

    def hardware_target(
        self, run: Mapping[str, Any], cassette: Mapping[str, Any]
    ) -> HardwareTargetBinding:
        return LinuxLtfsBackend.target_binding_from(
            self._archive._settings,
            self._expected(run, cassette),
            self._archive._device_identities,
        )

    def run(
        self,
        run_id: str,
        context: OperationContext,
        stop_requested: Callable[[], bool],
    ) -> object:
        with self._catalog_factory() as catalog:
            run = catalog.restore_run(run_id)
            cassette = next(
                item
                for item in run["cassettes"]
                if item["sequence"] == context.record.cassette_sequence
            )
            target = self.hardware_target(run, cassette)
            if catalog.hardware_target_binding(context.record.id) != target:
                raise RuntimeError("restore hardware target differs from admission")
            daemon = catalog.current_daemon_fence()
            if daemon is None or daemon.generation != context.fence.owner_generation:
                raise RuntimeError("restore daemon fence is no longer current")
            event_sink = getattr(
                self._archive, "_event_sink", NullOperationalEventSink()
            )
            supervisor = _production_supervisor(
                catalog,
                daemon,
                self._archive._scope_manager,
                self._archive._privilege_boundary,
                event_sink=event_sink,
                operation_context=closed_operational_correlation(
                    operation_id=context.record.id,
                    job_id=run_id,
                    cassette_label=str(cassette["physical_label"]),
                    cassette_sequence=int(cassette["sequence"]),
                    daemon_generation=context.fence.owner_generation,
                ),
            )
            media_probe = BrokeredLtfsInfoMediaIdentityProbe(
                supervisor,
                context,
                self._archive._settings,
                self._archive._ltfs_info_binary,
            )

            def backend_factory(bound_expected: ExpectedMedia, fence: object):
                return LinuxLtfsBackend(
                    settings=self._archive._settings,
                    expected=bound_expected,
                    fence=fence,
                    catalog=catalog,
                    supervisor=supervisor,
                    ltfs_sessions=self._archive._ltfs_sessions,
                    device_identities=self._archive._device_identities,
                    media_identity_probe=media_probe,
                )

            runner = RestoreCassetteRunner(
                catalog_factory=self._catalog_factory,
                backend_factory=backend_factory,
                destination_verifier=self._destination_verifier,
                event_sink=event_sink,
            )
            return runner.run(run_id, context, stop_requested)

    def inspect(
        self,
        operation: DurableOperation,
        fence: RecoveryCommandFence,
        catalog: Catalog,
    ) -> AggregateRecoveryProbe:
        if operation.kind != "restore.cassette":
            raise RuntimeError("restore recovery operation is mismatched")
        catalog.assert_command_fence(fence)
        row = catalog.get_operation(operation.operation_id)
        if row is None or row["job_id"] is None:
            raise RuntimeError("restore recovery coordinates are unavailable")
        run = catalog.restore_run(str(row["job_id"]))
        cassette = next(
            item
            for item in run["cassettes"]
            if item["sequence"] == operation.cassette_sequence
        )
        target = self.hardware_target(run, cassette)
        if target != operation.target:
            raise RuntimeError("restore recovery target differs from admission")
        mount_probe = ProcMountInfoProbe()
        mounted = mount_probe.is_mounted(
            self._archive._settings.mount_path,
            filesystem_type="fuse.ltfs",
            source="ltfs",
        )
        if not mounted and mount_probe.has_fuse_mount(
            self._archive._settings.mount_path
        ):
            raise RuntimeError("restore recovery mount identity is ambiguous")
        daemon = catalog.current_daemon_fence()
        if daemon is None or daemon.generation != fence.owner_generation:
            raise RuntimeError("restore recovery daemon fence changed")
        supervisor = self._recovery_supervisor(
            catalog,
            daemon,
            fence,
            job_id=row["job_id"],
            cassette_label=cassette["physical_label"],
            cassette_sequence=cassette["sequence"],
        )
        probe = BrokeredLtfsInfoMediaIdentityProbe(
            supervisor,
            type("RecoveryContext", (), {"fence": fence})(),
            self._archive._settings,
            self._archive._ltfs_info_binary,
            command_kind="probe_media",
        )
        media_loaded = True
        observed = None
        try:
            fields = (
                probe.identify_mounted(self._archive._settings.mount_path)
                if mounted
                else probe.identify_unmounted()
            )
            drive = self._archive._device_identities.resolve(
                self._archive._settings.scsi_device_path
            )
            observed = media_identity_sha256(
                MediaIdentity(
                    drive.serial_token,
                    fields.mam_barcode,
                    fields.mam_volume_serial,
                    fields.ltfs_volume_label,
                    fields.ltfs_volume_uuid,
                ).canonical_fields()
            )
        except CommandFailed as exc:
            if exc.returncode != 3:
                raise
            media_loaded = False
        process_probe = LinuxProcessProbe()
        processes = tuple(
            command.process
            for command in catalog.hardware_commands_for_operation(
                operation.operation_id
            )
            if command.process is not None
        )
        absent = process_probe.identities_and_groups_absent(processes)
        correlated = tuple(
            process for process, is_absent in zip(processes, absent, strict=True)
            if not is_absent
        )
        return AggregateRecoveryProbe(
            target=target,
            observed_media_identity_sha256=observed,
            configured_mount_source_identity_sha256=target.tape_device_identity_sha256,
            configured_mount_fstype="fuse.ltfs",
            mounted=mounted,
            mounted_source_identity_sha256=(
                target.tape_device_identity_sha256 if mounted else None
            ),
            mounted_fstype="fuse.ltfs" if mounted else None,
            media_loaded=media_loaded,
            drive_busy=bool(correlated),
            correlated_processes=correlated,
        )

    def prepare_restore_retry(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        return self._resolve_restore_boundary(
            blocker, fence, "retry", RecoveryAction.PREPARE_RESTORE_RETRY
        )

    def reconcile_restore_commit(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        return self._resolve_restore_boundary(
            blocker, fence, "commit", RecoveryAction.RECONCILE_RESTORE_COMMIT
        )

    def finalize_restore_control(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        return self._resolve_restore_boundary(
            blocker, fence, "control", RecoveryAction.FINALIZE_RESTORE_CONTROL
        )

    def _resolve_restore_boundary(
        self,
        blocker: OperationRecord,
        fence: RecoveryCommandFence,
        action: str,
        recovery_action: RecoveryAction,
    ) -> RecoveryEffectReceipt:
        if self._operations is None:
            raise RuntimeError("restore recovery operations are unavailable")
        with self._catalog_factory() as catalog:
            target = catalog.hardware_target_binding(blocker.id)
            row = catalog.get_operation(blocker.id)
            if target is None or row is None:
                raise RuntimeError("restore recovery evidence is unavailable")
            operation = CatalogRecoveryStateSource(
                catalog,
                expected_mount_source_identity_sha256=(
                    target.tape_device_identity_sha256
                ),
                expected_mount_fstype="fuse.ltfs",
            ).operation(blocker.id)
            probe = self.inspect(operation, fence, catalog)
            if (
                probe.mounted
                or probe.media_loaded
                or probe.drive_busy
                or probe.correlated_processes
            ):
                raise RuntimeError("restore recovery is not safely ejected")
            daemon = catalog.current_daemon_fence()
            assert daemon is not None
            plan_fingerprint = str(
                catalog.restore_run(str(blocker.job_id))["plan_fingerprint_sha256"]
            )
            if (
                action in {"retry", "control"}
                and catalog.restore_release_boundary(
                    blocker.id,
                    str(blocker.job_id),
                    int(blocker.cassette_sequence),
                    plan_fingerprint,
                )
                == "missing"
            ):
                catalog.record_restore_pre_mount_recovery_receipt(
                    daemon,
                    blocker.id,
                    str(blocker.job_id),
                    int(blocker.cassette_sequence),
                    plan_fingerprint,
                )
            command = self._recovery_supervisor(
                catalog,
                daemon,
                fence,
                job_id=blocker.job_id,
                cassette_sequence=blocker.cassette_sequence,
            ).reconcile(blocker.id, daemon)
            physical = catalog.create_physical_reconciliation_receipt(
                blocker.id,
                daemon,
                command.id,
                VerifiedPhysicalQuiescence(
                    target, operation.observed_media_identity_sha256,
                    False, False, False, (),
                ),
            )
            run = catalog.restore_run(str(blocker.job_id))
            catalog.resolve_restore_recovery_boundary(
                blocker.id,
                str(blocker.job_id),
                int(blocker.cassette_sequence),
                str(run["plan_fingerprint_sha256"]),
                self._operations.daemon_fence,
                SafeRecoveryResolution(
                    "restore_restart_safe", command.id, physical.id
                ),
                action=action,
            )
        return RecoveryEffectReceipt(
            recovery_action.value,
            blocker.id,
            fence.owner_generation,
            physical.id,
        )


__all__ = [
    "ProductionRestoreRuntime",
    "RestoreSequenceCoordinator",
    "SequenceCoordinatorGroup",
]
