from __future__ import annotations

import hashlib
import sqlite3
import uuid
from collections.abc import Callable, Mapping
from concurrent.futures import Executor, Future, wait
from contextlib import contextmanager
from dataclasses import dataclass, field
from queue import Empty, Queue
from threading import RLock, Thread
from typing import Any

from ..catalog import Catalog
from ..util import utc_now
from .models import (
    CriticalRecoveryObservation,
    DaemonFence,
    HardwareTargetBinding,
    OperationAdmission,
    OperationFence,
    OperationRecord,
    RecoveryCommandFence,
    SafeRecoveryResolution,
    StaleOperationFence,
)
from .timeouts import validate_shutdown_timeout

CatalogFactory = Callable[[], Catalog]
OperationCallback = Callable[["OperationContext"], None]


class InvalidOperationAdmissionSnapshot(RuntimeError):
    """The immutable settings captured at operation admission are unusable."""


@dataclass(frozen=True)
class _DaemonWorkItem:
    future: Future[Any]
    function: Callable[..., Any]
    args: tuple[Any, ...]
    kwargs: dict[str, Any]


class _DaemonWorkerExecutor(Executor):
    """Single daemon worker which never participates in CPython's exit join."""

    _STOP = object()

    def __init__(self) -> None:
        self._queue: Queue[_DaemonWorkItem | object] = Queue()
        self._lock = RLock()
        self._shutdown = False
        self._thread = Thread(
            target=self._work,
            name="ltobackup-operation_0",
            daemon=True,
        )
        self._thread.start()

    def submit(self, fn, /, *args, **kwargs):
        with self._lock:
            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
            future: Future[Any] = Future()
            self._queue.put(_DaemonWorkItem(future, fn, args, kwargs))
            return future

    def shutdown(self, wait: bool = True, *, cancel_futures: bool = False) -> None:
        with self._lock:
            if not self._shutdown:
                self._shutdown = True
                if cancel_futures:
                    self._cancel_queued()
                self._queue.put(self._STOP)
        if wait:
            self._thread.join()

    def _cancel_queued(self) -> None:
        while True:
            try:
                item = self._queue.get_nowait()
            except Empty:
                return
            if isinstance(item, _DaemonWorkItem):
                item.future.cancel()

    def _work(self) -> None:
        while True:
            item = self._queue.get()
            if item is self._STOP:
                return
            assert isinstance(item, _DaemonWorkItem)
            if not item.future.set_running_or_notify_cancel():
                continue
            try:
                result = item.function(*item.args, **item.kwargs)
            except BaseException as exc:  # noqa: BLE001 - Future preserves BaseException.
                item.future.set_exception(exc)
            else:
                item.future.set_result(result)


def _operation_record(row: sqlite3.Row) -> OperationRecord:
    return OperationRecord(
        id=row["id"],
        kind=row["kind"],
        state=row["state"],
        phase=row["phase"],
        idempotency_key=row["idempotency_key"],
        principal=row["principal"],
        job_id=row["job_id"],
        cassette_sequence=row["cassette_sequence"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        error_class=row["error_class"],
        error_code=row["error_code"],
        error_message=row["error_message"],
    )


@dataclass(frozen=True)
class OperationContext:
    record: OperationRecord
    fence: OperationFence
    _catalog_factory: CatalogFactory = field(repr=False, compare=False)
    _diagnostics_progress: Callable[[int], None] | None = field(
        default=None, repr=False, compare=False
    )

    def assert_current(self) -> None:
        with self._catalog_factory() as catalog:
            catalog.assert_operation_fence(self.fence)

    def admitted_copy_buffer_bytes(self) -> int:
        """Return the immutable buffer value committed with this admission."""

        with self._catalog_factory() as catalog:
            row = catalog.get_operation(self.record.id)
        if row is None:
            raise InvalidOperationAdmissionSnapshot(
                "admitted operation is unavailable"
            )
        value = row["copy_buffer_bytes"]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1024**2 <= value <= 64 * 1024**2
        ):
            raise InvalidOperationAdmissionSnapshot(
                "admitted copy buffer snapshot is unavailable"
            )
        return value

    def transition_phase(self, phase: str) -> None:
        with self._catalog_factory() as catalog:
            catalog.set_operation_phase(self.fence, phase)

    def record_phase_sample(
        self,
        phase: str,
        started_at: str,
        duration_seconds: float,
    ) -> None:
        with self._catalog_factory() as catalog:
            catalog.record_phase_sample(
                self.fence,
                phase,
                started_at,
                duration_seconds,
            )

    def record_progress(self, byte_count: int) -> None:
        """Forward a verified copy delta to the admitted diagnostics sink.

        Progress is observational only: it never authorizes or alters an
        operation fence.  Callers supply the sink when constructing the
        operation context; older operation paths deliberately retain no-op
        behavior until they opt in.
        """

        if isinstance(byte_count, bool) or not isinstance(byte_count, int) or byte_count < 0:
            raise ValueError("progress byte count must be a non-negative integer")
        if self._diagnostics_progress is not None:
            self._diagnostics_progress(byte_count)


def new_operation(
    kind: str,
    idempotency_key: str,
    principal: str,
    job_id: str | None = None,
    cassette_sequence: int | None = None,
) -> OperationRecord:
    return OperationRecord(
        id=f"operation-{uuid.uuid4().hex}",
        kind=kind,
        state="running",
        phase=None,
        idempotency_key=idempotency_key,
        principal=principal,
        job_id=job_id,
        cassette_sequence=cassette_sequence,
        started_at=utc_now(),
        finished_at=None,
    )


class OperationManager:
    def __init__(
        self,
        catalog_factory: CatalogFactory,
        daemon_fence: DaemonFence,
        *,
        executor: Executor | None = None,
        accepting: bool = True,
    ) -> None:
        self._catalog_factory = catalog_factory
        self._daemon_fence = daemon_fence
        self._owns_executor = executor is None
        self._executor = executor or _DaemonWorkerExecutor()
        self._accepting = bool(accepting)
        self._lock = RLock()
        self._futures: dict[str, Future[None]] = {}

    @property
    def daemon_fence(self) -> DaemonFence:
        return self._daemon_fence

    def start(
        self,
        kind: str,
        idempotency_key: str,
        principal: str,
        callback: OperationCallback,
        *,
        job_id: str | None = None,
        cassette_sequence: int | None = None,
        hardware_target: HardwareTargetBinding | None = None,
        cutover_credential: str | None = None,
        format_confirmation_label: str | None = None,
        sequence_authorization_id: str | None = None,
        caller_peer_kind: str | None = None,
        current_host_id: str | None = None,
        on_admitted: Callable[[OperationRecord], None] | None = None,
        on_complete: Callable[[OperationRecord], None] | None = None,
        sequence_layout_fingerprint_sha256: str | None = None,
        restore_sequence_candidate: Mapping[str, object] | None = None,
        enable_native_sequence: bool = False,
    ) -> OperationRecord:
        return self.start_with_admission(
            kind,
            idempotency_key,
            principal,
            callback,
            job_id=job_id,
            cassette_sequence=cassette_sequence,
            hardware_target=hardware_target,
            cutover_credential=cutover_credential,
            format_confirmation_label=format_confirmation_label,
            sequence_authorization_id=sequence_authorization_id,
            caller_peer_kind=caller_peer_kind,
            current_host_id=current_host_id,
            on_admitted=on_admitted,
            on_complete=on_complete,
            sequence_layout_fingerprint_sha256=(
                sequence_layout_fingerprint_sha256
            ),
            restore_sequence_candidate=restore_sequence_candidate,
            enable_native_sequence=enable_native_sequence,
        ).record

    def start_with_admission(
        self,
        kind: str,
        idempotency_key: str,
        principal: str,
        callback: OperationCallback,
        *,
        job_id: str | None = None,
        cassette_sequence: int | None = None,
        hardware_target: HardwareTargetBinding | None = None,
        cutover_credential: str | None = None,
        format_confirmation_label: str | None = None,
        sequence_authorization_id: str | None = None,
        caller_peer_kind: str | None = None,
        current_host_id: str | None = None,
        on_admitted: Callable[[OperationRecord], None] | None = None,
        on_complete: Callable[[OperationRecord], None] | None = None,
        sequence_layout_fingerprint_sha256: str | None = None,
        restore_sequence_candidate: Mapping[str, object] | None = None,
        enable_native_sequence: bool = False,
    ) -> OperationAdmission:
        candidate = new_operation(
            kind,
            idempotency_key,
            principal,
            job_id,
            cassette_sequence,
        )
        if kind == "restore.cassette" and restore_sequence_candidate is None:
            raise ValueError("restore sequence candidate snapshot is required")
        with self._lock:
            with self._catalog_factory() as catalog:
                if restore_sequence_candidate is None:
                    admission = catalog.admit_operation(
                        candidate,
                        self._daemon_fence,
                        admission_open=self._accepting,
                        enable_native_sequence=enable_native_sequence,
                        hardware_target=hardware_target,
                        cutover_credential=cutover_credential,
                        format_confirmation_label=format_confirmation_label,
                        sequence_authorization_id=sequence_authorization_id,
                        caller_peer_kind=caller_peer_kind,
                        current_host_id=current_host_id,
                        sequence_layout_fingerprint_sha256=(
                            sequence_layout_fingerprint_sha256
                        ),
                    )
                else:
                    if hardware_target is None:
                        raise ValueError("restore sequence hardware target is required")
                    admission = catalog.admit_restore_sequence_operation(
                        candidate,
                        self._daemon_fence,
                        admission_open=self._accepting,
                        hardware_target=hardware_target,
                        expected_candidate=restore_sequence_candidate,
                    )
            if not admission.replayed:
                context = OperationContext(
                    record=admission.record,
                    fence=OperationFence(
                        admission.record.id,
                        self._daemon_fence.generation,
                    ),
                    _catalog_factory=self._catalog_factory,
                )
                if on_admitted is not None:
                    try:
                        on_admitted(admission.record)
                    except BaseException:
                        try:
                            with self._catalog_factory() as catalog:
                                catalog.finish_operation(
                                    context.fence,
                                    "failed",
                                    error_class="terminal_safety_failure",
                                    error_code="operation_failed",
                                )
                        except StaleOperationFence:
                            pass
                        raise
                try:
                    future = self._executor.submit(self._run, context, callback)
                except BaseException:
                    try:
                        with self._catalog_factory() as catalog:
                            catalog.finish_operation(
                                context.fence,
                                "failed",
                                error_class="terminal_safety_failure",
                                error_code="operation_failed",
                            )
                    except StaleOperationFence:
                        pass
                    raise
                self._futures[admission.record.id] = future
                future.add_done_callback(
                    lambda completed, record=admission.record: self._completed(
                        record, completed, on_complete
                    )
                )
        return admission

    def recover_interrupted(self) -> tuple[OperationRecord, ...]:
        with self._catalog_factory() as catalog:
            return catalog.recover_interrupted_operations(self._daemon_fence)

    def reconcile_admission_blockers(self) -> tuple[OperationRecord, ...]:
        with self._catalog_factory() as catalog:
            return catalog.reconcile_admission_blockers(self._daemon_fence)

    @contextmanager
    def stopped_pre_media_reset(self, operation_id: str):
        """Serialize reset with admission and reject even a queued local worker."""
        with self._lock:
            if operation_id in self._futures:
                raise StaleOperationFence("pre-media attempt still has a local worker")
            yield

    def retry_native_recovery(
        self,
        blocker: OperationRecord,
        fence: RecoveryCommandFence,
        callback: OperationCallback,
        *,
        on_admitted: Callable[[OperationRecord], None] | None = None,
    ) -> OperationRecord:
        """Replace and submit one native recovery attempt in one admission lock.

        This intentionally bypasses normal global admission: the durable recovery
        claim and command fence are the admission authority for this exact retry.
        """
        if (
            blocker.id != fence.operation_id
            or blocker.kind != "archive.native"
            or blocker.job_id is None
            or blocker.cassette_sequence is None
            or fence.owner_generation != self._daemon_fence.generation
        ):
            raise RuntimeError("native recovery replacement is not exact")
        replay_key = (
            f"recovery-native-{blocker.id}-{fence.owner_generation}"
        )
        candidate = new_operation(
            "archive.native",
            replay_key,
            blocker.principal,
            blocker.job_id,
            blocker.cassette_sequence,
        )
        with self._lock:
            with self._catalog_factory() as catalog:
                existing = catalog.find_operation_by_key(replay_key)
                if existing is not None:
                    replacement = _operation_record(existing)
                else:
                    reset = catalog.reset_automatic_cassette_for_recovery(
                        fence,
                        "automatic_recovery",
                        replacement_candidate=candidate,
                    )
                    replacement = reset.get("replacement")
                    if not isinstance(replacement, OperationRecord):
                        raise RuntimeError(
                            "native recovery replacement was not admitted"
                        )
                dispatch = catalog.native_recovery_dispatch(replacement.id)
                if dispatch is None:
                    raise RuntimeError("native recovery dispatch receipt is unavailable")
            context = OperationContext(
                record=replacement,
                fence=OperationFence(replacement.id, fence.owner_generation),
                _catalog_factory=self._catalog_factory,
            )
            if dispatch["state"] != "admitted" or replacement.id in self._futures:
                return replacement
            if on_admitted is not None:
                on_admitted(replacement)
            try:
                future = self._executor.submit(
                    self._run_native_recovery_once, context, callback
                )
            except BaseException as exc:
                with self._catalog_factory() as catalog:
                    observed = catalog.native_recovery_dispatch(replacement.id)
                if observed is not None and observed["state"] in {
                    "started",
                    "finished",
                }:
                    return replacement
                if isinstance(exc, OSError):
                    raise
                raise OSError("native recovery worker submission failed") from exc
            self._futures[replacement.id] = future
            future.add_done_callback(
                lambda completed, operation_id=replacement.id: (
                    self._forget_future(operation_id, completed)
                )
            )
            return replacement

    def authorize_critical_replacement(
        self,
        blocker: OperationRecord,
        fence: RecoveryCommandFence,
        callback: OperationCallback,
        *,
        principal: str,
        idempotency_key: str,
        job_id: str,
        cassette_sequence: int,
        expected_label: str,
        attempt_number: int,
        evidence_sha256: str,
        target: HardwareTargetBinding,
        observed_media_identity_sha256: str,
        observation: CriticalRecoveryObservation,
        consumed_at: str,
        on_admitted: Callable[[OperationRecord], None] | None = None,
    ) -> OperationRecord:
        """Atomically replace one exact critical native attempt and dispatch it."""

        replay_digest = hashlib.sha256(
            f"{blocker.id}\0{fence.owner_generation}\0{attempt_number}".encode("utf-8")
        ).hexdigest()
        candidate = new_operation(
            "archive.native",
            f"critical-native-{replay_digest}",
            blocker.principal,
            blocker.job_id,
            blocker.cassette_sequence,
        )
        with self._lock:
            with self._catalog_factory() as catalog:
                replacement = catalog.authorize_critical_replacement(
                    blocker.id,
                    fence,
                    candidate,
                    principal=principal,
                    idempotency_key=idempotency_key,
                    job_id=job_id,
                    cassette_sequence=cassette_sequence,
                    expected_label=expected_label,
                    attempt_number=attempt_number,
                    evidence_sha256=evidence_sha256,
                    target=target,
                    observed_media_identity_sha256=(
                        observed_media_identity_sha256
                    ),
                    observation=observation,
                    consumed_at=consumed_at,
                )
                dispatch = catalog.native_recovery_dispatch(replacement.id)
                if dispatch is None:
                    raise RuntimeError(
                        "critical recovery dispatch receipt is unavailable"
                    )
            context = OperationContext(
                record=replacement,
                fence=OperationFence(replacement.id, fence.owner_generation),
                _catalog_factory=self._catalog_factory,
            )
            if dispatch["state"] != "admitted" or replacement.id in self._futures:
                return replacement
            if on_admitted is not None:
                on_admitted(replacement)
            try:
                future = self._executor.submit(
                    self._run_native_recovery_once, context, callback
                )
            except BaseException as exc:
                with self._catalog_factory() as catalog:
                    observed = catalog.native_recovery_dispatch(replacement.id)
                if observed is not None and observed["state"] in {
                    "started",
                    "finished",
                }:
                    return replacement
                if isinstance(exc, OSError):
                    raise
                raise OSError("critical recovery worker submission failed") from exc
            self._futures[replacement.id] = future
            future.add_done_callback(
                lambda completed, operation_id=replacement.id: (
                    self._forget_future(operation_id, completed)
                )
            )
            return replacement

    def _run_native_recovery_once(
        self, context: OperationContext, callback: OperationCallback
    ) -> None:
        with self._catalog_factory() as catalog:
            owned = catalog.claim_native_recovery_dispatch_start(context.fence)
        if not owned:
            return
        try:
            self._run(context, callback)
        finally:
            try:
                with self._catalog_factory() as catalog:
                    catalog.finish_native_recovery_dispatch(context.fence)
            except StaleOperationFence:
                pass

    def resolve_recovery(
        self,
        operation_id: str,
        resolution: SafeRecoveryResolution,
    ) -> OperationRecord:
        with self._catalog_factory() as catalog:
            return catalog.resolve_recovery(
                operation_id,
                self._daemon_fence,
                resolution,
            )

    def operation(self, operation_id: str) -> OperationRecord | None:
        with self._catalog_factory() as catalog:
            row = catalog.get_operation(operation_id)
            return None if row is None else _operation_record(row)

    def replay(self, idempotency_key: str) -> OperationRecord | None:
        with self._catalog_factory() as catalog:
            row = catalog.replay_operation_by_key(idempotency_key)
            return None if row is None else _operation_record(row)

    def start_accepting(self) -> None:
        with self._lock:
            self._accepting = True

    def stop_accepting(self) -> None:
        with self._lock:
            self._accepting = False

    def mark_unfinished_recovery_required(
        self,
        timeout_seconds: float,
    ) -> tuple[OperationRecord, ...]:
        timeout_seconds = validate_shutdown_timeout(timeout_seconds)
        self.stop_accepting()
        with self._lock:
            pending = dict(self._futures)
        if pending:
            _, unfinished = wait(tuple(pending.values()), timeout=timeout_seconds)
        else:
            unfinished = set()

        marked: list[OperationRecord] = []
        for operation_id, future in pending.items():
            if future not in unfinished:
                continue
            fence = OperationFence(operation_id, self._daemon_fence.generation)
            try:
                with self._catalog_factory() as catalog:
                    catalog.finish_operation(
                        fence,
                        "recovery_required",
                        error_class="operator_required",
                        error_code="recovery_required",
                    )
                    row = catalog.get_operation(operation_id)
                    if row is not None:
                        marked.append(_operation_record(row))
            except StaleOperationFence:
                continue
        return tuple(marked)

    def shutdown(self, timeout_seconds: float) -> tuple[OperationRecord, ...]:
        marked = self.mark_unfinished_recovery_required(timeout_seconds)
        if self._owns_executor:
            self._executor.shutdown(wait=False, cancel_futures=True)
        return marked

    def _run(self, context: OperationContext, callback: OperationCallback) -> None:
        try:
            callback(context)
        except BaseException:
            try:
                with self._catalog_factory() as catalog:
                    current = catalog.get_operation(context.fence.operation_id)
                    if current is not None and current["state"] == "running":
                        catalog.finish_operation(
                            context.fence,
                            "failed",
                            error_class="terminal_safety_failure",
                            error_code="operation_failed",
                        )
            except StaleOperationFence:
                pass
            raise
        try:
            with self._catalog_factory() as catalog:
                current = catalog.get_operation(context.fence.operation_id)
                if current is not None and current["state"] == "running":
                    catalog.finish_operation(context.fence, "succeeded")
        except StaleOperationFence:
            pass

    def _forget_future(
        self,
        operation_id: str,
        completed: Future[None],
    ) -> None:
        with self._lock:
            if self._futures.get(operation_id) is completed:
                self._futures.pop(operation_id, None)

    def _completed(
        self,
        record: OperationRecord,
        completed: Future[None],
        callback: Callable[[OperationRecord], None] | None,
    ) -> None:
        self._forget_future(record.id, completed)
        if callback is not None:
            callback(record)
