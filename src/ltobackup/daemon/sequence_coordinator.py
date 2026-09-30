"""Durable admission of one native cassette after an unloaded checkpoint."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from threading import Event, Lock, RLock, Thread, current_thread

from ..catalog import Catalog
from .models import OperationRecord, sequence_continuation_idempotency_key

CatalogFactory = Callable[[], Catalog]


@dataclass(frozen=True)
class SequenceCandidate:
    job_id: str
    cassette_sequence: int
    authorization_id: str | None
    layout_fingerprint_sha256: str
    idempotency_key: str


AdmissionCallback = Callable[[SequenceCandidate], OperationRecord]


class NativeSequenceCoordinator:
    """Observe catalog checkpoints and ask the normal operation admission path.

    This coordinator deliberately has no access to tape, LTFS, SCSI, mount, or
    command interfaces.  The catalog query is fail-closed and the supplied
    callback performs the normal fenced operation admission.
    """

    def __init__(
        self,
        catalog_factory: CatalogFactory,
        *,
        daemon_generation: int,
        admit: AdmissionCallback,
        check_sources: Callable[[SequenceCandidate], bool] | None = None,
        reconcile_boundary: Callable[[], bool] | None = None,
        poll_interval_seconds: float = 1.0,
        shutdown_timeout_seconds: float = 1.0,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if type(daemon_generation) is not int or daemon_generation <= 0:
            raise ValueError("daemon generation must be positive")
        if poll_interval_seconds <= 0:
            raise ValueError("poll interval must be positive")
        if shutdown_timeout_seconds <= 0:
            raise ValueError("shutdown timeout must be positive")
        self._catalog_factory = catalog_factory
        self._daemon_generation = daemon_generation
        self._admit = admit
        self._check_sources = check_sources
        self._reconcile_boundary = reconcile_boundary
        self._poll_interval_seconds = poll_interval_seconds
        self._shutdown_timeout_seconds = shutdown_timeout_seconds
        self._on_error = on_error
        self._wake_event = Event()
        self._stopped = Event()
        self._reconciling = Lock()
        self._lifecycle_lock = RLock()
        self._thread: Thread | None = None
        self._consecutive_failures = 0

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None:
                return
            if self._stopped.is_set():
                raise RuntimeError("sequence coordinator cannot restart after shutdown")
            thread = Thread(
                target=self._run,
                name="ltobackup-sequence-coordinator",
                daemon=True,
            )
            self._thread = thread
            thread.start()
        self.wake()

    def wake(self) -> None:
        if not self._stopped.is_set():
            self._wake_event.set()

    def shutdown(self) -> None:
        self._stopped.set()
        self._wake_event.set()
        with self._lifecycle_lock:
            thread = self._thread
        if thread is current_thread():
            raise RuntimeError("sequence coordinator cannot join its own worker")
        if thread is not None:
            thread.join(timeout=self._shutdown_timeout_seconds)
            if thread.is_alive():
                raise RuntimeError("sequence coordinator worker did not stop")
            with self._lifecycle_lock:
                if self._thread is thread:
                    self._thread = None

    def reconcile_once(self) -> OperationRecord | None:
        if self._stopped.is_set() or not self._reconciling.acquire(blocking=False):
            return None
        try:
            if self._reconcile_boundary is not None:
                with self._catalog_factory() as catalog:
                    busy = catalog.connection.execute(
                        "SELECT 1 FROM daemon_operations WHERE state IN ('running','recovery_required') "
                        "UNION ALL SELECT 1 FROM hardware_command_executions WHERE state<>'quiesced' LIMIT 1"
                    ).fetchone()
                if busy is not None or not self._reconcile_boundary():
                    return None
                if self._stopped.is_set():
                    return None
            # Refresh may replace the unused suffix and its fingerprint, or
            # discover work after the old last cassette. Query only afterwards.
            with self._catalog_factory() as catalog:
                row = catalog.next_automatic_sequence_candidate()
            if row is None:
                return None
            job_id = str(row["job_id"])
            sequence = int(row["cassette_sequence"])
            fingerprint = str(row["layout_fingerprint_sha256"])
            key = sequence_continuation_idempotency_key(
                job_id,
                fingerprint,
                sequence,
                self._daemon_generation,
            )
            authorization = row["authorization_id"]
            candidate = SequenceCandidate(
                job_id=job_id,
                cassette_sequence=sequence,
                authorization_id=None if authorization is None else str(authorization),
                layout_fingerprint_sha256=fingerprint,
                idempotency_key=key,
            )
            if self._check_sources is not None and not self._check_sources(candidate):
                return None
            return self._admit(candidate)
        finally:
            self._reconciling.release()

    def _run(self) -> None:
        delay = self._poll_interval_seconds
        while not self._stopped.is_set():
            self._wake_event.wait(delay)
            self._wake_event.clear()
            if self._stopped.is_set():
                return
            try:
                self.reconcile_once()
            except Exception as exc:
                self._consecutive_failures += 1
                if self._on_error is not None and (
                    self._consecutive_failures == 1
                    or self._consecutive_failures & (self._consecutive_failures - 1) == 0
                ):
                    self._on_error(exc)
                delay = min(
                    self._poll_interval_seconds * (2 ** min(self._consecutive_failures, 6)),
                    60.0,
                )
            else:
                self._consecutive_failures = 0
                delay = self._poll_interval_seconds


__all__ = ["NativeSequenceCoordinator", "SequenceCandidate"]
