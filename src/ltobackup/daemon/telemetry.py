from __future__ import annotations

import math
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from threading import RLock

_MIB = 1024 * 1024
_PROGRESS_SAMPLE_INTERVAL_SECONDS = 1.0
_CURRENT_SAMPLE_FRESHNESS_SECONDS = 5.0


class TelemetryPhase(StrEnum):
    SOURCE_OPEN = "source_open"
    SMB_READ = "smb_read"
    LTFS_WRITE_ADMISSION = "ltfs_write_admission"
    COPY = "copy"
    CLOSE = "close"
    MANIFEST = "manifest"
    SNAPSHOT = "snapshot"
    FINALIZATION = "finalization"
    UNMOUNT = "unmount"
    UNLOAD = "unload"
    RETRY = "retry"
    OPERATOR_WAIT = "operator_wait"


_PHASES = tuple(TelemetryPhase)
_API_PHASES = (
    TelemetryPhase.COPY,
    TelemetryPhase.CLOSE,
    TelemetryPhase.FINALIZATION,
    TelemetryPhase.UNMOUNT,
    TelemetryPhase.UNLOAD,
)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class TelemetrySample:
    event_id: int
    occurred_at: datetime
    bytes_per_second: float | None


@dataclass(frozen=True, slots=True)
class PhaseDurations:
    source_open_seconds: float = 0.0
    smb_read_seconds: float = 0.0
    ltfs_write_admission_seconds: float = 0.0
    copy_seconds: float = 0.0
    close_seconds: float = 0.0
    manifest_seconds: float = 0.0
    snapshot_seconds: float = 0.0
    finalization_seconds: float = 0.0
    unmount_seconds: float = 0.0
    unload_seconds: float = 0.0
    retry_seconds: float = 0.0
    operator_wait_seconds: float = 0.0

    def to_api_payload(self) -> dict[str, float]:
        values = self.to_diagnostic_payload()
        return {
            f"{phase.value}_seconds": values[f"{phase.value}_seconds"]
            for phase in _API_PHASES
        }

    def to_diagnostic_payload(self) -> dict[str, float]:
        return {
            f"{phase.value}_seconds": getattr(self, f"{phase.value}_seconds")
            for phase in _PHASES
        }


@dataclass(frozen=True, slots=True)
class TelemetrySnapshot:
    files_completed: int
    bytes_completed: int
    current_bytes_per_second: float | None
    effective_bytes_per_second: float | None
    samples: tuple[TelemetrySample, ...]
    durations: PhaseDurations
    current_phase: TelemetryPhase | None
    closed: bool
    window_generation: int
    current_sample_age_seconds: float | None = None
    current_sample_stale: bool = False

    def to_api_progress(self, *, files_total: int, bytes_total: int) -> dict[str, int]:
        if files_total < self.files_completed or bytes_total < self.bytes_completed:
            raise ValueError("progress totals cannot be below completed values")
        return {
            "files_completed": self.files_completed,
            "files_total": files_total,
            "bytes_completed": self.bytes_completed,
            "bytes_total": bytes_total,
        }

    def to_api_telemetry(self) -> dict[str, object]:
        return {
            "current_mib_per_second": _to_mib(self.current_bytes_per_second),
            "effective_mib_per_second": _to_mib(self.effective_bytes_per_second),
            "current_sample_age_seconds": self.current_sample_age_seconds,
            "current_sample_stale": self.current_sample_stale,
            "samples": tuple(
                {
                    "event_id": sample.event_id,
                    "occurred_at": _rfc3339(sample.occurred_at),
                    "mib_per_second": _to_mib(sample.bytes_per_second),
                }
                for sample in self.samples
            ),
            "durations": self.durations.to_api_payload(),
        }


def _to_mib(value: float | None) -> float | None:
    return None if value is None else value / _MIB


class TelemetryAccumulator:
    """Thread-safe event telemetry; service/API wiring is intentionally external.

    Callers feed completed file and phase events. This module never polls the
    drive, starts a worker thread, or touches hardware.
    """

    def __init__(
        self,
        *,
        monotonic: Callable[[], float],
        utc_now: Callable[[], datetime],
        sample_every_files: int = 1,
        max_samples: int = 300,
    ) -> None:
        if (
            isinstance(sample_every_files, bool)
            or not isinstance(sample_every_files, int)
            or sample_every_files <= 0
        ):
            raise ValueError("sample_every_files must be a positive integer")
        if (
            isinstance(max_samples, bool)
            or not isinstance(max_samples, int)
            or max_samples <= 0
        ):
            raise ValueError("max_samples must be a positive integer")
        self._monotonic = monotonic
        self._utc_now = utc_now
        self._sample_every_files = sample_every_files
        self._samples: deque[TelemetrySample] = deque(maxlen=max_samples)
        self._lock = RLock()
        self._started_at = self._read_monotonic()
        self._window_started_at: float | None = None
        self._window_start_bytes = 0
        self._last_observed_at = self._started_at
        self._last_sample_at = self._started_at
        self._last_sample_bytes = 0
        self._files_since_sample = 0
        self._bytes_completed = 0
        self._active_file_bytes = 0
        self._window_generation = 0
        self._files_completed = 0
        self._current_rate: float | None = None
        self._next_event_id = 1
        self._durations: dict[TelemetryPhase, float] = {phase: 0.0 for phase in _PHASES}
        self._current_phase: TelemetryPhase | None = None
        self._phase_started_at: float | None = None
        self._closed_snapshot: TelemetrySnapshot | None = None

    def begin_window(self) -> TelemetrySnapshot:
        """Start an operation-local rate window without losing lifetime totals."""

        with self._lock:
            self._require_open()
            now = self._read_monotonic()
            self._require_not_backwards(now)
            self._active_file_bytes = 0
            self._window_generation += 1
            self._window_started_at = now
            self._window_start_bytes = self._bytes_completed
            self._last_observed_at = now
            self._last_sample_at = now
            self._last_sample_bytes = self._bytes_completed
            self._files_since_sample = 0
            self._samples.clear()
            self._current_rate = None
            self._durations = {phase: 0.0 for phase in _PHASES}
            self._current_phase = None
            self._phase_started_at = None
            return self._snapshot_locked(closed=False, now=now)

    def record_progress(self, byte_count: int) -> TelemetrySnapshot:
        """Record newly copied bytes without claiming that a file completed."""

        if isinstance(byte_count, bool) or not isinstance(byte_count, int):
            raise TypeError("byte_count must be an integer")
        if byte_count < 0:
            raise ValueError("byte_count must be non-negative")
        with self._lock:
            self._require_open()
            now = self._read_monotonic()
            self._require_not_backwards(now)
            self._active_file_bytes += byte_count
            self._last_observed_at = now
            self._sample_pending_progress(now, force=False)
            return self._snapshot_locked(closed=False, now=now)

    def complete_file(self) -> TelemetrySnapshot:
        """Complete the current file after its bytes were reported as progress."""

        with self._lock:
            self._require_open()
            now = self._read_monotonic()
            self._require_not_backwards(now)
            self._bytes_completed += self._active_file_bytes
            self._active_file_bytes = 0
            self._files_completed += 1
            self._last_observed_at = now
            self._sample_pending_progress(now, force=True)
            return self._snapshot_locked(closed=False, now=now)

    def committed_progress(self) -> tuple[int, int]:
        """Return completed files and bytes without the active partial file."""

        with self._lock:
            return self._files_completed, self._bytes_completed

    def committed_checkpoint(self) -> tuple[int, int, int]:
        """Return committed progress and the current operation-window generation."""

        with self._lock:
            return (
                self._files_completed,
                self._bytes_completed,
                self._window_generation,
            )

    def record_file(self, byte_count: int) -> TelemetrySnapshot:
        if isinstance(byte_count, bool) or not isinstance(byte_count, int):
            raise TypeError("byte_count must be an integer")
        if byte_count < 0:
            raise ValueError("byte_count must be non-negative")
        with self._lock:
            self._require_open()
            now = self._read_monotonic()
            self._require_not_backwards(now)
            next_bytes = self._bytes_completed + byte_count
            next_files = self._files_completed + 1
            next_files_since_sample = self._files_since_sample + 1
            sample: TelemetrySample | None = None
            rate: float | None = None
            if next_files_since_sample == self._sample_every_files:
                elapsed = now - self._last_sample_at
                rate = (
                    (next_bytes - self._last_sample_bytes) / elapsed
                    if elapsed > 0
                    else None
                )
                sample = self._new_sample(rate)
            self._bytes_completed = next_bytes
            self._files_completed = next_files
            self._files_since_sample = next_files_since_sample
            self._last_observed_at = now
            if sample is not None:
                self._append_sample(sample)
                self._last_sample_at = now
                self._last_sample_bytes = self._bytes_completed
                self._files_since_sample = 0
            return self._snapshot_locked(closed=False, now=now)

    def mark_unavailable(self) -> TelemetrySnapshot:
        """Append a real chart gap and rebase the next rate observation."""

        with self._lock:
            self._require_open()
            now = self._read_monotonic()
            self._require_not_backwards(now)
            sample = self._new_sample(None)
            self._last_observed_at = now
            self._append_sample(sample)
            self._last_sample_at = now
            self._last_sample_bytes = self._observed_bytes()
            self._files_since_sample = 0
            return self._snapshot_locked(closed=False, now=now)

    def add_duration(
        self, phase: TelemetryPhase | str, seconds: float
    ) -> TelemetrySnapshot:
        phase = self._coerce_phase(phase)
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise TypeError("phase duration must be a number")
        seconds = float(seconds)
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError("phase duration must be finite and non-negative")
        with self._lock:
            self._require_open()
            self._durations[phase] += seconds
            return self._snapshot_locked(
                closed=False,
                now=self._last_observed_at,
            )

    def start_phase(self, phase: TelemetryPhase | str) -> TelemetrySnapshot:
        phase = self._coerce_phase(phase)
        with self._lock:
            self._require_open()
            if self._current_phase is not None:
                raise RuntimeError("a telemetry phase is already active")
            now = self._read_monotonic()
            self._require_not_backwards(now)
            self._last_observed_at = now
            self._current_phase = phase
            self._phase_started_at = now
            return self._snapshot_locked(closed=False, now=now)

    def finish_phase(self, phase: TelemetryPhase | str) -> TelemetrySnapshot:
        phase = self._coerce_phase(phase)
        with self._lock:
            self._require_open()
            if self._current_phase != phase or self._phase_started_at is None:
                raise RuntimeError("telemetry phase is not active")
            now = self._read_monotonic()
            self._require_not_backwards(now)
            self._durations[phase] += now - self._phase_started_at
            self._last_observed_at = now
            self._current_phase = None
            self._phase_started_at = None
            return self._snapshot_locked(closed=False, now=now)

    def close(self) -> TelemetrySnapshot:
        with self._lock:
            if self._closed_snapshot is not None:
                return self._closed_snapshot
            now = self._read_monotonic()
            self._require_not_backwards(now)
            pending_sample = self._files_since_sample > 0
            sample: TelemetrySample | None = None
            if pending_sample:
                elapsed = now - self._last_sample_at
                rate = (
                    (self._bytes_completed - self._last_sample_bytes) / elapsed
                    if elapsed > 0
                    else None
                )
                sample = self._new_sample(rate)
            if self._current_phase is not None and self._phase_started_at is not None:
                self._durations[self._current_phase] += now - self._phase_started_at
                self._current_phase = None
                self._phase_started_at = None
            self._last_observed_at = now
            if sample is not None:
                self._append_sample(sample)
                self._last_sample_at = now
                self._last_sample_bytes = self._bytes_completed
                self._files_since_sample = 0
            self._closed_snapshot = self._snapshot_locked(closed=True, now=now)
            return self._closed_snapshot

    def snapshot(self) -> TelemetrySnapshot:
        with self._lock:
            if self._closed_snapshot is not None:
                return self._closed_snapshot
            now = self._read_monotonic()
            self._require_not_backwards(now)
            return self._snapshot_locked(closed=False, now=now)

    def _new_sample(self, rate: float | None) -> TelemetrySample:
        occurred_at = self._utc_now()
        if not isinstance(occurred_at, datetime) or occurred_at.utcoffset() is None:
            raise ValueError("utc_now must return an aware datetime")
        return TelemetrySample(self._next_event_id, occurred_at.astimezone(UTC), rate)

    def _append_sample(self, sample: TelemetrySample) -> None:
        self._samples.append(sample)
        self._next_event_id += 1
        self._current_rate = sample.bytes_per_second

    def _sample_pending_progress(self, now: float, *, force: bool) -> None:
        observed_bytes = self._observed_bytes()
        if observed_bytes == self._last_sample_bytes:
            return
        elapsed = now - self._last_sample_at
        if not force and elapsed < _PROGRESS_SAMPLE_INTERVAL_SECONDS:
            return
        rate = (
            (observed_bytes - self._last_sample_bytes) / elapsed
            if elapsed > 0
            else None
        )
        self._append_sample(self._new_sample(rate))
        self._last_sample_at = now
        self._last_sample_bytes = observed_bytes

    def _observed_bytes(self) -> int:
        return self._bytes_completed + self._active_file_bytes

    def _snapshot_locked(self, *, closed: bool, now: float) -> TelemetrySnapshot:
        sample_age = now - self._last_sample_at if self._samples else None
        sample_stale = (
            sample_age is not None and sample_age > _CURRENT_SAMPLE_FRESHNESS_SECONDS
        )
        if sample_stale and self._current_rate is not None:
            # Publish one explicit gap without rebasing the byte/time window:
            # the next observation must include the time spent stalled.
            self._append_sample(self._new_sample(None))
        effective_started_at = (
            self._window_started_at
            if self._window_started_at is not None
            else self._started_at
        )
        effective_start_bytes = (
            self._window_start_bytes if self._window_started_at is not None else 0
        )
        elapsed = now - effective_started_at
        observed_bytes = self._observed_bytes()
        effective_bytes = observed_bytes - effective_start_bytes
        effective = effective_bytes / elapsed if elapsed > 0 else None
        durations = dict(self._durations)
        if self._current_phase is not None and self._phase_started_at is not None:
            durations[self._current_phase] += now - self._phase_started_at
        return TelemetrySnapshot(
            files_completed=self._files_completed,
            bytes_completed=observed_bytes,
            current_bytes_per_second=self._current_rate,
            effective_bytes_per_second=effective,
            samples=tuple(self._samples),
            durations=PhaseDurations(
                **{f"{phase.value}_seconds": durations[phase] for phase in _PHASES}
            ),
            current_phase=self._current_phase,
            closed=closed,
            window_generation=self._window_generation,
            current_sample_age_seconds=sample_age,
            current_sample_stale=sample_stale,
        )

    def _require_open(self) -> None:
        if self._closed_snapshot is not None:
            raise RuntimeError("telemetry accumulator is closed")

    @staticmethod
    def _coerce_phase(phase: TelemetryPhase | str) -> TelemetryPhase:
        try:
            return TelemetryPhase(phase)
        except (TypeError, ValueError) as error:
            raise ValueError("unknown telemetry phase") from error

    def _require_not_backwards(self, value: float) -> None:
        if value < self._last_observed_at:
            raise ValueError("monotonic clock moved backwards")

    def _read_monotonic(self) -> float:
        value = self._monotonic()
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise TypeError("monotonic clock must return a number")
        value = float(value)
        if not math.isfinite(value):
            raise ValueError("monotonic clock must return a finite value")
        return value
