from __future__ import annotations

import json
import os
import re
import tempfile
import zipfile
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from itertools import islice
from pathlib import Path
from threading import Condition, RLock
from typing import Any

from .telemetry import TelemetryAccumulator, TelemetryPhase, TelemetrySnapshot

_SAFE_VERSION = re.compile(r"^[A-Za-z0-9.+_-]{1,64}$")


class DiagnosticHealthStatus(StrEnum):
    OK = "ok"
    DEGRADED = "degraded"
    ATTENTION = "attention"
    UNAVAILABLE = "unavailable"


class DiagnosticLogLevel(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class DiagnosticEventCode(StrEnum):
    TELEMETRY_SAMPLE = "telemetry.sample"
    TELEMETRY_UNAVAILABLE = "telemetry.unavailable"
    ARCHIVE_WRITE_FAILED = "archive.write_failed"
    FINALIZATION_STARTED = "finalization.started"
    FINALIZATION_COMPLETED = "finalization.completed"
    FINALIZATION_FAILED = "finalization.failed"
    UNMOUNT_STARTED = "unmount.started"
    UNMOUNT_COMPLETED = "unmount.completed"
    UNMOUNT_FAILED = "unmount.failed"
    UNLOAD_STARTED = "unload.started"
    UNLOAD_COMPLETED = "unload.completed"
    UNLOAD_FAILED = "unload.failed"
    RECOVERY_REQUIRED = "recovery.required"
    OPERATOR_REQUIRED = "operator.required"


class TapeAlertCode(IntEnum):
    FLAG_01 = 1
    FLAG_02 = 2
    FLAG_03 = 3
    FLAG_04 = 4
    FLAG_05 = 5
    FLAG_06 = 6
    FLAG_07 = 7
    FLAG_08 = 8
    FLAG_09 = 9
    FLAG_10 = 10
    FLAG_11 = 11
    FLAG_12 = 12
    FLAG_13 = 13
    FLAG_14 = 14
    FLAG_15 = 15
    FLAG_16 = 16
    FLAG_17 = 17
    FLAG_18 = 18
    FLAG_19 = 19
    FLAG_20 = 20
    FLAG_21 = 21
    FLAG_22 = 22
    FLAG_23 = 23
    FLAG_24 = 24
    FLAG_25 = 25
    FLAG_26 = 26
    FLAG_27 = 27
    FLAG_28 = 28
    FLAG_29 = 29
    FLAG_30 = 30
    FLAG_31 = 31
    FLAG_32 = 32
    FLAG_33 = 33
    FLAG_34 = 34
    FLAG_35 = 35
    FLAG_36 = 36
    FLAG_37 = 37
    FLAG_38 = 38
    FLAG_39 = 39
    FLAG_40 = 40
    FLAG_41 = 41
    FLAG_42 = 42
    FLAG_43 = 43
    FLAG_44 = 44
    FLAG_45 = 45
    FLAG_46 = 46
    FLAG_47 = 47
    FLAG_48 = 48
    FLAG_49 = 49
    FLAG_50 = 50
    FLAG_51 = 51
    FLAG_52 = 52
    FLAG_53 = 53
    FLAG_54 = 54
    FLAG_55 = 55
    FLAG_56 = 56
    FLAG_57 = 57
    FLAG_58 = 58
    FLAG_59 = 59
    FLAG_60 = 60
    FLAG_61 = 61
    FLAG_62 = 62
    FLAG_63 = 63
    FLAG_64 = 64

    CLEAN_NOW = 20
    CLEAN_PERIODIC = 21
    EXPIRED_CLEANING_MEDIA = 22
    INVALID_CLEANING_MEDIA = 23


@dataclass(frozen=True, slots=True)
class DiagnosticHealth:
    status: DiagnosticHealthStatus
    cleaning_required: bool | None
    tape_alert_codes: tuple[TapeAlertCode, ...] = ()

    def __post_init__(self) -> None:
        if type(self.status) is not DiagnosticHealthStatus:
            raise TypeError("diagnostic health status must use its closed enum")
        if self.cleaning_required is not None and not isinstance(
            self.cleaning_required, bool
        ):
            raise TypeError("cleaning_required must be boolean or unavailable")
        if type(self.tape_alert_codes) is not tuple:
            raise TypeError("TapeAlert codes must be a tuple of closed enum values")
        if len(self.tape_alert_codes) > 64:
            raise ValueError("too many TapeAlert codes")
        if any(type(value) is not TapeAlertCode for value in self.tape_alert_codes):
            raise TypeError("TapeAlert codes must use the closed TapeAlert enum")


@dataclass(frozen=True, slots=True)
class DiagnosticLogRecord:
    occurred_at: str
    level: DiagnosticLogLevel
    code: DiagnosticEventCode

    def __post_init__(self) -> None:
        if type(self.level) is not DiagnosticLogLevel:
            raise TypeError("diagnostic log level must use its closed enum")
        if type(self.code) is not DiagnosticEventCode:
            raise TypeError("diagnostic event code must use its closed enum")
        if not isinstance(self.occurred_at, str):
            raise TypeError("diagnostic log timestamp must be RFC3339 text")
        object.__setattr__(
            self, "occurred_at", _rfc3339(_parse_rfc3339(self.occurred_at))
        )


@dataclass(frozen=True, slots=True)
class RuntimeDiagnosticSummary:
    """Closed runtime diagnostic view for the daemon/API composition layer."""

    health: DiagnosticHealth
    telemetry: TelemetrySnapshot


class RuntimeDiagnostics:
    """Own bounded telemetry and produce only redacted diagnostic artifacts.

    No caller selects an export path or contributes diagnostic text.  The daemon
    owns this facade and can publish a snapshot only after an accumulator update
    succeeds, so a rejected monotonic-clock observation has no external event.
    """

    def __init__(
        self,
        *,
        version: str,
        monotonic: Callable[[], float],
        utc_now: Callable[[], datetime],
        health: Callable[[], DiagnosticHealth] | None = None,
        on_snapshot: Callable[[TelemetrySnapshot], None] | None = None,
        max_samples: int = 300,
        max_logs: int = 200,
    ) -> None:
        if health is not None and not callable(health):
            raise TypeError("diagnostic health provider must be callable")
        if on_snapshot is not None and not callable(on_snapshot):
            raise TypeError("diagnostic snapshot callback must be callable")
        if isinstance(max_logs, bool) or not isinstance(max_logs, int) or max_logs < 0:
            raise ValueError("max_logs must be a non-negative integer")
        self._health = health or _unavailable_health
        self._on_snapshot = on_snapshot
        self._lock = RLock()
        self._notify_condition = Condition(RLock())
        self._next_snapshot_sequence = 1
        self._next_notification_sequence = 1
        self._last_live_sample_event_id: int | None = None
        self._logs: deque[DiagnosticLogRecord] = deque(maxlen=max_logs)
        self._telemetry = TelemetryAccumulator(
            monotonic=monotonic,
            utc_now=utc_now,
            max_samples=max_samples,
        )
        self._exporter = DiagnosticExporter(
            version=version,
            health=self._validated_health,
            telemetry=self.snapshot,
            logs=self._logs_page,
            utc_now=utc_now,
            max_logs=max_logs,
        )

    def snapshot(self) -> TelemetrySnapshot:
        with self._lock:
            return self._telemetry.snapshot()

    def summary(self) -> RuntimeDiagnosticSummary:
        with self._lock:
            return RuntimeDiagnosticSummary(
                health=self._validated_health(),
                telemetry=self._telemetry.snapshot(),
            )

    def record_file(self, byte_count: int) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.record_file(byte_count)
            if snapshot.samples:
                self._append_log(
                    DiagnosticLogLevel.INFO,
                    DiagnosticEventCode.TELEMETRY_SAMPLE,
                    snapshot.samples[-1].occurred_at,
                )
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def begin_window(self) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.begin_window()
            self._last_live_sample_event_id = None
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def record_progress(self, byte_count: int) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.record_progress(byte_count)
            latest = snapshot.samples[-1] if snapshot.samples else None
            if latest is None or latest.event_id == self._last_live_sample_event_id:
                return snapshot
            self._last_live_sample_event_id = latest.event_id
            self._append_log(
                DiagnosticLogLevel.INFO,
                DiagnosticEventCode.TELEMETRY_SAMPLE,
                latest.occurred_at,
            )
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def complete_file(self) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.complete_file()
            latest = snapshot.samples[-1] if snapshot.samples else None
            if (
                latest is not None
                and latest.event_id != self._last_live_sample_event_id
            ):
                self._last_live_sample_event_id = latest.event_id
                self._append_log(
                    DiagnosticLogLevel.INFO,
                    DiagnosticEventCode.TELEMETRY_SAMPLE,
                    latest.occurred_at,
                )
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def committed_progress(self) -> tuple[int, int]:
        with self._lock:
            return self._telemetry.committed_progress()

    def committed_checkpoint(self) -> tuple[int, int, int]:
        with self._lock:
            return self._telemetry.committed_checkpoint()

    def mark_unavailable(self) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.mark_unavailable()
            self._last_live_sample_event_id = snapshot.samples[-1].event_id
            self._append_log(
                DiagnosticLogLevel.WARNING,
                DiagnosticEventCode.TELEMETRY_UNAVAILABLE,
                snapshot.samples[-1].occurred_at,
            )
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def add_duration(
        self, phase: TelemetryPhase | str, seconds: float
    ) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.add_duration(phase, seconds)
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def start_phase(self, phase: TelemetryPhase | str) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.start_phase(phase)
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def finish_phase(self, phase: TelemetryPhase | str) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.finish_phase(phase)
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def close(self) -> TelemetrySnapshot:
        with self._lock:
            snapshot = self._telemetry.close()
            sequence = self._reserve_notification_locked()
        self._notify(sequence, snapshot)
        return snapshot

    def export_bytes(self) -> bytes:
        """Return a new redacted bundle without accepting client-controlled paths."""

        with (
            self._lock,
            tempfile.TemporaryDirectory(prefix="lto-diagnostics-") as directory,
        ):
            archive = self._exporter.create(Path(directory) / "diagnostics.zip")
            return archive.read_bytes()

    def _validated_health(self) -> DiagnosticHealth:
        health = self._health()
        if type(health) is not DiagnosticHealth:
            raise TypeError("diagnostic health provider must return DiagnosticHealth")
        return health

    def _logs_page(self, limit: int) -> Iterable[DiagnosticLogRecord]:
        with self._lock:
            return tuple(islice(self._logs, limit))

    def _append_log(
        self,
        level: DiagnosticLogLevel,
        code: DiagnosticEventCode,
        occurred_at: datetime,
    ) -> None:
        self._logs.append(
            DiagnosticLogRecord(
                occurred_at=_rfc3339(_aware_utc(occurred_at)),
                level=level,
                code=code,
            )
        )

    def _reserve_notification_locked(self) -> int:
        sequence = self._next_snapshot_sequence
        self._next_snapshot_sequence += 1
        return sequence

    def _notify(self, sequence: int, snapshot: TelemetrySnapshot) -> None:
        """Publish in mutation order without holding diagnostics state locks."""

        with self._notify_condition:
            while sequence != self._next_notification_sequence:
                self._notify_condition.wait()
            try:
                if self._on_snapshot is not None:
                    self._on_snapshot(snapshot)
            finally:
                self._next_notification_sequence += 1
                self._notify_condition.notify_all()


def _unavailable_health() -> DiagnosticHealth:
    return DiagnosticHealth(
        status=DiagnosticHealthStatus.UNAVAILABLE,
        cleaning_required=None,
    )


class DiagnosticExporter:
    """Build a bounded support bundle solely from closed, allowlisted fields.

    Daemon service/API composition is deliberately outside this hardware-free
    module; providers are injected and no catalog or device provider exists.
    """

    def __init__(
        self,
        *,
        version: str,
        health: Callable[[], DiagnosticHealth],
        telemetry: Callable[[], TelemetrySnapshot],
        logs: Callable[[int], Iterable[DiagnosticLogRecord]],
        utc_now: Callable[[], datetime],
        max_logs: int = 200,
        max_uncompressed_bytes: int = 256 * 1024,
    ) -> None:
        if not isinstance(version, str) or _SAFE_VERSION.fullmatch(version) is None:
            raise ValueError("version must contain only safe diagnostic characters")
        if isinstance(max_logs, bool) or not isinstance(max_logs, int) or max_logs < 0:
            raise ValueError("max_logs must be a non-negative integer")
        if (
            isinstance(max_uncompressed_bytes, bool)
            or not isinstance(max_uncompressed_bytes, int)
            or max_uncompressed_bytes <= 0
        ):
            raise ValueError("max_uncompressed_bytes must be a positive integer")
        self._version = version
        self._health = health
        self._telemetry = telemetry
        self._logs = logs
        self._utc_now = utc_now
        self._max_logs = max_logs
        self._max_uncompressed_bytes = max_uncompressed_bytes

    def create(self, destination: Path, *, include_catalog: bool = False) -> Path:
        if include_catalog is not False:
            raise ValueError(
                "catalog data is forbidden in the redacted diagnostic bundle"
            )
        destination = Path(destination)
        if destination.exists():
            raise FileExistsError(destination)
        if not destination.parent.is_dir():
            raise FileNotFoundError(destination.parent)

        generated_at = _aware_utc(self._utc_now())
        payloads = self._payloads(generated_at)
        if (
            sum(len(payload) for payload in payloads.values())
            > self._max_uncompressed_bytes
        ):
            raise ValueError("diagnostic bundle exceeds its uncompressed size bound")

        descriptor, temporary_name = tempfile.mkstemp(
            dir=destination.parent,
            prefix=".diagnostic-",
            suffix=".zip.tmp",
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            with zipfile.ZipFile(
                temporary, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as bundle:
                for name, payload in sorted(payloads.items()):
                    info = _zip_info(name, generated_at)
                    bundle.writestr(info, payload)
            os.link(temporary, destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination

    def _payloads(self, generated_at: datetime) -> dict[str, bytes]:
        health = self._safe_health(self._health())
        telemetry = self._telemetry()
        if not isinstance(telemetry, TelemetrySnapshot):
            raise TypeError("telemetry provider must return TelemetrySnapshot")
        log_records = tuple(
            self._safe_log(record)
            for record in islice(self._logs(self._max_logs), self._max_logs)
        )
        durations = telemetry.durations.to_diagnostic_payload()
        return {
            "version.json": _json_bytes(
                {
                    "generated_at": _rfc3339(generated_at),
                    "version": self._version,
                }
            ),
            "health.json": _json_bytes(health),
            "phase-summary.json": _json_bytes(
                {
                    "bytes_completed": telemetry.bytes_completed,
                    "closed": telemetry.closed,
                    "durations": durations,
                    "files_completed": telemetry.files_completed,
                }
            ),
            "logs.jsonl": b"".join(
                _json_bytes(record) + b"\n" for record in log_records
            ),
        }

    @staticmethod
    def _safe_health(raw: DiagnosticHealth) -> dict[str, object]:
        if type(raw) is not DiagnosticHealth:
            raise TypeError("health provider must return DiagnosticHealth")
        return {
            "cleaning_required": raw.cleaning_required,
            "status": raw.status.value,
            "tape_alert_codes": tuple(
                str(int(value)) for value in raw.tape_alert_codes
            ),
        }

    @staticmethod
    def _safe_log(raw: DiagnosticLogRecord) -> dict[str, str]:
        if type(raw) is not DiagnosticLogRecord:
            raise TypeError("logs provider must return DiagnosticLogRecord values")
        return {
            "code": raw.code.value,
            "level": raw.level.value,
            "occurred_at": raw.occurred_at,
        }


def _aware_utc(value: object) -> datetime:
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("utc_now must return an aware datetime")
    return value.astimezone(UTC)


def _parse_rfc3339(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ValueError("diagnostic log timestamp must be RFC3339") from error
    return _aware_utc(parsed)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _zip_info(name: str, generated_at: datetime) -> zipfile.ZipInfo:
    year = min(2107, max(1980, generated_at.year))
    info = zipfile.ZipInfo(
        filename=name,
        date_time=(
            year,
            generated_at.month,
            generated_at.day,
            generated_at.hour,
            generated_at.minute,
            generated_at.second,
        ),
    )
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = 0o600 << 16
    return info
