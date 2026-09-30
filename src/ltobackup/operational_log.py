"""Closed, redacted operational events for the host journal boundary."""

from __future__ import annotations

import re
import socket
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Final, Protocol

_SAFE_IDENTIFIER: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_JOURNAL_SOCKET: Final = "/run/systemd/journal/socket"
_SYSLOG_IDENTIFIER: Final = "lto-archiver"
_JOURNAL_ERROR_CODE: Final = "journald_unavailable"
_MAX_CASSETTE_SEQUENCE: Final = 2**31 - 1
_MIN_EXIT_CODE: Final = -(2**31)
_MAX_EXIT_CODE: Final = 2**31 - 1
_MAX_ELAPSED_MS: Final = 2**63 - 1
_MAX_DAEMON_GENERATION: Final = 2**63 - 1
_MAX_REPEAT_COUNT: Final = 2**31 - 1
_AUTHORIZATION: Final = re.compile(
    r"(?i)\bauthorization\s*:\s*(?:bearer|basic)\s+[^\s,;]+"
)
_SECRET_NAME: Final = (
    r"(?:password|passphrase|secret|token|api[-_]?key|"
    r"auth(?:entication|orization)?|cookie|session[-_]?cookie|"
    r"csrf(?:[-_]?token)?)"
)
_QUOTED_SECRET_VALUE: Final = r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')'''
_SECRET_ASSIGNMENT: Final = re.compile(
    rf"(?i)(?P<prefix>\b{_SECRET_NAME}\s*=\s*)"
    rf"(?:{_QUOTED_SECRET_VALUE}|[^\s&;,]+)"
)
_SECRET_COLON: Final = re.compile(
    rf"(?i)(?P<prefix>[\"']?{_SECRET_NAME}[\"']?\s*:\s*)"
    rf"(?:{_QUOTED_SECRET_VALUE}|[^\s,;}}\]]+)"
)
_SECRET_CLI: Final = re.compile(
    rf"(?i)(?P<prefix>--{_SECRET_NAME}\s+)"
    rf"(?:{_QUOTED_SECRET_VALUE}|[^\s&;,]+)"
)
_URL_USERINFO: Final = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^\s/@]+@")


class OperationalSource(StrEnum):
    DAEMON = "daemon"
    WEBUI = "webui"
    LTFS = "ltfs"
    COMMAND_BROKER = "command_broker"
    SHARE_BROKER = "share_broker"
    QUALIFICATION = "qualification"


class OperationalSeverity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class OperationalCorrelation:
    """Closed correlation copied from already-durable operation metadata."""

    operation_id: str | None = None
    job_id: str | None = None
    cassette_label: str | None = None
    cassette_sequence: int | None = None
    command_id: str | None = None
    daemon_generation: int | None = None

    def __post_init__(self) -> None:
        for name, value in (
            ("operation ID", self.operation_id),
            ("job ID", self.job_id),
            ("cassette label", self.cassette_label),
            ("command ID", self.command_id),
        ):
            if value is not None:
                _require_identifier(value, name)
        if self.cassette_sequence is not None and (
            type(self.cassette_sequence) is not int
            or not 1 <= self.cassette_sequence <= _MAX_CASSETTE_SEQUENCE
        ):
            raise ValueError("cassette sequence must be a bounded positive integer")
        if self.daemon_generation is not None and (
            type(self.daemon_generation) is not int
            or not 0 <= self.daemon_generation <= _MAX_DAEMON_GENERATION
        ):
            raise ValueError("daemon generation must be a bounded non-negative integer")


def closed_operational_correlation(
    *,
    operation_id: object = None,
    job_id: object = None,
    cassette_label: object = None,
    cassette_sequence: object = None,
    command_id: object = None,
    daemon_generation: object = None,
) -> OperationalCorrelation:
    """Drop unsafe optional metadata instead of affecting the owning operation."""

    def identifier(value: object) -> str | None:
        return (
            value
            if isinstance(value, str) and _SAFE_IDENTIFIER.fullmatch(value)
            else None
        )

    sequence = (
        cassette_sequence
        if type(cassette_sequence) is int
        and 1 <= cassette_sequence <= _MAX_CASSETTE_SEQUENCE
        else None
    )
    generation = (
        daemon_generation
        if type(daemon_generation) is int
        and 0 <= daemon_generation <= _MAX_DAEMON_GENERATION
        else None
    )
    return OperationalCorrelation(
        operation_id=identifier(operation_id),
        job_id=identifier(job_id),
        cassette_label=identifier(cassette_label),
        cassette_sequence=sequence,
        command_id=identifier(command_id),
        daemon_generation=generation,
    )


@dataclass(frozen=True, slots=True)
class OperationalEvent:
    source: OperationalSource
    severity: OperationalSeverity
    code: str
    message: str
    operation_id: str | None = None
    job_id: str | None = None
    cassette_label: str | None = None
    cassette_sequence: int | None = None
    command_id: str | None = None
    daemon_generation: int | None = None
    command_kind: str | None = None
    phase: str | None = None
    exit_code: int | None = None
    elapsed_ms: int | None = None
    repeat_count: int = 1
    truncated: bool = False

    def __post_init__(self) -> None:
        if type(self.source) is not OperationalSource:
            raise TypeError("operational source must be closed")
        if type(self.severity) is not OperationalSeverity:
            raise TypeError("operational severity must be closed")
        _require_identifier(self.code, "code")
        if not isinstance(self.message, str):
            raise TypeError("operational message must be text")
        for name, value in (
            ("operation ID", self.operation_id),
            ("job ID", self.job_id),
            ("cassette label", self.cassette_label),
            ("command ID", self.command_id),
            ("command kind", self.command_kind),
            ("phase", self.phase),
        ):
            if value is not None:
                _require_identifier(value, name)
        if self.cassette_sequence is not None and (
            type(self.cassette_sequence) is not int
            or not 1 <= self.cassette_sequence <= _MAX_CASSETTE_SEQUENCE
        ):
            raise ValueError("cassette sequence must be a bounded positive integer")
        if self.daemon_generation is not None and (
            type(self.daemon_generation) is not int
            or not 0 <= self.daemon_generation <= _MAX_DAEMON_GENERATION
        ):
            raise ValueError("daemon generation must be a bounded non-negative integer")
        if self.exit_code is not None and (
            type(self.exit_code) is not int
            or not _MIN_EXIT_CODE <= self.exit_code <= _MAX_EXIT_CODE
        ):
            raise ValueError("exit code must be a bounded integer")
        if self.elapsed_ms is not None and (
            type(self.elapsed_ms) is not int
            or not 0 <= self.elapsed_ms <= _MAX_ELAPSED_MS
        ):
            raise ValueError("elapsed milliseconds must be a bounded non-negative integer")
        if (
            type(self.repeat_count) is not int
            or not 1 <= self.repeat_count <= _MAX_REPEAT_COUNT
        ):
            raise ValueError("repeat count must be a bounded positive integer")
        if type(self.truncated) is not bool:
            raise TypeError("truncated must be a boolean")


class OperationalEventSink(Protocol):
    def emit(self, event: OperationalEvent) -> None:
        """Emit one closed operational event without raising operational errors."""


class NullOperationalEventSink:
    """An event sink for callers that do not have a journal destination."""

    def emit(self, event: OperationalEvent) -> None:
        if not isinstance(event, OperationalEvent):
            raise TypeError("operational event is required")


class OperationalPhaseTracker:
    """Emit one terminal result for each started phase attempt."""

    def __init__(
        self,
        sink: OperationalEventSink,
        correlation: OperationalCorrelation,
    ) -> None:
        if not isinstance(correlation, OperationalCorrelation):
            raise TypeError("operational correlation is required")
        self._sink = sink
        self._correlation = correlation
        self._open: list[tuple[str, bool]] = []

    def start(self, phase: str, *, read_only: bool = False) -> bool:
        _require_phase_attempt(phase, read_only)
        key = (phase, read_only)
        if key in self._open:
            return False
        self._open.append(key)
        emit_operational_phase(
            self._sink,
            self._correlation,
            phase,
            "started",
            read_only=read_only,
        )
        return True

    def succeed(self, phase: str, *, read_only: bool = False) -> bool:
        return self._terminal(phase, "succeeded", read_only=read_only)

    def fail(self, phase: str, *, read_only: bool = False) -> bool:
        return self._terminal(phase, "failed", read_only=read_only)

    def fail_open(self) -> None:
        for phase, read_only in tuple(self._open):
            self.fail(phase, read_only=read_only)

    def _terminal(self, phase: str, result: str, *, read_only: bool) -> bool:
        _require_phase_attempt(phase, read_only)
        key = (phase, read_only)
        if key not in self._open:
            return False
        self._open.remove(key)
        emit_operational_phase(
            self._sink,
            self._correlation,
            phase,
            result,
            read_only=read_only,
        )
        return True


class JournalOperationalEventSink:
    """Best-effort journald native-protocol sink with a closed field allowlist."""

    def __init__(
        self,
        *,
        send: Callable[[bytes], object] | None = None,
        socket_path: str = _JOURNAL_SOCKET,
        on_error: Callable[[str], object] | None = None,
        syslog_identifier: str = _SYSLOG_IDENTIFIER,
    ) -> None:
        if send is not None and not callable(send):
            raise TypeError("journal send callback must be callable")
        if (
            not isinstance(socket_path, str)
            or not socket_path.startswith("/")
            or "\x00" in socket_path
        ):
            raise ValueError("journal socket path must be absolute")
        if on_error is not None and not callable(on_error):
            raise TypeError("journal error callback must be callable")
        _require_identifier(syslog_identifier, "syslog identifier")
        self._send = send
        self._socket_path = socket_path
        self._on_error = on_error
        self._syslog_identifier = syslog_identifier

    def emit(self, event: OperationalEvent) -> None:
        if not isinstance(event, OperationalEvent):
            raise TypeError("operational event is required")
        try:
            message, message_truncated = redact_operational_message(event.message)
            payload = _serialize_journal_event(
                event,
                message=message,
                truncated=event.truncated or message_truncated,
                syslog_identifier=self._syslog_identifier,
            )
            if self._send is None:
                self._send_to_journal(payload)
            else:
                self._send(payload)
        except BaseException:  # noqa: BLE001 - journald must never affect tape work
            self._report_unavailable()

    def _send_to_journal(self, payload: bytes) -> None:
        journal = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            journal.setblocking(False)
            journal.connect(self._socket_path)
            journal.send(payload)
        finally:
            journal.close()

    def _report_unavailable(self) -> None:
        if self._on_error is None:
            return
        try:
            self._on_error(_JOURNAL_ERROR_CODE)
        except BaseException:  # noqa: BLE001, S110 - callback is diagnostics only
            pass


_OPERATIONAL_PHASES: Final = frozenset(
    {
        "identify",
        "format",
        "mount",
        "copy",
        "sync",
        "finalizing_index",
        "unmount",
        "eject",
        "commit",
        "media_wait",
    }
)
_OPERATIONAL_RESULTS: Final = frozenset({"started", "succeeded", "failed"})


def _require_phase_attempt(phase: str, read_only: bool) -> None:
    if phase not in _OPERATIONAL_PHASES:
        raise ValueError("operational phase is not closed")
    if type(read_only) is not bool:
        raise TypeError("read-only marker must be boolean")


def emit_operational_phase(
    sink: OperationalEventSink,
    correlation: OperationalCorrelation,
    phase: str,
    result: str,
    *,
    read_only: bool = False,
    message: str | None = None,
) -> None:
    """Best-effort phase event at a caller-owned durable lifecycle boundary."""

    if not isinstance(correlation, OperationalCorrelation):
        raise TypeError("operational correlation is required")
    if phase not in _OPERATIONAL_PHASES:
        raise ValueError("operational phase is not closed")
    if result not in _OPERATIONAL_RESULTS:
        raise ValueError("operational phase result is not closed")
    if type(read_only) is not bool:
        raise TypeError("read-only marker must be boolean")
    effective_phase = "mount_read_only" if phase == "mount" and read_only else phase
    severity = (
        OperationalSeverity.ERROR
        if result == "failed"
        else OperationalSeverity.INFO
    )
    try:
        safe_message, truncated = redact_operational_message(
            message or f"LTFS {effective_phase} {result}."
        )
        sink.emit(
            OperationalEvent(
                source=OperationalSource.LTFS,
                severity=severity,
                code=f"ltfs.phase.{result}",
                message=safe_message,
                operation_id=correlation.operation_id,
                job_id=correlation.job_id,
                cassette_label=correlation.cassette_label,
                cassette_sequence=correlation.cassette_sequence,
                command_id=correlation.command_id,
                daemon_generation=correlation.daemon_generation,
                phase=effective_phase,
                truncated=truncated,
            )
        )
    except BaseException:  # noqa: BLE001 - diagnostics never change tape work
        return


def redact_operational_message(value: object, *, limit: int = 4096) -> tuple[str, bool]:
    """Return safe UTF-8 operational text and whether its byte limit was reached."""

    if type(limit) is not int or limit < 1:
        raise ValueError("message limit must be a positive integer")
    text = _safe_text(value)
    text = _replace_controls(text)
    text = _URL_USERINFO.sub(r"\1<redacted>@", text)
    text = _AUTHORIZATION.sub("Authorization: <redacted>", text)
    text = _SECRET_ASSIGNMENT.sub(_redacted_secret_value, text)
    text = _SECRET_COLON.sub(_redacted_secret_value, text)
    text = _SECRET_CLI.sub(_redacted_secret_value, text)
    return _truncate_utf8(text, limit)


def coalesce_operational_lines(
    lines: tuple[str, ...], *, max_bytes: int = 32768
) -> tuple[tuple[tuple[str, int], ...], bool]:
    """Redact, coalesce, and cap consecutive command-output lines by UTF-8 bytes."""

    if not isinstance(lines, tuple) or any(not isinstance(line, str) for line in lines):
        raise TypeError("operational lines must be a tuple of text lines")
    if type(max_bytes) is not int or max_bytes < 1:
        raise ValueError("maximum bytes must be a positive integer")

    grouped: list[tuple[str, int]] = []
    redaction_truncated = False
    for line in lines:
        safe_line, line_truncated = redact_operational_message(line)
        redaction_truncated = redaction_truncated or line_truncated
        if grouped and grouped[-1][0] == safe_line:
            previous_line, previous_count = grouped[-1]
            grouped[-1] = (previous_line, previous_count + 1)
        else:
            grouped.append((safe_line, 1))

    result: list[tuple[str, int]] = []
    used_bytes = 0
    output_truncated = redaction_truncated
    for line, repeat_count in grouped:
        line_bytes = len(line.encode("utf-8"))
        remaining = max_bytes - used_bytes
        if line_bytes <= remaining:
            result.append((line, repeat_count))
            used_bytes += line_bytes
            continue
        if remaining:
            partial_line, _ = _truncate_utf8(line, remaining)
            if partial_line:
                result.append((partial_line, repeat_count))
        output_truncated = True
        break
    return tuple(result), output_truncated


def _require_identifier(value: object, name: str) -> None:
    if not isinstance(value, str) or _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{name} must be a safe ASCII identifier")


def _safe_text(value: object) -> str:
    value_type = type(value)
    if (
        value_type.__name__ == "SecretArgument"
        and value_type.__module__ == "ltobackup.tape.command_supervisor"
    ):
        return "<redacted>"
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if isinstance(value, str):
        return value
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - diagnostics must be closed even for hostile objects
        return "<unavailable>"


def _replace_controls(value: str) -> str:
    return "".join(
        " " if ord(character) < 32 or 127 <= ord(character) <= 159 else character
        for character in value
    )


def _redacted_secret_value(match: re.Match[str]) -> str:
    return match.group("prefix") + "<redacted>"


def _truncate_utf8(value: str, limit: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return encoded.decode("utf-8", "replace"), False
    return encoded[:limit].decode("utf-8", "ignore"), True


def _serialize_journal_event(
    event: OperationalEvent,
    *,
    message: str,
    truncated: bool,
    syslog_identifier: str = _SYSLOG_IDENTIFIER,
) -> bytes:
    fields: list[tuple[str, str]] = [
        ("MESSAGE", message),
        ("PRIORITY", _journal_priority(event.severity)),
        ("SYSLOG_IDENTIFIER", syslog_identifier),
        ("LTO_ARCHIVER_SOURCE", event.source.value),
        ("LTO_ARCHIVER_CODE", event.code),
    ]
    for field, value in (
        ("LTO_ARCHIVER_OPERATION_ID", event.operation_id),
        ("LTO_ARCHIVER_JOB_ID", event.job_id),
        ("LTO_ARCHIVER_CASSETTE_LABEL", event.cassette_label),
        ("LTO_ARCHIVER_CASSETTE_SEQUENCE", event.cassette_sequence),
        ("LTO_ARCHIVER_COMMAND_ID", event.command_id),
        ("LTO_ARCHIVER_DAEMON_GENERATION", event.daemon_generation),
        ("LTO_ARCHIVER_COMMAND_KIND", event.command_kind),
        ("LTO_ARCHIVER_PHASE", event.phase),
        ("LTO_ARCHIVER_EXIT_CODE", event.exit_code),
        ("LTO_ARCHIVER_ELAPSED_MS", event.elapsed_ms),
    ):
        if value is not None:
            fields.append((field, str(value)))
    if event.repeat_count != 1:
        fields.append(("LTO_ARCHIVER_REPEAT_COUNT", str(event.repeat_count)))
    if truncated:
        fields.append(("LTO_ARCHIVER_TRUNCATED", "1"))
    return b"".join(
        f"{field}={value}\n".encode() for field, value in fields
    )


def _journal_priority(severity: OperationalSeverity) -> str:
    return {
        OperationalSeverity.DEBUG: "7",
        OperationalSeverity.INFO: "6",
        OperationalSeverity.WARNING: "4",
        OperationalSeverity.ERROR: "3",
    }[severity]
