from __future__ import annotations

import json
import os
import selectors
import signal
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from ltobackup.operational_log import redact_operational_message

from .protocol import (
    MAX_FRAME_BYTES,
    JournalEntry,
    JournalPage,
    JournalQuery,
    LogDirection,
    LogRange,
    LogSource,
    ProtocolError,
    Severity,
    decode_request,
    encode_response,
)

JOURNALCTL = "/usr/bin/journalctl"
JOURNAL_TIMEOUT_SECONDS = 5.0
MAX_JOURNAL_OUTPUT_BYTES = 2 * 1024 * 1024
_CANDIDATE_LIMIT = 200
_PROCESS_GROUP_GRACE_SECONDS = 1.0
_PROCESS_GROUP_KILL_AFTER_SECONDS = 0.2
_PIPE_POLL_SECONDS = 0.05
_ENV = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"}
_RANGE_SINCE = {
    LogRange.ONE_HOUR: "1 hour ago",
    LogRange.SIX_HOURS: "6 hours ago",
    LogRange.ONE_DAY: "24 hours ago",
    LogRange.SEVEN_DAYS: "7 days ago",
    LogRange.THIRTY_DAYS: "30 days ago",
}
_SOURCE_UNITS: Mapping[LogSource, tuple[str, ...]] = {
    LogSource.DAEMON: ("lto-archiverd.service",),
    LogSource.WEBUI: ("lto-archiver-web.service",),
    LogSource.LTFS: (
        "lto-archiverd.service",
        "lto-archiver-command-broker.service",
        "lto-archiver-ltfs-qualification.service",
        "lto-archiver-archive-runner-qualification.service",
    ),
    LogSource.COMMAND_BROKER: ("lto-archiver-command-broker.service",),
    LogSource.SHARE_BROKER: ("lto-archiver-share-broker.service",),
    LogSource.QUALIFICATION: (
        "lto-archiver-ltfs-qualification.service",
        "lto-archiver-archive-runner-qualification.service",
    ),
}
_ALL_UNITS = tuple(sorted({unit for units in _SOURCE_UNITS.values() for unit in units}))
_UNIT_SOURCE = {
    "lto-archiverd.service": LogSource.DAEMON,
    "lto-archiver-web.service": LogSource.WEBUI,
    "lto-archiver-command-broker.service": LogSource.COMMAND_BROKER,
    "lto-archiver-share-broker.service": LogSource.SHARE_BROKER,
    "lto-archiver-ltfs-qualification.service": LogSource.QUALIFICATION,
    "lto-archiver-archive-runner-qualification.service": LogSource.QUALIFICATION,
}
_PRIORITY_SEVERITY = {
    0: Severity.ERROR,
    1: Severity.ERROR,
    2: Severity.ERROR,
    3: Severity.ERROR,
    4: Severity.WARNING,
    5: Severity.INFO,
    6: Severity.INFO,
    7: Severity.DEBUG,
}
_SEVERITY_MAX_PRIORITY = {
    Severity.DEBUG: 7,
    Severity.INFO: 6,
    Severity.WARNING: 4,
    Severity.ERROR: 3,
}
_STRUCTURED_FIELDS = {
    "LTO_ARCHIVER_SOURCE": "source",
    "LTO_ARCHIVER_OPERATION_ID": "operation_id",
    "LTO_ARCHIVER_JOB_ID": "job_id",
    "LTO_ARCHIVER_CASSETTE_LABEL": "cassette_label",
    "LTO_ARCHIVER_CASSETTE_SEQUENCE": "cassette_sequence",
    "LTO_ARCHIVER_COMMAND_ID": "command_id",
    "LTO_ARCHIVER_DAEMON_GENERATION": "daemon_generation",
    "LTO_ARCHIVER_COMMAND_KIND": "command_kind",
    "LTO_ARCHIVER_PHASE": "phase",
    "LTO_ARCHIVER_EXIT_CODE": "exit_code",
    "LTO_ARCHIVER_ELAPSED_MS": "elapsed_ms",
    "LTO_ARCHIVER_REPEAT_COUNT": "repeat_count",
    "LTO_ARCHIVER_TRUNCATED": "truncated",
}


class JournalReaderUnavailable(RuntimeError):
    """Closed failure from the privileged, read-only journal boundary."""

    def __init__(self, *, cursor_rotated: bool = False) -> None:
        self.cursor_rotated = cursor_rotated
        super().__init__("journal reader unavailable")


def _default_run_command(
    argv: tuple[str, ...],
    *,
    timeout: float,
    env: Mapping[str, str],
    max_output_bytes: int,
) -> subprocess.CompletedProcess[str]:
    process = subprocess.Popen(
        argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=dict(env),
        start_new_session=True,
    )
    if process.stdout is None or process.stderr is None:
        raise JournalReaderUnavailable
    streams = (process.stdout, process.stderr)
    buffers = [bytearray(), bytearray()]
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    shutdown_started: float | None = None
    group_shutdown = False
    kill_sent = False
    overflow = False
    timed_out = False
    cleanup_failed = False

    def signal_group(signal_number: signal.Signals) -> None:
        try:
            os.killpg(process.pid, signal_number)
        except ProcessLookupError:
            pass

    def group_exists() -> bool:
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return False
        return True

    def begin_shutdown(now: float, *, terminate_group: bool) -> None:
        nonlocal group_shutdown, shutdown_started
        if shutdown_started is None:
            shutdown_started = now
            group_shutdown = terminate_group
            if terminate_group:
                signal_group(signal.SIGTERM)

    try:
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        while True:
            now = time.monotonic()
            returncode = process.poll()
            active_streams = bool(selector.get_map())
            active_group = group_exists()

            if shutdown_started is None:
                if overflow:
                    begin_shutdown(now, terminate_group=returncode is None or active_group)
                elif returncode is None and now >= deadline:
                    timed_out = True
                    begin_shutdown(now, terminate_group=True)
                elif returncode is not None and (active_streams or active_group):
                    begin_shutdown(now, terminate_group=active_group)
                elif returncode is not None:
                    break
            else:
                elapsed = now - shutdown_started
                if (
                    group_shutdown
                    and not kill_sent
                    and elapsed >= _PROCESS_GROUP_KILL_AFTER_SECONDS
                ):
                    signal_group(signal.SIGKILL)
                    kill_sent = True
                if returncode is not None and not active_streams and not active_group:
                    break
                if elapsed >= _PROCESS_GROUP_GRACE_SECONDS:
                    if group_shutdown:
                        signal_group(signal.SIGKILL)
                    cleanup_failed = active_streams or returncode is None or active_group
                    break

            if selector.get_map():
                wait_until = (
                    deadline
                    if shutdown_started is None
                    else shutdown_started + _PROCESS_GROUP_GRACE_SECONDS
                )
                wait = max(0.0, min(_PIPE_POLL_SECONDS, wait_until - now))
                ready = selector.select(wait)
                for key, _events in ready:
                    stream = key.fileobj
                    try:
                        chunk = os.read(stream.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    remaining = max_output_bytes - sum(map(len, buffers))
                    if remaining > 0:
                        buffers[key.data].extend(chunk[:remaining])
                    if len(chunk) > remaining:
                        overflow = True
                        begin_shutdown(
                            time.monotonic(),
                            terminate_group=process.poll() is None or group_exists(),
                        )
            else:
                time.sleep(_PIPE_POLL_SECONDS)
    finally:
        if process.poll() is None:
            signal_group(signal.SIGKILL)
            try:
                process.wait(timeout=_PIPE_POLL_SECONDS)
            except subprocess.TimeoutExpired:
                cleanup_failed = True
        selector.close()
        for stream in streams:
            stream.close()
    if overflow or cleanup_failed:
        raise JournalReaderUnavailable
    if timed_out:
        raise subprocess.TimeoutExpired(argv, timeout)
    return subprocess.CompletedProcess(
        argv,
        process.returncode,
        bytes(buffers[0]).decode("utf-8", "replace"),
        bytes(buffers[1]).decode("utf-8", "replace"),
    )


class JournalReaderService:
    """Constrained reader which owns the only journalctl invocation seam."""

    def __init__(
        self,
        *,
        run_command: Callable[
            ..., subprocess.CompletedProcess[str]
        ] = _default_run_command,
        daemon_uid: int = 0,
        daemon_gid: int = 0,
        connection_timeout: float = 6.0,
    ) -> None:
        if (
            not callable(run_command)
            or type(daemon_uid) is not int
            or type(daemon_gid) is not int
            or min(daemon_uid, daemon_gid) < 0
            or type(connection_timeout) not in (int, float)
            or type(connection_timeout) is bool
            or not 0 < float(connection_timeout) <= 6.0
        ):
            raise ValueError("invalid journal reader policy")
        self._run_command = run_command
        self.daemon_uid = daemon_uid
        self.daemon_gid = daemon_gid
        self.connection_timeout = float(connection_timeout)

    def query(self, request: JournalQuery) -> JournalPage:
        if type(request) is not JournalQuery:
            raise JournalReaderUnavailable
        try:
            result = self._run_command(
                self._argv(request),
                timeout=JOURNAL_TIMEOUT_SECONDS,
                env=dict(_ENV),
                max_output_bytes=MAX_JOURNAL_OUTPUT_BYTES,
            )
            if (
                type(result) is not subprocess.CompletedProcess
                or type(result.returncode) is not int
                or type(result.stdout) is not str
                or type(result.stderr) is not str
                or len(result.stdout.encode("utf-8")) > MAX_JOURNAL_OUTPUT_BYTES
                or len(result.stderr.encode("utf-8")) > MAX_JOURNAL_OUTPUT_BYTES
            ):
                raise JournalReaderUnavailable
            if result.returncode != 0:
                if request.cursor is not None and "cursor" in result.stderr.lower():
                    return JournalPage((), None, None, True)
                raise JournalReaderUnavailable
            return self._parse_page(request, result.stdout)
        except JournalReaderUnavailable:
            raise
        except Exception:  # noqa: BLE001 - no journal/subprocess diagnostic crosses this boundary
            raise JournalReaderUnavailable from None

    def handle_packet(self, packet: bytes, *, peer_uid: int, peer_gid: int) -> bytes:
        if peer_uid != self.daemon_uid or peer_gid != self.daemon_gid:
            raise PermissionError("journal reader authentication denied")
        return encode_response(self.query(decode_request(packet)))

    def handle_connection(self, connection: socket.socket) -> None:
        if (
            type(connection) is not socket.socket
            or connection.family != socket.AF_UNIX
            or connection.type & 0xF != socket.SOCK_STREAM
        ):
            raise PermissionError("journal reader authentication denied")
        connection.settimeout(self.connection_timeout)
        uid, gid = _peer_identity(connection)
        if uid != self.daemon_uid or gid != self.daemon_gid:
            raise PermissionError("journal reader authentication denied")
        packet = _read_one_request(connection)
        response = self.handle_packet(packet, peer_uid=uid, peer_gid=gid)
        connection.sendall(response)
        connection.shutdown(socket.SHUT_WR)

    def serve(self, listener: socket.socket, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            with connection:
                try:
                    self.handle_connection(connection)
                except Exception:  # noqa: BLE001,S112 - unauthenticated peers receive no diagnostic
                    continue

    def _argv(self, request: JournalQuery) -> tuple[str, ...]:
        argv: list[str] = [
            JOURNALCTL,
            "--output=json",
            "--no-pager",
            "--quiet",
            f"--lines={_CANDIDATE_LIMIT}",
        ]
        since = _RANGE_SINCE.get(request.range)
        if since is not None:
            argv.append(f"--since={since}")
        if request.direction is LogDirection.OLDER:
            argv.append("--reverse")
        if request.cursor is not None:
            argv.append(f"--after-cursor={request.cursor}")
        units = (
            _ALL_UNITS
            if request.source is LogSource.ALL
            else _SOURCE_UNITS[request.source]
        )
        argv.extend(f"_SYSTEMD_UNIT={unit}" for unit in units)
        if request.source is LogSource.LTFS:
            argv.append("LTO_ARCHIVER_SOURCE=ltfs")
            argv.append("+")
            argv.extend(f"_SYSTEMD_UNIT={unit}" for unit in units)
            argv.append("_EXE=/usr/bin/ltfs")
        argv.append(f"--priority=0..{_SEVERITY_MAX_PRIORITY[request.minimum_severity]}")
        return tuple(argv)

    def _parse_page(self, request: JournalQuery, stdout: str) -> JournalPage:
        if len(stdout.encode("utf-8")) > MAX_JOURNAL_OUTPUT_BYTES:
            raise JournalReaderUnavailable
        candidates: list[JournalEntry] = []
        unavailable_sources: set[LogSource] = set()
        raw_candidate_count = 0
        for line in stdout.splitlines():
            if not line:
                continue
            raw_candidate_count += 1
            if raw_candidate_count > _CANDIDATE_LIMIT:
                raise JournalReaderUnavailable
            try:
                entry = _parse_entry(line)
            except JournalReaderUnavailable:
                source = _attributable_source(line)
                if request.source is not LogSource.ALL or source is None:
                    raise
                unavailable_sources.add(source)
                candidates = [
                    entry for entry in candidates if entry.source is not source
                ]
                continue
            if entry is None:
                if request.source is LogSource.ALL:
                    source = _attributable_source(line)
                    if source is None:
                        raise JournalReaderUnavailable
                    unavailable_sources.add(source)
                    candidates = [
                        entry for entry in candidates if entry.source is not source
                    ]
                continue
            if entry.source in unavailable_sources:
                continue
            candidates.append(entry)

        entries: list[JournalEntry] = []
        boundary: list[JournalEntry] = []
        for entry in candidates:
            priority = _SEVERITY_MAX_PRIORITY[entry.severity]
            if priority > _SEVERITY_MAX_PRIORITY[request.minimum_severity]:
                continue
            if (
                request.source is not LogSource.ALL
                and entry.source is not request.source
            ):
                continue
            entries.append(entry)
            boundary.append(entry)
            if len(entries) == request.limit:
                break
        if not entries:
            boundary = candidates
        if request.direction is LogDirection.OLDER:
            older_cursor = boundary[-1].cursor if boundary else None
            newer_cursor = boundary[0].cursor if boundary else None
        else:
            older_cursor = boundary[0].cursor if boundary else None
            newer_cursor = boundary[-1].cursor if boundary else None
        page = JournalPage(
            entries=tuple(entries),
            older_cursor=older_cursor,
            newer_cursor=newer_cursor,
            cursor_rotated=False,
            unavailable_sources=tuple(
                sorted(unavailable_sources, key=lambda source: source.value)
            ),
        )
        try:
            encode_response(page)
        except ProtocolError:
            raise JournalReaderUnavailable from None
        return page


class _DuplicateKey(ValueError):
    pass


def _parse_entry(line: str) -> JournalEntry | None:
    try:
        value = json.loads(
            line,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, _DuplicateKey, ValueError):
        raise JournalReaderUnavailable from None
    if type(value) is not dict:
        raise JournalReaderUnavailable
    unit = value.get("_SYSTEMD_UNIT")
    if type(unit) is not str or unit not in _UNIT_SOURCE:
        return None
    priority = value.get("PRIORITY")
    if not _priority_value(priority):
        raise JournalReaderUnavailable
    source = _entry_source(value.get("LTO_ARCHIVER_SOURCE"), unit, value.get("_EXE"))
    if source is None:
        return None
    cursor = value.get("__CURSOR")
    timestamp = _timestamp(value.get("__REALTIME_TIMESTAMP"))
    message = value.get("MESSAGE")
    if type(cursor) is not str or timestamp is None or type(message) is not str:
        raise JournalReaderUnavailable
    redacted_message, truncated = redact_operational_message(message)
    structured = _structured_values(value)
    try:
        return JournalEntry(
            cursor=cursor,
            timestamp=timestamp,
            source=source,
            severity=_PRIORITY_SEVERITY[int(priority)],
            unit=unit,
            message=redacted_message,
            operation_id=structured["operation_id"],
            job_id=structured["job_id"],
            cassette_label=structured["cassette_label"],
            cassette_sequence=structured["cassette_sequence"],
            command_id=structured["command_id"],
            daemon_generation=structured["daemon_generation"],
            command_kind=structured["command_kind"],
            phase=structured["phase"],
            exit_code=structured["exit_code"],
            elapsed_ms=structured["elapsed_ms"],
            repeat_count=structured["repeat_count"],
            truncated=truncated or structured["truncated"],
            pid=_optional_integer(value.get("_PID")),
            boot_id=_optional_string(value.get("_BOOT_ID")),
        )
    except (TypeError, ValueError):
        raise JournalReaderUnavailable from None


def _structured_values(value: Mapping[str, object]) -> dict[str, object]:
    result: dict[str, object] = {
        "operation_id": None,
        "job_id": None,
        "cassette_label": None,
        "cassette_sequence": None,
        "command_id": None,
        "daemon_generation": None,
        "command_kind": None,
        "phase": None,
        "exit_code": None,
        "elapsed_ms": None,
        "repeat_count": 1,
        "truncated": False,
    }
    for field, destination in _STRUCTURED_FIELDS.items():
        if field not in value or field == "LTO_ARCHIVER_SOURCE":
            continue
        raw = value[field]
        if destination in {
            "cassette_sequence",
            "daemon_generation",
            "exit_code",
            "elapsed_ms",
            "repeat_count",
        }:
            parsed = (
                _signed_integer(raw)
                if destination == "exit_code"
                else _optional_integer(raw)
            )
            if parsed is None or (destination == "repeat_count" and parsed < 1):
                raise JournalReaderUnavailable
            result[destination] = parsed
        elif destination == "truncated":
            if raw not in ("0", "1"):
                raise JournalReaderUnavailable
            result[destination] = raw == "1"
        elif type(raw) is not str:
            raise JournalReaderUnavailable
        else:
            result[destination] = raw
    return result


def _entry_source(raw: object, unit: str, executable: object = None) -> LogSource | None:
    unit_source = _UNIT_SOURCE[unit]
    if raw is None:
        # _EXE and _SYSTEMD_UNIT are journal-owned metadata. Process names,
        # syslog identifiers and message prefixes are caller-controlled.
        if executable == "/usr/bin/ltfs" and unit in _SOURCE_UNITS[LogSource.LTFS]:
            return LogSource.LTFS
        return unit_source
    if type(raw) is not str:
        raise JournalReaderUnavailable
    try:
        source = LogSource(raw)
    except ValueError:
        raise JournalReaderUnavailable from None
    if source is LogSource.ALL:
        raise JournalReaderUnavailable
    if source is LogSource.LTFS:
        return source if unit in _SOURCE_UNITS[LogSource.LTFS] else None
    return source if source is unit_source else None


def _attributable_source(line: str) -> LogSource | None:
    try:
        value = json.loads(
            line,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, _DuplicateKey, ValueError):
        return None
    if type(value) is not dict:
        return None
    unit = value.get("_SYSTEMD_UNIT")
    if type(unit) is not str or unit not in _UNIT_SOURCE:
        return None
    try:
        return _entry_source(value.get("LTO_ARCHIVER_SOURCE"), unit, value.get("_EXE"))
    except JournalReaderUnavailable:
        return None


def _priority(line: str) -> int:
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        raise JournalReaderUnavailable from None
    priority = value.get("PRIORITY") if type(value) is dict else None
    if not _priority_value(priority):
        raise JournalReaderUnavailable
    return int(priority)


def _priority_value(value: object) -> bool:
    return (type(value) is int and 0 <= value <= 7) or (
        type(value) is str and value in {str(index) for index in range(8)}
    )


def _timestamp(value: object) -> str | None:
    if type(value) is not str or not value.isdecimal():
        return None
    try:
        microseconds = int(value)
        if microseconds <= 0:
            return None
        seconds, remainder = divmod(microseconds, 1_000_000)
        return (
            datetime.fromtimestamp(seconds, UTC)
            .replace(microsecond=remainder)
            .isoformat()
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return None


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is int and value >= 0:
        return value
    if type(value) is str and value.isdecimal():
        return int(value)
    raise JournalReaderUnavailable


def _signed_integer(value: object) -> int | None:
    if value is None:
        return None
    if type(value) is int:
        return value
    if type(value) is str and value.lstrip("-").isdecimal() and value != "-":
        return int(value)
    raise JournalReaderUnavailable


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if type(value) is str:
        return value
    raise JournalReaderUnavailable


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise ValueError


def _peer_identity(connection: socket.socket) -> tuple[int, int]:
    size = struct.calcsize("3i")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    if type(raw) is not bytes or len(raw) != size:
        raise PermissionError("journal reader authentication denied")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise PermissionError("journal reader authentication denied")
    return uid, gid


def _read_one_request(connection: socket.socket) -> bytes:
    header = _read_exact(connection, 4)
    length = int.from_bytes(header, "big")
    if not 0 < length <= MAX_FRAME_BYTES:
        raise ProtocolError
    packet = header + _read_exact(connection, length)
    if connection.recv(1):
        raise ProtocolError
    return packet


def _read_exact(connection: socket.socket, size: int) -> bytes:
    parts: list[bytes] = []
    remaining = size
    while remaining:
        part = connection.recv(remaining)
        if not part:
            raise ProtocolError
        parts.append(part)
        remaining -= len(part)
    return b"".join(parts)
