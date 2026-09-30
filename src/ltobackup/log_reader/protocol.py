from __future__ import annotations

import json
import struct
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 256 * 1024
MAX_CURSOR_CHARS = 2_048
MAX_PAGE_ENTRIES = 200
MAX_CASSETTE_SEQUENCE = 2**31 - 1
MIN_EXIT_CODE = -(2**31)
MAX_EXIT_CODE = 2**31 - 1
MAX_ELAPSED_MS = 2**63 - 1
MAX_REPEAT_COUNT = 2**31 - 1
MAX_PID = 2**31 - 1


class ProtocolError(ValueError):
    """Raised for every malformed or out-of-policy reader packet."""

    def __init__(self) -> None:
        super().__init__("invalid journal reader protocol")


class LogSource(StrEnum):
    ALL = "all"
    DAEMON = "daemon"
    WEBUI = "webui"
    LTFS = "ltfs"
    COMMAND_BROKER = "command_broker"
    SHARE_BROKER = "share_broker"
    QUALIFICATION = "qualification"


class Severity(StrEnum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class LogRange(StrEnum):
    ONE_HOUR = "1h"
    SIX_HOURS = "6h"
    ONE_DAY = "24h"
    SEVEN_DAYS = "7d"
    THIRTY_DAYS = "30d"
    RETAINED = "retained"


class LogDirection(StrEnum):
    OLDER = "older"
    NEWER = "newer"


@dataclass(frozen=True, slots=True)
class JournalQuery:
    source: LogSource
    minimum_severity: Severity
    range: LogRange
    direction: LogDirection
    cursor: str | None
    limit: int

    def __post_init__(self) -> None:
        if (
            type(self.source) is not LogSource
            or type(self.minimum_severity) is not Severity
            or type(self.range) is not LogRange
            or type(self.direction) is not LogDirection
            or not _cursor(self.cursor)
            or type(self.limit) is not int
            or not 1 <= self.limit <= MAX_PAGE_ENTRIES
        ):
            raise ProtocolError


@dataclass(frozen=True, slots=True)
class JournalEntry:
    cursor: str
    timestamp: str
    source: LogSource
    severity: Severity
    unit: str
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
    pid: int | None = None
    boot_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not _cursor(self.cursor, required=True)
            or not _timestamp(self.timestamp)
            or type(self.source) is not LogSource
            or self.source is LogSource.ALL
            or type(self.severity) is not Severity
            or not _bounded_text(self.unit, 256)
            or not _bounded_text(self.message, 4_096)
            or not all(
                _optional_text(value, 256)
                for value in (
                    self.operation_id,
                    self.job_id,
                    self.cassette_label,
                    self.command_id,
                    self.command_kind,
                    self.phase,
                    self.boot_id,
                )
            )
            or not _optional_int(
                self.cassette_sequence, minimum=1, maximum=MAX_CASSETTE_SEQUENCE
            )
            or not _optional_int(
                self.daemon_generation, minimum=0, maximum=MAX_ELAPSED_MS
            )
            or not _optional_int(
                self.exit_code, minimum=MIN_EXIT_CODE, maximum=MAX_EXIT_CODE
            )
            or not _optional_int(self.elapsed_ms, minimum=0, maximum=MAX_ELAPSED_MS)
            or type(self.repeat_count) is not int
            or not 1 <= self.repeat_count <= MAX_REPEAT_COUNT
            or type(self.truncated) is not bool
            or not _optional_int(self.pid, minimum=1, maximum=MAX_PID)
        ):
            raise ProtocolError


@dataclass(frozen=True, slots=True)
class JournalPage:
    entries: tuple[JournalEntry, ...]
    older_cursor: str | None
    newer_cursor: str | None
    cursor_rotated: bool
    unavailable_sources: tuple[LogSource, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.entries) is not tuple
            or len(self.entries) > MAX_PAGE_ENTRIES
            or any(type(entry) is not JournalEntry for entry in self.entries)
            or not _cursor(self.older_cursor)
            or not _cursor(self.newer_cursor)
            or type(self.cursor_rotated) is not bool
            or type(self.unavailable_sources) is not tuple
            or any(
                type(source) is not LogSource or source is LogSource.ALL
                for source in self.unavailable_sources
            )
            or self.unavailable_sources
            != tuple(
                sorted(set(self.unavailable_sources), key=lambda source: source.value)
            )
        ):
            raise ProtocolError


_REQUEST_KEYS = frozenset(
    {"version", "source", "minimum_severity", "range", "direction", "cursor", "limit"}
)
_RESPONSE_KEYS = frozenset(
    {
        "version",
        "entries",
        "older_cursor",
        "newer_cursor",
        "cursor_rotated",
        "unavailable_sources",
    }
)
_ENTRY_KEYS = frozenset(JournalEntry.__dataclass_fields__)


class _DuplicateKey(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    """Encode one canonical, bounded length-prefixed protocol frame."""

    if type(value) is not dict:
        raise ProtocolError
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError):
        raise ProtocolError from None
    if not raw or len(raw) > MAX_FRAME_BYTES:
        raise ProtocolError
    return struct.pack(">I", len(raw)) + raw


def encode_request(request: JournalQuery) -> bytes:
    if type(request) is not JournalQuery:
        raise ProtocolError
    return canonical_json(
        {
            "version": PROTOCOL_VERSION,
            "source": request.source.value,
            "minimum_severity": request.minimum_severity.value,
            "range": request.range.value,
            "direction": request.direction.value,
            "cursor": request.cursor,
            "limit": request.limit,
        }
    )


def decode_request(packet: bytes) -> JournalQuery:
    value = _exact_object(_parse_frame(packet), _REQUEST_KEYS)
    if _integer(value["version"]) != PROTOCOL_VERSION:
        raise ProtocolError
    try:
        return JournalQuery(
            source=LogSource(value["source"]),
            minimum_severity=Severity(value["minimum_severity"]),
            range=LogRange(value["range"]),
            direction=LogDirection(value["direction"]),
            cursor=value["cursor"],
            limit=value["limit"],
        )
    except (TypeError, ValueError):
        raise ProtocolError from None


def encode_response(page: JournalPage) -> bytes:
    if type(page) is not JournalPage:
        raise ProtocolError
    return canonical_json(
        {
            "version": PROTOCOL_VERSION,
            "entries": [_entry_to_mapping(entry) for entry in page.entries],
            "older_cursor": page.older_cursor,
            "newer_cursor": page.newer_cursor,
            "cursor_rotated": page.cursor_rotated,
            "unavailable_sources": [
                source.value for source in page.unavailable_sources
            ],
        }
    )


def decode_response(packet: bytes) -> JournalPage:
    value = _exact_object(_parse_frame(packet), _RESPONSE_KEYS)
    if (
        _integer(value["version"]) != PROTOCOL_VERSION
        or type(value["entries"]) is not list
        or type(value["unavailable_sources"]) is not list
    ):
        raise ProtocolError
    try:
        entries = tuple(_entry_from_mapping(entry) for entry in value["entries"])
        return JournalPage(
            entries=entries,
            older_cursor=value["older_cursor"],
            newer_cursor=value["newer_cursor"],
            cursor_rotated=value["cursor_rotated"],
            unavailable_sources=tuple(
                LogSource(source) for source in value["unavailable_sources"]
            ),
        )
    except (TypeError, ValueError):
        raise ProtocolError from None


def _entry_to_mapping(entry: JournalEntry) -> dict[str, object]:
    value = asdict(entry)
    value["source"] = entry.source.value
    value["severity"] = entry.severity.value
    return value


def _entry_from_mapping(value: object) -> JournalEntry:
    if type(value) is not dict:
        raise ProtocolError
    legacy_keys = _ENTRY_KEYS - {"command_id", "daemon_generation"}
    if set(value) not in {_ENTRY_KEYS, legacy_keys}:
        raise ProtocolError
    source = dict(value)
    source.setdefault("command_id", None)
    source.setdefault("daemon_generation", None)
    return JournalEntry(
        cursor=source["cursor"],
        timestamp=source["timestamp"],
        source=LogSource(source["source"]),
        severity=Severity(source["severity"]),
        unit=source["unit"],
        message=source["message"],
        operation_id=source["operation_id"],
        job_id=source["job_id"],
        cassette_label=source["cassette_label"],
        cassette_sequence=source["cassette_sequence"],
        command_id=source["command_id"],
        daemon_generation=source["daemon_generation"],
        command_kind=source["command_kind"],
        phase=source["phase"],
        exit_code=source["exit_code"],
        elapsed_ms=source["elapsed_ms"],
        repeat_count=source["repeat_count"],
        truncated=source["truncated"],
        pid=source["pid"],
        boot_id=source["boot_id"],
    )


def _parse_frame(packet: bytes) -> dict[str, object]:
    if type(packet) is not bytes or len(packet) < 5:
        raise ProtocolError
    length = struct.unpack(">I", packet[:4])[0]
    if length == 0 or length > MAX_FRAME_BYTES or len(packet) != length + 4:
        raise ProtocolError
    try:
        value = json.loads(
            packet[4:].decode("ascii", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError):
        raise ProtocolError from None
    if type(value) is not dict or canonical_json(value) != packet:
        raise ProtocolError
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise ValueError


def _exact_object(value: object, keys: frozenset[str]) -> dict[str, object]:
    if type(value) is not dict or frozenset(value) != keys:
        raise ProtocolError
    return value


def _integer(value: object) -> int:
    if type(value) is not int:
        raise ProtocolError
    return value


def _cursor(value: object, *, required: bool = False) -> bool:
    if value is None:
        return not required
    return (
        type(value) is str
        and bool(value)
        and len(value) <= MAX_CURSOR_CHARS
        and value.isascii()
        and "\x00" not in value
    )


def _timestamp(value: object) -> bool:
    if type(value) is not str or not value.endswith("Z") or len(value) > 64:
        return False
    try:
        datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return False
    return True


def _bounded_text(value: object, maximum: int) -> bool:
    return type(value) is str and bool(value) and len(value.encode("utf-8")) <= maximum


def _optional_text(value: object, maximum: int) -> bool:
    return value is None or _bounded_text(value, maximum)


def _optional_int(value: object, *, minimum: int, maximum: int) -> bool:
    return value is None or (type(value) is int and minimum <= value <= maximum)
