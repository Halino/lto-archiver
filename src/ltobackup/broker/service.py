from __future__ import annotations

import array
import base64
import contextlib
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import struct
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace

from ltobackup.broker.cgroup import (
    CgroupConflict,
    CgroupUnavailable,
    CgroupV2BrokerRoot,
)
from ltobackup.broker.ltfs_session import (
    LtfsLifecycleUnavailable,
    LtfsPinningError,
    derive_receipt_operation_uuid,
    device_fd_identity_sha256,
)
from ltobackup.broker.protocol import (
    MAX_PACKET_BYTES,
    BrokerProtocolError,
    BrokerRequest,
    _decode_request_structure,
    encode_response,
    ltfs_request_sha256,
    readiness_capability_payload,
)
from ltobackup.broker.store import (
    BrokerStateConflict,
    BrokerStateStore,
    BrokerStateUnavailable,
    ScopeRecord,
    permit_sha256,
)
from ltobackup.operational_log import (
    NullOperationalEventSink,
    OperationalCorrelation,
    OperationalEvent,
    OperationalEventSink,
    OperationalPhaseTracker,
    OperationalSeverity,
    OperationalSource,
    closed_operational_correlation,
)
from ltobackup.qualification.broker_executor import BrokerQualificationExecutor
from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationExecution,
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    BrokerQualificationRequest,
    qualification_dispatch_proof_payload,
    qualification_inspection_proof_payload,
    qualification_success_exit_codes,
)
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupReleaseClaim,
    BrokeredCgroupReleasePermit,
    BrokeredCgroupScopeReceipt,
    BrokeredCgroupScopeValidation,
    LtfsFinalizationReceipt,
    LtfsReadyReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
)

_FD_ITEM_SIZE = array.array("i").itemsize
_ANCILLARY_BYTES = socket.CMSG_SPACE(16 * _FD_ITEM_SIZE)
_SO_PEERSEC = getattr(socket, "SO_PEERSEC", 31)
_MAX_PEERSEC_BYTES = 1024
_PROOF_BYTES = 32
_MAX_CONNECTIONS = 64
_MAX_TIMEOUT = 60.0
_MAX_LTFS_TIMEOUT = 86_400.0
_BROKER_CHILD_UID = 0
_ROOT_QUALIFICATION_METHODS = frozenset(
    {"execute_ltfs_qualification_stage", "inspect_ltfs_qualification_stage"}
)


class _AuthenticationDenied(RuntimeError):
    pass


class _AmbiguousRelease(RuntimeError):
    pass


@dataclass
class _ActiveLtfsSession:
    request: LtfsSessionRequest
    targets: object
    launch: object
    receipt: LtfsSessionReceipt
    scope_receipt: BrokeredCgroupScopeReceipt


_LTFS_EVENT_KEYS = frozenset({"schema", "operation_id", "code", "detail"})
_LTFS_EVENT_MAP = {
    "device.identity.mismatch": (
        OperationalSeverity.ERROR,
        "LTFS device identity mismatch.",
        "mount",
    ),
}
_DRIVER_UINT_FIELDS = frozenset({
    "seq", "monotonic_ns", "bytes_done", "files_done", "rate_bytes_per_second",
    "queue_fill_bytes", "buffer_underrun_count", "retry_count",
    "memory_high_water_bytes", "phase_elapsed_ns",
})
_DRIVER_OPTIONAL_UINT_FIELDS = frozenset({
    "prior_generation", "new_generation", "bytes_total", "files_total",
    "index_done", "index_total", "eta_seconds",
})
_DRIVER_EVENT_KEYS = _DRIVER_UINT_FIELDS | _DRIVER_OPTIONAL_UINT_FIELDS | {
    "schema", "operation_id", "volume_uuid", "wall_time", "phase", "status",
    "result", "device_close_result", "telemetry_overflowed", "device_serial",
    "message_code",
}
_DRIVER_PHASES = frozenset({
    "STARTING", "MOUNTING", "READY", "WRITING", "CLOSING_HANDLES",
    "DRAINING_DATA", "BUILDING_INDEX", "WRITING_INDEX", "UNMOUNTING",
    "MEDIA_COMMITTED", "PERSISTING_RECEIPT", "UNLOADING", "COMPLETE", "FAILED",
})
_DRIVER_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89aAbB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}"
)


def _parse_driver_event(
    value: dict[str, object], correlation: OperationalCorrelation
) -> OperationalEvent | None:
    """Validate the r16 lifecycle schema and publish only fixed diagnostics.

    The broker owns the pipe and correlation. Driver telemetry never supplies
    receipt evidence or modifies the session state machine.
    """
    if set(value) != _DRIVER_EVENT_KEYS:
        return None
    for name in _DRIVER_UINT_FIELDS | _DRIVER_OPTIONAL_UINT_FIELDS:
        item = value[name]
        if item is None and name in _DRIVER_OPTIONAL_UINT_FIELDS:
            continue
        if type(item) is not int or not 0 <= item < 2**64:
            return None
    if value["seq"] == 0 or value["index_total"] == 0:
        return None
    if value["memory_high_water_bytes"] > 536870912:
        return None
    for name in ("result", "device_close_result"):
        item = value[name]
        if item is None and name == "device_close_result":
            continue
        if type(item) is not int or not -(2**31) <= item < 2**31:
            return None
    for name in ("volume_uuid", "operation_id"):
        item = value[name]
        if item is None and name == "volume_uuid":
            continue
        if type(item) is not str or _DRIVER_UUID.fullmatch(item) is None:
            return None
    phase = value["phase"]
    status = value["status"]
    code = value["message_code"]
    wall_time = value["wall_time"]
    serial = value["device_serial"]
    if (
        type(phase) is not str
        or phase not in _DRIVER_PHASES
        or type(status) is not str
        or status not in {"started", "progress", "complete", "failed"}
        or type(code) is not str
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,127}", code) is None
        or type(wall_time) is not str
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z",
            wall_time,
        ) is None
        or (serial is not None and (type(serial) is not str or len(serial) > 256))
        or type(value["telemetry_overflowed"]) is not bool
    ):
        return None
    result = value["result"]
    phase_name = phase.lower()
    event_code = f"ltfs.driver.{phase_name}.{status}"
    severity = (
        OperationalSeverity.ERROR
        if status == "failed" or result != 0 else OperationalSeverity.INFO
    )
    message = f"LTFS driver {phase_name.replace('_', ' ')}: {status} (result {result})."
    if code in _LTFS_EVENT_MAP:
        mapped_severity, message, phase_name = _LTFS_EVENT_MAP[code]
        if severity is not OperationalSeverity.ERROR:
            severity = mapped_severity
        event_code = code
    return OperationalEvent(
        source=OperationalSource.LTFS,
        severity=severity,
        code=event_code,
        message=message,
        operation_id=correlation.operation_id,
        job_id=correlation.job_id,
        cassette_label=correlation.cassette_label,
        cassette_sequence=correlation.cassette_sequence,
        phase=phase_name,
        exit_code=result,
    )


def _closed_ltfs_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if type(key) is not str or key in value:
            raise ValueError("invalid LTFS event object")
        value[key] = item
    return value


def _parse_ltfs_event(
    line: bytes,
    correlation: OperationalCorrelation,
    *,
    expected_stream_operation_id: str,
) -> OperationalEvent | None:
    if not line or len(line) > 4096:
        return None
    try:
        value = json.loads(
            line.decode("utf-8", "strict"), object_pairs_hook=_closed_ltfs_pairs
        )
        if (
            type(value) is not dict
            or type(value.get("schema")) is not int
            or value.get("schema") != 1
            or value.get("operation_id") != expected_stream_operation_id
        ):
            return None
        if set(value) == _DRIVER_EVENT_KEYS:
            return _parse_driver_event(value, correlation)
        if set(value) != _LTFS_EVENT_KEYS or type(value.get("detail")) is not str:
            return None
        code = value.get("code")
        mapped = _LTFS_EVENT_MAP.get(code) if type(code) is str else None
        if mapped is None:
            return None
        severity, message, phase = mapped
        return OperationalEvent(
            source=OperationalSource.LTFS,
            severity=severity,
            code=code,
            message=message,
            operation_id=correlation.operation_id,
            job_id=correlation.job_id,
            cassette_label=correlation.cassette_label,
            cassette_sequence=correlation.cassette_sequence,
            phase=phase,
        )
    except (TypeError, ValueError, UnicodeError, json.JSONDecodeError, RecursionError):
        return None


def drain_ltfs_event_stream(
    descriptor: int,
    *,
    sink: OperationalEventSink,
    correlation: OperationalCorrelation,
    expected_stream_operation_id: str,
) -> None:
    """Drain the mandatory pipe continuously and publish only bounded closed JSON."""

    buffer = bytearray()
    discard_until_newline = False
    published_bytes = 0
    pending: OperationalEvent | None = None
    repeat_count = 0

    def flush_pending() -> None:
        nonlocal pending, repeat_count
        if pending is None:
            return
        event = replace(pending, repeat_count=repeat_count)
        pending = None
        repeat_count = 0
        try:
            sink.emit(event)
        except BaseException:  # noqa: BLE001, S110 - drain must outlive diagnostics
            pass

    try:
        while chunk := os.read(descriptor, 64 * 1024):
            if discard_until_newline:
                newline = chunk.find(b"\n")
                if newline < 0:
                    continue
                chunk = chunk[newline + 1 :]
                discard_until_newline = False
                if not chunk:
                    continue
            buffer.extend(chunk)
            while newline := buffer.find(b"\n") + 1:
                line = bytes(buffer[: newline - 1])
                del buffer[:newline]
                try:
                    event = _parse_ltfs_event(
                        line,
                        correlation,
                        expected_stream_operation_id=expected_stream_operation_id,
                    )
                except BaseException:  # noqa: BLE001 - drain must outlive parser
                    flush_pending()
                    continue
                if event is None:
                    flush_pending()
                    continue
                if event == pending:
                    repeat_count = min(repeat_count + 1, 2**31 - 1)
                    continue
                flush_pending()
                if published_bytes >= 32 * 1024:
                    continue
                event_bytes = len(event.message.encode("utf-8"))
                if published_bytes + event_bytes > 32 * 1024:
                    continue
                published_bytes += event_bytes
                pending = event
                repeat_count = 1
            if len(buffer) > 4096:
                # Oversized/malformed records are discarded without stopping
                # the drain that prevents the LTFS child from blocking.
                flush_pending()
                buffer.clear()
                discard_until_newline = True
    except OSError:
        pass
    finally:
        flush_pending()
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _peer_identity(connection: socket.socket) -> tuple[int, int, bytes | None]:
    size = struct.calcsize("3i")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
    if type(raw) is not bytes or len(raw) != size:
        raise _AuthenticationDenied
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise _AuthenticationDenied
    try:
        context = connection.getsockopt(
            socket.SOL_SOCKET, _SO_PEERSEC, _MAX_PEERSEC_BYTES
        )
    except OSError:
        context = None
    if context is not None:
        if (
            type(context) is not bytes
            or not context
            or len(context) > _MAX_PEERSEC_BYTES
        ):
            raise _AuthenticationDenied
        context = context.rstrip(b"\0")
    return uid, gid, context


def _close_fd(fd: int) -> None:
    with contextlib.suppress(OSError):
        os.close(fd)


def _received_fds(ancillary: list[tuple[int, int, bytes]]) -> tuple[list[int], bool]:
    descriptors: list[int] = []
    valid = True
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            valid = False
            continue
        values = array.array("i")
        if len(data) % values.itemsize:
            valid = False
        values.frombytes(data[: len(data) - len(data) % values.itemsize])
        descriptors.extend(values)
    return descriptors, valid


def _canonical_proof_value(value: object) -> object:
    if type(value) is bytes:
        return {"base64": base64.b64encode(value).decode("ascii")}
    if type(value) in (str, int, bool) or value is None:
        return value
    if type(value) in (tuple, list):
        return [_canonical_proof_value(item) for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise BrokerProtocolError
        return {key: _canonical_proof_value(value[key]) for key in sorted(value)}
    raise BrokerProtocolError


def _proof_payload(domain: str, fields: Mapping[str, object]) -> bytes:
    if type(domain) is not str or not domain.isascii() or not domain:
        raise BrokerProtocolError
    value = {
        "domain": domain,
        "fields": _canonical_proof_value(dict(fields)),
        "version": 1,
    }
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _receipt_fields(receipt: BrokeredCgroupScopeReceipt) -> dict[str, object]:
    return {
        "protocol_version": receipt.protocol_version,
        "command_id": receipt.command_id,
        "owner_generation": receipt.owner_generation,
        "request_nonce": receipt.request_nonce,
        "scope_id": receipt.scope_id,
        "scope_path_sha256": receipt.scope_path_sha256,
        "broker_nonce": receipt.broker_nonce,
        "recursive_population": receipt.recursive_population,
        "recursive_members": receipt.recursive_members,
        "cgroup_kill": receipt.cgroup_kill,
    }


def _receipt_mapping(receipt: BrokeredCgroupScopeReceipt) -> dict[str, object]:
    result = _receipt_fields(receipt)
    result["broker_proof"] = receipt.broker_proof
    return result


def _receipt_from_mapping(value: object) -> BrokeredCgroupScopeReceipt:
    if type(value) is not dict:
        raise BrokerProtocolError
    try:
        return BrokeredCgroupScopeReceipt(**value)
    except (TypeError, ValueError):
        raise BrokerProtocolError from None


def _permit_fields(permit: BrokeredCgroupReleasePermit) -> dict[str, object]:
    return {
        "protocol_version": permit.protocol_version,
        "receipt": _receipt_mapping(permit.receipt),
        "pid": permit.pid,
        "request_nonce": permit.request_nonce,
        "permit_nonce": permit.permit_nonce,
    }


def _permit_mapping(permit: BrokeredCgroupReleasePermit) -> dict[str, object]:
    result = _permit_fields(permit)
    result["broker_proof"] = permit.broker_proof
    return result


def _permit_from_mapping(value: object) -> BrokeredCgroupReleasePermit:
    if type(value) is not dict:
        raise BrokerProtocolError
    source = dict(value)
    source["receipt"] = _receipt_from_mapping(source.get("receipt"))
    try:
        return BrokeredCgroupReleasePermit(**source)
    except (TypeError, ValueError):
        raise BrokerProtocolError from None


def _ltfs_receipt_fields(receipt: LtfsSessionReceipt) -> dict[str, object]:
    return {
        "protocol_version": receipt.protocol_version,
        "operation_id": receipt.operation_id,
        "receipt_operation_uuid": receipt.receipt_operation_uuid,
        "observed_volume_uuid": receipt.observed_volume_uuid,
        "observed_prior_generation": receipt.observed_prior_generation,
        "observed_volume_label": receipt.observed_volume_label,
        "observed_media_identity_sha256": (receipt.observed_media_identity_sha256),
        "read_only": receipt.read_only,
        "owner_generation": receipt.owner_generation,
        "request_nonce": receipt.request_nonce,
        "session_id": receipt.session_id,
        "request_sha256": receipt.request_sha256,
        "child_pid": receipt.child_pid,
        "child_start_ticks": receipt.child_start_ticks,
        "mount_namespace_sha256": receipt.mount_namespace_sha256,
        "broker_nonce": receipt.broker_nonce,
        "mounted": receipt.mounted,
    }


def _ltfs_receipt_mapping(receipt: LtfsSessionReceipt) -> dict[str, object]:
    result = _ltfs_receipt_fields(receipt)
    result["broker_proof"] = receipt.broker_proof
    return result


def _ltfs_finalization_fields(
    receipt: LtfsFinalizationReceipt,
) -> dict[str, object]:
    standalone = receipt.standalone_receipt
    return {
        "protocol_version": receipt.protocol_version,
        "session_receipt": _ltfs_receipt_mapping(receipt.session_receipt),
        "standalone_receipt": {
            "schema": standalone.schema,
            "stage": standalone.stage,
            "operation_id": standalone.operation_id,
            "volume_uuid": standalone.volume_uuid,
            "prior_generation": standalone.prior_generation,
            "new_generation": standalone.new_generation,
            "bytes_valid": standalone.bytes_valid,
            "bytes": standalone.bytes,
            "files_valid": standalone.files_valid,
            "files": standalone.files,
            "phase_duration_ns": list(standalone.phase_duration_ns),
            "capture_duration_ns": standalone.capture_duration_ns,
            "device_close_duration_ns": standalone.device_close_duration_ns,
            "device_close_result_valid": standalone.device_close_result_valid,
            "device_close_result": standalone.device_close_result,
            "catalog_ack_duration_ns": standalone.catalog_ack_duration_ns,
            "media_committed": standalone.media_committed,
            "catalog_acknowledged": standalone.catalog_acknowledged,
            "cleanup_failed": standalone.cleanup_failed,
            "result": standalone.result,
            "terminal_sha256": standalone.terminal_sha256,
        },
        "request_nonce": receipt.request_nonce,
        "finalization_nonce": receipt.finalization_nonce,
        "unmounted": receipt.unmounted,
        "child_quiesced": receipt.child_quiesced,
    }


class CommandBrokerService:
    """Authenticated one-packet broker boundary over Unix ``SOCK_SEQPACKET``."""

    def __init__(
        self,
        store: BrokerStateStore,
        cgroup: CgroupV2BrokerRoot,
        *,
        capability: bytes,
        proof_key: bytes,
        daemon_uid: int,
        daemon_gid: int,
        enforcing: bool,
        daemon_context: str,
        connection_timeout: float = 5.0,
        ltfs_mount_ready_timeout: float = 1_800.0,
        ltfs_finalize_timeout: float = 7_200.0,
        max_connections: int = 8,
        ltfs_pins: object | None = None,
        ltfs_receipt_root: object | None = None,
        ltfs_executor: object | None = None,
        ltfs_mountinfo_probe: object | None = None,
        ltfs_process_probe: object | None = None,
        qualification_executor: object | None = None,
        event_sink: OperationalEventSink | None = None,
    ) -> None:
        ltfs_dependencies = (
            ltfs_pins,
            ltfs_receipt_root,
            ltfs_executor,
            ltfs_mountinfo_probe,
            ltfs_process_probe,
        )
        if (
            type(capability) is not bytes
            or len(capability) != 32
            or type(proof_key) is not bytes
            or len(proof_key) != _PROOF_BYTES
            or hmac.compare_digest(capability, proof_key)
            or type(daemon_uid) is not int
            or not 0 <= daemon_uid < 1 << 32
            or type(daemon_gid) is not int
            or not 0 <= daemon_gid < 1 << 32
            or type(enforcing) is not bool
            or type(daemon_context) is not str
            or not daemon_context
            or not daemon_context.isascii()
            or type(connection_timeout) not in (int, float)
            or type(connection_timeout) is bool
            or not 0 < float(connection_timeout) <= _MAX_TIMEOUT
            or type(ltfs_mount_ready_timeout) not in (int, float)
            or type(ltfs_mount_ready_timeout) is bool
            or not 0 < float(ltfs_mount_ready_timeout) <= _MAX_LTFS_TIMEOUT
            or type(ltfs_finalize_timeout) not in (int, float)
            or type(ltfs_finalize_timeout) is bool
            or not 0 < float(ltfs_finalize_timeout) <= _MAX_LTFS_TIMEOUT
            or type(max_connections) is not int
            or not 1 <= max_connections <= _MAX_CONNECTIONS
            or (
                any(value is None for value in ltfs_dependencies)
                and any(value is not None for value in ltfs_dependencies)
            )
        ):
            raise ValueError("invalid command broker service configuration")
        self.store = store
        self.cgroup = cgroup
        self._capability = capability
        self._proof_key = proof_key
        self.daemon_uid = daemon_uid
        self.daemon_gid = daemon_gid
        self.enforcing = enforcing
        self.daemon_context = daemon_context.encode("ascii")
        self.connection_timeout = float(connection_timeout)
        self.ltfs_mount_ready_timeout = float(ltfs_mount_ready_timeout)
        self.ltfs_finalize_timeout = float(ltfs_finalize_timeout)
        self.max_connections = max_connections
        self._ltfs_pins = ltfs_pins
        self._ltfs_receipt_root = ltfs_receipt_root
        self._ltfs_executor = ltfs_executor
        self._ltfs_mountinfo_probe = ltfs_mountinfo_probe
        self._ltfs_process_probe = ltfs_process_probe
        if (
            qualification_executor is not None
            and type(qualification_executor) is not BrokerQualificationExecutor
        ):
            raise ValueError("invalid LTFS qualification executor")
        self._qualification_executor = qualification_executor
        self._event_sink = event_sink or NullOperationalEventSink()
        self._ltfs_lock = threading.Lock()
        # Cover both durable permit transitions and the subsequent gate write.
        # Whenever both locks are needed, acquire LTFS before command lifecycle.
        self._command_lifecycle_lock = threading.Lock()
        self._active_ltfs: _ActiveLtfsSession | None = None
        self._reconciliation_clean = False
        self._readiness_reconciliation_nonces: set[bytes] = set()
        self._shutdown = threading.Event()
        self._listener: socket.socket | None = None
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()
        self._finalizing_monitors = 0
        self._slots = threading.BoundedSemaphore(max_connections)

    def _proof(self, domain: str, fields: Mapping[str, object]) -> bytes:
        return hmac.new(
            self._proof_key, _proof_payload(domain, fields), hashlib.sha256
        ).digest()

    def reconcile_startup(self) -> None:
        """Fail readiness after durably containing contradictory active state."""

        self._reconciliation_clean = False
        unavailable = False
        finalizing_monitors = 0
        try:
            records = self.store.scopes_for_reconciliation()
            ltfs_records_for_reconciliation = getattr(
                self.store, "ltfs_sessions_for_reconciliation", None
            )
            sessions = (
                ltfs_records_for_reconciliation()
                if ltfs_records_for_reconciliation is not None
                else ()
            )
        except (BrokerStateConflict, BrokerStateUnavailable):
            raise BrokerStateUnavailable from None
        linked_ltfs_scopes = {session.cgroup_scope_id for session in sessions}
        for record in records:
            if record.state == "BROKEN":
                unavailable = True
                continue
            if record.state != "ACTIVE":
                continue
            receipt = self._new_receipt(
                command_id=record.command_id,
                owner_generation=record.owner_generation,
                request_nonce=secrets.token_bytes(32),
                scope_id=record.scope_id,
                scope_path_sha256=record.scope_path_sha256,
            )
            try:
                if record.cgroup_device is None or record.cgroup_inode is None:
                    raise CgroupConflict
                self.cgroup.open(record)
                validation = self.cgroup.validate(record)
                if (
                    record.command_id.startswith("ltfs-")
                    and len(record.command_id) == 69
                    and all(
                        character in "0123456789abcdef"
                        for character in record.command_id[5:]
                    )
                    and record.scope_id not in linked_ltfs_scopes
                ):
                    if validation.populated or validation.member_pids:
                        raise CgroupConflict
                    self.cgroup.release(record)
                    self.store.mark_scope(receipt, "CLOSED")
            except (CgroupConflict, CgroupUnavailable, OSError, ValueError, TypeError):
                try:
                    self.store.mark_scope(receipt, "BROKEN")
                except (BrokerStateConflict, BrokerStateUnavailable):
                    raise BrokerStateUnavailable from None
                unavailable = True
        if ltfs_records_for_reconciliation is not None:
            scopes_by_id = {record.scope_id: record for record in records}
            for session in sessions:
                if session.state == "UNMOUNTED":
                    continue
                scope = scopes_by_id.get(session.cgroup_scope_id)
                if session.state == "FINALIZING" or (
                    session.state == "BROKEN"
                    and session.finalization_request_nonce is not None
                ):
                    if session.state == "FINALIZING" and scope is not None:
                        try:
                            self._reconcile_finalizing_session(session, scope)
                            continue
                        except (
                            BrokerStateConflict,
                            BrokerStateUnavailable,
                            CgroupConflict,
                            CgroupUnavailable,
                            LtfsLifecycleUnavailable,
                            OSError,
                            TypeError,
                            ValueError,
                        ):
                            current = self.store.ltfs_session(
                                session.operation_id, session.owner_generation
                            )
                            if current.state == "BROKEN":
                                unavailable = True
                                continue
                            self._start_finalizing_monitor(session, scope)
                            finalizing_monitors += 1
                            continue
                    unavailable = True
                    continue
                if scope is not None:
                    with contextlib.suppress(Exception):
                        self.cgroup.kill(scope)
                try:
                    self.store.break_ltfs_session(
                        session.operation_id, session.owner_generation
                    )
                except (BrokerStateConflict, BrokerStateUnavailable):
                    raise BrokerStateUnavailable from None
                if scope is not None:
                    receipt = self._new_receipt(
                        command_id=scope.command_id,
                        owner_generation=scope.owner_generation,
                        request_nonce=secrets.token_bytes(32),
                        scope_id=scope.scope_id,
                        scope_path_sha256=scope.scope_path_sha256,
                    )
                    with contextlib.suppress(
                        BrokerStateConflict, BrokerStateUnavailable
                    ):
                        self.store.mark_scope(receipt, "BROKEN")
                unavailable = True
        if unavailable:
            raise BrokerStateUnavailable
        self._reconciliation_clean = finalizing_monitors == 0

    def _start_finalizing_monitor(self, session: object, scope: ScopeRecord) -> None:
        def monitor() -> None:
            try:
                while True:
                    try:
                        self._reconcile_finalizing_session(session, scope)
                        break
                    except Exception:  # noqa: BLE001 - remain fenced, never signal
                        threading.Event().wait(1.0)
                with self._workers_lock:
                    self._finalizing_monitors -= 1
                    if self._finalizing_monitors == 0:
                        self._reconciliation_clean = True
            finally:
                current = threading.current_thread()
                with self._workers_lock:
                    self._workers.discard(current)

        worker = threading.Thread(
            target=monitor,
            name="ltfs-finalization-reconcile",
            daemon=False,
        )
        with self._workers_lock:
            self._finalizing_monitors += 1
            self._workers.add(worker)
        worker.start()

    def _reconcile_finalizing_session(
        self, session: object, scope: ScopeRecord
    ) -> None:
        _pins, receipt_root, _executor, mount_probe, process_probe = (
            self._require_ltfs_runtime()
        )
        receipt = self._ltfs_receipt_from_record(session)
        observed = process_probe.observe(receipt.child_pid)
        if observed is not None:
            self._require_process(
                observed,
                pid=receipt.child_pid,
                start_ticks=receipt.child_start_ticks,
                mount_namespace_sha256=receipt.mount_namespace_sha256,
            )
            raise BrokerStateUnavailable
        if mount_probe.await_unmounted(self._ltfs_pins.mount_path) is not True:
            raise BrokerStateUnavailable
        if not self.store.has_ltfs_child_exit_zero(
            receipt.operation_id, receipt.owner_generation
        ):
            self.store.break_ltfs_session(
                receipt.operation_id, receipt.owner_generation
            )
            raise BrokerStateUnavailable
        standalone = receipt_root.read_terminal(
            operation_id=receipt.receipt_operation_uuid,
            owner_generation=receipt.owner_generation,
            request_sha256=receipt.request_sha256,
        )
        if (
            standalone.volume_uuid != receipt.observed_volume_uuid
            or standalone.prior_generation != receipt.observed_prior_generation
            or session.read_only
            and standalone.new_generation != standalone.prior_generation
            or not session.read_only
            and standalone.new_generation < standalone.prior_generation
        ):
            raise BrokerStateConflict
        self.store.bind_ltfs_terminal_receipt(receipt, standalone)
        validation = self.cgroup.validate(scope)
        if validation.populated is not False or validation.member_pids != ():
            raise BrokerStateUnavailable
        request_nonce = session.finalization_request_nonce
        if type(request_nonce) is not bytes or len(request_nonce) != 32:
            raise BrokerStateConflict
        while True:
            finalization_nonce = secrets.token_bytes(32)
            provisional = LtfsFinalizationReceipt(
                1,
                receipt,
                standalone,
                request_nonce,
                finalization_nonce,
                b"x" * 32,
                True,
                True,
            )
            proof = self._proof(
                "ltfs-finalization-receipt-v1",
                _ltfs_finalization_fields(provisional),
            )
            if len({request_nonce, finalization_nonce, proof}) == 3:
                final = replace(provisional, broker_proof=proof)
                break
        self.store.mark_ltfs_unmounted(final)
        self.cgroup.release(scope)
        scope_receipt = self._new_receipt(
            command_id=scope.command_id,
            owner_generation=scope.owner_generation,
            request_nonce=secrets.token_bytes(32),
            scope_id=scope.scope_id,
            scope_path_sha256=scope.scope_path_sha256,
        )
        self.store.mark_scope(scope_receipt, "CLOSED")

    def _new_receipt(
        self,
        *,
        command_id: str,
        owner_generation: int,
        request_nonce: bytes,
        scope_id: str,
        scope_path_sha256: str,
    ) -> BrokeredCgroupScopeReceipt:
        provisional = BrokeredCgroupScopeReceipt(
            1,
            command_id,
            owner_generation,
            request_nonce,
            scope_id,
            scope_path_sha256,
            secrets.token_bytes(32),
            b"x" * 32,
            True,
            True,
            True,
        )
        return replace(
            provisional,
            broker_proof=self._proof("scope-receipt-v1", _receipt_fields(provisional)),
        )

    def _verify_receipt(self, value: object) -> BrokeredCgroupScopeReceipt:
        receipt = _receipt_from_mapping(value)
        if (
            receipt.protocol_version != 1
            or receipt.recursive_population is not True
            or receipt.recursive_members is not True
            or receipt.cgroup_kill is not True
            or receipt.scope_path_sha256
            != CgroupV2BrokerRoot.scope_path_sha256(
                receipt.command_id, receipt.owner_generation
            )
            or not hmac.compare_digest(
                receipt.broker_proof,
                self._proof("scope-receipt-v1", _receipt_fields(receipt)),
            )
        ):
            raise BrokerStateConflict
        return receipt

    def _verify_permit(
        self,
        value: object,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
    ) -> BrokeredCgroupReleasePermit:
        permit = _permit_from_mapping(value)
        if (
            permit.protocol_version != 1
            or permit.receipt != receipt
            or permit.pid != pid
            or not hmac.compare_digest(
                permit.broker_proof,
                self._proof("release-permit-v1", _permit_fields(permit)),
            )
        ):
            raise BrokerStateConflict
        return permit

    def _authenticate_peer(self, connection: socket.socket, method: str) -> None:
        uid, gid, peer_context = _peer_identity(connection)
        daemon_peer = uid == self.daemon_uid and gid == self.daemon_gid
        root_qualification_peer = (
            uid == 0 and gid == 0 and method in _ROOT_QUALIFICATION_METHODS
        )
        if not (daemon_peer or root_qualification_peer) or (
            self.enforcing and peer_context != self.daemon_context
        ):
            raise _AuthenticationDenied

    @staticmethod
    def _validate_release_fd(fd: int) -> None:
        try:
            status = os.fstat(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        except OSError:
            raise BrokerProtocolError from None
        if not stat.S_ISFIFO(status.st_mode) or flags & os.O_ACCMODE != os.O_WRONLY:
            raise BrokerProtocolError

    def handle_connection(self, connection: socket.socket) -> None:
        request: BrokerRequest | None = None
        descriptors: list[int] = []
        try:
            if (
                type(connection) is not socket.socket
                or connection.family != socket.AF_UNIX
                or connection.type & 0xF != socket.SOCK_SEQPACKET
            ):
                raise _AuthenticationDenied
            connection.settimeout(self.connection_timeout)
            packet, ancillary, flags, _address = connection.recvmsg(
                MAX_PACKET_BYTES + 1,
                _ANCILLARY_BYTES,
                getattr(socket, "MSG_CMSG_CLOEXEC", 0),
            )
            descriptors, ancillary_valid = _received_fds(ancillary)
            for descriptor in descriptors:
                try:
                    os.set_inheritable(descriptor, False)
                except OSError:
                    ancillary_valid = False
            if (
                not packet
                or len(packet) > MAX_PACKET_BYTES
                or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or not ancillary_valid
            ):
                raise BrokerProtocolError
            request = _decode_request_structure(packet)
            if not hmac.compare_digest(request.capability, self._capability):
                raise _AuthenticationDenied
            self._authenticate_peer(connection, request.method)
            if request.method == "release_child":
                if len(descriptors) != 1:
                    raise BrokerProtocolError
                self._validate_release_fd(descriptors[0])
            elif request.method == "start_ltfs_session":
                if self._ltfs_pins is None or len(descriptors) != 2:
                    raise BrokerProtocolError
                session_request = request.params.get("request")
                if type(session_request) is not LtfsSessionRequest:
                    raise BrokerProtocolError
                try:
                    descriptor_identities = (
                        device_fd_identity_sha256(descriptors[0], "tape"),
                        device_fd_identity_sha256(descriptors[1], "scsi"),
                    )
                except LtfsPinningError:
                    raise BrokerProtocolError from None
                if descriptor_identities != (
                    session_request.tape_fd_identity_sha256,
                    session_request.scsi_fd_identity_sha256,
                ):
                    raise BrokerProtocolError
            elif request.method in {
                "observe_ltfs_session",
                "finalize_ltfs_session",
                "recover_ltfs_finalization",
                "execute_ltfs_qualification_stage",
            }:
                if (
                    request.method != "execute_ltfs_qualification_stage"
                    and self._ltfs_pins is None
                ) or descriptors:
                    raise BrokerProtocolError
            elif descriptors:
                raise BrokerProtocolError
            # A timed-out create can still be committing its replay journal or
            # binding its cgroup. Serialize open with that entire transaction,
            # not only dispatch, so recovery cannot reject a half-created scope.
            # These two dispatch branches do not acquire the lifecycle lock.
            scope_creation_lock = (
                self._command_lifecycle_lock
                if request.method in {"create_scope", "open_scope"}
                else contextlib.nullcontext()
            )
            with scope_creation_lock:
                # Inspection must not mutate even the replay journal.
                if request.method != "inspect_ltfs_qualification_stage":
                    self.store.record_nonce(request.method, request.request_id)
                if request.method in {
                    "create_scope",
                    "open_scope",
                    "prepare_release",
                    "readiness",
                    "recover_ltfs_finalization",
                }:
                    semantic_nonce = request.params.get(
                        "request_nonce",
                        request.params.get(
                            "nonce",
                            getattr(request.params.get("request"), "request_nonce", None),
                        ),
                    )
                    if type(semantic_nonce) is not bytes:
                        raise BrokerProtocolError
                    self.store.record_nonce(request.method, semantic_nonce)
                result = self._dispatch(request, tuple(descriptors))
            try:
                response = encode_response(
                    request.method, request_id=request.request_id, result=result
                )
                if connection.send(response) != len(response):
                    raise OSError("short broker response")
            except Exception:
                self._mark_ltfs_response_ambiguous(request)
                raise
        except _AuthenticationDenied:
            if request is not None:
                self._send_error(connection, request, "auth.denied")
        except _AmbiguousRelease:
            if request is not None:
                self._send_error(connection, request, "state.ambiguous")
        except BrokerProtocolError:
            if request is not None:
                self._send_error(connection, request, "protocol.invalid")
        except (BrokerStateConflict, CgroupConflict):
            if request is not None:
                self._send_error(connection, request, "scope.conflict")
        except (
            BrokerStateUnavailable,
            CgroupUnavailable,
            LtfsPinningError,
            LtfsLifecycleUnavailable,
        ):
            if request is not None:
                self._send_error(connection, request, "state.unavailable")
        except Exception:  # noqa: BLE001 - redact the complete privileged boundary
            if request is not None:
                self._send_error(connection, request, "state.unavailable")
        finally:
            for descriptor in descriptors:
                _close_fd(descriptor)
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()

    @staticmethod
    def _send_error(
        connection: socket.socket, request: BrokerRequest, code: str
    ) -> None:
        with contextlib.suppress(OSError, BrokerProtocolError):
            response = encode_response(
                request.method, request_id=request.request_id, error_code=code
            )
            if connection.send(response) != len(response):
                return

    def _scope_record(self, receipt: BrokeredCgroupScopeReceipt) -> ScopeRecord:
        return self.store.open_scope(receipt)

    def _revalidate_child(
        self, receipt: BrokeredCgroupScopeReceipt, pid: int
    ) -> ScopeRecord:
        record = self._scope_record(receipt)
        if record.pid != pid:
            raise BrokerStateConflict
        self.cgroup.attach(record, pid, daemon_uid=self.daemon_uid, store=self.store)
        return self._scope_record(receipt)

    def _require_ltfs_runtime(self) -> tuple[object, object, object, object, object]:
        runtime = (
            self._ltfs_pins,
            self._ltfs_receipt_root,
            self._ltfs_executor,
            self._ltfs_mountinfo_probe,
            self._ltfs_process_probe,
        )
        if any(value is None for value in runtime):
            raise BrokerProtocolError
        return runtime  # type: ignore[return-value]

    def _verify_ltfs_receipt(self, value: object) -> LtfsSessionReceipt:
        if type(value) is not LtfsSessionReceipt:
            raise BrokerStateConflict
        if (
            value.protocol_version != 1
            or value.mounted is not True
            or not hmac.compare_digest(
                value.broker_proof,
                self._proof("ltfs-session-receipt-v1", _ltfs_receipt_fields(value)),
            )
        ):
            raise BrokerStateConflict
        return value

    def _new_ltfs_receipt(
        self,
        request: LtfsSessionRequest,
        process: object,
        ready: LtfsReadyReceipt,
    ) -> LtfsSessionReceipt:
        while True:
            provisional = LtfsSessionReceipt(
                1,
                request.operation_id,
                ready.operation_id,
                ready.volume_uuid,
                ready.prior_generation,
                request.read_only,
                request.owner_generation,
                request.request_nonce,
                "ltfs-" + secrets.token_hex(24),
                ltfs_request_sha256(request),
                process.pid,
                process.start_ticks,
                process.mount_namespace_sha256,
                secrets.token_bytes(32),
                b"x" * 32,
                True,
                ready.ltfs_volume_label,
                request.observed_media_identity_sha256,
            )
            proof = self._proof(
                "ltfs-session-receipt-v1", _ltfs_receipt_fields(provisional)
            )
            if len({request.request_nonce, provisional.broker_nonce, proof}) == 3:
                return replace(provisional, broker_proof=proof)

    def _ltfs_receipt_from_record(self, record: object) -> LtfsSessionReceipt:
        required = (
            record.receipt_operation_uuid,
            record.observed_volume_uuid,
            record.observed_prior_generation,
            record.observed_volume_label,
            record.session_id,
            record.child_pid,
            record.child_start_ticks,
            record.mount_namespace_sha256,
            record.session_broker_nonce,
            record.session_broker_proof,
        )
        if any(value is None for value in required):
            raise BrokerStateConflict
        receipt = LtfsSessionReceipt(
            1,
            record.operation_id,
            record.receipt_operation_uuid,
            record.observed_volume_uuid,
            record.observed_prior_generation,
            record.read_only,
            record.owner_generation,
            record.start_request_nonce,
            record.session_id,
            record.request_sha256,
            record.child_pid,
            record.child_start_ticks,
            record.mount_namespace_sha256,
            record.session_broker_nonce,
            record.session_broker_proof,
            True,
            record.observed_volume_label,
            record.observed_media_identity_sha256,
        )
        return self._verify_ltfs_receipt(receipt)

    @staticmethod
    def _require_process(
        observed: object,
        *,
        pid: int,
        start_ticks: int | None = None,
        mount_namespace_sha256: str | None = None,
    ) -> object:
        try:
            observed_pid = observed.pid
            observed_start_ticks = observed.start_ticks
            observed_namespace = observed.mount_namespace_sha256
        except AttributeError:
            raise LtfsLifecycleUnavailable from None
        if (
            type(observed_pid) is not int
            or observed_pid != pid
            or type(observed_start_ticks) is not int
            or observed_start_ticks <= 0
            or type(observed_namespace) is not str
            or len(observed_namespace) != 64
            or any(
                character not in "0123456789abcdef" for character in observed_namespace
            )
            or (start_ticks is not None and observed_start_ticks != start_ticks)
            or (
                mount_namespace_sha256 is not None
                and observed_namespace != mount_namespace_sha256
            )
        ):
            raise LtfsLifecycleUnavailable
        return observed

    def _require_ltfs_health(self, active: _ActiveLtfsSession) -> None:
        _pins, _receipt_root, _executor, mount_probe, process_probe = (
            self._require_ltfs_runtime()
        )
        observed = self._require_process(
            process_probe.observe(active.receipt.child_pid),
            pid=active.receipt.child_pid,
            start_ticks=active.receipt.child_start_ticks,
            mount_namespace_sha256=active.receipt.mount_namespace_sha256,
        )
        del observed
        mounted = mount_probe.await_mounted(active.targets.mount_path)
        if (
            getattr(mounted, "target", None) != active.targets.mount_path
            or getattr(mounted, "fs_type", None) != "fuse.ltfs"
            or getattr(mounted, "source", None) != "ltfs"
        ):
            raise LtfsLifecycleUnavailable
        validation = self.cgroup.validate(self._scope_record(active.scope_receipt))
        if validation.populated is not True or validation.member_pids != (
            active.receipt.child_pid,
        ):
            raise LtfsLifecycleUnavailable

    def _contain_ltfs(
        self,
        *,
        request: LtfsSessionRequest,
        targets: object | None,
        launch: object | None,
        scope_receipt: BrokeredCgroupScopeReceipt,
        start_ticks: int | None,
    ) -> None:
        self._reconciliation_clean = False
        _pins, _receipt_root, executor, _mount_probe, _process_probe = (
            self._require_ltfs_runtime()
        )
        with contextlib.suppress(Exception):
            self.cgroup.kill(self._scope_record(scope_receipt))
        if launch is not None:
            with contextlib.suppress(Exception):
                executor.terminate_reap(
                    launch,
                    pid=launch.pid,
                    start_ticks=start_ticks if start_ticks is not None else 1,
                )
        if targets is not None:
            with contextlib.suppress(Exception):
                targets.close()
        with contextlib.suppress(Exception):
            self.store.break_ltfs_session(
                request.operation_id, request.owner_generation
            )
        with contextlib.suppress(Exception):
            self.store.mark_scope(scope_receipt, "BROKEN")
        self._active_ltfs = None

    def _mark_ltfs_response_ambiguous(self, request: BrokerRequest) -> None:
        if request.method not in {
            "start_ltfs_session",
            "observe_ltfs_session",
            "finalize_ltfs_session",
        }:
            return
        self._reconciliation_clean = False
        with self._ltfs_lock:
            active = self._active_ltfs
            if request.method == "finalize_ltfs_session":
                return
            if active is not None:
                self._contain_ltfs(
                    request=active.request,
                    targets=active.targets,
                    launch=active.launch,
                    scope_receipt=active.scope_receipt,
                    start_ticks=active.receipt.child_start_ticks,
                )
                return
            if request.method == "start_ltfs_session":
                model = request.params.get("request")
                operation_id = getattr(model, "operation_id", None)
                owner_generation = getattr(model, "owner_generation", None)
            else:
                operation_id = request.params.get("operation_id")
                owner_generation = request.params.get("owner_generation")
            with contextlib.suppress(Exception):
                self.store.break_ltfs_session(operation_id, owner_generation)

    def _start_ltfs_session(
        self, request: LtfsSessionRequest, descriptors: tuple[int, ...]
    ) -> dict[str, object]:
        pins, receipt_root, executor, mount_probe, process_probe = (
            self._require_ltfs_runtime()
        )
        if len(descriptors) != 2:
            raise BrokerProtocolError
        scope_receipt = self._verify_receipt(
            _receipt_mapping(request.cgroup_scope_receipt)
        )
        if self._active_ltfs is not None:
            if self._active_ltfs.request == request:
                try:
                    self._require_ltfs_health(self._active_ltfs)
                except Exception:  # noqa: BLE001 - ambiguity requires containment
                    active = self._active_ltfs
                    self._contain_ltfs(
                        request=active.request,
                        targets=active.targets,
                        launch=active.launch,
                        scope_receipt=active.scope_receipt,
                        start_ticks=active.receipt.child_start_ticks,
                    )
                    raise BrokerStateUnavailable from None
                return {"receipt": self._active_ltfs.receipt}
            self._close_unbound_ltfs_scope(scope_receipt)
            raise BrokerStateConflict
        targets = None
        launch = None
        process = None
        transition_started = False
        correlation = closed_operational_correlation(
            operation_id=request.operation_id,
            daemon_generation=request.owner_generation,
        )
        phases = OperationalPhaseTracker(self._event_sink, correlation)
        event_reader = -1
        event_writer = -1
        try:
            scope_record = self._scope_record(scope_receipt)
            self.cgroup.open(scope_record)
            targets = pins.validate_request(
                request, tape_fd=descriptors[0], scsi_fd=descriptors[1]
            )
            transition = self.store.begin_ltfs_session(
                request,
                pins.ltfs_tool_identity_sha256,
                pins.fusermount_tool_identity_sha256,
            )
            if not transition.transitioned:
                targets.close()
                raise BrokerStateConflict
            transition_started = True
            targets.assert_launch_anchors()
            request_digest = ltfs_request_sha256(request)
            receipt_operation_uuid = derive_receipt_operation_uuid(
                operation_id=request.operation_id,
                owner_generation=request.owner_generation,
                request_sha256=request_digest,
            )
            receipt_path = receipt_root.target_path(
                operation_id=receipt_operation_uuid,
                owner_generation=request.owner_generation,
                request_sha256=request_digest,
            )
            option = "ro" if request.read_only else "sync_type=unmount"
            event_reader, event_writer = os.pipe2(os.O_CLOEXEC)
            argv = (
                str(targets.ltfs_exec_path),
                "-f",
                f"--event-fd={event_writer}",
                "--event-schema=1",
                f"--operation-id={receipt_operation_uuid}",
                "-o",
                f"devname=/proc/self/fd/{targets.scsi_fd}",
                "-o",
                "subtype=ltfs",
                "-o",
                "fsname=ltfs",
                "-o",
                "allow_other",
                "-o",
                "default_permissions",
                "-o",
                f"uid={self.daemon_uid}",
                "-o",
                f"gid={self.daemon_gid}",
                "-o",
                "umask=027",
                "-o",
                option,
                "-o",
                f"standalone_receipt={receipt_path}",
                str(targets.mount_path),
            )
            launch = executor.spawn_blocked(
                argv,
                pass_fds=(targets.ltfs_fd, targets.scsi_fd, event_writer),
            )
            os.close(event_writer)
            event_writer = -1
            event_drain = threading.Thread(
                target=drain_ltfs_event_stream,
                args=(event_reader,),
                kwargs={
                    "sink": self._event_sink,
                    "correlation": correlation,
                    "expected_stream_operation_id": receipt_operation_uuid,
                },
                name="lto-ltfs-event-drain",
                daemon=True,
            )
            event_drain.start()
            event_reader = -1
            process = self._require_process(
                process_probe.observe(launch.pid), pid=launch.pid
            )
            proof = self.cgroup.attach(
                scope_record,
                launch.pid,
                daemon_uid=_BROKER_CHILD_UID,
                store=self.store,
            )
            if (
                getattr(proof, "pid", None) != launch.pid
                or getattr(proof, "start_ticks", None) != process.start_ticks
            ):
                raise LtfsLifecycleUnavailable
            scope_record = self._scope_record(scope_receipt)
            validation = self.cgroup.validate(scope_record)
            if validation.populated is not True or validation.member_pids != (
                launch.pid,
            ):
                raise LtfsLifecycleUnavailable
            self._require_process(
                process_probe.observe(launch.pid),
                pid=launch.pid,
                start_ticks=process.start_ticks,
                mount_namespace_sha256=process.mount_namespace_sha256,
            )
            self.store.bind_ltfs_child(
                request,
                launch.pid,
                process.start_ticks,
                process.mount_namespace_sha256,
            )
            targets.assert_launch_anchors()
            executor.release_launch(launch)
            phases.start("mount", read_only=request.read_only)
            mounted = mount_probe.await_mounted(targets.mount_path)
            if (
                getattr(mounted, "target", None) != targets.mount_path
                or getattr(mounted, "fs_type", None) != "fuse.ltfs"
                or getattr(mounted, "source", None) != "ltfs"
            ):
                raise LtfsLifecycleUnavailable
            ready = receipt_root.wait_ready(
                operation_id=receipt_operation_uuid,
                owner_generation=request.owner_generation,
                request_sha256=request_digest,
                expected_media_identity_sha256=(request.observed_media_identity_sha256),
                expected_read_only=request.read_only,
                timeout=self.ltfs_mount_ready_timeout,
            )
            if (
                request.expected_volume_uuid is not None
                and ready.volume_uuid != request.expected_volume_uuid
                or ready.prior_generation != request.expected_prior_generation
            ):
                raise LtfsLifecycleUnavailable
            self._require_process(
                process_probe.observe(launch.pid),
                pid=launch.pid,
                start_ticks=process.start_ticks,
                mount_namespace_sha256=process.mount_namespace_sha256,
            )
            validation = self.cgroup.validate(self._scope_record(scope_receipt))
            if validation.populated is not True or validation.member_pids != (
                launch.pid,
            ):
                raise LtfsLifecycleUnavailable
            receipt = self._new_ltfs_receipt(request, process, ready)
            self.store.mark_ltfs_mounted(receipt)
            phases.succeed("mount", read_only=request.read_only)
            self._active_ltfs = _ActiveLtfsSession(
                request, targets, launch, receipt, scope_receipt
            )
            return {"receipt": receipt}
        except Exception:
            if transition_started:
                phases.fail("mount", read_only=request.read_only)
            if transition_started:
                self._contain_ltfs(
                    request=request,
                    targets=targets,
                    launch=launch,
                    scope_receipt=scope_receipt,
                    start_ticks=(
                        None
                        if process is None
                        else getattr(process, "start_ticks", None)
                    ),
                )
                raise BrokerStateUnavailable from None
            if targets is not None:
                with contextlib.suppress(Exception):
                    targets.close()
            try:
                self._close_unbound_ltfs_scope(scope_receipt)
            except Exception:  # noqa: BLE001 - rejected scope must become terminal
                with contextlib.suppress(BrokerStateConflict, BrokerStateUnavailable):
                    self.store.mark_scope(scope_receipt, "BROKEN")
                raise BrokerStateUnavailable from None
            raise
        finally:
            if event_reader >= 0:
                with contextlib.suppress(OSError):
                    os.close(event_reader)
            if event_writer >= 0:
                with contextlib.suppress(OSError):
                    os.close(event_writer)

    def _close_unbound_ltfs_scope(
        self, scope_receipt: BrokeredCgroupScopeReceipt
    ) -> None:
        sessions_for_reconciliation = getattr(
            self.store, "ltfs_sessions_for_reconciliation", None
        )
        if sessions_for_reconciliation is not None:
            try:
                linked = any(
                    session.cgroup_scope_id == scope_receipt.scope_id
                    and session.state != "UNMOUNTED"
                    for session in sessions_for_reconciliation()
                )
            except (BrokerStateConflict, BrokerStateUnavailable):
                raise BrokerStateUnavailable from None
            if linked:
                return
        rejected_scope = self._scope_record(scope_receipt)
        validation = self.cgroup.validate(rejected_scope)
        if validation.populated or validation.member_pids:
            raise LtfsLifecycleUnavailable
        self.cgroup.release(rejected_scope)
        self.store.mark_scope(scope_receipt, "CLOSED")

    def _observe_ltfs_session(self, params: Mapping[str, object]) -> dict[str, object]:
        self._require_ltfs_runtime()
        receipt = self._verify_ltfs_receipt(params.get("receipt"))
        active = self._active_ltfs
        if (
            active is None
            or active.receipt != receipt
            or params.get("operation_id") != receipt.operation_id
            or params.get("owner_generation") != receipt.owner_generation
        ):
            raise BrokerStateConflict
        try:
            self._require_ltfs_health(active)
            challenge = params.get("challenge")
            if type(challenge) is not bytes or len(challenge) != 32:
                raise BrokerProtocolError
            while True:
                observation_nonce = secrets.token_bytes(32)
                fields = {
                    "protocol_version": 1,
                    "receipt": _ltfs_receipt_mapping(receipt),
                    "challenge": challenge,
                    "observation_nonce": observation_nonce,
                    "mounted": True,
                }
                proof = self._proof("ltfs-observation-v1", fields)
                if len({challenge, observation_nonce, proof}) == 3:
                    break
            transition = self.store.record_ltfs_observation(
                receipt,
                challenge=challenge,
                observation_nonce=observation_nonce,
                broker_proof=proof,
            )
            return {
                "receipt": receipt,
                "challenge": challenge,
                "observation_nonce": transition.record.observation_nonce,
                "broker_proof": transition.record.broker_proof,
                "mounted": True,
            }
        except BrokerProtocolError:
            raise
        except Exception:  # noqa: BLE001 - ambiguity requires containment
            self._contain_ltfs(
                request=active.request,
                targets=active.targets,
                launch=active.launch,
                scope_receipt=active.scope_receipt,
                start_ticks=active.receipt.child_start_ticks,
            )
            raise BrokerStateUnavailable from None

    def _finalize_ltfs_session(self, params: Mapping[str, object]) -> dict[str, object]:
        _pins, receipt_root, executor, mount_probe, process_probe = (
            self._require_ltfs_runtime()
        )
        receipt = self._verify_ltfs_receipt(params.get("receipt"))
        active = self._active_ltfs
        if (
            active is None
            or active.receipt != receipt
            or params.get("operation_id") != receipt.operation_id
            or params.get("owner_generation") != receipt.owner_generation
        ):
            raise BrokerStateConflict
        request_nonce = params.get("request_nonce")
        if type(request_nonce) is not bytes or len(request_nonce) != 32:
            raise BrokerProtocolError
        finalization_started = False
        correlation = closed_operational_correlation(
            operation_id=receipt.operation_id,
            daemon_generation=receipt.owner_generation,
        )
        phases = OperationalPhaseTracker(self._event_sink, correlation)
        try:
            self._require_ltfs_health(active)
            self.store.begin_ltfs_finalization(receipt, request_nonce)
            finalization_started = True
            phases.start("finalizing_index")
            phases.start("unmount")
            active.targets.assert_finalization_anchors()
            argv = (
                str(active.targets.fusermount_exec_path),
                "-u",
                "--",
                str(active.targets.mount_path),
            )
            if (
                executor.run_fusermount(argv, pass_fds=(active.targets.fusermount_fd,))
                != 0
            ):
                raise LtfsLifecycleUnavailable
            if mount_probe.await_unmounted(active.targets.mount_path) is not True:
                raise LtfsLifecycleUnavailable
            if (
                executor.reap_natural(
                    active.launch,
                    pid=receipt.child_pid,
                    start_ticks=receipt.child_start_ticks,
                    timeout=self.ltfs_finalize_timeout,
                )
                is not True
            ):
                raise LtfsLifecycleUnavailable
            self.store.bind_ltfs_child_exit_zero(receipt)
            standalone = receipt_root.read_terminal(
                operation_id=receipt.receipt_operation_uuid,
                owner_generation=receipt.owner_generation,
                request_sha256=receipt.request_sha256,
            )
            if (
                standalone.volume_uuid != receipt.observed_volume_uuid
                or standalone.prior_generation != receipt.observed_prior_generation
                or (
                    active.request.expected_volume_uuid is not None
                    and standalone.volume_uuid != active.request.expected_volume_uuid
                )
                or (
                    active.request.read_only
                    and standalone.new_generation != standalone.prior_generation
                )
                or (
                    not active.request.read_only
                    and standalone.new_generation < standalone.prior_generation
                )
            ):
                raise LtfsLifecycleUnavailable
            self.store.bind_ltfs_terminal_receipt(receipt, standalone)
            if process_probe.observe(receipt.child_pid) is not None:
                raise LtfsLifecycleUnavailable
            scope_record = self._scope_record(active.scope_receipt)
            validation = self.cgroup.validate(scope_record)
            if validation.populated is not False or validation.member_pids != ():
                raise LtfsLifecycleUnavailable
            active.targets.close()
            while True:
                finalization_nonce = secrets.token_bytes(32)
                provisional = LtfsFinalizationReceipt(
                    1,
                    receipt,
                    standalone,
                    request_nonce,
                    finalization_nonce,
                    b"x" * 32,
                    True,
                    True,
                )
                proof = self._proof(
                    "ltfs-finalization-receipt-v1",
                    _ltfs_finalization_fields(provisional),
                )
                if len({request_nonce, finalization_nonce, proof}) == 3:
                    final_receipt = replace(provisional, broker_proof=proof)
                    break
            self.store.mark_ltfs_unmounted(final_receipt)
            phases.succeed("finalizing_index")
            phases.succeed("unmount")
            self.cgroup.release(scope_record)
            self.store.mark_scope(active.scope_receipt, "CLOSED")
            self._active_ltfs = None
            return {"receipt": final_receipt}
        except BrokerProtocolError:
            raise
        except Exception:  # noqa: BLE001 - post-finalization must never kill media I/O
            if finalization_started:
                phases.fail_open()
            if not finalization_started:
                self._contain_ltfs(
                    request=active.request,
                    targets=active.targets,
                    launch=active.launch,
                    scope_receipt=active.scope_receipt,
                    start_ticks=active.receipt.child_start_ticks,
                )
                raise BrokerStateUnavailable from None
            self._reconciliation_clean = False
            raise BrokerStateUnavailable from None

    def _recover_ltfs_finalization(
        self, params: Mapping[str, object]
    ) -> dict[str, object]:
        operation_id = params.get("operation_id")
        owner_generation = params.get("owner_generation")
        if type(operation_id) is not str or type(owner_generation) is not int:
            raise BrokerProtocolError
        record = self.store.ltfs_session(operation_id, owner_generation)
        expected = (
            params.get("mount_path_sha256"),
            params.get("tape_device_identity_sha256"),
            params.get("scsi_device_identity_sha256"),
            params.get("expected_media_scope_sha256"),
            params.get("observed_media_identity_sha256"),
        )
        actual = (
            record.mount_path_sha256,
            record.tape_device_identity_sha256,
            record.scsi_device_identity_sha256,
            record.expected_media_scope_sha256,
            record.observed_media_identity_sha256,
        )
        if expected != actual or record.state != "UNMOUNTED":
            raise BrokerStateConflict
        required = (
            record.finalization_request_nonce,
            record.finalization_nonce,
            record.finalization_broker_proof,
            record.standalone_receipt_json,
        )
        if any(value is None for value in required):
            raise BrokerStateConflict
        session = self._ltfs_receipt_from_record(record)
        try:
            from ltobackup.broker.protocol import (
                _transform_ltfs_standalone_receipt,
            )

            standalone = _transform_ltfs_standalone_receipt(
                json.loads(record.standalone_receipt_json), encode=False
            )
        except (BrokerProtocolError, TypeError, ValueError, json.JSONDecodeError):
            raise BrokerStateConflict from None
        receipt = LtfsFinalizationReceipt(
            1,
            session,
            standalone,
            record.finalization_request_nonce,
            record.finalization_nonce,
            record.finalization_broker_proof,
            True,
            True,
        )
        if not hmac.compare_digest(
            receipt.broker_proof,
            self._proof(
                "ltfs-finalization-receipt-v1",
                _ltfs_finalization_fields(receipt),
            ),
        ):
            raise BrokerStateConflict
        return {"receipt": receipt}

    def _readiness_result(self, challenge: object) -> dict[str, object]:
        """Issue one fresh capability proof for the current clean state."""

        try:
            if (
                self._reconciliation_clean is not True
                or type(challenge) is not bytes
                or len(challenge) != 32
            ):
                raise BrokerStateUnavailable
            pins, _receipt_root, _executor, _mount_probe, _process_probe = (
                self._require_ltfs_runtime()
            )
            assert_readiness_anchors = pins.assert_readiness_anchors
            if not callable(assert_readiness_anchors):
                raise BrokerStateUnavailable
            assert_readiness_anchors()
            records = self.store.scopes_for_reconciliation()
            if any(getattr(record, "state", None) == "BROKEN" for record in records):
                raise BrokerStateUnavailable
            ltfs_ready = getattr(self.store, "ltfs_sessions_ready", None)
            if not callable(ltfs_ready) or ltfs_ready() is not True:
                raise BrokerStateUnavailable
            self.cgroup.validate_readiness()
            while True:
                reconciliation_nonce = secrets.token_bytes(32)
                features: dict[str, object] = {
                    "broker_state": True,
                    "delegated_cgroup": True,
                    "recursive_population": True,
                    "cgroup_kill": True,
                    "ltfs_session_contract": 1,
                    "challenge": challenge,
                    "reconciliation_nonce": reconciliation_nonce,
                    "ltfs_tool_identity_sha256": (pins.ltfs_tool_identity_sha256),
                    "fusermount_tool_identity_sha256": (
                        pins.fusermount_tool_identity_sha256
                    ),
                    "reconciliation_clean": True,
                }
                proof = hmac.new(
                    self._capability,
                    readiness_capability_payload(features),
                    hashlib.sha256,
                ).digest()
                if (
                    reconciliation_nonce not in self._readiness_reconciliation_nonces
                    and len({challenge, reconciliation_nonce, proof}) == 3
                ):
                    self._readiness_reconciliation_nonces.add(reconciliation_nonce)
                    features["capability_proof"] = proof
                    return {"nonce": challenge, "features": features}
        except BrokerProtocolError:
            self._reconciliation_clean = False
            raise BrokerStateUnavailable from None
        except Exception:  # noqa: BLE001 - readiness is a fail-closed boundary
            self._reconciliation_clean = False
            raise BrokerStateUnavailable from None

    @staticmethod
    def _qualification_dispatch_from_record(
        record: object,
    ) -> BrokerQualificationDispatch:
        if (
            getattr(record, "state", None) != "TERMINAL"
            or getattr(record, "terminal_receipt_sha256", None) is None
            or getattr(record, "child_exit_code", None) is None
            or getattr(record, "evidence_sha256", None) is None
            or getattr(record, "broker_nonce", None) is None
            or getattr(record, "broker_proof", None) is None
        ):
            raise BrokerStateConflict
        return BrokerQualificationDispatch(
            protocol_version=1,
            run_id=record.run_id,
            stage_ordinal=record.stage_ordinal,
            operation=record.operation,
            request_sha256=record.request_sha256,
            dispatch_state="terminal",
            terminal_receipt_sha256=record.terminal_receipt_sha256,
            child_exit_code=record.child_exit_code,
            evidence_sha256=record.evidence_sha256,
            broker_nonce=record.broker_nonce,
            broker_proof=record.broker_proof,
        )

    def _execute_ltfs_qualification_stage(
        self, params: Mapping[str, object]
    ) -> dict[str, object]:
        request = params.get("request")
        if type(request) is not BrokerQualificationRequest:
            raise BrokerProtocolError
        request.require_execution_authority()
        if self._qualification_executor is None:
            raise BrokerStateUnavailable
        prepared = self.store.prepare_ltfs_qualification(request)
        if prepared.record.state == "TERMINAL":
            return {
                "dispatch": self._qualification_dispatch_from_record(prepared.record)
            }
        if prepared.record.state in {"DISPATCHED", "FENCED"}:
            raise BrokerStateConflict
        dispatched = self.store.mark_ltfs_qualification_dispatched(request)
        if not dispatched.transitioned:
            raise BrokerStateConflict
        try:
            with self._ltfs_lock:
                if self._active_ltfs is not None or self._finalizing_monitors:
                    raise BrokerStateUnavailable
                result = self._qualification_executor.execute(request)
            if type(result) is not BrokerQualificationExecution:
                raise BrokerStateConflict
            accepted = qualification_success_exit_codes(request.operation)
            if result.child_exit_code not in accepted:
                raise BrokerStateConflict
            while True:
                broker_nonce = secrets.token_bytes(32)
                unsigned = BrokerQualificationDispatch(
                    protocol_version=1,
                    run_id=request.run_id,
                    stage_ordinal=request.stage_ordinal,
                    operation=request.operation,
                    request_sha256=request.request_sha256,
                    dispatch_state="terminal",
                    terminal_receipt_sha256=result.terminal_receipt_sha256,
                    child_exit_code=result.child_exit_code,
                    evidence_sha256=result.evidence_sha256,
                    broker_nonce=broker_nonce,
                    broker_proof=b"\0" * 32,
                )
                proof = hmac.new(
                    self._capability,
                    qualification_dispatch_proof_payload(unsigned),
                    hashlib.sha256,
                ).digest()
                if len({request.request_nonce, broker_nonce, proof}) == 3:
                    break
            dispatch = replace(unsigned, broker_proof=proof)
            completed = self.store.complete_ltfs_qualification(request, dispatch)
            return {
                "dispatch": self._qualification_dispatch_from_record(completed.record)
            }
        except BaseException:
            with contextlib.suppress(Exception):
                self.store.fence_ltfs_qualification(request)
            raise

    def _inspect_ltfs_qualification_stage(
        self, params: Mapping[str, object]
    ) -> dict[str, object]:
        request = params.get("request")
        if type(request) is not BrokerQualificationInspectionRequest:
            raise BrokerProtocolError
        snapshot = self.store.inspect_ltfs_qualification_stage(
            request.run_id, request.stage_ordinal
        )
        if snapshot is None:
            state = "missing"
            dispatch = None
        else:
            state = {
                "PREPARED": "pre_dispatch",
                "DISPATCHED": "dispatched",
                "TERMINAL": "terminal",
                "FENCED": "fenced",
            }.get(snapshot["state"])
            if state is None:
                raise BrokerStateConflict
            dispatch = None
            if state == "terminal":
                record = self.store.ltfs_qualification_stage(
                    request.run_id, request.stage_ordinal
                )
                if record is None or record.state != "TERMINAL":
                    raise BrokerStateConflict
                dispatch = self._qualification_dispatch_from_record(record)
        observation_nonce = secrets.token_bytes(32)
        unsigned = BrokerQualificationInspection(
            state=state,
            stage_snapshot=snapshot,
            dispatch=dispatch,
            observation_nonce=observation_nonce,
            proof=b"\0" * 32,
        )
        proof = hmac.new(
            self._capability,
            qualification_inspection_proof_payload(request, unsigned),
            hashlib.sha256,
        ).digest()
        return {"inspection": replace(unsigned, proof=proof)}

    def _dispatch(
        self, request: BrokerRequest, descriptors: tuple[int, ...]
    ) -> dict[str, object]:
        method = request.method
        params = request.params
        if method == "readiness":
            with self._ltfs_lock:
                return self._readiness_result(params["nonce"])
        if method == "create_scope":
            command_id = params["command_id"]
            generation = params["owner_generation"]
            nonce = params["request_nonce"]
            if not (
                type(command_id) is str
                and type(generation) is int
                and type(nonce) is bytes
            ):
                raise BrokerProtocolError
            digest = CgroupV2BrokerRoot.scope_path_sha256(command_id, generation)
            receipt = self._new_receipt(
                command_id=command_id,
                owner_generation=generation,
                request_nonce=nonce,
                scope_id="scope-" + secrets.token_hex(24),
                scope_path_sha256=digest,
            )
            record = self.store.create_scope(receipt)
            try:
                self.cgroup.create(record, self.store)
            except Exception:
                with contextlib.suppress(Exception):
                    self.store.mark_scope(receipt, "BROKEN")
                raise
            return {"receipt": _receipt_mapping(receipt)}
        if method == "open_scope":
            command_id = params["command_id"]
            generation = params["owner_generation"]
            nonce = params["request_nonce"]
            if not (
                type(command_id) is str
                and type(generation) is int
                and type(nonce) is bytes
            ):
                raise BrokerProtocolError
            record = self.store.scope_for_identity(command_id, generation)
            receipt = self._new_receipt(
                command_id=record.command_id,
                owner_generation=record.owner_generation,
                request_nonce=nonce,
                scope_id=record.scope_id,
                scope_path_sha256=record.scope_path_sha256,
            )
            record = self.store.open_scope(receipt)
            self.cgroup.open(record)
            return {"receipt": _receipt_mapping(receipt)}

        if method == "start_ltfs_session":
            request_model = params.get("request")
            if type(request_model) is not LtfsSessionRequest:
                raise BrokerProtocolError
            with self._ltfs_lock, self._command_lifecycle_lock:
                return self._start_ltfs_session(request_model, descriptors)
        if method == "observe_ltfs_session":
            with self._ltfs_lock:
                return self._observe_ltfs_session(params)
        if method == "finalize_ltfs_session":
            with self._ltfs_lock:
                return self._finalize_ltfs_session(params)
        if method == "recover_ltfs_finalization":
            with self._ltfs_lock:
                return self._recover_ltfs_finalization(params)
        if method == "execute_ltfs_qualification_stage":
            return self._execute_ltfs_qualification_stage(params)
        if method == "inspect_ltfs_qualification_stage":
            return self._inspect_ltfs_qualification_stage(params)

        with self._command_lifecycle_lock:
            return self._dispatch_scope_command(request, descriptors)

    def _dispatch_scope_command(
        self, request: BrokerRequest, descriptors: tuple[int, ...]
    ) -> dict[str, object]:
        method = request.method
        params = request.params
        receipt = self._verify_receipt(params["receipt"])
        if method == "attach":
            record = self._scope_record(receipt)
            self.cgroup.attach(
                record,
                params["pid"],
                daemon_uid=self.daemon_uid,
                store=self.store,
            )
            return {}
        if method == "validate_scope":
            validation = self.cgroup.validate(self._scope_record(receipt))
            challenge = params["challenge"]
            nonce = secrets.token_bytes(32)
            fields = {
                "protocol_version": 1,
                "receipt": _receipt_mapping(receipt),
                "challenge": challenge,
                "validation_nonce": nonce,
                "populated": validation.populated,
                "member_pids": validation.member_pids,
            }
            result = BrokeredCgroupScopeValidation(
                1,
                receipt,
                challenge,
                nonce,
                self._proof("scope-validation-v1", fields),
                validation.populated,
                validation.member_pids,
            )
            return {
                "validation": {
                    **fields,
                    "broker_proof": result.broker_proof,
                }
            }
        if method == "prepare_release":
            pid = params["pid"]
            self._revalidate_child(receipt, pid)
            provisional = BrokeredCgroupReleasePermit(
                1,
                receipt,
                pid,
                params["request_nonce"],
                secrets.token_bytes(32),
                b"x" * 32,
            )
            permit = replace(
                provisional,
                broker_proof=self._proof(
                    "release-permit-v1", _permit_fields(provisional)
                ),
            )
            self.store.prepare_permit(permit)
            return {"permit": _permit_mapping(permit)}
        if method == "release_child":
            if len(descriptors) != 1:
                raise BrokerProtocolError
            release_fd = descriptors[0]
            pid = params["pid"]
            permit = self._verify_permit(params["permit"], receipt, pid)
            self._revalidate_child(receipt, pid)
            transition = self.store.commit_release(permit, permit_sha256(permit))
            if not transition.transitioned:
                raise _AmbiguousRelease
            try:
                if os.write(release_fd, b"1") != 1:
                    raise OSError("short release write")
            except OSError:
                raise _AmbiguousRelease from None
            return {}
        if method == "claim_unreleased":
            pid = params["pid"]
            digest = params["permit_sha256"]
            transition = self.store.claim_or_observe(receipt, pid, digest)
            released = transition.record.state == "RELEASE_COMMITTED"
            revoked = transition.record.state == "REVOKED"
            if not (released ^ revoked):
                raise BrokerStateUnavailable
            challenge = params["challenge"]
            nonce = secrets.token_bytes(32)
            fields = {
                "protocol_version": 1,
                "receipt": _receipt_mapping(receipt),
                "pid": pid,
                "permit_sha256": digest,
                "challenge": challenge,
                "claim_nonce": nonce,
                "released": released,
                "permit_revoked": revoked,
            }
            claim = BrokeredCgroupReleaseClaim(
                1,
                receipt,
                pid,
                digest,
                challenge,
                nonce,
                self._proof("release-claim-v1", fields),
                released,
                revoked,
            )
            return {"claim": {**fields, "broker_proof": claim.broker_proof}}
        if method == "signal_scope":
            self.cgroup.signal(
                self._scope_record(receipt),
                params["signum"],
                daemon_uid=self.daemon_uid,
                store=self.store,
            )
            return {}
        if method == "kill_scope":
            self.cgroup.kill(self._scope_record(receipt))
            return {}
        if method == "release_scope":
            record = self._scope_record(receipt)
            if record.state == "CLOSED":
                # Only the broker's exact device/inode release cache can prove
                # an in-process retry. A missing path alone is never success.
                self.cgroup.release(record)
                self.store.mark_scope(receipt, "CLOSED")
                return {}
            validation = self.cgroup.validate(record)
            if validation.populated or validation.member_pids:
                raise CgroupConflict
            # A prepare response can be lost after the permit was persisted.
            # Revoke it durably before removing its only physical scope proof.
            self.store.revoke_scope_prepared_permits(receipt)
            self.cgroup.release(record)
            self.store.mark_scope(receipt, "CLOSED")
            return {}
        raise BrokerProtocolError

    def serve(self, listener: socket.socket) -> None:
        if (
            type(listener) is not socket.socket
            or listener.family != socket.AF_UNIX
            or listener.type & 0xF != socket.SOCK_SEQPACKET
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        ):
            raise ValueError("invalid command broker listener")
        self._listener = listener
        listener.settimeout(min(self.connection_timeout, 0.5))
        try:
            while not self._shutdown.is_set():
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._shutdown.is_set():
                        break
                    raise
                os.set_inheritable(connection.fileno(), False)
                if not self._slots.acquire(blocking=False):
                    connection.close()
                    continue
                worker = threading.Thread(
                    target=self._serve_worker,
                    args=(connection,),
                    name="command-broker-connection",
                    daemon=False,
                )
                with self._workers_lock:
                    self._workers.add(worker)
                worker.start()
        finally:
            self._listener = None
            self._shutdown.set()
            with self._workers_lock:
                workers = tuple(self._workers)
            for worker in workers:
                worker.join()

    def _serve_worker(self, connection: socket.socket) -> None:
        try:
            self.handle_connection(connection)
        finally:
            self._slots.release()
            current = threading.current_thread()
            with self._workers_lock:
                self._workers.discard(current)

    def shutdown(self) -> None:
        self._shutdown.set()

    def close(self) -> None:
        """Contain any live LTFS session before dependent resources close."""

        self.shutdown()
        with self._ltfs_lock:
            active = self._active_ltfs
            if active is not None:
                with contextlib.suppress(Exception):
                    record = self.store.ltfs_session(
                        active.request.operation_id,
                        active.request.owner_generation,
                    )
                    if record.finalization_request_nonce is not None:
                        self._reconciliation_clean = False
                        return
                self._contain_ltfs(
                    request=active.request,
                    targets=active.targets,
                    launch=active.launch,
                    scope_receipt=active.scope_receipt,
                    start_ticks=active.receipt.child_start_ticks,
                )
