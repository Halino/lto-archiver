from __future__ import annotations

import array
import contextlib
import hashlib
import hmac
import math
import os
import secrets
import signal
import socket
import stat
import struct
import uuid
import weakref
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ltobackup.broker.ltfs_session import (
    LtfsPinningError,
    device_fd_identity_sha256,
)
from ltobackup.broker.protocol import (
    MAX_PACKET_BYTES,
    BrokerProtocolError,
    BrokerRequest,
    LtfsProtocolAuthority,
    decode_response,
    encode_request,
    readiness_capability_payload,
)
from ltobackup.daemon.models import OperationFence, RecoveryCommandFence
from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    BrokerQualificationRequest,
    qualification_dispatch_proof_payload,
    qualification_inspection_proof_payload,
)
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupExecutionScopeManager,
    BrokeredCgroupReleaseClaim,
    BrokeredCgroupReleasePermit,
    BrokeredCgroupScopeReceipt,
    BrokeredCgroupScopeToken,
    BrokeredCgroupScopeValidation,
    CommandError,
    ExecutionScopeIdentity,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
)

_MAX_SOCKET_PATH_BYTES = 107
_MAX_TIMEOUT_SECONDS = 86_400.0
_FD_ITEM_SIZE = array.array("i").itemsize
_ANCILLARY_BUFFER_BYTES = socket.CMSG_SPACE(16 * _FD_ITEM_SIZE)
_BROKER_SOCKET_UID = 0
_BROKER_SOCKET_MODE = 0o660
_BROKER_RUNTIME_MODE = 0o750
_BROKER_PEER_UID = 0
_BROKER_FAILURE_REASONS = frozenset(
    {"timeout", "eof", "protocol", "rejected", "pre_dispatch", "transport", "unavailable"}
)


class BrokerUnavailable(RuntimeError):
    """The authenticated local broker exchange did not complete exactly."""

    def __init__(self, *, reason: str = "unavailable") -> None:
        super().__init__("command broker unavailable")
        self._reason = (
            reason
            if type(reason) is str and reason in _BROKER_FAILURE_REASONS
            else "unavailable"
        )

    @property
    def reason(self) -> str:
        """A bounded diagnostic category, never privileged exception details."""
        return self._reason


class _BrokerPreDispatch(BrokerUnavailable):
    pass


class _BrokerDefiniteRejection(BrokerUnavailable):
    pass


class _BrokerDispatchAmbiguous(BrokerUnavailable):
    pass


def _ltfs_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("LTFS session digest is invalid")
    return value


@dataclass(frozen=True)
class LtfsSessionAdmission:
    """Digest-only daemon authority for one broker-owned LTFS session."""

    operation_id: str
    owner_generation: int
    mount_path_sha256: str
    tape_device_identity_sha256: str
    scsi_device_identity_sha256: str
    expected_media_scope_sha256: str
    observed_media_identity_sha256: str
    expected_volume_uuid: str
    expected_prior_generation: int
    read_only: bool

    def __post_init__(self) -> None:
        if (
            type(self.operation_id) is not str
            or not self.operation_id
            or len(self.operation_id) > 1024
            or not self.operation_id.isascii()
            or not self.operation_id.isprintable()
            or "/" in self.operation_id
            or "\\" in self.operation_id
            or type(self.owner_generation) is not int
            or self.owner_generation < 0
            or type(self.read_only) is not bool
            or self.expected_volume_uuid is None
            or type(self.expected_prior_generation) is not int
            or not 0 < self.expected_prior_generation < 1 << 64
        ):
            raise ValueError("LTFS session admission is invalid")
        try:
            if str(uuid.UUID(self.expected_volume_uuid)) != self.expected_volume_uuid:
                raise ValueError
        except (ValueError, AttributeError, TypeError):
            raise ValueError("LTFS session admission is invalid") from None
        for value in (
            self.mount_path_sha256,
            self.tape_device_identity_sha256,
            self.scsi_device_identity_sha256,
            self.expected_media_scope_sha256,
            self.observed_media_identity_sha256,
        ):
            _ltfs_digest(value)


@dataclass(frozen=True)
class LtfsSessionRecoveryAdmission:
    """Catalog-attested authority to finalize one pending LTFS session."""

    fence: OperationFence | RecoveryCommandFence
    original_owner_generation: int
    mount_path_sha256: str
    tape_device_identity_sha256: str
    scsi_device_identity_sha256: str
    expected_media_scope_sha256: str
    observed_media_identity_sha256: str

    def __post_init__(self) -> None:
        if (
            type(self.fence) not in {OperationFence, RecoveryCommandFence}
            or type(self.fence.operation_id) is not str
            or not self.fence.operation_id
            or len(self.fence.operation_id) > 1024
            or not self.fence.operation_id.isascii()
            or not self.fence.operation_id.isprintable()
            or "/" in self.fence.operation_id
            or "\\" in self.fence.operation_id
            or type(self.fence.owner_generation) is not int
            or not 0 <= self.fence.owner_generation < 1 << 63
            or type(self.original_owner_generation) is not int
            or not 0 <= self.original_owner_generation < 1 << 63
            or (
                type(self.fence) is OperationFence
                and self.original_owner_generation != self.fence.owner_generation
            )
            or (
                type(self.fence) is RecoveryCommandFence
                and self.original_owner_generation >= self.fence.owner_generation
            )
        ):
            raise ValueError("LTFS recovery fence is invalid")
        for value in (
            self.mount_path_sha256,
            self.tape_device_identity_sha256,
            self.scsi_device_identity_sha256,
            self.expected_media_scope_sha256,
            self.observed_media_identity_sha256,
        ):
            _ltfs_digest(value)


class LtfsSessionHandle:
    """Opaque, non-transferable lifecycle handle issued by one broker client."""

    __slots__ = ("__weakref__", "_receipt")

    def __init__(
        self, receipt: LtfsSessionReceipt, *, _issuer: object | None = None
    ) -> None:
        if (
            _issuer is not _LTFS_HANDLE_ISSUER
            or type(receipt) is not LtfsSessionReceipt
        ):
            raise TypeError("LTFS session handles are issued by the broker client")
        object.__setattr__(self, "_receipt", receipt)

    @property
    def receipt(self) -> LtfsSessionReceipt:
        return self._receipt

    def __setattr__(self, _name: str, _value: object) -> None:
        raise TypeError("LTFS session handles are immutable")

    def __copy__(self) -> LtfsSessionHandle:
        raise TypeError("LTFS session handles cannot be copied")

    def __deepcopy__(self, _memo: dict[int, object]) -> LtfsSessionHandle:
        raise TypeError("LTFS session handles cannot be copied")

    def __reduce__(self) -> object:
        raise TypeError("LTFS session handles cannot be serialized")

    def __repr__(self) -> str:
        return "<LtfsSessionHandle>"


_LTFS_HANDLE_ISSUER = object()


def _issue_ltfs_session_handle(receipt: LtfsSessionReceipt) -> LtfsSessionHandle:
    return LtfsSessionHandle(receipt, _issuer=_LTFS_HANDLE_ISSUER)


@dataclass
class _ClientLtfsSession:
    receipt: LtfsSessionReceipt
    authority: LtfsProtocolAuthority
    admission: LtfsSessionAdmission
    pending_cleanup: bool = False


class LtfsSessionApi(Protocol):
    def start_ltfs_session(
        self,
        admission: LtfsSessionAdmission,
        *,
        tape_fd: int,
        scsi_fd: int,
    ) -> LtfsSessionHandle: ...

    def observe_ltfs_session(self, handle: LtfsSessionHandle) -> LtfsSessionReceipt: ...

    def finalize_ltfs_session(
        self, handle: LtfsSessionHandle
    ) -> LtfsFinalizationReceipt: ...

    def recover_pending_ltfs_session(
        self, admission: LtfsSessionRecoveryAdmission
    ) -> LtfsFinalizationReceipt | None: ...


class LtfsQualificationApi(Protocol):
    def execute_ltfs_qualification_stage(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationDispatch: ...

    def inspect_ltfs_qualification_stage(
        self,
        request: BrokerQualificationInspectionRequest | str,
        stage_ordinal: int | None = None,
    ) -> BrokerQualificationInspection: ...


def _receipt_mapping(receipt: BrokeredCgroupScopeReceipt) -> dict[str, object]:
    if type(receipt) is not BrokeredCgroupScopeReceipt:
        raise BrokerProtocolError
    return {
        "protocol_version": receipt.protocol_version,
        "command_id": receipt.command_id,
        "owner_generation": receipt.owner_generation,
        "request_nonce": receipt.request_nonce,
        "scope_id": receipt.scope_id,
        "scope_path_sha256": receipt.scope_path_sha256,
        "broker_nonce": receipt.broker_nonce,
        "broker_proof": receipt.broker_proof,
        "recursive_population": receipt.recursive_population,
        "recursive_members": receipt.recursive_members,
        "cgroup_kill": receipt.cgroup_kill,
    }


def _receipt_from_mapping(value: object) -> BrokeredCgroupScopeReceipt:
    if type(value) is not dict:
        raise BrokerProtocolError
    return BrokeredCgroupScopeReceipt(**value)


def _permit_mapping(permit: BrokeredCgroupReleasePermit) -> dict[str, object]:
    if type(permit) is not BrokeredCgroupReleasePermit:
        raise BrokerProtocolError
    return {
        "protocol_version": permit.protocol_version,
        "receipt": _receipt_mapping(permit.receipt),
        "pid": permit.pid,
        "request_nonce": permit.request_nonce,
        "permit_nonce": permit.permit_nonce,
        "broker_proof": permit.broker_proof,
    }


def _permit_from_mapping(value: object) -> BrokeredCgroupReleasePermit:
    if type(value) is not dict:
        raise BrokerProtocolError
    source = dict(value)
    source["receipt"] = _receipt_from_mapping(source.get("receipt"))
    return BrokeredCgroupReleasePermit(**source)


def _validation_from_mapping(value: object) -> BrokeredCgroupScopeValidation:
    if type(value) is not dict:
        raise BrokerProtocolError
    source = dict(value)
    source["receipt"] = _receipt_from_mapping(source.get("receipt"))
    return BrokeredCgroupScopeValidation(**source)


def _claim_from_mapping(value: object) -> BrokeredCgroupReleaseClaim:
    if type(value) is not dict:
        raise BrokerProtocolError
    source = dict(value)
    source["receipt"] = _receipt_from_mapping(source.get("receipt"))
    return BrokeredCgroupReleaseClaim(**source)


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _scm_rights_fds(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    descriptors: list[int] = []
    for level, kind, data in ancillary:
        if level != socket.SOL_SOCKET or kind != socket.SCM_RIGHTS:
            continue
        values = array.array("i")
        values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
        descriptors.extend(values)
    return descriptors


class UnixBrokeredCgroupScopeApi:
    """One authenticated version-1 exchange per Unix seqpacket connection."""

    def __init__(
        self,
        socket_path: Path,
        capability: BrokeredCgroupScopeToken,
        *,
        timeout: float = 5.0,
        ltfs_lifecycle_timeout: float = 7_500.0,
    ) -> None:
        self._validate_configuration(
            socket_path, capability, timeout, ltfs_lifecycle_timeout
        )
        self.socket_path = socket_path
        self._capability = capability
        self.timeout = float(timeout)
        self.ltfs_lifecycle_timeout = float(ltfs_lifecycle_timeout)
        self._connected_socket: socket.socket | None = None
        self._connected_socket_only = False
        self._expected_peer_uid = _BROKER_PEER_UID
        self._ltfs_sessions: dict[LtfsSessionHandle, _ClientLtfsSession] = {}
        self._ltfs_pending: dict[tuple[str, int, str], LtfsSessionHandle] = {}
        self._ltfs_tombstones: weakref.WeakSet[LtfsSessionHandle] = weakref.WeakSet()
        self._readiness_reconciliation_nonces: set[bytes] = set()

    @classmethod
    def from_connected_socket(
        cls,
        connected_socket: socket.socket,
        capability: BrokeredCgroupScopeToken,
        *,
        timeout: float = 5.0,
        ltfs_lifecycle_timeout: float = 7_500.0,
        expected_peer_uid: int = _BROKER_PEER_UID,
    ) -> UnixBrokeredCgroupScopeApi:
        synthetic_path = Path("/run/lto-archiver-broker/control.sock")
        cls._validate_configuration(
            synthetic_path, capability, timeout, ltfs_lifecycle_timeout
        )
        if (
            type(connected_socket) is not socket.socket
            or connected_socket.family != socket.AF_UNIX
            or connected_socket.type & 0xF != socket.SOCK_SEQPACKET
            or connected_socket.fileno() < 0
        ):
            raise ValueError("an open Unix SOCK_SEQPACKET socket is required")
        if type(expected_peer_uid) is not int or not 0 <= expected_peer_uid < (1 << 32):
            raise ValueError("command broker peer uid is invalid")
        os.set_inheritable(connected_socket.fileno(), False)
        instance = cls.__new__(cls)
        instance.socket_path = synthetic_path
        instance._capability = capability
        instance.timeout = float(timeout)
        instance.ltfs_lifecycle_timeout = float(ltfs_lifecycle_timeout)
        instance._connected_socket = connected_socket
        instance._connected_socket_only = True
        instance._expected_peer_uid = expected_peer_uid
        instance._ltfs_sessions = {}
        instance._ltfs_pending = {}
        instance._ltfs_tombstones = weakref.WeakSet()
        instance._readiness_reconciliation_nonces = set()
        return instance

    @staticmethod
    def _validate_configuration(
        socket_path: Path,
        capability: BrokeredCgroupScopeToken,
        timeout: float,
        ltfs_lifecycle_timeout: float,
    ) -> None:
        if not isinstance(socket_path, Path) or not socket_path.is_absolute():
            raise ValueError("command broker socket path must be absolute")
        encoded_path = os.fsencode(socket_path)
        if (
            not encoded_path
            or b"\0" in encoded_path
            or len(encoded_path) > _MAX_SOCKET_PATH_BYTES
        ):
            raise ValueError("command broker socket path is invalid")
        if type(capability) is not BrokeredCgroupScopeToken:
            raise ValueError("an exact command broker capability is required")
        if (
            type(timeout) not in (int, float)
            or type(timeout) is bool
            or not math.isfinite(timeout)
            or timeout <= 0.0
            or timeout > _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("command broker timeout is invalid")
        if (
            type(ltfs_lifecycle_timeout) not in (int, float)
            or type(ltfs_lifecycle_timeout) is bool
            or not math.isfinite(ltfs_lifecycle_timeout)
            or ltfs_lifecycle_timeout <= 0.0
            or ltfs_lifecycle_timeout > _MAX_TIMEOUT_SECONDS
        ):
            raise ValueError("command broker LTFS lifecycle timeout is invalid")

    def _check_capability(self, capability: BrokeredCgroupScopeToken) -> None:
        if type(capability) is not BrokeredCgroupScopeToken or not hmac.compare_digest(
            capability.value, self._capability.value
        ):
            self._discard_connected_socket()
            raise BrokerUnavailable

    def _discard_connected_socket(self) -> None:
        connection = self._connected_socket
        self._connected_socket = None
        if connection is not None:
            connection.close()

    def _wire_receipt(self, receipt: BrokeredCgroupScopeReceipt) -> dict[str, object]:
        try:
            return _receipt_mapping(receipt)
        except (BrokerProtocolError, TypeError, ValueError):
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def _wire_permit(self, permit: BrokeredCgroupReleasePermit) -> dict[str, object]:
        try:
            return _permit_mapping(permit)
        except (BrokerProtocolError, TypeError, ValueError):
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def _connect(self, *, timeout: float | None = None) -> socket.socket:
        socket_anchor: int | None = None
        connection: socket.socket | None = None
        try:
            socket_anchor = self._open_socket_anchor()
            flags = socket.SOCK_SEQPACKET | getattr(socket, "SOCK_CLOEXEC", 0)
            connection = socket.socket(socket.AF_UNIX, flags)
            connection.settimeout(self.timeout if timeout is None else timeout)
            connection.connect(f"/proc/self/fd/{socket_anchor}")
            return connection
        except (OSError, ValueError):
            if connection is not None:
                connection.close()
            raise BrokerUnavailable from None
        finally:
            if socket_anchor is not None:
                _close_quietly(socket_anchor)

    def _open_socket_anchor(self) -> int:
        components = self.socket_path.parts
        if (
            len(components) < 3
            or components[0] != os.sep
            or any(component in {"", ".", ".."} for component in components[1:])
        ):
            raise BrokerProtocolError
        directory_flags = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        process_groups = {os.getegid(), *os.getgroups()}
        current_directory: int | None = None
        socket_anchor: int | None = None
        try:
            current_directory = os.open(os.sep, directory_flags)
            for component in components[1:-1]:
                next_directory = os.open(
                    component, directory_flags, dir_fd=current_directory
                )
                _close_quietly(current_directory)
                current_directory = next_directory
            runtime_status = os.fstat(current_directory)
            if (
                not stat.S_ISDIR(runtime_status.st_mode)
                or runtime_status.st_uid != _BROKER_SOCKET_UID
                or runtime_status.st_gid not in process_groups
                or stat.S_IMODE(runtime_status.st_mode) != _BROKER_RUNTIME_MODE
            ):
                raise BrokerProtocolError
            socket_anchor = os.open(
                components[-1],
                os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current_directory,
            )
            socket_status = os.fstat(socket_anchor)
            if (
                not stat.S_ISSOCK(socket_status.st_mode)
                or socket_status.st_uid != _BROKER_SOCKET_UID
                or socket_status.st_gid != runtime_status.st_gid
                or stat.S_IMODE(socket_status.st_mode) != _BROKER_SOCKET_MODE
            ):
                raise BrokerProtocolError
            result = socket_anchor
            socket_anchor = None
            return result
        finally:
            if socket_anchor is not None:
                _close_quietly(socket_anchor)
            if current_directory is not None:
                _close_quietly(current_directory)

    def _take_socket(self, *, timeout: float | None = None) -> socket.socket:
        connection = self._connected_socket
        if connection is not None:
            self._connected_socket = None
            connection.settimeout(self.timeout if timeout is None else timeout)
            return connection
        if self._connected_socket_only:
            raise BrokerUnavailable
        return self._connect(timeout=timeout)

    def assert_ready(self) -> None:
        """Authenticate broker state/cgroup readiness with a fresh nonce."""

        nonce = secrets.token_bytes(32)
        try:
            result = self._exchange("readiness", {"nonce": nonce})
            features = result["features"]
            proof_fields = {
                key: value
                for key, value in features.items()
                if key != "capability_proof"
            }
            reconciliation_nonce = features["reconciliation_nonce"]
            expected_proof = hmac.new(
                self._capability.value,
                readiness_capability_payload(proof_fields),
                hashlib.sha256,
            ).digest()
            if (
                result.get("nonce") != nonce
                or type(features) is not dict
                or frozenset(features)
                != {
                    "broker_state",
                    "delegated_cgroup",
                    "recursive_population",
                    "cgroup_kill",
                    "ltfs_session_contract",
                    "challenge",
                    "reconciliation_nonce",
                    "ltfs_tool_identity_sha256",
                    "fusermount_tool_identity_sha256",
                    "reconciliation_clean",
                    "capability_proof",
                }
                or features["broker_state"] is not True
                or features["delegated_cgroup"] is not True
                or features["recursive_population"] is not True
                or features["cgroup_kill"] is not True
                or features["ltfs_session_contract"] != 1
                or features["challenge"] != nonce
                or features["reconciliation_clean"] is not True
                or reconciliation_nonce in self._readiness_reconciliation_nonces
                or not hmac.compare_digest(features["capability_proof"], expected_proof)
            ):
                raise BrokerProtocolError
            self._readiness_reconciliation_nonces.add(reconciliation_nonce)
        except Exception:  # noqa: BLE001 - redact the local IPC boundary
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def _verify_broker_peer(self, connection: socket.socket) -> None:
        credential_size = struct.calcsize("3i")
        credential = connection.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, credential_size
        )
        if type(credential) is not bytes or len(credential) != credential_size:
            raise BrokerProtocolError
        pid, uid, _gid = struct.unpack("3i", credential)
        if pid <= 0 or uid != self._expected_peer_uid:
            raise BrokerProtocolError

    def _exchange(
        self,
        method: str,
        params: dict[str, object],
        *,
        release_fd: int | None = None,
        ltfs_fds: tuple[int, int] | None = None,
        ltfs_fd_identities: tuple[str, str] | None = None,
        ltfs_authority: LtfsProtocolAuthority | None = None,
        classify_failure: bool = False,
    ) -> dict[str, object]:
        request_id = secrets.token_bytes(32)
        duplicated_fd: int | None = None
        received_fds: list[int] = []
        dispatch_possible = False
        try:
            packet = encode_request(
                method,
                request_id=request_id,
                capability=self._capability.value,
                params=params,
            )
            semantic_request = BrokerRequest(
                method=method,
                request_id=request_id,
                capability=self._capability.value,
                params=params,
            )
            lifecycle_timeout = (
                self.ltfs_lifecycle_timeout
                if method
                in {
                    "start_ltfs_session",
                    "finalize_ltfs_session",
                    "recover_ltfs_finalization",
                    "execute_ltfs_qualification_stage",
                }
                else None
            )
            connection = self._take_socket(timeout=lifecycle_timeout)
            with connection:
                self._verify_broker_peer(connection)
                if ltfs_authority is not None:
                    if release_fd is not None:
                        raise BrokerProtocolError
                    ancillary_identities: tuple[str, ...] = ()
                    if method == "start_ltfs_session":
                        if ltfs_fds is None or ltfs_fd_identities is None:
                            raise BrokerProtocolError
                        ancillary_identities = self._ltfs_fd_identities(ltfs_fds)
                        if ancillary_identities != ltfs_fd_identities:
                            raise BrokerProtocolError
                    elif ltfs_fds is not None or ltfs_fd_identities is not None:
                        raise BrokerProtocolError
                    ltfs_authority.accept_request(
                        semantic_request, ancillary_identities
                    )
                elif ltfs_fds is not None or ltfs_fd_identities is not None:
                    raise BrokerProtocolError
                if ltfs_fds is not None:
                    rights = array.array("i", ltfs_fds)
                    dispatch_possible = True
                    sent = connection.sendmsg(
                        [packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)]
                    )
                elif release_fd is None:
                    dispatch_possible = True
                    sent = connection.send(packet)
                else:
                    if type(release_fd) is not int or release_fd < 0:
                        raise BrokerProtocolError
                    duplicated_fd = os.dup(release_fd)
                    os.set_inheritable(duplicated_fd, False)
                    rights = array.array("i", [duplicated_fd])
                    try:
                        dispatch_possible = True
                        sent = connection.sendmsg(
                            [packet],
                            [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                        )
                    finally:
                        _close_quietly(duplicated_fd)
                        duplicated_fd = None
                if sent != len(packet):
                    raise BrokerProtocolError
                response_packet, ancillary, flags, _address = connection.recvmsg(
                    MAX_PACKET_BYTES + 1,
                    _ANCILLARY_BUFFER_BYTES,
                    getattr(socket, "MSG_CMSG_CLOEXEC", 0),
                )
                received_fds = _scm_rights_fds(ancillary)
                if not response_packet:
                    raise EOFError
                if (
                    len(response_packet) > MAX_PACKET_BYTES
                    or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    or ancillary
                ):
                    raise BrokerProtocolError
            response = decode_response(
                response_packet,
                request=(
                    semantic_request
                    if ltfs_authority is not None
                    or method
                    in {
                        "execute_ltfs_qualification_stage",
                        "inspect_ltfs_qualification_stage",
                    }
                    else None
                ),
                ltfs_authority=ltfs_authority,
            )
            if response.method != method or not hmac.compare_digest(
                response.request_id, request_id
            ):
                raise BrokerProtocolError
            if response.error_code is not None:
                raise _BrokerDefiniteRejection
            if response.result is None:
                raise BrokerProtocolError
            return response.result
        except _BrokerDefiniteRejection:
            self._discard_connected_socket()
            failure = (
                _BrokerDefiniteRejection if classify_failure else BrokerUnavailable
            )
            raise failure(reason="rejected") from None
        except Exception as error:  # noqa: BLE001 - redact every local IPC boundary failure
            self._discard_connected_socket()
            if not dispatch_possible:
                reason = "pre_dispatch"
            elif isinstance(error, TimeoutError):
                reason = "timeout"
            elif isinstance(error, EOFError):
                reason = "eof"
            elif isinstance(error, (BrokerProtocolError, TypeError, ValueError)):
                reason = "protocol"
            elif isinstance(error, OSError):
                reason = "transport"
            else:
                reason = "unavailable"
            failure = BrokerUnavailable
            if classify_failure:
                failure = (
                    _BrokerDispatchAmbiguous if dispatch_possible else _BrokerPreDispatch
                )
            raise failure(reason=reason) from None
        finally:
            if duplicated_fd is not None:
                _close_quietly(duplicated_fd)
            for descriptor in received_fds:
                _close_quietly(descriptor)

    def execute_ltfs_qualification_stage(
        self, request: BrokerQualificationRequest
    ) -> BrokerQualificationDispatch:
        if type(request) is not BrokerQualificationRequest:
            raise ValueError("an exact LTFS qualification request is required")
        try:
            result = self._exchange(
                "execute_ltfs_qualification_stage",
                {"request": request},
                classify_failure=True,
            )
            dispatch = result.get("dispatch")
            if type(dispatch) is not BrokerQualificationDispatch:
                raise BrokerProtocolError
            expected = hmac.new(
                self._capability.value,
                qualification_dispatch_proof_payload(dispatch),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(dispatch.broker_proof, expected):
                raise BrokerProtocolError
            return dispatch
        except Exception:  # noqa: BLE001 - redact the authenticated IPC boundary
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def inspect_ltfs_qualification_stage(
        self,
        request: BrokerQualificationInspectionRequest | str,
        stage_ordinal: int | None = None,
    ) -> BrokerQualificationInspection:
        if type(request) is str:
            try:
                request = BrokerQualificationInspectionRequest(
                    run_id=request,
                    stage_ordinal=stage_ordinal,
                    challenge=secrets.token_bytes(32),
                )
            except (TypeError, ValueError):
                raise ValueError(
                    "a valid LTFS qualification inspection identity is required"
                ) from None
        elif (
            type(request) is not BrokerQualificationInspectionRequest
            or stage_ordinal is not None
        ):
            raise ValueError(
                "an exact LTFS qualification inspection request is required"
            )
        try:
            result = self._exchange(
                "inspect_ltfs_qualification_stage", {"request": request}
            )
            inspection = result.get("inspection")
            if type(inspection) is not BrokerQualificationInspection:
                raise BrokerProtocolError
            expected = hmac.new(
                self._capability.value,
                qualification_inspection_proof_payload(request, inspection),
                hashlib.sha256,
            ).digest()
            if not hmac.compare_digest(inspection.proof, expected):
                raise BrokerProtocolError
            if inspection.dispatch is not None:
                dispatch_proof = hmac.new(
                    self._capability.value,
                    qualification_dispatch_proof_payload(inspection.dispatch),
                    hashlib.sha256,
                ).digest()
                if not hmac.compare_digest(
                    inspection.dispatch.broker_proof, dispatch_proof
                ):
                    raise BrokerProtocolError
            return inspection
        except Exception:  # noqa: BLE001 - redact the authenticated IPC boundary
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    @staticmethod
    def _ltfs_fd_identities(fds: tuple[int, int]) -> tuple[str, str]:
        if (
            type(fds) is not tuple
            or len(fds) != 2
            or any(type(fd) is not int or fd < 0 for fd in fds)
            or fds[0] == fds[1]
        ):
            raise BrokerProtocolError
        try:
            tape_status = os.fstat(fds[0])
            scsi_status = os.fstat(fds[1])
            if (
                tape_status.st_dev,
                tape_status.st_ino,
                tape_status.st_rdev,
            ) == (
                scsi_status.st_dev,
                scsi_status.st_ino,
                scsi_status.st_rdev,
            ):
                raise BrokerProtocolError
            identities = (
                device_fd_identity_sha256(fds[0], "tape"),
                device_fd_identity_sha256(fds[1], "scsi"),
            )
        except (OSError, ValueError, TypeError, LtfsPinningError):
            raise BrokerProtocolError from None
        if identities[0] == identities[1]:
            raise BrokerProtocolError
        return identities

    @staticmethod
    def _ltfs_scope_identity(
        admission: LtfsSessionAdmission,
    ) -> ExecutionScopeIdentity:
        digest = hashlib.sha256(
            b"lto-ltfs-client-scope-v1\0"
            + admission.operation_id.encode("ascii")
            + b"\0"
            + str(admission.owner_generation).encode("ascii")
        ).hexdigest()
        return ExecutionScopeIdentity(f"ltfs-{digest}", admission.owner_generation)

    def start_ltfs_session(
        self,
        admission: LtfsSessionAdmission,
        *,
        tape_fd: int,
        scsi_fd: int,
    ) -> LtfsSessionHandle:
        if type(admission) is not LtfsSessionAdmission:
            raise BrokerUnavailable
        if any(
            session.pending_cleanup
            and self._same_ltfs_target(session.admission, admission)
            for session in self._ltfs_sessions.values()
        ):
            raise BrokerUnavailable
        fds = (tape_fd, scsi_fd)
        scope = None
        response_accepted = False
        try:
            fd_identities = self._ltfs_fd_identities(fds)
            manager = BrokeredCgroupExecutionScopeManager(self, self._capability)
            scope_identity = self._ltfs_scope_identity(admission)
            try:
                scope = manager.create(scope_identity)
            except CommandError:
                scope = manager.open(scope_identity)
            request = LtfsSessionRequest(
                protocol_version=1,
                operation_id=admission.operation_id,
                owner_generation=admission.owner_generation,
                mount_path_sha256=admission.mount_path_sha256,
                tape_device_identity_sha256=admission.tape_device_identity_sha256,
                scsi_device_identity_sha256=admission.scsi_device_identity_sha256,
                expected_media_scope_sha256=admission.expected_media_scope_sha256,
                observed_media_identity_sha256=(
                    admission.observed_media_identity_sha256
                ),
                expected_volume_uuid=admission.expected_volume_uuid,
                expected_prior_generation=admission.expected_prior_generation,
                read_only=admission.read_only,
                tape_fd_identity_sha256=fd_identities[0],
                scsi_fd_identity_sha256=fd_identities[1],
                cgroup_scope_receipt=scope.receipt,
                request_nonce=secrets.token_bytes(32),
            )
            authority = LtfsProtocolAuthority(
                operation_id=request.operation_id,
                owner_generation=request.owner_generation,
                cgroup_scope_receipt=request.cgroup_scope_receipt,
                tape_fd_identity_sha256=request.tape_fd_identity_sha256,
                scsi_fd_identity_sha256=request.scsi_fd_identity_sha256,
            )
            result = self._exchange(
                "start_ltfs_session",
                {"request": request},
                ltfs_fds=fds,
                ltfs_fd_identities=fd_identities,
                ltfs_authority=authority,
                classify_failure=True,
            )
            response_accepted = True
            receipt = result["receipt"]
            if type(receipt) is not LtfsSessionReceipt:
                raise BrokerProtocolError
            handle = _issue_ltfs_session_handle(receipt)
            self._ltfs_sessions[handle] = _ClientLtfsSession(
                receipt, authority, admission
            )
            return handle
        except _BrokerDispatchAmbiguous:
            self._discard_connected_socket()
            raise BrokerUnavailable from None
        except Exception:  # noqa: BLE001 - redact every local IPC boundary failure
            if scope is not None and not response_accepted:
                with contextlib.suppress(Exception):
                    scope.close()
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def _checked_ltfs_handle(self, handle: LtfsSessionHandle) -> _ClientLtfsSession:
        if type(handle) is not LtfsSessionHandle:
            raise BrokerUnavailable
        session = self._ltfs_sessions.get(handle)
        if session is None or handle in self._ltfs_tombstones:
            raise BrokerUnavailable
        return session

    def _tombstone_ltfs_handle(self, handle: LtfsSessionHandle) -> None:
        session = self._ltfs_sessions.pop(handle, None)
        if session is not None:
            key = self._ltfs_session_key(session.receipt)
            if self._ltfs_pending.get(key) is handle:
                del self._ltfs_pending[key]
        self._ltfs_tombstones.add(handle)

    @staticmethod
    def _ltfs_session_key(receipt: LtfsSessionReceipt) -> tuple[str, int, str]:
        return receipt.operation_id, receipt.owner_generation, receipt.session_id

    def _mark_ltfs_pending(
        self, handle: LtfsSessionHandle, session: _ClientLtfsSession
    ) -> None:
        key = self._ltfs_session_key(session.receipt)
        previous = self._ltfs_pending.get(key)
        if previous is not None and previous is not handle:
            self._tombstone_ltfs_handle(handle)
            raise BrokerUnavailable
        session.pending_cleanup = True
        self._ltfs_pending[key] = handle

    @staticmethod
    def _same_ltfs_target(
        first: LtfsSessionAdmission, second: LtfsSessionAdmission
    ) -> bool:
        return (
            first.mount_path_sha256 == second.mount_path_sha256
            and first.tape_device_identity_sha256 == second.tape_device_identity_sha256
            and first.scsi_device_identity_sha256 == second.scsi_device_identity_sha256
        )

    def observe_ltfs_session(self, handle: LtfsSessionHandle) -> LtfsSessionReceipt:
        session = self._checked_ltfs_handle(handle)
        challenge = secrets.token_bytes(32)
        try:
            result = self._exchange(
                "observe_ltfs_session",
                {
                    "operation_id": session.receipt.operation_id,
                    "owner_generation": session.receipt.owner_generation,
                    "receipt": session.receipt,
                    "challenge": challenge,
                },
                ltfs_authority=session.authority,
                classify_failure=True,
            )
            if (
                result.get("receipt") != session.receipt
                or result.get("challenge") != challenge
                or result.get("mounted") is not True
            ):
                raise BrokerProtocolError
            return session.receipt
        except _BrokerPreDispatch:
            self._discard_connected_socket()
            raise BrokerUnavailable from None
        except Exception:  # noqa: BLE001 - poison every ambiguous lifecycle result
            self._tombstone_ltfs_handle(handle)
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def recover_pending_ltfs_session(
        self, admission: LtfsSessionRecoveryAdmission
    ) -> LtfsFinalizationReceipt | None:
        if type(admission) is not LtfsSessionRecoveryAdmission:
            raise BrokerUnavailable
        local_candidates = [
            (handle, session)
            for handle in self._ltfs_pending.values()
            if (session := self._ltfs_sessions.get(handle)) is not None
            and session.admission.operation_id == admission.fence.operation_id
            and session.admission.owner_generation
            == admission.original_owner_generation
        ]
        matches = [
            (handle, session)
            for handle, session in local_candidates
            if session.admission.mount_path_sha256 == admission.mount_path_sha256
            and session.admission.tape_device_identity_sha256
            == admission.tape_device_identity_sha256
            and session.admission.scsi_device_identity_sha256
            == admission.scsi_device_identity_sha256
            and session.admission.expected_media_scope_sha256
            == admission.expected_media_scope_sha256
            and session.admission.observed_media_identity_sha256
            == admission.observed_media_identity_sha256
        ]
        if local_candidates and not matches:
            return None
        if not matches:
            request_nonce = secrets.token_bytes(32)
            try:
                result = self._exchange(
                    "recover_ltfs_finalization",
                    {
                        "operation_id": admission.fence.operation_id,
                        "owner_generation": admission.original_owner_generation,
                        "mount_path_sha256": admission.mount_path_sha256,
                        "tape_device_identity_sha256": (
                            admission.tape_device_identity_sha256
                        ),
                        "scsi_device_identity_sha256": (
                            admission.scsi_device_identity_sha256
                        ),
                        "expected_media_scope_sha256": (
                            admission.expected_media_scope_sha256
                        ),
                        "observed_media_identity_sha256": (
                            admission.observed_media_identity_sha256
                        ),
                        "request_nonce": request_nonce,
                    },
                    classify_failure=True,
                )
                receipt = result.get("receipt")
                if (
                    type(receipt) is not LtfsFinalizationReceipt
                    or receipt.session_receipt.operation_id
                    != admission.fence.operation_id
                    or receipt.session_receipt.owner_generation
                    != admission.original_owner_generation
                    or receipt.session_receipt.observed_media_identity_sha256
                    != admission.observed_media_identity_sha256
                ):
                    raise BrokerProtocolError
                return receipt
            except Exception:  # noqa: BLE001 - redact durable lookup boundary
                self._discard_connected_socket()
                raise BrokerUnavailable from None
        if len(matches) != 1:
            raise BrokerUnavailable
        handle, _session = matches[0]
        return self.finalize_ltfs_session(handle)

    def finalize_ltfs_session(
        self, handle: LtfsSessionHandle
    ) -> LtfsFinalizationReceipt:
        session = self._checked_ltfs_handle(handle)
        request_nonce = secrets.token_bytes(32)
        try:
            result = self._exchange(
                "finalize_ltfs_session",
                {
                    "operation_id": session.receipt.operation_id,
                    "owner_generation": session.receipt.owner_generation,
                    "receipt": session.receipt,
                    "request_nonce": request_nonce,
                },
                ltfs_authority=session.authority,
                classify_failure=True,
            )
            receipt = result.get("receipt")
            if (
                type(receipt) is not LtfsFinalizationReceipt
                or receipt.session_receipt != session.receipt
                or receipt.request_nonce != request_nonce
                or receipt.unmounted is not True
                or receipt.child_quiesced is not True
            ):
                raise BrokerProtocolError
            self._tombstone_ltfs_handle(handle)
            return receipt
        except _BrokerPreDispatch:
            self._mark_ltfs_pending(handle, session)
            self._discard_connected_socket()
            raise BrokerUnavailable from None
        except Exception:  # noqa: BLE001 - poison every ambiguous lifecycle result
            self._tombstone_ltfs_handle(handle)
            self._discard_connected_socket()
            raise BrokerUnavailable from None

    def create_scope(
        self,
        identity: ExecutionScopeIdentity,
        request_nonce: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupScopeReceipt:
        self._check_capability(capability)
        if type(identity) is not ExecutionScopeIdentity:
            self._discard_connected_socket()
            raise BrokerUnavailable
        result = self._exchange(
            "create_scope",
            {
                "command_id": identity.command_id,
                "owner_generation": identity.owner_generation,
                "request_nonce": request_nonce,
            },
        )
        try:
            return _receipt_from_mapping(result["receipt"])
        except (KeyError, TypeError, ValueError):
            raise BrokerUnavailable from None

    def open_scope(
        self,
        identity: ExecutionScopeIdentity,
        request_nonce: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupScopeReceipt:
        self._check_capability(capability)
        if type(identity) is not ExecutionScopeIdentity:
            self._discard_connected_socket()
            raise BrokerUnavailable
        result = self._exchange(
            "open_scope",
            {
                "command_id": identity.command_id,
                "owner_generation": identity.owner_generation,
                "request_nonce": request_nonce,
            },
        )
        try:
            return _receipt_from_mapping(result["receipt"])
        except (KeyError, TypeError, ValueError):
            raise BrokerUnavailable from None

    def attach(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        self._check_capability(capability)
        self._exchange("attach", {"receipt": self._wire_receipt(receipt), "pid": pid})

    def validate_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        challenge: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupScopeValidation:
        self._check_capability(capability)
        result = self._exchange(
            "validate_scope",
            {"receipt": self._wire_receipt(receipt), "challenge": challenge},
        )
        try:
            return _validation_from_mapping(result["validation"])
        except (KeyError, TypeError, ValueError):
            raise BrokerUnavailable from None

    def prepare_release(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        request_nonce: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupReleasePermit:
        self._check_capability(capability)
        result = self._exchange(
            "prepare_release",
            {
                "receipt": self._wire_receipt(receipt),
                "pid": pid,
                "request_nonce": request_nonce,
            },
        )
        try:
            return _permit_from_mapping(result["permit"])
        except (KeyError, TypeError, ValueError):
            raise BrokerUnavailable from None

    def release_child(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        permit: BrokeredCgroupReleasePermit,
        pid: int,
        release_fd: int,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        self._check_capability(capability)
        self._exchange(
            "release_child",
            {
                "receipt": self._wire_receipt(receipt),
                "permit": self._wire_permit(permit),
                "pid": pid,
            },
            release_fd=release_fd,
        )

    def claim_unreleased(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        permit_sha256: str,
        challenge: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupReleaseClaim:
        self._check_capability(capability)
        result = self._exchange(
            "claim_unreleased",
            {
                "receipt": self._wire_receipt(receipt),
                "pid": pid,
                "permit_sha256": permit_sha256,
                "challenge": challenge,
            },
        )
        try:
            return _claim_from_mapping(result["claim"])
        except (KeyError, TypeError, ValueError):
            raise BrokerUnavailable from None

    def signal_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        signum: int,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        self._check_capability(capability)
        if type(signum) not in (int, signal.Signals) or signum != signal.SIGTERM:
            self._discard_connected_socket()
            raise BrokerUnavailable
        self._exchange(
            "signal_scope",
            {"receipt": self._wire_receipt(receipt), "signum": int(signum)},
        )

    def kill_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        self._check_capability(capability)
        self._exchange("kill_scope", {"receipt": self._wire_receipt(receipt)})

    def release_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        self._check_capability(capability)
        self._exchange("release_scope", {"receipt": self._wire_receipt(receipt)})
