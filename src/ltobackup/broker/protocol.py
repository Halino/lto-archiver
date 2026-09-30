from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TypeAlias

from ltobackup.broker.ltfs_session import derive_receipt_operation_uuid
from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationInspection,
    BrokerQualificationInspectionRequest,
    BrokerQualificationRequest,
    qualification_inspection_snapshot_payload,
)
from ltobackup.qualification.plan import QualificationOperation
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupScopeReceipt,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)

PROTOCOL_VERSION = 1
MAX_PACKET_BYTES = 65_536

_METHODS = frozenset(
    {
        "create_scope",
        "open_scope",
        "attach",
        "validate_scope",
        "prepare_release",
        "release_child",
        "claim_unreleased",
        "signal_scope",
        "kill_scope",
        "release_scope",
        "readiness",
        "start_ltfs_session",
        "observe_ltfs_session",
        "finalize_ltfs_session",
        "recover_ltfs_finalization",
        "execute_ltfs_qualification_stage",
        "inspect_ltfs_qualification_stage",
    }
)
_LTFS_METHODS = frozenset(
    {"start_ltfs_session", "observe_ltfs_session", "finalize_ltfs_session"}
)
_ERROR_CODES = frozenset(
    {
        "protocol.invalid",
        "auth.denied",
        "scope.conflict",
        "state.unavailable",
        "state.ambiguous",
    }
)
_REQUEST_KEYS = frozenset({"version", "method", "request_id", "capability", "params"})
_RESPONSE_OK_KEYS = frozenset({"version", "method", "request_id", "status", "result"})
_RESPONSE_ERROR_KEYS = frozenset({"version", "method", "request_id", "status", "error"})
_READINESS_PROOF_KEYS = frozenset(
    {
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
    }
)
_READINESS_FEATURE_KEYS = _READINESS_PROOF_KEYS | {"capability_proof"}

JsonObject: TypeAlias = dict[str, object]


class BrokerProtocolError(ValueError):
    """A redacted error for a malformed or out-of-contract packet."""

    def __init__(self) -> None:
        super().__init__("invalid command broker protocol")


@dataclass(frozen=True)
class BrokerRequest:
    method: str
    request_id: bytes
    capability: bytes
    params: JsonObject


@dataclass(frozen=True)
class BrokerResponse:
    method: str
    request_id: bytes
    result: JsonObject | None
    error_code: str | None


@dataclass
class LtfsProtocolAuthority:
    """One fail-closed semantic authority for a brokered LTFS session.

    The transport supplies the two received descriptor identities in SCM_RIGHTS
    order.  This object consumes every request nonce/challenge once and binds
    every response to the request that caused it.  Durable replay state replaces
    these in-memory sets in the broker store in Task 2.
    """

    operation_id: str
    owner_generation: int
    cgroup_scope_receipt: BrokeredCgroupScopeReceipt
    tape_fd_identity_sha256: str
    scsi_fd_identity_sha256: str
    _seen_opaque: set[bytes] = field(default_factory=set, init=False, repr=False)
    _session_receipt: LtfsSessionReceipt | None = field(
        default=None, init=False, repr=False
    )
    _pending_requests: dict[tuple[str, bytes], BrokerRequest] = field(
        default_factory=dict, init=False, repr=False
    )
    _seen_request_keys: set[tuple[str, bytes]] = field(
        default_factory=set, init=False, repr=False
    )
    _state: str = field(default="new", init=False, repr=False)

    def __post_init__(self) -> None:
        _identity(self.operation_id)
        _exact_int(self.owner_generation)
        if type(self.cgroup_scope_receipt) is not BrokeredCgroupScopeReceipt:
            raise BrokerProtocolError
        _scope_receipt_model(self.cgroup_scope_receipt, encode=True)
        _hex_digest(self.tape_fd_identity_sha256)
        _hex_digest(self.scsi_fd_identity_sha256)
        if self.tape_fd_identity_sha256 == self.scsi_fd_identity_sha256:
            raise BrokerProtocolError
        scope_opaque = {
            self.cgroup_scope_receipt.request_nonce,
            self.cgroup_scope_receipt.broker_nonce,
            self.cgroup_scope_receipt.broker_proof,
        }
        if len(scope_opaque) != 3:
            raise BrokerProtocolError
        self._seen_opaque.update(scope_opaque)

    def _consume(self, value: bytes) -> None:
        if type(value) is not bytes or len(value) != 32 or value in self._seen_opaque:
            raise BrokerProtocolError
        self._seen_opaque.add(value)

    def accept_request(
        self,
        request: BrokerRequest,
        ancillary_fd_identities: tuple[str, ...],
    ) -> None:
        key = (request.method, request.request_id)
        if key in self._seen_request_keys:
            raise BrokerProtocolError
        if request.method == "start_ltfs_session":
            if self._state != "new":
                raise BrokerProtocolError
            if ancillary_fd_identities != (
                self.tape_fd_identity_sha256,
                self.scsi_fd_identity_sha256,
            ):
                raise BrokerProtocolError
            model = request.params.get("request")
            if (
                type(model) is not LtfsSessionRequest
                or model.operation_id != self.operation_id
                or model.owner_generation != self.owner_generation
                or model.cgroup_scope_receipt != self.cgroup_scope_receipt
                or model.tape_fd_identity_sha256 != self.tape_fd_identity_sha256
                or model.scsi_fd_identity_sha256 != self.scsi_fd_identity_sha256
            ):
                raise BrokerProtocolError
            self._consume(model.request_nonce)
        else:
            if ancillary_fd_identities:
                raise BrokerProtocolError
            if (
                request.method
                not in {
                    "observe_ltfs_session",
                    "finalize_ltfs_session",
                }
                or self._state != "started"
            ):
                raise BrokerProtocolError
            receipt = request.params.get("receipt")
            if (
                self._session_receipt is None
                or receipt != self._session_receipt
                or request.params.get("operation_id") != self.operation_id
                or request.params.get("owner_generation") != self.owner_generation
            ):
                raise BrokerProtocolError
            nonce_key = (
                "challenge"
                if request.method == "observe_ltfs_session"
                else "request_nonce"
            )
            nonce = request.params.get(nonce_key)
            if type(nonce) is not bytes:
                raise BrokerProtocolError
            self._consume(nonce)
        if key in self._pending_requests:
            raise BrokerProtocolError
        self._seen_request_keys.add(key)
        self._pending_requests[key] = request
        self._state = {
            "start_ltfs_session": "start_pending",
            "observe_ltfs_session": "observe_pending",
            "finalize_ltfs_session": "finalize_pending",
        }[request.method]

    def accept_response(self, request: BrokerRequest, response: BrokerResponse) -> None:
        key = (request.method, request.request_id)
        if (
            self._pending_requests.get(key) != request
            or response.method != request.method
            or response.request_id != request.request_id
        ):
            raise BrokerProtocolError
        if response.error_code is not None:
            if response.result is not None:
                raise BrokerProtocolError
            del self._pending_requests[key]
            self._state = "new" if request.method == "start_ltfs_session" else "started"
            return
        if response.result is None:
            raise BrokerProtocolError
        if request.method == "start_ltfs_session":
            session_request = request.params.get("request")
            receipt = response.result.get("receipt")
            if (
                type(session_request) is not LtfsSessionRequest
                or type(receipt) is not LtfsSessionReceipt
                or receipt.operation_id != session_request.operation_id
                or receipt.owner_generation != session_request.owner_generation
                or receipt.request_nonce != session_request.request_nonce
                or receipt.request_sha256 != ltfs_request_sha256(session_request)
                or receipt.receipt_operation_uuid
                != derive_receipt_operation_uuid(
                    operation_id=session_request.operation_id,
                    owner_generation=session_request.owner_generation,
                    request_sha256=receipt.request_sha256,
                )
                or (
                    session_request.expected_volume_uuid is not None
                    and receipt.observed_volume_uuid
                    != session_request.expected_volume_uuid
                )
                or receipt.broker_nonce == receipt.request_nonce
                or receipt.broker_proof in {receipt.request_nonce, receipt.broker_nonce}
            ):
                raise BrokerProtocolError
            self._consume(receipt.broker_nonce)
            self._consume(receipt.broker_proof)
            self._session_receipt = receipt
            del self._pending_requests[key]
            self._state = "started"
            return
        if request.method == "observe_ltfs_session":
            receipt = response.result.get("receipt")
            challenge = response.result.get("challenge")
            observation_nonce = response.result.get("observation_nonce")
            proof = response.result.get("broker_proof")
            if (
                receipt != request.params.get("receipt")
                or challenge != request.params.get("challenge")
                or type(challenge) is not bytes
                or type(observation_nonce) is not bytes
                or type(proof) is not bytes
                or len({challenge, observation_nonce, proof}) != 3
            ):
                raise BrokerProtocolError
            self._consume(observation_nonce)
            self._consume(proof)
            del self._pending_requests[key]
            self._state = "started"
            return
        if request.method == "finalize_ltfs_session":
            receipt = response.result.get("receipt")
            if (
                type(receipt) is not LtfsFinalizationReceipt
                or receipt.session_receipt != request.params.get("receipt")
                or receipt.request_nonce != request.params.get("request_nonce")
                or len(
                    {
                        receipt.request_nonce,
                        receipt.finalization_nonce,
                        receipt.broker_proof,
                    }
                )
                != 3
            ):
                raise BrokerProtocolError
            self._consume(receipt.finalization_nonce)
            self._consume(receipt.broker_proof)
            del self._pending_requests[key]
            self._state = "finalized"
            return
        raise BrokerProtocolError


class _DuplicateKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise ValueError


def _parse_packet(payload: bytes) -> JsonObject:
    if type(payload) is not bytes or not payload or len(payload) > MAX_PACKET_BYTES:
        raise BrokerProtocolError
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, ValueError):
        raise BrokerProtocolError from None
    if type(value) is not dict:
        raise BrokerProtocolError
    if _canonical_packet(value) != payload:
        raise BrokerProtocolError
    return value


def _canonical_packet(value: JsonObject) -> bytes:
    try:
        payload = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise BrokerProtocolError from None
    if len(payload) > MAX_PACKET_BYTES:
        raise BrokerProtocolError
    return payload


def _readiness_proof_fields(value: object) -> JsonObject:
    source = _exact_object(value, _READINESS_PROOF_KEYS)
    for key in (
        "broker_state",
        "delegated_cgroup",
        "recursive_population",
        "cgroup_kill",
        "reconciliation_clean",
    ):
        if _exact_bool(source[key]) is not True:
            raise BrokerProtocolError
    if _exact_int(source["ltfs_session_contract"], minimum=1, maximum=1) != 1:
        raise BrokerProtocolError
    challenge = source["challenge"]
    reconciliation_nonce = source["reconciliation_nonce"]
    if (
        type(challenge) is not bytes
        or len(challenge) != 32
        or type(reconciliation_nonce) is not bytes
        or len(reconciliation_nonce) != 32
        or challenge == reconciliation_nonce
    ):
        raise BrokerProtocolError
    ltfs_identity = _hex_digest(source["ltfs_tool_identity_sha256"])
    fusermount_identity = _hex_digest(source["fusermount_tool_identity_sha256"])
    if ltfs_identity == fusermount_identity:
        raise BrokerProtocolError
    return {
        "broker_state": True,
        "delegated_cgroup": True,
        "recursive_population": True,
        "cgroup_kill": True,
        "ltfs_session_contract": 1,
        "challenge": challenge,
        "reconciliation_nonce": reconciliation_nonce,
        "ltfs_tool_identity_sha256": ltfs_identity,
        "fusermount_tool_identity_sha256": fusermount_identity,
        "reconciliation_clean": True,
    }


def readiness_capability_payload(value: object) -> bytes:
    """Return the one canonical capability-HMAC payload for readiness."""

    fields = _readiness_proof_fields(value)
    canonical_fields = {
        key: (
            {"base64": base64.b64encode(item).decode("ascii")}
            if type(item) is bytes
            else item
        )
        for key, item in fields.items()
    }
    return json.dumps(
        {
            "domain": "readiness-capability-proof-v1",
            "fields": canonical_fields,
            "version": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _transform_readiness_features(value: object, *, encode: bool) -> JsonObject:
    source = _exact_object(value, _READINESS_FEATURE_KEYS)
    opaque = _encode_opaque if encode else _decode_opaque
    proof_fields = {
        **source,
        "challenge": opaque(source["challenge"], exact_length=32),
        "reconciliation_nonce": opaque(source["reconciliation_nonce"], exact_length=32),
    }
    capability_proof = opaque(source["capability_proof"], exact_length=32)
    del proof_fields["capability_proof"]
    if encode:
        model = {
            **proof_fields,
            "challenge": _decode_opaque(proof_fields["challenge"], exact_length=32),
            "reconciliation_nonce": _decode_opaque(
                proof_fields["reconciliation_nonce"], exact_length=32
            ),
        }
    else:
        model = proof_fields
    checked = _readiness_proof_fields(model)
    raw_proof = (
        _decode_opaque(capability_proof, exact_length=32)
        if encode
        else capability_proof
    )
    if raw_proof in {checked["challenge"], checked["reconciliation_nonce"]}:
        raise BrokerProtocolError
    return {**proof_fields, "capability_proof": capability_proof}


def _exact_object(value: object, keys: frozenset[str]) -> JsonObject:
    if type(value) is not dict or frozenset(value) != keys:
        raise BrokerProtocolError
    return value


def _exact_int(value: object, *, minimum: int = 0, maximum: int = (1 << 63) - 1) -> int:
    if type(value) is not int or value < minimum or value > maximum:
        raise BrokerProtocolError
    return value


def _exact_bool(value: object) -> bool:
    if type(value) is not bool:
        raise BrokerProtocolError
    return value


def _identity(value: object) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 1024
        or not value.isascii()
        or not value.isprintable()
        or "/" in value
        or "\\" in value
    ):
        raise BrokerProtocolError
    return value


def _media_identity_text(value: object, *, maximum: int = 255) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip(" ")
        or not value.isascii()
        or not value.isprintable()
    ):
        raise BrokerProtocolError
    return value


def _method(value: object) -> str:
    if type(value) is not str or value not in _METHODS:
        raise BrokerProtocolError
    return value


def _hex_digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BrokerProtocolError
    return value


def _encode_opaque(value: object, *, exact_length: int | None = None) -> str:
    if type(value) is not bytes:
        raise BrokerProtocolError
    if exact_length is not None:
        if len(value) != exact_length:
            raise BrokerProtocolError
    elif not 32 <= len(value) <= 4096:
        raise BrokerProtocolError
    return base64.b64encode(value).decode("ascii")


def _decode_opaque(value: object, *, exact_length: int | None = None) -> bytes:
    if type(value) is not str or not value or not value.isascii():
        raise BrokerProtocolError
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise BrokerProtocolError from None
    if base64.b64encode(decoded).decode("ascii") != value:
        raise BrokerProtocolError
    if exact_length is not None:
        if len(decoded) != exact_length:
            raise BrokerProtocolError
    elif not 32 <= len(decoded) <= 4096:
        raise BrokerProtocolError
    return decoded


_RECEIPT_KEYS = frozenset(
    {
        "protocol_version",
        "command_id",
        "owner_generation",
        "request_nonce",
        "scope_id",
        "scope_path_sha256",
        "broker_nonce",
        "broker_proof",
        "recursive_population",
        "recursive_members",
        "cgroup_kill",
    }
)
_PERMIT_KEYS = frozenset(
    {
        "protocol_version",
        "receipt",
        "pid",
        "request_nonce",
        "permit_nonce",
        "broker_proof",
    }
)
_VALIDATION_KEYS = frozenset(
    {
        "protocol_version",
        "receipt",
        "challenge",
        "validation_nonce",
        "broker_proof",
        "populated",
        "member_pids",
    }
)
_CLAIM_KEYS = frozenset(
    {
        "protocol_version",
        "receipt",
        "pid",
        "permit_sha256",
        "challenge",
        "claim_nonce",
        "broker_proof",
        "released",
        "permit_revoked",
    }
)


def _encode_receipt(value: object) -> JsonObject:
    source = _exact_object(value, _RECEIPT_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    return {
        "protocol_version": PROTOCOL_VERSION,
        "command_id": _identity(source["command_id"]),
        "owner_generation": _exact_int(source["owner_generation"]),
        "request_nonce": _encode_opaque(source["request_nonce"]),
        "scope_id": _identity(source["scope_id"]),
        "scope_path_sha256": _hex_digest(source["scope_path_sha256"]),
        "broker_nonce": _encode_opaque(source["broker_nonce"]),
        "broker_proof": _encode_opaque(source["broker_proof"]),
        "recursive_population": _exact_bool(source["recursive_population"]),
        "recursive_members": _exact_bool(source["recursive_members"]),
        "cgroup_kill": _exact_bool(source["cgroup_kill"]),
    }


def _decode_receipt(value: object) -> JsonObject:
    source = _exact_object(value, _RECEIPT_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    return {
        "protocol_version": PROTOCOL_VERSION,
        "command_id": _identity(source["command_id"]),
        "owner_generation": _exact_int(source["owner_generation"]),
        "request_nonce": _decode_opaque(source["request_nonce"]),
        "scope_id": _identity(source["scope_id"]),
        "scope_path_sha256": _hex_digest(source["scope_path_sha256"]),
        "broker_nonce": _decode_opaque(source["broker_nonce"]),
        "broker_proof": _decode_opaque(source["broker_proof"]),
        "recursive_population": _exact_bool(source["recursive_population"]),
        "recursive_members": _exact_bool(source["recursive_members"]),
        "cgroup_kill": _exact_bool(source["cgroup_kill"]),
    }


_LTFS_REQUEST_KEYS = frozenset(
    {
        "protocol_version",
        "operation_id",
        "owner_generation",
        "mount_path_sha256",
        "tape_device_identity_sha256",
        "scsi_device_identity_sha256",
        "expected_media_scope_sha256",
        "observed_media_identity_sha256",
        "expected_volume_uuid",
        "expected_prior_generation",
        "read_only",
        "tape_fd_identity_sha256",
        "scsi_fd_identity_sha256",
        "cgroup_scope_receipt",
        "request_nonce",
    }
)
_LTFS_RECEIPT_KEYS = frozenset(
    {
        "protocol_version",
        "operation_id",
        "receipt_operation_uuid",
        "observed_volume_uuid",
        "observed_prior_generation",
        "observed_volume_label",
        "observed_media_identity_sha256",
        "read_only",
        "owner_generation",
        "request_nonce",
        "session_id",
        "request_sha256",
        "child_pid",
        "child_start_ticks",
        "mount_namespace_sha256",
        "broker_nonce",
        "broker_proof",
        "mounted",
    }
)
_LTFS_FINALIZATION_KEYS = frozenset(
    {
        "protocol_version",
        "session_receipt",
        "standalone_receipt",
        "request_nonce",
        "finalization_nonce",
        "broker_proof",
        "unmounted",
        "child_quiesced",
    }
)
_LTFS_STANDALONE_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "stage",
        "operation_id",
        "volume_uuid",
        "prior_generation",
        "new_generation",
        "bytes_valid",
        "bytes",
        "files_valid",
        "files",
        "phase_duration_ns",
        "capture_duration_ns",
        "device_close_duration_ns",
        "device_close_result_valid",
        "device_close_result",
        "catalog_ack_duration_ns",
        "media_committed",
        "catalog_acknowledged",
        "cleanup_failed",
        "result",
        "terminal_sha256",
    }
)


def _canonical_uuid(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 36
        or any(value[index] != "-" for index in (8, 13, 18, 23))
        or any(
            character not in "0123456789abcdef"
            for index, character in enumerate(value)
            if index not in (8, 13, 18, 23)
        )
    ):
        raise BrokerProtocolError
    return value


def _standalone_receipt_values(value: LtfsStandaloneReceipt) -> JsonObject:
    return {
        "schema": value.schema,
        "stage": value.stage,
        "operation_id": value.operation_id,
        "volume_uuid": value.volume_uuid,
        "prior_generation": value.prior_generation,
        "new_generation": value.new_generation,
        "bytes_valid": value.bytes_valid,
        "bytes": value.bytes,
        "files_valid": value.files_valid,
        "files": value.files,
        "phase_duration_ns": list(value.phase_duration_ns),
        "capture_duration_ns": value.capture_duration_ns,
        "device_close_duration_ns": value.device_close_duration_ns,
        "device_close_result_valid": value.device_close_result_valid,
        "device_close_result": value.device_close_result,
        "catalog_ack_duration_ns": value.catalog_ack_duration_ns,
        "media_committed": value.media_committed,
        "catalog_acknowledged": value.catalog_acknowledged,
        "cleanup_failed": value.cleanup_failed,
        "result": value.result,
        "terminal_sha256": value.terminal_sha256,
    }


def _transform_ltfs_standalone_receipt(
    value: object, *, encode: bool
) -> LtfsStandaloneReceipt:
    if encode:
        if type(value) is not LtfsStandaloneReceipt:
            raise BrokerProtocolError
        source = _exact_object(
            _standalone_receipt_values(value), _LTFS_STANDALONE_RECEIPT_KEYS
        )
    else:
        source = _exact_object(value, _LTFS_STANDALONE_RECEIPT_KEYS)
    phases = source["phase_duration_ns"]
    if type(phases) is not list or len(phases) != 11:
        raise BrokerProtocolError
    receipt = LtfsStandaloneReceipt(
        schema=_exact_int(source["schema"], minimum=1, maximum=1),
        stage=source["stage"],
        operation_id=_canonical_uuid(source["operation_id"]),
        volume_uuid=_canonical_uuid(source["volume_uuid"]),
        prior_generation=_exact_int(source["prior_generation"], maximum=(1 << 64) - 1),
        new_generation=_exact_int(
            source["new_generation"], minimum=1, maximum=(1 << 64) - 1
        ),
        bytes_valid=_exact_bool(source["bytes_valid"]),
        bytes=_exact_int(source["bytes"], maximum=(1 << 64) - 1),
        files_valid=_exact_bool(source["files_valid"]),
        files=_exact_int(source["files"], maximum=(1 << 64) - 1),
        phase_duration_ns=tuple(
            _exact_int(item, maximum=(1 << 64) - 1) for item in phases
        ),
        capture_duration_ns=_exact_int(
            source["capture_duration_ns"], maximum=(1 << 64) - 1
        ),
        device_close_duration_ns=_exact_int(
            source["device_close_duration_ns"], maximum=(1 << 64) - 1
        ),
        device_close_result_valid=_exact_bool(source["device_close_result_valid"]),
        device_close_result=_exact_int(
            source["device_close_result"], minimum=-(1 << 31), maximum=(1 << 31) - 1
        ),
        catalog_ack_duration_ns=_exact_int(
            source["catalog_ack_duration_ns"], maximum=(1 << 64) - 1
        ),
        media_committed=_exact_bool(source["media_committed"]),
        catalog_acknowledged=_exact_bool(source["catalog_acknowledged"]),
        cleanup_failed=_exact_bool(source["cleanup_failed"]),
        result=_exact_int(source["result"], minimum=-(1 << 31), maximum=(1 << 31) - 1),
        terminal_sha256=_hex_digest(source["terminal_sha256"]),
    )
    c_fields = _standalone_receipt_values(receipt)
    del c_fields["terminal_sha256"]
    terminal_sha256 = hashlib.sha256(
        (json.dumps(c_fields, separators=(",", ":")) + "\n").encode("ascii")
    ).hexdigest()
    if (
        receipt.stage != "terminal"
        or receipt.new_generation < receipt.prior_generation
        or (not receipt.bytes_valid and receipt.bytes != 0)
        or (not receipt.files_valid and receipt.files != 0)
        or not receipt.device_close_result_valid
        or receipt.device_close_result != 0
        or not receipt.media_committed
        or not receipt.catalog_acknowledged
        or receipt.cleanup_failed
        or receipt.result != 0
        or not hmac.compare_digest(receipt.terminal_sha256, terminal_sha256)
    ):
        raise BrokerProtocolError
    return receipt


def _encode_ltfs_standalone_receipt(value: object) -> JsonObject:
    return _standalone_receipt_values(
        _transform_ltfs_standalone_receipt(value, encode=True)
    )


def _scope_receipt_values(value: BrokeredCgroupScopeReceipt) -> JsonObject:
    return {
        "protocol_version": value.protocol_version,
        "command_id": value.command_id,
        "owner_generation": value.owner_generation,
        "request_nonce": value.request_nonce,
        "scope_id": value.scope_id,
        "scope_path_sha256": value.scope_path_sha256,
        "broker_nonce": value.broker_nonce,
        "broker_proof": value.broker_proof,
        "recursive_population": value.recursive_population,
        "recursive_members": value.recursive_members,
        "cgroup_kill": value.cgroup_kill,
    }


def _scope_receipt_model(value: object, *, encode: bool) -> BrokeredCgroupScopeReceipt:
    if encode:
        if type(value) is not BrokeredCgroupScopeReceipt:
            raise BrokerProtocolError
        fields = _decode_receipt(_encode_receipt(_scope_receipt_values(value)))
    else:
        fields = _decode_receipt(value)
    try:
        return BrokeredCgroupScopeReceipt(**fields)
    except TypeError:
        raise BrokerProtocolError from None


def _encode_scope_receipt_model(value: object) -> JsonObject:
    model = _scope_receipt_model(value, encode=True)
    return _encode_receipt(_scope_receipt_values(model))


def _ltfs_request_values(value: LtfsSessionRequest) -> JsonObject:
    return {
        "protocol_version": value.protocol_version,
        "operation_id": value.operation_id,
        "owner_generation": value.owner_generation,
        "mount_path_sha256": value.mount_path_sha256,
        "tape_device_identity_sha256": value.tape_device_identity_sha256,
        "scsi_device_identity_sha256": value.scsi_device_identity_sha256,
        "expected_media_scope_sha256": value.expected_media_scope_sha256,
        "observed_media_identity_sha256": value.observed_media_identity_sha256,
        "expected_volume_uuid": value.expected_volume_uuid,
        "expected_prior_generation": value.expected_prior_generation,
        "read_only": value.read_only,
        "tape_fd_identity_sha256": value.tape_fd_identity_sha256,
        "scsi_fd_identity_sha256": value.scsi_fd_identity_sha256,
        "cgroup_scope_receipt": value.cgroup_scope_receipt,
        "request_nonce": value.request_nonce,
    }


def _transform_ltfs_request(value: object, *, encode: bool) -> LtfsSessionRequest:
    if encode:
        if type(value) is not LtfsSessionRequest:
            raise BrokerProtocolError
        source = _exact_object(_ltfs_request_values(value), _LTFS_REQUEST_KEYS)
    else:
        source = _exact_object(value, _LTFS_REQUEST_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    opaque = _encode_opaque if encode else _decode_opaque
    scope = (
        _encode_scope_receipt_model(source["cgroup_scope_receipt"])
        if encode
        else source["cgroup_scope_receipt"]
    )
    if encode:
        decoded_scope = _scope_receipt_model(scope, encode=False)
    else:
        decoded_scope = _scope_receipt_model(scope, encode=False)
    fields = {
        "protocol_version": PROTOCOL_VERSION,
        "operation_id": _identity(source["operation_id"]),
        "owner_generation": _exact_int(source["owner_generation"]),
        "mount_path_sha256": _hex_digest(source["mount_path_sha256"]),
        "tape_device_identity_sha256": _hex_digest(
            source["tape_device_identity_sha256"]
        ),
        "scsi_device_identity_sha256": _hex_digest(
            source["scsi_device_identity_sha256"]
        ),
        "expected_media_scope_sha256": _hex_digest(
            source["expected_media_scope_sha256"]
        ),
        "observed_media_identity_sha256": _hex_digest(
            source["observed_media_identity_sha256"]
        ),
        "expected_volume_uuid": (
            None
            if source["expected_volume_uuid"] is None
            else _canonical_uuid(source["expected_volume_uuid"])
        ),
        "expected_prior_generation": _exact_int(
            source["expected_prior_generation"], minimum=1, maximum=(1 << 64) - 1
        ),
        "read_only": _exact_bool(source["read_only"]),
        "tape_fd_identity_sha256": _hex_digest(source["tape_fd_identity_sha256"]),
        "scsi_fd_identity_sha256": _hex_digest(source["scsi_fd_identity_sha256"]),
        "cgroup_scope_receipt": decoded_scope,
        "request_nonce": (
            _decode_opaque(opaque(source["request_nonce"]), exact_length=32)
            if encode
            else opaque(source["request_nonce"], exact_length=32)
        ),
    }
    if decoded_scope.owner_generation != fields["owner_generation"]:
        raise BrokerProtocolError
    if fields["expected_volume_uuid"] is None:
        raise BrokerProtocolError
    try:
        return LtfsSessionRequest(**fields)
    except TypeError:
        raise BrokerProtocolError from None


def _encode_ltfs_request(value: object) -> JsonObject:
    model = _transform_ltfs_request(value, encode=True)
    fields = _ltfs_request_values(model)
    fields["cgroup_scope_receipt"] = _encode_scope_receipt_model(
        model.cgroup_scope_receipt
    )
    fields["request_nonce"] = _encode_opaque(model.request_nonce, exact_length=32)
    return fields


def ltfs_request_sha256(value: LtfsSessionRequest) -> str:
    """Canonical digest bound into the broker's mounted-session receipt."""

    return hashlib.sha256(_canonical_packet(_encode_ltfs_request(value))).hexdigest()


def _ltfs_receipt_values(value: LtfsSessionReceipt) -> JsonObject:
    return {
        "protocol_version": value.protocol_version,
        "operation_id": value.operation_id,
        "receipt_operation_uuid": value.receipt_operation_uuid,
        "observed_volume_uuid": value.observed_volume_uuid,
        "observed_prior_generation": value.observed_prior_generation,
        "observed_volume_label": value.observed_volume_label,
        "observed_media_identity_sha256": value.observed_media_identity_sha256,
        "read_only": value.read_only,
        "owner_generation": value.owner_generation,
        "request_nonce": value.request_nonce,
        "session_id": value.session_id,
        "request_sha256": value.request_sha256,
        "child_pid": value.child_pid,
        "child_start_ticks": value.child_start_ticks,
        "mount_namespace_sha256": value.mount_namespace_sha256,
        "broker_nonce": value.broker_nonce,
        "broker_proof": value.broker_proof,
        "mounted": value.mounted,
    }


def _transform_ltfs_receipt(value: object, *, encode: bool) -> LtfsSessionReceipt:
    if encode:
        if type(value) is not LtfsSessionReceipt:
            raise BrokerProtocolError
        source = _exact_object(_ltfs_receipt_values(value), _LTFS_RECEIPT_KEYS)
    else:
        source = _exact_object(value, _LTFS_RECEIPT_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    opaque = _encode_opaque if encode else _decode_opaque

    def checked_opaque(item: object) -> bytes:
        if encode:
            return _decode_opaque(opaque(item, exact_length=32), exact_length=32)
        return opaque(item, exact_length=32)

    mounted = _exact_bool(source["mounted"])
    if not mounted:
        raise BrokerProtocolError
    fields = {
        "protocol_version": PROTOCOL_VERSION,
        "operation_id": _identity(source["operation_id"]),
        "receipt_operation_uuid": _canonical_uuid(source["receipt_operation_uuid"]),
        "observed_volume_uuid": _canonical_uuid(source["observed_volume_uuid"]),
        "observed_prior_generation": _exact_int(
            source["observed_prior_generation"], minimum=1, maximum=(1 << 64) - 1
        ),
        "observed_volume_label": _media_identity_text(source["observed_volume_label"]),
        "observed_media_identity_sha256": _hex_digest(
            source["observed_media_identity_sha256"]
        ),
        "read_only": _exact_bool(source["read_only"]),
        "owner_generation": _exact_int(source["owner_generation"]),
        "request_nonce": checked_opaque(source["request_nonce"]),
        "session_id": _identity(source["session_id"]),
        "request_sha256": _hex_digest(source["request_sha256"]),
        "child_pid": _exact_int(source["child_pid"], minimum=1, maximum=(1 << 31) - 1),
        "child_start_ticks": _exact_int(source["child_start_ticks"], minimum=1),
        "mount_namespace_sha256": _hex_digest(source["mount_namespace_sha256"]),
        "broker_nonce": checked_opaque(source["broker_nonce"]),
        "broker_proof": checked_opaque(source["broker_proof"]),
        "mounted": mounted,
    }
    if (
        len(
            {
                fields["request_nonce"],
                fields["broker_nonce"],
                fields["broker_proof"],
            }
        )
        != 3
    ):
        raise BrokerProtocolError
    try:
        return LtfsSessionReceipt(**fields)
    except TypeError:
        raise BrokerProtocolError from None


def _encode_ltfs_receipt(value: object) -> JsonObject:
    model = _transform_ltfs_receipt(value, encode=True)
    fields = _ltfs_receipt_values(model)
    for key in ("request_nonce", "broker_nonce", "broker_proof"):
        fields[key] = _encode_opaque(fields[key], exact_length=32)
    return fields


def _transform_ltfs_finalization(
    value: object, *, encode: bool
) -> LtfsFinalizationReceipt:
    if encode:
        if type(value) is not LtfsFinalizationReceipt:
            raise BrokerProtocolError
        source = _exact_object(
            {
                "protocol_version": value.protocol_version,
                "session_receipt": value.session_receipt,
                "standalone_receipt": value.standalone_receipt,
                "request_nonce": value.request_nonce,
                "finalization_nonce": value.finalization_nonce,
                "broker_proof": value.broker_proof,
                "unmounted": value.unmounted,
                "child_quiesced": value.child_quiesced,
            },
            _LTFS_FINALIZATION_KEYS,
        )
    else:
        source = _exact_object(value, _LTFS_FINALIZATION_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    session = _transform_ltfs_receipt(source["session_receipt"], encode=encode)
    standalone = _transform_ltfs_standalone_receipt(
        source["standalone_receipt"], encode=encode
    )
    if (
        standalone.operation_id != session.receipt_operation_uuid
        or standalone.volume_uuid != session.observed_volume_uuid
        or standalone.prior_generation != session.observed_prior_generation
        or (
            session.read_only
            and standalone.new_generation != standalone.prior_generation
        )
        or (
            not session.read_only
            and standalone.new_generation < standalone.prior_generation
        )
    ):
        raise BrokerProtocolError
    opaque = _encode_opaque if encode else _decode_opaque

    def checked_opaque(item: object) -> bytes:
        if encode:
            return _decode_opaque(opaque(item, exact_length=32), exact_length=32)
        return opaque(item, exact_length=32)

    unmounted = _exact_bool(source["unmounted"])
    quiesced = _exact_bool(source["child_quiesced"])
    if not unmounted or not quiesced:
        raise BrokerProtocolError
    request_nonce = checked_opaque(source["request_nonce"])
    finalization_nonce = checked_opaque(source["finalization_nonce"])
    broker_proof = checked_opaque(source["broker_proof"])
    if len({request_nonce, finalization_nonce, broker_proof}) != 3:
        raise BrokerProtocolError
    return LtfsFinalizationReceipt(
        protocol_version=PROTOCOL_VERSION,
        session_receipt=session,
        standalone_receipt=standalone,
        request_nonce=request_nonce,
        finalization_nonce=finalization_nonce,
        broker_proof=broker_proof,
        unmounted=True,
        child_quiesced=True,
    )


def _encode_ltfs_finalization(value: object) -> JsonObject:
    model = _transform_ltfs_finalization(value, encode=True)
    return {
        "protocol_version": PROTOCOL_VERSION,
        "session_receipt": _encode_ltfs_receipt(model.session_receipt),
        "standalone_receipt": _encode_ltfs_standalone_receipt(model.standalone_receipt),
        "request_nonce": _encode_opaque(model.request_nonce, exact_length=32),
        "finalization_nonce": _encode_opaque(model.finalization_nonce, exact_length=32),
        "broker_proof": _encode_opaque(model.broker_proof, exact_length=32),
        "unmounted": True,
        "child_quiesced": True,
    }


def _transform_permit(
    value: object,
    *,
    receipt: Callable[[object], JsonObject],
    opaque: Callable[[object], bytes | str],
) -> JsonObject:
    source = _exact_object(value, _PERMIT_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    return {
        "protocol_version": PROTOCOL_VERSION,
        "receipt": receipt(source["receipt"]),
        "pid": _exact_int(source["pid"], minimum=1, maximum=(1 << 31) - 1),
        "request_nonce": opaque(source["request_nonce"]),
        "permit_nonce": opaque(source["permit_nonce"]),
        "broker_proof": opaque(source["broker_proof"]),
    }


def _encode_permit(value: object) -> JsonObject:
    return _transform_permit(value, receipt=_encode_receipt, opaque=_encode_opaque)


def _decode_permit(value: object) -> JsonObject:
    return _transform_permit(value, receipt=_decode_receipt, opaque=_decode_opaque)


def _transform_validation(
    value: object,
    *,
    receipt: Callable[[object], JsonObject],
    opaque: Callable[[object], bytes | str],
) -> JsonObject:
    source = _exact_object(value, _VALIDATION_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    members = source["member_pids"]
    if type(members) not in (list, tuple):
        raise BrokerProtocolError
    normalized_members = tuple(
        _exact_int(pid, minimum=1, maximum=(1 << 31) - 1) for pid in members
    )
    if normalized_members != tuple(sorted(set(normalized_members))):
        raise BrokerProtocolError
    populated = _exact_bool(source["populated"])
    if populated is not bool(normalized_members):
        raise BrokerProtocolError
    return {
        "protocol_version": PROTOCOL_VERSION,
        "receipt": receipt(source["receipt"]),
        "challenge": opaque(source["challenge"]),
        "validation_nonce": opaque(source["validation_nonce"]),
        "broker_proof": opaque(source["broker_proof"]),
        "populated": populated,
        "member_pids": normalized_members,
    }


def _encode_validation(value: object) -> JsonObject:
    transformed = _transform_validation(
        value, receipt=_encode_receipt, opaque=_encode_opaque
    )
    transformed["member_pids"] = list(transformed["member_pids"])
    return transformed


def _decode_validation(value: object) -> JsonObject:
    return _transform_validation(value, receipt=_decode_receipt, opaque=_decode_opaque)


def _transform_claim(
    value: object,
    *,
    receipt: Callable[[object], JsonObject],
    opaque: Callable[[object], bytes | str],
) -> JsonObject:
    source = _exact_object(value, _CLAIM_KEYS)
    if _exact_int(source["protocol_version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    released = _exact_bool(source["released"])
    revoked = _exact_bool(source["permit_revoked"])
    if released == revoked:
        raise BrokerProtocolError
    return {
        "protocol_version": PROTOCOL_VERSION,
        "receipt": receipt(source["receipt"]),
        "pid": _exact_int(source["pid"], minimum=1, maximum=(1 << 31) - 1),
        "permit_sha256": _hex_digest(source["permit_sha256"]),
        "challenge": opaque(source["challenge"]),
        "claim_nonce": opaque(source["claim_nonce"]),
        "broker_proof": opaque(source["broker_proof"]),
        "released": released,
        "permit_revoked": revoked,
    }


def _encode_claim(value: object) -> JsonObject:
    return _transform_claim(value, receipt=_encode_receipt, opaque=_encode_opaque)


def _decode_claim(value: object) -> JsonObject:
    return _transform_claim(value, receipt=_decode_receipt, opaque=_decode_opaque)


_REQUEST_PARAM_KEYS = {
    "readiness": frozenset({"nonce"}),
    "create_scope": frozenset({"command_id", "owner_generation", "request_nonce"}),
    "open_scope": frozenset({"command_id", "owner_generation", "request_nonce"}),
    "attach": frozenset({"receipt", "pid"}),
    "validate_scope": frozenset({"receipt", "challenge"}),
    "prepare_release": frozenset({"receipt", "pid", "request_nonce"}),
    "release_child": frozenset({"receipt", "permit", "pid"}),
    "claim_unreleased": frozenset({"receipt", "pid", "permit_sha256", "challenge"}),
    "signal_scope": frozenset({"receipt", "signum"}),
    "kill_scope": frozenset({"receipt"}),
    "release_scope": frozenset({"receipt"}),
    "start_ltfs_session": frozenset({"request"}),
    "observe_ltfs_session": frozenset(
        {"operation_id", "owner_generation", "receipt", "challenge"}
    ),
    "finalize_ltfs_session": frozenset(
        {"operation_id", "owner_generation", "receipt", "request_nonce"}
    ),
    "recover_ltfs_finalization": frozenset(
        {
            "operation_id",
            "owner_generation",
            "mount_path_sha256",
            "tape_device_identity_sha256",
            "scsi_device_identity_sha256",
            "expected_media_scope_sha256",
            "observed_media_identity_sha256",
            "request_nonce",
        }
    ),
    "execute_ltfs_qualification_stage": frozenset({"request"}),
    "inspect_ltfs_qualification_stage": frozenset({"request"}),
}

_QUALIFICATION_REQUEST_KEYS = frozenset(
    {
        "protocol_version",
        "run_id",
        "plan_sha256",
        "stage_ordinal",
        "operation",
        "operation_token",
        "tape_device_identity_sha256",
        "scsi_device_identity_sha256",
        "expected_media_scope_sha256",
        "observed_media_identity_sha256",
        "expected_physical_label",
        "expected_tape_serial",
        "expected_drive_serial",
        "expected_drive_wwid",
        "expected_volume_uuid",
        "expected_generation",
        "issued_at_ns",
        "expires_at_ns",
        "request_nonce",
    }
)

_QUALIFICATION_INSPECTION_REQUEST_KEYS = frozenset(
    {"run_id", "stage_ordinal", "challenge"}
)

_QUALIFICATION_INSPECTION_SNAPSHOT_KEYS = frozenset(
    {
        "run_id",
        "stage_ordinal",
        "state",
        "boot_id",
        "request_sha256",
        "immutable_sha256",
        "plan_sha256",
        "operation",
        "operation_token_sha256",
        "tape_device_identity_sha256",
        "scsi_device_identity_sha256",
        "expected_media_scope_sha256",
        "observed_media_identity_sha256",
        "expected_physical_label",
        "expected_tape_serial",
        "expected_drive_serial",
        "expected_drive_wwid",
        "expected_volume_uuid",
        "expected_generation",
        "request_nonce",
        "created_at",
        "dispatched_at",
        "terminal_at",
    }
)

_QUALIFICATION_INSPECTION_KEYS = frozenset(
    {"state", "stage_snapshot", "dispatch", "observation_nonce", "proof"}
)


def _transform_qualification_request(
    value: object, *, encode: bool
) -> BrokerQualificationRequest:
    if encode:
        if type(value) is not BrokerQualificationRequest:
            raise BrokerProtocolError
        source = {
            "protocol_version": value.protocol_version,
            "run_id": value.run_id,
            "plan_sha256": value.plan_sha256,
            "stage_ordinal": value.stage_ordinal,
            "operation": value.operation.value,
            "operation_token": value.operation_token,
            "tape_device_identity_sha256": value.tape_device_identity_sha256,
            "scsi_device_identity_sha256": value.scsi_device_identity_sha256,
            "expected_media_scope_sha256": value.expected_media_scope_sha256,
            "observed_media_identity_sha256": value.observed_media_identity_sha256,
            "expected_physical_label": value.expected_physical_label,
            "expected_tape_serial": value.expected_tape_serial,
            "expected_drive_serial": value.expected_drive_serial,
            "expected_drive_wwid": value.expected_drive_wwid,
            "expected_volume_uuid": value.expected_volume_uuid,
            "expected_generation": value.expected_generation,
            "issued_at_ns": value.issued_at_ns,
            "expires_at_ns": value.expires_at_ns,
            "request_nonce": value.request_nonce,
        }
        if value.protocol_version == 2:
            source["canonical_plan_json"] = value.canonical_plan_json
    else:
        keys = _QUALIFICATION_REQUEST_KEYS
        if type(value) is dict and value.get("protocol_version") == 2:
            keys = keys | {"canonical_plan_json"}
        source = _exact_object(value, keys)
    try:
        operation = QualificationOperation(source["operation"])
    except (TypeError, ValueError):
        raise BrokerProtocolError from None
    opaque = _encode_opaque if encode else _decode_opaque
    raw_nonce = source["request_nonce"]
    request_nonce = (
        _decode_opaque(opaque(raw_nonce, exact_length=32), exact_length=32)
        if encode
        else opaque(raw_nonce, exact_length=32)
    )
    volume_uuid = source["expected_volume_uuid"]
    generation = source["expected_generation"]
    if (volume_uuid is None) != (generation is None):
        raise BrokerProtocolError
    if volume_uuid is not None:
        volume_uuid = _canonical_uuid(volume_uuid)
        generation = _exact_int(generation, maximum=(1 << 63) - 1)
    try:
        return BrokerQualificationRequest(
            protocol_version=_exact_int(source["protocol_version"], minimum=1),
            run_id=_canonical_uuid(source["run_id"]),
            plan_sha256=_hex_digest(source["plan_sha256"]),
            stage_ordinal=_exact_int(source["stage_ordinal"], minimum=1),
            operation=operation,
            operation_token=_hex_digest(source["operation_token"]),
            tape_device_identity_sha256=_hex_digest(
                source["tape_device_identity_sha256"]
            ),
            scsi_device_identity_sha256=_hex_digest(
                source["scsi_device_identity_sha256"]
            ),
            expected_media_scope_sha256=_hex_digest(
                source["expected_media_scope_sha256"]
            ),
            observed_media_identity_sha256=_hex_digest(
                source["observed_media_identity_sha256"]
            ),
            expected_physical_label=_media_identity_text(
                source["expected_physical_label"]
            ),
            expected_tape_serial=_media_identity_text(
                source["expected_tape_serial"], maximum=32
            ),
            expected_drive_serial=_media_identity_text(source["expected_drive_serial"]),
            expected_drive_wwid=_media_identity_text(source["expected_drive_wwid"]),
            expected_volume_uuid=volume_uuid,
            expected_generation=generation,
            issued_at_ns=_exact_int(source["issued_at_ns"]),
            expires_at_ns=_exact_int(source["expires_at_ns"], minimum=1),
            request_nonce=request_nonce,
            canonical_plan_json=source.get("canonical_plan_json"),
        )
    except (TypeError, ValueError):
        raise BrokerProtocolError from None


def _encode_qualification_request(value: object) -> JsonObject:
    model = _transform_qualification_request(value, encode=True)
    result = {
        "protocol_version": model.protocol_version,
        "run_id": model.run_id,
        "plan_sha256": model.plan_sha256,
        "stage_ordinal": model.stage_ordinal,
        "operation": model.operation.value,
        "operation_token": model.operation_token,
        "tape_device_identity_sha256": model.tape_device_identity_sha256,
        "scsi_device_identity_sha256": model.scsi_device_identity_sha256,
        "expected_media_scope_sha256": model.expected_media_scope_sha256,
        "observed_media_identity_sha256": model.observed_media_identity_sha256,
        "expected_physical_label": model.expected_physical_label,
        "expected_tape_serial": model.expected_tape_serial,
        "expected_drive_serial": model.expected_drive_serial,
        "expected_drive_wwid": model.expected_drive_wwid,
        "expected_volume_uuid": model.expected_volume_uuid,
        "expected_generation": model.expected_generation,
        "issued_at_ns": model.issued_at_ns,
        "expires_at_ns": model.expires_at_ns,
        "request_nonce": _encode_opaque(model.request_nonce, exact_length=32),
    }
    if model.protocol_version == 2:
        result["canonical_plan_json"] = model.canonical_plan_json
    return result


def _transform_qualification_inspection_request(
    value: object, *, encode: bool
) -> BrokerQualificationInspectionRequest:
    if encode:
        if type(value) is not BrokerQualificationInspectionRequest:
            raise BrokerProtocolError
        source = {
            "run_id": value.run_id,
            "stage_ordinal": value.stage_ordinal,
            "challenge": value.challenge,
        }
    else:
        source = _exact_object(value, _QUALIFICATION_INSPECTION_REQUEST_KEYS)
    opaque = _encode_opaque if encode else _decode_opaque
    challenge = (
        _decode_opaque(opaque(source["challenge"], exact_length=32), exact_length=32)
        if encode
        else opaque(source["challenge"], exact_length=32)
    )
    try:
        return BrokerQualificationInspectionRequest(
            run_id=_canonical_uuid(source["run_id"]),
            stage_ordinal=_exact_int(source["stage_ordinal"], minimum=1),
            challenge=challenge,
        )
    except (TypeError, ValueError):
        raise BrokerProtocolError from None


def _encode_qualification_inspection_request(value: object) -> JsonObject:
    model = _transform_qualification_inspection_request(value, encode=True)
    return {
        "run_id": model.run_id,
        "stage_ordinal": model.stage_ordinal,
        "challenge": _encode_opaque(model.challenge, exact_length=32),
    }


def _transform_params(method: str, params: object, *, encode: bool) -> JsonObject:
    source = _exact_object(params, _REQUEST_PARAM_KEYS[method])
    opaque = _encode_opaque if encode else _decode_opaque
    receipt = _encode_receipt if encode else _decode_receipt
    permit = _encode_permit if encode else _decode_permit
    if method == "readiness":
        return {"nonce": opaque(source["nonce"])}
    if method == "start_ltfs_session":
        transform = (
            _encode_ltfs_request
            if encode
            else lambda item: _transform_ltfs_request(item, encode=False)
        )
        return {"request": transform(source["request"])}
    if method == "execute_ltfs_qualification_stage":
        transform = (
            _encode_qualification_request
            if encode
            else lambda item: _transform_qualification_request(item, encode=False)
        )
        return {"request": transform(source["request"])}
    if method == "inspect_ltfs_qualification_stage":
        transform = (
            _encode_qualification_inspection_request
            if encode
            else lambda item: _transform_qualification_inspection_request(
                item, encode=False
            )
        )
        return {"request": transform(source["request"])}
    if method in {"observe_ltfs_session", "finalize_ltfs_session"}:
        transform = (
            _encode_ltfs_receipt
            if encode
            else lambda item: _transform_ltfs_receipt(item, encode=False)
        )
        session = transform(source["receipt"])
        operation_id = _identity(source["operation_id"])
        owner_generation = _exact_int(source["owner_generation"])
        model = _transform_ltfs_receipt(session, encode=False) if encode else session
        if (
            model.operation_id != operation_id
            or model.owner_generation != owner_generation
        ):
            raise BrokerProtocolError
        result = {
            "operation_id": operation_id,
            "owner_generation": owner_generation,
            "receipt": session,
        }
        if method == "observe_ltfs_session":
            result["challenge"] = opaque(source["challenge"], exact_length=32)
        else:
            result["request_nonce"] = opaque(source["request_nonce"], exact_length=32)
        return result
    if method == "recover_ltfs_finalization":
        return {
            "operation_id": _identity(source["operation_id"]),
            "owner_generation": _exact_int(source["owner_generation"]),
            "mount_path_sha256": _hex_digest(source["mount_path_sha256"]),
            "tape_device_identity_sha256": _hex_digest(
                source["tape_device_identity_sha256"]
            ),
            "scsi_device_identity_sha256": _hex_digest(
                source["scsi_device_identity_sha256"]
            ),
            "expected_media_scope_sha256": _hex_digest(
                source["expected_media_scope_sha256"]
            ),
            "observed_media_identity_sha256": _hex_digest(
                source["observed_media_identity_sha256"]
            ),
            "request_nonce": opaque(source["request_nonce"], exact_length=32),
        }
    if method in {"create_scope", "open_scope"}:
        return {
            "command_id": _identity(source["command_id"]),
            "owner_generation": _exact_int(source["owner_generation"]),
            "request_nonce": opaque(source["request_nonce"]),
        }
    result: JsonObject = {"receipt": receipt(source["receipt"])}
    if method in {"attach", "prepare_release", "release_child", "claim_unreleased"}:
        result["pid"] = _exact_int(source["pid"], minimum=1, maximum=(1 << 31) - 1)
    if method == "validate_scope":
        result["challenge"] = opaque(source["challenge"])
    elif method == "prepare_release":
        result["request_nonce"] = opaque(source["request_nonce"])
    elif method == "release_child":
        result["permit"] = permit(source["permit"])
    elif method == "claim_unreleased":
        result["permit_sha256"] = _hex_digest(source["permit_sha256"])
        result["challenge"] = opaque(source["challenge"])
    elif method == "signal_scope":
        signum = _exact_int(source["signum"], minimum=1)
        if signum != 15:
            raise BrokerProtocolError
        result["signum"] = signum
    return result


def encode_request(
    method: str,
    *,
    request_id: bytes,
    capability: bytes,
    params: Mapping[str, object],
) -> bytes:
    checked_method = _method(method)
    encoded = {
        "version": PROTOCOL_VERSION,
        "method": checked_method,
        "request_id": _encode_opaque(request_id, exact_length=32),
        "capability": _encode_opaque(capability),
        "params": _transform_params(checked_method, params, encode=True),
    }
    return _canonical_packet(encoded)


def _decode_request_structure(payload: bytes) -> BrokerRequest:
    """Decode one canonical request without granting semantic authority."""

    source = _exact_object(_parse_packet(payload), _REQUEST_KEYS)
    if _exact_int(source["version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    method = _method(source["method"])
    return BrokerRequest(
        method=method,
        request_id=_decode_opaque(source["request_id"], exact_length=32),
        capability=_decode_opaque(source["capability"]),
        params=_transform_params(method, source["params"], encode=False),
    )


def decode_request(
    payload: bytes,
    *,
    ltfs_authority: LtfsProtocolAuthority | None = None,
    ancillary_fd_identities: tuple[str, ...] = (),
) -> BrokerRequest:
    request = _decode_request_structure(payload)
    method = request.method
    if method in _LTFS_METHODS:
        if ltfs_authority is None:
            raise BrokerProtocolError
        ltfs_authority.accept_request(request, ancillary_fd_identities)
    elif ancillary_fd_identities:
        raise BrokerProtocolError
    return request


_RESULT_KEYS = {
    "readiness": frozenset({"nonce", "features"}),
    "create_scope": frozenset({"receipt"}),
    "open_scope": frozenset({"receipt"}),
    "attach": frozenset(),
    "validate_scope": frozenset({"validation"}),
    "prepare_release": frozenset({"permit"}),
    "release_child": frozenset(),
    "claim_unreleased": frozenset({"claim"}),
    "signal_scope": frozenset(),
    "kill_scope": frozenset(),
    "release_scope": frozenset(),
    "start_ltfs_session": frozenset({"receipt"}),
    "observe_ltfs_session": frozenset(
        {"receipt", "challenge", "observation_nonce", "broker_proof", "mounted"}
    ),
    "finalize_ltfs_session": frozenset({"receipt"}),
    "recover_ltfs_finalization": frozenset({"receipt"}),
    "execute_ltfs_qualification_stage": frozenset({"dispatch"}),
    "inspect_ltfs_qualification_stage": frozenset({"inspection"}),
}

_QUALIFICATION_DISPATCH_KEYS = frozenset(
    {
        "protocol_version",
        "run_id",
        "stage_ordinal",
        "operation",
        "request_sha256",
        "dispatch_state",
        "terminal_receipt_sha256",
        "child_exit_code",
        "evidence_sha256",
        "broker_nonce",
        "broker_proof",
    }
)


def _transform_qualification_dispatch(
    value: object, *, encode: bool
) -> BrokerQualificationDispatch:
    if encode:
        if type(value) is not BrokerQualificationDispatch:
            raise BrokerProtocolError
        source = {
            "protocol_version": value.protocol_version,
            "run_id": value.run_id,
            "stage_ordinal": value.stage_ordinal,
            "operation": value.operation.value,
            "request_sha256": value.request_sha256,
            "dispatch_state": value.dispatch_state,
            "terminal_receipt_sha256": value.terminal_receipt_sha256,
            "child_exit_code": value.child_exit_code,
            "evidence_sha256": value.evidence_sha256,
            "broker_nonce": value.broker_nonce,
            "broker_proof": value.broker_proof,
        }
    else:
        source = _exact_object(value, _QUALIFICATION_DISPATCH_KEYS)
    try:
        operation = QualificationOperation(source["operation"])
    except (TypeError, ValueError):
        raise BrokerProtocolError from None
    terminal = source["terminal_receipt_sha256"]
    if terminal is not None:
        terminal = _hex_digest(terminal)
    exit_code = source["child_exit_code"]
    if exit_code is not None:
        exit_code = _exact_int(exit_code, maximum=255)
    opaque = _encode_opaque if encode else _decode_opaque
    broker_nonce = (
        _decode_opaque(opaque(source["broker_nonce"], exact_length=32), exact_length=32)
        if encode
        else opaque(source["broker_nonce"], exact_length=32)
    )
    broker_proof = (
        _decode_opaque(opaque(source["broker_proof"], exact_length=32), exact_length=32)
        if encode
        else opaque(source["broker_proof"], exact_length=32)
    )
    try:
        return BrokerQualificationDispatch(
            protocol_version=_exact_int(source["protocol_version"], minimum=1),
            run_id=_canonical_uuid(source["run_id"]),
            stage_ordinal=_exact_int(source["stage_ordinal"], minimum=1),
            operation=operation,
            request_sha256=_hex_digest(source["request_sha256"]),
            dispatch_state=source["dispatch_state"],
            terminal_receipt_sha256=terminal,
            child_exit_code=exit_code,
            evidence_sha256=_hex_digest(source["evidence_sha256"]),
            broker_nonce=broker_nonce,
            broker_proof=broker_proof,
        )
    except (TypeError, ValueError):
        raise BrokerProtocolError from None


def _encode_qualification_dispatch(value: object) -> JsonObject:
    model = _transform_qualification_dispatch(value, encode=True)
    return {
        "protocol_version": model.protocol_version,
        "run_id": model.run_id,
        "stage_ordinal": model.stage_ordinal,
        "operation": model.operation.value,
        "request_sha256": model.request_sha256,
        "dispatch_state": model.dispatch_state,
        "terminal_receipt_sha256": model.terminal_receipt_sha256,
        "child_exit_code": model.child_exit_code,
        "evidence_sha256": model.evidence_sha256,
        "broker_nonce": _encode_opaque(model.broker_nonce, exact_length=32),
        "broker_proof": _encode_opaque(model.broker_proof, exact_length=32),
    }


def _transform_qualification_inspection_snapshot(
    value: object, *, encode: bool
) -> JsonObject:
    if encode:
        try:
            encoded = json.loads(qualification_inspection_snapshot_payload(value))
        except (TypeError, ValueError, json.JSONDecodeError):
            raise BrokerProtocolError from None
        return _exact_object(encoded, _QUALIFICATION_INSPECTION_SNAPSHOT_KEYS)
    source = _exact_object(value, _QUALIFICATION_INSPECTION_SNAPSHOT_KEYS)
    fields = dict(source)
    fields["request_nonce"] = _decode_opaque(fields["request_nonce"], exact_length=32)
    try:
        # The model-owned helper is the only durable-snapshot authority.
        qualification_inspection_snapshot_payload(fields)
    except (TypeError, ValueError):
        raise BrokerProtocolError from None
    return fields


def _transform_qualification_inspection(
    value: object, *, encode: bool
) -> BrokerQualificationInspection:
    if encode:
        if type(value) is not BrokerQualificationInspection:
            raise BrokerProtocolError
        source = {
            "state": value.state,
            "stage_snapshot": value.stage_snapshot,
            "dispatch": value.dispatch,
            "observation_nonce": value.observation_nonce,
            "proof": value.proof,
        }
    else:
        source = _exact_object(value, _QUALIFICATION_INSPECTION_KEYS)
    snapshot = source["stage_snapshot"]
    if snapshot is not None:
        if encode:
            try:
                qualification_inspection_snapshot_payload(snapshot)
            except (TypeError, ValueError):
                raise BrokerProtocolError from None
            snapshot = dict(snapshot)
        else:
            snapshot = _transform_qualification_inspection_snapshot(
                snapshot, encode=False
            )
    dispatch = source["dispatch"]
    if dispatch is not None:
        dispatch = _transform_qualification_dispatch(dispatch, encode=encode)
    opaque = _encode_opaque if encode else _decode_opaque
    observation_nonce = opaque(source["observation_nonce"], exact_length=32)
    proof = opaque(source["proof"], exact_length=32)
    if encode:
        observation_nonce = _decode_opaque(observation_nonce, exact_length=32)
        proof = _decode_opaque(proof, exact_length=32)
    try:
        return BrokerQualificationInspection(
            state=source["state"],
            stage_snapshot=snapshot,
            dispatch=dispatch,
            observation_nonce=observation_nonce,
            proof=proof,
        )
    except (TypeError, ValueError):
        raise BrokerProtocolError from None


def _encode_qualification_inspection(value: object) -> JsonObject:
    model = _transform_qualification_inspection(value, encode=True)
    snapshot = model.stage_snapshot
    return {
        "state": model.state,
        "stage_snapshot": (
            None
            if snapshot is None
            else _transform_qualification_inspection_snapshot(snapshot, encode=True)
        ),
        "dispatch": (
            None
            if model.dispatch is None
            else _encode_qualification_dispatch(model.dispatch)
        ),
        "observation_nonce": _encode_opaque(model.observation_nonce, exact_length=32),
        "proof": _encode_opaque(model.proof, exact_length=32),
    }


def _transform_result(method: str, result: object, *, encode: bool) -> JsonObject:
    source = _exact_object(result, _RESULT_KEYS[method])
    if method == "readiness":
        opaque = _encode_opaque if encode else _decode_opaque
        nonce = opaque(source["nonce"], exact_length=32)
        features = _transform_readiness_features(source["features"], encode=encode)
        challenge = features["challenge"]
        if encode:
            challenge = _decode_opaque(challenge, exact_length=32)
            raw_nonce = _decode_opaque(nonce, exact_length=32)
        else:
            raw_nonce = nonce
        if challenge != raw_nonce:
            raise BrokerProtocolError
        return {"nonce": nonce, "features": features}
    if method in {"create_scope", "open_scope"}:
        transform = _encode_receipt if encode else _decode_receipt
        return {"receipt": transform(source["receipt"])}
    if method == "validate_scope":
        transform = _encode_validation if encode else _decode_validation
        return {"validation": transform(source["validation"])}
    if method == "prepare_release":
        transform = _encode_permit if encode else _decode_permit
        return {"permit": transform(source["permit"])}
    if method == "claim_unreleased":
        transform = _encode_claim if encode else _decode_claim
        return {"claim": transform(source["claim"])}
    if method == "start_ltfs_session":
        transform = (
            _encode_ltfs_receipt
            if encode
            else lambda item: _transform_ltfs_receipt(item, encode=False)
        )
        return {"receipt": transform(source["receipt"])}
    if method == "observe_ltfs_session":
        transform = (
            _encode_ltfs_receipt
            if encode
            else lambda item: _transform_ltfs_receipt(item, encode=False)
        )
        opaque = _encode_opaque if encode else _decode_opaque
        mounted = _exact_bool(source["mounted"])
        if not mounted:
            raise BrokerProtocolError
        challenge = opaque(source["challenge"], exact_length=32)
        observation_nonce = opaque(source["observation_nonce"], exact_length=32)
        broker_proof = opaque(source["broker_proof"], exact_length=32)
        decoded_values = (
            (
                _decode_opaque(challenge, exact_length=32),
                _decode_opaque(observation_nonce, exact_length=32),
                _decode_opaque(broker_proof, exact_length=32),
            )
            if encode
            else (challenge, observation_nonce, broker_proof)
        )
        if len(set(decoded_values)) != 3:
            raise BrokerProtocolError
        return {
            "receipt": transform(source["receipt"]),
            "challenge": challenge,
            "observation_nonce": observation_nonce,
            "broker_proof": broker_proof,
            "mounted": True,
        }
    if method in {"finalize_ltfs_session", "recover_ltfs_finalization"}:
        transform = (
            _encode_ltfs_finalization
            if encode
            else lambda item: _transform_ltfs_finalization(item, encode=False)
        )
        return {"receipt": transform(source["receipt"])}
    if method == "execute_ltfs_qualification_stage":
        transform = (
            _encode_qualification_dispatch
            if encode
            else lambda item: _transform_qualification_dispatch(item, encode=False)
        )
        return {"dispatch": transform(source["dispatch"])}
    if method == "inspect_ltfs_qualification_stage":
        transform = (
            _encode_qualification_inspection
            if encode
            else lambda item: _transform_qualification_inspection(item, encode=False)
        )
        return {"inspection": transform(source["inspection"])}
    return {}


def encode_response(
    method: str,
    *,
    request_id: bytes,
    result: Mapping[str, object] | None = None,
    error_code: str | None = None,
) -> bytes:
    checked_method = _method(method)
    encoded: JsonObject = {
        "version": PROTOCOL_VERSION,
        "method": checked_method,
        "request_id": _encode_opaque(request_id, exact_length=32),
    }
    if (result is None) == (error_code is None):
        raise BrokerProtocolError
    if error_code is not None:
        if type(error_code) is not str or error_code not in _ERROR_CODES:
            raise BrokerProtocolError
        encoded.update({"status": "error", "error": {"code": error_code}})
    else:
        encoded.update(
            {
                "status": "ok",
                "result": _transform_result(checked_method, result, encode=True),
            }
        )
    return _canonical_packet(encoded)


def decode_response(
    payload: bytes,
    *,
    request: BrokerRequest | None = None,
    ltfs_authority: LtfsProtocolAuthority | None = None,
) -> BrokerResponse:
    source = _parse_packet(payload)
    status = source.get("status")
    if type(status) is not str or status not in {"ok", "error"}:
        raise BrokerProtocolError
    expected_keys = _RESPONSE_OK_KEYS if status == "ok" else _RESPONSE_ERROR_KEYS
    source = _exact_object(source, expected_keys)
    if _exact_int(source["version"], minimum=1) != PROTOCOL_VERSION:
        raise BrokerProtocolError
    method = _method(source["method"])
    request_id = _decode_opaque(source["request_id"], exact_length=32)
    if status == "ok":
        response = BrokerResponse(
            method=method,
            request_id=request_id,
            result=_transform_result(method, source["result"], encode=False),
            error_code=None,
        )
        if method in _LTFS_METHODS:
            if request is None or ltfs_authority is None:
                raise BrokerProtocolError
            ltfs_authority.accept_response(request, response)
        elif method == "execute_ltfs_qualification_stage":
            if (
                request is None
                or request.method != method
                or request.request_id != request_id
                or response.result is None
            ):
                raise BrokerProtocolError
            request_model = request.params.get("request")
            dispatch = response.result.get("dispatch")
            if (
                type(request_model) is not BrokerQualificationRequest
                or type(dispatch) is not BrokerQualificationDispatch
                or dispatch.run_id != request_model.run_id
                or dispatch.stage_ordinal != request_model.stage_ordinal
                or dispatch.operation != request_model.operation
                or dispatch.request_sha256 != request_model.request_sha256
            ):
                raise BrokerProtocolError
        elif method == "inspect_ltfs_qualification_stage":
            if (
                request is None
                or request.method != method
                or request.request_id != request_id
                or response.result is None
            ):
                raise BrokerProtocolError
            request_model = request.params.get("request")
            inspection = response.result.get("inspection")
            if (
                type(request_model) is not BrokerQualificationInspectionRequest
                or type(inspection) is not BrokerQualificationInspection
                or (
                    inspection.stage_snapshot is not None
                    and (
                        inspection.stage_snapshot["run_id"] != request_model.run_id
                        or inspection.stage_snapshot["stage_ordinal"]
                        != request_model.stage_ordinal
                    )
                )
            ):
                raise BrokerProtocolError
        return response
    error = _exact_object(source["error"], frozenset({"code"}))
    code = error["code"]
    if type(code) is not str or code not in _ERROR_CODES:
        raise BrokerProtocolError
    response = BrokerResponse(
        method=method,
        request_id=request_id,
        result=None,
        error_code=code,
    )
    if method in _LTFS_METHODS or (
        request is not None and request.method in _LTFS_METHODS
    ):
        if request is None or ltfs_authority is None:
            raise BrokerProtocolError
        ltfs_authority.accept_response(request, response)
    elif method in {
        "execute_ltfs_qualification_stage",
        "inspect_ltfs_qualification_stage",
    } or (
        request is not None
        and request.method
        in {"execute_ltfs_qualification_stage", "inspect_ltfs_qualification_stage"}
    ):
        if (
            request is None
            or request.method != method
            or request.request_id != request_id
        ):
            raise BrokerProtocolError
    return response
