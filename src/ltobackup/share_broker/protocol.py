from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import ipaddress
import json
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, TypeAlias

from pydantic import TypeAdapter
from pydantic import ValidationError as PydanticValidationError

from ltobackup.shares import (
    ShareConfig,
    ShareValidationError,
    normalize_server,
    normalize_share_id,
    validate_share_safe_error_code,
)

PROTOCOL_VERSION = 1
MAX_FRAME_BYTES = 65_536
_OPAQUE_BYTES = 32
_ACTIONS = frozenset(
    {
        "credential.install",
        "credential.delete",
        "credential.inspect",
        "mount.start",
        "mount.stop",
        "mount.inspect",
        "mount.fence",
        "broker.ready",
    }
)
_REQUEST_KEYS = frozenset(
    {"version", "action", "request_id", "nonce", "params", "capability_proof"}
)
_RESPONSE_KEYS = frozenset(
    {"version", "action", "request_id", "status", "result", "error", "proof"}
)
_MOUNT_PARAM_KEYS = frozenset(
    {
        "share_id",
        "config",
        "config_revision",
        "credential_generation",
        "admitted_addresses",
    }
)
_STOP_PARAM_KEYS = frozenset({"share_id"})
_INSPECT_PARAM_KEYS = frozenset({"share_id"})
_INSTALL_PARAM_KEYS = frozenset(
    {"share_id", "credential_generation", "username", "domain", "password"}
)
_DELETE_PARAM_KEYS = frozenset({"share_id", "credential_generation"})
_CREDENTIAL_INSPECT_PARAM_KEYS = frozenset({"share_id"})
_FENCE_PARAM_KEYS = frozenset({"known_share_ids"})
_READY_PARAM_KEYS = frozenset()
_RECEIPT_KEYS = frozenset(
    {
        "schema",
        "action",
        "share_id",
        "request_sha256",
        "config_revision",
        "credential_generation",
        "unit_name",
        "mount_identity_sha256",
        "read_only",
        "result",
        "safe_error_code",
        "broker_nonce",
        "broker_proof",
        "endpoint_server",
        "admitted_addresses",
        "filesystem_type",
        "source_sha256",
    }
)
_ERROR_CODES = frozenset(
    {
        "auth.denied",
        "protocol.invalid",
        "share_broker_unavailable",
        "share_credentials_required",
        "share_identity_changed",
        "share_mount_failed",
        "share_endpoint_not_allowed",
        "share_recovery_required",
        "share_state_conflict",
    }
)
_SHARE_ADAPTER = TypeAdapter(ShareConfig)

JsonObject: TypeAlias = dict[str, object]


class ShareBrokerProtocolError(ValueError):
    """Redacted malformed or out-of-contract local broker packet."""

    def __init__(self) -> None:
        super().__init__("invalid share broker protocol")


@dataclass(frozen=True)
class ShareBrokerRequest:
    action: str
    request_id: bytes
    nonce: bytes
    params: JsonObject
    request_sha256: str


@dataclass(frozen=True)
class ShareMountReceiptV1:
    schema: int
    action: Literal["mount.start", "mount.stop", "mount.inspect"]
    share_id: str
    request_sha256: str
    config_revision: int
    credential_generation: int
    unit_name: str
    mount_identity_sha256: str | None
    read_only: bool
    result: Literal["mounted", "unmounted", "failed"]
    safe_error_code: str | None
    broker_nonce: bytes
    broker_proof: bytes
    endpoint_server: str | None
    admitted_addresses: tuple[str, ...]
    filesystem_type: Literal["nfs", "nfs4", "cifs"] | None
    source_sha256: str | None


@dataclass(frozen=True)
class ShareBrokerResponse:
    action: str
    request_id: bytes
    result: JsonObject | None
    error_code: str | None


class _DuplicateKey(ValueError):
    pass


def encode_request(
    action: str,
    *,
    request_id: bytes,
    nonce: bytes,
    capability: bytes,
    params: Mapping[str, object],
) -> bytes:
    checked_action = _action(action)
    request_id_encoded = _encode_opaque(request_id)
    nonce_encoded = _encode_opaque(nonce)
    checked_params = _transform_params(checked_action, params, encode=True)
    unsigned = {
        "version": PROTOCOL_VERSION,
        "action": checked_action,
        "request_id": request_id_encoded,
        "nonce": nonce_encoded,
        "params": checked_params,
    }
    proof = hmac.new(
        _capability(capability),
        b"lto-share-broker-request-v1\0" + _canonical_json(unsigned),
        hashlib.sha256,
    ).digest()
    return _frame({**unsigned, "capability_proof": _encode_opaque(proof)})


def decode_request(payload: bytes, *, capability: bytes) -> ShareBrokerRequest:
    source = _exact_object(_parse_frame(payload), _REQUEST_KEYS)
    if _integer(source["version"], minimum=1) != PROTOCOL_VERSION:
        raise ShareBrokerProtocolError
    action = _action(source["action"])
    request_id = _decode_opaque(source["request_id"])
    nonce = _decode_opaque(source["nonce"])
    if hmac.compare_digest(request_id, nonce):
        raise ShareBrokerProtocolError
    unsigned = {key: source[key] for key in _REQUEST_KEYS if key != "capability_proof"}
    expected = hmac.new(
        _capability(capability),
        b"lto-share-broker-request-v1\0" + _canonical_json(unsigned),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_decode_opaque(source["capability_proof"]), expected):
        raise ShareBrokerProtocolError
    params = _transform_params(action, source["params"], encode=False)
    return ShareBrokerRequest(
        action=action,
        request_id=request_id,
        nonce=nonce,
        params=params,
        request_sha256=hashlib.sha256(
            b"lto-share-broker-request-digest-v1\0" + _canonical_json(unsigned)
        ).hexdigest(),
    )


def encode_response(
    action: str,
    *,
    request_id: bytes,
    proof_key: bytes,
    result: Mapping[str, object] | None = None,
    error_code: str | None = None,
) -> bytes:
    checked_action = _action(action)
    if (result is None) == (error_code is None):
        raise ShareBrokerProtocolError
    encoded_result: object = None
    encoded_error: object = None
    status = "ok"
    if result is not None:
        encoded_result = _transform_result(checked_action, result, encode=True)
    else:
        status = "error"
        if type(error_code) is not str or error_code not in _ERROR_CODES:
            raise ShareBrokerProtocolError
        encoded_error = {"code": error_code}
    unsigned = {
        "version": PROTOCOL_VERSION,
        "action": checked_action,
        "request_id": _encode_opaque(request_id),
        "status": status,
        "result": encoded_result,
        "error": encoded_error,
    }
    proof = hmac.new(
        _proof_key(proof_key),
        b"lto-share-broker-response-v1\0" + _canonical_json(unsigned),
        hashlib.sha256,
    ).digest()
    return _frame({**unsigned, "proof": _encode_opaque(proof)})


def decode_response(payload: bytes, *, proof_key: bytes) -> ShareBrokerResponse:
    source = _exact_object(_parse_frame(payload), _RESPONSE_KEYS)
    if _integer(source["version"], minimum=1) != PROTOCOL_VERSION:
        raise ShareBrokerProtocolError
    action = _action(source["action"])
    request_id = _decode_opaque(source["request_id"])
    unsigned = {key: source[key] for key in _RESPONSE_KEYS if key != "proof"}
    expected = hmac.new(
        _proof_key(proof_key),
        b"lto-share-broker-response-v1\0" + _canonical_json(unsigned),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(_decode_opaque(source["proof"]), expected):
        raise ShareBrokerProtocolError
    status = source["status"]
    if status == "ok":
        if source["error"] is not None:
            raise ShareBrokerProtocolError
        result = _transform_result(action, source["result"], encode=False)
        if action in {"mount.start", "mount.stop", "mount.inspect"}:
            result["receipt"] = verify_mount_receipt(
                result["receipt"], proof_key=proof_key
            )
        return ShareBrokerResponse(action, request_id, result, None)
    if status == "error":
        if source["result"] is not None:
            raise ShareBrokerProtocolError
        error = _exact_object(source["error"], frozenset({"code"}))
        code = error["code"]
        if type(code) is not str or code not in _ERROR_CODES:
            raise ShareBrokerProtocolError
        return ShareBrokerResponse(action, request_id, None, code)
    raise ShareBrokerProtocolError


def issue_mount_receipt(
    *,
    action: str,
    share_id: str,
    request_sha256: str,
    config_revision: int,
    credential_generation: int,
    unit_name: str,
    mount_identity_sha256: str | None,
    read_only: bool,
    result: str,
    safe_error_code: str | None,
    broker_nonce: bytes,
    proof_key: bytes,
    endpoint_server: str | None,
    admitted_addresses: tuple[str, ...],
    filesystem_type: str | None,
    source_sha256: str | None,
) -> ShareMountReceiptV1:
    unsigned = _receipt_unsigned(
        action=action,
        share_id=share_id,
        request_sha256=request_sha256,
        config_revision=config_revision,
        credential_generation=credential_generation,
        unit_name=unit_name,
        mount_identity_sha256=mount_identity_sha256,
        read_only=read_only,
        result=result,
        safe_error_code=safe_error_code,
        broker_nonce=broker_nonce,
        endpoint_server=endpoint_server,
        admitted_addresses=admitted_addresses,
        filesystem_type=filesystem_type,
        source_sha256=source_sha256,
    )
    proof = hmac.new(
        _proof_key(proof_key),
        b"lto-share-mount-receipt-v1\0" + _canonical_json(unsigned),
        hashlib.sha256,
    ).digest()
    return _receipt_from_mapping(
        {**unsigned, "broker_proof": _encode_opaque(proof)}, proof_key
    )


def verify_mount_receipt(
    receipt: ShareMountReceiptV1, *, proof_key: bytes
) -> ShareMountReceiptV1:
    if type(receipt) is not ShareMountReceiptV1:
        raise ShareBrokerProtocolError
    return _receipt_from_mapping(_encode_receipt(receipt), proof_key)


def mount_receipt_sha256(receipt: ShareMountReceiptV1) -> str:
    """Return the canonical public digest of one validated signed receipt."""

    checked = _receipt_from_mapping(_encode_receipt(receipt), None)
    return hashlib.sha256(
        b"lto-share-mount-receipt-digest-v1\0"
        + _canonical_json(_encode_receipt(checked))
    ).hexdigest()


def _transform_params(action: str, value: object, *, encode: bool) -> JsonObject:
    if not isinstance(value, Mapping):
        raise ShareBrokerProtocolError
    keys = {
        "credential.install": _INSTALL_PARAM_KEYS,
        "credential.delete": _DELETE_PARAM_KEYS,
        "credential.inspect": _CREDENTIAL_INSPECT_PARAM_KEYS,
        "mount.start": _MOUNT_PARAM_KEYS,
        "mount.stop": _STOP_PARAM_KEYS,
        "mount.inspect": _INSPECT_PARAM_KEYS,
        "mount.fence": _FENCE_PARAM_KEYS,
        "broker.ready": _READY_PARAM_KEYS,
    }[action]
    if action == "broker.ready":
        _exact_object(value, keys)
        return {}
    if action == "mount.inspect" and frozenset(value) == _MOUNT_PARAM_KEYS:
        keys = _MOUNT_PARAM_KEYS
    source = _exact_object(value, keys)
    if action == "mount.fence":
        return {"known_share_ids": _known_share_ids(source["known_share_ids"])}
    try:
        share_id = normalize_share_id(source["share_id"])
    except (ShareValidationError, TypeError):
        raise ShareBrokerProtocolError from None
    result: JsonObject = {"share_id": share_id}
    if action in {"credential.inspect", "mount.stop"} or (
        action == "mount.inspect" and keys == _INSPECT_PARAM_KEYS
    ):
        return result
    generation = _integer(source["credential_generation"], minimum=0)
    result["credential_generation"] = generation
    if action == "credential.install":
        if generation < 1:
            raise ShareBrokerProtocolError
        result.update(
            username=_bounded_secret_field(source["username"], 256, empty=False),
            domain=_bounded_secret_field(source["domain"], 256, empty=True),
            password=_bounded_secret_field(source["password"], 4096, empty=False),
        )
        return result
    if action == "credential.delete":
        if generation < 1:
            raise ShareBrokerProtocolError
        return result
    result["config_revision"] = _integer(source["config_revision"], minimum=1)
    try:
        config = _SHARE_ADAPTER.validate_python(source["config"])
    except (PydanticValidationError, TypeError, ValueError):
        raise ShareBrokerProtocolError from None
    result["config"] = config.model_dump(mode="json") if encode else config
    addresses = _admitted_addresses(source["admitted_addresses"])
    result["admitted_addresses"] = list(addresses) if encode else addresses
    return result


def _transform_result(action: str, value: object, *, encode: bool) -> JsonObject:
    if action == "broker.ready":
        source = _exact_object(value, frozenset({"schema", "ready"}))
        if source["schema"] != 1 or source["ready"] is not True:
            raise ShareBrokerProtocolError
        return {"schema": 1, "ready": True}
    if action.startswith("credential."):
        source = _exact_object(
            value, frozenset({"share_id", "generation", "configured"})
        )
        try:
            share_id = normalize_share_id(source["share_id"])
        except (ShareValidationError, TypeError):
            raise ShareBrokerProtocolError from None
        configured = source["configured"]
        if type(configured) is not bool:
            raise ShareBrokerProtocolError
        return {
            "share_id": share_id,
            "generation": _integer(
                source["generation"],
                minimum=0 if action == "credential.inspect" else 1,
            ),
            "configured": configured,
        }
    if action == "mount.fence":
        source = _exact_object(value, frozenset({"fenced_count"}))
        return {"fenced_count": _integer(source["fenced_count"], minimum=0)}
    source = _exact_object(value, frozenset({"receipt"}))
    receipt = source["receipt"]
    if encode:
        if type(receipt) is not ShareMountReceiptV1:
            raise ShareBrokerProtocolError
        return {"receipt": _encode_receipt(receipt)}
    return {"receipt": _receipt_from_mapping(receipt, None)}


def _receipt_unsigned(**fields: object) -> JsonObject:
    action = fields["action"]
    if action not in {"mount.start", "mount.stop", "mount.inspect"}:
        raise ShareBrokerProtocolError
    try:
        share_id = normalize_share_id(fields["share_id"])
        safe_error = validate_share_safe_error_code(fields["safe_error_code"])
    except (ShareValidationError, TypeError):
        raise ShareBrokerProtocolError from None
    request_sha256 = _digest(fields["request_sha256"])
    mount_digest = fields["mount_identity_sha256"]
    if mount_digest is not None:
        mount_digest = _digest(mount_digest)
    unit_name = fields["unit_name"]
    if (
        type(unit_name) is not str
        or not unit_name.endswith(".mount")
        or not unit_name.isascii()
        or "/" in unit_name
        or ".." in unit_name
        or len(unit_name) > 255
    ):
        raise ShareBrokerProtocolError
    read_only = fields["read_only"]
    if type(read_only) is not bool:
        raise ShareBrokerProtocolError
    result = fields["result"]
    if result not in {"mounted", "unmounted", "failed"}:
        raise ShareBrokerProtocolError
    if result == "mounted" and (
        not read_only or mount_digest is None or safe_error is not None
    ):
        raise ShareBrokerProtocolError
    if result == "unmounted" and (
        read_only or mount_digest is not None or safe_error is not None
    ):
        raise ShareBrokerProtocolError
    if result == "failed" and safe_error is None:
        raise ShareBrokerProtocolError
    endpoint_server = fields["endpoint_server"]
    if endpoint_server is not None:
        try:
            endpoint_server = normalize_server(endpoint_server)
        except (ShareValidationError, TypeError):
            raise ShareBrokerProtocolError from None
    admitted_addresses = _admitted_addresses(
        fields["admitted_addresses"], allow_empty=True
    )
    filesystem_type = fields["filesystem_type"]
    if filesystem_type not in {None, "nfs", "nfs4", "cifs"}:
        raise ShareBrokerProtocolError
    source_sha256 = fields["source_sha256"]
    if source_sha256 is not None:
        source_sha256 = _digest(source_sha256)
    if result == "mounted" and (
        endpoint_server is None
        or not admitted_addresses
        or filesystem_type is None
        or source_sha256 is None
    ):
        raise ShareBrokerProtocolError
    if result != "mounted" and (
        filesystem_type is not None or source_sha256 is not None
    ):
        raise ShareBrokerProtocolError
    raw_nonce = fields["broker_nonce"]
    if type(raw_nonce) is str:
        raw_nonce = _decode_opaque(raw_nonce)
    return {
        "schema": PROTOCOL_VERSION,
        "action": action,
        "share_id": share_id,
        "request_sha256": request_sha256,
        "config_revision": _integer(fields["config_revision"], minimum=1),
        "credential_generation": _integer(fields["credential_generation"], minimum=0),
        "unit_name": unit_name,
        "mount_identity_sha256": mount_digest,
        "read_only": read_only,
        "result": result,
        "safe_error_code": safe_error,
        "broker_nonce": _encode_opaque(raw_nonce),
        "endpoint_server": endpoint_server,
        "admitted_addresses": list(admitted_addresses),
        "filesystem_type": filesystem_type,
        "source_sha256": source_sha256,
    }


def _encode_receipt(receipt: ShareMountReceiptV1) -> JsonObject:
    return {
        "schema": receipt.schema,
        "action": receipt.action,
        "share_id": receipt.share_id,
        "request_sha256": receipt.request_sha256,
        "config_revision": receipt.config_revision,
        "credential_generation": receipt.credential_generation,
        "unit_name": receipt.unit_name,
        "mount_identity_sha256": receipt.mount_identity_sha256,
        "read_only": receipt.read_only,
        "result": receipt.result,
        "safe_error_code": receipt.safe_error_code,
        "broker_nonce": _encode_opaque(receipt.broker_nonce),
        "broker_proof": _encode_opaque(receipt.broker_proof),
        "endpoint_server": receipt.endpoint_server,
        "admitted_addresses": list(receipt.admitted_addresses),
        "filesystem_type": receipt.filesystem_type,
        "source_sha256": receipt.source_sha256,
    }


def _receipt_from_mapping(
    value: object, proof_key: bytes | None
) -> ShareMountReceiptV1:
    source = _exact_object(value, _RECEIPT_KEYS)
    if _integer(source["schema"], minimum=1) != PROTOCOL_VERSION:
        raise ShareBrokerProtocolError
    unsigned = _receipt_unsigned(
        **{
            key: source[key]
            for key in _RECEIPT_KEYS
            if key not in {"schema", "broker_proof"}
        }
    )
    proof = _decode_opaque(source["broker_proof"])
    if proof_key is not None:
        expected = hmac.new(
            _proof_key(proof_key),
            b"lto-share-mount-receipt-v1\0" + _canonical_json(unsigned),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(proof, expected):
            raise ShareBrokerProtocolError
    return ShareMountReceiptV1(
        schema=PROTOCOL_VERSION,
        action=unsigned["action"],
        share_id=unsigned["share_id"],
        request_sha256=unsigned["request_sha256"],
        config_revision=unsigned["config_revision"],
        credential_generation=unsigned["credential_generation"],
        unit_name=unsigned["unit_name"],
        mount_identity_sha256=unsigned["mount_identity_sha256"],
        read_only=unsigned["read_only"],
        result=unsigned["result"],
        safe_error_code=unsigned["safe_error_code"],
        broker_nonce=_decode_opaque(unsigned["broker_nonce"]),
        broker_proof=proof,
        endpoint_server=unsigned["endpoint_server"],
        admitted_addresses=tuple(unsigned["admitted_addresses"]),
        filesystem_type=unsigned["filesystem_type"],
        source_sha256=unsigned["source_sha256"],
    )


def _admitted_addresses(value: object, *, allow_empty: bool = False) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or len(value) > 16
        or (not value and not allow_empty)
    ):
        raise ShareBrokerProtocolError
    normalized: list[str] = []
    for candidate in value:
        if type(candidate) is not str:
            raise ShareBrokerProtocolError
        try:
            normalized.append(str(ipaddress.ip_address(candidate)))
        except ValueError:
            raise ShareBrokerProtocolError from None
    if len(set(normalized)) != len(normalized):
        raise ShareBrokerProtocolError
    return tuple(sorted(normalized))


def _known_share_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > 1024:
        raise ShareBrokerProtocolError
    normalized: list[str] = []
    for candidate in value:
        try:
            normalized.append(normalize_share_id(candidate))
        except (ShareValidationError, TypeError):
            raise ShareBrokerProtocolError from None
    if len(set(normalized)) != len(normalized):
        raise ShareBrokerProtocolError
    return tuple(sorted(normalized))


def _parse_frame(payload: bytes) -> JsonObject:
    if (
        type(payload) is not bytes
        or len(payload) < 6
        or len(payload) > MAX_FRAME_BYTES + 4
    ):
        raise ShareBrokerProtocolError
    size = struct.unpack(">I", payload[:4])[0]
    body = payload[4:]
    if size != len(body) or size > MAX_FRAME_BYTES:
        raise ShareBrokerProtocolError
    try:
        value = json.loads(body, object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey, TypeError):
        raise ShareBrokerProtocolError from None
    if _canonical_json(value) != body or type(value) is not dict:
        raise ShareBrokerProtocolError
    return value


def _frame(value: object) -> bytes:
    body = _canonical_json(value)
    if len(body) > MAX_FRAME_BYTES:
        raise ShareBrokerProtocolError
    return struct.pack(">I", len(body)) + body


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        raise ShareBrokerProtocolError from None


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> JsonObject:
    result: JsonObject = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey
        result[key] = value
    return result


def _exact_object(value: object, keys: frozenset[str]) -> JsonObject:
    if type(value) is not dict or frozenset(value) != keys:
        raise ShareBrokerProtocolError
    return value


def _action(value: object) -> str:
    if type(value) is not str or value not in _ACTIONS:
        raise ShareBrokerProtocolError
    return value


def _integer(value: object, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value < 1 << 63:
        raise ShareBrokerProtocolError
    return value


def _bounded_secret_field(value: object, maximum: int, *, empty: bool) -> str | None:
    if value is None and empty:
        return None
    if type(value) is not str or len(value) > maximum or (not value and not empty):
        raise ShareBrokerProtocolError
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ShareBrokerProtocolError
    return value or None


def _capability(value: object) -> bytes:
    if type(value) is not bytes or len(value) != _OPAQUE_BYTES:
        raise ShareBrokerProtocolError
    return value


def _proof_key(value: object) -> bytes:
    return _capability(value)


def _encode_opaque(value: object) -> str:
    if type(value) is not bytes or len(value) != _OPAQUE_BYTES:
        raise ShareBrokerProtocolError
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_opaque(value: object) -> bytes:
    if type(value) is not str or len(value) != 43 or not value.isascii():
        raise ShareBrokerProtocolError
    try:
        decoded = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except (ValueError, binascii.Error):
        raise ShareBrokerProtocolError from None
    if len(decoded) != _OPAQUE_BYTES or _encode_opaque(decoded) != value:
        raise ShareBrokerProtocolError
    return decoded


def _digest(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ShareBrokerProtocolError
    return value
