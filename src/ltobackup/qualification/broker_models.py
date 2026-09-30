"""Typed broker wire models for one LTFS qualification stage."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

from .plan import (
    SUPPORTED_QUALIFICATION_OPERATIONS,
    QualificationOperation,
    QualificationPlan,
    QualificationRefused,
    qualification_success_exit_codes,
)

_REQUEST_DOMAIN = b"lto-archiver/broker-ltfs-qualification-request/v1\x00"
_AUTHORIZATION_DOMAIN = b"lto-archiver/broker-ltfs-qualification-authorization/v2\x00"
_DISPATCH_STATES = frozenset({"pre_dispatch", "dispatched", "terminal", "fenced"})
_DISPATCH_PROOF_DOMAIN = b"lto-archiver/broker-ltfs-qualification-dispatch/v1\x00"
_INSPECTION_PROOF_DOMAIN = b"lto-archiver/broker-ltfs-qualification-inspection/v1\x00"
_MAX_AUTHORIZATION_LIFETIME_NS = 24 * 60 * 60 * 1_000_000_000
_INSPECTION_STATES = frozenset(
    {"missing", "pre_dispatch", "dispatched", "terminal", "fenced"}
)
_DURABLE_STATES = frozenset({"PREPARED", "DISPATCHED", "TERMINAL", "FENCED"})
_INSPECTION_SNAPSHOT_KEYS = frozenset(
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


@dataclass(frozen=True, slots=True)
class BrokerQualificationRequest:
    protocol_version: int
    run_id: str
    plan_sha256: str
    stage_ordinal: int
    operation: QualificationOperation
    operation_token: str
    tape_device_identity_sha256: str
    scsi_device_identity_sha256: str
    expected_media_scope_sha256: str
    observed_media_identity_sha256: str
    expected_physical_label: str
    expected_tape_serial: str
    expected_drive_serial: str
    expected_drive_wwid: str
    expected_volume_uuid: str | None
    expected_generation: int | None
    issued_at_ns: int
    expires_at_ns: int
    request_nonce: bytes
    canonical_plan_json: str | None = None

    def __post_init__(self) -> None:
        if type(self.protocol_version) is not int or self.protocol_version not in (
            1,
            2,
        ):
            raise QualificationRefused("broker qualification protocol is unsupported")
        _uuid4(self.run_id, "run id")
        for value, purpose in (
            (self.plan_sha256, "plan"),
            (self.operation_token, "operation token"),
            (self.tape_device_identity_sha256, "tape device identity"),
            (self.scsi_device_identity_sha256, "SCSI device identity"),
            (self.expected_media_scope_sha256, "expected media scope"),
            (self.observed_media_identity_sha256, "observed media identity"),
        ):
            _digest(value, purpose)
        if type(self.stage_ordinal) is not int or self.stage_ordinal < 1:
            raise QualificationRefused("broker qualification stage is invalid")
        if (
            type(self.operation) is not QualificationOperation
            or self.operation not in SUPPORTED_QUALIFICATION_OPERATIONS
        ):
            raise QualificationRefused("broker qualification operation is invalid")
        _text(self.expected_physical_label, "physical label")
        _text(self.expected_tape_serial, "tape serial")
        _text(self.expected_drive_serial, "drive serial")
        _text(self.expected_drive_wwid, "drive WWID")
        if (self.expected_volume_uuid is None) != (self.expected_generation is None):
            raise QualificationRefused("broker qualification media state is incomplete")
        if self.expected_volume_uuid is not None:
            _canonical_uuid(self.expected_volume_uuid, "volume UUID")
            if (
                type(self.expected_generation) is not int
                or not 0 <= self.expected_generation < 1 << 64
            ):
                raise QualificationRefused("broker qualification generation is invalid")
        if (
            type(self.issued_at_ns) is not int
            or type(self.expires_at_ns) is not int
            or self.issued_at_ns < 0
            or self.expires_at_ns <= self.issued_at_ns
            or self.expires_at_ns - self.issued_at_ns > _MAX_AUTHORIZATION_LIFETIME_NS
        ):
            raise QualificationRefused(
                "broker qualification authorization lifetime is invalid"
            )
        if type(self.request_nonce) is not bytes or len(self.request_nonce) != 32:
            raise QualificationRefused("broker qualification request nonce is invalid")
        if self.tape_device_identity_sha256 == self.scsi_device_identity_sha256:
            raise QualificationRefused("broker qualification device identities collide")
        if self.protocol_version == 1:
            if self.canonical_plan_json is not None:
                raise QualificationRefused(
                    "legacy qualification request cannot embed a plan"
                )
        else:
            if type(self.canonical_plan_json) is not str:
                raise QualificationRefused("canonical qualification plan is required")
            plan = QualificationPlan.from_bytes(
                self.canonical_plan_json.encode("utf-8")
            )
            if (
                plan.schema != 2
                or plan.canonical_bytes().decode("utf-8") != self.canonical_plan_json
                or plan.plan_sha256 != self.plan_sha256
                or plan.run_id != self.run_id
                or plan.physical_label != self.expected_physical_label
                or plan.tape_serial != self.expected_tape_serial
                or plan.drive_serial != self.expected_drive_serial
                or plan.drive_wwid != self.expected_drive_wwid
                or self.operation not in plan.operations
                or plan.issued_at_ns != self.issued_at_ns
                or plan.expires_at_ns != self.expires_at_ns
            ):
                raise QualificationRefused(
                    "embedded qualification plan does not match request authority"
                )

    @property
    def expected_mam_medium_serial(self) -> str | None:
        if self.canonical_plan_json is None:
            return None
        return QualificationPlan.from_bytes(
            self.canonical_plan_json.encode("utf-8")
        ).expected_mam_medium_serial

    def require_execution_authority(self) -> None:
        if (
            self.operation is QualificationOperation.FORMAT
            and self.protocol_version != 2
        ):
            raise QualificationRefused(
                "format execution requires an explicit MAM medium serial"
            )

    @property
    def request_sha256(self) -> str:
        payload = {
            "expected_generation": self.expected_generation,
            "expected_drive_serial": self.expected_drive_serial,
            "expected_drive_wwid": self.expected_drive_wwid,
            "expected_media_scope_sha256": self.expected_media_scope_sha256,
            "expected_physical_label": self.expected_physical_label,
            "expected_tape_serial": self.expected_tape_serial,
            "expected_volume_uuid": self.expected_volume_uuid,
            "expires_at_ns": self.expires_at_ns,
            "issued_at_ns": self.issued_at_ns,
            "observed_media_identity_sha256": self.observed_media_identity_sha256,
            "operation": self.operation.value,
            "operation_token": self.operation_token,
            "plan_sha256": self.plan_sha256,
            "protocol_version": self.protocol_version,
            "request_nonce": base64.b64encode(self.request_nonce).decode("ascii"),
            "run_id": self.run_id,
            "scsi_device_identity_sha256": self.scsi_device_identity_sha256,
            "stage_ordinal": self.stage_ordinal,
            "tape_device_identity_sha256": self.tape_device_identity_sha256,
        }
        if self.protocol_version == 2:
            payload["canonical_plan_json"] = self.canonical_plan_json
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(_REQUEST_DOMAIN + encoded).hexdigest()


def qualification_request_authorization_payload(
    request: BrokerQualificationRequest,
) -> bytes:
    """Return the exact stage authority; the token itself is intentionally excluded."""

    if type(request) is not BrokerQualificationRequest:
        raise QualificationRefused("exact broker qualification request required")
    if request.operation not in SUPPORTED_QUALIFICATION_OPERATIONS:
        raise QualificationRefused("broker qualification operation is invalid")
    payload = {
        "expected_generation": request.expected_generation,
        "expected_drive_serial": request.expected_drive_serial,
        "expected_drive_wwid": request.expected_drive_wwid,
        "expected_media_scope_sha256": request.expected_media_scope_sha256,
        "expected_physical_label": request.expected_physical_label,
        "expected_tape_serial": request.expected_tape_serial,
        "expected_volume_uuid": request.expected_volume_uuid,
        "expires_at_ns": request.expires_at_ns,
        "issued_at_ns": request.issued_at_ns,
        "observed_media_identity_sha256": request.observed_media_identity_sha256,
        "operation": request.operation.value,
        "plan_sha256": request.plan_sha256,
        "protocol_version": request.protocol_version,
        "request_nonce": base64.b64encode(request.request_nonce).decode("ascii"),
        "run_id": request.run_id,
        "scsi_device_identity_sha256": request.scsi_device_identity_sha256,
        "stage_ordinal": request.stage_ordinal,
        "tape_device_identity_sha256": request.tape_device_identity_sha256,
    }
    if request.protocol_version == 2:
        payload["canonical_plan_json"] = request.canonical_plan_json
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _AUTHORIZATION_DOMAIN + encoded


def qualification_request_operation_token(
    request: BrokerQualificationRequest, credential: bytes
) -> str:
    if type(credential) is not bytes or len(credential) != 32:
        raise QualificationRefused("qualification credential is invalid")
    request.require_execution_authority()
    return hmac.new(
        credential,
        qualification_request_authorization_payload(request),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class BrokerQualificationDispatch:
    protocol_version: int
    run_id: str
    stage_ordinal: int
    operation: QualificationOperation
    request_sha256: str
    dispatch_state: Literal["pre_dispatch", "dispatched", "terminal", "fenced"]
    terminal_receipt_sha256: str | None
    child_exit_code: int | None
    evidence_sha256: str
    broker_nonce: bytes
    broker_proof: bytes

    def __post_init__(self) -> None:
        if type(self.protocol_version) is not int or self.protocol_version != 1:
            raise QualificationRefused("broker qualification protocol is unsupported")
        _uuid4(self.run_id, "run id")
        if type(self.stage_ordinal) is not int or self.stage_ordinal < 1:
            raise QualificationRefused("broker qualification stage is invalid")
        if (
            type(self.operation) is not QualificationOperation
            or self.operation not in SUPPORTED_QUALIFICATION_OPERATIONS
        ):
            raise QualificationRefused("broker qualification operation is invalid")
        _digest(self.request_sha256, "request")
        _digest(self.evidence_sha256, "evidence")
        if self.dispatch_state not in _DISPATCH_STATES:
            raise QualificationRefused("broker qualification dispatch state is invalid")
        if type(self.broker_nonce) is not bytes or len(self.broker_nonce) != 32:
            raise QualificationRefused("broker qualification nonce is invalid")
        if type(self.broker_proof) is not bytes or len(self.broker_proof) != 32:
            raise QualificationRefused("broker qualification proof is invalid")
        if self.broker_nonce == self.broker_proof:
            raise QualificationRefused("broker qualification opaque values collide")
        if self.dispatch_state == "terminal":
            if self.terminal_receipt_sha256 is None:
                raise QualificationRefused("broker terminal receipt is missing")
            _digest(self.terminal_receipt_sha256, "terminal receipt")
            if type(self.child_exit_code) is not int:
                raise QualificationRefused("broker terminal exit code is invalid")
            accepted = qualification_success_exit_codes(self.operation)
            if self.child_exit_code not in accepted:
                raise QualificationRefused("broker terminal exit code is invalid")
        elif (
            self.terminal_receipt_sha256 is not None or self.child_exit_code is not None
        ):
            raise QualificationRefused("broker nonterminal evidence is invalid")


@dataclass(frozen=True, slots=True)
class BrokerQualificationExecution:
    terminal_receipt_sha256: str
    child_exit_code: int
    evidence_sha256: str

    def __post_init__(self) -> None:
        _digest(self.terminal_receipt_sha256, "terminal receipt")
        _digest(self.evidence_sha256, "evidence")
        if type(self.child_exit_code) is not int:
            raise QualificationRefused("broker qualification exit code is invalid")


@dataclass(frozen=True, slots=True)
class BrokerQualificationInspectionRequest:
    """A capability-authenticated, read-only qualification-stage lookup."""

    run_id: str
    stage_ordinal: int
    challenge: bytes

    def __post_init__(self) -> None:
        _uuid4(self.run_id, "run id")
        if type(self.stage_ordinal) is not int or self.stage_ordinal < 1:
            raise QualificationRefused("broker qualification stage is invalid")
        if type(self.challenge) is not bytes or len(self.challenge) != 32:
            raise QualificationRefused("broker qualification challenge is invalid")


@dataclass(frozen=True, slots=True)
class BrokerQualificationInspection:
    """A signed, immutable observation of one durable qualification stage."""

    state: Literal["missing", "pre_dispatch", "dispatched", "terminal", "fenced"]
    stage_snapshot: Mapping[str, object] | None
    dispatch: BrokerQualificationDispatch | None
    observation_nonce: bytes
    proof: bytes

    def __post_init__(self) -> None:
        if type(self.state) is not str or self.state not in _INSPECTION_STATES:
            raise QualificationRefused(
                "broker qualification inspection state is invalid"
            )
        if (
            type(self.observation_nonce) is not bytes
            or len(self.observation_nonce) != 32
        ):
            raise QualificationRefused(
                "broker qualification observation nonce is invalid"
            )
        if type(self.proof) is not bytes or len(self.proof) != 32:
            raise QualificationRefused(
                "broker qualification inspection proof is invalid"
            )
        if self.state == "missing":
            if self.stage_snapshot is not None or self.dispatch is not None:
                raise QualificationRefused(
                    "missing qualification inspection is invalid"
                )
            return
        if type(self.stage_snapshot) not in {dict, MappingProxyType}:
            raise QualificationRefused(
                "broker qualification inspection snapshot is invalid"
            )
        snapshot = _inspection_snapshot_values(self.stage_snapshot)
        expected_state = {
            "pre_dispatch": "PREPARED",
            "dispatched": "DISPATCHED",
            "terminal": "TERMINAL",
            "fenced": "FENCED",
        }[self.state]
        if snapshot["state"] != expected_state:
            raise QualificationRefused(
                "broker qualification inspection state is invalid"
            )
        if self.state == "terminal":
            if type(self.dispatch) is not BrokerQualificationDispatch:
                raise QualificationRefused("terminal qualification dispatch is missing")
            if (
                self.dispatch.run_id != snapshot["run_id"]
                or self.dispatch.stage_ordinal != snapshot["stage_ordinal"]
                or self.dispatch.operation.value != snapshot["operation"]
                or self.dispatch.request_sha256 != snapshot["request_sha256"]
                or self.dispatch.dispatch_state != "terminal"
            ):
                raise QualificationRefused("terminal qualification dispatch is invalid")
        elif self.dispatch is not None:
            raise QualificationRefused("nonterminal qualification dispatch is invalid")
        object.__setattr__(self, "stage_snapshot", MappingProxyType(snapshot))


def qualification_inspection_snapshot_payload(snapshot: Mapping[str, object]) -> bytes:
    """Return the sole canonical encoding for a durable inspection snapshot."""

    fields = _inspection_snapshot_values(snapshot)
    encoded = {
        key: (
            base64.b64encode(value).decode("ascii") if type(value) is bytes else value
        )
        for key, value in fields.items()
    }
    return json.dumps(
        encoded,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def qualification_inspection_proof_payload(
    request: BrokerQualificationInspectionRequest,
    inspection: BrokerQualificationInspection,
) -> bytes:
    """Return the exact authenticated input for a stage-inspection observation."""

    if type(request) is not BrokerQualificationInspectionRequest:
        raise QualificationRefused("broker qualification inspection request is invalid")
    if type(inspection) is not BrokerQualificationInspection:
        raise QualificationRefused("broker qualification inspection is invalid")
    snapshot = (
        None
        if inspection.stage_snapshot is None
        else json.loads(
            qualification_inspection_snapshot_payload(inspection.stage_snapshot)
        )
    )
    dispatch = (
        None
        if inspection.dispatch is None
        else {
            "protocol_version": inspection.dispatch.protocol_version,
            "run_id": inspection.dispatch.run_id,
            "stage_ordinal": inspection.dispatch.stage_ordinal,
            "operation": inspection.dispatch.operation.value,
            "request_sha256": inspection.dispatch.request_sha256,
            "dispatch_state": inspection.dispatch.dispatch_state,
            "terminal_receipt_sha256": inspection.dispatch.terminal_receipt_sha256,
            "child_exit_code": inspection.dispatch.child_exit_code,
            "evidence_sha256": inspection.dispatch.evidence_sha256,
            "broker_nonce": base64.b64encode(inspection.dispatch.broker_nonce).decode(
                "ascii"
            ),
            "broker_proof": base64.b64encode(inspection.dispatch.broker_proof).decode(
                "ascii"
            ),
        }
    )
    payload = {
        "protocol_version": 1,
        "method": "inspect_ltfs_qualification_stage",
        "run_id": request.run_id,
        "stage_ordinal": request.stage_ordinal,
        "challenge": base64.b64encode(request.challenge).decode("ascii"),
        "observation_nonce": base64.b64encode(inspection.observation_nonce).decode(
            "ascii"
        ),
        "state": inspection.state,
        "stage_snapshot": snapshot,
        "dispatch": dispatch,
    }
    return _INSPECTION_PROOF_DOMAIN + json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def qualification_dispatch_proof_payload(
    dispatch: BrokerQualificationDispatch,
) -> bytes:
    if type(dispatch) is not BrokerQualificationDispatch:
        raise QualificationRefused("broker qualification dispatch is invalid")
    payload = {
        "broker_nonce": base64.b64encode(dispatch.broker_nonce).decode("ascii"),
        "child_exit_code": dispatch.child_exit_code,
        "dispatch_state": dispatch.dispatch_state,
        "evidence_sha256": dispatch.evidence_sha256,
        "operation": dispatch.operation.value,
        "protocol_version": dispatch.protocol_version,
        "request_sha256": dispatch.request_sha256,
        "run_id": dispatch.run_id,
        "stage_ordinal": dispatch.stage_ordinal,
        "terminal_receipt_sha256": dispatch.terminal_receipt_sha256,
    }
    return _DISPATCH_PROOF_DOMAIN + json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _inspection_snapshot_values(snapshot: Mapping[str, object]) -> dict[str, object]:
    if not isinstance(snapshot, Mapping) or set(snapshot) != _INSPECTION_SNAPSHOT_KEYS:
        raise QualificationRefused(
            "broker qualification inspection snapshot is invalid"
        )
    try:
        operation = QualificationOperation(snapshot["operation"])
    except (TypeError, ValueError):
        raise QualificationRefused(
            "broker qualification inspection operation is invalid"
        ) from None
    if operation not in SUPPORTED_QUALIFICATION_OPERATIONS:
        raise QualificationRefused(
            "broker qualification inspection operation is invalid"
        )
    state = snapshot["state"]
    if type(state) is not str or state not in _DURABLE_STATES:
        raise QualificationRefused("broker qualification durable state is invalid")
    _uuid4(snapshot["run_id"], "run id")
    _canonical_uuid(snapshot["boot_id"], "boot id")
    for key, purpose in (
        ("request_sha256", "request"),
        ("immutable_sha256", "immutable"),
        ("plan_sha256", "plan"),
        ("operation_token_sha256", "operation token"),
        ("tape_device_identity_sha256", "tape device identity"),
        ("scsi_device_identity_sha256", "SCSI device identity"),
        ("expected_media_scope_sha256", "expected media scope"),
        ("observed_media_identity_sha256", "observed media identity"),
    ):
        _digest(snapshot[key], purpose)
    for key, purpose in (
        ("expected_physical_label", "physical label"),
        ("expected_tape_serial", "tape serial"),
        ("expected_drive_serial", "drive serial"),
        ("expected_drive_wwid", "drive WWID"),
        ("created_at", "created timestamp"),
    ):
        _text(snapshot[key], purpose)
    volume_uuid = snapshot["expected_volume_uuid"]
    generation = snapshot["expected_generation"]
    if (volume_uuid is None) != (generation is None):
        raise QualificationRefused(
            "broker qualification inspection media state is invalid"
        )
    if volume_uuid is not None:
        _canonical_uuid(volume_uuid, "volume UUID")
        if type(generation) is not int or not 0 <= generation < 1 << 64:
            raise QualificationRefused(
                "broker qualification inspection generation is invalid"
            )
    request_nonce = snapshot["request_nonce"]
    if type(request_nonce) is not bytes or len(request_nonce) != 32:
        raise QualificationRefused(
            "broker qualification inspection request nonce is invalid"
        )
    dispatched_at = snapshot["dispatched_at"]
    terminal_at = snapshot["terminal_at"]
    if dispatched_at is not None:
        _text(dispatched_at, "dispatched timestamp")
    if terminal_at is not None:
        _text(terminal_at, "terminal timestamp")
    if (
        (state == "PREPARED" and (dispatched_at is not None or terminal_at is not None))
        or (
            state == "DISPATCHED" and (dispatched_at is None or terminal_at is not None)
        )
        or (state == "TERMINAL" and (dispatched_at is None or terminal_at is None))
        or (state == "FENCED" and terminal_at is None)
    ):
        raise QualificationRefused(
            "broker qualification inspection timestamps are invalid"
        )
    return {
        "run_id": snapshot["run_id"],
        "stage_ordinal": _positive_ordinal(snapshot["stage_ordinal"]),
        "state": state,
        "boot_id": snapshot["boot_id"],
        "request_sha256": snapshot["request_sha256"],
        "immutable_sha256": snapshot["immutable_sha256"],
        "plan_sha256": snapshot["plan_sha256"],
        "operation": operation.value,
        "operation_token_sha256": snapshot["operation_token_sha256"],
        "tape_device_identity_sha256": snapshot["tape_device_identity_sha256"],
        "scsi_device_identity_sha256": snapshot["scsi_device_identity_sha256"],
        "expected_media_scope_sha256": snapshot["expected_media_scope_sha256"],
        "observed_media_identity_sha256": snapshot["observed_media_identity_sha256"],
        "expected_physical_label": snapshot["expected_physical_label"],
        "expected_tape_serial": snapshot["expected_tape_serial"],
        "expected_drive_serial": snapshot["expected_drive_serial"],
        "expected_drive_wwid": snapshot["expected_drive_wwid"],
        "expected_volume_uuid": volume_uuid,
        "expected_generation": generation,
        "request_nonce": request_nonce,
        "created_at": snapshot["created_at"],
        "dispatched_at": dispatched_at,
        "terminal_at": terminal_at,
    }


def _positive_ordinal(value: object) -> int:
    if type(value) is not int or value < 1:
        raise QualificationRefused("broker qualification stage is invalid")
    return value


def _digest(value: object, purpose: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise QualificationRefused(f"broker qualification {purpose} digest is invalid")
    return value


def _text(value: object, purpose: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > 255
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise QualificationRefused(f"broker qualification {purpose} is invalid")
    return value


def _canonical_uuid(value: object, purpose: str) -> str:
    if type(value) is not str:
        raise QualificationRefused(f"broker qualification {purpose} is invalid")
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise QualificationRefused(
            f"broker qualification {purpose} is invalid"
        ) from None
    if str(parsed) != value:
        raise QualificationRefused(f"broker qualification {purpose} is invalid")
    return value


def _uuid4(value: object, purpose: str) -> str:
    result = _canonical_uuid(value, purpose)
    if uuid.UUID(result).version != 4:
        raise QualificationRefused(f"broker qualification {purpose} is invalid")
    return result
