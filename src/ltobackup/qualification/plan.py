"""Canonical label-bound authorization plans for manual LTFS qualification."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum

_PLAN_KEYS = frozenset(
    {
        "schema",
        "run_id",
        "job_id",
        "cassette_sequence",
        "physical_label",
        "tape_serial",
        "drive_serial",
        "drive_wwid",
        "linux_tree_sha256",
        "ltfs_tree_sha256",
        "ltfs_rpm_sha256",
        "issued_at_ns",
        "expires_at_ns",
        "operations",
    }
)
_MAX_PLAN_LIFETIME_NS = 24 * 60 * 60 * 1_000_000_000
_AUTH_DOMAIN = b"lto-archiver/ltfs-qualification/v1\x00"


def _closed_plan_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise QualificationRefused("qualification plan contains duplicate fields")
        result[key] = value
    return result


class QualificationRefused(ValueError):
    pass


class QualificationOperation(StrEnum):
    READ_ONLY = "read_only"
    ADDITIVE_WRITE = "additive_write"
    FORMAT = "format"
    OVERWRITE = "overwrite"
    REPAIR = "repair"
    WIPE = "wipe"
    LONG_WIPE = "long_wipe"
    UNLOAD = "unload"
    LOAD = "load"
    EJECT = "eject"


SUPPORTED_QUALIFICATION_OPERATIONS = frozenset(
    {
        QualificationOperation.READ_ONLY,
        QualificationOperation.ADDITIVE_WRITE,
        QualificationOperation.FORMAT,
        QualificationOperation.OVERWRITE,
        QualificationOperation.REPAIR,
        QualificationOperation.WIPE,
        QualificationOperation.UNLOAD,
        QualificationOperation.LOAD,
        QualificationOperation.EJECT,
    }
)


def qualification_success_exit_codes(
    operation: QualificationOperation,
) -> frozenset[int]:
    """Return the closed success contract shared by every qualification layer."""
    operation = _operation(operation)
    if operation is QualificationOperation.WIPE:
        return frozenset({1})
    if operation is QualificationOperation.REPAIR:
        return frozenset({0, 1})
    return frozenset({0})


def qualification_authorization_payload(
    *,
    plan_sha256: str,
    run_id: str,
    physical_label: str,
    operation: QualificationOperation,
) -> bytes:
    _sha256(plan_sha256, "plan digest")
    _uuid4(run_id)
    _text(physical_label, "physical label")
    operation = _operation(operation)
    encoded = json.dumps(
        {
            "operation": operation.value,
            "physical_label": physical_label,
            "plan_sha256": plan_sha256,
            "run_id": run_id,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return _AUTH_DOMAIN + encoded


def _text(value: object, purpose: str, *, maximum: int = 255) -> str:
    if (
        type(value) is not str
        or not value
        or len(value.encode("utf-8")) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise QualificationRefused(f"{purpose} is invalid")
    return value


def _sha256(value: object, purpose: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise QualificationRefused(f"{purpose} is invalid")
    return value


def _mam_medium_serial(value: object) -> str:
    if (
        type(value) is not str
        or not 0 < len(value) <= 255
        or not value.isascii()
        or not value.isprintable()
        or value.strip() != value
    ):
        raise QualificationRefused("expected MAM medium serial is invalid")
    return value


def _uuid4(value: object) -> str:
    if type(value) is not str:
        raise QualificationRefused("run id is invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise QualificationRefused("run id is invalid") from None
    if parsed.version != 4 or str(parsed) != value:
        raise QualificationRefused("run id is invalid")
    return value


def _operation(value: object) -> QualificationOperation:
    operation = None
    if type(value) is QualificationOperation:
        operation = value
    elif type(value) is str:
        try:
            operation = QualificationOperation(value)
        except ValueError:
            pass
    if operation is QualificationOperation.LONG_WIPE:
        raise QualificationRefused("qualification operation is unsupported")
    if operation in SUPPORTED_QUALIFICATION_OPERATIONS:
        return operation
    raise QualificationRefused("qualification operation is invalid")


@dataclass(frozen=True, slots=True)
class QualificationPlan:
    schema: int
    run_id: str
    job_id: str
    cassette_sequence: int
    physical_label: str
    tape_serial: str
    drive_serial: str
    drive_wwid: str
    linux_tree_sha256: str
    ltfs_tree_sha256: str
    ltfs_rpm_sha256: str
    issued_at_ns: int
    expires_at_ns: int
    operations: tuple[QualificationOperation, ...]
    expected_mam_medium_serial: str | None = None

    def __post_init__(self) -> None:
        if type(self.schema) is not int or self.schema not in (1, 2):
            raise QualificationRefused("qualification plan schema is unsupported")
        if self.schema == 2:
            _mam_medium_serial(self.expected_mam_medium_serial)
        elif self.expected_mam_medium_serial is not None:
            raise QualificationRefused(
                "legacy qualification plan cannot carry a MAM pin"
            )
        _uuid4(self.run_id)
        _text(self.job_id, "job id", maximum=1024)
        if (
            type(self.cassette_sequence) is not int
            or not 1 <= self.cassette_sequence <= 20
        ):
            raise QualificationRefused("cassette sequence is invalid")
        _text(self.physical_label, "physical label")
        _text(self.tape_serial, "tape serial")
        _text(self.drive_serial, "drive serial")
        _text(self.drive_wwid, "drive WWID")
        _sha256(self.linux_tree_sha256, "Linux tree digest")
        _sha256(self.ltfs_tree_sha256, "LTFS tree digest")
        _sha256(self.ltfs_rpm_sha256, "LTFS RPM digest")
        if (
            type(self.issued_at_ns) is not int
            or type(self.expires_at_ns) is not int
            or self.issued_at_ns < 0
            or self.expires_at_ns <= self.issued_at_ns
            or self.expires_at_ns - self.issued_at_ns > _MAX_PLAN_LIFETIME_NS
        ):
            raise QualificationRefused("qualification plan lifetime is invalid")
        if (
            type(self.operations) is not tuple
            or not self.operations
            or any(type(item) is not QualificationOperation for item in self.operations)
            or len(self.operations) != len(set(self.operations))
        ):
            raise QualificationRefused("qualification operations are invalid")
        if any(
            operation not in SUPPORTED_QUALIFICATION_OPERATIONS
            for operation in self.operations
        ):
            raise QualificationRefused("qualification operation is unsupported")
        object.__setattr__(
            self,
            "operations",
            tuple(sorted(self.operations, key=lambda item: item.value)),
        )

    def canonical_bytes(self) -> bytes:
        payload = {
            "schema": self.schema,
            "run_id": self.run_id,
            "job_id": self.job_id,
            "cassette_sequence": self.cassette_sequence,
            "physical_label": self.physical_label,
            "tape_serial": self.tape_serial,
            "drive_serial": self.drive_serial,
            "drive_wwid": self.drive_wwid,
            "linux_tree_sha256": self.linux_tree_sha256,
            "ltfs_tree_sha256": self.ltfs_tree_sha256,
            "ltfs_rpm_sha256": self.ltfs_rpm_sha256,
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "operations": sorted(item.value for item in self.operations),
        }
        if self.schema == 2:
            payload["expected_mam_medium_serial"] = self.expected_mam_medium_serial
        return json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @property
    def plan_sha256(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()

    def authorize(self, operation: QualificationOperation, credential: bytes) -> str:
        operation = _operation(operation)
        if operation is QualificationOperation.FORMAT and self.schema != 2:
            raise QualificationRefused(
                "format authorization requires an explicit MAM medium serial"
            )
        if operation not in self.operations:
            raise QualificationRefused("qualification operation is not planned")
        key = self._credential(credential)
        message = qualification_authorization_payload(
            plan_sha256=self.plan_sha256,
            run_id=self.run_id,
            physical_label=self.physical_label,
            operation=operation,
        )
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def verify_token(
        self,
        operation: QualificationOperation,
        token: str,
        credential: bytes,
        *,
        now_ns: int,
    ) -> None:
        operation = _operation(operation)
        if operation not in self.operations:
            raise QualificationRefused("qualification operation is not planned")
        if type(now_ns) is not int or now_ns < self.issued_at_ns:
            raise QualificationRefused("qualification plan is not active")
        if now_ns > self.expires_at_ns:
            raise QualificationRefused("qualification plan is expired")
        if (
            type(token) is not str
            or len(token) != 64
            or any(character not in "0123456789abcdef" for character in token)
        ):
            raise QualificationRefused("qualification token is invalid")
        expected = self.authorize(operation, credential)
        if not hmac.compare_digest(token, expected):
            raise QualificationRefused("qualification token does not match the plan")

    @staticmethod
    def _credential(value: object) -> bytes:
        if type(value) is not bytes or len(value) != 32:
            raise QualificationRefused("qualification credential is invalid")
        return value

    @classmethod
    def from_bytes(cls, raw: bytes) -> QualificationPlan:
        if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
            raise QualificationRefused("qualification plan payload is invalid")
        try:
            value = json.loads(
                raw.decode("utf-8"), object_pairs_hook=_closed_plan_pairs
            )
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise QualificationRefused(
                "qualification plan payload is invalid"
            ) from None
        if type(value) is not dict or set(value) != (
            _PLAN_KEYS | {"expected_mam_medium_serial"}
            if value.get("schema") == 2
            else _PLAN_KEYS
        ):
            raise QualificationRefused("qualification plan schema is not closed")
        operations = value["operations"]
        if type(operations) is not list:
            raise QualificationRefused("qualification operations are invalid")
        try:
            parsed_operations = tuple(_operation(item) for item in operations)
            return cls(
                schema=value["schema"],
                run_id=value["run_id"],
                job_id=value["job_id"],
                cassette_sequence=value["cassette_sequence"],
                physical_label=value["physical_label"],
                tape_serial=value["tape_serial"],
                drive_serial=value["drive_serial"],
                drive_wwid=value["drive_wwid"],
                linux_tree_sha256=value["linux_tree_sha256"],
                ltfs_tree_sha256=value["ltfs_tree_sha256"],
                ltfs_rpm_sha256=value["ltfs_rpm_sha256"],
                issued_at_ns=value["issued_at_ns"],
                expires_at_ns=value["expires_at_ns"],
                operations=parsed_operations,
                expected_mam_medium_serial=value.get("expected_mam_medium_serial"),
            )
        except KeyError:
            raise QualificationRefused(
                "qualification plan schema is not closed"
            ) from None

    @classmethod
    def from_catalog(
        cls,
        cassette: Mapping[str, object],
        *,
        run_id: str,
        drive_serial: str,
        drive_wwid: str,
        linux_tree_sha256: str,
        ltfs_tree_sha256: str,
        ltfs_rpm_sha256: str,
        issued_at_ns: int,
        expires_at_ns: int,
        operations: tuple[QualificationOperation, ...],
        expected_physical_label: str | None = None,
        expected_mam_medium_serial: str | None = None,
    ) -> QualificationPlan:
        try:
            physical_label = cassette["physical_label"]
            if (
                expected_physical_label is not None
                and physical_label != expected_physical_label
            ):
                raise QualificationRefused("catalog physical label mismatch")
            return cls(
                schema=1 if expected_mam_medium_serial is None else 2,
                run_id=run_id,
                job_id=cassette["job_id"],
                cassette_sequence=cassette["sequence"],
                physical_label=physical_label,
                tape_serial=cassette["tape_serial"],
                drive_serial=drive_serial,
                drive_wwid=drive_wwid,
                linux_tree_sha256=linux_tree_sha256,
                ltfs_tree_sha256=ltfs_tree_sha256,
                ltfs_rpm_sha256=ltfs_rpm_sha256,
                issued_at_ns=issued_at_ns,
                expires_at_ns=expires_at_ns,
                operations=operations,
                expected_mam_medium_serial=expected_mam_medium_serial,
            )
        except KeyError:
            raise QualificationRefused(
                "catalog cassette record is incomplete"
            ) from None
