from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import threading
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Self

from ltobackup.qualification.broker_models import (
    BrokerQualificationDispatch,
    BrokerQualificationRequest,
)
from ltobackup.qualification.plan import (
    QualificationOperation,
    qualification_success_exit_codes,
)
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupReleasePermit,
    BrokeredCgroupScopeReceipt,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)

SCHEMA_VERSION = 10

ScopeState = Literal["ACTIVE", "CLOSED", "BROKEN"]
PermitState = Literal["PREPARED", "RELEASE_COMMITTED", "REVOKED"]
LtfsSessionState = Literal["STARTING", "MOUNTED", "FINALIZING", "UNMOUNTED", "BROKEN"]
QualificationStageState = Literal["PREPARED", "DISPATCHED", "TERMINAL", "FENCED"]

_SCOPE_STATES = frozenset({"ACTIVE", "CLOSED", "BROKEN"})
_TERMINAL_SCOPE_STATES = frozenset({"CLOSED", "BROKEN"})
_PERMIT_STATES = frozenset({"PREPARED", "RELEASE_COMMITTED", "REVOKED"})
_TERMINAL_PERMIT_STATES = frozenset({"RELEASE_COMMITTED", "REVOKED"})
_LTFS_SESSION_STATES = frozenset(
    {"STARTING", "MOUNTED", "FINALIZING", "UNMOUNTED", "BROKEN"}
)
_ACTIVE_LTFS_SESSION_STATES = frozenset({"STARTING", "MOUNTED", "FINALIZING"})
_NONCE_DOMAINS = frozenset(
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
    }
)
_HEX_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z\Z")
_PERMIT_JSON_KEYS = frozenset(
    {
        "protocol_version",
        "command_id",
        "owner_generation",
        "scope_id",
        "scope_path_sha256",
        "scope_request_nonce",
        "scope_broker_nonce",
        "scope_broker_proof",
        "pid",
        "request_nonce",
        "permit_nonce",
        "broker_proof",
    }
)

_SCOPES_V1_SQL = """
    CREATE TABLE scopes(
        scope_id TEXT PRIMARY KEY,
        command_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        scope_path_sha256 TEXT NOT NULL,
        boot_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('ACTIVE','CLOSED','BROKEN')),
        pid INTEGER,
        process_start_ticks INTEGER,
        created_at TEXT NOT NULL,
        UNIQUE(command_id, owner_generation)
    )
    """

_SCHEMA_V1 = (
    _SCOPES_V1_SQL,
    """
    CREATE TABLE permits(
        permit_sha256 TEXT PRIMARY KEY,
        scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
        pid INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('PREPARED','RELEASE_COMMITTED','REVOKED')),
        permit_json TEXT NOT NULL,
        prepared_at TEXT NOT NULL,
        terminal_at TEXT
    )
    """,
    """
    CREATE TABLE replay_nonces(
        domain TEXT NOT NULL,
        nonce_sha256 TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        PRIMARY KEY(domain, nonce_sha256)
    )
    """,
)

_SCHEMA_V2 = (
    """
    CREATE TABLE scopes(
        scope_id TEXT PRIMARY KEY,
        command_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        scope_path_sha256 TEXT NOT NULL,
        boot_id TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('ACTIVE','CLOSED','BROKEN')),
        pid INTEGER,
        process_start_ticks INTEGER,
        created_at TEXT NOT NULL,
        UNIQUE(command_id, owner_generation)
    )
    """,
    """
    CREATE TABLE permits(
        permit_sha256 TEXT PRIMARY KEY,
        scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
        pid INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('PREPARED','RELEASE_COMMITTED','REVOKED')),
        permit_json TEXT NOT NULL,
        prepared_at TEXT NOT NULL,
        terminal_at TEXT
    )
    """,
    """
    CREATE TABLE replay_nonces(
        domain TEXT NOT NULL,
        nonce_sha256 TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        PRIMARY KEY(domain, nonce_sha256)
    )
    """,
    """
    CREATE TABLE cgroup_bindings(
        scope_id TEXT PRIMARY KEY REFERENCES scopes(scope_id),
        device INTEGER NOT NULL CHECK(device >= 0),
        inode INTEGER NOT NULL CHECK(inode > 0)
    )
    """,
)

_LTFS_SESSIONS_V3_SQL = """
    CREATE TABLE ltfs_sessions(
        operation_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('STARTING','MOUNTED','FINALIZING','UNMOUNTED','BROKEN')),
        boot_id TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        mount_path_sha256 TEXT NOT NULL,
        tape_device_identity_sha256 TEXT NOT NULL,
        scsi_device_identity_sha256 TEXT NOT NULL,
        expected_media_scope_sha256 TEXT NOT NULL,
        observed_media_identity_sha256 TEXT NOT NULL,
        tape_fd_identity_sha256 TEXT NOT NULL,
        scsi_fd_identity_sha256 TEXT NOT NULL,
        read_only INTEGER NOT NULL CHECK(read_only IN (0,1)),
        ltfs_tool_identity_sha256 TEXT NOT NULL,
        fusermount_tool_identity_sha256 TEXT NOT NULL,
        cgroup_scope_id TEXT NOT NULL,
        child_pid INTEGER,
        child_start_ticks INTEGER,
        mount_namespace_sha256 TEXT,
        start_request_nonce BLOB NOT NULL,
        session_id TEXT UNIQUE,
        session_broker_nonce BLOB,
        session_broker_proof BLOB,
        finalization_request_nonce BLOB,
        finalization_nonce BLOB,
        finalization_broker_proof BLOB,
        created_at TEXT NOT NULL,
        mounted_at TEXT,
        finalizing_at TEXT,
        terminal_at TEXT,
        PRIMARY KEY(operation_id, owner_generation)
    )
    """

_SCHEMA_V3 = (*_SCHEMA_V2, _LTFS_SESSIONS_V3_SQL)

_LTFS_SESSIONS_SQL = """
    CREATE TABLE ltfs_sessions(
        operation_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('STARTING','MOUNTED','FINALIZING','UNMOUNTED','BROKEN')),
        boot_id TEXT NOT NULL,
        request_sha256 TEXT NOT NULL,
        immutable_sha256 TEXT NOT NULL,
        mount_path_sha256 TEXT NOT NULL,
        tape_device_identity_sha256 TEXT NOT NULL,
        scsi_device_identity_sha256 TEXT NOT NULL,
        expected_media_scope_sha256 TEXT NOT NULL,
        observed_media_identity_sha256 TEXT NOT NULL,
        tape_fd_identity_sha256 TEXT NOT NULL,
        scsi_fd_identity_sha256 TEXT NOT NULL,
        read_only INTEGER NOT NULL CHECK(read_only IN (0,1)),
        ltfs_tool_identity_sha256 TEXT NOT NULL,
        fusermount_tool_identity_sha256 TEXT NOT NULL,
        cgroup_scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
        child_pid INTEGER,
        child_start_ticks INTEGER,
        mount_namespace_sha256 TEXT,
        start_request_nonce BLOB NOT NULL,
        session_id TEXT UNIQUE,
        session_broker_nonce BLOB,
        session_broker_proof BLOB,
        finalization_request_nonce BLOB,
        finalization_nonce BLOB,
        finalization_broker_proof BLOB,
        created_at TEXT NOT NULL,
        mounted_at TEXT,
        finalizing_at TEXT,
        terminal_at TEXT,
        PRIMARY KEY(operation_id, owner_generation)
    )
    """

_LTFS_SESSIONS_V5_SQL = _LTFS_SESSIONS_SQL
_LTFS_SESSIONS_SQL = _LTFS_SESSIONS_V5_SQL.replace(
    "expected_media_scope_sha256 TEXT NOT NULL,",
    "expected_media_scope_sha256 TEXT NOT NULL,\n"
    "        expected_volume_uuid TEXT,\n"
    "        expected_prior_generation INTEGER,\n"
    "        receipt_operation_uuid TEXT,\n"
    "        observed_volume_uuid TEXT,\n"
    "        observed_prior_generation INTEGER,",
).replace(
    "finalization_broker_proof BLOB,",
    "finalization_broker_proof BLOB,\n"
    "        standalone_receipt_json TEXT,\n"
    "        terminal_sha256 TEXT,\n"
    "        standalone_bound_at TEXT,",
)
_LTFS_SESSIONS_V6_SQL = _LTFS_SESSIONS_SQL
_LTFS_SESSIONS_SQL = _LTFS_SESSIONS_V6_SQL.replace(
    "observed_prior_generation INTEGER,",
    "observed_prior_generation INTEGER,\n        observed_volume_label TEXT,",
)

_LTFS_OBSERVATIONS_SQL = """
    CREATE TABLE ltfs_observations(
        operation_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        session_id TEXT NOT NULL,
        challenge BLOB NOT NULL,
        observation_nonce BLOB NOT NULL UNIQUE,
        broker_proof BLOB NOT NULL UNIQUE,
        observed_at TEXT NOT NULL,
        PRIMARY KEY(operation_id, owner_generation, challenge),
        FOREIGN KEY(operation_id, owner_generation)
            REFERENCES ltfs_sessions(operation_id, owner_generation)
    )
    """

_LTFS_CHILD_EXIT_RECEIPTS_SQL = """
    CREATE TABLE ltfs_child_exit_receipts(
        operation_id TEXT NOT NULL,
        owner_generation INTEGER NOT NULL,
        child_exit_code INTEGER NOT NULL CHECK(child_exit_code = 0),
        exit_observed_at TEXT NOT NULL,
        PRIMARY KEY(operation_id, owner_generation),
        FOREIGN KEY(operation_id, owner_generation)
            REFERENCES ltfs_sessions(operation_id, owner_generation)
    )
    """

_LTFS_QUALIFICATION_STAGES_V9_SQL = """
    CREATE TABLE ltfs_qualification_stages(
        run_id TEXT NOT NULL,
        stage_ordinal INTEGER NOT NULL CHECK(stage_ordinal > 0),
        state TEXT NOT NULL CHECK(state IN ('PREPARED','DISPATCHED','TERMINAL','FENCED')),
        boot_id TEXT NOT NULL,
        request_sha256 TEXT NOT NULL UNIQUE,
        immutable_sha256 TEXT NOT NULL,
        plan_sha256 TEXT NOT NULL,
        operation TEXT NOT NULL CHECK(operation IN ('read_only','additive_write','format','overwrite','repair','wipe','long_wipe','unload','eject')),
        operation_token_sha256 TEXT NOT NULL,
        tape_device_identity_sha256 TEXT NOT NULL,
        scsi_device_identity_sha256 TEXT NOT NULL,
        expected_media_scope_sha256 TEXT NOT NULL,
        observed_media_identity_sha256 TEXT NOT NULL,
        expected_physical_label TEXT NOT NULL,
        expected_tape_serial TEXT NOT NULL,
        expected_volume_uuid TEXT,
        expected_generation INTEGER,
        request_nonce BLOB NOT NULL UNIQUE,
        terminal_receipt_sha256 TEXT,
        child_exit_code INTEGER,
        evidence_sha256 TEXT,
        broker_nonce BLOB UNIQUE,
        broker_proof BLOB UNIQUE,
        created_at TEXT NOT NULL,
        dispatched_at TEXT,
        terminal_at TEXT,
        PRIMARY KEY(run_id, stage_ordinal)
    )
    """

_LTFS_QUALIFICATION_STAGES_SQL = _LTFS_QUALIFICATION_STAGES_V9_SQL.replace(
    "'unload','eject'", "'unload','load','eject'"
).replace(
    "expected_tape_serial TEXT NOT NULL,",
    "expected_tape_serial TEXT NOT NULL,\n"
    "        expected_drive_serial TEXT NOT NULL,\n"
    "        expected_drive_wwid TEXT NOT NULL,",
)

_SCHEMA_V7 = (*_SCHEMA_V2, _LTFS_SESSIONS_SQL, _LTFS_OBSERVATIONS_SQL)
_SCHEMA_V8 = (*_SCHEMA_V7, _LTFS_CHILD_EXIT_RECEIPTS_SQL)
_SCHEMA_V9 = (*_SCHEMA_V8, _LTFS_QUALIFICATION_STAGES_V9_SQL)
_SCHEMA = (*_SCHEMA_V8, _LTFS_QUALIFICATION_STAGES_SQL)
_SCHEMA_V4 = (*_SCHEMA_V2, _LTFS_SESSIONS_V5_SQL, _LTFS_OBSERVATIONS_SQL)
_SCHEMA_V5 = _SCHEMA_V4
_SCHEMA_V6 = (*_SCHEMA_V2, _LTFS_SESSIONS_V6_SQL, _LTFS_OBSERVATIONS_SQL)

_SCOPE_SELECT = (
    "SELECT s.scope_id,s.command_id,s.owner_generation,s.scope_path_sha256,"
    "s.boot_id,s.state,s.pid,s.process_start_ticks,b.device,b.inode,s.created_at "
    "FROM scopes AS s LEFT JOIN cgroup_bindings AS b ON b.scope_id=s.scope_id"
)

_LTFS_SESSION_SELECT = (
    "SELECT operation_id,owner_generation,state,boot_id,request_sha256,immutable_sha256,"
    "mount_path_sha256,tape_device_identity_sha256,scsi_device_identity_sha256,"
    "expected_media_scope_sha256,expected_volume_uuid,expected_prior_generation,receipt_operation_uuid,"
    "observed_volume_uuid,observed_prior_generation,observed_volume_label,"
    "observed_media_identity_sha256,"
    "tape_fd_identity_sha256,scsi_fd_identity_sha256,read_only,"
    "ltfs_tool_identity_sha256,fusermount_tool_identity_sha256,cgroup_scope_id,"
    "child_pid,child_start_ticks,mount_namespace_sha256,start_request_nonce,"
    "session_id,session_broker_nonce,session_broker_proof,"
    "finalization_request_nonce,finalization_nonce,finalization_broker_proof,"
    "standalone_receipt_json,terminal_sha256,standalone_bound_at,"
    "created_at,mounted_at,finalizing_at,terminal_at FROM ltfs_sessions"
)

_LTFS_SESSION_SELECT_V5 = (
    _LTFS_SESSION_SELECT.replace(
        "expected_volume_uuid,expected_prior_generation,receipt_operation_uuid,observed_volume_uuid,"
        "observed_prior_generation,",
        "",
    )
    .replace(
        "standalone_receipt_json,terminal_sha256,standalone_bound_at,",
        "",
    )
    .replace("observed_volume_label,", "")
)

_LTFS_SESSION_SELECT_V6 = _LTFS_SESSION_SELECT.replace("observed_volume_label,", "")

_LTFS_SESSION_SELECT_V3 = _LTFS_SESSION_SELECT_V5.replace(
    "request_sha256,immutable_sha256,", "request_sha256,"
)

_LTFS_OBSERVATION_SELECT = (
    "SELECT operation_id,owner_generation,session_id,challenge,observation_nonce,"
    "broker_proof,observed_at FROM ltfs_observations"
)

_QUALIFICATION_STAGE_SELECT = (
    "SELECT run_id,stage_ordinal,state,boot_id,request_sha256,immutable_sha256,"
    "plan_sha256,operation,operation_token_sha256,tape_device_identity_sha256,"
    "scsi_device_identity_sha256,expected_media_scope_sha256,"
    "observed_media_identity_sha256,expected_physical_label,expected_tape_serial,"
    "expected_drive_serial,expected_drive_wwid,"
    "expected_volume_uuid,expected_generation,request_nonce,"
    "terminal_receipt_sha256,child_exit_code,evidence_sha256,broker_nonce,broker_proof,"
    "created_at,dispatched_at,terminal_at FROM ltfs_qualification_stages"
)


class BrokerStateUnavailable(RuntimeError):
    """The broker state cannot be trusted or made durable."""

    code = "state.unavailable"

    def __init__(self) -> None:
        super().__init__("command broker state unavailable")


class BrokerStateConflict(RuntimeError):
    """The requested mutation contradicts durable broker state."""

    code = "scope.conflict"

    def __init__(self) -> None:
        super().__init__("command broker state conflict")


@dataclass(frozen=True)
class ScopeRecord:
    scope_id: str = field(repr=False)
    command_id: str = field(repr=False)
    owner_generation: int
    scope_path_sha256: str
    boot_id: str
    state: ScopeState
    pid: int | None
    process_start_ticks: int | None
    cgroup_device: int | None = field(repr=False)
    cgroup_inode: int | None = field(repr=False)
    created_at: str


@dataclass(frozen=True)
class PermitRecord:
    permit_sha256: str
    scope_id: str = field(repr=False)
    pid: int
    state: PermitState
    permit_json: str = field(repr=False)
    prepared_at: str
    terminal_at: str | None


@dataclass(frozen=True)
class PermitTransition:
    record: PermitRecord
    transitioned: bool


@dataclass(frozen=True)
class LtfsSessionRecord:
    operation_id: str = field(repr=False)
    owner_generation: int
    state: LtfsSessionState
    boot_id: str
    request_sha256: str
    immutable_sha256: str
    mount_path_sha256: str
    tape_device_identity_sha256: str
    scsi_device_identity_sha256: str
    expected_media_scope_sha256: str
    observed_media_identity_sha256: str
    expected_volume_uuid: str | None
    expected_prior_generation: int | None
    receipt_operation_uuid: str | None
    observed_volume_uuid: str | None
    observed_prior_generation: int | None
    observed_volume_label: str | None
    tape_fd_identity_sha256: str
    scsi_fd_identity_sha256: str
    read_only: bool
    ltfs_tool_identity_sha256: str
    fusermount_tool_identity_sha256: str
    cgroup_scope_id: str = field(repr=False)
    child_pid: int | None
    child_start_ticks: int | None
    mount_namespace_sha256: str | None
    start_request_nonce: bytes = field(repr=False)
    session_id: str | None = field(repr=False)
    session_broker_nonce: bytes | None = field(repr=False)
    session_broker_proof: bytes | None = field(repr=False)
    finalization_request_nonce: bytes | None = field(repr=False)
    finalization_nonce: bytes | None = field(repr=False)
    finalization_broker_proof: bytes | None = field(repr=False)
    standalone_receipt_json: str | None = field(repr=False)
    terminal_sha256: str | None
    standalone_bound_at: str | None
    created_at: str
    mounted_at: str | None
    finalizing_at: str | None
    terminal_at: str | None


@dataclass(frozen=True)
class LtfsSessionTransition:
    record: LtfsSessionRecord
    transitioned: bool


@dataclass(frozen=True)
class LtfsObservationRecord:
    operation_id: str = field(repr=False)
    owner_generation: int
    session_id: str = field(repr=False)
    challenge: bytes = field(repr=False)
    observation_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)
    observed_at: str


@dataclass(frozen=True)
class LtfsObservationTransition:
    record: LtfsObservationRecord
    transitioned: bool


@dataclass(frozen=True)
class QualificationStageRecord:
    run_id: str = field(repr=False)
    stage_ordinal: int
    state: QualificationStageState
    boot_id: str
    request_sha256: str
    immutable_sha256: str
    plan_sha256: str
    operation: QualificationOperation
    operation_token_sha256: str
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
    request_nonce: bytes = field(repr=False)
    terminal_receipt_sha256: str | None
    child_exit_code: int | None
    evidence_sha256: str | None
    broker_nonce: bytes | None = field(repr=False)
    broker_proof: bytes | None = field(repr=False)
    created_at: str
    dispatched_at: str | None
    terminal_at: str | None


@dataclass(frozen=True)
class QualificationStageTransition:
    record: QualificationStageRecord
    transitioned: bool


def _is_identity(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value) <= 1024
        and value.isascii()
        and value.isprintable()
        and "/" not in value
        and "\\" not in value
    )


def _is_digest(value: object) -> bool:
    return type(value) is str and _HEX_DIGEST.fullmatch(value) is not None


def _is_opaque(value: object) -> bool:
    return type(value) is bytes and 32 <= len(value) <= 4096


def _qualification_text(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and len(value.encode("utf-8")) <= 255
        and all(ord(character) >= 32 and ord(character) != 127 for character in value)
    )


def _qualification_token_sha256(token: str) -> str:
    return hashlib.sha256(
        b"lto-broker-qualification-token/v1\0" + token.encode("ascii")
    ).hexdigest()


def _qualification_immutable_sha256(values: dict[str, object]) -> str:
    encoded = json.dumps(
        values,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(b"lto-broker-qualification-store/v1\0" + encoded).hexdigest()


def _qualification_request_values(
    request: BrokerQualificationRequest,
) -> dict[str, object]:
    if type(request) is not BrokerQualificationRequest:
        raise BrokerStateConflict
    return {
        "run_id": request.run_id,
        "stage_ordinal": request.stage_ordinal,
        "request_sha256": request.request_sha256,
        "plan_sha256": request.plan_sha256,
        "operation": request.operation.value,
        "operation_token_sha256": _qualification_token_sha256(request.operation_token),
        "tape_device_identity_sha256": request.tape_device_identity_sha256,
        "scsi_device_identity_sha256": request.scsi_device_identity_sha256,
        "expected_media_scope_sha256": request.expected_media_scope_sha256,
        "observed_media_identity_sha256": request.observed_media_identity_sha256,
        "expected_physical_label": request.expected_physical_label,
        "expected_tape_serial": request.expected_tape_serial,
        "expected_drive_serial": request.expected_drive_serial,
        "expected_drive_wwid": request.expected_drive_wwid,
        "expected_volume_uuid": request.expected_volume_uuid,
        "expected_generation": request.expected_generation,
        "request_nonce": request.request_nonce.hex(),
    }


def _qualification_record_values(record: QualificationStageRecord) -> dict[str, object]:
    return {
        "run_id": record.run_id,
        "stage_ordinal": record.stage_ordinal,
        "request_sha256": record.request_sha256,
        "plan_sha256": record.plan_sha256,
        "operation": record.operation.value,
        "operation_token_sha256": record.operation_token_sha256,
        "tape_device_identity_sha256": record.tape_device_identity_sha256,
        "scsi_device_identity_sha256": record.scsi_device_identity_sha256,
        "expected_media_scope_sha256": record.expected_media_scope_sha256,
        "observed_media_identity_sha256": record.observed_media_identity_sha256,
        "expected_physical_label": record.expected_physical_label,
        "expected_tape_serial": record.expected_tape_serial,
        "expected_drive_serial": record.expected_drive_serial,
        "expected_drive_wwid": record.expected_drive_wwid,
        "expected_volume_uuid": record.expected_volume_uuid,
        "expected_generation": record.expected_generation,
        "request_nonce": record.request_nonce.hex(),
    }


def _qualification_inspection_snapshot(
    record: QualificationStageRecord,
) -> MappingProxyType[str, object]:
    """Return the closed, immutable durable view used by broker inspection."""

    return MappingProxyType(
        {
            "run_id": record.run_id,
            "stage_ordinal": record.stage_ordinal,
            "state": record.state,
            "boot_id": record.boot_id,
            "request_sha256": record.request_sha256,
            "immutable_sha256": record.immutable_sha256,
            "plan_sha256": record.plan_sha256,
            "operation": record.operation.value,
            "operation_token_sha256": record.operation_token_sha256,
            "tape_device_identity_sha256": record.tape_device_identity_sha256,
            "scsi_device_identity_sha256": record.scsi_device_identity_sha256,
            "expected_media_scope_sha256": record.expected_media_scope_sha256,
            "observed_media_identity_sha256": record.observed_media_identity_sha256,
            "expected_physical_label": record.expected_physical_label,
            "expected_tape_serial": record.expected_tape_serial,
            "expected_drive_serial": record.expected_drive_serial,
            "expected_drive_wwid": record.expected_drive_wwid,
            "expected_volume_uuid": record.expected_volume_uuid,
            "expected_generation": record.expected_generation,
            "request_nonce": record.request_nonce,
            "created_at": record.created_at,
            "dispatched_at": record.dispatched_at,
            "terminal_at": record.terminal_at,
        }
    )


def _qualification_stage_from_row(row: tuple[object, ...]) -> QualificationStageRecord:
    if len(row) != 28:
        raise BrokerStateUnavailable
    (
        run_id,
        stage_ordinal,
        state,
        boot_id,
        request_sha256,
        immutable_sha256,
        plan_sha256,
        operation,
        operation_token_sha256,
        tape_identity,
        scsi_identity,
        media_scope,
        observed_identity,
        physical_label,
        tape_serial,
        drive_serial,
        drive_wwid,
        volume_uuid,
        generation,
        request_nonce,
        terminal_receipt,
        child_exit_code,
        evidence_sha256,
        broker_nonce,
        broker_proof,
        created_at,
        dispatched_at,
        terminal_at,
    ) = row
    try:
        checked_operation = QualificationOperation(operation)
        parsed_run_id = uuid.UUID(run_id)
        parsed_volume_uuid = uuid.UUID(volume_uuid) if volume_uuid is not None else None
    except (TypeError, ValueError, AttributeError):
        raise BrokerStateUnavailable from None
    if (
        type(run_id) is not str
        or str(parsed_run_id) != run_id
        or parsed_run_id.version != 4
        or type(stage_ordinal) is not int
        or stage_ordinal < 1
        or state not in {"PREPARED", "DISPATCHED", "TERMINAL", "FENCED"}
        or _validate_boot_id(boot_id) != boot_id
        or not all(
            _is_digest(value)
            for value in (
                request_sha256,
                immutable_sha256,
                plan_sha256,
                operation_token_sha256,
                tape_identity,
                scsi_identity,
                media_scope,
                observed_identity,
            )
        )
        or not _qualification_text(physical_label)
        or not _qualification_text(tape_serial)
        or not _qualification_text(drive_serial)
        or not _qualification_text(drive_wwid)
        or (volume_uuid is None) != (generation is None)
        or (
            volume_uuid is not None
            and (
                str(parsed_volume_uuid) != volume_uuid
                or type(generation) is not int
                or not 0 <= generation < 1 << 64
            )
        )
        or type(request_nonce) is not bytes
        or len(request_nonce) != 32
    ):
        raise BrokerStateUnavailable
    checked_created = _validate_timestamp(created_at)
    checked_dispatched = (
        None if dispatched_at is None else _validate_timestamp(dispatched_at)
    )
    checked_terminal = None if terminal_at is None else _validate_timestamp(terminal_at)
    terminal_fields = (
        terminal_receipt,
        child_exit_code,
        evidence_sha256,
        broker_nonce,
        broker_proof,
    )
    if (
        (
            state == "PREPARED"
            and (checked_dispatched is not None or checked_terminal is not None)
        )
        or (
            state == "DISPATCHED"
            and (checked_dispatched is None or checked_terminal is not None)
        )
        or (state in {"TERMINAL", "FENCED"} and checked_terminal is None)
        or (state == "TERMINAL" and checked_dispatched is None)
        or (state != "TERMINAL" and any(value is not None for value in terminal_fields))
        or (
            state == "TERMINAL"
            and (
                not _is_digest(terminal_receipt)
                or type(child_exit_code) is not int
                or not _is_digest(evidence_sha256)
                or type(broker_nonce) is not bytes
                or len(broker_nonce) != 32
                or type(broker_proof) is not bytes
                or len(broker_proof) != 32
                or broker_nonce == broker_proof
            )
        )
        or (checked_dispatched is not None and checked_dispatched < checked_created)
        or (checked_terminal is not None and checked_terminal < checked_created)
    ):
        raise BrokerStateUnavailable
    record = QualificationStageRecord(
        run_id,
        stage_ordinal,
        state,
        boot_id,
        request_sha256,
        immutable_sha256,
        plan_sha256,
        checked_operation,
        operation_token_sha256,
        tape_identity,
        scsi_identity,
        media_scope,
        observed_identity,
        physical_label,
        tape_serial,
        drive_serial,
        drive_wwid,
        volume_uuid,
        generation,
        request_nonce,
        terminal_receipt,
        child_exit_code,
        evidence_sha256,
        broker_nonce,
        broker_proof,
        checked_created,
        checked_dispatched,
        checked_terminal,
    )
    if record.immutable_sha256 != _qualification_immutable_sha256(
        _qualification_record_values(record)
    ):
        raise BrokerStateUnavailable
    accepted = qualification_success_exit_codes(record.operation)
    if record.state == "TERMINAL" and record.child_exit_code not in accepted:
        raise BrokerStateUnavailable
    return record


def _normalize_sql(value: str) -> str:
    return "".join(value.lower().split()).rstrip(";")


def _validate_boot_id(value: object) -> str:
    if type(value) is not str:
        raise BrokerStateUnavailable
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise BrokerStateUnavailable from None
    if str(parsed) != value or parsed.version is None:
        raise BrokerStateUnavailable
    return value


def _validate_timestamp(value: object) -> str:
    if type(value) is not str or _TIMESTAMP.fullmatch(value) is None:
        raise BrokerStateUnavailable
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise BrokerStateUnavailable from None
    return value


def _effective_ids() -> tuple[int, int]:
    return (os.geteuid(), os.getegid())


def _fstat(fd: int) -> os.stat_result:
    return os.fstat(fd)


def _stat_at(name: str, *, dir_fd: int) -> os.stat_result:
    return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)


def _migration_execute(
    connection: sqlite3.Connection, statement: str
) -> sqlite3.Cursor:
    return connection.execute(statement)


def _validate_receipt(receipt: object) -> BrokeredCgroupScopeReceipt:
    if (
        type(receipt) is not BrokeredCgroupScopeReceipt
        or type(receipt.protocol_version) is not int
        or receipt.protocol_version != 1
        or not _is_identity(receipt.command_id)
        or type(receipt.owner_generation) is not int
        or receipt.owner_generation < 0
        or receipt.owner_generation >= 1 << 63
        or not _is_opaque(receipt.request_nonce)
        or not _is_identity(receipt.scope_id)
        or not _is_digest(receipt.scope_path_sha256)
        or not _is_opaque(receipt.broker_nonce)
        or not _is_opaque(receipt.broker_proof)
        or len({receipt.request_nonce, receipt.broker_nonce, receipt.broker_proof}) != 3
        or receipt.recursive_population is not True
        or receipt.recursive_members is not True
        or receipt.cgroup_kill is not True
    ):
        raise BrokerStateConflict
    return receipt


def _validate_permit(permit: object) -> BrokeredCgroupReleasePermit:
    if (
        type(permit) is not BrokeredCgroupReleasePermit
        or type(permit.protocol_version) is not int
        or permit.protocol_version != 1
        or type(permit.pid) is not int
        or not 0 < permit.pid < 1 << 31
        or not _is_opaque(permit.request_nonce)
        or not _is_opaque(permit.permit_nonce)
        or not _is_opaque(permit.broker_proof)
        or len({permit.request_nonce, permit.permit_nonce, permit.broker_proof}) != 3
    ):
        raise BrokerStateConflict
    _validate_receipt(permit.receipt)
    return permit


def _canonical_permit_json(permit: BrokeredCgroupReleasePermit) -> str:
    checked = _validate_permit(permit)
    receipt = checked.receipt
    return json.dumps(
        {
            "protocol_version": checked.protocol_version,
            "command_id": receipt.command_id,
            "owner_generation": receipt.owner_generation,
            "scope_id": receipt.scope_id,
            "scope_path_sha256": receipt.scope_path_sha256,
            "scope_request_nonce": receipt.request_nonce.hex(),
            "scope_broker_nonce": receipt.broker_nonce.hex(),
            "scope_broker_proof": receipt.broker_proof.hex(),
            "pid": checked.pid,
            "request_nonce": checked.request_nonce.hex(),
            "permit_nonce": checked.permit_nonce.hex(),
            "broker_proof": checked.broker_proof.hex(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )


def permit_sha256(permit: BrokeredCgroupReleasePermit) -> str:
    """Return the supervisor-compatible version-1 release permit digest."""

    encoded = _canonical_permit_json(permit).encode("ascii")
    return hashlib.sha256(b"lto-broker-release-v1\0" + encoded).hexdigest()


def _is_opaque_hex(value: object) -> bool:
    return (
        type(value) is str
        and 64 <= len(value) <= 8192
        and len(value) % 2 == 0
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_stored_permit_json(
    value: object, expected_digest: str, expected_scope_id: str, expected_pid: int
) -> str:
    if type(value) is not str or not value or not value.isascii():
        raise BrokerStateUnavailable
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        raise BrokerStateUnavailable from None
    if (
        type(decoded) is not dict
        or frozenset(decoded) != _PERMIT_JSON_KEYS
        or type(decoded["protocol_version"]) is not int
        or decoded["protocol_version"] != 1
        or not _is_identity(decoded["command_id"])
        or type(decoded["owner_generation"]) is not int
        or not 0 <= decoded["owner_generation"] < 1 << 63
        or decoded["scope_id"] != expected_scope_id
        or not _is_identity(decoded["scope_id"])
        or not _is_digest(decoded["scope_path_sha256"])
        or type(decoded["pid"]) is not int
        or decoded["pid"] != expected_pid
        or any(
            not _is_opaque_hex(decoded[field])
            for field in (
                "scope_request_nonce",
                "scope_broker_nonce",
                "scope_broker_proof",
                "request_nonce",
                "permit_nonce",
                "broker_proof",
            )
        )
        or len(
            {
                decoded["scope_request_nonce"],
                decoded["scope_broker_nonce"],
                decoded["scope_broker_proof"],
            }
        )
        != 3
        or len(
            {
                decoded["request_nonce"],
                decoded["permit_nonce"],
                decoded["broker_proof"],
            }
        )
        != 3
        or json.dumps(decoded, separators=(",", ":"), sort_keys=True) != value
        or hashlib.sha256(
            b"lto-broker-release-v1\0" + value.encode("ascii")
        ).hexdigest()
        != expected_digest
    ):
        raise BrokerStateUnavailable
    return value


def _scope_from_row(row: tuple[object, ...]) -> ScopeRecord:
    if len(row) != 11:
        raise BrokerStateUnavailable
    (
        scope_id,
        command_id,
        owner_generation,
        scope_path_sha256,
        boot_id,
        state_value,
        pid,
        process_start_ticks,
        cgroup_device,
        cgroup_inode,
        created_at,
    ) = row
    if (
        not _is_identity(scope_id)
        or not _is_identity(command_id)
        or type(owner_generation) is not int
        or not 0 <= owner_generation < 1 << 63
        or not _is_digest(scope_path_sha256)
        or type(state_value) is not str
        or state_value not in _SCOPE_STATES
        or (pid is None) != (process_start_ticks is None)
        or (cgroup_device is None) != (cgroup_inode is None)
        or (pid is not None and (type(pid) is not int or not 0 < pid < 1 << 31))
        or (
            process_start_ticks is not None
            and (type(process_start_ticks) is not int or process_start_ticks < 0)
        )
        or (
            cgroup_device is not None
            and (type(cgroup_device) is not int or not 0 <= cgroup_device < 1 << 63)
        )
        or (
            cgroup_inode is not None
            and (type(cgroup_inode) is not int or not 0 < cgroup_inode < 1 << 63)
        )
    ):
        raise BrokerStateUnavailable
    checked_boot_id = _validate_boot_id(boot_id)
    checked_created_at = _validate_timestamp(created_at)
    return ScopeRecord(
        scope_id=scope_id,
        command_id=command_id,
        owner_generation=owner_generation,
        scope_path_sha256=scope_path_sha256,
        boot_id=checked_boot_id,
        state=state_value,
        pid=pid,
        process_start_ticks=process_start_ticks,
        cgroup_device=cgroup_device,
        cgroup_inode=cgroup_inode,
        created_at=checked_created_at,
    )


def _is_exact_opaque(value: object) -> bool:
    return type(value) is bytes and len(value) == 32


def _is_canonical_uuid(value: object) -> bool:
    try:
        return type(value) is str and str(uuid.UUID(value)) == value
    except (ValueError, AttributeError, TypeError):
        return False


def _validate_ltfs_request(value: object) -> tuple[LtfsSessionRequest, str]:
    if type(value) is not LtfsSessionRequest:
        raise BrokerStateConflict
    receipt = _validate_receipt(value.cgroup_scope_receipt)
    digests = (
        value.mount_path_sha256,
        value.tape_device_identity_sha256,
        value.scsi_device_identity_sha256,
        value.expected_media_scope_sha256,
        value.observed_media_identity_sha256,
        value.tape_fd_identity_sha256,
        value.scsi_fd_identity_sha256,
    )
    if (
        type(value.protocol_version) is not int
        or value.protocol_version != 1
        or not _is_identity(value.operation_id)
        or type(value.owner_generation) is not int
        or not 0 <= value.owner_generation < 1 << 63
        or any(not _is_digest(digest) for digest in digests)
        or type(value.read_only) is not bool
        or (
            value.expected_volume_uuid is not None
            and not _is_canonical_uuid(value.expected_volume_uuid)
        )
        or value.expected_volume_uuid is None
        or type(value.expected_prior_generation) is not int
        or not 0 < value.expected_prior_generation < 1 << 64
        or not _is_exact_opaque(value.request_nonce)
        or receipt.owner_generation != value.owner_generation
        or value.tape_fd_identity_sha256 == value.scsi_fd_identity_sha256
        or value.request_nonce
        in {receipt.request_nonce, receipt.broker_nonce, receipt.broker_proof}
    ):
        raise BrokerStateConflict
    from ltobackup.broker.protocol import ltfs_request_sha256

    return value, ltfs_request_sha256(value)


def _validate_ltfs_receipt(value: object) -> LtfsSessionReceipt:
    if (
        type(value) is not LtfsSessionReceipt
        or type(value.protocol_version) is not int
        or value.protocol_version != 1
        or not _is_identity(value.operation_id)
        or not _is_canonical_uuid(value.receipt_operation_uuid)
        or not _is_canonical_uuid(value.observed_volume_uuid)
        or type(value.observed_prior_generation) is not int
        or not 0 < value.observed_prior_generation < 1 << 64
        or type(value.observed_volume_label) is not str
        or not value.observed_volume_label
        or len(value.observed_volume_label) > 255
        or value.observed_volume_label != value.observed_volume_label.strip(" ")
        or not value.observed_volume_label.isascii()
        or not value.observed_volume_label.isprintable()
        or not _is_digest(value.observed_media_identity_sha256)
        or type(value.read_only) is not bool
        or type(value.owner_generation) is not int
        or not 0 <= value.owner_generation < 1 << 63
        or not _is_exact_opaque(value.request_nonce)
        or not _is_identity(value.session_id)
        or not _is_digest(value.request_sha256)
        or type(value.child_pid) is not int
        or not 0 < value.child_pid < 1 << 31
        or type(value.child_start_ticks) is not int
        or value.child_start_ticks <= 0
        or not _is_digest(value.mount_namespace_sha256)
        or not _is_exact_opaque(value.broker_nonce)
        or not _is_exact_opaque(value.broker_proof)
        or len({value.request_nonce, value.broker_nonce, value.broker_proof}) != 3
        or value.mounted is not True
    ):
        raise BrokerStateConflict
    return value


def _validate_ltfs_finalization(value: object) -> LtfsFinalizationReceipt:
    if (
        type(value) is not LtfsFinalizationReceipt
        or type(value.protocol_version) is not int
        or value.protocol_version != 1
        or not _is_exact_opaque(value.request_nonce)
        or not _is_exact_opaque(value.finalization_nonce)
        or not _is_exact_opaque(value.broker_proof)
        or len({value.request_nonce, value.finalization_nonce, value.broker_proof}) != 3
        or value.unmounted is not True
        or value.child_quiesced is not True
    ):
        raise BrokerStateConflict
    _validate_ltfs_receipt(value.session_receipt)
    from ltobackup.broker.protocol import _transform_ltfs_standalone_receipt

    _transform_ltfs_standalone_receipt(value.standalone_receipt, encode=True)
    return value


def _standalone_receipt_json(value: LtfsStandaloneReceipt) -> str:
    from ltobackup.broker.protocol import _encode_ltfs_standalone_receipt

    return json.dumps(
        _encode_ltfs_standalone_receipt(value),
        separators=(",", ":"),
        sort_keys=True,
    )


def _ltfs_immutable_sha256(
    *,
    operation_id: str,
    owner_generation: int,
    boot_id: str,
    request_sha256: str,
    mount_path_sha256: str,
    tape_device_identity_sha256: str,
    scsi_device_identity_sha256: str,
    expected_media_scope_sha256: str,
    observed_media_identity_sha256: str,
    tape_fd_identity_sha256: str,
    scsi_fd_identity_sha256: str,
    read_only: bool,
    ltfs_tool_identity_sha256: str,
    fusermount_tool_identity_sha256: str,
    cgroup_scope_id: str,
    start_request_nonce: bytes,
) -> str:
    canonical = json.dumps(
        {
            "boot_id": boot_id,
            "cgroup_scope_id": cgroup_scope_id,
            "expected_media_scope_sha256": expected_media_scope_sha256,
            "fusermount_tool_identity_sha256": fusermount_tool_identity_sha256,
            "ltfs_tool_identity_sha256": ltfs_tool_identity_sha256,
            "mount_path_sha256": mount_path_sha256,
            "observed_media_identity_sha256": observed_media_identity_sha256,
            "operation_id": operation_id,
            "owner_generation": owner_generation,
            "read_only": read_only,
            "request_sha256": request_sha256,
            "scsi_device_identity_sha256": scsi_device_identity_sha256,
            "scsi_fd_identity_sha256": scsi_fd_identity_sha256,
            "start_request_nonce": start_request_nonce.hex(),
            "tape_device_identity_sha256": tape_device_identity_sha256,
            "tape_fd_identity_sha256": tape_fd_identity_sha256,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"lto-broker-ltfs-session-v1\0" + canonical).hexdigest()


def _ltfs_session_from_row(row: tuple[object, ...]) -> LtfsSessionRecord:
    if len(row) != 40:
        raise BrokerStateUnavailable
    (
        operation_id,
        owner_generation,
        state_value,
        boot_id,
        request_sha256,
        immutable_sha256,
        mount_path_sha256,
        tape_device_identity_sha256,
        scsi_device_identity_sha256,
        expected_media_scope_sha256,
        expected_volume_uuid,
        expected_prior_generation,
        receipt_operation_uuid,
        observed_volume_uuid,
        observed_prior_generation,
        observed_volume_label,
        observed_media_identity_sha256,
        tape_fd_identity_sha256,
        scsi_fd_identity_sha256,
        read_only,
        ltfs_tool_identity_sha256,
        fusermount_tool_identity_sha256,
        cgroup_scope_id,
        child_pid,
        child_start_ticks,
        mount_namespace_sha256,
        start_request_nonce,
        session_id,
        session_broker_nonce,
        session_broker_proof,
        finalization_request_nonce,
        finalization_nonce,
        finalization_broker_proof,
        standalone_receipt_json,
        terminal_sha256,
        standalone_bound_at,
        created_at,
        mounted_at,
        finalizing_at,
        terminal_at,
    ) = row
    digests = (
        request_sha256,
        mount_path_sha256,
        tape_device_identity_sha256,
        scsi_device_identity_sha256,
        expected_media_scope_sha256,
        observed_media_identity_sha256,
        tape_fd_identity_sha256,
        scsi_fd_identity_sha256,
        ltfs_tool_identity_sha256,
        fusermount_tool_identity_sha256,
    )
    child_values = (child_pid, child_start_ticks, mount_namespace_sha256)
    session_values = (session_id, session_broker_nonce, session_broker_proof)
    ready_values = (
        receipt_operation_uuid,
        observed_volume_uuid,
        observed_prior_generation,
        observed_volume_label,
    )
    terminal_values = (
        standalone_receipt_json,
        terminal_sha256,
        standalone_bound_at,
    )
    if (
        not _is_identity(operation_id)
        or type(owner_generation) is not int
        or not 0 <= owner_generation < 1 << 63
        or type(state_value) is not str
        or state_value not in _LTFS_SESSION_STATES
        or any(not _is_digest(digest) for digest in digests)
        or not _is_digest(immutable_sha256)
        or tape_fd_identity_sha256 == scsi_fd_identity_sha256
        or ltfs_tool_identity_sha256 == fusermount_tool_identity_sha256
        or type(read_only) is not int
        or read_only not in {0, 1}
        or not _is_identity(cgroup_scope_id)
        or not _is_exact_opaque(start_request_nonce)
        or any(value is None for value in child_values)
        != all(value is None for value in child_values)
        or any(value is None for value in session_values)
        != all(value is None for value in session_values)
        or (finalization_nonce is None) != (finalization_broker_proof is None)
        or any(value is None for value in ready_values)
        != all(value is None for value in ready_values)
        or any(value is None for value in terminal_values)
        != all(value is None for value in terminal_values)
    ):
        raise BrokerStateUnavailable
    for uuid_value in (
        expected_volume_uuid,
        receipt_operation_uuid,
        observed_volume_uuid,
    ):
        if uuid_value is not None:
            try:
                if str(uuid.UUID(uuid_value)) != uuid_value:
                    raise ValueError
            except (ValueError, AttributeError, TypeError):
                raise BrokerStateUnavailable from None
    if observed_prior_generation is not None and (
        type(observed_prior_generation) is not int
        or not 0 < observed_prior_generation < 1 << 64
    ):
        raise BrokerStateUnavailable
    if observed_volume_label is not None and (
        type(observed_volume_label) is not str
        or not observed_volume_label
        or len(observed_volume_label) > 255
        or observed_volume_label != observed_volume_label.strip(" ")
        or not observed_volume_label.isascii()
        or not observed_volume_label.isprintable()
    ):
        raise BrokerStateUnavailable
    if expected_prior_generation is not None and (
        type(expected_prior_generation) is not int
        or not 0 < expected_prior_generation < 1 << 64
    ):
        raise BrokerStateUnavailable
    if terminal_sha256 is not None and not _is_digest(terminal_sha256):
        raise BrokerStateUnavailable
    if child_pid is not None and (
        type(child_pid) is not int
        or not 0 < child_pid < 1 << 31
        or type(child_start_ticks) is not int
        or child_start_ticks <= 0
        or not _is_digest(mount_namespace_sha256)
    ):
        raise BrokerStateUnavailable
    if session_id is not None and (
        not _is_identity(session_id)
        or not _is_exact_opaque(session_broker_nonce)
        or not _is_exact_opaque(session_broker_proof)
    ):
        raise BrokerStateUnavailable
    if finalization_request_nonce is not None and not _is_exact_opaque(
        finalization_request_nonce
    ):
        raise BrokerStateUnavailable
    if finalization_nonce is not None and (
        not _is_exact_opaque(finalization_nonce)
        or not _is_exact_opaque(finalization_broker_proof)
    ):
        raise BrokerStateUnavailable
    opaque_values = tuple(
        value
        for value in (
            start_request_nonce,
            session_broker_nonce,
            session_broker_proof,
            finalization_request_nonce,
            finalization_nonce,
            finalization_broker_proof,
        )
        if value is not None
    )
    if len(set(opaque_values)) != len(opaque_values):
        raise BrokerStateUnavailable

    checked_boot_id = _validate_boot_id(boot_id)
    checked_created_at = _validate_timestamp(created_at)
    checked_mounted_at = None if mounted_at is None else _validate_timestamp(mounted_at)
    checked_finalizing_at = (
        None if finalizing_at is None else _validate_timestamp(finalizing_at)
    )
    checked_terminal_at = (
        None if terminal_at is None else _validate_timestamp(terminal_at)
    )
    checked_standalone_bound_at = (
        None
        if standalone_bound_at is None
        else _validate_timestamp(standalone_bound_at)
    )
    if any(
        later is not None and later < earlier
        for earlier, later in (
            (checked_created_at, checked_mounted_at),
            (checked_mounted_at or checked_created_at, checked_finalizing_at),
            (
                checked_finalizing_at or checked_mounted_at or checked_created_at,
                checked_terminal_at,
            ),
        )
    ):
        raise BrokerStateUnavailable

    child_bound = child_pid is not None
    session_bound = session_id is not None
    finalizing_bound = finalization_request_nonce is not None
    final_bound = finalization_nonce is not None
    ready_bound = receipt_operation_uuid is not None
    terminal_receipt_bound = standalone_receipt_json is not None
    if (
        (
            (expected_volume_uuid is None or expected_prior_generation is None)
            and state_value not in {"BROKEN", "UNMOUNTED"}
        )
        or (state_value != "BROKEN" and session_bound != ready_bound)
        or (state_value != "BROKEN" and final_bound and not terminal_receipt_bound)
        or (state_value == "UNMOUNTED" and not terminal_receipt_bound)
    ):
        raise BrokerStateUnavailable
    if state_value == "STARTING" and (
        session_bound
        or checked_mounted_at is not None
        or finalizing_bound
        or checked_finalizing_at is not None
        or final_bound
        or checked_terminal_at is not None
    ):
        raise BrokerStateUnavailable
    if state_value == "MOUNTED" and (
        not child_bound
        or not session_bound
        or checked_mounted_at is None
        or finalizing_bound
        or checked_finalizing_at is not None
        or final_bound
        or checked_terminal_at is not None
    ):
        raise BrokerStateUnavailable
    if state_value == "FINALIZING" and (
        not child_bound
        or not session_bound
        or checked_mounted_at is None
        or not finalizing_bound
        or checked_finalizing_at is None
        or final_bound
        or checked_terminal_at is not None
    ):
        raise BrokerStateUnavailable
    if state_value == "UNMOUNTED" and (
        not child_bound
        or not session_bound
        or checked_mounted_at is None
        or not finalizing_bound
        or checked_finalizing_at is None
        or not final_bound
        or checked_terminal_at is None
    ):
        raise BrokerStateUnavailable
    if state_value == "BROKEN" and (
        checked_terminal_at is None
        or session_bound != (checked_mounted_at is not None)
        or session_bound
        and not child_bound
        or finalizing_bound != (checked_finalizing_at is not None)
        or finalizing_bound
        and not session_bound
        or final_bound
        and not finalizing_bound
    ):
        raise BrokerStateUnavailable

    return LtfsSessionRecord(
        operation_id=operation_id,
        owner_generation=owner_generation,
        state=state_value,
        boot_id=checked_boot_id,
        request_sha256=request_sha256,
        immutable_sha256=immutable_sha256,
        mount_path_sha256=mount_path_sha256,
        tape_device_identity_sha256=tape_device_identity_sha256,
        scsi_device_identity_sha256=scsi_device_identity_sha256,
        expected_media_scope_sha256=expected_media_scope_sha256,
        expected_volume_uuid=expected_volume_uuid,
        expected_prior_generation=expected_prior_generation,
        receipt_operation_uuid=receipt_operation_uuid,
        observed_volume_uuid=observed_volume_uuid,
        observed_prior_generation=observed_prior_generation,
        observed_volume_label=observed_volume_label,
        observed_media_identity_sha256=observed_media_identity_sha256,
        tape_fd_identity_sha256=tape_fd_identity_sha256,
        scsi_fd_identity_sha256=scsi_fd_identity_sha256,
        read_only=bool(read_only),
        ltfs_tool_identity_sha256=ltfs_tool_identity_sha256,
        fusermount_tool_identity_sha256=fusermount_tool_identity_sha256,
        cgroup_scope_id=cgroup_scope_id,
        child_pid=child_pid,
        child_start_ticks=child_start_ticks,
        mount_namespace_sha256=mount_namespace_sha256,
        start_request_nonce=start_request_nonce,
        session_id=session_id,
        session_broker_nonce=session_broker_nonce,
        session_broker_proof=session_broker_proof,
        finalization_request_nonce=finalization_request_nonce,
        finalization_nonce=finalization_nonce,
        finalization_broker_proof=finalization_broker_proof,
        standalone_receipt_json=standalone_receipt_json,
        terminal_sha256=terminal_sha256,
        standalone_bound_at=checked_standalone_bound_at,
        created_at=checked_created_at,
        mounted_at=checked_mounted_at,
        finalizing_at=checked_finalizing_at,
        terminal_at=checked_terminal_at,
    )


def _ltfs_opaque_values(record: LtfsSessionRecord) -> frozenset[bytes]:
    return frozenset(
        value
        for value in (
            record.start_request_nonce,
            record.session_broker_nonce,
            record.session_broker_proof,
            record.finalization_request_nonce,
            record.finalization_nonce,
            record.finalization_broker_proof,
        )
        if value is not None
    )


def _ltfs_observation_from_row(row: tuple[object, ...]) -> LtfsObservationRecord:
    if len(row) != 7:
        raise BrokerStateUnavailable
    (
        operation_id,
        owner_generation,
        session_id,
        challenge,
        observation_nonce,
        broker_proof,
        observed_at,
    ) = row
    if (
        not _is_identity(operation_id)
        or type(owner_generation) is not int
        or not 0 <= owner_generation < 1 << 63
        or not _is_identity(session_id)
        or not _is_exact_opaque(challenge)
        or not _is_exact_opaque(observation_nonce)
        or not _is_exact_opaque(broker_proof)
        or len({challenge, observation_nonce, broker_proof}) != 3
    ):
        raise BrokerStateUnavailable
    return LtfsObservationRecord(
        operation_id=operation_id,
        owner_generation=owner_generation,
        session_id=session_id,
        challenge=challenge,
        observation_nonce=observation_nonce,
        broker_proof=broker_proof,
        observed_at=_validate_timestamp(observed_at),
    )


def _ltfs_legacy_sha256(record: LtfsSessionRecord) -> str:
    return _ltfs_immutable_sha256(
        operation_id=record.operation_id,
        owner_generation=record.owner_generation,
        boot_id=record.boot_id,
        request_sha256=record.request_sha256,
        mount_path_sha256=record.mount_path_sha256,
        tape_device_identity_sha256=record.tape_device_identity_sha256,
        scsi_device_identity_sha256=record.scsi_device_identity_sha256,
        expected_media_scope_sha256=record.expected_media_scope_sha256,
        observed_media_identity_sha256=record.observed_media_identity_sha256,
        tape_fd_identity_sha256=record.tape_fd_identity_sha256,
        scsi_fd_identity_sha256=record.scsi_fd_identity_sha256,
        read_only=record.read_only,
        ltfs_tool_identity_sha256=record.ltfs_tool_identity_sha256,
        fusermount_tool_identity_sha256=record.fusermount_tool_identity_sha256,
        cgroup_scope_id=record.cgroup_scope_id,
        start_request_nonce=record.start_request_nonce,
    )


def _ltfs_record_sha256(
    record: LtfsSessionRecord,
    observations: tuple[LtfsObservationRecord, ...],
) -> str:
    def opaque(value: bytes | None) -> str | None:
        return None if value is None else value.hex()

    canonical = json.dumps(
        {
            "boot_id": record.boot_id,
            "cgroup_scope_id": record.cgroup_scope_id,
            "child_pid": record.child_pid,
            "child_start_ticks": record.child_start_ticks,
            "created_at": record.created_at,
            "expected_media_scope_sha256": record.expected_media_scope_sha256,
            "expected_volume_uuid": record.expected_volume_uuid,
            "expected_prior_generation": record.expected_prior_generation,
            "finalization_broker_proof": opaque(record.finalization_broker_proof),
            "finalization_nonce": opaque(record.finalization_nonce),
            "finalization_request_nonce": opaque(record.finalization_request_nonce),
            "finalizing_at": record.finalizing_at,
            "fusermount_tool_identity_sha256": record.fusermount_tool_identity_sha256,
            "ltfs_tool_identity_sha256": record.ltfs_tool_identity_sha256,
            "mount_namespace_sha256": record.mount_namespace_sha256,
            "mount_path_sha256": record.mount_path_sha256,
            "mounted_at": record.mounted_at,
            "observations": [
                {
                    "broker_proof": observation.broker_proof.hex(),
                    "challenge": observation.challenge.hex(),
                    "observation_nonce": observation.observation_nonce.hex(),
                    "observed_at": observation.observed_at,
                    "operation_id": observation.operation_id,
                    "owner_generation": observation.owner_generation,
                    "session_id": observation.session_id,
                }
                for observation in sorted(
                    observations,
                    key=lambda item: (
                        item.challenge,
                        item.observation_nonce,
                        item.broker_proof,
                    ),
                )
            ],
            "observed_media_identity_sha256": record.observed_media_identity_sha256,
            "observed_prior_generation": record.observed_prior_generation,
            "observed_volume_label": record.observed_volume_label,
            "observed_volume_uuid": record.observed_volume_uuid,
            "operation_id": record.operation_id,
            "owner_generation": record.owner_generation,
            "read_only": record.read_only,
            "request_sha256": record.request_sha256,
            "receipt_operation_uuid": record.receipt_operation_uuid,
            "scsi_device_identity_sha256": record.scsi_device_identity_sha256,
            "scsi_fd_identity_sha256": record.scsi_fd_identity_sha256,
            "session_broker_nonce": opaque(record.session_broker_nonce),
            "session_broker_proof": opaque(record.session_broker_proof),
            "session_id": record.session_id,
            "start_request_nonce": record.start_request_nonce.hex(),
            "standalone_bound_at": record.standalone_bound_at,
            "standalone_receipt_json": record.standalone_receipt_json,
            "state": record.state,
            "tape_device_identity_sha256": record.tape_device_identity_sha256,
            "tape_fd_identity_sha256": record.tape_fd_identity_sha256,
            "terminal_at": record.terminal_at,
            "terminal_sha256": record.terminal_sha256,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"lto-broker-ltfs-record-v2\0" + canonical).hexdigest()


def _ltfs_session_values(record: LtfsSessionRecord) -> tuple[object, ...]:
    return (
        record.operation_id,
        record.owner_generation,
        record.state,
        record.boot_id,
        record.request_sha256,
        record.immutable_sha256,
        record.mount_path_sha256,
        record.tape_device_identity_sha256,
        record.scsi_device_identity_sha256,
        record.expected_media_scope_sha256,
        record.expected_volume_uuid,
        record.expected_prior_generation,
        record.receipt_operation_uuid,
        record.observed_volume_uuid,
        record.observed_prior_generation,
        record.observed_volume_label,
        record.observed_media_identity_sha256,
        record.tape_fd_identity_sha256,
        record.scsi_fd_identity_sha256,
        int(record.read_only),
        record.ltfs_tool_identity_sha256,
        record.fusermount_tool_identity_sha256,
        record.cgroup_scope_id,
        record.child_pid,
        record.child_start_ticks,
        record.mount_namespace_sha256,
        record.start_request_nonce,
        record.session_id,
        record.session_broker_nonce,
        record.session_broker_proof,
        record.finalization_request_nonce,
        record.finalization_nonce,
        record.finalization_broker_proof,
        record.standalone_receipt_json,
        record.terminal_sha256,
        record.standalone_bound_at,
        record.created_at,
        record.mounted_at,
        record.finalizing_at,
        record.terminal_at,
    )


def _upgrade_ltfs_v3_row(row: tuple[object, ...]) -> tuple[object, ...]:
    if len(row) != 30:
        raise BrokerStateUnavailable
    seal = _ltfs_immutable_sha256(
        operation_id=row[0],
        owner_generation=row[1],
        boot_id=row[3],
        request_sha256=row[4],
        mount_path_sha256=row[5],
        tape_device_identity_sha256=row[6],
        scsi_device_identity_sha256=row[7],
        expected_media_scope_sha256=row[8],
        observed_media_identity_sha256=row[9],
        tape_fd_identity_sha256=row[10],
        scsi_fd_identity_sha256=row[11],
        read_only=bool(row[12]),
        ltfs_tool_identity_sha256=row[13],
        fusermount_tool_identity_sha256=row[14],
        cgroup_scope_id=row[15],
        start_request_nonce=row[19],
    )
    return _upgrade_ltfs_v5_row((*row[:5], seal, *row[5:]))


def _upgrade_ltfs_v5_row(row: tuple[object, ...]) -> tuple[object, ...]:
    if len(row) != 31:
        raise BrokerStateUnavailable
    legacy = list(row)
    legacy[2] = "BROKEN"
    legacy[30] = legacy[30] or legacy[29] or legacy[28] or legacy[27]
    row = tuple(legacy)
    upgraded = (
        *row[:10],
        None,
        None,
        None,
        None,
        None,
        *row[10:27],
        None,
        None,
        None,
        *row[27:],
    )
    return _upgrade_ltfs_v6_row(upgraded)


def _upgrade_ltfs_v6_row(row: tuple[object, ...]) -> tuple[object, ...]:
    if len(row) != 39:
        raise BrokerStateUnavailable
    legacy = list(row)
    legacy[2] = "BROKEN"
    legacy[38] = legacy[38] or legacy[37] or legacy[36] or legacy[35]
    upgraded = (*legacy[:15], None, *legacy[15:])
    record = _ltfs_session_from_row(upgraded)
    return _ltfs_session_values(
        replace(record, immutable_sha256=_ltfs_record_sha256(record, ()))
    )


class BrokerStateStore:
    """Fail-closed, one-connection SQLite authority for broker state."""

    def __init__(
        self,
        connection: sqlite3.Connection,
        database_fd: int,
        *,
        boot_id: str,
        clock: Callable[[], str],
    ) -> None:
        self._connection = connection
        self._database_fd = database_fd
        self._boot_id = boot_id
        self._clock = clock
        self._lock = threading.RLock()
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        boot_id: str,
        clock: Callable[[], str],
    ) -> BrokerStateStore:
        checked_boot_id = _validate_boot_id(boot_id)
        if not isinstance(path, Path) or not path.is_absolute() or not callable(clock):
            raise BrokerStateUnavailable
        if path.name in {"", ".", ".."}:
            raise BrokerStateUnavailable
        try:
            effective_ids = _effective_ids()
        except OSError:
            raise BrokerStateUnavailable from None
        if effective_ids != (0, 0):
            raise BrokerStateUnavailable

        parent_fd: int | None = None
        database_fd: int | None = None
        connection: sqlite3.Connection | None = None
        instance: BrokerStateStore | None = None
        created = False
        try:
            parent_fd = cls._open_parent(path.parent)
            parent_status = _fstat(parent_fd)
            if not cls._secure_parent_status(parent_status):
                raise BrokerStateUnavailable
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            try:
                database_fd = os.open(path.name, flags, dir_fd=parent_fd)
            except FileNotFoundError:
                database_fd = os.open(
                    path.name,
                    flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=parent_fd,
                )
                created = True
            status = _fstat(database_fd)
            if not cls._secure_database_status(status):
                raise BrokerStateUnavailable
            anchored_status = _stat_at(path.name, dir_fd=parent_fd)
            if (
                anchored_status.st_dev != status.st_dev
                or anchored_status.st_ino != status.st_ino
            ):
                raise BrokerStateUnavailable

            connection = sqlite3.connect(
                f"file:/proc/self/fd/{database_fd}?mode=rw",
                uri=True,
                isolation_level=None,
                check_same_thread=False,
                timeout=5.0,
            )
            instance = cls(
                connection,
                database_fd,
                boot_id=checked_boot_id,
                clock=clock,
            )
            database_fd = None
            instance._configure_and_validate(created=created)
            os.fsync(parent_fd)
            final_status = _stat_at(path.name, dir_fd=parent_fd)
            if (
                not cls._secure_database_status(final_status)
                or final_status.st_dev != status.st_dev
                or final_status.st_ino != status.st_ino
                or not cls._secure_parent_status(_fstat(parent_fd))
            ):
                raise BrokerStateUnavailable
            return instance
        except BrokerStateUnavailable:
            if instance is not None:
                instance.close()
            raise
        except (OSError, sqlite3.Error, ValueError, TypeError):
            if instance is not None:
                instance.close()
            raise BrokerStateUnavailable from None
        finally:
            if connection is not None and database_fd is not None:
                with contextlib.suppress(sqlite3.Error):
                    connection.close()
            if database_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(database_fd)
            if parent_fd is not None:
                with contextlib.suppress(OSError):
                    os.close(parent_fd)

    @staticmethod
    def _secure_parent_status(status: os.stat_result) -> bool:
        return (
            stat.S_ISDIR(status.st_mode)
            and status.st_uid == 0
            and status.st_gid == 0
            and stat.S_IMODE(status.st_mode) == 0o700
        )

    @staticmethod
    def _secure_database_status(status: os.stat_result) -> bool:
        return (
            stat.S_ISREG(status.st_mode)
            and status.st_uid == 0
            and status.st_gid == 0
            and stat.S_IMODE(status.st_mode) == 0o600
            and status.st_nlink == 1
        )

    @staticmethod
    def _open_parent(parent: Path) -> int:
        parts = parent.parts
        if (
            not parts
            or parts[0] != os.sep
            or any(part in {"", ".", ".."} for part in parts[1:])
            or not hasattr(os, "O_PATH")
        ):
            raise BrokerStateUnavailable
        common_flags = os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        traversal_flags = os.O_PATH | common_flags
        final_flags = os.O_RDONLY | common_flags
        if len(parts) == 1:
            return os.open(os.sep, final_flags)
        current = os.open(os.sep, traversal_flags)
        try:
            for index, part in enumerate(parts[1:], start=1):
                flags = final_flags if index == len(parts) - 1 else traversal_flags
                next_fd = os.open(part, flags, dir_fd=current)
                os.close(current)
                current = next_fd
            result = current
            current = -1
            return result
        finally:
            if current >= 0:
                os.close(current)

    def _configure_and_validate(self, *, created: bool) -> None:
        try:
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("PRAGMA foreign_keys=ON")
            journal_mode = self._connection.execute(
                "PRAGMA journal_mode=DELETE"
            ).fetchone()
            self._connection.execute("PRAGMA synchronous=FULL")
            if journal_mode != ("delete",):
                raise BrokerStateUnavailable
            if created:
                self._connection.execute("BEGIN IMMEDIATE")
                try:
                    for statement in _SCHEMA:
                        self._connection.execute(statement)
                    self._connection.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                    self._connection.commit()
                except BaseException:
                    self._connection.rollback()
                    raise
            else:
                self._migrate_legacy_schema()
            self._validate_schema()
            if self.pragma("integrity_check") != "ok":
                raise BrokerStateUnavailable
            self._validate_rows()
            self._recover_boot_change()
            self._validate_rows()
        except BrokerStateUnavailable:
            self.close()
            raise
        except (sqlite3.Error, OSError, ValueError, TypeError):
            self.close()
            raise BrokerStateUnavailable from None

    def _migrate_legacy_schema(self) -> None:
        version = self._connection.execute("PRAGMA user_version").fetchone()
        if version == (1,):
            expected_schema = _SCHEMA_V1
            additions = (
                _SCHEMA_V2[-1],
                _LTFS_SESSIONS_SQL,
                _LTFS_OBSERVATIONS_SQL,
                _LTFS_CHILD_EXIT_RECEIPTS_SQL,
                _LTFS_QUALIFICATION_STAGES_SQL,
            )
        elif version == (2,):
            expected_schema = _SCHEMA_V2
            additions = (
                _LTFS_SESSIONS_SQL,
                _LTFS_OBSERVATIONS_SQL,
                _LTFS_CHILD_EXIT_RECEIPTS_SQL,
                _LTFS_QUALIFICATION_STAGES_SQL,
            )
        elif version == (3,):
            self._migrate_version_three()
            return
        elif version == (4,):
            self._migrate_version_four()
            return
        elif version == (5,):
            self._migrate_version_five()
            return
        elif version == (6,):
            self._migrate_version_six()
            return
        elif version == (7,):
            self._migrate_version_seven()
            return
        elif version == (8,):
            self._migrate_version_eight()
            return
        elif version == (9,):
            self._migrate_version_nine()
            return
        else:
            return
        if self._schema_objects() != self._expected_schema(expected_schema):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects():
            raise BrokerStateUnavailable
        if self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for statement in additions:
                _migration_execute(self._connection, statement)
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _migrate_version_three(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V3):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects():
            raise BrokerStateUnavailable
        if self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        old_rows = self._connection.execute(_LTFS_SESSION_SELECT_V3).fetchall()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(
                self._connection,
                "ALTER TABLE ltfs_sessions RENAME TO ltfs_sessions_v3",
            )
            _migration_execute(self._connection, _LTFS_SESSIONS_SQL)
            insert_sql = (
                "INSERT INTO ltfs_sessions VALUES("
                + ",".join("?" for _field in range(40))
                + ")"
            )
            for row in old_rows:
                self._connection.execute(insert_sql, _upgrade_ltfs_v3_row(row))
            _migration_execute(self._connection, "DROP TABLE ltfs_sessions_v3")
            _migration_execute(self._connection, _LTFS_OBSERVATIONS_SQL)
            _migration_execute(self._connection, _LTFS_CHILD_EXIT_RECEIPTS_SQL)
            _migration_execute(self._connection, _LTFS_QUALIFICATION_STAGES_SQL)
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _migrate_version_four(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V4):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects():
            raise BrokerStateUnavailable
        if self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(self._connection, "PRAGMA user_version=5")
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise
        self._migrate_version_five()

    def _migrate_version_five(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V5):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects() or self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        old_rows = self._connection.execute(_LTFS_SESSION_SELECT_V5).fetchall()
        old_observations = self._connection.execute(_LTFS_OBSERVATION_SELECT).fetchall()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(self._connection, "DROP TABLE ltfs_observations")
            _migration_execute(
                self._connection,
                "ALTER TABLE ltfs_sessions RENAME TO ltfs_sessions_v5",
            )
            _migration_execute(self._connection, _LTFS_SESSIONS_SQL)
            insert_sql = (
                "INSERT INTO ltfs_sessions VALUES("
                + ",".join("?" for _field in range(40))
                + ")"
            )
            for row in old_rows:
                if len(row) != 31:
                    raise BrokerStateUnavailable
                self._connection.execute(insert_sql, _upgrade_ltfs_v5_row(row))
            _migration_execute(self._connection, "DROP TABLE ltfs_sessions_v5")
            _migration_execute(self._connection, _LTFS_OBSERVATIONS_SQL)
            _migration_execute(self._connection, _LTFS_CHILD_EXIT_RECEIPTS_SQL)
            _migration_execute(self._connection, _LTFS_QUALIFICATION_STAGES_SQL)
            for observation in old_observations:
                self._connection.execute(
                    "INSERT INTO ltfs_observations VALUES(?,?,?,?,?,?,?)",
                    observation,
                )
            for row in self._connection.execute(_LTFS_SESSION_SELECT).fetchall():
                record = _ltfs_session_from_row(row)
                seal = _ltfs_record_sha256(
                    record, self._ltfs_observations_for_session(record)
                )
                self._connection.execute(
                    "UPDATE ltfs_sessions SET immutable_sha256=? "
                    "WHERE operation_id=? AND owner_generation=?",
                    (seal, record.operation_id, record.owner_generation),
                )
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _migrate_version_six(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V6):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects() or self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        old_rows = self._connection.execute(_LTFS_SESSION_SELECT_V6).fetchall()
        old_observations = self._connection.execute(_LTFS_OBSERVATION_SELECT).fetchall()
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(self._connection, "DROP TABLE ltfs_observations")
            _migration_execute(
                self._connection,
                "ALTER TABLE ltfs_sessions RENAME TO ltfs_sessions_v6",
            )
            _migration_execute(self._connection, _LTFS_SESSIONS_SQL)
            insert_sql = (
                "INSERT INTO ltfs_sessions VALUES("
                + ",".join("?" for _field in range(40))
                + ")"
            )
            for row in old_rows:
                self._connection.execute(insert_sql, _upgrade_ltfs_v6_row(row))
            _migration_execute(self._connection, "DROP TABLE ltfs_sessions_v6")
            _migration_execute(self._connection, _LTFS_OBSERVATIONS_SQL)
            _migration_execute(self._connection, _LTFS_CHILD_EXIT_RECEIPTS_SQL)
            _migration_execute(self._connection, _LTFS_QUALIFICATION_STAGES_SQL)
            for observation in old_observations:
                self._connection.execute(
                    "INSERT INTO ltfs_observations VALUES(?,?,?,?,?,?,?)",
                    observation,
                )
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _migrate_version_seven(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V7):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects() or self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(self._connection, _LTFS_CHILD_EXIT_RECEIPTS_SQL)
            _migration_execute(self._connection, _LTFS_QUALIFICATION_STAGES_SQL)
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _migrate_version_eight(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V8):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects() or self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(self._connection, _LTFS_QUALIFICATION_STAGES_SQL)
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _migrate_version_nine(self) -> None:
        if self._schema_objects() != self._expected_schema(_SCHEMA_V9):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects() or self.pragma("integrity_check") != "ok":
            raise BrokerStateUnavailable
        count = self._connection.execute(
            "SELECT COUNT(*) FROM ltfs_qualification_stages"
        ).fetchone()
        if count != (0,):
            raise BrokerStateUnavailable
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            _migration_execute(self._connection, "DROP TABLE ltfs_qualification_stages")
            _migration_execute(self._connection, _LTFS_QUALIFICATION_STAGES_SQL)
            _migration_execute(
                self._connection, f"PRAGMA user_version={SCHEMA_VERSION}"
            )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def _schema_objects(self) -> dict[str, str]:
        rows = self._connection.execute(
            "SELECT name, sql FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return {name: _normalize_sql(sql) for name, sql in rows}

    @staticmethod
    def _expected_schema(statements: tuple[str, ...]) -> dict[str, str]:
        expected = {}
        for statement in statements:
            name = statement.split("CREATE TABLE ", 1)[1].split("(", 1)[0].strip()
            expected[name] = _normalize_sql(statement)
        return expected

    def _unexpected_schema_objects(self) -> list[tuple[object, ...]]:
        return self._connection.execute(
            "SELECT type,name FROM sqlite_master "
            "WHERE type!='table' AND name NOT LIKE 'sqlite_%' AND sql IS NOT NULL"
        ).fetchall()

    def _validate_schema(self) -> None:
        version = self._connection.execute("PRAGMA user_version").fetchone()
        if version != (SCHEMA_VERSION,):
            raise BrokerStateUnavailable
        if self._schema_objects() != self._expected_schema(_SCHEMA):
            raise BrokerStateUnavailable
        if self._unexpected_schema_objects():
            raise BrokerStateUnavailable
        foreign_keys = self._connection.execute("PRAGMA foreign_keys").fetchone()
        if foreign_keys != (1,):
            raise BrokerStateUnavailable
        if self._connection.execute("PRAGMA foreign_key_check").fetchall():
            raise BrokerStateUnavailable

    def _validate_rows(self, *, seal_version: int = 2) -> None:
        scope_rows = self._connection.execute(_SCOPE_SELECT).fetchall()
        scopes: dict[str, ScopeRecord] = {}
        for row in scope_rows:
            scope = _scope_from_row(row)
            scopes[scope.scope_id] = scope
        permit_rows = self._connection.execute(
            "SELECT permit_sha256,scope_id,pid,state,permit_json,prepared_at,terminal_at "
            "FROM permits"
        ).fetchall()
        permit_scopes: set[str] = set()
        for row in permit_rows:
            permit = self._permit_from_row(row)
            scope = scopes.get(permit.scope_id)
            permit_identity = json.loads(permit.permit_json)
            if (
                scope is None
                or scope.pid != permit.pid
                or permit.scope_id in permit_scopes
                or permit_identity["command_id"] != scope.command_id
                or permit_identity["owner_generation"] != scope.owner_generation
                or permit_identity["scope_path_sha256"] != scope.scope_path_sha256
                or (permit.state == "PREPARED" and scope.state != "ACTIVE")
            ):
                raise BrokerStateUnavailable
            permit_scopes.add(permit.scope_id)
        nonce_rows = self._connection.execute(
            "SELECT domain,nonce_sha256,recorded_at FROM replay_nonces"
        ).fetchall()
        for domain, nonce_sha256, recorded_at in nonce_rows:
            if (
                domain not in _NONCE_DOMAINS
                or not _is_digest(nonce_sha256)
                or _validate_timestamp(recorded_at) != recorded_at
            ):
                raise BrokerStateUnavailable
        ltfs_rows = self._connection.execute(_LTFS_SESSION_SELECT).fetchall()
        active_sessions = 0
        seen_ltfs_opaque: set[bytes] = set()
        sessions: dict[tuple[str, int], LtfsSessionRecord] = {}
        for row in ltfs_rows:
            session = _ltfs_session_from_row(row)
            scope = scopes.get(session.cgroup_scope_id)
            if (
                scope is None
                or scope.owner_generation != session.owner_generation
                or scope.cgroup_device is None
                or scope.cgroup_inode is None
                or (
                    session.state in _ACTIVE_LTFS_SESSION_STATES
                    and (scope.state != "ACTIVE" or session.boot_id != scope.boot_id)
                )
            ):
                raise BrokerStateUnavailable
            if session.state in _ACTIVE_LTFS_SESSION_STATES:
                active_sessions += 1
            opaque_values = _ltfs_opaque_values(session)
            if seen_ltfs_opaque & opaque_values:
                raise BrokerStateUnavailable
            seen_ltfs_opaque.update(opaque_values)
            sessions[(session.operation_id, session.owner_generation)] = session
        if active_sessions > 1:
            raise BrokerStateUnavailable
        exit_rows = self._connection.execute(
            "SELECT operation_id,owner_generation,child_exit_code,exit_observed_at "
            "FROM ltfs_child_exit_receipts"
        ).fetchall()
        for operation_id, owner_generation, exit_code, exit_observed_at in exit_rows:
            session = sessions.get((operation_id, owner_generation))
            checked_exit_at = _validate_timestamp(exit_observed_at)
            if (
                session is None
                or exit_code != 0
                or session.state not in {"FINALIZING", "UNMOUNTED", "BROKEN"}
                or session.finalizing_at is None
                or checked_exit_at < session.finalizing_at
            ):
                raise BrokerStateUnavailable
        observation_rows = self._connection.execute(_LTFS_OBSERVATION_SELECT).fetchall()
        observations_by_session: dict[tuple[str, int], list[LtfsObservationRecord]] = {}
        for row in observation_rows:
            observation = _ltfs_observation_from_row(row)
            session = sessions.get(
                (observation.operation_id, observation.owner_generation)
            )
            opaque_values = frozenset(
                {
                    observation.challenge,
                    observation.observation_nonce,
                    observation.broker_proof,
                }
            )
            if (
                session is None
                or session.session_id != observation.session_id
                or session.state == "STARTING"
                or session.mounted_at is None
                or observation.observed_at < session.mounted_at
                or seen_ltfs_opaque & opaque_values
            ):
                raise BrokerStateUnavailable
            seen_ltfs_opaque.update(opaque_values)
            observations_by_session.setdefault(
                (observation.operation_id, observation.owner_generation), []
            ).append(observation)
        for key, session in sessions.items():
            expected_seal = (
                _ltfs_legacy_sha256(session)
                if seal_version == 1
                else _ltfs_record_sha256(
                    session, tuple(observations_by_session.get(key, ()))
                )
            )
            if session.immutable_sha256 != expected_seal:
                raise BrokerStateUnavailable
        qualification_rows = self._connection.execute(
            _QUALIFICATION_STAGE_SELECT
        ).fetchall()
        seen_qualification_opaque: set[bytes] = set()
        for row in qualification_rows:
            stage = _qualification_stage_from_row(row)
            opaque = {stage.request_nonce}
            if stage.broker_nonce is not None:
                opaque.add(stage.broker_nonce)
            if stage.broker_proof is not None:
                opaque.add(stage.broker_proof)
            if seen_qualification_opaque & opaque:
                raise BrokerStateUnavailable
            seen_qualification_opaque.update(opaque)

    def _recover_boot_change(self) -> None:
        scope_rows = self._connection.execute(
            _SCOPE_SELECT + " WHERE s.state='ACTIVE' AND s.boot_id!=?",
            (self._boot_id,),
        ).fetchall()
        session_rows = self._connection.execute(
            _LTFS_SESSION_SELECT
            + " WHERE state IN ('STARTING','MOUNTED','FINALIZING') AND boot_id!=?",
            (self._boot_id,),
        ).fetchall()
        qualification_rows = self._connection.execute(
            _QUALIFICATION_STAGE_SELECT + " WHERE state IN ('PREPARED','DISPATCHED')",
        ).fetchall()
        if not scope_rows and not session_rows and not qualification_rows:
            return
        for row in scope_rows:
            _scope_from_row(row)
        sessions = tuple(_ltfs_session_from_row(row) for row in session_rows)
        qualifications = tuple(
            _qualification_stage_from_row(row) for row in qualification_rows
        )
        terminal_at = self._now()
        if any(
            terminal_at
            < (session.finalizing_at or session.mounted_at or session.created_at)
            for session in sessions
        ) or any(
            terminal_at < (qualification.dispatched_at or qualification.created_at)
            for qualification in qualifications
        ):
            raise BrokerStateUnavailable
        prepared_rows = self._connection.execute(
            "SELECT p.prepared_at FROM permits AS p JOIN scopes AS s "
            "ON s.scope_id=p.scope_id WHERE p.state='PREPARED' "
            "AND s.state='ACTIVE' AND s.boot_id!=?",
            (self._boot_id,),
        ).fetchall()
        if any(
            terminal_at < _validate_timestamp(prepared_at)
            for (prepared_at,) in prepared_rows
        ):
            raise BrokerStateUnavailable
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            self._connection.execute(
                "UPDATE permits SET state='REVOKED',terminal_at=? "
                "WHERE state='PREPARED' AND scope_id IN "
                "(SELECT scope_id FROM scopes WHERE state='ACTIVE' AND boot_id!=?)",
                (terminal_at, self._boot_id),
            )
            self._connection.execute(
                "UPDATE scopes SET state='BROKEN' WHERE state='ACTIVE' AND boot_id!=?",
                (self._boot_id,),
            )
            for session in sessions:
                self._update_ltfs_record(
                    session, state="BROKEN", terminal_at=terminal_at
                )
            for qualification in qualifications:
                self._connection.execute(
                    "UPDATE ltfs_qualification_stages SET state='FENCED',terminal_at=? "
                    "WHERE run_id=? AND stage_ordinal=? "
                    "AND state IN ('PREPARED','DISPATCHED')",
                    (
                        terminal_at,
                        qualification.run_id,
                        qualification.stage_ordinal,
                    ),
                )
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    @staticmethod
    def _permit_from_row(row: tuple[object, ...]) -> PermitRecord:
        if len(row) != 7:
            raise BrokerStateUnavailable
        (
            permit_sha256,
            scope_id,
            pid,
            state_value,
            permit_json,
            prepared_at,
            terminal_at,
        ) = row
        if (
            not _is_digest(permit_sha256)
            or not _is_identity(scope_id)
            or type(pid) is not int
            or not 0 < pid < 1 << 31
            or type(state_value) is not str
            or state_value not in _PERMIT_STATES
            or (state_value in _TERMINAL_PERMIT_STATES) != (terminal_at is not None)
        ):
            raise BrokerStateUnavailable
        checked_permit_json = _validate_stored_permit_json(
            permit_json, permit_sha256, scope_id, pid
        )
        checked_prepared_at = _validate_timestamp(prepared_at)
        checked_terminal_at = (
            None if terminal_at is None else _validate_timestamp(terminal_at)
        )
        if (
            checked_terminal_at is not None
            and checked_terminal_at < checked_prepared_at
        ):
            raise BrokerStateUnavailable
        return PermitRecord(
            permit_sha256=permit_sha256,
            scope_id=scope_id,
            pid=pid,
            state=state_value,
            permit_json=checked_permit_json,
            prepared_at=checked_prepared_at,
            terminal_at=checked_terminal_at,
        )

    def pragma(self, name: str) -> object:
        if name not in {
            "foreign_keys",
            "journal_mode",
            "synchronous",
            "integrity_check",
            "user_version",
        }:
            raise BrokerStateUnavailable
        with self._lock:
            self._assert_open()
            try:
                row = self._connection.execute(f"PRAGMA {name}").fetchone()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        if row is None or len(row) != 1:
            raise BrokerStateUnavailable
        return row[0]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            with contextlib.suppress(sqlite3.Error):
                self._connection.close()
            with contextlib.suppress(OSError):
                os.close(self._database_fd)

    def __enter__(self) -> Self:
        self._assert_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _assert_open(self) -> None:
        if self._closed:
            raise BrokerStateUnavailable

    def _now(self) -> str:
        try:
            return _validate_timestamp(self._clock())
        except BrokerStateUnavailable:
            raise
        except Exception:  # noqa: BLE001 - redact the injected clock boundary
            raise BrokerStateUnavailable from None

    def _terminal_now(self, prepared_at: str) -> str:
        terminal_at = self._now()
        if terminal_at < prepared_at:
            raise BrokerStateUnavailable
        return terminal_at

    @contextlib.contextmanager
    def _transaction(self, *, durable: bool = False) -> Iterator[None]:
        with self._lock:
            self._assert_open()
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                yield
                self._connection.commit()
                if durable:
                    os.fsync(self._database_fd)
            except (BrokerStateConflict, BrokerStateUnavailable):
                with contextlib.suppress(sqlite3.Error):
                    self._connection.rollback()
                raise
            except (sqlite3.Error, OSError, ValueError, TypeError):
                with contextlib.suppress(sqlite3.Error):
                    self._connection.rollback()
                if durable:
                    self.close()
                raise BrokerStateUnavailable from None

    def create_scope(self, receipt: BrokeredCgroupScopeReceipt) -> ScopeRecord:
        checked = _validate_receipt(receipt)
        with self._transaction():
            row = self._select_scope(checked.scope_id)
            if row is not None:
                record = _scope_from_row(row)
                self._require_scope_match(record, checked)
                return record
            identity_row = self._connection.execute(
                "SELECT scope_id FROM scopes WHERE command_id=? AND owner_generation=?",
                (checked.command_id, checked.owner_generation),
            ).fetchone()
            if identity_row is not None:
                raise BrokerStateConflict
            created_at = self._now()
            self._connection.execute(
                "INSERT INTO scopes(scope_id,command_id,owner_generation,"
                "scope_path_sha256,boot_id,state,pid,process_start_ticks,created_at) "
                "VALUES(?,?,?,?,?,'ACTIVE',NULL,NULL,?)",
                (
                    checked.scope_id,
                    checked.command_id,
                    checked.owner_generation,
                    checked.scope_path_sha256,
                    self._boot_id,
                    created_at,
                ),
            )
            return ScopeRecord(
                checked.scope_id,
                checked.command_id,
                checked.owner_generation,
                checked.scope_path_sha256,
                self._boot_id,
                "ACTIVE",
                None,
                None,
                None,
                None,
                created_at,
            )

    def open_scope(self, receipt: BrokeredCgroupScopeReceipt) -> ScopeRecord:
        checked = _validate_receipt(receipt)
        with self._lock:
            self._assert_open()
            try:
                row = self._select_scope(checked.scope_id)
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
            if row is None:
                raise BrokerStateConflict
            record = _scope_from_row(row)
            self._require_scope_match(record, checked)
            return record

    def scope_for_identity(self, command_id: str, owner_generation: int) -> ScopeRecord:
        if (
            not _is_identity(command_id)
            or type(owner_generation) is not int
            or not 0 <= owner_generation < 1 << 63
        ):
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            try:
                rows = self._connection.execute(
                    _SCOPE_SELECT + " WHERE s.command_id=? AND s.owner_generation=?",
                    (command_id, owner_generation),
                ).fetchall()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
            if len(rows) != 1:
                raise BrokerStateConflict
            return _scope_from_row(rows[0])

    def bind_cgroup(
        self,
        record: ScopeRecord,
        *,
        device: int,
        inode: int,
    ) -> ScopeRecord:
        if (
            type(record) is not ScopeRecord
            or type(device) is not int
            or not 0 <= device < 1 << 63
            or type(inode) is not int
            or not 0 < inode < 1 << 63
        ):
            raise BrokerStateConflict
        with self._transaction():
            row = self._select_scope(record.scope_id)
            if row is None:
                raise BrokerStateConflict
            current = _scope_from_row(row)
            if (
                current.command_id != record.command_id
                or current.owner_generation != record.owner_generation
                or current.scope_path_sha256 != record.scope_path_sha256
                or current.boot_id != record.boot_id
                or current.state != record.state
                or current.pid != record.pid
                or current.process_start_ticks != record.process_start_ticks
                or current.state != "ACTIVE"
                or current.boot_id != self._boot_id
            ):
                raise BrokerStateConflict
            if current.cgroup_device is not None:
                if (current.cgroup_device, current.cgroup_inode) != (device, inode) or (
                    record.cgroup_device,
                    record.cgroup_inode,
                ) != (current.cgroup_device, current.cgroup_inode):
                    raise BrokerStateConflict
                return current
            if record.cgroup_device is not None or record.cgroup_inode is not None:
                raise BrokerStateConflict
            self._connection.execute(
                "INSERT INTO cgroup_bindings(scope_id,device,inode) VALUES(?,?,?)",
                (record.scope_id, device, inode),
            )
            return ScopeRecord(
                current.scope_id,
                current.command_id,
                current.owner_generation,
                current.scope_path_sha256,
                current.boot_id,
                current.state,
                current.pid,
                current.process_start_ticks,
                device,
                inode,
                current.created_at,
            )

    def require_cgroup_scope(self, record: ScopeRecord) -> ScopeRecord:
        if type(record) is not ScopeRecord:
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            try:
                row = self._select_scope(record.scope_id)
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
            if row is None:
                raise BrokerStateConflict
            current = _scope_from_row(row)
            if (
                current.command_id != record.command_id
                or current.owner_generation != record.owner_generation
                or current.scope_path_sha256 != record.scope_path_sha256
                or current.boot_id != record.boot_id
                or current.state != record.state
                or current.cgroup_device != record.cgroup_device
                or current.cgroup_inode != record.cgroup_inode
                or current.created_at != record.created_at
                or current.cgroup_device is None
                or (
                    record.pid is not None
                    and (current.pid, current.process_start_ticks)
                    != (record.pid, record.process_start_ticks)
                )
            ):
                raise BrokerStateConflict
            return current

    def attach_cgroup_process(
        self,
        record: ScopeRecord,
        *,
        pid: int,
        start_ticks: int,
    ) -> ScopeRecord:
        if (
            type(record) is not ScopeRecord
            or type(pid) is not int
            or not 0 < pid < 1 << 31
            or type(start_ticks) is not int
            or not 0 <= start_ticks < 1 << 63
        ):
            raise BrokerStateConflict
        with self._transaction():
            row = self._select_scope(record.scope_id)
            if row is None:
                raise BrokerStateConflict
            current = _scope_from_row(row)
            if (
                current != record
                or current.state != "ACTIVE"
                or current.boot_id != self._boot_id
                or current.cgroup_device is None
            ):
                raise BrokerStateConflict
            if current.pid is not None:
                if (current.pid, current.process_start_ticks) != (pid, start_ticks):
                    raise BrokerStateConflict
                return current
            self._connection.execute(
                "UPDATE scopes SET pid=?,process_start_ticks=? "
                "WHERE scope_id=? AND state='ACTIVE' AND pid IS NULL",
                (pid, start_ticks, current.scope_id),
            )
            return ScopeRecord(
                current.scope_id,
                current.command_id,
                current.owner_generation,
                current.scope_path_sha256,
                current.boot_id,
                current.state,
                pid,
                start_ticks,
                current.cgroup_device,
                current.cgroup_inode,
                current.created_at,
            )

    def break_cgroup_scope(self, record: ScopeRecord) -> ScopeRecord:
        if type(record) is not ScopeRecord or record.cgroup_device is None:
            raise BrokerStateConflict
        with self._transaction(durable=True):
            row = self._select_scope(record.scope_id)
            if row is None:
                raise BrokerStateConflict
            current = _scope_from_row(row)
            if (
                current.command_id != record.command_id
                or current.owner_generation != record.owner_generation
                or current.scope_path_sha256 != record.scope_path_sha256
                or current.boot_id != record.boot_id
                or current.cgroup_device != record.cgroup_device
                or current.cgroup_inode != record.cgroup_inode
                or current.boot_id != self._boot_id
                or current.state not in {"ACTIVE", "BROKEN"}
            ):
                raise BrokerStateConflict
            if current.state == "BROKEN":
                return current
            self._break_linked_ltfs_session(current.scope_id)
            self._connection.execute(
                "UPDATE scopes SET state='BROKEN' WHERE scope_id=? AND state='ACTIVE'",
                (current.scope_id,),
            )
            return ScopeRecord(
                current.scope_id,
                current.command_id,
                current.owner_generation,
                current.scope_path_sha256,
                current.boot_id,
                "BROKEN",
                current.pid,
                current.process_start_ticks,
                current.cgroup_device,
                current.cgroup_inode,
                current.created_at,
            )

    def _select_scope(self, scope_id: str) -> tuple[object, ...] | None:
        return self._connection.execute(
            _SCOPE_SELECT + " WHERE s.scope_id=?",
            (scope_id,),
        ).fetchone()

    @staticmethod
    def _require_scope_match(
        record: ScopeRecord, receipt: BrokeredCgroupScopeReceipt
    ) -> None:
        if (
            record.command_id != receipt.command_id
            or record.owner_generation != receipt.owner_generation
            or record.scope_path_sha256 != receipt.scope_path_sha256
        ):
            raise BrokerStateConflict

    def revoke_scope_prepared_permits(
        self, receipt: BrokeredCgroupScopeReceipt
    ) -> None:
        """Retire unknown preparation after the broker proves the scope empty.

        The service holds its command lifecycle lock across that proof, this
        durable transition, cgroup removal and closure. A lost prepare response
        cannot supply a permit digest; only the exact scope is available.
        """
        checked = _validate_receipt(receipt)
        with self._transaction(durable=True):
            row = self._select_scope(checked.scope_id)
            if row is None:
                raise BrokerStateConflict
            record = _scope_from_row(row)
            self._require_scope_match(record, checked)
            if record.state != "ACTIVE" or record.boot_id != self._boot_id:
                raise BrokerStateConflict
            active_ltfs = self._connection.execute(
                "SELECT 1 FROM ltfs_sessions WHERE cgroup_scope_id=? "
                "AND state IN ('STARTING','MOUNTED','FINALIZING') LIMIT 1",
                (checked.scope_id,),
            ).fetchone()
            if active_ltfs is not None:
                raise BrokerStateConflict
            permits = self._connection.execute(
                "SELECT permit_sha256,scope_id,pid,state,permit_json,prepared_at,"
                "terminal_at FROM permits WHERE scope_id=?",
                (checked.scope_id,),
            ).fetchall()
            if len(permits) > 1:
                raise BrokerStateConflict
            for permit_row in permits:
                permit = self._permit_from_row(permit_row)
                if permit.pid != record.pid or not self._permit_json_matches_receipt(
                    permit.permit_json, checked, permit.pid
                ):
                    raise BrokerStateConflict
                if permit.state == "PREPARED":
                    terminal_at = self._terminal_now(permit.prepared_at)
                    self._connection.execute(
                        "UPDATE permits SET state='REVOKED',terminal_at=? "
                        "WHERE permit_sha256=? AND state='PREPARED'",
                        (terminal_at, permit.permit_sha256),
                    )

    def mark_scope(
        self, receipt: BrokeredCgroupScopeReceipt, state: ScopeState
    ) -> ScopeRecord:
        checked = _validate_receipt(receipt)
        if type(state) is not str or state not in _TERMINAL_SCOPE_STATES:
            raise BrokerStateConflict
        with self._transaction(durable=True):
            row = self._select_scope(checked.scope_id)
            if row is None:
                raise BrokerStateConflict
            record = _scope_from_row(row)
            self._require_scope_match(record, checked)
            if record.state == state:
                return record
            if record.state != "ACTIVE":
                raise BrokerStateConflict
            if state == "CLOSED":
                prepared = self._connection.execute(
                    "SELECT 1 FROM permits WHERE scope_id=? AND state='PREPARED'",
                    (checked.scope_id,),
                ).fetchone()
                active_ltfs = self._connection.execute(
                    "SELECT 1 FROM ltfs_sessions WHERE cgroup_scope_id=? "
                    "AND state IN ('STARTING','MOUNTED','FINALIZING') LIMIT 1",
                    (checked.scope_id,),
                ).fetchone()
                if prepared is not None or active_ltfs is not None:
                    raise BrokerStateConflict
            else:
                self._break_linked_ltfs_session(checked.scope_id)
            self._connection.execute(
                "UPDATE scopes SET state=? WHERE scope_id=? AND state='ACTIVE'",
                (state, checked.scope_id),
            )
            return ScopeRecord(
                record.scope_id,
                record.command_id,
                record.owner_generation,
                record.scope_path_sha256,
                record.boot_id,
                state,
                record.pid,
                record.process_start_ticks,
                record.cgroup_device,
                record.cgroup_inode,
                record.created_at,
            )

    def attach_process(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        process_start_ticks: int,
    ) -> ScopeRecord:
        checked = _validate_receipt(receipt)
        if (
            type(pid) is not int
            or not 0 < pid < 1 << 31
            or type(process_start_ticks) is not int
            or process_start_ticks < 0
        ):
            raise BrokerStateConflict
        with self._transaction():
            row = self._select_scope(checked.scope_id)
            if row is None:
                raise BrokerStateConflict
            record = _scope_from_row(row)
            self._require_scope_match(record, checked)
            if record.state != "ACTIVE" or record.boot_id != self._boot_id:
                raise BrokerStateConflict
            if record.pid is not None:
                if (record.pid, record.process_start_ticks) != (
                    pid,
                    process_start_ticks,
                ):
                    raise BrokerStateConflict
                return record
            self._connection.execute(
                "UPDATE scopes SET pid=?,process_start_ticks=? "
                "WHERE scope_id=? AND state='ACTIVE' AND pid IS NULL",
                (pid, process_start_ticks, checked.scope_id),
            )
            return ScopeRecord(
                record.scope_id,
                record.command_id,
                record.owner_generation,
                record.scope_path_sha256,
                record.boot_id,
                record.state,
                pid,
                process_start_ticks,
                record.cgroup_device,
                record.cgroup_inode,
                record.created_at,
            )

    def prepare_permit(self, permit: BrokeredCgroupReleasePermit) -> PermitRecord:
        checked = _validate_permit(permit)
        canonical_json = _canonical_permit_json(checked)
        digest = hashlib.sha256(
            b"lto-broker-release-v1\0" + canonical_json.encode("ascii")
        ).hexdigest()
        with self._transaction():
            scope_row = self._select_scope(checked.receipt.scope_id)
            if scope_row is None:
                raise BrokerStateConflict
            scope = _scope_from_row(scope_row)
            self._require_scope_match(scope, checked.receipt)
            if (
                scope.state != "ACTIVE"
                or scope.boot_id != self._boot_id
                or scope.pid != checked.pid
            ):
                raise BrokerStateConflict
            existing_scope_permit = self._connection.execute(
                "SELECT permit_sha256,scope_id,pid,state,permit_json,prepared_at,"
                "terminal_at FROM permits WHERE scope_id=?",
                (scope.scope_id,),
            ).fetchone()
            if existing_scope_permit is not None:
                record = self._permit_from_row(existing_scope_permit)
                if (
                    record.permit_sha256 != digest
                    or record.pid != checked.pid
                    or record.permit_json != canonical_json
                ):
                    raise BrokerStateConflict
                return record
            prepared_at = self._now()
            self._connection.execute(
                "INSERT INTO permits(permit_sha256,scope_id,pid,state,permit_json,"
                "prepared_at,terminal_at) VALUES(?,?,?,'PREPARED',?,?,NULL)",
                (digest, scope.scope_id, checked.pid, canonical_json, prepared_at),
            )
            return PermitRecord(
                digest,
                scope.scope_id,
                checked.pid,
                "PREPARED",
                canonical_json,
                prepared_at,
                None,
            )

    def commit_release(
        self,
        permit: BrokeredCgroupReleasePermit,
        expected_permit_sha256: str,
    ) -> PermitTransition:
        checked = _validate_permit(permit)
        if not _is_digest(expected_permit_sha256):
            raise BrokerStateConflict
        canonical_json = _canonical_permit_json(checked)
        digest = hashlib.sha256(
            b"lto-broker-release-v1\0" + canonical_json.encode("ascii")
        ).hexdigest()
        if digest != expected_permit_sha256:
            raise BrokerStateConflict
        with self._transaction():
            record = self._select_permit(digest)
            self._require_permit_match(record, checked, canonical_json)
            if record.state == "RELEASE_COMMITTED":
                return PermitTransition(record, False)
            if record.state != "PREPARED":
                raise BrokerStateConflict
            scope_row = self._select_scope(checked.receipt.scope_id)
            if scope_row is None:
                raise BrokerStateConflict
            scope = _scope_from_row(scope_row)
            self._require_scope_match(scope, checked.receipt)
            if scope.state != "ACTIVE" or scope.boot_id != self._boot_id:
                raise BrokerStateConflict
            terminal_at = self._terminal_now(record.prepared_at)
            cursor = self._connection.execute(
                "UPDATE permits SET state='RELEASE_COMMITTED',terminal_at=? "
                "WHERE permit_sha256=? AND state='PREPARED'",
                (terminal_at, digest),
            )
            if cursor.rowcount != 1:
                raise BrokerStateConflict
            return PermitTransition(
                PermitRecord(
                    record.permit_sha256,
                    record.scope_id,
                    record.pid,
                    "RELEASE_COMMITTED",
                    record.permit_json,
                    record.prepared_at,
                    terminal_at,
                ),
                True,
            )

    def claim_or_observe(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        expected_permit_sha256: str,
    ) -> PermitTransition:
        checked = _validate_receipt(receipt)
        if (
            type(pid) is not int
            or not 0 < pid < 1 << 31
            or not _is_digest(expected_permit_sha256)
        ):
            raise BrokerStateConflict
        with self._transaction():
            record = self._select_permit(expected_permit_sha256)
            if record.pid != pid or record.scope_id != checked.scope_id:
                raise BrokerStateConflict
            scope_row = self._select_scope(checked.scope_id)
            if scope_row is None:
                raise BrokerStateConflict
            scope = _scope_from_row(scope_row)
            self._require_scope_match(scope, checked)
            if not self._permit_json_matches_receipt(record.permit_json, checked, pid):
                raise BrokerStateConflict
            if record.state in _TERMINAL_PERMIT_STATES:
                return PermitTransition(record, False)
            if record.state != "PREPARED":
                raise BrokerStateConflict
            terminal_at = self._terminal_now(record.prepared_at)
            cursor = self._connection.execute(
                "UPDATE permits SET state='REVOKED',terminal_at=? "
                "WHERE permit_sha256=? AND state='PREPARED'",
                (terminal_at, expected_permit_sha256),
            )
            if cursor.rowcount != 1:
                raise BrokerStateConflict
            return PermitTransition(
                PermitRecord(
                    record.permit_sha256,
                    record.scope_id,
                    record.pid,
                    "REVOKED",
                    record.permit_json,
                    record.prepared_at,
                    terminal_at,
                ),
                True,
            )

    def _select_permit(self, digest: str) -> PermitRecord:
        row = self._connection.execute(
            "SELECT permit_sha256,scope_id,pid,state,permit_json,prepared_at,terminal_at "
            "FROM permits WHERE permit_sha256=?",
            (digest,),
        ).fetchone()
        if row is None:
            raise BrokerStateConflict
        return self._permit_from_row(row)

    @staticmethod
    def _require_permit_match(
        record: PermitRecord,
        permit: BrokeredCgroupReleasePermit,
        canonical_json: str,
    ) -> None:
        if (
            record.scope_id != permit.receipt.scope_id
            or record.pid != permit.pid
            or record.permit_json != canonical_json
        ):
            raise BrokerStateConflict

    @staticmethod
    def _permit_json_matches_receipt(
        permit_json: str,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
    ) -> bool:
        try:
            value = json.loads(permit_json)
        except (json.JSONDecodeError, TypeError):
            raise BrokerStateUnavailable from None
        if type(value) is not dict:
            raise BrokerStateUnavailable
        expected = {
            "protocol_version": 1,
            "command_id": receipt.command_id,
            "owner_generation": receipt.owner_generation,
            "scope_id": receipt.scope_id,
            "scope_path_sha256": receipt.scope_path_sha256,
            "pid": pid,
        }
        return all(
            value.get(key) == expected_value for key, expected_value in expected.items()
        )

    def record_nonce(self, domain: str, nonce: bytes) -> str:
        if domain not in _NONCE_DOMAINS or not _is_opaque(nonce):
            raise BrokerStateConflict
        digest = hashlib.sha256(
            b"lto-broker-replay-nonce-v1\0" + domain.encode("ascii") + b"\0" + nonce
        ).hexdigest()
        with self._transaction():
            try:
                self._connection.execute(
                    "INSERT INTO replay_nonces(domain,nonce_sha256,recorded_at) "
                    "VALUES(?,?,?)",
                    (domain, digest, self._now()),
                )
            except sqlite3.IntegrityError:
                raise BrokerStateConflict from None
        return digest

    def permit_for_reconciliation(self, digest: str) -> PermitRecord:
        if not _is_digest(digest):
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            try:
                return self._select_permit(digest)
            except sqlite3.Error:
                raise BrokerStateUnavailable from None

    def scopes_for_reconciliation(self) -> tuple[ScopeRecord, ...]:
        with self._lock:
            self._assert_open()
            try:
                rows = self._connection.execute(
                    _SCOPE_SELECT + " ORDER BY s.scope_id"
                ).fetchall()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        return tuple(_scope_from_row(row) for row in rows)

    def permits_for_reconciliation(self) -> tuple[PermitRecord, ...]:
        with self._lock:
            self._assert_open()
            try:
                rows = self._connection.execute(
                    "SELECT permit_sha256,scope_id,pid,state,permit_json,prepared_at,"
                    "terminal_at FROM permits ORDER BY permit_sha256"
                ).fetchall()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        return tuple(self._permit_from_row(row) for row in rows)

    def _select_ltfs_qualification_stage(
        self, run_id: str, stage_ordinal: int
    ) -> tuple[object, ...] | None:
        return self._connection.execute(
            _QUALIFICATION_STAGE_SELECT + " WHERE run_id=? AND stage_ordinal=?",
            (run_id, stage_ordinal),
        ).fetchone()

    @staticmethod
    def _qualification_request_matches(
        record: QualificationStageRecord, request: BrokerQualificationRequest
    ) -> bool:
        values = _qualification_request_values(request)
        return (
            record.request_sha256 == request.request_sha256
            and record.immutable_sha256 == _qualification_immutable_sha256(values)
            and _qualification_record_values(record) == values
        )

    def prepare_ltfs_qualification(
        self, request: BrokerQualificationRequest
    ) -> QualificationStageTransition:
        values = _qualification_request_values(request)
        immutable = _qualification_immutable_sha256(values)
        with self._transaction(durable=True):
            existing = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if existing is not None:
                record = _qualification_stage_from_row(existing)
                if not self._qualification_request_matches(record, request):
                    raise BrokerStateConflict
                return QualificationStageTransition(record, False)
            request.require_execution_authority()
            unresolved = self._connection.execute(
                "SELECT 1 FROM ltfs_qualification_stages "
                "WHERE state IN ('PREPARED','DISPATCHED','FENCED') LIMIT 1"
            ).fetchone()
            if unresolved is not None:
                raise BrokerStateConflict
            created_at = self._now()
            try:
                self._connection.execute(
                    "INSERT INTO ltfs_qualification_stages("
                    "run_id,stage_ordinal,state,boot_id,request_sha256,immutable_sha256,"
                    "plan_sha256,operation,operation_token_sha256,"
                    "tape_device_identity_sha256,scsi_device_identity_sha256,"
                    "expected_media_scope_sha256,observed_media_identity_sha256,"
                    "expected_physical_label,expected_tape_serial,"
                    "expected_drive_serial,expected_drive_wwid,expected_volume_uuid,"
                    "expected_generation,request_nonce,terminal_receipt_sha256,"
                    "child_exit_code,evidence_sha256,broker_nonce,broker_proof,"
                    "created_at,dispatched_at,terminal_at) "
                    "VALUES(?,?,'PREPARED',?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,"
                    "NULL,NULL,NULL,NULL,NULL,?,NULL,NULL)",
                    (
                        request.run_id,
                        request.stage_ordinal,
                        self._boot_id,
                        request.request_sha256,
                        immutable,
                        request.plan_sha256,
                        request.operation.value,
                        values["operation_token_sha256"],
                        request.tape_device_identity_sha256,
                        request.scsi_device_identity_sha256,
                        request.expected_media_scope_sha256,
                        request.observed_media_identity_sha256,
                        request.expected_physical_label,
                        request.expected_tape_serial,
                        request.expected_drive_serial,
                        request.expected_drive_wwid,
                        request.expected_volume_uuid,
                        request.expected_generation,
                        request.request_nonce,
                        created_at,
                    ),
                )
            except sqlite3.IntegrityError:
                raise BrokerStateConflict from None
            row = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if row is None:
                raise BrokerStateUnavailable
            return QualificationStageTransition(
                _qualification_stage_from_row(row), True
            )

    def mark_ltfs_qualification_dispatched(
        self, request: BrokerQualificationRequest
    ) -> QualificationStageTransition:
        _qualification_request_values(request)
        with self._transaction(durable=True):
            row = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if row is None:
                raise BrokerStateConflict
            record = _qualification_stage_from_row(row)
            if not self._qualification_request_matches(record, request):
                raise BrokerStateConflict
            if record.state == "DISPATCHED":
                return QualificationStageTransition(record, False)
            if record.state != "PREPARED" or record.boot_id != self._boot_id:
                raise BrokerStateConflict
            request.require_execution_authority()
            dispatched_at = self._terminal_now(record.created_at)
            cursor = self._connection.execute(
                "UPDATE ltfs_qualification_stages SET state='DISPATCHED',"
                "dispatched_at=? WHERE run_id=? AND stage_ordinal=? "
                "AND state='PREPARED' AND boot_id=?",
                (
                    dispatched_at,
                    request.run_id,
                    request.stage_ordinal,
                    self._boot_id,
                ),
            )
            if cursor.rowcount != 1:
                raise BrokerStateConflict
            updated = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if updated is None:
                raise BrokerStateUnavailable
            return QualificationStageTransition(
                _qualification_stage_from_row(updated), True
            )

    def complete_ltfs_qualification(
        self,
        request: BrokerQualificationRequest,
        dispatch: BrokerQualificationDispatch,
    ) -> QualificationStageTransition:
        _qualification_request_values(request)
        if (
            type(dispatch) is not BrokerQualificationDispatch
            or dispatch.run_id != request.run_id
            or dispatch.stage_ordinal != request.stage_ordinal
            or dispatch.operation is not request.operation
            or dispatch.request_sha256 != request.request_sha256
            or dispatch.dispatch_state != "terminal"
        ):
            raise BrokerStateConflict
        with self._transaction(durable=True):
            row = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if row is None:
                raise BrokerStateConflict
            record = _qualification_stage_from_row(row)
            if not self._qualification_request_matches(record, request):
                raise BrokerStateConflict
            if record.state == "TERMINAL":
                if (
                    record.terminal_receipt_sha256 != dispatch.terminal_receipt_sha256
                    or record.child_exit_code != dispatch.child_exit_code
                    or record.evidence_sha256 != dispatch.evidence_sha256
                    or record.broker_nonce != dispatch.broker_nonce
                    or record.broker_proof != dispatch.broker_proof
                ):
                    raise BrokerStateConflict
                return QualificationStageTransition(record, False)
            if record.state != "DISPATCHED" or record.boot_id != self._boot_id:
                raise BrokerStateConflict
            terminal_at = self._terminal_now(record.dispatched_at or record.created_at)
            cursor = self._connection.execute(
                "UPDATE ltfs_qualification_stages SET state='TERMINAL',"
                "terminal_receipt_sha256=?,child_exit_code=?,evidence_sha256=?,"
                "broker_nonce=?,broker_proof=?,terminal_at=? "
                "WHERE run_id=? AND stage_ordinal=? AND state='DISPATCHED' AND boot_id=?",
                (
                    dispatch.terminal_receipt_sha256,
                    dispatch.child_exit_code,
                    dispatch.evidence_sha256,
                    dispatch.broker_nonce,
                    dispatch.broker_proof,
                    terminal_at,
                    request.run_id,
                    request.stage_ordinal,
                    self._boot_id,
                ),
            )
            if cursor.rowcount != 1:
                raise BrokerStateConflict
            updated = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if updated is None:
                raise BrokerStateUnavailable
            return QualificationStageTransition(
                _qualification_stage_from_row(updated), True
            )

    def fence_ltfs_qualification(
        self, request: BrokerQualificationRequest
    ) -> QualificationStageTransition:
        _qualification_request_values(request)
        with self._transaction(durable=True):
            row = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if row is None:
                raise BrokerStateConflict
            record = _qualification_stage_from_row(row)
            if not self._qualification_request_matches(record, request):
                raise BrokerStateConflict
            if record.state == "FENCED":
                return QualificationStageTransition(record, False)
            if record.state not in {"PREPARED", "DISPATCHED"}:
                raise BrokerStateConflict
            terminal_at = self._terminal_now(record.created_at)
            cursor = self._connection.execute(
                "UPDATE ltfs_qualification_stages SET state='FENCED',terminal_at=? "
                "WHERE run_id=? AND stage_ordinal=? "
                "AND state IN ('PREPARED','DISPATCHED')",
                (terminal_at, request.run_id, request.stage_ordinal),
            )
            if cursor.rowcount != 1:
                raise BrokerStateConflict
            updated = self._select_ltfs_qualification_stage(
                request.run_id, request.stage_ordinal
            )
            if updated is None:
                raise BrokerStateUnavailable
            return QualificationStageTransition(
                _qualification_stage_from_row(updated), True
            )

    def ltfs_qualification_stage(
        self, run_id: str, stage_ordinal: int
    ) -> QualificationStageRecord | None:
        if type(run_id) is not str or type(stage_ordinal) is not int:
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            try:
                row = self._select_ltfs_qualification_stage(run_id, stage_ordinal)
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        return None if row is None else _qualification_stage_from_row(row)

    def inspect_ltfs_qualification_stage(
        self, run_id: str, stage_ordinal: int
    ) -> MappingProxyType[str, object] | None:
        """Read one durable qualification stage without a state transition."""

        if (
            type(run_id) is not str
            or type(stage_ordinal) is not int
            or stage_ordinal < 1
        ):
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            try:
                row = self._select_ltfs_qualification_stage(run_id, stage_ordinal)
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        if row is None:
            return None
        return _qualification_inspection_snapshot(_qualification_stage_from_row(row))

    def _select_ltfs_session(
        self, operation_id: str, owner_generation: int
    ) -> tuple[object, ...] | None:
        return self._connection.execute(
            _LTFS_SESSION_SELECT + " WHERE operation_id=? AND owner_generation=?",
            (operation_id, owner_generation),
        ).fetchone()

    def _ltfs_observations_for_session(
        self, record: LtfsSessionRecord
    ) -> tuple[LtfsObservationRecord, ...]:
        rows = self._connection.execute(
            _LTFS_OBSERVATION_SELECT
            + " WHERE operation_id=? AND owner_generation=? ORDER BY challenge",
            (record.operation_id, record.owner_generation),
        ).fetchall()
        return tuple(_ltfs_observation_from_row(row) for row in rows)

    def _update_ltfs_record(
        self, record: LtfsSessionRecord, **changes: object
    ) -> LtfsSessionRecord:
        mutable_columns = frozenset(
            {
                "state",
                "child_pid",
                "child_start_ticks",
                "mount_namespace_sha256",
                "receipt_operation_uuid",
                "observed_volume_uuid",
                "observed_prior_generation",
                "observed_volume_label",
                "session_id",
                "session_broker_nonce",
                "session_broker_proof",
                "finalization_request_nonce",
                "finalization_nonce",
                "finalization_broker_proof",
                "standalone_receipt_json",
                "terminal_sha256",
                "standalone_bound_at",
                "mounted_at",
                "finalizing_at",
                "terminal_at",
            }
        )
        if not set(changes) <= mutable_columns:
            raise BrokerStateUnavailable
        candidate = replace(record, immutable_sha256="0" * 64, **changes)
        sealed = replace(
            candidate,
            immutable_sha256=_ltfs_record_sha256(
                candidate, self._ltfs_observations_for_session(candidate)
            ),
        )
        assignments = [f"{column}=?" for column in changes]
        assignments.append("immutable_sha256=?")
        values = [*changes.values(), sealed.immutable_sha256]
        self._connection.execute(
            "UPDATE ltfs_sessions SET "
            + ",".join(assignments)
            + " WHERE operation_id=? AND owner_generation=?",
            (*values, sealed.operation_id, sealed.owner_generation),
        )
        row = self._select_ltfs_session(sealed.operation_id, sealed.owner_generation)
        if row is None:
            raise BrokerStateUnavailable
        return _ltfs_session_from_row(row)

    @staticmethod
    def _ltfs_request_matches(
        record: LtfsSessionRecord,
        request: LtfsSessionRequest,
        request_sha256: str,
        *,
        ltfs_tool_identity_sha256: str | None = None,
        fusermount_tool_identity_sha256: str | None = None,
    ) -> bool:
        matches = (
            record.request_sha256 == request_sha256
            and record.mount_path_sha256 == request.mount_path_sha256
            and record.tape_device_identity_sha256
            == request.tape_device_identity_sha256
            and record.scsi_device_identity_sha256
            == request.scsi_device_identity_sha256
            and record.expected_media_scope_sha256
            == request.expected_media_scope_sha256
            and record.expected_volume_uuid == request.expected_volume_uuid
            and record.expected_prior_generation == request.expected_prior_generation
            and record.observed_media_identity_sha256
            == request.observed_media_identity_sha256
            and record.tape_fd_identity_sha256 == request.tape_fd_identity_sha256
            and record.scsi_fd_identity_sha256 == request.scsi_fd_identity_sha256
            and record.read_only is request.read_only
            and record.cgroup_scope_id == request.cgroup_scope_receipt.scope_id
            and record.start_request_nonce == request.request_nonce
        )
        if ltfs_tool_identity_sha256 is not None:
            matches = (
                matches
                and record.ltfs_tool_identity_sha256 == ltfs_tool_identity_sha256
                and record.fusermount_tool_identity_sha256
                == fusermount_tool_identity_sha256
            )
        return matches

    def _mark_ltfs_broken(self, record: LtfsSessionRecord) -> LtfsSessionRecord:
        if record.state == "BROKEN":
            return record
        if record.state == "UNMOUNTED":
            terminal_at = record.terminal_at
        else:
            last_at = record.finalizing_at or record.mounted_at or record.created_at
            terminal_at = self._terminal_now(last_at)
        return self._update_ltfs_record(record, state="BROKEN", terminal_at=terminal_at)

    def _break_linked_ltfs_session(self, scope_id: str) -> None:
        rows = self._connection.execute(
            _LTFS_SESSION_SELECT + " WHERE cgroup_scope_id=? "
            "AND state IN ('STARTING','MOUNTED','FINALIZING')",
            (scope_id,),
        ).fetchall()
        if len(rows) > 1:
            raise BrokerStateUnavailable
        if rows:
            self._mark_ltfs_broken(_ltfs_session_from_row(rows[0]))

    def _ltfs_opaque_conflicts(
        self,
        values: frozenset[bytes],
        *,
        exclude: tuple[str, int] | None = None,
    ) -> bool:
        for row in self._connection.execute(_LTFS_SESSION_SELECT).fetchall():
            record = _ltfs_session_from_row(row)
            if exclude == (record.operation_id, record.owner_generation):
                continue
            if values & _ltfs_opaque_values(record):
                return True
        for row in self._connection.execute(_LTFS_OBSERVATION_SELECT).fetchall():
            observation = _ltfs_observation_from_row(row)
            if values & {
                observation.challenge,
                observation.observation_nonce,
                observation.broker_proof,
            }:
                return True
        return False

    def begin_ltfs_session(
        self,
        request: LtfsSessionRequest,
        ltfs_tool_identity_sha256: str,
        fusermount_tool_identity_sha256: str,
    ) -> LtfsSessionTransition:
        checked, request_digest = _validate_ltfs_request(request)
        if (
            not _is_digest(ltfs_tool_identity_sha256)
            or not _is_digest(fusermount_tool_identity_sha256)
            or ltfs_tool_identity_sha256 == fusermount_tool_identity_sha256
        ):
            raise BrokerStateConflict
        conflict = False
        result: LtfsSessionTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            if row is not None:
                record = _ltfs_session_from_row(row)
                if record.state == "BROKEN" or not self._ltfs_request_matches(
                    record,
                    checked,
                    request_digest,
                    ltfs_tool_identity_sha256=ltfs_tool_identity_sha256,
                    fusermount_tool_identity_sha256=fusermount_tool_identity_sha256,
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                    result = LtfsSessionTransition(record, False)
                else:
                    result = LtfsSessionTransition(record, False)
            else:
                scope_row = self._select_scope(checked.cgroup_scope_receipt.scope_id)
                if scope_row is None:
                    conflict = True
                    scope = None
                else:
                    scope = _scope_from_row(scope_row)
                    self._require_scope_match(scope, checked.cgroup_scope_receipt)
                blocked = self._connection.execute(
                    "SELECT 1 FROM ltfs_sessions WHERE state!='UNMOUNTED' LIMIT 1"
                ).fetchone()
                if (
                    conflict
                    or scope is None
                    or scope.state != "ACTIVE"
                    or scope.boot_id != self._boot_id
                    or scope.cgroup_device is None
                    or scope.cgroup_inode is None
                    or blocked is not None
                    or self._ltfs_opaque_conflicts(frozenset({checked.request_nonce}))
                ):
                    conflict = True
                else:
                    created_at = self._now()
                    candidate = LtfsSessionRecord(
                        operation_id=checked.operation_id,
                        owner_generation=checked.owner_generation,
                        state="STARTING",
                        boot_id=self._boot_id,
                        request_sha256=request_digest,
                        immutable_sha256="0" * 64,
                        mount_path_sha256=checked.mount_path_sha256,
                        tape_device_identity_sha256=checked.tape_device_identity_sha256,
                        scsi_device_identity_sha256=checked.scsi_device_identity_sha256,
                        expected_media_scope_sha256=checked.expected_media_scope_sha256,
                        expected_volume_uuid=checked.expected_volume_uuid,
                        expected_prior_generation=checked.expected_prior_generation,
                        receipt_operation_uuid=None,
                        observed_volume_uuid=None,
                        observed_prior_generation=None,
                        observed_volume_label=None,
                        observed_media_identity_sha256=checked.observed_media_identity_sha256,
                        tape_fd_identity_sha256=checked.tape_fd_identity_sha256,
                        scsi_fd_identity_sha256=checked.scsi_fd_identity_sha256,
                        read_only=checked.read_only,
                        ltfs_tool_identity_sha256=ltfs_tool_identity_sha256,
                        fusermount_tool_identity_sha256=fusermount_tool_identity_sha256,
                        cgroup_scope_id=checked.cgroup_scope_receipt.scope_id,
                        child_pid=None,
                        child_start_ticks=None,
                        mount_namespace_sha256=None,
                        start_request_nonce=checked.request_nonce,
                        session_id=None,
                        session_broker_nonce=None,
                        session_broker_proof=None,
                        finalization_request_nonce=None,
                        finalization_nonce=None,
                        finalization_broker_proof=None,
                        standalone_receipt_json=None,
                        terminal_sha256=None,
                        standalone_bound_at=None,
                        created_at=created_at,
                        mounted_at=None,
                        finalizing_at=None,
                        terminal_at=None,
                    )
                    created = replace(
                        candidate,
                        immutable_sha256=_ltfs_record_sha256(candidate, ()),
                    )
                    self._connection.execute(
                        "INSERT INTO ltfs_sessions VALUES("
                        + ",".join("?" for _field in range(40))
                        + ")",
                        _ltfs_session_values(created),
                    )
                    created_row = self._select_ltfs_session(
                        checked.operation_id, checked.owner_generation
                    )
                    if created_row is None:
                        raise BrokerStateUnavailable
                    result = LtfsSessionTransition(
                        _ltfs_session_from_row(created_row), True
                    )
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    def bind_ltfs_child(
        self,
        request: LtfsSessionRequest,
        child_pid: int,
        child_start_ticks: int,
        mount_namespace_sha256: str,
    ) -> LtfsSessionTransition:
        checked, request_digest = _validate_ltfs_request(request)
        if (
            type(child_pid) is not int
            or not 0 < child_pid < 1 << 31
            or type(child_start_ticks) is not int
            or child_start_ticks <= 0
            or not _is_digest(mount_namespace_sha256)
        ):
            raise BrokerStateConflict
        conflict = False
        result: LtfsSessionTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            if row is None:
                conflict = True
            else:
                record = _ltfs_session_from_row(row)
                exact_child = (
                    record.child_pid,
                    record.child_start_ticks,
                    record.mount_namespace_sha256,
                ) == (child_pid, child_start_ticks, mount_namespace_sha256)
                if (
                    record.state == "BROKEN"
                    or not self._ltfs_request_matches(record, checked, request_digest)
                    or (record.child_pid is not None and not exact_child)
                    or (record.state != "STARTING" and not exact_child)
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                elif exact_child:
                    result = LtfsSessionTransition(record, False)
                else:
                    updated_record = self._update_ltfs_record(
                        record,
                        child_pid=child_pid,
                        child_start_ticks=child_start_ticks,
                        mount_namespace_sha256=mount_namespace_sha256,
                    )
                    result = LtfsSessionTransition(updated_record, True)
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    @staticmethod
    def _ltfs_receipt_matches(
        record: LtfsSessionRecord, receipt: LtfsSessionReceipt
    ) -> bool:
        return (
            record.operation_id == receipt.operation_id
            and record.owner_generation == receipt.owner_generation
            and record.start_request_nonce == receipt.request_nonce
            and record.request_sha256 == receipt.request_sha256
            and record.receipt_operation_uuid in {None, receipt.receipt_operation_uuid}
            and record.observed_volume_uuid in {None, receipt.observed_volume_uuid}
            and record.observed_prior_generation
            in {None, receipt.observed_prior_generation}
            and record.observed_volume_label in {None, receipt.observed_volume_label}
            and record.observed_media_identity_sha256
            == receipt.observed_media_identity_sha256
            and record.read_only is receipt.read_only
            and record.child_pid == receipt.child_pid
            and record.child_start_ticks == receipt.child_start_ticks
            and record.mount_namespace_sha256 == receipt.mount_namespace_sha256
            and (
                record.session_id,
                record.session_broker_nonce,
                record.session_broker_proof,
            )
            in {
                (None, None, None),
                (receipt.session_id, receipt.broker_nonce, receipt.broker_proof),
            }
        )

    def mark_ltfs_mounted(self, receipt: LtfsSessionReceipt) -> LtfsSessionTransition:
        checked = _validate_ltfs_receipt(receipt)
        conflict = False
        result: LtfsSessionTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            if row is None:
                conflict = True
            else:
                record = _ltfs_session_from_row(row)
                receipt_matches = self._ltfs_receipt_matches(record, checked)
                duplicate_session = self._connection.execute(
                    "SELECT operation_id,owner_generation FROM ltfs_sessions "
                    "WHERE session_id=?",
                    (checked.session_id,),
                ).fetchone()
                if (
                    record.state == "BROKEN"
                    or not receipt_matches
                    or self._ltfs_opaque_conflicts(
                        frozenset({checked.broker_nonce, checked.broker_proof}),
                        exclude=(checked.operation_id, checked.owner_generation),
                    )
                    or duplicate_session
                    not in {None, (checked.operation_id, checked.owner_generation)}
                    or (
                        record.state not in {"STARTING", "MOUNTED"}
                        and record.session_id != checked.session_id
                    )
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                elif record.state != "STARTING":
                    result = LtfsSessionTransition(record, False)
                else:
                    mounted_at = self._terminal_now(record.created_at)
                    updated_record = self._update_ltfs_record(
                        record,
                        state="MOUNTED",
                        receipt_operation_uuid=checked.receipt_operation_uuid,
                        observed_volume_uuid=checked.observed_volume_uuid,
                        observed_prior_generation=checked.observed_prior_generation,
                        observed_volume_label=checked.observed_volume_label,
                        session_id=checked.session_id,
                        session_broker_nonce=checked.broker_nonce,
                        session_broker_proof=checked.broker_proof,
                        mounted_at=mounted_at,
                    )
                    result = LtfsSessionTransition(updated_record, True)
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    def record_ltfs_observation(
        self,
        receipt: LtfsSessionReceipt,
        *,
        challenge: bytes,
        observation_nonce: bytes,
        broker_proof: bytes,
    ) -> LtfsObservationTransition:
        checked = _validate_ltfs_receipt(receipt)
        if (
            not _is_exact_opaque(challenge)
            or not _is_exact_opaque(observation_nonce)
            or not _is_exact_opaque(broker_proof)
            or len({challenge, observation_nonce, broker_proof}) != 3
        ):
            raise BrokerStateConflict
        conflict = False
        result: LtfsObservationTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            if row is None:
                conflict = True
            else:
                session = _ltfs_session_from_row(row)
                existing_row = self._connection.execute(
                    _LTFS_OBSERVATION_SELECT
                    + " WHERE operation_id=? AND owner_generation=? AND challenge=?",
                    (checked.operation_id, checked.owner_generation, challenge),
                ).fetchone()
                existing = (
                    None
                    if existing_row is None
                    else _ltfs_observation_from_row(existing_row)
                )
                causal_existing = (
                    existing is not None
                    and existing.session_id == checked.session_id
                    and self._ltfs_receipt_matches(session, checked)
                )
                if causal_existing:
                    result = LtfsObservationTransition(existing, False)
                elif (
                    session.state != "MOUNTED"
                    or not self._ltfs_receipt_matches(session, checked)
                    or existing is not None
                    or self._ltfs_opaque_conflicts(
                        frozenset({challenge, observation_nonce, broker_proof}),
                        exclude=(checked.operation_id, checked.owner_generation),
                    )
                    or bool(
                        {challenge, observation_nonce, broker_proof}
                        & _ltfs_opaque_values(session)
                    )
                ):
                    self._mark_ltfs_broken(session)
                    conflict = True
                else:
                    observed_at = self._terminal_now(
                        session.mounted_at or session.created_at
                    )
                    self._connection.execute(
                        "INSERT INTO ltfs_observations("
                        "operation_id,owner_generation,session_id,challenge,"
                        "observation_nonce,broker_proof,observed_at) "
                        "VALUES(?,?,?,?,?,?,?)",
                        (
                            checked.operation_id,
                            checked.owner_generation,
                            checked.session_id,
                            challenge,
                            observation_nonce,
                            broker_proof,
                            observed_at,
                        ),
                    )
                    inserted = self._connection.execute(
                        _LTFS_OBSERVATION_SELECT
                        + " WHERE operation_id=? AND owner_generation=? AND challenge=?",
                        (checked.operation_id, checked.owner_generation, challenge),
                    ).fetchone()
                    if inserted is None:
                        raise BrokerStateUnavailable
                    self._update_ltfs_record(session)
                    result = LtfsObservationTransition(
                        _ltfs_observation_from_row(inserted), True
                    )
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    def begin_ltfs_finalization(
        self, receipt: LtfsSessionReceipt, request_nonce: bytes
    ) -> LtfsSessionTransition:
        checked = _validate_ltfs_receipt(receipt)
        if not _is_exact_opaque(request_nonce):
            raise BrokerStateConflict
        conflict = False
        result: LtfsSessionTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            if row is None:
                conflict = True
            else:
                record = _ltfs_session_from_row(row)
                receipt_matches = self._ltfs_receipt_matches(record, checked)
                opaque_collision = request_nonce in {
                    record.start_request_nonce,
                    record.session_broker_nonce,
                    record.session_broker_proof,
                }
                exact_duplicate = record.finalization_request_nonce == request_nonce
                if (
                    record.state == "BROKEN"
                    or not receipt_matches
                    or opaque_collision
                    or self._ltfs_opaque_conflicts(
                        frozenset({request_nonce}),
                        exclude=(checked.operation_id, checked.owner_generation),
                    )
                    or (
                        record.state in {"FINALIZING", "UNMOUNTED"}
                        and not exact_duplicate
                    )
                    or record.state not in {"MOUNTED", "FINALIZING", "UNMOUNTED"}
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                elif record.state != "MOUNTED":
                    result = LtfsSessionTransition(record, False)
                else:
                    finalizing_at = self._terminal_now(
                        record.mounted_at or record.created_at
                    )
                    updated_record = self._update_ltfs_record(
                        record,
                        state="FINALIZING",
                        finalization_request_nonce=request_nonce,
                        finalizing_at=finalizing_at,
                    )
                    result = LtfsSessionTransition(updated_record, True)
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    def bind_ltfs_terminal_receipt(
        self,
        receipt: LtfsSessionReceipt,
        standalone: LtfsStandaloneReceipt,
    ) -> LtfsSessionTransition:
        checked = _validate_ltfs_receipt(receipt)
        terminal_json = _standalone_receipt_json(standalone)
        if (
            standalone.operation_id != checked.receipt_operation_uuid
            or standalone.volume_uuid != checked.observed_volume_uuid
            or standalone.prior_generation != checked.observed_prior_generation
            or (
                checked.read_only
                and standalone.new_generation != standalone.prior_generation
            )
            or (
                not checked.read_only
                and standalone.new_generation < standalone.prior_generation
            )
        ):
            raise BrokerStateConflict
        conflict = False
        result: LtfsSessionTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            if row is None:
                conflict = True
            else:
                record = _ltfs_session_from_row(row)
                exact = (
                    record.standalone_receipt_json == terminal_json
                    and record.terminal_sha256 == standalone.terminal_sha256
                )
                if (
                    record.state == "BROKEN"
                    or not self._ltfs_receipt_matches(record, checked)
                    or record.state not in {"FINALIZING", "UNMOUNTED"}
                    or (record.standalone_receipt_json is not None and not exact)
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                elif exact:
                    result = LtfsSessionTransition(record, False)
                else:
                    bound_at = self._terminal_now(
                        record.finalizing_at or record.mounted_at or record.created_at
                    )
                    updated = self._update_ltfs_record(
                        record,
                        standalone_receipt_json=terminal_json,
                        terminal_sha256=standalone.terminal_sha256,
                        standalone_bound_at=bound_at,
                    )
                    result = LtfsSessionTransition(updated, True)
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    def bind_ltfs_child_exit_zero(self, receipt: LtfsSessionReceipt) -> str:
        """Durably attest the exact successful waitpid result before completion."""

        checked = _validate_ltfs_receipt(receipt)
        conflict = False
        observed_at: str | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                checked.operation_id, checked.owner_generation
            )
            existing = self._connection.execute(
                "SELECT child_exit_code,exit_observed_at "
                "FROM ltfs_child_exit_receipts "
                "WHERE operation_id=? AND owner_generation=?",
                (checked.operation_id, checked.owner_generation),
            ).fetchone()
            if row is None:
                conflict = True
            else:
                record = _ltfs_session_from_row(row)
                if (
                    record.state == "BROKEN"
                    or record.state not in {"FINALIZING", "UNMOUNTED"}
                    or not self._ltfs_receipt_matches(record, checked)
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                elif existing is not None:
                    if (
                        existing[0] != 0
                        or _validate_timestamp(existing[1]) != existing[1]
                    ):
                        self._mark_ltfs_broken(record)
                        conflict = True
                    else:
                        observed_at = existing[1]
                else:
                    observed_at = self._terminal_now(
                        record.finalizing_at or record.mounted_at or record.created_at
                    )
                    self._connection.execute(
                        "INSERT INTO ltfs_child_exit_receipts("
                        "operation_id,owner_generation,child_exit_code,exit_observed_at) "
                        "VALUES(?,?,0,?)",
                        (checked.operation_id, checked.owner_generation, observed_at),
                    )
        if conflict or observed_at is None:
            raise BrokerStateConflict
        return observed_at

    def has_ltfs_child_exit_zero(
        self, operation_id: str, owner_generation: int
    ) -> bool:
        if not _is_identity(operation_id) or type(owner_generation) is not int:
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            row = self._connection.execute(
                "SELECT child_exit_code,exit_observed_at "
                "FROM ltfs_child_exit_receipts "
                "WHERE operation_id=? AND owner_generation=?",
                (operation_id, owner_generation),
            ).fetchone()
            if row is None:
                return False
            if row[0] != 0 or _validate_timestamp(row[1]) != row[1]:
                raise BrokerStateUnavailable
            return True

    def mark_ltfs_unmounted(
        self, receipt: LtfsFinalizationReceipt
    ) -> LtfsSessionTransition:
        checked = _validate_ltfs_finalization(receipt)
        session = checked.session_receipt
        conflict = False
        result: LtfsSessionTransition | None = None
        with self._transaction(durable=True):
            row = self._select_ltfs_session(
                session.operation_id, session.owner_generation
            )
            if row is None:
                conflict = True
            else:
                record = _ltfs_session_from_row(row)
                final_values = (checked.finalization_nonce, checked.broker_proof)
                exact_duplicate = (
                    record.finalization_nonce,
                    record.finalization_broker_proof,
                ) == final_values
                opaque_collision = bool(
                    {
                        checked.finalization_nonce,
                        checked.broker_proof,
                    }
                    & {
                        record.start_request_nonce,
                        record.session_broker_nonce,
                        record.session_broker_proof,
                        record.finalization_request_nonce,
                    }
                )
                if (
                    record.state == "BROKEN"
                    or not self._ltfs_receipt_matches(record, session)
                    or record.standalone_receipt_json
                    != _standalone_receipt_json(checked.standalone_receipt)
                    or record.terminal_sha256
                    != checked.standalone_receipt.terminal_sha256
                    or record.finalization_request_nonce != checked.request_nonce
                    or opaque_collision
                    or self._ltfs_opaque_conflicts(
                        frozenset({checked.finalization_nonce, checked.broker_proof}),
                        exclude=(session.operation_id, session.owner_generation),
                    )
                    or (record.state == "UNMOUNTED" and not exact_duplicate)
                    or record.state not in {"FINALIZING", "UNMOUNTED"}
                ):
                    self._mark_ltfs_broken(record)
                    conflict = True
                elif record.state == "UNMOUNTED":
                    result = LtfsSessionTransition(record, False)
                else:
                    terminal_at = self._terminal_now(
                        record.finalizing_at or record.mounted_at or record.created_at
                    )
                    updated_record = self._update_ltfs_record(
                        record,
                        state="UNMOUNTED",
                        finalization_nonce=checked.finalization_nonce,
                        finalization_broker_proof=checked.broker_proof,
                        terminal_at=terminal_at,
                    )
                    result = LtfsSessionTransition(updated_record, True)
        if conflict or result is None:
            raise BrokerStateConflict
        return result

    def break_ltfs_session(
        self, operation_id: str, owner_generation: int
    ) -> LtfsSessionTransition:
        if (
            not _is_identity(operation_id)
            or type(owner_generation) is not int
            or not 0 <= owner_generation < 1 << 63
        ):
            raise BrokerStateConflict
        with self._transaction(durable=True):
            row = self._select_ltfs_session(operation_id, owner_generation)
            if row is None:
                raise BrokerStateConflict
            record = _ltfs_session_from_row(row)
            if record.state == "BROKEN":
                return LtfsSessionTransition(record, False)
            return LtfsSessionTransition(self._mark_ltfs_broken(record), True)

    def ltfs_session(
        self, operation_id: str, owner_generation: int
    ) -> LtfsSessionRecord:
        if (
            not _is_identity(operation_id)
            or type(owner_generation) is not int
            or not 0 <= owner_generation < 1 << 63
        ):
            raise BrokerStateConflict
        with self._lock:
            self._assert_open()
            try:
                row = self._select_ltfs_session(operation_id, owner_generation)
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        if row is None:
            raise BrokerStateConflict
        return _ltfs_session_from_row(row)

    def ltfs_sessions_for_reconciliation(self) -> tuple[LtfsSessionRecord, ...]:
        with self._lock:
            self._assert_open()
            try:
                rows = self._connection.execute(
                    _LTFS_SESSION_SELECT + " ORDER BY operation_id,owner_generation"
                ).fetchall()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        return tuple(_ltfs_session_from_row(row) for row in rows)

    def ltfs_observations_for_reconciliation(
        self,
    ) -> tuple[LtfsObservationRecord, ...]:
        with self._lock:
            self._assert_open()
            try:
                rows = self._connection.execute(
                    _LTFS_OBSERVATION_SELECT
                    + " ORDER BY operation_id,owner_generation,challenge"
                ).fetchall()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        return tuple(_ltfs_observation_from_row(row) for row in rows)

    def ltfs_sessions_ready(self) -> bool:
        with self._lock:
            self._assert_open()
            try:
                broken = self._connection.execute(
                    "SELECT 1 FROM ltfs_sessions WHERE state='BROKEN' LIMIT 1"
                ).fetchone()
                unresolved_qualification = self._connection.execute(
                    "SELECT 1 FROM ltfs_qualification_stages "
                    "WHERE state IN ('PREPARED','DISPATCHED','FENCED') LIMIT 1"
                ).fetchone()
            except sqlite3.Error:
                raise BrokerStateUnavailable from None
        return broken is None and unresolved_qualification is None
