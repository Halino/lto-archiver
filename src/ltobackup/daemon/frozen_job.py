"""Read-only execution plan for an imported immutable automatic job."""

from __future__ import annotations

import json
import os
import sqlite3
import stat
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Literal, Protocol, Self

from ..migration.validator import (
    canonical_assignment_sha256,
    canonical_cassette_plan_sha256,
    canonical_completed_evidence_sha256,
    canonical_sequence_manifest_sha256,
)
from .models import (
    IMPORTED_POSTCOMMIT_COMMAND_FIELDS,
    cutover_authorization_evidence_sha256,
    cutover_catalog_binding_sha256,
    expected_media_scope_sha256,
    hardware_command_release_evidence_valid,
    imported_cassette_commit_binding_sha256,
    imported_media_ledger_shape_valid,
    imported_postcommit_command_sha256,
    imported_postcommit_observation_transition_valid,
    imported_postcommit_terminal_timeline_valid,
    imported_recovery_lineage_sha256,
    imported_recovery_resolution_sha256,
)


class CatalogView(Protocol):
    connection: sqlite3.Connection


class FrozenJobError(RuntimeError):
    """Base class for stable, non-secret frozen-job load failures."""

    code = "frozen-job-invalid"

    def __init__(self) -> None:
        super().__init__(self.code)


class FrozenJobNotImported(FrozenJobError):
    code = "job-not-imported"


class FrozenJobAuthorityInvalid(FrozenJobError):
    code = "frozen-authority-invalid"


class FrozenJobAssignmentChanged(FrozenJobError):
    code = "frozen-assignment-changed"


class FrozenJobStateInvalid(FrozenJobError):
    code = "frozen-job-state-invalid"
    error_class = "operator_required"


class FrozenJobComplete(FrozenJobError):
    code = "frozen-job-complete"

    def __init__(self, job_id: str) -> None:
        self.job_id = job_id
        super().__init__()


@dataclass(frozen=True)
class FrozenItem:
    sequence: int
    item_sequence: int
    library_id: str
    relative_path: str
    size: int
    mtime_ns: int


@dataclass(frozen=True)
class FrozenCassette:
    sequence: int
    physical_label: str
    tape_serial: str
    operation: Literal["format", "append"]
    status: str
    planned_files: int
    planned_bytes: int
    tape_id: str | None
    block_id: str | None
    copied_files: int
    copied_bytes: int
    started_at: str | None
    completed_at: str | None
    error: str | None
    reuse_registered: bool
    items: tuple[FrozenItem, ...]


SourceIssueCode = Literal[
    "source_missing",
    "source_changed",
    "source_unavailable",
    "source_path_invalid",
]


@dataclass(frozen=True)
class SourceValidationIssue:
    code: SourceIssueCode
    library_id: str
    relative_path: str


@dataclass(frozen=True)
class SourceValidation:
    sequence: int
    assignment_sha256: str
    checked_files: int
    issues: tuple[SourceValidationIssue, ...]
    error_class: Literal["operator_required"] | None = None
    error_code: Literal["frozen_source_validation_failed"] | None = None

    @property
    def accepted(self) -> bool:
        return not self.issues

    @property
    def blocked(self) -> bool:
        return bool(self.issues)


@dataclass(frozen=True)
class FrozenJobPlan:
    job_id: str
    assignment_sha256: str
    cassette_plan_sha256: str
    completed_evidence_sha256: str
    bundle_sha256: str
    authority_state: Literal["pre_cutover", "active_linux"]
    cassettes: tuple[FrozenCassette, ...]
    _library_roots: tuple[tuple[str, Path], ...] = field(repr=False)
    _recovery_pending: bool = field(default=False, repr=False)

    @classmethod
    def load(cls, catalog: CatalogView, job_id: str) -> Self:
        """Load and attest an imported allocation without scanning any source."""

        if not isinstance(job_id, str) or not job_id:
            raise FrozenJobNotImported()
        try:
            return cls._load(catalog.connection, job_id)
        except FrozenJobError:
            raise
        except (LookupError, sqlite3.DatabaseError, TypeError, ValueError):
            raise FrozenJobAuthorityInvalid() from None

    @classmethod
    def _load(cls, connection: sqlite3.Connection, job_id: str) -> Self:
        job = connection.execute(
            "SELECT id, status, current_sequence, total_cassettes "
            "FROM automatic_jobs WHERE id=?",
            (job_id,),
        ).fetchone()
        policy = connection.execute(
            "SELECT * FROM imported_job_policies WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if job is None or policy is None:
            raise FrozenJobNotImported()
        receipts = connection.execute(
            "SELECT id, job_id, bundle_sha256, assignment_sha256, "
            "cassette_plan_sha256, completed_evidence_sha256 "
            "FROM migration_receipts WHERE job_id=? ORDER BY id",
            (job_id,),
        ).fetchall()
        _require_policy_authority(job_id, policy, receipts)

        cassette_rows = connection.execute(
            "SELECT job_id, sequence, physical_label, tape_serial, operation, status, "
            "planned_files, planned_bytes, tape_id, block_id, copied_files, "
            "copied_bytes, started_at, completed_at, error, reuse_registered "
            "FROM automatic_cassettes "
            "WHERE job_id=? ORDER BY sequence",
            (job_id,),
        ).fetchall()
        item_rows = connection.execute(
            "SELECT job_id, sequence, item_sequence, library_id, relative_path, "
            "size, mtime_ns FROM automatic_cassette_items "
            "WHERE job_id=? ORDER BY sequence, item_sequence",
            (job_id,),
        ).fetchall()
        assignment_sha256 = canonical_assignment_sha256(connection, job_id)
        if (
            assignment_sha256 != policy["assignment_sha256"]
            or assignment_sha256 != receipts[0]["assignment_sha256"]
        ):
            raise FrozenJobAssignmentChanged()
        try:
            completed_evidence_sha256 = canonical_completed_evidence_sha256(
                connection,
                job_id,
                (1, 2, 3),
                allow_missing_assignments=True,
            )
        except (LookupError, sqlite3.DatabaseError, TypeError, ValueError):
            raise FrozenJobStateInvalid() from None
        if (
            completed_evidence_sha256 != policy["completed_evidence_sha256"]
            or completed_evidence_sha256 != receipts[0]["completed_evidence_sha256"]
        ):
            raise FrozenJobStateInvalid()
        cassette_plan_sha256 = canonical_cassette_plan_sha256(
            connection,
            job_id,
            assignment_sha256=assignment_sha256,
        )
        if (
            cassette_plan_sha256 != policy["cassette_plan_sha256"]
            or cassette_plan_sha256 != receipts[0]["cassette_plan_sha256"]
        ):
            raise FrozenJobAssignmentChanged()

        items = tuple(_frozen_item(row, job_id) for row in item_rows)
        cassettes = _frozen_cassettes(job, cassette_rows, items)
        next_sequence = _next_sequence(cassettes)
        _require_resumable_state(job, policy, cassettes, next_sequence)
        recovery_pending = False
        if policy["authority_state"] == "active_linux":
            recovery_pending = _require_activation_proof(
                connection, job_id, policy, cassettes
            )

        library_ids = tuple(dict.fromkeys(item.library_id for item in items))
        roots = (
            connection.execute(
                "SELECT id, source_root FROM libraries WHERE id IN ("
                + ",".join("?" for _ in library_ids)
                + ") ORDER BY id",
                library_ids,
            ).fetchall()
            if library_ids
            else ()
        )
        root_map = {
            row["id"]: Path(row["source_root"])
            for row in roots
            if isinstance(row["id"], str) and isinstance(row["source_root"], str)
        }
        if set(root_map) != set(library_ids):
            raise FrozenJobAssignmentChanged()

        return cls(
            job_id=job_id,
            assignment_sha256=assignment_sha256,
            cassette_plan_sha256=cassette_plan_sha256,
            completed_evidence_sha256=completed_evidence_sha256,
            bundle_sha256=policy["bundle_sha256"],
            authority_state=policy["authority_state"],
            cassettes=cassettes,
            _library_roots=tuple((key, root_map[key]) for key in sorted(root_map)),
            _recovery_pending=recovery_pending,
        )

    @property
    def items(self) -> tuple[FrozenItem, ...]:
        return tuple(item for cassette in self.cassettes for item in cassette.items)

    @property
    def relative_paths(self) -> tuple[str, ...]:
        return tuple(item.relative_path for item in self.items)

    def next_cassette(self) -> FrozenCassette:
        if self._recovery_pending:
            raise FrozenJobStateInvalid()
        pending = tuple(
            cassette
            for cassette in self.cassettes
            if cassette.status in {"pending", "waiting_media"}
        )
        if not pending:
            if all(cassette.status == "completed" for cassette in self.cassettes):
                raise FrozenJobComplete(self.job_id)
            raise FrozenJobStateInvalid()
        return pending[0]

    def cassette_for_recovery(self, sequence: int) -> FrozenCassette:
        """Return one exact frozen cassette without reopening normal admission."""

        if type(sequence) is not int or not 4 <= sequence <= 20:
            raise FrozenJobStateInvalid()
        if self.authority_state == "pre_cutover":
            allowed = sequence == 4
        elif self.authority_state == "active_linux":
            allowed = sequence >= 4
        else:
            allowed = False
        matches = tuple(
            cassette
            for cassette in self.cassettes
            if type(cassette) is FrozenCassette and cassette.sequence == sequence
        )
        if not allowed or len(matches) != 1:
            raise FrozenJobStateInvalid()
        return matches[0]

    def validate_sources(self) -> SourceValidation:
        """Validate only the exact next manifest; never enumerate a library."""

        cassette = self.next_cassette()
        roots = dict(self._library_roots)
        issues: list[SourceValidationIssue] = []
        for item in cassette.items:
            issue = _validate_source_item(item, roots[item.library_id])
            if issue is not None:
                issues.append(issue)
        frozen_issues = tuple(issues)
        return SourceValidation(
            sequence=cassette.sequence,
            assignment_sha256=self.assignment_sha256,
            checked_files=len(cassette.items),
            issues=frozen_issues,
            error_class="operator_required" if frozen_issues else None,
            error_code=("frozen_source_validation_failed" if frozen_issues else None),
        )


def _require_policy_authority(job_id: str, policy, receipts) -> None:
    if (
        policy["job_id"] != job_id
        or policy["policy_kind"] != "frozen-allocation"
        or not _is_sha256(policy["assignment_sha256"])
        or not _is_sha256(policy["cassette_plan_sha256"])
        or not _is_sha256(policy["completed_evidence_sha256"])
        or not _is_sha256(policy["bundle_sha256"])
        or len(receipts) != 1
    ):
        raise FrozenJobAuthorityInvalid()
    receipt = receipts[0]
    if (
        receipt["job_id"] != job_id
        or receipt["assignment_sha256"] != policy["assignment_sha256"]
        or receipt["cassette_plan_sha256"] != policy["cassette_plan_sha256"]
        or receipt["completed_evidence_sha256"] != policy["completed_evidence_sha256"]
        or receipt["bundle_sha256"] != policy["bundle_sha256"]
    ):
        raise FrozenJobAuthorityInvalid()
    pre_cutover = (
        policy["authority_state"] == "pre_cutover"
        and policy["windows_authority"] == "resumable"
        and policy["rollback_allowed"] == 1
        and policy["activated_by_operation"] is None
        and policy["activated_at"] is None
    )
    active_linux = (
        policy["authority_state"] == "active_linux"
        and policy["windows_authority"] == "historical_read_only"
        and policy["rollback_allowed"] == 0
        and isinstance(policy["activated_by_operation"], str)
        and bool(policy["activated_by_operation"])
        and _timestamp(policy["activated_at"]) is not None
    )
    if not (pre_cutover or active_linux):
        raise FrozenJobAuthorityInvalid()


def _frozen_item(row, job_id: str) -> FrozenItem:
    if row["job_id"] != job_id:
        raise FrozenJobAssignmentChanged()
    values = (
        _nonnegative_integer(row["sequence"]),
        _nonnegative_integer(row["item_sequence"]),
        _nonnegative_integer(row["size"]),
        _nonnegative_integer(row["mtime_ns"]),
    )
    if any(value is None for value in values):
        raise FrozenJobAssignmentChanged()
    if (
        not isinstance(row["library_id"], str)
        or not row["library_id"]
        or not isinstance(row["relative_path"], str)
        or not _safe_relative_path(row["relative_path"])
    ):
        raise FrozenJobAssignmentChanged()
    return FrozenItem(
        sequence=values[0],
        item_sequence=values[1],
        library_id=row["library_id"],
        relative_path=row["relative_path"],
        size=values[2],
        mtime_ns=values[3],
    )


def _frozen_cassettes(
    job, rows, items: tuple[FrozenItem, ...]
) -> tuple[FrozenCassette, ...]:
    total = _nonnegative_integer(job["total_cassettes"])
    if total is None or total < 1 or len(rows) != total:
        raise FrozenJobStateInvalid()
    by_sequence: dict[int, list[FrozenItem]] = {}
    for item in items:
        by_sequence.setdefault(item.sequence, []).append(item)
    cassettes: list[FrozenCassette] = []
    for expected_sequence, row in enumerate(rows, 1):
        sequence = _nonnegative_integer(row["sequence"])
        planned_files = _nonnegative_integer(row["planned_files"])
        planned_bytes = _nonnegative_integer(row["planned_bytes"])
        copied_files = _nonnegative_integer(row["copied_files"])
        copied_bytes = _nonnegative_integer(row["copied_bytes"])
        reuse_registered = _nonnegative_integer(row["reuse_registered"])
        cassette_items = tuple(by_sequence.get(expected_sequence, ()))
        manifest_matches = (
            planned_files == len(cassette_items)
            and planned_bytes == sum(item.size for item in cassette_items)
        ) or (row["status"] == "completed" and not cassette_items)
        if (
            row["job_id"] != job["id"]
            or sequence != expected_sequence
            or planned_files is None
            or planned_bytes is None
            or copied_files is None
            or copied_bytes is None
            or reuse_registered not in {0, 1}
            or tuple(item.item_sequence for item in cassette_items)
            != tuple(range(1, len(cassette_items) + 1))
            or not manifest_matches
            or row["operation"] not in {"format", "append"}
            or not _exact_media_text(row["physical_label"], maximum=255)
            or not _exact_media_text(row["tape_serial"], maximum=32)
        ):
            raise FrozenJobAssignmentChanged()
        cassettes.append(
            FrozenCassette(
                sequence=expected_sequence,
                physical_label=row["physical_label"],
                tape_serial=row["tape_serial"],
                operation=row["operation"],
                status=row["status"],
                planned_files=planned_files,
                planned_bytes=planned_bytes,
                tape_id=row["tape_id"],
                block_id=row["block_id"],
                copied_files=copied_files,
                copied_bytes=copied_bytes,
                started_at=row["started_at"],
                completed_at=row["completed_at"],
                error=row["error"],
                reuse_registered=bool(reuse_registered),
                items=cassette_items,
            )
        )
    if set(by_sequence) - set(range(1, total + 1)):
        raise FrozenJobAssignmentChanged()
    return tuple(cassettes)


def _exact_media_text(value: object, *, maximum: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and value == value.strip(" ")
        and value.isascii()
        and value.isprintable()
    )


def _require_resumable_state(job, policy, cassettes, next_sequence: int | None) -> None:
    completed = tuple(
        cassette.sequence for cassette in cassettes if cassette.status == "completed"
    )
    if completed != tuple(range(1, len(completed) + 1)):
        raise FrozenJobStateInvalid()
    if any(
        not _completed_cassette_valid(cassette)
        for cassette in cassettes[: len(completed)]
    ):
        raise FrozenJobStateInvalid()
    if any(
        cassette.status not in {"completed", "pending", "waiting_media"}
        for cassette in cassettes
    ):
        raise FrozenJobStateInvalid()
    current_sequence = _nonnegative_integer(job["current_sequence"])
    if job["status"] == "completed":
        if next_sequence is not None:
            raise FrozenJobStateInvalid()
        return
    if job["status"] not in {"paused", "waiting_media"}:
        raise FrozenJobStateInvalid()
    if next_sequence is None or current_sequence != next_sequence:
        raise FrozenJobStateInvalid()
    current = cassettes[next_sequence - 1]
    later = cassettes[next_sequence:]
    if not _untouched_current_cassette(current) or any(
        not _pristine_future_cassette(cassette) for cassette in later
    ):
        raise FrozenJobStateInvalid()
    if policy["authority_state"] == "pre_cutover":
        if next_sequence != 4 or completed != (1, 2, 3):
            raise FrozenJobAuthorityInvalid()
    elif next_sequence <= 4 or 4 not in completed:
        raise FrozenJobAuthorityInvalid()


def _completed_cassette_valid(cassette: FrozenCassette) -> bool:
    started = _timestamp(cassette.started_at)
    completed = _timestamp(cassette.completed_at)
    return bool(
        cassette.status == "completed"
        and isinstance(cassette.tape_id, str)
        and cassette.tape_id
        and isinstance(cassette.block_id, str)
        and cassette.block_id
        and cassette.copied_files == cassette.planned_files
        and cassette.copied_bytes == cassette.planned_bytes
        and started is not None
        and completed is not None
        and completed >= started
        and cassette.error is None
    )


def _untouched_current_cassette(cassette: FrozenCassette) -> bool:
    return bool(
        cassette.status in {"pending", "waiting_media"}
        and cassette.tape_id is None
        and cassette.block_id is None
        and cassette.copied_files == 0
        and cassette.copied_bytes == 0
        and cassette.started_at is None
        and cassette.completed_at is None
        and cassette.error is None
        and not cassette.reuse_registered
    )


def _pristine_future_cassette(cassette: FrozenCassette) -> bool:
    return bool(
        cassette.status == "pending"
        and cassette.tape_id is None
        and cassette.block_id is None
        and cassette.copied_files == 0
        and cassette.copied_bytes == 0
        and cassette.started_at is None
        and cassette.completed_at is None
        and cassette.error is None
        and not cassette.reuse_registered
    )


def _require_activation_proof(connection, job_id: str, policy, cassettes) -> bool:
    operation_id = policy["activated_by_operation"]
    operation = connection.execute(
        "SELECT id, kind, state, phase, owner_generation, job_id, cassette_sequence, started_at, "
        "finished_at, error_class, error_code, error_message "
        "FROM daemon_operations WHERE id=?",
        (operation_id,),
    ).fetchone()
    target = connection.execute(
        "SELECT mount_path_sha256, tape_device_identity_sha256, "
        "scsi_device_identity_sha256, expected_media_scope_sha256, bound_at "
        "FROM operation_hardware_targets WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    authorizations = connection.execute(
        "SELECT * FROM cutover_authorizations "
        "WHERE consumed_by_operation_id=? ORDER BY id",
        (operation_id,),
    ).fetchall()
    media_binding = connection.execute(
        "SELECT * FROM operation_media_identity_bindings WHERE operation_id=?",
        (operation_id,),
    ).fetchone()
    commands = _commands_with_release(connection, operation_id)
    commit_receipts = connection.execute(
        "SELECT * FROM imported_cassette_commit_receipts WHERE job_id=? AND sequence=4",
        (job_id,),
    ).fetchall()
    fourth = cassettes[3] if len(cassettes) >= 4 else None
    commit = commit_receipts[0] if len(commit_receipts) == 1 else None
    if (
        operation is None
        or target is None
        or len(authorizations) != 1
        or media_binding is None
        or not commands
        or commit is None
        or fourth is None
        or not _completed_cassette_valid(fourth)
        or operation["id"] != operation_id
        or operation["kind"] != "archive.resume"
        or operation["state"]
        not in {"running", "succeeded", "recovery_required", "cancelled"}
        or operation["phase"] != "unloading"
        or operation["job_id"] != job_id
        or operation["cassette_sequence"] != 4
        or operation["owner_generation"] != commit["owner_generation"]
    ):
        raise FrozenJobAuthorityInvalid()
    started_at = _timestamp(operation["started_at"])
    finished_at = _timestamp(operation["finished_at"])
    committed_at = _timestamp(commit["committed_at"])
    bound_at = _timestamp(target["bound_at"])
    authorization = authorizations[0]
    created_at = _timestamp(authorization["created_at"])
    expires_at = _timestamp(authorization["expires_at"])
    consumed_at = _timestamp(authorization["consumed_at"])
    cassette_completed_at = _timestamp(fourth.completed_at)
    media_bound_at = _timestamp(media_binding["bound_at"])
    try:
        fourth_evidence_sha256 = canonical_completed_evidence_sha256(
            connection,
            job_id,
            (4,),
            allow_missing_assignments=False,
        )
        manifest_sha256 = canonical_sequence_manifest_sha256(connection, job_id, 4)
        block_ids = tuple(json.loads(commit["block_ids_json"]))
        command_ids = tuple(json.loads(commit["command_ids_json"]))
    except (LookupError, sqlite3.DatabaseError, TypeError, ValueError):
        raise FrozenJobAuthorityInvalid() from None
    if not block_ids or not command_ids:
        raise FrozenJobAuthorityInvalid()
    command_by_id = {row["id"]: row for row in commands}
    if len(command_by_id) != len(commands) or any(
        command_id not in command_by_id for command_id in command_ids
    ):
        raise FrozenJobAuthorityInvalid()
    committed_commands = tuple(command_by_id[value] for value in command_ids)
    command_evidence = imported_postcommit_command_sha256(
        tuple(_postcommit_command_tuple(command) for command in committed_commands)
    )
    authorization_evidence = cutover_authorization_evidence_sha256(
        (
            authorization["id"],
            authorization["credential_sha256"],
            authorization["job_id"],
            authorization["cassette_sequence"],
            authorization["bundle_sha256"],
            authorization["catalog_binding_sha256"],
            authorization["assignment_sha256"],
            authorization["expected_label"],
            authorization["host_id"],
            authorization["drive_serial_sha256"],
            authorization["peer_kind"],
            authorization["created_at"],
            authorization["expires_at"],
            authorization["consumed_at"],
            authorization["consumed_by_operation_id"],
            operation["id"],
            operation["kind"],
            operation["job_id"],
            operation["cassette_sequence"],
            tuple(
                target[field]
                for field in (
                    "mount_path_sha256",
                    "tape_device_identity_sha256",
                    "scsi_device_identity_sha256",
                    "expected_media_scope_sha256",
                )
            ),
        )
    )
    postcommit_commands = _validated_activation_command_ledger(
        connection,
        operation,
        commit,
        target,
        media_binding,
        commands,
        command_ids,
        started_at,
        committed_at,
        media_bound_at,
    )
    command_timeline_invalid = postcommit_commands is None
    terminal_sha256 = (
        commit["terminal_sha256"]
        if "terminal_sha256" in frozenset(commit.keys())
        else None
    )
    terminal_receipt = (
        None
        if terminal_sha256 is None
        else connection.execute(
            "SELECT terminal_sha256,observed_volume_label FROM "
            "ltfs_terminal_receipts WHERE operation_id=? AND owner_generation=?",
            (operation_id, commit["owner_generation"]),
        ).fetchone()
    )
    terminal_binding = () if terminal_sha256 is None else (terminal_sha256,)
    binding = imported_cassette_commit_binding_sha256(
        (
            operation_id,
            commit["owner_generation"],
            job_id,
            4,
            commit["tape_id"],
            block_ids,
            manifest_sha256,
            fourth_evidence_sha256,
            media_binding["observed_media_identity_sha256"],
            *terminal_binding,
            tuple(
                target[field]
                for field in (
                    "mount_path_sha256",
                    "tape_device_identity_sha256",
                    "scsi_device_identity_sha256",
                    "expected_media_scope_sha256",
                )
            ),
            command_ids,
            command_evidence,
            authorization_evidence,
            commit["committed_at"],
        )
    )
    if (
        started_at is None
        or committed_at is None
        or bound_at is None
        or created_at is None
        or expires_at is None
        or consumed_at is None
        or cassette_completed_at is None
        or media_bound_at is None
        or not (
            created_at <= started_at <= bound_at <= consumed_at <= expires_at
            and consumed_at <= media_bound_at <= cassette_completed_at == committed_at
        )
        or (finished_at is not None and finished_at < committed_at)
        or (operation["state"] in {"succeeded", "cancelled"} and finished_at is None)
        or (
            operation["state"] in {"running", "recovery_required"}
            and finished_at is not None
        )
        or (
            postcommit_commands is not None
            and not _activation_operation_state_valid(
                connection,
                operation,
                target,
                media_binding,
                commit,
                commands,
                postcommit_commands,
                committed_at,
                finished_at,
            )
        )
        or any(
            not _is_sha256(target[field])
            for field in (
                "mount_path_sha256",
                "tape_device_identity_sha256",
                "scsi_device_identity_sha256",
                "expected_media_scope_sha256",
            )
        )
        or authorization["job_id"] != job_id
        or authorization["cassette_sequence"] != 4
        or authorization["bundle_sha256"] != policy["bundle_sha256"]
        or authorization["assignment_sha256"] != policy["assignment_sha256"]
        or authorization["expected_label"] != fourth.physical_label
        or terminal_sha256 is not None
        and (
            terminal_receipt is None
            or terminal_receipt["terminal_sha256"] != terminal_sha256
            or terminal_receipt["observed_volume_label"] != fourth.physical_label
        )
        or authorization["peer_kind"] != "local_admin"
        or not isinstance(authorization["host_id"], str)
        or not authorization["host_id"]
        or not _is_sha256(authorization["credential_sha256"])
        or not _is_sha256(authorization["drive_serial_sha256"])
        or authorization["drive_serial_sha256"] != target["tape_device_identity_sha256"]
        or target["expected_media_scope_sha256"]
        != expected_media_scope_sha256(
            (
                "archive.resume",
                job_id,
                "4",
                fourth.physical_label,
                "",
                "",
            )
        )
        or not _is_sha256(media_binding["observed_media_identity_sha256"])
        or command_timeline_invalid
        or any(
            command["operation_id"] != operation_id
            or any(
                command[field] != target[field]
                for field in (
                    "mount_path_sha256",
                    "tape_device_identity_sha256",
                    "scsi_device_identity_sha256",
                    "expected_media_scope_sha256",
                )
            )
            for command in commands
        )
        or commit["operation_id"] != operation_id
        or commit["job_id"] != job_id
        or commit["sequence"] != 4
        or commit["migration_receipt_id"]
        != connection.execute(
            "SELECT id FROM migration_receipts WHERE job_id=?", (job_id,)
        ).fetchone()["id"]
        or commit["cutover_authorization_id"] != authorization["id"]
        or commit["cutover_authorization_sha256"] != authorization_evidence
        or commit["evidence_sha256"] != fourth_evidence_sha256
        or commit["manifest_sha256"] != manifest_sha256
        or commit["tape_id"] != fourth.tape_id
        or ",".join(block_ids) != fourth.block_id
        or commit["command_evidence_sha256"] != command_evidence
        or commit["commit_binding_sha256"] != binding
        or commit["observed_media_identity_sha256"]
        != media_binding["observed_media_identity_sha256"]
        or any(
            commit[field] != target[field]
            for field in (
                "mount_path_sha256",
                "tape_device_identity_sha256",
                "scsi_device_identity_sha256",
                "expected_media_scope_sha256",
            )
        )
        or commit["committed_at"] != policy["activated_at"]
        or authorization["catalog_binding_sha256"]
        != cutover_catalog_binding_sha256(
            job_id,
            policy["bundle_sha256"],
            policy["assignment_sha256"],
            policy["cassette_plan_sha256"],
            policy["completed_evidence_sha256"],
            fourth.physical_label,
        )
    ):
        raise FrozenJobAuthorityInvalid()
    return operation["state"] in {"running", "recovery_required"}


_RECOVERY_COMMAND_KINDS = frozenset(
    {
        "unload",
        "probe_mount",
        "probe_media",
        "probe_drive",
        "status",
        "inquiry",
        "terminate_process_group",
    }
)


def _validated_activation_command_ledger(
    connection,
    operation,
    commit,
    target,
    media_binding,
    commands,
    command_ids: tuple[object, ...],
    started_at: datetime | None,
    committed_at: datetime | None,
    media_bound_at: datetime | None,
):
    if (
        started_at is None
        or committed_at is None
        or media_bound_at is None
        or len(set(command_ids)) != len(command_ids)
        or any(not isinstance(value, str) or not value for value in command_ids)
        or len({row["id"] for row in commands}) != len(commands)
    ):
        return None
    committed_id_set = set(command_ids)
    if (
        tuple(row["id"] for row in commands if row["id"] in committed_id_set)
        != command_ids
    ):
        return None
    precommit = tuple(row for row in commands if row["id"] in committed_id_set)
    legacy_commit = (
        "terminal_sha256" not in frozenset(commit.keys())
        or commit["terminal_sha256"] is None
    )
    has_format_rebinding_schema = not legacy_commit
    format_rebind = (
        connection.execute(
            "SELECT * FROM format_media_rebindings WHERE operation_id=?",
            (operation["id"],),
        ).fetchone()
        if has_format_rebinding_schema
        else None
    )
    cassette = (
        connection.execute(
            "SELECT physical_label FROM automatic_cassettes "
            "WHERE job_id=? AND sequence=?",
            (operation["job_id"], operation["cassette_sequence"]),
        ).fetchone()
        if has_format_rebinding_schema
        else None
    )
    bound_index = next(
        (
            index
            for index, row in enumerate(precommit)
            if row["id"] == media_binding["bound_by_command_id"]
        ),
        None,
    )
    pre_bound_index = (
        None
        if format_rebind is None
        else next(
            (
                index
                for index, row in enumerate(precommit)
                if row["id"] == format_rebind["pre_probe_media_command_id"]
            ),
            None,
        )
    )
    command_kinds = tuple(row["command_kind"] for row in precommit)
    if (
        len(precommit) != len(command_ids)
        or any(row["command_kind"] == "unload" for row in precommit)
        or media_binding["bound_by_command_id"] not in committed_id_set
        or (
            has_format_rebinding_schema
            and (
                format_rebind is None
                or cassette is None
                or format_rebind["owner_generation"] != operation["owner_generation"]
                or format_rebind["expected_label"] != cassette["physical_label"]
                or format_rebind["observed_label"] != cassette["physical_label"]
                or format_rebind["expected_serial"]
                != format_rebind["observed_serial"]
                or format_rebind["post_media_identity_sha256"]
                != media_binding["observed_media_identity_sha256"]
                or pre_bound_index is None
                or not imported_media_ledger_shape_valid(
                    command_kinds,
                    operation="format",
                    pre_bound_probe_index=pre_bound_index,
                    bound_probe_index=bound_index,
                )
                or (
                    precommit[pre_bound_index + 2]["id"]
                    != format_rebind["format_command_id"]
                    and precommit[pre_bound_index + 3]["id"]
                    != format_rebind["format_command_id"]
                )
                or precommit[bound_index]["id"]
                != format_rebind["post_probe_media_command_id"]
            )
        )
        or (
            not has_format_rebinding_schema
            and not any(row["command_kind"] == "unmount" for row in precommit)
        )
    ):
        return None
    identity_command = next(
        (row for row in precommit if row["id"] == media_binding["bound_by_command_id"]),
        None,
    )
    expected_identity_kind = (
        "probe_media" if has_format_rebinding_schema else "identify"
    )
    if (
        identity_command is None
        or identity_command["command_kind"] != expected_identity_kind
    ):
        return None
    postcommit = []
    for command in commands:
        created = _timestamp(command["created_at"])
        released = _timestamp(command["released_at"])
        exited = _timestamp(command["exit_observed_at"])
        quiesced = _timestamp(command["quiesced_at"])
        is_precommit = command["id"] in committed_id_set
        if (
            created is None
            or command["operation_id"] != operation["id"]
            or not hardware_command_release_evidence_valid(
                _postcommit_command_tuple(command)
            )
            or any(
                command[field] != target[field]
                for field in (
                    "mount_path_sha256",
                    "tape_device_identity_sha256",
                    "scsi_device_identity_sha256",
                    "expected_media_scope_sha256",
                )
            )
        ):
            return None
        if is_precommit:
            if (
                released is None
                or exited is None
                or quiesced is None
                or command["state"] != "quiesced"
                or not (created <= released <= exited <= quiesced)
                or command["exit_outcome"] != "completed"
                or not (started_at <= created <= quiesced <= committed_at)
                or command["issued_generation"] != operation["owner_generation"]
            ):
                return None
        else:
            if (
                command["command_kind"] not in _RECOVERY_COMMAND_KINDS
                or (
                    command["state"] == "quiesced"
                    and not imported_postcommit_terminal_timeline_valid(
                        outcome=command["exit_outcome"],
                        created_at=command["created_at"],
                        released_at=command["released_at"],
                        exit_observed_at=command["exit_observed_at"],
                        quiesced_at=command["quiesced_at"],
                        process_identity=tuple(
                            command[field]
                            for field in (
                                "boot_id",
                                "pid",
                                "process_start_ticks",
                                "process_group_id",
                            )
                        ),
                        committed_at=commit["committed_at"],
                    )
                )
                or (
                    command["state"] != "quiesced"
                    and not imported_postcommit_observation_transition_valid(
                        _postcommit_command_tuple(command),
                        _postcommit_command_tuple(command),
                    )
                )
            ):
                return None
            postcommit.append(command)
            if (
                created < media_bound_at
                or command["observed_media_identity_sha256"]
                != media_binding["observed_media_identity_sha256"]
            ):
                return None
            continue
        if not is_precommit:
            continue
        if has_format_rebinding_schema:
            command_index = precommit.index(command)
            expected_observed = (
                None
                if command_index <= pre_bound_index
                else format_rebind["pre_media_identity_sha256"]
                if command_index <= bound_index
                else media_binding["observed_media_identity_sha256"]
            )
            if command["observed_media_identity_sha256"] != expected_observed:
                return None
            if command["id"] == media_binding["bound_by_command_id"]:
                if quiesced > media_bound_at:
                    return None
            elif command_index > bound_index and created < media_bound_at:
                return None
        elif command["id"] == media_binding["bound_by_command_id"]:
            if quiesced > media_bound_at:
                return None
        elif quiesced <= media_bound_at:
            if command["observed_media_identity_sha256"] is not None:
                return None
        elif created >= media_bound_at:
            if (
                command["observed_media_identity_sha256"]
                != media_binding["observed_media_identity_sha256"]
            ):
                return None
        else:
            return None
    frozen_postcommit = tuple(postcommit)
    if not _postcommit_receipts_valid(
        connection,
        operation,
        commit,
        commands,
        command_ids,
        frozen_postcommit,
    ):
        return None
    return frozen_postcommit


def _activation_operation_state_valid(
    connection,
    operation,
    target,
    media_binding,
    commit,
    commands,
    postcommit_commands,
    committed_at: datetime | None,
    finished_at: datetime | None,
) -> bool:
    if committed_at is None:
        return False
    unloads = tuple(
        command
        for command in postcommit_commands
        if command["command_kind"] == "unload"
    )
    state = operation["state"]
    pending = tuple(
        command for command in postcommit_commands if command["state"] != "quiesced"
    )
    if pending:
        if len(postcommit_commands) != 1 or pending != unloads:
            return False
        if state == "running":
            return all(
                operation[field] is None
                for field in ("error_class", "error_code", "error_message")
            )
        return bool(
            state == "recovery_required"
            and operation["error_class"] == "operator_required"
            and operation["error_code"] == "recovery_required"
            and isinstance(operation["error_message"], str)
            and operation["error_message"]
        )
    if state == "running":
        return bool(
            operation["error_class"] is None
            and operation["error_code"] is None
            and operation["error_message"] is None
            and len(postcommit_commands) <= 1
            and len(unloads) == len(postcommit_commands)
        )
    if state == "succeeded":
        unload_quiesced = (
            _timestamp(unloads[0]["quiesced_at"]) if len(unloads) == 1 else None
        )
        return bool(
            len(postcommit_commands) == 1
            and unloads[0]["exit_outcome"] == "completed"
            and operation["error_class"] is None
            and operation["error_code"] is None
            and operation["error_message"] is None
            and unload_quiesced is not None
            and finished_at is not None
            and committed_at < unload_quiesced <= finished_at
        )
    failed_unloads = tuple(
        command
        for command in unloads
        if command["exit_outcome"] in {"terminated", "launch_aborted"}
    )
    if state == "recovery_required":
        zero_command_restart = _zero_command_restart_lineage(
            connection, operation, commit
        )
        completed_unload_restart = _completed_unload_restart_lineage(
            connection, operation, commit, unloads
        )
        unattested_terminal = _unattested_terminal_restart_observation(
            connection, operation, unloads
        )
        attempted_sequence = bool(
            len(failed_unloads) == 1
            and len(unloads) in {1, 2}
            and (
                len(unloads) == 1
                or (
                    unloads[1]["exit_outcome"] == "completed"
                    and _timestamp(unloads[0]["quiesced_at"])
                    < _timestamp(unloads[1]["created_at"])
                )
            )
        )
        return bool(
            (
                attempted_sequence
                or completed_unload_restart
                or unattested_terminal
                or (zero_command_restart and not unloads)
            )
            and operation["error_class"] == "operator_required"
            and operation["error_code"] in {"recovery_required", "unload_failed"}
            and isinstance(operation["error_message"], str)
            and operation["error_message"]
        )
    zero_crash_cancel = bool(
        _zero_command_restart_lineage(connection, operation, commit)
        and len(unloads) == 1
        and unloads[0]["exit_outcome"] == "completed"
    )
    completed_crash_cancel = _completed_unload_restart_lineage(
        connection, operation, commit, unloads
    )
    attempted_cancel = bool(
        len(unloads) == 2
        and len(failed_unloads) == 1
        and sum(command["exit_outcome"] == "completed" for command in unloads) == 1
    )
    if state != "cancelled" or not (
        zero_crash_cancel or completed_crash_cancel or attempted_cancel
    ):
        return False
    if any(
        operation[field] is not None
        for field in ("error_class", "error_code", "error_message")
    ):
        return False
    return _cancelled_recovery_valid(
        connection,
        operation,
        target,
        media_binding,
        commit,
        commands,
        unloads,
        failed_unloads,
        committed_at,
        finished_at,
    )


def _commands_with_release(connection, operation_id: str):
    return connection.execute(
        """
        SELECT command.*,
               authorization.permit_sha256 AS release_permit_sha256,
               authorization.release_status AS release_status,
               authorization.authorized_at AS release_authorized_at,
               authorization.confirmed_at AS release_confirmed_at
        FROM hardware_command_executions command
        LEFT JOIN hardware_command_release_authorizations authorization
          ON authorization.command_id=command.id
        WHERE command.operation_id=?
        ORDER BY command.created_at, command.id
        """,
        (operation_id,),
    ).fetchall()


def _postcommit_command_tuple(command) -> tuple[object, ...]:
    return tuple(command[key] for key in IMPORTED_POSTCOMMIT_COMMAND_FIELDS)


def _postcommit_ledger_sha256(commands) -> str:
    return imported_postcommit_command_sha256(
        tuple(_postcommit_command_tuple(command) for command in commands)
    )


def _recovery_lineages(connection, operation_id: str):
    return connection.execute(
        "SELECT * FROM imported_recovery_lineage_receipts WHERE operation_id=? "
        "ORDER BY recovery_generation, id",
        (operation_id,),
    ).fetchall()


def _postcommit_receipts_valid(
    connection,
    operation,
    commit,
    commands,
    command_ids,
    postcommit,
) -> bool:
    receipts = connection.execute(
        "SELECT * FROM imported_postcommit_command_receipts WHERE operation_id=? "
        "ORDER BY command_order",
        (operation["id"],),
    ).fetchall()
    lineages = _recovery_lineages(connection, operation["id"])
    owner = connection.execute(
        "SELECT owner_id, generation FROM daemon_ownership WHERE singleton=1"
    ).fetchone()
    command_by_id = {row["id"]: row for row in commands}
    prior_id = None
    prior_generation = commit["owner_generation"]
    lineage_by_generation = {}
    lineage_by_id = {}
    lineage_command_ids_by_id = {}
    lineage_observations_by_id = {}
    for lineage in lineages:
        try:
            lineage_ids = tuple(json.loads(lineage["command_ids_json"]))
            lineage_observations = tuple(
                tuple(value)
                for value in json.loads(lineage["command_observations_json"])
            )
            lineage_commands = tuple(command_by_id[value] for value in lineage_ids)
        except (KeyError, TypeError, ValueError):
            return False
        if (
            tuple(value[0] for value in lineage_observations) != lineage_ids
            or len(lineage_observations) != len(lineage_commands)
            or any(
                not imported_postcommit_observation_transition_valid(
                    observation, _postcommit_command_tuple(command)
                )
                for observation, command in zip(lineage_observations, lineage_commands)
            )
        ):
            return False
        lineage_evidence = imported_postcommit_command_sha256(lineage_observations)
        lineage_recorded = _timestamp(lineage["recorded_at"])
        lineage_command_times = tuple(
            _timestamp(observation[index])
            for observation in lineage_observations
            for index in (16, 17, 18, 19, 22, 23)
            if observation[index] is not None
        )
        transitioned_terminal_times = tuple(
            _timestamp(command["quiesced_at"])
            for observation, command in zip(lineage_observations, lineage_commands)
            if observation != _postcommit_command_tuple(command)
        )
        lineage_binding = imported_recovery_lineage_sha256(
            (
                lineage["id"],
                lineage["job_id"],
                lineage["sequence"],
                lineage["operation_id"],
                lineage["original_owner_generation"],
                lineage["recovery_generation"],
                lineage["daemon_owner_id"],
                lineage["prior_lineage_id"],
                lineage["commit_binding_sha256"],
                lineage["restart_state"],
                lineage_ids,
                lineage_evidence,
                lineage["recorded_at"],
            )
        )
        if (
            lineage["job_id"] != commit["job_id"]
            or lineage["sequence"] != 4
            or lineage["operation_id"] != operation["id"]
            or lineage["original_owner_generation"] != commit["owner_generation"]
            or lineage["recovery_generation"] <= prior_generation
            or lineage["prior_lineage_id"] != prior_id
            or lineage["commit_binding_sha256"] != commit["commit_binding_sha256"]
            or lineage["command_evidence_sha256"] != lineage_evidence
            or lineage["lineage_sha256"] != lineage_binding
            or lineage_recorded is None
            or lineage_recorded <= _timestamp(commit["committed_at"])
            or any(value is None for value in lineage_command_times)
            or any(value is None for value in transitioned_terminal_times)
            or (
                lineage_command_times and max(lineage_command_times) >= lineage_recorded
            )
            or (
                transitioned_terminal_times
                and min(transitioned_terminal_times) <= lineage_recorded
            )
        ):
            return False
        lineage_by_generation[lineage["recovery_generation"]] = lineage
        lineage_by_id[lineage["id"]] = lineage
        lineage_command_ids_by_id[lineage["id"]] = lineage_ids
        lineage_observations_by_id[lineage["id"]] = {
            value[0]: value for value in lineage_observations
        }
        prior_id = lineage["id"]
        prior_generation = lineage["recovery_generation"]
    if lineages:
        if owner is None:
            return False
        latest = lineages[-1]
        unresolved_owner_invalid = bool(
            operation["state"] in {"running", "recovery_required"}
            and (
                owner["generation"] != latest["recovery_generation"]
                or owner["owner_id"] != latest["daemon_owner_id"]
            )
        )
        terminal_owner_invalid = bool(
            operation["state"] == "cancelled"
            and (
                owner["generation"] < latest["recovery_generation"]
                or (
                    owner["generation"] == latest["recovery_generation"]
                    and owner["owner_id"] != latest["daemon_owner_id"]
                )
            )
        )
        if unresolved_owner_invalid or terminal_owner_invalid:
            return False
    receipt_by_command = {row["command_id"]: row for row in receipts}
    if len(receipt_by_command) != len(receipts) or set(receipt_by_command) - {
        row["id"] for row in postcommit
    }:
        return False
    for order, command in enumerate(postcommit, 1):
        receipt = receipt_by_command.get(command["id"])
        if command["state"] != "quiesced":
            if (
                receipt is not None
                or not lineages
                or command["id"] not in lineage_command_ids_by_id[lineages[-1]["id"]]
            ):
                return False
            continue
        if receipt is None:
            latest_observation = (
                None
                if not lineages
                else lineage_observations_by_id[lineages[-1]["id"]].get(command["id"])
            )
            current_command = _postcommit_command_tuple(command)
            if not (
                operation["state"] in {"running", "recovery_required"}
                and latest_observation is not None
                and latest_observation != current_command
                and imported_postcommit_observation_transition_valid(
                    latest_observation, current_command
                )
            ):
                return False
            continue
        evidence = imported_postcommit_command_sha256(
            _postcommit_command_tuple(command)
        )
        lineage = lineage_by_generation.get(command["issued_generation"])
        receipt_lineage = lineage_by_id.get(receipt["recovery_lineage_id"])
        historical_backfill = bool(
            receipt_lineage is not None
            and receipt_lineage["recovery_generation"] > command["issued_generation"]
            and command["id"] in lineage_command_ids_by_id[receipt_lineage["id"]]
        )
        expected_lineage_id = None if lineage is None else lineage["id"]
        receipt_recorded = _timestamp(receipt["recorded_at"])
        receipt_lineage_recorded = (
            None
            if receipt_lineage is None
            else _timestamp(receipt_lineage["recorded_at"])
        )
        if (
            receipt["command_id"] != command["id"]
            or receipt["operation_id"] != operation["id"]
            or receipt["job_id"] != commit["job_id"]
            or receipt["sequence"] != 4
            or receipt["issued_generation"] != command["issued_generation"]
            or (
                receipt["recovery_lineage_id"] != expected_lineage_id
                and not historical_backfill
            )
            or receipt["command_order"] != order
            or receipt["command_evidence_sha256"] != evidence
            or receipt_recorded is None
            or receipt_recorded <= _timestamp(command["quiesced_at"])
            or (
                historical_backfill
                and (
                    receipt_lineage_recorded is None
                    or receipt_recorded <= receipt_lineage_recorded
                )
            )
            or (
                lineage is None
                and command["issued_generation"] != commit["owner_generation"]
            )
        ):
            return False
    return True


def _zero_command_restart_lineage(connection, operation, commit) -> bool:
    lineages = _recovery_lineages(connection, operation["id"])
    if not lineages:
        return False
    for lineage in lineages:
        try:
            command_ids = tuple(json.loads(lineage["command_ids_json"]))
        except (TypeError, ValueError):
            return False
        if (
            lineage["restart_state"] == "running"
            and not command_ids
            and lineage["original_owner_generation"] == commit["owner_generation"]
        ):
            return True
    return False


def _completed_unload_restart_lineage(connection, operation, commit, unloads) -> bool:
    if len(unloads) != 1 or unloads[0]["exit_outcome"] != "completed":
        return False
    command = unloads[0]
    receipt = connection.execute(
        "SELECT * FROM imported_postcommit_command_receipts WHERE command_id=?",
        (command["id"],),
    ).fetchone()
    if (
        receipt is None
        or receipt["issued_generation"] != commit["owner_generation"]
        or receipt["recovery_lineage_id"] is not None
    ):
        return False
    receipt_recorded = _timestamp(receipt["recorded_at"])
    for lineage in _recovery_lineages(connection, operation["id"]):
        try:
            command_ids = tuple(json.loads(lineage["command_ids_json"]))
        except (TypeError, ValueError):
            return False
        lineage_recorded = _timestamp(lineage["recorded_at"])
        if (
            lineage["restart_state"] == "running"
            and command_ids == (command["id"],)
            and lineage["original_owner_generation"] == commit["owner_generation"]
            and receipt_recorded is not None
            and lineage_recorded is not None
            and receipt_recorded < lineage_recorded
        ):
            return True
    return False


def _unattested_terminal_restart_observation(connection, operation, unloads) -> bool:
    if len(unloads) != 1 or unloads[0]["state"] != "quiesced":
        return False
    command = unloads[0]
    if (
        connection.execute(
            "SELECT 1 FROM imported_postcommit_command_receipts WHERE command_id=?",
            (command["id"],),
        ).fetchone()
        is not None
    ):
        return False
    lineages = _recovery_lineages(connection, operation["id"])
    if not lineages:
        return False
    try:
        observations = {
            value[0]: tuple(value)
            for value in json.loads(lineages[-1]["command_observations_json"])
        }
    except (TypeError, ValueError):
        return False
    observed = observations.get(command["id"])
    current = _postcommit_command_tuple(command)
    return bool(
        observed is not None
        and observed != current
        and imported_postcommit_observation_transition_valid(observed, current)
    )


def _cancelled_recovery_valid(
    connection,
    operation,
    target,
    media_binding,
    commit,
    commands,
    unloads,
    failed_unloads,
    committed_at: datetime,
    finished_at: datetime | None,
) -> bool:
    lineages = _recovery_lineages(connection, operation["id"])
    recovery_generation = (
        lineages[-1]["recovery_generation"] if lineages else commit["owner_generation"]
    )
    resolutions = connection.execute(
        "SELECT * FROM recovery_resolutions WHERE operation_id=?",
        (operation["id"],),
    ).fetchall()
    if len(resolutions) != 1:
        return False
    resolution = resolutions[0]
    command_receipt = connection.execute(
        "SELECT * FROM command_quiescence_receipts WHERE id=?",
        (resolution["command_receipt_id"],),
    ).fetchone()
    physical = connection.execute(
        "SELECT * FROM physical_reconciliation_receipts WHERE id=?",
        (resolution["physical_receipt_id"],),
    ).fetchone()
    items = connection.execute(
        "SELECT command_id, exit_outcome FROM command_quiescence_receipt_items "
        "WHERE receipt_id=? ORDER BY command_id",
        (resolution["command_receipt_id"],),
    ).fetchall()
    resolution_receipts = connection.execute(
        "SELECT * FROM imported_recovery_resolution_receipts WHERE operation_id=?",
        (operation["id"],),
    ).fetchall()
    if command_receipt is None or physical is None:
        return False
    command_recorded = _timestamp(command_receipt["recorded_at"])
    physical_recorded = _timestamp(physical["recorded_at"])
    resolved_at = _timestamp(resolution["resolved_at"])
    latest_quiesced = max(
        (_timestamp(command["quiesced_at"]) for command in commands),
        default=None,
    )
    retry_unloads = tuple(
        command for command in unloads if command["exit_outcome"] == "completed"
    )
    failed_quiesced = max(
        (_timestamp(command["quiesced_at"]) for command in failed_unloads),
        default=None,
    )
    retry_created = max(
        (_timestamp(command["created_at"]) for command in retry_unloads),
        default=None,
    )
    exact_items = tuple(
        (row["command_id"], row["exit_outcome"]) for row in items
    ) == tuple(sorted((row["id"], row["exit_outcome"]) for row in commands))
    resolution_receipt = (
        resolution_receipts[0] if len(resolution_receipts) == 1 else None
    )
    expected_lineage_id = None
    if recovery_generation != commit["owner_generation"]:
        expected_lineage_id = lineages[-1]["id"] if lineages else None
    resolution_evidence = imported_recovery_resolution_sha256(
        (
            operation["id"],
            expected_lineage_id,
            commit["commit_binding_sha256"],
            recovery_generation,
            resolution["reason_code"],
            tuple(command_receipt),
            tuple((row["command_id"], row["exit_outcome"]) for row in items),
            tuple(physical),
            resolution["resolved_at"],
        )
    )
    unload_sequence_valid = bool(
        retry_created is not None
        and (
            (
                failed_quiesced is not None
                and committed_at < failed_quiesced < retry_created <= latest_quiesced
            )
            or (
                failed_quiesced is None
                and committed_at < retry_created <= latest_quiesced
                and (
                    _zero_command_restart_lineage(connection, operation, commit)
                    or _completed_unload_restart_lineage(
                        connection, operation, commit, unloads
                    )
                )
            )
        )
    )
    return bool(
        resolution_receipt is not None
        and resolution_receipt["recovery_lineage_id"] == expected_lineage_id
        and resolution_receipt["commit_binding_sha256"]
        == commit["commit_binding_sha256"]
        and resolution_receipt["resolved_generation"] == recovery_generation
        and resolution_receipt["command_receipt_id"] == command_receipt["id"]
        and resolution_receipt["physical_receipt_id"] == physical["id"]
        and resolution_receipt["resolved_at"] == resolution["resolved_at"]
        and resolution_receipt["resolution_evidence_sha256"] == resolution_evidence
        and resolution["resolved_by_generation"] == recovery_generation
        and command_receipt["operation_id"] == operation["id"]
        and command_receipt["reconciled_by_generation"] == recovery_generation
        and physical["operation_id"] == operation["id"]
        and physical["reconciled_by_generation"] == recovery_generation
        and physical["command_receipt_id"] == command_receipt["id"]
        and resolution["command_receipt_id"] == command_receipt["id"]
        and resolution["physical_receipt_id"] == physical["id"]
        and exact_items
        and physical["mounted"] == 0
        and physical["media_loaded"] == 0
        and physical["drive_busy"] == 0
        and physical["related_process_count"] == 0
        and physical["observed_media_identity_sha256"]
        == media_binding["observed_media_identity_sha256"]
        and all(
            physical[field] == target[field]
            for field in (
                "mount_path_sha256",
                "tape_device_identity_sha256",
                "scsi_device_identity_sha256",
                "expected_media_scope_sha256",
            )
        )
        and latest_quiesced is not None
        and retry_created is not None
        and command_recorded is not None
        and physical_recorded is not None
        and resolved_at is not None
        and finished_at is not None
        and unload_sequence_valid
        and latest_quiesced < command_recorded < physical_recorded < resolved_at
        and resolved_at <= finished_at
    )


def _next_sequence(cassettes: tuple[FrozenCassette, ...]) -> int | None:
    return next(
        (
            cassette.sequence
            for cassette in cassettes
            if cassette.status in {"pending", "waiting_media"}
        ),
        None,
    )


def _validate_source_item(
    item: FrozenItem, source_root: Path
) -> SourceValidationIssue | None:
    try:
        resolved_root = source_root.resolve(strict=True)
        candidate = (resolved_root / PurePosixPath(item.relative_path)).resolve(
            strict=True
        )
        candidate.relative_to(resolved_root)
        metadata = os.stat(candidate, follow_symlinks=False)
    except FileNotFoundError:
        return SourceValidationIssue(
            "source_missing", item.library_id, item.relative_path
        )
    except ValueError:
        return SourceValidationIssue(
            "source_path_invalid", item.library_id, item.relative_path
        )
    except OSError:
        return SourceValidationIssue(
            "source_unavailable", item.library_id, item.relative_path
        )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != item.size
        or metadata.st_mtime_ns != item.mtime_ns
    ):
        return SourceValidationIssue(
            "source_changed", item.library_id, item.relative_path
        )
    return None


def _safe_relative_path(value: str) -> bool:
    posix_path = PurePosixPath(value)
    windows_path = PureWindowsPath(value)
    return bool(
        value
        and value != "."
        and "\x00" not in value
        and "\\" not in value
        and not posix_path.is_absolute()
        and not windows_path.drive
        and not windows_path.root
        and ".." not in posix_path.parts
        and str(posix_path) == value
    )


def _nonnegative_integer(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _is_sha256(value: object) -> bool:
    return bool(
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )
