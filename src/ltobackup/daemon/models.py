from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

_SHA256 = re.compile(r"^[0-9a-f]{64}$")

IMPORTED_POSTCOMMIT_COMMAND_FIELDS = (
    "id",
    "operation_id",
    "issued_generation",
    "command_kind",
    "argv_sha256",
    "mount_path_sha256",
    "tape_device_identity_sha256",
    "scsi_device_identity_sha256",
    "expected_media_scope_sha256",
    "observed_media_identity_sha256",
    "state",
    "exit_outcome",
    "boot_id",
    "pid",
    "process_start_ticks",
    "process_group_id",
    "created_at",
    "released_at",
    "exit_observed_at",
    "quiesced_at",
    "release_permit_sha256",
    "release_status",
    "release_authorized_at",
    "release_confirmed_at",
)


def _utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _target_sha256(domain: str, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(
        b"lto-target-v1\0" + domain.encode("ascii") + b"\0" + encoded
    ).hexdigest()


def media_identity_sha256(identity_fields: tuple[object | None, ...]) -> str:
    """Hash the fixed-position, allowlisted observed-media identity tuple."""

    if not isinstance(identity_fields, tuple):
        raise TypeError("observed media identity must be a canonical tuple")
    return _target_sha256("observed-media", identity_fields)


def expected_media_scope_sha256(expected_media_scope: tuple[str, ...]) -> str:
    """Hash the fixed operation/job/cassette/label scope tuple."""

    if type(expected_media_scope) is not tuple or len(expected_media_scope) != 6:
        raise TypeError("expected media scope must be a canonical string tuple")
    if any(type(value) is not str for value in expected_media_scope):
        raise TypeError("expected media scope must contain exact strings")
    if any(
        len(value.encode("utf-8")) > 256
        or any(unicodedata.category(character).startswith("C") for character in value)
        for value in expected_media_scope
    ):
        raise ValueError("expected media scope contains unsafe text")
    operation_kind, job_id, sequence, volume_label, _, _ = expected_media_scope
    if (
        not operation_kind.strip()
        or not job_id.strip()
        or not sequence
        or not volume_label.strip()
        or any(value and not value.strip() for value in expected_media_scope[4:])
    ):
        raise ValueError("expected media scope core fields must be non-empty")
    try:
        numeric_sequence = int(sequence)
    except ValueError:
        raise ValueError("expected media scope sequence must be canonical") from None
    if numeric_sequence <= 0 or str(numeric_sequence) != sequence:
        raise ValueError("expected media scope sequence must be canonical")
    return _target_sha256("expected-media", expected_media_scope)


def sequence_continuation_idempotency_key(
    job_id: str,
    layout_fingerprint_sha256: str,
    cassette_sequence: int,
    owner_generation: int,
) -> str:
    """Bind one automatic continuation to its exact layout and daemon fence."""

    return hashlib.sha256(
        f"{job_id}\0{layout_fingerprint_sha256}\0{cassette_sequence}\0"
        f"{owner_generation}".encode("utf-8")
    ).hexdigest()


def imported_cassette_commit_binding_sha256(value: tuple[object, ...]) -> str:
    """Hash the immutable fenced cassette-commit ledger payload."""

    if not isinstance(value, tuple):
        raise TypeError("cassette commit binding must be a canonical tuple")
    return _target_sha256("imported-cassette-commit", value)


def imported_postcommit_command_sha256(value: tuple[object, ...]) -> str:
    """Hash one exact post-commit hardware command execution."""

    if not isinstance(value, tuple):
        raise TypeError("post-commit command evidence must be a canonical tuple")
    return _target_sha256("imported-postcommit-command", value)


def imported_postcommit_terminal_timeline_valid(
    *,
    outcome: object,
    created_at: object,
    released_at: object,
    exit_observed_at: object,
    quiesced_at: object,
    process_identity: tuple[object, object, object, object],
    committed_at: object,
) -> bool:
    """Validate the two exact terminal lifecycle shapes for postcommit commands."""

    created = _utc_timestamp(created_at)
    released = _utc_timestamp(released_at)
    exited = _utc_timestamp(exit_observed_at)
    quiesced = _utc_timestamp(quiesced_at)
    committed = _utc_timestamp(committed_at)
    if created is None or exited is None or quiesced is None or committed is None:
        return False
    if not committed < created:
        return False
    if outcome == "launch_aborted":
        return bool(
            released_at is None
            and (
                all(value is None for value in process_identity)
                or all(value is not None for value in process_identity)
            )
            and created <= exited == quiesced
        )
    if outcome == "terminated" and released_at is None:
        return bool(
            all(value is not None for value in process_identity)
            and created <= exited == quiesced
        )
    return bool(
        outcome in {"completed", "terminated"}
        and released is not None
        and all(value is not None for value in process_identity)
        and created <= released <= exited == quiesced
    )


def hardware_command_exit_transition_valid(
    *,
    prior_state: object,
    outcome: object,
    created_at: object,
    released_at: object,
    exit_at: object,
    recorded_process: tuple[object, object, object, object],
    evidence_process: tuple[object, object, object, object],
) -> bool:
    """Validate one public command acknowledgement against its launch state."""

    created = _utc_timestamp(created_at)
    released = _utc_timestamp(released_at)
    exited = _utc_timestamp(exit_at)
    if created is None or exited is None or created > exited:
        return False
    if prior_state == "launch_reserved":
        return bool(
            outcome == "launch_aborted"
            and released_at is None
            and all(value is None for value in recorded_process)
            and all(value is None for value in evidence_process)
        )
    if prior_state == "launch_blocked":
        return bool(
            outcome in {"launch_aborted", "terminated"}
            and released_at is None
            and all(value is not None for value in recorded_process)
            and recorded_process == evidence_process
        )
    if prior_state == "released":
        return bool(
            outcome in {"completed", "terminated"}
            and released is not None
            and created <= released <= exited
            and all(value is not None for value in recorded_process)
            and recorded_process == evidence_process
        )
    return False


def hardware_command_release_evidence_valid(command: tuple[object, ...]) -> bool:
    """Validate exact release-ledger evidence against the public command lifecycle."""

    if type(command) is not tuple or len(command) != len(
        IMPORTED_POSTCOMMIT_COMMAND_FIELDS
    ):
        return False
    state = command[10]
    outcome = command[11]
    process = command[12:16]
    created = _utc_timestamp(command[16])
    released = _utc_timestamp(command[17])
    exited = _utc_timestamp(command[18])
    quiesced = _utc_timestamp(command[19])
    permit = command[20]
    release_status = command[21]
    authorized = _utc_timestamp(command[22])
    confirmed = _utc_timestamp(command[23])
    if created is None:
        return False
    process_absent = all(value is None for value in process)
    process_exact = bool(
        type(process[0]) is str
        and process[0]
        and all(type(value) is int and value > 0 for value in process[1:])
    )
    no_release_row = command[20:24] == (None, None, None, None)
    if no_release_row:
        if state == "launch_reserved":
            return bool(
                outcome is None
                and process_absent
                and released is None
                and exited is None
                and quiesced is None
            )
        if state == "launch_blocked":
            return bool(
                outcome is None
                and process_exact
                and released is None
                and exited is None
                and quiesced is None
            )
        return bool(
            state == "quiesced"
            and outcome == "launch_aborted"
            and released is None
            and exited is not None
            and quiesced is not None
            and exited == quiesced
            and created <= exited
            and (process_absent or process_exact)
        )
    if (
        type(permit) is not str
        or _SHA256.fullmatch(permit) is None
        or release_status not in {"authorized", "released", "aborted", "ambiguous"}
        or authorized is None
        or not created <= authorized
    ):
        return False
    if release_status == "released":
        if (
            confirmed is None
            or released is None
            or confirmed != released
            or not authorized <= confirmed
            or not process_exact
        ):
            return False
        if state == "released":
            return bool(outcome is None and exited is None and quiesced is None)
        if state == "exit_observed":
            return bool(
                outcome in {"completed", "terminated"}
                and exited is not None
                and quiesced is None
                and released <= exited
            )
        return bool(
            state == "quiesced"
            and outcome in {"completed", "terminated"}
            and exited is not None
            and quiesced is not None
            and released <= exited == quiesced
        )
    if confirmed is not None or released is not None or not process_exact:
        return False
    if release_status == "authorized":
        return bool(
            state == "launch_blocked"
            and outcome is None
            and exited is None
            and quiesced is None
        )
    if release_status == "aborted":
        return bool(
            (
                state == "launch_blocked"
                and outcome is None
                and exited is None
                and quiesced is None
            )
            or (
                state == "quiesced"
                and outcome == "launch_aborted"
                and exited is not None
                and quiesced is not None
                and authorized <= exited == quiesced
            )
        )
    return bool(
        release_status == "ambiguous"
        and (
            (
                state == "launch_blocked"
                and outcome is None
                and exited is None
                and quiesced is None
            )
            or (
                state == "quiesced"
                and outcome == "terminated"
                and exited is not None
                and quiesced is not None
                and authorized <= exited == quiesced
            )
        )
    )


def imported_media_ledger_shape_valid(
    command_kinds: tuple[str, ...],
    *,
    operation: str,
    pre_bound_probe_index: int | None,
    bound_probe_index: int | None,
) -> bool:
    """Validate retryable pre-bind polls and the closed operation tail."""

    prefix_valid = bool(
        type(pre_bound_probe_index) is int
        and pre_bound_probe_index >= 1
        and pre_bound_probe_index % 2 == 1
        and command_kinds[: pre_bound_probe_index + 1]
        == ("identify", "probe_media") * ((pre_bound_probe_index + 1) // 2)
    )
    if not prefix_valid:
        return False
    tail = command_kinds[pre_bound_probe_index + 1 :]
    if operation == "append":
        return bound_probe_index == pre_bound_probe_index and tail == ("inquiry",)
    if operation == "format":
        return bool(
            (
                bound_probe_index == pre_bound_probe_index + 4
                and tail
                == ("inquiry", "format", "identify", "probe_media", "inquiry")
            )
            or (
                bound_probe_index == pre_bound_probe_index + 5
                and tail
                == (
                    "inquiry",
                    "probe_media",
                    "format",
                    "identify",
                    "probe_media",
                    "inquiry",
                )
            )
        )
    return False


def imported_postcommit_observation_transition_valid(
    observed: tuple[object, ...],
    current: tuple[object, ...],
) -> bool:
    """Validate an exact restart observation or its one allowed terminal transition."""

    if not hardware_command_release_evidence_valid(
        observed
    ) or not hardware_command_release_evidence_valid(current):
        return False
    if current == observed:
        state = observed[10]
        process = observed[12:16]
        created = _utc_timestamp(observed[16])
        if created is None:
            return False
        if state == "quiesced":
            return True
        if observed[11] is not None or observed[18:20] != (None, None):
            return False
        if state == "launch_reserved":
            return bool(
                all(value is None for value in process) and observed[17] is None
            )
        if state == "launch_blocked":
            return bool(
                all(value is not None for value in process) and observed[17] is None
            )
        if state == "released":
            released = _utc_timestamp(observed[17])
            return bool(
                all(value is not None for value in process)
                and released is not None
                and created <= released
            )
        return False
    immutable_indexes = (*range(10), 16)
    if any(current[index] != observed[index] for index in immutable_indexes):
        return False
    if current[10] != "quiesced" or observed[11] is not None:
        return False
    observed_process = observed[12:16]
    current_process = current[12:16]
    if observed[10] == "launch_reserved":
        return bool(
            all(value is None for value in observed_process)
            and observed[17:20] == (None, None, None)
            and current[11] == "launch_aborted"
            and current_process == observed_process
            and current[17] is None
            and observed[20:] == current[20:] == (None, None, None, None)
        )
    if observed[10] == "launch_blocked":
        observed_release = observed[20:24]
        current_release = current[20:24]
        release_transition_valid = bool(
            observed_release == current_release
            or (
                observed_release[1] == "authorized"
                and current_release
                == (
                    observed_release[0],
                    "aborted",
                    observed_release[2],
                    None,
                )
            )
        )
        return bool(
            all(value is not None for value in observed_process)
            and observed[17:20] == (None, None, None)
            and current[11] in {"launch_aborted", "terminated"}
            and current_process == observed_process
            and current[17] is None
            and release_transition_valid
        )
    if observed[10] == "released":
        return bool(
            all(value is not None for value in observed_process)
            and _utc_timestamp(observed[17]) is not None
            and observed[18:20] == (None, None)
            and current[11] in {"completed", "terminated"}
            and current_process == observed_process
            and current[17] == observed[17]
            and current[20:] == observed[20:]
        )
    return False


def imported_recovery_lineage_sha256(value: tuple[object, ...]) -> str:
    """Hash one restart lineage step for an imported operation."""

    if not isinstance(value, tuple):
        raise TypeError("recovery lineage evidence must be a canonical tuple")
    return _target_sha256("imported-recovery-lineage", value)


def imported_recovery_resolution_sha256(value: tuple[object, ...]) -> str:
    """Hash the exact durable resolution of one imported recovery lineage."""

    if not isinstance(value, tuple):
        raise TypeError("recovery resolution evidence must be a canonical tuple")
    return _target_sha256("imported-recovery-resolution", value)


def cutover_authorization_evidence_sha256(value: tuple[object, ...]) -> str:
    """Hash the complete consumed cutover authorization and target binding."""

    if not isinstance(value, tuple):
        raise TypeError("cutover authorization evidence must be a canonical tuple")
    return _target_sha256("cutover-authorization-evidence", value)


def cutover_catalog_binding_sha256(
    job_id: str,
    bundle_sha256: str,
    assignment_sha256: str,
    cassette_plan_sha256: str,
    completed_evidence_sha256: str,
    expected_label: str,
) -> str:
    """Bind one cutover credential to all immutable imported-plan evidence."""

    return _target_sha256(
        "cutover-catalog",
        (
            job_id,
            bundle_sha256,
            assignment_sha256,
            cassette_plan_sha256,
            completed_evidence_sha256,
            expected_label,
        ),
    )


@dataclass(frozen=True)
class OperationRecord:
    id: str
    kind: str
    state: str
    phase: str | None
    idempotency_key: str
    principal: str
    job_id: str | None
    cassette_sequence: int | None
    started_at: str
    finished_at: str | None
    error_class: str | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class OperationAdmission:
    record: OperationRecord
    replayed: bool


class OperationConflict(RuntimeError):
    def __init__(self, active: OperationRecord):
        self.active = active
        super().__init__("another catalog operation is already active")


class MutationAdmissionClosed(RuntimeError):
    pass


class RecoveryAdmissionBlocked(OperationConflict):
    pass


@dataclass(frozen=True)
class DaemonFence:
    owner_id: str
    generation: int


@dataclass(frozen=True)
class OperationFence:
    operation_id: str
    owner_generation: int


@dataclass(frozen=True)
class RecoveryCommandFence:
    operation_id: str
    owner_generation: int


class StaleDaemonFence(RuntimeError):
    pass


class StaleOperationFence(RuntimeError):
    pass


class CommandQuiescenceRequired(RuntimeError):
    pass


class MediaTargetMismatch(RuntimeError):
    def __init__(self) -> None:
        super().__init__("observed media identity does not match the immutable binding")


class PhysicalTargetMismatch(RuntimeError):
    _DIMENSIONS = frozenset(
        {
            "mount_path_sha256",
            "tape_device_identity_sha256",
            "scsi_device_identity_sha256",
            "expected_media_scope_sha256",
            "observed_media_identity_sha256",
        }
    )

    def __init__(self, dimension: str):
        if dimension not in self._DIMENSIONS:
            raise ValueError("invalid physical target dimension")
        self.dimension = dimension
        super().__init__(f"physical reconciliation mismatch: {dimension}")


@dataclass(frozen=True)
class ProcessIdentity:
    boot_id: str
    pid: int
    start_ticks: int
    process_group_id: int


@dataclass(frozen=True)
class CommandExitEvidence:
    command_id: str
    process: ProcessIdentity | None
    outcome: Literal["completed", "terminated", "launch_aborted"]
    quiesced_at: str
    terminal_exit_code: int | None = None


@dataclass(frozen=True)
class HardwareTargetBinding:
    mount_path_sha256: str
    tape_device_identity_sha256: str
    scsi_device_identity_sha256: str
    expected_media_scope_sha256: str

    def __post_init__(self) -> None:
        if not all(
            _SHA256.fullmatch(value)
            for value in (
                self.mount_path_sha256,
                self.tape_device_identity_sha256,
                self.scsi_device_identity_sha256,
                self.expected_media_scope_sha256,
            )
        ):
            raise ValueError("hardware target fields must be lowercase SHA-256 digests")

    @classmethod
    def from_verified_inputs(
        cls,
        canonical_mount_path: Path,
        stable_tape_identity: str,
        stable_scsi_identity: str,
        expected_media_scope: tuple[str, ...],
    ) -> HardwareTargetBinding:
        mount = str(Path(canonical_mount_path).resolve(strict=False))
        return cls(
            mount_path_sha256=_target_sha256("mount-path", mount),
            tape_device_identity_sha256=_target_sha256(
                "tape-device", stable_tape_identity
            ),
            scsi_device_identity_sha256=_target_sha256(
                "generic-scsi", stable_scsi_identity
            ),
            expected_media_scope_sha256=expected_media_scope_sha256(
                expected_media_scope
            ),
        )


@dataclass(frozen=True)
class HardwareCommandExecution:
    id: str
    operation_id: str
    issued_generation: int
    kind: str
    argv_sha256: str
    target: HardwareTargetBinding
    observed_media_identity_sha256: str | None
    state: str
    process: ProcessIdentity | None
    exit_outcome: str | None
    created_at: str
    release_permit_sha256: str | None
    release_status: str | None
    release_authorized_at: str | None
    release_confirmed_at: str | None
    released_at: str | None
    exit_observed_at: str | None
    quiesced_at: str | None
    terminal_exit_code: int | None = None


def critical_command_ledger_sha256(
    commands: tuple[HardwareCommandExecution, ...],
) -> str:
    """Hash the complete ordered command ledger observed by a critical action."""

    if type(commands) is not tuple or any(
        not isinstance(command, HardwareCommandExecution) for command in commands
    ):
        raise TypeError("critical command ledger must contain durable commands")
    payload = tuple(
        (
            command.id,
            command.operation_id,
            command.issued_generation,
            command.kind,
            command.argv_sha256,
            command.target.mount_path_sha256,
            command.target.tape_device_identity_sha256,
            command.target.scsi_device_identity_sha256,
            command.target.expected_media_scope_sha256,
            command.observed_media_identity_sha256,
            command.state,
            None
            if command.process is None
            else (
                command.process.boot_id,
                command.process.pid,
                command.process.start_ticks,
                command.process.process_group_id,
            ),
            command.exit_outcome,
            command.created_at,
            command.release_permit_sha256,
            command.release_status,
            command.release_authorized_at,
            command.release_confirmed_at,
            command.released_at,
            command.exit_observed_at,
            command.quiesced_at,
        )
        for command in commands
    )
    return hashlib.sha256(
        b"lto-critical-command-ledger-v1\0"
        + json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode(
            "ascii"
        )
    ).hexdigest()


@dataclass(frozen=True)
class CriticalRecoveryObservation:
    """One bounded, redacted, read-only observation for a critical action."""

    operation_id: str
    daemon_generation: int
    target: HardwareTargetBinding
    bound_media_identity_sha256: str | None
    observed_media_identity_sha256: str | None
    command_ledger_sha256: str
    commands_quiescent: bool
    mounted: bool
    media_loaded: bool
    drive_busy: bool
    related_process_count: int
    evidence_category: str
    evidence_sha256: str
    observed_at: str

    def __post_init__(self) -> None:
        if not isinstance(self.operation_id, str) or not self.operation_id:
            raise ValueError("critical observation operation is invalid")
        if type(self.daemon_generation) is not int or self.daemon_generation <= 0:
            raise ValueError("critical observation generation is invalid")
        if not isinstance(self.target, HardwareTargetBinding):
            raise TypeError("critical observation target is invalid")
        if self.bound_media_identity_sha256 is not None and not _SHA256.fullmatch(
            self.bound_media_identity_sha256
        ):
            raise ValueError("critical observation bound media digest is invalid")
        for value, name in (
            (self.command_ledger_sha256, "command ledger"),
            (self.evidence_sha256, "evidence"),
        ):
            if not isinstance(value, str) or not _SHA256.fullmatch(value):
                raise ValueError(f"critical observation {name} digest is invalid")
        if self.observed_media_identity_sha256 is not None and not _SHA256.fullmatch(
            self.observed_media_identity_sha256
        ):
            raise ValueError("critical observed media digest is invalid")
        if any(
            type(value) is not bool
            for value in (
                self.commands_quiescent,
                self.mounted,
                self.media_loaded,
                self.drive_busy,
            )
        ):
            raise TypeError("critical observation state must be boolean")
        if (
            type(self.related_process_count) is not int
            or self.related_process_count < 0
        ):
            raise ValueError("critical related process count is invalid")
        if (
            not isinstance(self.evidence_category, str)
            or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", self.evidence_category)
        ):
            raise ValueError("critical evidence category is invalid")
        observed = _utc_timestamp(self.observed_at)
        if observed is None:
            raise ValueError("critical observation timestamp is invalid")


@dataclass(frozen=True)
class CommandQuiescenceReceipt:
    id: str
    operation_id: str
    reconciled_by_generation: int
    command_ids: tuple[str, ...]
    evidence: tuple[CommandExitEvidence, ...]
    recorded_at: str


@dataclass(frozen=True)
class VerifiedPhysicalQuiescence:
    target: HardwareTargetBinding | None
    observed_media_identity_sha256: str | None
    mounted: Literal[False]
    media_loaded: Literal[False]
    drive_busy: Literal[False]
    related_processes: tuple[ProcessIdentity, ...]


@dataclass(frozen=True)
class PhysicalReconciliationReceipt:
    id: str
    operation_id: str
    reconciled_by_generation: int
    command_receipt_id: str
    target: HardwareTargetBinding | None
    observed_media_identity_sha256: str | None
    mounted: Literal[False]
    media_loaded: Literal[False]
    drive_busy: Literal[False]
    related_processes: tuple[ProcessIdentity, ...]
    recorded_at: str


@dataclass(frozen=True)
class SafeRecoveryResolution:
    reason_code: str
    command_receipt_id: str
    physical_receipt_id: str


@dataclass(frozen=True)
class RecoveryAttemptSummary:
    operation_id: str
    job_id: str | None
    cassette_sequence: int | None
    cassette_label: str | None
    attempt_number: int
    trigger: str
    started_evidence_sha256: str
    started_decision: str
    started_generation: int
    started_at: str
    state: str
    evidence_sha256: str
    decision: str
    daemon_generation: int
    outcome_at: str | None
    next_eligible_at: str | None


@dataclass(frozen=True)
class RecoveryAttemptClaim:
    """Atomic ownership result for one immutable recovery-attempt start."""

    attempt: RecoveryAttemptSummary
    owned: bool


@dataclass(frozen=True)
class RecoveryEffectReceipt:
    """Action-specific proof returned only after its durable effect is visible."""

    action: str
    operation_id: str
    owner_generation: int
    proof: str


@dataclass(frozen=True)
class ImportedJobPolicy:
    job_id: str
    policy_kind: str
    assignment_sha256: str
    cassette_plan_sha256: str
    completed_evidence_sha256: str
    bundle_sha256: str
    authority_state: str
    windows_authority: str
    rollback_allowed: bool
    frozen_at: str
    activated_by_operation: str | None
    activated_at: str | None
