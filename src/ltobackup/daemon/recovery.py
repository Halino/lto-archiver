"""Pure, hardware-free recovery policy for interrupted archive operations."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Any, Protocol

from .models import (
    CommandExitEvidence,
    CommandQuiescenceReceipt,
    HardwareCommandExecution,
    HardwareTargetBinding,
    PhysicalReconciliationReceipt,
    ProcessIdentity,
    hardware_command_release_evidence_valid,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_QUIESCED_OUTCOMES = frozenset({"completed", "terminated", "launch_aborted"})
_OPERATION_STATES = frozenset(
    {"running", "succeeded", "failed", "cancelled", "recovery_required"}
)
_OPERATION_PHASES = frozenset(
    {
        "identifying_media",
        "formatting_media",
        "mounting",
        "writing",
        "writing_manifest",
        "finalizing_index",
        "unmounting",
        "committing",
        "unloading",
    }
)
_DANGEROUS_PHASES = frozenset(
    {
        "formatting_media",
        "mounting",
        "writing",
        "writing_manifest",
        "finalizing_index",
        "unmounting",
    }
)
_HARDWARE_COMMAND_KINDS = frozenset(
    {
        "identify",
        "format",
        "mount",
        "unmount",
        "unload",
        "inquiry",
        "load",
        "status",
        "wait_for_media",
        "probe_mount",
        "probe_media",
        "probe_drive",
        "terminate_process_group",
        "startup-evidence",
    }
)


class RecoveryOutcome(StrEnum):
    RETRY = "retry"
    RECONCILE = "reconcile"
    RECOVERY_REQUIRED = "recovery_required"
    RESOLVED = "resolved"


class RecoveryAction(StrEnum):
    RETRY_CURRENT_CASSETTE = "retry_current_cassette"
    RETRY_IDENTIFICATION = "retry_identification"
    RECONCILE_COMMANDS = "reconcile_commands"
    RECONCILE_COMMIT = "reconcile_commit"
    RETRY_UNLOAD = "retry_unload"
    WAIT_FOR_MEDIA = "wait_for_media"
    ENTER_CRITICAL_QUARANTINE = "enter_critical_quarantine"
    # Compatibility only for previously serialized recovery data. The closed
    # normal-backup policy below never emits this action.
    REQUEST_OPERATOR = "request_operator"
    HOLD_ADMISSION = "hold_admission"
    OPEN_ADMISSION = "open_admission"
    PREPARE_RESTORE_RETRY = "prepare_restore_retry"
    RECONCILE_RESTORE_COMMIT = "reconcile_restore_commit"
    FINALIZE_RESTORE_CONTROL = "finalize_restore_control"


class RecoveryReason(StrEnum):
    WAITING_MEDIA_RETRY_SAFE = "waiting_media_retry_safe"
    IDENTIFICATION_RETRY_SAFE = "identification_retry_safe"
    COMMANDS_NOT_QUIESCENT = "commands_not_quiescent"
    STALE_GENERATION = "stale_generation"
    LINEAGE_MISSING = "lineage_missing"
    LINEAGE_MISMATCH = "lineage_mismatch"
    TARGET_MISMATCH = "target_mismatch"
    MEDIA_IDENTITY_MISMATCH = "media_identity_mismatch"
    MEDIA_BINDING_MISMATCH = "media_binding_mismatch"
    PHASE_REQUIRES_OPERATOR = "phase_requires_operator"
    CASSETTE_CHECKPOINT_RETRY_SAFE = "cassette_checkpoint_retry_safe"
    COMMIT_EVIDENCE_EXACT = "commit_evidence_exact"
    COMMIT_EVIDENCE_INCOMPLETE = "commit_evidence_incomplete"
    UNLOAD_IDENTITY_EXACT = "unload_identity_exact"
    UNLOAD_NOT_RETRYABLE = "unload_not_retryable"
    POSTCOMMIT_BACKUP_FAILED = "postcommit_backup_failed"
    POSTCOMMIT_UNLOAD_FAILED = "postcommit_unload_failed"
    RECEIPT_CHAIN_MISSING = "receipt_chain_missing"
    RECEIPT_CHAIN_MISMATCH = "receipt_chain_mismatch"
    PHYSICAL_NOT_QUIESCENT = "physical_not_quiescent"
    OPERATION_STILL_BLOCKING = "operation_still_blocking"
    RECOVERY_RESOLVED = "recovery_resolved"
    HISTORICAL_MEDIA_PROHIBITED = "historical_media_prohibited"
    UNKNOWN_PHASE = "unknown_phase"
    DURABLE_EVIDENCE_MISSING = "durable_evidence_missing"
    RESTORE_PHYSICAL_AMBIGUOUS = "restore_physical_ambiguous"
    RESTORE_DESTINATION_CONFLICT = "restore_destination_conflict"
    RESTORE_RETRY_SAFE = "restore_retry_safe"
    RESTORE_RELEASE_RECEIPT_MISSING = "restore_release_receipt_missing"
    RESTORE_COMMIT_EXACT = "restore_commit_exact"
    RESTORE_CONTROL_EXACT = "restore_control_exact"


@dataclass(frozen=True)
class MediaBinding:
    observed_media_identity_sha256: str
    bound_by_command_id: str
    bound_at: str

    def __post_init__(self) -> None:
        _validate_sha256(self.observed_media_identity_sha256, "observed media identity")
        if not self.bound_by_command_id:
            raise ValueError("media binding command must be present")
        _timestamp(self.bound_at)


@dataclass(frozen=True)
class DurableOperation:
    operation_id: str
    state: str
    phase: str | None
    interrupted_generation: int
    cassette_sequence: int
    target: HardwareTargetBinding
    expected_mount_source_identity_sha256: str
    expected_mount_fstype: str
    media_binding: MediaBinding | None
    started_at: str
    error_code: str | None = None
    kind: str = "archive.resume"

    def __post_init__(self) -> None:
        if not self.operation_id or self.interrupted_generation <= 0:
            raise ValueError("operation identity and generation must be durable")
        if self.kind not in {"archive.resume", "archive.native", "restore.cassette"}:
            raise ValueError("operation recovery kind is invalid")
        if self.cassette_sequence <= 0:
            raise ValueError("cassette sequence must be positive")
        _validate_sha256(
            self.expected_mount_source_identity_sha256,
            "expected mount source identity",
        )
        if not self.expected_mount_fstype:
            raise ValueError("expected mount filesystem type must be present")
        _timestamp(self.started_at)

    @property
    def observed_media_identity_sha256(self) -> str | None:
        if self.media_binding is None:
            return None
        return self.media_binding.observed_media_identity_sha256


@dataclass(frozen=True)
class RecoveryLineage:
    lineage_id: str
    operation_id: str
    original_generation: int
    recovery_generation: int
    prior_lineage_id: str | None
    command_ids: tuple[str, ...]
    recorded_at: str
    authenticated_sha256: str
    expected_sha256: str
    daemon_owner_id: str | None = None

    def __post_init__(self) -> None:
        if (
            not self.lineage_id
            or not self.operation_id
            or self.original_generation <= 0
            or self.recovery_generation <= self.original_generation
        ):
            raise ValueError("recovery lineage identity is invalid")
        if len(set(self.command_ids)) != len(self.command_ids):
            raise ValueError("recovery lineage commands must be unique")
        _timestamp(self.recorded_at)
        _validate_sha256(self.authenticated_sha256, "authenticated lineage")
        _validate_sha256(self.expected_sha256, "expected lineage")
        if self.daemon_owner_id is not None and not self.daemon_owner_id:
            raise ValueError("recovery lineage daemon owner cannot be empty")


def recovery_lineage_sha256(
    *,
    lineage_id: str,
    operation_id: str,
    original_generation: int,
    recovery_generation: int,
    prior_lineage_id: str | None,
    command_ids: tuple[str, ...],
    recorded_at: str,
    daemon_owner_id: str | None = None,
) -> str:
    """Hash the complete generic recovery-lineage binding."""

    fields = (
        lineage_id,
        operation_id,
        original_generation,
        recovery_generation,
        prior_lineage_id,
        command_ids,
        recorded_at,
    )
    domain = b"lto-recovery-lineage-v1\0"
    if daemon_owner_id is not None:
        fields = (
            lineage_id,
            operation_id,
            original_generation,
            recovery_generation,
            daemon_owner_id,
            prior_lineage_id,
            command_ids,
            recorded_at,
        )
        domain = b"lto-recovery-lineage-v2\0"
    encoded = json.dumps(
        fields,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(domain + encoded).hexdigest()


@dataclass(frozen=True)
class RecoveryContext:
    current_generation: int
    lineages: tuple[RecoveryLineage, ...]

    def __post_init__(self) -> None:
        if self.current_generation <= 0:
            raise ValueError("current recovery generation must be positive")


@dataclass(frozen=True)
class AggregateRecoveryProbe:
    target: HardwareTargetBinding
    observed_media_identity_sha256: str | None
    configured_mount_source_identity_sha256: str
    configured_mount_fstype: str
    mounted: bool
    mounted_source_identity_sha256: str | None
    mounted_fstype: str | None
    media_loaded: bool
    drive_busy: bool
    correlated_processes: tuple[ProcessIdentity, ...]

    def __post_init__(self) -> None:
        _validate_optional_sha256(
            self.observed_media_identity_sha256, "probe media identity"
        )
        _validate_sha256(
            self.configured_mount_source_identity_sha256,
            "configured mount source identity",
        )
        _validate_optional_sha256(
            self.mounted_source_identity_sha256, "mounted source identity"
        )
        if not self.configured_mount_fstype:
            raise ValueError("configured mount filesystem type must be present")
        if self.mounted_fstype is not None and not self.mounted_fstype:
            raise ValueError("mounted filesystem type cannot be empty")
        if len(set(self.correlated_processes)) != len(self.correlated_processes):
            raise ValueError("correlated process identities must be unique")


@dataclass(frozen=True)
class RestoreRecoveryCheckpoint:
    """Immutable-plan checkpoint used by restore-specific restart policy."""

    run_id: str
    cassette_sequence: int
    plan_fingerprint_sha256: str
    first_incomplete_item_sequence: int | None
    conflict_state: str | None
    commands_quiescent: bool = True
    release_boundary: str = "missing"
    pending_control: str | None = None
    pre_mount_recoverable: bool = False

    def __post_init__(self) -> None:
        if not self.run_id or self.cassette_sequence <= 0:
            raise ValueError("restore recovery coordinates are invalid")
        _validate_sha256(self.plan_fingerprint_sha256, "restore plan fingerprint")
        if (
            self.first_incomplete_item_sequence is not None
            and self.first_incomplete_item_sequence <= 0
        ):
            raise ValueError("restore incomplete item sequence is invalid")
        if self.conflict_state not in {None, "recorded", "authorized", "consumed"}:
            raise ValueError("restore conflict state is invalid")
        if type(self.commands_quiescent) is not bool:
            raise ValueError("restore command evidence is invalid")
        if self.release_boundary not in {"missing", "pre_mount", "post_eject"}:
            raise ValueError("restore release boundary is invalid")
        if self.pending_control not in {None, "paused", "cancelled"}:
            raise ValueError("restore pending control is invalid")
        if type(self.pre_mount_recoverable) is not bool:
            raise ValueError("restore pre-mount recovery evidence is invalid")


@dataclass(frozen=True)
class CommitEvidence:
    operation_id: str
    attempt_generation: int
    target: HardwareTargetBinding
    observed_media_identity_sha256: str
    unmount_command_id: str
    manifest_sha256: str
    provisional_manifest_sha256: str
    recorded_at: str

    def __post_init__(self) -> None:
        if self.attempt_generation <= 0:
            raise ValueError("commit attempt generation must be positive")
        _validate_sha256(self.observed_media_identity_sha256, "commit media identity")
        _validate_sha256(self.manifest_sha256, "manifest")
        _validate_sha256(self.provisional_manifest_sha256, "provisional manifest")
        _timestamp(self.recorded_at)


@dataclass(frozen=True)
class ResolutionReceipt:
    receipt_id: str
    operation_id: str
    resolved_generation: int
    command_receipt_id: str
    physical_receipt_id: str
    recorded_at: str


@dataclass(frozen=True)
class ReceiptChain:
    command: CommandQuiescenceReceipt | None = None
    physical: PhysicalReconciliationReceipt | None = None
    resolution: ResolutionReceipt | None = None


@dataclass(frozen=True)
class RecoveryInput:
    operation: DurableOperation
    recovery: RecoveryContext
    commands: tuple[HardwareCommandExecution, ...]
    probe: AggregateRecoveryProbe
    commit_evidence: CommitEvidence | None
    receipts: ReceiptChain


@dataclass(frozen=True)
class RecoveryDecision:
    outcome: RecoveryOutcome
    actions: tuple[RecoveryAction, ...]
    reason: RecoveryReason
    operator_required: bool
    admission_open: bool

    def __post_init__(self) -> None:
        if not self.actions or len(set(self.actions)) != len(self.actions):
            raise ValueError("recovery actions must be a non-empty closed set")
        if self.admission_open != (self.actions == (RecoveryAction.OPEN_ADMISSION,)):
            raise ValueError("admission can open only as the sole resolved action")
        if self.admission_open != (self.outcome is RecoveryOutcome.RESOLVED):
            raise ValueError("resolved outcome and admission state must agree")


class RecoveryStateSource(Protocol):
    def operation(self, operation_id: str) -> DurableOperation: ...

    def recovery_context(self, operation_id: str) -> RecoveryContext: ...

    def command_ledger(
        self, operation_id: str
    ) -> tuple[HardwareCommandExecution, ...]: ...

    def commit_evidence(self, operation_id: str) -> CommitEvidence | None: ...

    def receipt_chain(self, operation_id: str) -> ReceiptChain: ...


class RecoveryStateError(RuntimeError):
    """Raised when durable recovery evidence cannot be reconstructed exactly."""


class _CatalogRecoveryView(Protocol):
    def get_operation(self, operation_id: str) -> Any: ...

    def hardware_target_binding(
        self, operation_id: str
    ) -> HardwareTargetBinding | None: ...

    def media_identity_binding_evidence(self, operation_id: str) -> Any: ...

    def current_daemon_fence(self) -> Any: ...

    def recovery_lineage_evidence(self, operation_id: str) -> tuple[Any, ...]: ...

    def hardware_commands_for_operation(
        self, operation_id: str
    ) -> tuple[HardwareCommandExecution, ...]: ...

    def recovery_commit_evidence(
        self, operation_id: str
    ) -> CommitEvidence | None: ...

    def latest_command_quiescence_receipt(
        self, operation_id: str
    ) -> CommandQuiescenceReceipt | None: ...

    def latest_physical_reconciliation_receipt(
        self, operation_id: str
    ) -> PhysicalReconciliationReceipt | None: ...

    def recovery_resolution_evidence(self, operation_id: str) -> Any: ...


def _validate_process_model(process: ProcessIdentity | None) -> None:
    if process is None:
        return
    if (
        not isinstance(process, ProcessIdentity)
        or not isinstance(process.boot_id, str)
        or not process.boot_id
    ):
        raise ValueError("invalid recovery process identity")
    if any(
        type(value) is not int or value <= 0
        for value in (process.pid, process.start_ticks, process.process_group_id)
    ):
        raise ValueError("invalid recovery process identity")


def _validate_target_model(target: HardwareTargetBinding) -> None:
    if not isinstance(target, HardwareTargetBinding):
        raise TypeError("invalid recovery hardware target")
    for value in (
        target.mount_path_sha256,
        target.tape_device_identity_sha256,
        target.scsi_device_identity_sha256,
        target.expected_media_scope_sha256,
    ):
        _validate_sha256(value, "recovery hardware target")


def _validate_command_model(
    command: HardwareCommandExecution, operation_id: str
) -> None:
    if not isinstance(command, HardwareCommandExecution):
        raise TypeError("invalid recovery command model")
    if (
        not command.id
        or command.operation_id != operation_id
        or type(command.issued_generation) is not int
        or command.issued_generation <= 0
        or command.kind not in _HARDWARE_COMMAND_KINDS
    ):
        raise ValueError("invalid recovery command identity")
    _validate_sha256(command.argv_sha256, "command argument digest")
    _validate_target_model(command.target)
    _validate_optional_sha256(
        command.observed_media_identity_sha256, "command media identity"
    )
    _validate_process_model(command.process)
    _timestamp(command.created_at)
    for value in (
        command.released_at,
        command.exit_observed_at,
        command.quiesced_at,
        command.release_authorized_at,
        command.release_confirmed_at,
    ):
        if value is not None:
            _timestamp(value)
    if command.release_permit_sha256 is not None:
        _validate_sha256(command.release_permit_sha256, "command release permit")
    process = command.process
    canonical_state = (
        "launch_blocked" if command.state == "release_authorized" else command.state
    )
    lifecycle = (
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
        canonical_state,
        command.exit_outcome,
        None if process is None else process.boot_id,
        None if process is None else process.pid,
        None if process is None else process.start_ticks,
        None if process is None else process.process_group_id,
        command.created_at,
        command.released_at,
        command.exit_observed_at,
        command.quiesced_at,
        command.release_permit_sha256,
        command.release_status,
        command.release_authorized_at,
        command.release_confirmed_at,
    )
    if not hardware_command_release_evidence_valid(lifecycle):
        raise ValueError("invalid recovery command lifecycle")


def _validate_command_receipt_model(
    receipt: CommandQuiescenceReceipt, operation_id: str
) -> None:
    if not isinstance(receipt, CommandQuiescenceReceipt):
        raise TypeError("invalid command receipt model")
    if (
        not receipt.id
        or receipt.operation_id != operation_id
        or type(receipt.reconciled_by_generation) is not int
        or receipt.reconciled_by_generation <= 0
        or len(receipt.command_ids) != len(set(receipt.command_ids))
        or any(
            not isinstance(command_id, str) or not command_id
            for command_id in receipt.command_ids
        )
        or len(receipt.evidence) != len(receipt.command_ids)
    ):
        raise ValueError("invalid command receipt identity")
    _timestamp(receipt.recorded_at)
    evidence_ids: list[str] = []
    for item in receipt.evidence:
        if (
            not isinstance(item, CommandExitEvidence)
            or not item.command_id
            or item.outcome not in _QUIESCED_OUTCOMES
            or item.quiesced_at is None
        ):
            raise ValueError("invalid command receipt evidence")
        evidence_ids.append(item.command_id)
        _validate_process_model(item.process)
        _timestamp(item.quiesced_at)
    if tuple(evidence_ids) != receipt.command_ids:
        raise ValueError("command receipt evidence is not exact")


def _validate_physical_receipt_model(
    receipt: PhysicalReconciliationReceipt, operation_id: str
) -> None:
    if not isinstance(receipt, PhysicalReconciliationReceipt):
        raise TypeError("invalid physical receipt model")
    if (
        not receipt.id
        or receipt.operation_id != operation_id
        or type(receipt.reconciled_by_generation) is not int
        or receipt.reconciled_by_generation <= 0
        or not receipt.command_receipt_id
        or receipt.mounted is not False
        or receipt.media_loaded is not False
        or receipt.drive_busy is not False
        or receipt.related_processes
    ):
        raise ValueError("invalid physical receipt evidence")
    if receipt.target is not None:
        _validate_target_model(receipt.target)
    _validate_optional_sha256(
        receipt.observed_media_identity_sha256, "physical receipt media identity"
    )
    _timestamp(receipt.recorded_at)


def _validate_resolution_model(receipt: ResolutionReceipt, operation_id: str) -> None:
    if (
        not isinstance(receipt, ResolutionReceipt)
        or not receipt.receipt_id
        or receipt.operation_id != operation_id
        or type(receipt.resolved_generation) is not int
        or receipt.resolved_generation <= 0
        or not receipt.command_receipt_id
        or not receipt.physical_receipt_id
    ):
        raise ValueError("invalid recovery resolution identity")
    _timestamp(receipt.recorded_at)


class CatalogRecoveryStateSource:
    """Reconstruct closed recovery inputs only from public durable Catalog APIs."""

    def __init__(
        self,
        catalog: _CatalogRecoveryView,
        *,
        expected_mount_source_identity_sha256: str,
        expected_mount_fstype: str,
    ) -> None:
        _validate_sha256(
            expected_mount_source_identity_sha256,
            "expected mount source identity",
        )
        if not expected_mount_fstype:
            raise ValueError("expected mount filesystem type must be present")
        self._catalog = catalog
        self._expected_mount_source = expected_mount_source_identity_sha256
        self._expected_mount_fstype = expected_mount_fstype

    def operation(self, operation_id: str) -> DurableOperation:
        try:
            row = self._catalog.get_operation(operation_id)
            target = self._catalog.hardware_target_binding(operation_id)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError(
                "operation evidence cannot be reconstructed"
            ) from exc
        if row is None or target is None:
            raise RecoveryStateError("operation or exact hardware target is missing")
        try:
            sequence = row["cassette_sequence"]
            generation = row["owner_generation"]
        except (IndexError, KeyError, TypeError) as exc:
            raise RecoveryStateError(
                "operation recovery identity is incomplete"
            ) from exc
        if type(sequence) is not int or type(generation) is not int:
            raise RecoveryStateError("operation recovery identity is incomplete")
        if (
            row["id"] != operation_id
            or row["state"] not in _OPERATION_STATES
            or (row["phase"] is not None and row["phase"] not in _OPERATION_PHASES)
            or (
                row["error_code"] is not None and not isinstance(row["error_code"], str)
            )
        ):
            raise RecoveryStateError("operation recovery evidence is invalid")
        try:
            _validate_target_model(target)
            binding_row = self._catalog.media_identity_binding_evidence(operation_id)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError(
                "operation binding cannot be reconstructed"
            ) from exc
        binding = None
        if binding_row is not None:
            try:
                binding = MediaBinding(
                    observed_media_identity_sha256=binding_row[
                        "observed_media_identity_sha256"
                    ],
                    bound_by_command_id=binding_row["bound_by_command_id"],
                    bound_at=binding_row["bound_at"],
                )
            except (IndexError, KeyError, TypeError, ValueError) as exc:
                raise RecoveryStateError("media binding evidence is invalid") from exc
        try:
            return DurableOperation(
                operation_id=row["id"],
                state=row["state"],
                phase=row["phase"],
                interrupted_generation=generation,
                cassette_sequence=sequence,
                target=target,
                expected_mount_source_identity_sha256=self._expected_mount_source,
                expected_mount_fstype=self._expected_mount_fstype,
                media_binding=binding,
                started_at=row["started_at"],
                error_code=row["error_code"],
                kind=row["kind"],
            )
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError("operation recovery evidence is invalid") from exc

    def recovery_context(self, operation_id: str) -> RecoveryContext:
        try:
            owner = self._catalog.current_daemon_fence()
            rows = self._catalog.recovery_lineage_evidence(operation_id)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError(
                "recovery lineage cannot be reconstructed"
            ) from exc
        if owner is None:
            raise RecoveryStateError("current recovery daemon ownership is missing")
        if (
            not isinstance(owner.owner_id, str)
            or not owner.owner_id
            or type(owner.generation) is not int
            or owner.generation <= 0
        ):
            raise RecoveryStateError("current recovery daemon ownership is invalid")
        lineages: list[RecoveryLineage] = []
        for row in rows:
            try:
                decoded = json.loads(row["command_ids_json"])
                if not isinstance(decoded, list) or not all(
                    isinstance(command_id, str) and command_id for command_id in decoded
                ):
                    raise ValueError("invalid lineage command ids")
                command_ids = tuple(decoded)
                if (
                    row["operation_id"] != operation_id
                    or not isinstance(row["id"], str)
                    or not row["id"]
                    or not isinstance(row["daemon_owner_id"], str)
                    or not row["daemon_owner_id"]
                    or type(row["original_generation"]) is not int
                    or type(row["recovery_generation"]) is not int
                    or (
                        row["prior_lineage_id"] is not None
                        and (
                            not isinstance(row["prior_lineage_id"], str)
                            or not row["prior_lineage_id"]
                        )
                    )
                ):
                    raise ValueError("invalid recovery lineage identity")
                expected = recovery_lineage_sha256(
                    lineage_id=row["id"],
                    operation_id=row["operation_id"],
                    original_generation=row["original_generation"],
                    recovery_generation=row["recovery_generation"],
                    daemon_owner_id=row["daemon_owner_id"],
                    prior_lineage_id=row["prior_lineage_id"],
                    command_ids=command_ids,
                    recorded_at=row["recorded_at"],
                )
                lineages.append(
                    RecoveryLineage(
                        lineage_id=row["id"],
                        operation_id=row["operation_id"],
                        original_generation=row["original_generation"],
                        recovery_generation=row["recovery_generation"],
                        prior_lineage_id=row["prior_lineage_id"],
                        command_ids=command_ids,
                        recorded_at=row["recorded_at"],
                        authenticated_sha256=row["lineage_sha256"],
                        expected_sha256=expected,
                        daemon_owner_id=row["daemon_owner_id"],
                    )
                )
            except (IndexError, KeyError, TypeError, ValueError) as exc:
                raise RecoveryStateError(
                    "recovery lineage evidence is invalid"
                ) from exc
        if lineages and (
            lineages[-1].recovery_generation == owner.generation
            and lineages[-1].daemon_owner_id != owner.owner_id
        ):
            raise RecoveryStateError("current recovery lineage owner is not exact")
        return RecoveryContext(owner.generation, tuple(lineages))

    def command_ledger(self, operation_id: str) -> tuple[HardwareCommandExecution, ...]:
        try:
            commands = self._catalog.hardware_commands_for_operation(operation_id)
            for command in commands:
                _validate_command_model(command, operation_id)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError("command ledger cannot be reconstructed") from exc
        return commands

    def commit_evidence(self, operation_id: str) -> CommitEvidence | None:
        reader = getattr(self._catalog, "recovery_commit_evidence", None)
        if reader is None:
            return None
        try:
            evidence = reader(operation_id)
            if evidence is not None and not isinstance(evidence, CommitEvidence):
                raise TypeError("invalid commit evidence")
            return evidence
        except (AttributeError, IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError(
                "commit evidence cannot be reconstructed"
            ) from exc

    def receipt_chain(self, operation_id: str) -> ReceiptChain:
        try:
            command = self._catalog.latest_command_quiescence_receipt(operation_id)
            physical = self._catalog.latest_physical_reconciliation_receipt(
                operation_id
            )
            row = self._catalog.recovery_resolution_evidence(operation_id)
            if command is not None:
                _validate_command_receipt_model(command, operation_id)
            if physical is not None:
                _validate_physical_receipt_model(physical, operation_id)
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise RecoveryStateError(
                "recovery receipts cannot be reconstructed"
            ) from exc
        resolution = None
        if row is not None:
            try:
                if not isinstance(row["reason_code"], str) or not row["reason_code"]:
                    raise ValueError("invalid recovery resolution reason")
                resolution = ResolutionReceipt(
                    receipt_id=row["operation_id"],
                    operation_id=row["operation_id"],
                    resolved_generation=row["resolved_by_generation"],
                    command_receipt_id=row["command_receipt_id"],
                    physical_receipt_id=row["physical_receipt_id"],
                    recorded_at=row["resolved_at"],
                )
                _validate_resolution_model(resolution, operation_id)
            except (IndexError, KeyError, TypeError, ValueError) as exc:
                raise RecoveryStateError("recovery resolution is invalid") from exc
        return ReceiptChain(command, physical, resolution)


class AggregateProbeSource(Protocol):
    def inspect(self, operation: DurableOperation) -> AggregateRecoveryProbe: ...


class RecoveryManager:
    def __init__(
        self, state_source: RecoveryStateSource, probe_source: AggregateProbeSource
    ) -> None:
        self._state_source = state_source
        self._probe_source = probe_source

    def inspect(self, operation_id: str) -> RecoveryDecision:
        try:
            operation = self._state_source.operation(operation_id)
        except (RecoveryStateError, TypeError, ValueError):
            return _blocked(
                RecoveryReason.DURABLE_EVIDENCE_MISSING,
                operator_required=True,
            )
        if (
            operation.kind == "archive.resume"
            and operation.cassette_sequence <= 3
        ):
            return _blocked(
                RecoveryReason.HISTORICAL_MEDIA_PROHIBITED,
                operator_required=True,
            )
        try:
            return decide_recovery(
                RecoveryInput(
                    operation,
                    self._state_source.recovery_context(operation_id),
                    self._state_source.command_ledger(operation_id),
                    self._probe_source.inspect(operation),
                    self._state_source.commit_evidence(operation_id),
                    self._state_source.receipt_chain(operation_id),
                )
            )
        except (RecoveryStateError, TypeError, ValueError):
            return _blocked(
                RecoveryReason.DURABLE_EVIDENCE_MISSING,
                operator_required=True,
            )


def decide_recovery(snapshot: RecoveryInput) -> RecoveryDecision:
    operation = snapshot.operation
    if operation.kind == "archive.resume" and operation.cassette_sequence <= 3:
        return _blocked(
            RecoveryReason.HISTORICAL_MEDIA_PROHIBITED,
            operator_required=True,
        )
    if operation.error_code == "media_target_mismatch":
        return _blocked(RecoveryReason.MEDIA_IDENTITY_MISMATCH, operator_required=True)

    lineage_reason = _lineage_reason(snapshot)
    if lineage_reason is not None:
        return _blocked(lineage_reason, operator_required=True)

    command_reason = _command_ledger_reason(snapshot)
    if command_reason is not None:
        if command_reason is RecoveryReason.COMMANDS_NOT_QUIESCENT:
            return RecoveryDecision(
                RecoveryOutcome.RECOVERY_REQUIRED,
                (
                    RecoveryAction.RECONCILE_COMMANDS,
                    RecoveryAction.HOLD_ADMISSION,
                ),
                command_reason,
                operator_required=False,
                admission_open=False,
            )
        return _blocked(command_reason, operator_required=True)

    identity_reason = _probe_identity_reason(operation, snapshot.probe)
    if identity_reason is not None:
        return _blocked(identity_reason, operator_required=True)
    if not _configured_mount_exact(operation, snapshot.probe):
        return _blocked(RecoveryReason.PHYSICAL_NOT_QUIESCENT, operator_required=True)
    if not _mounted_identity_exact(operation, snapshot.probe):
        return _blocked(RecoveryReason.PHYSICAL_NOT_QUIESCENT, operator_required=True)
    if (
        operation.state in {"running", "recovery_required"}
        and operation.error_code is None
        and operation.media_binding is not None
        and (operation.phase is None or operation.phase in _DANGEROUS_PHASES)
        and _media_absence_safe(snapshot.probe)
    ):
        return _wait_for_media()

    receipt_reason = _receipt_chain_reason(snapshot)
    if operation.state not in {"running", "recovery_required"}:
        if operation.state == "cancelled" and receipt_reason is None:
            return RecoveryDecision(
                RecoveryOutcome.RESOLVED,
                (RecoveryAction.OPEN_ADMISSION,),
                RecoveryReason.RECOVERY_RESOLVED,
                operator_required=False,
                admission_open=True,
            )
        if receipt_reason in {
            RecoveryReason.RECEIPT_CHAIN_MISMATCH,
            RecoveryReason.PHYSICAL_NOT_QUIESCENT,
        }:
            return _blocked(receipt_reason, operator_required=True)
        return _hold(receipt_reason or RecoveryReason.OPERATION_STILL_BLOCKING)

    if snapshot.probe.correlated_processes:
        return _blocked(RecoveryReason.PHYSICAL_NOT_QUIESCENT, operator_required=True)
    if operation.error_code == "postcommit_backup_failed":
        return _blocked(RecoveryReason.POSTCOMMIT_BACKUP_FAILED, operator_required=True)
    if operation.error_code == "unload_failed":
        if _unload_retryable(snapshot.probe):
            return RecoveryDecision(
                RecoveryOutcome.RETRY,
                (RecoveryAction.RETRY_UNLOAD, RecoveryAction.HOLD_ADMISSION),
                RecoveryReason.POSTCOMMIT_UNLOAD_FAILED,
                operator_required=False,
                admission_open=False,
            )
        return _blocked(
            RecoveryReason.POSTCOMMIT_UNLOAD_FAILED,
            operator_required=True,
        )

    phase = operation.phase
    if phase is None:
        if not _waiting_for_media_safe(snapshot.probe):
            return _blocked(
                RecoveryReason.PHYSICAL_NOT_QUIESCENT, operator_required=True
            )
        if operation.media_binding is not None and snapshot.probe.media_loaded:
            return RecoveryDecision(
                RecoveryOutcome.RETRY,
                (
                    RecoveryAction.RETRY_CURRENT_CASSETTE,
                    RecoveryAction.HOLD_ADMISSION,
                ),
                RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
                operator_required=False,
                admission_open=False,
            )
        return _wait_for_media()
    if phase == "identifying_media":
        if not _identification_retryable(snapshot.probe):
            return _blocked(
                RecoveryReason.PHYSICAL_NOT_QUIESCENT, operator_required=True
            )
        return RecoveryDecision(
            RecoveryOutcome.RETRY,
            (
                RecoveryAction.RETRY_IDENTIFICATION,
                RecoveryAction.HOLD_ADMISSION,
            ),
            RecoveryReason.IDENTIFICATION_RETRY_SAFE,
            operator_required=False,
            admission_open=False,
        )
    if phase in _DANGEROUS_PHASES:
        return RecoveryDecision(
            RecoveryOutcome.RETRY,
            (
                RecoveryAction.RETRY_CURRENT_CASSETTE,
                RecoveryAction.HOLD_ADMISSION,
            ),
            RecoveryReason.CASSETTE_CHECKPOINT_RETRY_SAFE,
            operator_required=False,
            admission_open=False,
        )
    if phase == "committing":
        if not _physical_clean(snapshot.probe):
            return _blocked(
                RecoveryReason.PHYSICAL_NOT_QUIESCENT, operator_required=True
            )
        if not _commit_evidence_exact(snapshot):
            return _blocked(
                RecoveryReason.COMMIT_EVIDENCE_INCOMPLETE,
                operator_required=True,
            )
        return RecoveryDecision(
            RecoveryOutcome.RECONCILE,
            (RecoveryAction.RECONCILE_COMMIT, RecoveryAction.HOLD_ADMISSION),
            RecoveryReason.COMMIT_EVIDENCE_EXACT,
            operator_required=False,
            admission_open=False,
        )
    if phase == "unloading":
        if not _unload_retryable(snapshot.probe):
            return _blocked(RecoveryReason.UNLOAD_NOT_RETRYABLE, operator_required=True)
        return RecoveryDecision(
            RecoveryOutcome.RETRY,
            (RecoveryAction.RETRY_UNLOAD, RecoveryAction.HOLD_ADMISSION),
            RecoveryReason.UNLOAD_IDENTITY_EXACT,
            operator_required=False,
            admission_open=False,
        )
    return _blocked(RecoveryReason.UNKNOWN_PHASE, operator_required=True)


def decide_restore_recovery(
    checkpoint: RestoreRecoveryCheckpoint,
    probe: AggregateRecoveryProbe,
) -> RecoveryDecision:
    """Fail closed unless restart evidence proves an ejected restore boundary."""

    if checkpoint.conflict_state == "recorded":
        return _blocked(
            RecoveryReason.RESTORE_DESTINATION_CONFLICT,
            operator_required=True,
        )
    if not checkpoint.commands_quiescent:
        return _blocked(
            RecoveryReason.COMMANDS_NOT_QUIESCENT,
            operator_required=True,
        )
    if not _physical_clean(probe):
        return _blocked(
            RecoveryReason.RESTORE_PHYSICAL_AMBIGUOUS,
            operator_required=True,
        )
    if (
        checkpoint.release_boundary == "missing"
        and not checkpoint.pre_mount_recoverable
    ):
        return _blocked(
            RecoveryReason.RESTORE_RELEASE_RECEIPT_MISSING,
            operator_required=True,
        )
    if checkpoint.pending_control is not None:
        return RecoveryDecision(
            RecoveryOutcome.RECONCILE,
            (RecoveryAction.FINALIZE_RESTORE_CONTROL, RecoveryAction.HOLD_ADMISSION),
            RecoveryReason.RESTORE_CONTROL_EXACT,
            operator_required=False,
            admission_open=False,
        )
    if checkpoint.release_boundary not in {"pre_mount", "post_eject"} and not (
        checkpoint.release_boundary == "missing"
        and checkpoint.pre_mount_recoverable
    ):
        return _blocked(
            RecoveryReason.RESTORE_RELEASE_RECEIPT_MISSING,
            operator_required=True,
        )
    if checkpoint.first_incomplete_item_sequence is None:
        return RecoveryDecision(
            RecoveryOutcome.RECONCILE,
            (RecoveryAction.RECONCILE_RESTORE_COMMIT, RecoveryAction.HOLD_ADMISSION),
            RecoveryReason.RESTORE_COMMIT_EXACT,
            operator_required=False,
            admission_open=False,
        )
    return RecoveryDecision(
        RecoveryOutcome.RETRY,
        (RecoveryAction.PREPARE_RESTORE_RETRY, RecoveryAction.HOLD_ADMISSION),
        RecoveryReason.RESTORE_RETRY_SAFE,
        operator_required=False,
        admission_open=False,
    )


def _lineage_reason(snapshot: RecoveryInput) -> RecoveryReason | None:
    operation = snapshot.operation
    current = snapshot.recovery.current_generation
    lineages = snapshot.recovery.lineages
    if current < operation.interrupted_generation:
        return RecoveryReason.STALE_GENERATION
    if current == operation.interrupted_generation:
        if lineages:
            return RecoveryReason.LINEAGE_MISMATCH
        if any(
            command.issued_generation != operation.interrupted_generation
            for command in snapshot.commands
        ):
            return RecoveryReason.STALE_GENERATION
        return None
    if not lineages:
        return RecoveryReason.LINEAGE_MISSING
    prior_id: str | None = None
    prior_generation = operation.interrupted_generation
    for lineage in lineages:
        expected_authentication = recovery_lineage_sha256(
            lineage_id=lineage.lineage_id,
            operation_id=lineage.operation_id,
            original_generation=lineage.original_generation,
            recovery_generation=lineage.recovery_generation,
            daemon_owner_id=lineage.daemon_owner_id,
            prior_lineage_id=lineage.prior_lineage_id,
            command_ids=lineage.command_ids,
            recorded_at=lineage.recorded_at,
        )
        if (
            lineage.operation_id != operation.operation_id
            or lineage.original_generation != operation.interrupted_generation
            or lineage.recovery_generation <= prior_generation
            or lineage.prior_lineage_id != prior_id
            or lineage.authenticated_sha256 != expected_authentication
            or lineage.expected_sha256 != expected_authentication
        ):
            return RecoveryReason.LINEAGE_MISMATCH
        recorded = _timestamp(lineage.recorded_at)
        expected_ids = tuple(
            command.id
            for command in snapshot.commands
            if _timestamp(command.created_at) < recorded
        )
        if lineage.command_ids != expected_ids:
            return RecoveryReason.LINEAGE_MISMATCH
        prior_id = lineage.lineage_id
        prior_generation = lineage.recovery_generation
    if prior_generation != current:
        return RecoveryReason.LINEAGE_MISMATCH
    allowed_generations = {operation.interrupted_generation}
    allowed_generations.update(lineage.recovery_generation for lineage in lineages)
    for command in snapshot.commands:
        if command.issued_generation not in allowed_generations:
            return RecoveryReason.LINEAGE_MISMATCH
        if command.issued_generation == operation.interrupted_generation:
            if command.id not in lineages[0].command_ids:
                return RecoveryReason.LINEAGE_MISMATCH
            continue
        origin = next(
            lineage
            for lineage in lineages
            if lineage.recovery_generation == command.issued_generation
        )
        if _timestamp(command.created_at) <= _timestamp(origin.recorded_at):
            return RecoveryReason.LINEAGE_MISMATCH
    return None


def _command_ledger_reason(snapshot: RecoveryInput) -> RecoveryReason | None:
    operation = snapshot.operation
    seen: set[str] = set()
    for command in snapshot.commands:
        if command.id in seen or command.operation_id != operation.operation_id:
            return RecoveryReason.COMMANDS_NOT_QUIESCENT
        seen.add(command.id)
        if command.target != operation.target:
            return RecoveryReason.TARGET_MISMATCH
        if (
            command.state != "quiesced"
            or command.exit_outcome not in _QUIESCED_OUTCOMES
            or command.quiesced_at is None
            or _timestamp(command.quiesced_at) < _timestamp(command.created_at)
        ):
            return RecoveryReason.COMMANDS_NOT_QUIESCENT
    return _media_binding_reason(snapshot)


def _media_binding_reason(snapshot: RecoveryInput) -> RecoveryReason | None:
    binding = snapshot.operation.media_binding
    if binding is None:
        if any(
            command.kind != "identify"
            or command.observed_media_identity_sha256 is not None
            for command in snapshot.commands
        ):
            return RecoveryReason.MEDIA_BINDING_MISMATCH
        return None
    bound_at = _timestamp(binding.bound_at)
    bound_command = next(
        (
            command
            for command in snapshot.commands
            if command.id == binding.bound_by_command_id
        ),
        None,
    )
    if (
        bound_command is None
        or bound_command.kind != "identify"
        or bound_command.state != "quiesced"
        or bound_command.exit_outcome != "completed"
        or bound_command.observed_media_identity_sha256 is not None
        or bound_command.quiesced_at is None
        or _timestamp(bound_command.quiesced_at) >= bound_at
    ):
        return RecoveryReason.MEDIA_BINDING_MISMATCH
    for command in snapshot.commands:
        created = _timestamp(command.created_at)
        if created >= bound_at:
            if (
                command.observed_media_identity_sha256
                != binding.observed_media_identity_sha256
            ):
                return RecoveryReason.MEDIA_BINDING_MISMATCH
        elif command.observed_media_identity_sha256 is not None:
            return RecoveryReason.MEDIA_BINDING_MISMATCH
    return None


def _probe_identity_reason(
    operation: DurableOperation, probe: AggregateRecoveryProbe
) -> RecoveryReason | None:
    if probe.target != operation.target:
        return RecoveryReason.TARGET_MISMATCH
    if (
        operation.media_binding is not None
        and probe.observed_media_identity_sha256
        != operation.observed_media_identity_sha256
    ):
        if _media_absence_safe(probe):
            return None
        return RecoveryReason.MEDIA_IDENTITY_MISMATCH
    return None


def _configured_mount_exact(
    operation: DurableOperation, probe: AggregateRecoveryProbe
) -> bool:
    return bool(
        probe.configured_mount_source_identity_sha256
        == operation.expected_mount_source_identity_sha256
        and probe.configured_mount_fstype == operation.expected_mount_fstype
    )


def _mounted_identity_exact(
    operation: DurableOperation, probe: AggregateRecoveryProbe
) -> bool:
    if not probe.mounted:
        return bool(
            probe.mounted_source_identity_sha256 is None
            and probe.mounted_fstype is None
        )
    return bool(
        probe.mounted_source_identity_sha256
        == operation.expected_mount_source_identity_sha256
        and probe.mounted_fstype == operation.expected_mount_fstype
    )


def _physical_clean(probe: AggregateRecoveryProbe) -> bool:
    return bool(
        not probe.mounted
        and probe.mounted_source_identity_sha256 is None
        and probe.mounted_fstype is None
        and not probe.media_loaded
        and not probe.drive_busy
        and not probe.correlated_processes
    )


def _waiting_for_media_safe(probe: AggregateRecoveryProbe) -> bool:
    return bool(
        not probe.mounted
        and probe.mounted_source_identity_sha256 is None
        and probe.mounted_fstype is None
        and not probe.drive_busy
        and not probe.correlated_processes
    )


def _media_absence_safe(probe: AggregateRecoveryProbe) -> bool:
    return bool(
        not probe.media_loaded
        and probe.observed_media_identity_sha256 is None
        and _waiting_for_media_safe(probe)
    )


def _identification_retryable(probe: AggregateRecoveryProbe) -> bool:
    return bool(
        not probe.mounted
        and probe.mounted_source_identity_sha256 is None
        and probe.mounted_fstype is None
        and not probe.drive_busy
        and not probe.correlated_processes
    )


def _unload_retryable(probe: AggregateRecoveryProbe) -> bool:
    return bool(
        not probe.mounted
        and probe.mounted_source_identity_sha256 is None
        and probe.mounted_fstype is None
        and probe.media_loaded
        and not probe.drive_busy
        and not probe.correlated_processes
    )


def _commit_evidence_exact(snapshot: RecoveryInput) -> bool:
    operation = snapshot.operation
    evidence = snapshot.commit_evidence
    if evidence is None or operation.media_binding is None:
        return False
    unmount = next(
        (
            command
            for command in snapshot.commands
            if command.id == evidence.unmount_command_id
        ),
        None,
    )
    return bool(
        unmount is not None
        and unmount.kind == "unmount"
        and unmount.issued_generation == operation.interrupted_generation
        and unmount.state == "quiesced"
        and unmount.exit_outcome == "completed"
        and unmount.quiesced_at is not None
        and unmount.target == operation.target
        and unmount.observed_media_identity_sha256
        == operation.observed_media_identity_sha256
        and evidence.operation_id == operation.operation_id
        and evidence.attempt_generation == operation.interrupted_generation
        and evidence.target == operation.target
        and evidence.observed_media_identity_sha256
        == operation.observed_media_identity_sha256
        and evidence.manifest_sha256 == evidence.provisional_manifest_sha256
        and _timestamp(evidence.recorded_at) > _timestamp(unmount.quiesced_at)
    )


def _receipt_chain_reason(snapshot: RecoveryInput) -> RecoveryReason | None:
    command_receipt = snapshot.receipts.command
    physical = snapshot.receipts.physical
    resolution = snapshot.receipts.resolution
    if command_receipt is None or physical is None or resolution is None:
        return RecoveryReason.RECEIPT_CHAIN_MISSING
    current = snapshot.recovery.current_generation
    operation = snapshot.operation
    ledger_ids = tuple(command.id for command in snapshot.commands)
    expected_evidence = tuple(
        (
            command.id,
            command.process,
            command.exit_outcome,
            command.quiesced_at,
        )
        for command in snapshot.commands
    )
    actual_evidence = tuple(
        (item.command_id, item.process, item.outcome, item.quiesced_at)
        for item in command_receipt.evidence
    )
    latest_lineage_at = max(
        (_timestamp(lineage.recorded_at) for lineage in snapshot.recovery.lineages),
        default=_timestamp(operation.started_at),
    )
    command_time = _timestamp(command_receipt.recorded_at)
    physical_time = _timestamp(physical.recorded_at)
    resolution_time = _timestamp(resolution.recorded_at)
    if (
        command_receipt.operation_id != operation.operation_id
        or command_receipt.reconciled_by_generation != current
        or command_receipt.command_ids != ledger_ids
        or actual_evidence != expected_evidence
        or command_time <= latest_lineage_at
        or any(
            command.quiesced_at is None
            or command_time <= _timestamp(command.quiesced_at)
            for command in snapshot.commands
        )
        or physical.operation_id != operation.operation_id
        or physical.reconciled_by_generation != current
        or physical.command_receipt_id != command_receipt.id
        or physical.target != operation.target
        or physical.observed_media_identity_sha256
        != operation.observed_media_identity_sha256
        or physical.mounted
        or physical.media_loaded
        or physical.drive_busy
        or physical.related_processes
        or physical_time <= command_time
        or resolution.operation_id != operation.operation_id
        or resolution.resolved_generation != current
        or resolution.command_receipt_id != command_receipt.id
        or resolution.physical_receipt_id != physical.id
        or resolution_time <= physical_time
    ):
        return RecoveryReason.RECEIPT_CHAIN_MISMATCH
    if not _physical_clean(snapshot.probe):
        return RecoveryReason.PHYSICAL_NOT_QUIESCENT
    return None


def _validate_sha256(value: str, name: str) -> None:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


def _validate_optional_sha256(value: str | None, name: str) -> None:
    if value is not None:
        _validate_sha256(value, name)


def _timestamp(value: str) -> datetime:
    if not isinstance(value, str):
        raise TypeError("recovery timestamp must be RFC3339 text")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ValueError("recovery timestamp must be RFC3339 text") from None
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError("recovery timestamp must use UTC")
    return parsed


def _blocked(reason: RecoveryReason, *, operator_required: bool) -> RecoveryDecision:
    actions = (
        (
            RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            RecoveryAction.HOLD_ADMISSION,
        )
        if operator_required
        else (RecoveryAction.HOLD_ADMISSION,)
    )
    return RecoveryDecision(
        RecoveryOutcome.RECOVERY_REQUIRED,
        actions,
        reason,
        operator_required,
        False,
    )


def _hold(reason: RecoveryReason) -> RecoveryDecision:
    return RecoveryDecision(
        RecoveryOutcome.RECOVERY_REQUIRED,
        (RecoveryAction.HOLD_ADMISSION,),
        reason,
        False,
        False,
    )


def _wait_for_media() -> RecoveryDecision:
    return RecoveryDecision(
        RecoveryOutcome.RETRY,
        (RecoveryAction.WAIT_FOR_MEDIA, RecoveryAction.HOLD_ADMISSION),
        RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
        False,
        False,
    )
