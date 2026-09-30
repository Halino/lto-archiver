"""Persisted, fenced coordination for ordinary daemon restart recovery.

The coordinator owns policy sequencing and retry bookkeeping only.  Every
operation which can observe or change hardware is injected through
``RecoveryExecutor`` so the existing broker, command, daemon-owner, and
operation fences remain the sole authority for those effects.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, RLock, Thread
from typing import Protocol

from ..catalog import Catalog
from ..errors import CatalogError, ValidationError
from ..tape.command_supervisor import CommandError
from ..tape.linux_ltfs import BackendUnavailable
from .models import (
    CriticalRecoveryObservation,
    DaemonFence,
    OperationRecord,
    RecoveryAttemptSummary,
    RecoveryCommandFence,
    RecoveryEffectReceipt,
    StaleDaemonFence,
    StaleOperationFence,
    critical_command_ledger_sha256,
)
from .recovery import (
    AggregateRecoveryProbe,
    CatalogRecoveryStateSource,
    DurableOperation,
    RecoveryAction,
    RecoveryDecision,
    RecoveryInput,
    RecoveryOutcome,
    RecoveryReason,
    RestoreRecoveryCheckpoint,
    decide_recovery,
    decide_restore_recovery,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RETRY_DELAYS_SECONDS = (1, 2, 4, 8, 16)
_NON_EFFECT_ACTIONS = frozenset({RecoveryAction.HOLD_ADMISSION})
_ACTION_STATES = {
    RecoveryAction.RECONCILE_COMMANDS: "observed",
    RecoveryAction.RECONCILE_COMMIT: "commit_reconciled",
    RecoveryAction.RETRY_IDENTIFICATION: "identification_retried",
    RecoveryAction.RETRY_CURRENT_CASSETTE: "resumed",
    RecoveryAction.RETRY_UNLOAD: "unload_retried",
    RecoveryAction.PREPARE_RESTORE_RETRY: "restore_retry_prepared",
    RecoveryAction.RECONCILE_RESTORE_COMMIT: "restore_commit_reconciled",
    RecoveryAction.FINALIZE_RESTORE_CONTROL: "restore_control_finalized",
}


class TransientRecoveryError(RuntimeError):
    """A closed, retryable broker/device/share failure."""


class PermanentRecoveryError(RuntimeError):
    """An unambiguous failure for which owned resources may be released."""


class CriticalRecoveryError(RuntimeError):
    """Contradictory ownership, identity, integrity, or proof evidence."""


@dataclass(frozen=True)
class RecoveryAssessment:
    """One decision paired with a digest of the evidence used to derive it."""

    decision: RecoveryDecision
    evidence_sha256: str
    observation: CriticalRecoveryObservation | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.decision, RecoveryDecision):
            raise TypeError("recovery assessment decision is invalid")
        if not isinstance(self.evidence_sha256, str) or not _SHA256.fullmatch(
            self.evidence_sha256
        ):
            raise ValueError("recovery assessment evidence digest is invalid")
        if self.observation is not None and not isinstance(
            self.observation, CriticalRecoveryObservation
        ):
            raise TypeError("recovery assessment observation is invalid")


class RecoveryDecisionSource(Protocol):
    def assess(self, operation_id: str) -> RecoveryAssessment: ...


class FencedAggregateProbeSource(Protocol):
    def inspect(
        self,
        operation: DurableOperation,
        fence: RecoveryCommandFence,
        catalog: Catalog,
    ) -> AggregateRecoveryProbe: ...


class ProductionRecoveryDecisionSource:
    """Derive one decision and digest from exact durable and physical evidence."""

    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        daemon_fence: DaemonFence,
        probe_source: FencedAggregateProbeSource,
        *,
        expected_mount_fstype: str = "fuse.ltfs",
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._catalog_factory = catalog_factory
        self._daemon_fence = daemon_fence
        self._probe_source = probe_source
        self._expected_mount_fstype = expected_mount_fstype
        self._clock = clock

    def assess(self, operation_id: str) -> RecoveryAssessment:
        try:
            with self._catalog_factory() as catalog:
                original = catalog.get_operation(operation_id)
                replay_key = (
                    f"recovery-native-{operation_id}-{self._daemon_fence.generation}"
                )
                replacement = catalog.find_operation_by_key(replay_key)
                dispatch = (
                    None
                    if replacement is None
                    else catalog.native_recovery_dispatch(str(replacement["id"]))
                )
                if (
                    original is not None
                    and original["state"] == "cancelled"
                    and original["kind"] == "archive.native"
                    and replacement is not None
                    and dispatch is not None
                    and replacement["kind"] == "archive.native"
                    and replacement["job_id"] == original["job_id"]
                    and replacement["cassette_sequence"]
                    == original["cassette_sequence"]
                    and replacement["principal"] == original["principal"]
                    and replacement["owner_generation"]
                    == self._daemon_fence.generation
                    and dispatch["owner_generation"]
                    == self._daemon_fence.generation
                    and replacement["copy_buffer_bytes"]
                    == original["copy_buffer_bytes"]
                    and catalog.hardware_target_binding(str(replacement["id"]))
                    == catalog.hardware_target_binding(operation_id)
                ):
                    decision = RecoveryDecision(
                        RecoveryOutcome.RETRY,
                        (
                            RecoveryAction.RETRY_CURRENT_CASSETTE,
                            RecoveryAction.HOLD_ADMISSION,
                        ),
                        RecoveryReason.CASSETTE_CHECKPOINT_RETRY_SAFE,
                        operator_required=False,
                        admission_open=False,
                    )
                    encoded = json.dumps(
                        (
                            operation_id,
                            replacement["id"],
                            replacement["state"],
                            dispatch["state"],
                            dispatch["owner_generation"],
                        ),
                        ensure_ascii=True,
                        separators=(",", ":"),
                    ).encode("ascii")
                    return RecoveryAssessment(
                        decision,
                        hashlib.sha256(
                            b"lto-recovery-assessment-v1\0" + encoded
                        ).hexdigest(),
                    )
                target = catalog.hardware_target_binding(operation_id)
                if target is None:
                    raise ValueError("recovery target is unavailable")
                source = CatalogRecoveryStateSource(
                    catalog,
                    expected_mount_source_identity_sha256=(
                        target.tape_device_identity_sha256
                    ),
                    expected_mount_fstype=self._expected_mount_fstype,
                )
                operation = source.operation(operation_id)
                probe = self._probe_source.inspect(
                    operation,
                    RecoveryCommandFence(
                        operation_id, self._daemon_fence.generation
                    ),
                    catalog,
                )
                # A successful first identify can seal the physical medium.
                # Evaluate that durable seal, not the pre-probe snapshot.
                operation = source.operation(operation_id)
                commands = source.command_ledger(operation_id)
                snapshot = RecoveryInput(
                    operation=operation,
                    recovery=source.recovery_context(operation_id),
                    commands=commands,
                    probe=probe,
                    commit_evidence=source.commit_evidence(operation_id),
                    receipts=source.receipt_chain(operation_id),
                )
                if operation.kind == "restore.cassette":
                    run = catalog.restore_run(str(original["job_id"]))
                    cassette_sequence = int(original["cassette_sequence"])
                    if (
                        run["id"] != original["job_id"]
                        or run["current_cassette_sequence"] != cassette_sequence
                    ):
                        raise ValueError("restore recovery checkpoint is not current")
                    incomplete = tuple(
                        item
                        for item in run["items"]
                        if item["cassette_sequence"] == cassette_sequence
                        and item["state"] not in {"restored", "skipped_verified"}
                    )
                    conflict_states = tuple(
                        item["conflict"]["state"]
                        for item in incomplete
                        if item["conflict"] is not None
                    )
                    if len(conflict_states) > 1:
                        raise ValueError("restore recovery has ambiguous conflicts")
                    checkpoint = RestoreRecoveryCheckpoint(
                        run_id=str(run["id"]),
                        cassette_sequence=cassette_sequence,
                        plan_fingerprint_sha256=str(
                            run["plan_fingerprint_sha256"]
                        ),
                        first_incomplete_item_sequence=(
                            None
                            if not incomplete
                            else int(incomplete[0]["sequence"])
                        ),
                        conflict_state=(
                            None if not conflict_states else str(conflict_states[0])
                        ),
                        commands_quiescent=all(
                            command.state == "quiesced" for command in commands
                        ),
                        release_boundary=catalog.restore_release_boundary(
                            operation_id,
                            str(run["id"]),
                            cassette_sequence,
                            str(run["plan_fingerprint_sha256"]),
                        ),
                        pre_mount_recoverable=(
                            catalog.restore_pre_mount_recovery_candidate(
                                operation_id,
                                str(run["id"]),
                                cassette_sequence,
                                str(run["plan_fingerprint_sha256"]),
                            )
                        ),
                        pending_control=(
                            "cancelled"
                            if catalog.restore_run_cancel_requested(str(run["id"]))
                            else "paused"
                            if catalog.restore_run_pause_requested(str(run["id"]))
                            else None
                        ),
                    )
                    decision = decide_restore_recovery(checkpoint, probe)
                else:
                    decision = decide_recovery(snapshot)
                assessment_evidence = asdict(snapshot)
                if operation.kind == "restore.cassette":
                    assessment_evidence = {
                        "recovery": assessment_evidence,
                        "restore_checkpoint": asdict(checkpoint),
                    }
                encoded = json.dumps(
                    assessment_evidence,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii")
                evidence_sha256 = hashlib.sha256(
                    b"lto-recovery-assessment-v1\0" + encoded
                ).hexdigest()
                if (
                    operation.kind != "restore.cassette"
                    and operation.observed_media_identity_sha256 is None
                    and not (
                        operation.kind == "archive.native"
                        and operation.phase is None
                        and probe.media_loaded is False
                        and probe.observed_media_identity_sha256 is None
                    )
                ):
                    raise ValueError("critical recovery media binding is unavailable")
                observation = CriticalRecoveryObservation(
                    operation_id=operation_id,
                    daemon_generation=self._daemon_fence.generation,
                    target=probe.target,
                    bound_media_identity_sha256=(
                        operation.observed_media_identity_sha256
                    ),
                    observed_media_identity_sha256=(
                        probe.observed_media_identity_sha256
                    ),
                    command_ledger_sha256=critical_command_ledger_sha256(commands),
                    commands_quiescent=bool(commands)
                    and all(command.state == "quiesced" for command in commands),
                    mounted=probe.mounted,
                    media_loaded=probe.media_loaded,
                    drive_busy=probe.drive_busy,
                    related_process_count=len(probe.correlated_processes),
                    evidence_category=decision.reason.value,
                    evidence_sha256=evidence_sha256,
                    observed_at=self._clock().isoformat(timespec="microseconds"),
                )
        except BaseException as exc:
            decision = RecoveryDecision(
                RecoveryOutcome.RECOVERY_REQUIRED,
                (
                    RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                    RecoveryAction.HOLD_ADMISSION,
                ),
                RecoveryReason.DURABLE_EVIDENCE_MISSING,
                operator_required=True,
                admission_open=False,
            )
            encoded = json.dumps(
                (operation_id, type(exc).__name__),
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            observation = None
        return RecoveryAssessment(
            decision,
            hashlib.sha256(b"lto-recovery-assessment-v1\0" + encoded).hexdigest(),
            observation,
        )


class ProductionRecoveryExecutor:
    """Closed production effects; each callback retains its native fence."""

    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        *,
        observe_command: Callable[[OperationRecord, RecoveryCommandFence], None],
        reconcile_commit: Callable[[OperationRecord, RecoveryCommandFence], None],
        retry_identification: Callable[
            [OperationRecord, RecoveryCommandFence], None
        ],
        retry_unload: Callable[[OperationRecord, RecoveryCommandFence], None],
        safe_release: Callable[[OperationRecord, RecoveryCommandFence], None],
        prepare_restore_retry: Callable[
            [OperationRecord, RecoveryCommandFence], object
        ]
        | None = None,
        reconcile_restore_commit: Callable[
            [OperationRecord, RecoveryCommandFence], object
        ] | None = None,
        finalize_restore_control: Callable[
            [OperationRecord, RecoveryCommandFence], object
        ] | None = None,
        retry_current_cassette: Callable[
            [OperationRecord, RecoveryCommandFence], object
        ] | None = None,
        prove_incomplete: Callable[
            [RecoveryAction, OperationRecord, RecoveryCommandFence],
            RecoveryEffectReceipt | None,
        ] | None = None,
    ) -> None:
        self._catalog_factory = catalog_factory
        self._observe_command = observe_command
        self._reconcile_commit = reconcile_commit
        self._retry_identification = retry_identification
        self._retry_current_cassette = retry_current_cassette
        self._prove_incomplete = prove_incomplete
        self._retry_unload = retry_unload
        self._safe_release = safe_release
        self._prepare_restore_retry = prepare_restore_retry
        self._reconcile_restore_commit = reconcile_restore_commit
        self._finalize_restore_control = finalize_restore_control

    def _assert(self, blocker: OperationRecord, fence: RecoveryCommandFence) -> None:
        if fence.operation_id != blocker.id:
            raise CriticalRecoveryError("recovery effect fence is mismatched")
        with self._catalog_factory() as catalog:
            catalog.assert_command_fence(fence)

    def observe_command(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        return self._run_effect(self._observe_command, blocker, fence)

    def reconcile_commit(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        return self._run_effect(self._reconcile_commit, blocker, fence)

    def retry_identification(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        return self._run_effect(self._retry_identification, blocker, fence)

    def retry_current_cassette(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        if blocker.kind != "archive.native":
            raise CriticalRecoveryError("non-native cassette retry is unavailable")
        if self._retry_current_cassette is None:
            raise CriticalRecoveryError("native frozen retry executor is unavailable")
        return self._run_effect(self._retry_current_cassette, blocker, fence)

    def retry_unload(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        return self._run_effect(self._retry_unload, blocker, fence)

    def safe_release(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        return self._run_effect(self._safe_release, blocker, fence)

    def prepare_restore_retry(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        if blocker.kind != "restore.cassette":
            raise CriticalRecoveryError("non-restore retry preparation is unavailable")
        if self._prepare_restore_retry is None:
            raise CriticalRecoveryError("restore retry preparation is unavailable")
        return self._run_effect(self._prepare_restore_retry, blocker, fence)

    def reconcile_restore_commit(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        if blocker.kind != "restore.cassette" or self._reconcile_restore_commit is None:
            raise CriticalRecoveryError("restore commit reconciliation is unavailable")
        return self._run_effect(self._reconcile_restore_commit, blocker, fence)

    def finalize_restore_control(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt:
        self._assert(blocker, fence)
        if blocker.kind != "restore.cassette" or self._finalize_restore_control is None:
            raise CriticalRecoveryError("restore control finalization is unavailable")
        return self._run_effect(self._finalize_restore_control, blocker, fence)

    def prove_incomplete(
        self,
        action: RecoveryAction,
        blocker: OperationRecord,
        fence: RecoveryCommandFence,
    ) -> RecoveryEffectReceipt | None:
        if fence.operation_id != blocker.id:
            raise CriticalRecoveryError("recovery proof fence is mismatched")
        with self._catalog_factory() as catalog:
            daemon = catalog.current_daemon_fence()
            if daemon is None or daemon.generation != fence.owner_generation:
                raise CriticalRecoveryError("recovery proof daemon fence is stale")
        if self._prove_incomplete is None:
            return None
        try:
            return self._prove_incomplete(action, blocker, fence)
        except (BackendUnavailable, CatalogError, ValidationError) as exc:
            raise CriticalRecoveryError("incomplete recovery proof failed") from exc

    @staticmethod
    def _run_effect(callback, blocker, fence) -> RecoveryEffectReceipt:
        try:
            receipt = callback(blocker, fence)
        except (TransientRecoveryError, PermanentRecoveryError, CriticalRecoveryError):
            raise
        except (CommandError, OSError, TimeoutError) as exc:
            raise TransientRecoveryError("recovery effect is temporarily unavailable") from exc
        except (
            BackendUnavailable,
            CatalogError,
            ValidationError,
            StaleDaemonFence,
            StaleOperationFence,
        ) as exc:
            raise CriticalRecoveryError("recovery effect proof failed") from exc
        except BaseException as exc:
            raise CriticalRecoveryError("recovery effect failed closed") from exc
        if not isinstance(receipt, RecoveryEffectReceipt):
            raise CriticalRecoveryError("recovery effect did not return durable proof")
        return receipt


class RecoveryExecutor(Protocol):
    """All recovery effects, each still subject to the supplied command fence."""

    def observe_command(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def reconcile_commit(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def retry_identification(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def retry_current_cassette(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def retry_unload(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def safe_release(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def prepare_restore_retry(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def reconcile_restore_commit(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def finalize_restore_control(
        self, blocker: OperationRecord, fence: RecoveryCommandFence
    ) -> RecoveryEffectReceipt: ...

    def prove_incomplete(
        self,
        action: RecoveryAction,
        blocker: OperationRecord,
        fence: RecoveryCommandFence,
    ) -> RecoveryEffectReceipt | None: ...


@dataclass(frozen=True)
class RecoveryCoordinatorItem:
    operation_id: str
    state: str
    decision: str
    reason: str
    attempt_number: int | None
    next_eligible_at: str | None = None


@dataclass(frozen=True)
class RecoveryCoordinatorResult:
    items: tuple[RecoveryCoordinatorItem, ...]

    @property
    def waiting_operation_ids(self) -> tuple[str, ...]:
        return tuple(
            item.operation_id for item in self.items if item.state == "waiting_media"
        )

    @property
    def quarantined_operation_ids(self) -> tuple[str, ...]:
        return tuple(
            item.operation_id
            for item in self.items
            if item.state == "critical_quarantine"
        )


class AutomaticRecoveryCoordinator:
    """Fold immutable recovery events and dispatch each authorized effect once."""

    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        daemon_fence: DaemonFence,
        decision_source: RecoveryDecisionSource,
        executor: RecoveryExecutor,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        poll_interval_seconds: float = 1.0,
        on_transition: Callable[[RecoveryCoordinatorResult], None] | None = None,
    ) -> None:
        if not callable(catalog_factory):
            raise TypeError("recovery catalog factory is required")
        if not isinstance(daemon_fence, DaemonFence):
            raise TypeError("recovery daemon fence is required")
        if (
            isinstance(poll_interval_seconds, bool)
            or not isinstance(poll_interval_seconds, (int, float))
            or not 0 < float(poll_interval_seconds) <= 60
        ):
            raise ValueError("recovery media poll interval is invalid")
        self._catalog_factory = catalog_factory
        self._daemon_fence = daemon_fence
        self._decision_source = decision_source
        self._executor = executor
        self._clock = clock
        self._poll_interval_seconds = float(poll_interval_seconds)
        self._on_transition = on_transition or (lambda _result: None)
        self._tracked: dict[str, OperationRecord] = {}
        self._lock = RLock()
        self._stop = Event()
        self._thread: Thread | None = None

    def reconcile_startup(
        self, blockers: tuple[OperationRecord, ...]
    ) -> RecoveryCoordinatorResult:
        """Reconcile blockers synchronously before mutation admission may open."""

        normalized = tuple(blockers)
        if any(not isinstance(blocker, OperationRecord) for blocker in normalized):
            raise TypeError("recovery blockers must be durable operation records")
        with self._lock:
            for blocker in normalized:
                self._tracked[blocker.id] = blocker
        result = RecoveryCoordinatorResult(
            tuple(self._reconcile_one(blocker, "daemon_restart") for blocker in normalized)
        )
        self._on_transition(result)
        return result

    def set_transition_callback(
        self, callback: Callable[[RecoveryCoordinatorResult], None]
    ) -> None:
        """Install the service-owned admission transition before startup."""

        if not callable(callback):
            raise TypeError("recovery transition callback is required")
        with self._lock:
            if self._thread is not None:
                raise RuntimeError("recovery transition callback is already active")
            self._on_transition = callback

    def poll_waiting_media(self) -> RecoveryCoordinatorResult:
        """Reinspect tracked waits/retries without dispatching for wrong or absent media."""

        with self._lock:
            blockers = tuple(self._tracked.values())
        result = RecoveryCoordinatorResult(
            tuple(self._reconcile_one(blocker, "media_poll") for blocker in blockers)
        )
        self._on_transition(result)
        return result

    def reassess_critical(self, operation_id: str) -> RecoveryAssessment:
        """Return fresh evidence for a sticky quarantine without dispatching effects."""

        with self._lock:
            blocker = self._tracked.get(operation_id)
        if blocker is None or blocker.state != "recovery_required":
            raise CriticalRecoveryError("critical recovery blocker is unavailable")
        attempts = self._attempts(operation_id)
        if not any(item.state == "critical_quarantine" for item in attempts):
            raise CriticalRecoveryError("operation is not critically quarantined")
        assessment = self._decision_source.assess(operation_id)
        if not isinstance(assessment, RecoveryAssessment):
            raise TypeError("recovery decision source returned invalid evidence")
        return assessment

    def start(self) -> None:
        """Start one bounded watcher; repeated lifecycle calls are rejected."""

        with self._lock:
            if self._thread is not None:
                raise RuntimeError("automatic recovery coordinator already started")
            if self._stop.is_set():
                raise RuntimeError("automatic recovery coordinator cannot restart")
            self._thread = Thread(
                target=self._watch,
                name="ltobackup-recovery-coordinator",
                daemon=True,
            )
            self._thread.start()

    def shutdown(self) -> None:
        """Stop and join the watcher without touching a catalog or hardware lock."""

        with self._lock:
            thread = self._thread
            if thread is None:
                self._stop.set()
                return
            self._thread = None
            self._stop.set()
        thread.join(timeout=max(1.0, self._poll_interval_seconds * 2))
        if thread.is_alive():
            raise RuntimeError("automatic recovery coordinator did not stop")

    def _watch(self) -> None:
        while not self._stop.wait(self._poll_interval_seconds):
            try:
                self.poll_waiting_media()
            except BaseException:
                # A watcher failure cannot weaken admission.  The durable blocker
                # remains and the next bounded poll retries read-only assessment.
                continue

    def _reconcile_one(
        self, blocker: OperationRecord, trigger: str
    ) -> RecoveryCoordinatorItem:
        attempts = self._attempts(blocker.id)
        critical = next(
            (
                attempt
                for attempt in reversed(attempts)
                if attempt.state == "critical_quarantine"
            ),
            None,
        )
        if trigger == "media_poll" and critical is not None:
            return self._item_from_attempt(
                critical, RecoveryReason.OPERATION_STILL_BLOCKING.value
            )

        assessment = self._decision_source.assess(blocker.id)
        if not isinstance(assessment, RecoveryAssessment):
            raise TypeError("recovery decision source returned invalid evidence")
        action = self._primary_action(assessment.decision)
        decision_name = action.value
        if critical is not None:
            if critical.daemon_generation != self._daemon_fence.generation:
                return self._record_without_effect(
                    blocker,
                    trigger,
                    assessment,
                    RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
                    assessment.decision.reason.value,
                    "critical_quarantine",
                    attempts,
                )
            return self._item_from_attempt(critical, assessment.decision.reason.value)

        conflicting = next(
            (
                attempt
                for attempt in attempts
                if assessment.evidence_sha256 == attempt.started_evidence_sha256
                and decision_name != attempt.started_decision
            ),
            None,
        )
        if conflicting is not None:
            return self._record_without_effect(
                blocker,
                trigger,
                assessment,
                RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
                assessment.decision.reason.value,
                "critical_quarantine",
                attempts,
            )

        incomplete = next(
            (attempt for attempt in reversed(attempts) if attempt.state == "started"),
            None,
        )
        if incomplete is not None:
            if incomplete.started_generation == self._daemon_fence.generation:
                return self._item_from_attempt(
                    incomplete, assessment.decision.reason.value
                )
            return self._observe_incomplete(blocker, incomplete, assessment)

        active_schedule = next(
            (
                attempt
                for attempt in reversed(attempts)
                if attempt.state != "waiting_media"
            ),
            None,
        )
        if (
            active_schedule is not None
            and active_schedule.state == "retry_scheduled"
        ):
            if action is RecoveryAction.ENTER_CRITICAL_QUARANTINE:
                return self._record_without_effect(
                    blocker,
                    trigger,
                    assessment,
                    action.value,
                    assessment.decision.reason.value,
                    "critical_quarantine",
                    attempts,
                )
            if action is RecoveryAction.WAIT_FOR_MEDIA:
                exact_wait = next(
                    (
                        attempt
                        for attempt in reversed(attempts)
                        if attempt.started_evidence_sha256
                        == assessment.evidence_sha256
                        and attempt.started_decision == action.value
                    ),
                    None,
                )
                if exact_wait is not None:
                    return self._item_from_attempt(
                        exact_wait, assessment.decision.reason.value
                    )
                return self._record_without_effect(
                    blocker,
                    trigger,
                    assessment,
                    action.value,
                    assessment.decision.reason.value,
                    "waiting_media",
                    attempts,
                )
            if decision_name != active_schedule.started_decision:
                return self._record_without_effect(
                    blocker,
                    trigger,
                    assessment,
                    RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
                    assessment.decision.reason.value,
                    "critical_quarantine",
                    attempts,
                )
            if not self._eligible(active_schedule):
                return self._item_from_attempt(
                    active_schedule, assessment.decision.reason.value
                )

        exact = next(
            (
                attempt
                for attempt in reversed(attempts)
                if attempt.started_evidence_sha256 == assessment.evidence_sha256
                and attempt.started_decision == decision_name
            ),
            None,
        )
        if exact is not None:
            if exact.state != "retry_scheduled":
                return self._item_from_attempt(
                    exact, assessment.decision.reason.value
                )
            if not self._eligible(exact):
                return self._item_from_attempt(
                    exact, assessment.decision.reason.value
                )

        if action is RecoveryAction.ENTER_CRITICAL_QUARANTINE:
            return self._record_without_effect(
                blocker,
                trigger,
                assessment,
                decision_name,
                assessment.decision.reason.value,
                "critical_quarantine",
                attempts,
            )
        if action is RecoveryAction.WAIT_FOR_MEDIA:
            return self._record_without_effect(
                blocker,
                trigger,
                assessment,
                decision_name,
                assessment.decision.reason.value,
                "waiting_media",
                attempts,
            )

        scheduled_count = sum(
            attempt.state == "retry_scheduled" for attempt in attempts
        )
        if scheduled_count >= len(_RETRY_DELAYS_SECONDS):
            return self._record_without_effect(
                blocker,
                trigger,
                assessment,
                decision_name,
                assessment.decision.reason.value,
                "failed_safe",
                attempts,
            )

        attempt, owned = self._claim(
            blocker,
            self._next_attempt_number(attempts),
            trigger,
            assessment.evidence_sha256,
            decision_name,
        )
        if not owned:
            return self._item_from_attempt(
                attempt, assessment.decision.reason.value
            )
        try:
            self._dispatch(action, blocker)
        except TransientRecoveryError:
            return self._schedule_retry(
                blocker,
                attempt,
                assessment,
                _RETRY_DELAYS_SECONDS[scheduled_count],
            )
        except PermanentRecoveryError:
            try:
                self._executor.safe_release(blocker, self._command_fence(blocker))
            except BaseException:
                return self._finish_item(
                    blocker,
                    attempt,
                    assessment,
                    "critical_quarantine",
                    decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
                )
            return self._finish_item(blocker, attempt, assessment, "failed_safe")
        except CriticalRecoveryError:
            return self._finish_item(
                blocker,
                attempt,
                assessment,
                "critical_quarantine",
                decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            )
        except BaseException:
            return self._finish_item(
                blocker,
                attempt,
                assessment,
                "critical_quarantine",
                decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            )
        return self._finish_item(
            blocker,
            attempt,
            assessment,
            "succeeded",
            visible_state=_ACTION_STATES[action],
        )

    def _observe_incomplete(
        self,
        blocker: OperationRecord,
        attempt: RecoveryAttemptSummary,
        assessment: RecoveryAssessment,
    ) -> RecoveryCoordinatorItem:
        try:
            action = RecoveryAction(attempt.started_decision)
        except ValueError:
            return self._finish_existing(
                blocker,
                attempt,
                assessment,
                "critical_quarantine",
                decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            )
        if action not in _ACTION_STATES:
            return self._finish_existing(
                blocker,
                attempt,
                assessment,
                "critical_quarantine",
                decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            )
        primary = (
            assessment.decision.actions[0]
            if assessment.decision.actions
            else RecoveryAction.ENTER_CRITICAL_QUARANTINE
        )
        try:
            proof = self._executor.prove_incomplete(
                action, blocker, self._command_fence(blocker)
            )
        except BaseException:
            proof = None
            primary = RecoveryAction.ENTER_CRITICAL_QUARANTINE
        if proof is not None:
            try:
                self._validate_effect_receipt(action, blocker, proof)
            except CriticalRecoveryError:
                primary = RecoveryAction.ENTER_CRITICAL_QUARANTINE
            else:
                return self._finish_existing(
                    blocker,
                    attempt,
                    assessment,
                    "succeeded",
                    visible_state=_ACTION_STATES[action],
                )
        if primary != action:
            return self._finish_existing(
                blocker,
                attempt,
                assessment,
                "critical_quarantine",
                decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            )
        try:
            self._dispatch(action, blocker)
        except TransientRecoveryError:
            scheduled_count = sum(
                item.state == "retry_scheduled" for item in self._attempts(blocker.id)
            )
            if scheduled_count >= len(_RETRY_DELAYS_SECONDS):
                return self._finish_existing(
                    blocker, attempt, assessment, "failed_safe"
                )
            return self._schedule_retry(
                blocker,
                attempt,
                assessment,
                _RETRY_DELAYS_SECONDS[scheduled_count],
            )
        except BaseException:
            return self._finish_existing(
                blocker,
                attempt,
                assessment,
                "critical_quarantine",
                decision=RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            )
        return self._finish_existing(
            blocker,
            attempt,
            assessment,
            "succeeded",
            visible_state=_ACTION_STATES[action],
        )

    def _dispatch(self, action: RecoveryAction, blocker: OperationRecord) -> None:
        fence = self._command_fence(blocker)
        method_name = {
            RecoveryAction.RECONCILE_COMMANDS: "observe_command",
            RecoveryAction.RECONCILE_COMMIT: "reconcile_commit",
            RecoveryAction.RETRY_IDENTIFICATION: "retry_identification",
            RecoveryAction.RETRY_CURRENT_CASSETTE: "retry_current_cassette",
            RecoveryAction.RETRY_UNLOAD: "retry_unload",
            RecoveryAction.PREPARE_RESTORE_RETRY: "prepare_restore_retry",
            RecoveryAction.RECONCILE_RESTORE_COMMIT: "reconcile_restore_commit",
            RecoveryAction.FINALIZE_RESTORE_CONTROL: "finalize_restore_control",
        }[action]
        receipt = getattr(self._executor, method_name)(blocker, fence)
        self._validate_effect_receipt(action, blocker, receipt)

    def _validate_effect_receipt(
        self,
        action: RecoveryAction,
        blocker: OperationRecord,
        receipt: object,
    ) -> None:
        fence = self._command_fence(blocker)
        if (
            not isinstance(receipt, RecoveryEffectReceipt)
            or receipt.action != action.value
            or receipt.operation_id != blocker.id
            or receipt.owner_generation != fence.owner_generation
            or not receipt.proof
        ):
            raise CriticalRecoveryError("recovery effect receipt is unavailable")

    def _record_without_effect(
        self,
        blocker: OperationRecord,
        trigger: str,
        assessment: RecoveryAssessment,
        decision: str,
        reason: str,
        state: str,
        attempts: tuple[RecoveryAttemptSummary, ...],
    ) -> RecoveryCoordinatorItem:
        attempt = self._begin(
            blocker,
            self._next_attempt_number(attempts),
            trigger,
            assessment.evidence_sha256,
            decision,
        )
        return self._finish_item(
            blocker,
            attempt,
            assessment,
            state,
            decision=decision,
            visible_state=state,
            reason=reason,
        )

    def _schedule_retry(
        self,
        blocker: OperationRecord,
        attempt: RecoveryAttemptSummary,
        assessment: RecoveryAssessment,
        delay_seconds: int,
    ) -> RecoveryCoordinatorItem:
        outcome_at = self._after(attempt.started_at)
        next_at = outcome_at + timedelta(seconds=delay_seconds)
        with self._catalog_factory() as catalog:
            finished = catalog.finish_recovery_attempt(
                blocker.id,
                attempt.attempt_number,
                self._daemon_fence,
                state="retry_scheduled",
                evidence_sha256=assessment.evidence_sha256,
                decision=attempt.started_decision,
                recorded_at=outcome_at.isoformat(),
                next_eligible_at=next_at.isoformat(),
            )
        return self._item_from_attempt(finished, assessment.decision.reason.value)

    def _finish_item(
        self,
        blocker: OperationRecord,
        attempt: RecoveryAttemptSummary,
        assessment: RecoveryAssessment,
        state: str,
        *,
        decision: str | None = None,
        visible_state: str | None = None,
        reason: str | None = None,
    ) -> RecoveryCoordinatorItem:
        finished = self._finish(
            blocker,
            attempt,
            assessment.evidence_sha256,
            decision or attempt.started_decision,
            state,
        )
        item = self._item_from_attempt(
            finished, reason or assessment.decision.reason.value
        )
        if visible_state is None or visible_state == item.state:
            return item
        return RecoveryCoordinatorItem(
            item.operation_id,
            visible_state,
            item.decision,
            item.reason,
            item.attempt_number,
            item.next_eligible_at,
        )

    def _finish_existing(
        self,
        blocker: OperationRecord,
        attempt: RecoveryAttemptSummary,
        assessment: RecoveryAssessment,
        state: str,
        *,
        decision: str | None = None,
        visible_state: str | None = None,
    ) -> RecoveryCoordinatorItem:
        return self._finish_item(
            blocker,
            attempt,
            assessment,
            state,
            decision=decision,
            visible_state=visible_state,
        )

    def _finish(
        self,
        blocker: OperationRecord,
        attempt: RecoveryAttemptSummary,
        evidence_sha256: str,
        decision: str,
        state: str,
    ) -> RecoveryAttemptSummary:
        with self._catalog_factory() as catalog:
            return catalog.finish_recovery_attempt(
                blocker.id,
                attempt.attempt_number,
                self._daemon_fence,
                state=state,
                evidence_sha256=evidence_sha256,
                decision=decision,
                recorded_at=self._after(attempt.started_at).isoformat(),
            )

    def _begin(
        self,
        blocker: OperationRecord,
        attempt_number: int,
        trigger: str,
        evidence_sha256: str,
        decision: str,
    ) -> RecoveryAttemptSummary:
        with self._catalog_factory() as catalog:
            return catalog.begin_recovery_attempt(
                blocker.id,
                attempt_number,
                self._daemon_fence,
                trigger=trigger,
                evidence_sha256=evidence_sha256,
                decision=decision,
                recorded_at=self._now().isoformat(),
            )

    def _claim(
        self,
        blocker: OperationRecord,
        attempt_number: int,
        trigger: str,
        evidence_sha256: str,
        decision: str,
    ) -> tuple[RecoveryAttemptSummary, bool]:
        with self._catalog_factory() as catalog:
            claim = catalog.claim_recovery_attempt(
                blocker.id,
                attempt_number,
                self._daemon_fence,
                trigger=trigger,
                evidence_sha256=evidence_sha256,
                decision=decision,
                recorded_at=self._now().isoformat(),
            )
        return claim.attempt, claim.owned

    def _attempts(self, operation_id: str) -> tuple[RecoveryAttemptSummary, ...]:
        with self._catalog_factory() as catalog:
            return catalog.list_recovery_attempts(operation_id)

    def _eligible(self, attempt: RecoveryAttemptSummary) -> bool:
        if attempt.next_eligible_at is None:
            return False
        return self._now() >= datetime.fromisoformat(attempt.next_eligible_at)

    def _now(self) -> datetime:
        value = self._clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise ValueError("recovery clock must return a UTC datetime")
        return value.astimezone(UTC)

    def _after(self, value: str) -> datetime:
        floor = datetime.fromisoformat(value) + timedelta(microseconds=1)
        return max(self._now(), floor)

    def _command_fence(self, blocker: OperationRecord) -> RecoveryCommandFence:
        return RecoveryCommandFence(blocker.id, self._daemon_fence.generation)

    @staticmethod
    def _next_attempt_number(
        attempts: tuple[RecoveryAttemptSummary, ...]
    ) -> int:
        return 1 + max((attempt.attempt_number for attempt in attempts), default=0)

    @staticmethod
    def _primary_action(decision: RecoveryDecision) -> RecoveryAction:
        actions = tuple(
            action for action in decision.actions if action not in _NON_EFFECT_ACTIONS
        )
        if len(actions) == 1 and actions[0] in {
            *_ACTION_STATES,
            RecoveryAction.WAIT_FOR_MEDIA,
            RecoveryAction.ENTER_CRITICAL_QUARANTINE,
        }:
            return actions[0]
        return RecoveryAction.ENTER_CRITICAL_QUARANTINE

    @staticmethod
    def _item_from_attempt(
        attempt: RecoveryAttemptSummary, reason: str
    ) -> RecoveryCoordinatorItem:
        state = {
            "succeeded": {
                action.value: visible for action, visible in _ACTION_STATES.items()
            }.get(attempt.decision, "resumed"),
            "waiting_media": "waiting_media",
            "retry_scheduled": "retry_scheduled",
            "critical_quarantine": "critical_quarantine",
            "failed_safe": "failed_safe",
            "started": "observing",
        }[attempt.state]
        return RecoveryCoordinatorItem(
            attempt.operation_id,
            state,
            attempt.decision,
            reason,
            attempt.attempt_number,
            attempt.next_eligible_at,
        )


__all__ = [
    "AutomaticRecoveryCoordinator",
    "CriticalRecoveryError",
    "PermanentRecoveryError",
    "ProductionRecoveryDecisionSource",
    "ProductionRecoveryExecutor",
    "RecoveryAssessment",
    "RecoveryCoordinatorItem",
    "RecoveryCoordinatorResult",
    "RecoveryDecisionSource",
    "RecoveryExecutor",
    "TransientRecoveryError",
]
