from __future__ import annotations

import tempfile
import threading
import unittest
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.models import (
    CommandExitEvidence,
    DaemonFence,
    HardwareTargetBinding,
    MutationAdmissionClosed,
    OperationRecord,
    RecoveryCommandFence,
    RecoveryEffectReceipt,
    StaleDaemonFence,
    critical_command_ledger_sha256,
)
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.recovery import (
    AggregateRecoveryProbe,
    RecoveryAction,
    RecoveryDecision,
    RecoveryOutcome,
    RecoveryReason,
)
from ltobackup.daemon.recovery_coordinator import (
    AutomaticRecoveryCoordinator,
    ProductionRecoveryDecisionSource,
    RecoveryAssessment,
    RecoveryCoordinatorItem,
    RecoveryCoordinatorResult,
    TransientRecoveryError,
)
from ltobackup.daemon.service import DaemonService, Principal
from ltobackup.daemon.api_models import OperationRequest
from ltobackup.linux_settings import LinuxPaths, LinuxSettings


class _Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        current = self.value
        self.value += timedelta(microseconds=1)
        return current

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class _ConstantClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 28, 10, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


class _DecisionSource:
    def __init__(self, assessment: RecoveryAssessment) -> None:
        self.assessment = assessment
        self.calls: list[str] = []

    def assess(self, operation_id: str) -> RecoveryAssessment:
        self.calls.append(operation_id)
        return self.assessment


class _Executor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []
        self.transient_failures = 0

    def _effect(self, name: str, blocker: OperationRecord, _fence) -> None:
        self.calls.append((name, blocker.id))
        if self.transient_failures:
            self.transient_failures -= 1
            raise TransientRecoveryError("temporary broker failure")
        action = {
            "observe_command": "reconcile_commands",
            "reconcile_commit": "reconcile_commit",
            "retry_identification": "retry_identification",
            "retry_current_cassette": "retry_current_cassette",
            "retry_unload": "retry_unload",
            "safe_release": "safe_release",
        }[name]
        return RecoveryEffectReceipt(
            action, blocker.id, _fence.owner_generation, f"proof:{name}"
        )

    def observe_command(self, blocker: OperationRecord, fence) -> None:
        return self._effect("observe_command", blocker, fence)

    def reconcile_commit(self, blocker: OperationRecord, fence) -> None:
        return self._effect("reconcile_commit", blocker, fence)

    def retry_identification(self, blocker: OperationRecord, fence) -> None:
        return self._effect("retry_identification", blocker, fence)

    def retry_current_cassette(self, blocker: OperationRecord, fence) -> None:
        return self._effect("retry_current_cassette", blocker, fence)

    def retry_unload(self, blocker: OperationRecord, fence) -> None:
        return self._effect("retry_unload", blocker, fence)

    def safe_release(self, blocker: OperationRecord, fence) -> None:
        return self._effect("safe_release", blocker, fence)

    def prove_incomplete(self, action, blocker, fence):
        return None


class _BlockingCoordinator:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls: list[object] = []
        self.on_transition = None

    def set_transition_callback(self, callback) -> None:
        self.calls.append("set_transition_callback")
        self.on_transition = callback

    def reconcile_startup(self, blockers):
        self.calls.append(("reconcile_startup", tuple(blockers)))
        self.entered.set()
        if not self.release.wait(2):
            raise TimeoutError("test recovery coordinator was not released")
        return type("Result", (), {"items": ()})()

    def start(self) -> None:
        self.calls.append("start")

    def shutdown(self) -> None:
        self.calls.append("shutdown")


def _decision(
    action: RecoveryAction,
    reason: RecoveryReason = RecoveryReason.CASSETTE_CHECKPOINT_RETRY_SAFE,
) -> RecoveryDecision:
    if action is RecoveryAction.ENTER_CRITICAL_QUARANTINE:
        return RecoveryDecision(
            RecoveryOutcome.RECOVERY_REQUIRED,
            (action, RecoveryAction.HOLD_ADMISSION),
            reason,
            operator_required=True,
            admission_open=False,
        )
    return RecoveryDecision(
        RecoveryOutcome.RETRY,
        (action, RecoveryAction.HOLD_ADMISSION),
        reason,
        operator_required=False,
        admission_open=False,
    )


class AutomaticRecoveryCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "catalog.db"
        with Catalog(self.database) as catalog:
            catalog.initialize()
            catalog.add_library("LIB-1", "Library", self.temporary.name)
            catalog.create_automatic_job(
                "JOB-1",
                "LIB-1",
                "synthetic-drive",
                "/synthetic/mount",
                [(f"RC{i:04d}", f"SERIAL-{i}", 1, 1) for i in range(1, 5)],
                force_format=True,
            )
            original = catalog.claim_daemon_owner("daemon-original")
            admitted = catalog.admit_operation(
                OperationRecord(
                    id="operation-4",
                    kind="archive.native",
                    state="running",
                    phase="writing",
                    idempotency_key="recovery-operation",
                    principal="synthetic-admin",
                    job_id="JOB-1",
                    cassette_sequence=4,
                    started_at="2026-08-28T09:00:00+00:00",
                    finished_at=None,
                ),
                original,
                admission_open=True,
                hardware_target=HardwareTargetBinding.from_verified_inputs(
                    Path(self.temporary.name) / "mount",
                    "tape-by-id",
                    "scsi-by-id",
                    ("archive.native", "JOB-1", "4", "RC0004", "", ""),
                ),
            )
            self.assertFalse(admitted.replayed)
            self.fence = catalog.claim_daemon_owner("daemon-recovery")
            self.blocker = catalog.recover_interrupted_operations(self.fence)[0]
        self.clock = _Clock()
        self.executor = _Executor()
        self.source = _DecisionSource(
            RecoveryAssessment(
                _decision(RecoveryAction.RETRY_CURRENT_CASSETTE), "a" * 64
            )
        )

    def coordinator(self) -> AutomaticRecoveryCoordinator:
        return AutomaticRecoveryCoordinator(
            lambda: Catalog(self.database),
            self.fence,
            self.source,
            self.executor,
            clock=self.clock,
            poll_interval_seconds=0.01,
        )

    def attempts(self):
        with Catalog(self.database) as catalog:
            return catalog.list_recovery_attempts(self.blocker.id)

    def test_safe_action_is_started_before_effect_and_same_evidence_replays_once(
        self,
    ) -> None:
        coordinator = self.coordinator()

        first = coordinator.reconcile_startup((self.blocker,))
        second = coordinator.reconcile_startup((self.blocker,))

        self.assertEqual("resumed", first.items[0].state)
        self.assertEqual(first.items, second.items)
        self.assertEqual(
            [("retry_current_cassette", self.blocker.id)], self.executor.calls
        )
        attempts = self.attempts()
        self.assertEqual(1, len(attempts))
        self.assertEqual("succeeded", attempts[0].state)
        self.assertLess(attempts[0].started_at, attempts[0].outcome_at)

    def test_transient_retry_schedule_survives_restart_and_exhausts_after_delays(
        self,
    ) -> None:
        self.executor.transient_failures = 5
        coordinator = self.coordinator()
        observed_delays = []

        for expected_delay in (1, 2, 4, 8, 16):
            result = coordinator.reconcile_startup((self.blocker,))
            self.assertEqual("retry_scheduled", result.items[0].state)
            attempt = self.attempts()[-1]
            observed_delays.append(
                round(
                    (
                        datetime.fromisoformat(attempt.next_eligible_at)
                        - datetime.fromisoformat(attempt.outcome_at)
                    ).total_seconds()
                )
            )
            self.clock.value = datetime.fromisoformat(attempt.next_eligible_at)
            coordinator = self.coordinator()

        exhausted = coordinator.reconcile_startup((self.blocker,))

        self.assertEqual([1, 2, 4, 8, 16], observed_delays)
        self.assertEqual("failed_safe", exhausted.items[0].state)
        self.assertEqual(5, len(self.executor.calls))
        self.assertEqual("failed_safe", self.attempts()[-1].state)

    def test_waiting_media_does_not_consume_retry_budget_or_dispatch_effects(
        self,
    ) -> None:
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.WAIT_FOR_MEDIA,
                RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
            ),
            "b" * 64,
        )
        coordinator = self.coordinator()

        first = coordinator.reconcile_startup((self.blocker,))
        second = coordinator.poll_waiting_media()

        self.assertEqual("waiting_media", first.items[0].state)
        self.assertEqual("waiting_media", second.items[0].state)
        self.assertEqual([], self.executor.calls)
        self.assertEqual(1, len(self.attempts()))

        self.source.assessment = RecoveryAssessment(
            _decision(RecoveryAction.RETRY_CURRENT_CASSETTE), "c" * 64
        )
        resumed = coordinator.poll_waiting_media()

        self.assertEqual("resumed", resumed.items[0].state)
        self.assertEqual(
            [("retry_current_cassette", self.blocker.id)], self.executor.calls
        )
        self.executor.transient_failures = 1
        self.source.assessment = replace(
            self.source.assessment, evidence_sha256="d" * 64
        )
        scheduled = coordinator.reconcile_startup((self.blocker,))
        self.assertEqual("retry_scheduled", scheduled.items[0].state)
        attempt = self.attempts()[-1]
        self.assertEqual(
            1,
            round(
                (
                    datetime.fromisoformat(attempt.next_eligible_at)
                    - datetime.fromisoformat(attempt.outcome_at)
                ).total_seconds()
            ),
        )

    def test_critical_decision_never_invokes_executor(self) -> None:
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                RecoveryReason.MEDIA_IDENTITY_MISMATCH,
            ),
            "e" * 64,
        )
        critical = self.coordinator().reconcile_startup((self.blocker,))

        self.assertEqual("critical_quarantine", critical.items[0].state)
        self.assertEqual([], self.executor.calls)

    def test_production_decision_source_fails_closed_when_probe_is_unavailable(self):
        class UnavailableProbe:
            def inspect(self, _operation, _fence, _catalog):
                raise RuntimeError("physical observation unavailable")

        assessment = ProductionRecoveryDecisionSource(
            lambda: Catalog(self.database),
            self.fence,
            UnavailableProbe(),
        ).assess(self.blocker.id)

        self.assertEqual(
            (
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                RecoveryAction.HOLD_ADMISSION,
            ),
            assessment.decision.actions,
        )
        self.assertEqual(
            RecoveryReason.DURABLE_EVIDENCE_MISSING,
            assessment.decision.reason,
        )

    def test_production_observation_covers_command_added_by_read_only_probe(self):
        observed = "7" * 64
        with Catalog(self.database) as catalog:
            target = catalog.hardware_target_binding(self.blocker.id)
            assert target is not None
            command_fence = RecoveryCommandFence(
                self.blocker.id, self.fence.generation
            )
            catalog.reserve_hardware_command(
                command_fence, "critical-bound-command", "probe_media", "1" * 64
            )
            catalog.acknowledge_command_quiescence(
                "critical-bound-command",
                self.fence,
                CommandExitEvidence(
                    "critical-bound-command",
                    None,
                    "launch_aborted",
                    datetime.now(UTC).isoformat(),
                ),
            )
            catalog.connection.execute(
                "INSERT INTO operation_media_identity_bindings VALUES(?,?,?,?)",
                (
                    self.blocker.id,
                    observed,
                    "critical-bound-command",
                    "2026-08-28T09:00:04+00:00",
                ),
            )
            catalog.connection.commit()

        class LedgerMutatingProbe:
            def inspect(self, operation, fence, catalog):
                catalog.reserve_hardware_command(
                    fence, "critical-action-probe", "probe_media", "2" * 64
                )
                daemon = catalog.current_daemon_fence()
                assert daemon is not None
                catalog.acknowledge_command_quiescence(
                    "critical-action-probe",
                    daemon,
                    CommandExitEvidence(
                        "critical-action-probe",
                        None,
                        "launch_aborted",
                        datetime.now(UTC).isoformat(),
                    ),
                )
                return AggregateRecoveryProbe(
                    target=operation.target,
                    observed_media_identity_sha256=None,
                    configured_mount_source_identity_sha256=(
                        operation.target.tape_device_identity_sha256
                    ),
                    configured_mount_fstype="fuse.ltfs",
                    mounted=False,
                    mounted_source_identity_sha256=None,
                    mounted_fstype=None,
                    media_loaded=False,
                    drive_busy=False,
                    correlated_processes=(),
                )

        assessment = ProductionRecoveryDecisionSource(
            lambda: Catalog(self.database),
            self.fence,
            LedgerMutatingProbe(),
            clock=lambda: datetime(2026, 8, 28, 9, 1, 4, tzinfo=UTC),
        ).assess(self.blocker.id)

        self.assertIsNotNone(assessment.observation)
        with Catalog(self.database) as catalog:
            expected_ledger = critical_command_ledger_sha256(
                catalog.hardware_commands_for_operation(self.blocker.id)
            )
        self.assertEqual(
            expected_ledger, assessment.observation.command_ledger_sha256
        )
        self.assertTrue(assessment.observation.commands_quiescent)

    def test_same_evidence_with_a_different_decision_enters_quarantine(self) -> None:
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.WAIT_FOR_MEDIA,
                RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
            ),
            "f" * 64,
        )
        waiting = self.coordinator().reconcile_startup((self.blocker,))
        self.assertEqual("waiting_media", waiting.items[0].state)
        self.source.assessment = RecoveryAssessment(
            _decision(RecoveryAction.RETRY_IDENTIFICATION), "f" * 64
        )

        conflict = self.coordinator().reconcile_startup((self.blocker,))

        self.assertEqual("critical_quarantine", conflict.items[0].state)
        self.assertEqual([], self.executor.calls)

    def test_changed_evidence_cannot_bypass_an_unexpired_retry_delay(self) -> None:
        self.executor.transient_failures = 1
        coordinator = self.coordinator()
        scheduled = coordinator.reconcile_startup((self.blocker,))
        self.assertEqual("retry_scheduled", scheduled.items[0].state)
        self.source.assessment = replace(
            self.source.assessment, evidence_sha256="9" * 64
        )

        before_eligibility = coordinator.poll_waiting_media()

        self.assertEqual("retry_scheduled", before_eligibility.items[0].state)
        self.assertEqual(
            [("retry_current_cassette", self.blocker.id)], self.executor.calls
        )
        self.assertEqual(1, len(self.attempts()))

    def test_changed_evidence_respects_every_persisted_delay_boundary(self) -> None:
        self.executor.transient_failures = 5
        coordinator = self.coordinator()

        for index, expected_delay in enumerate((1, 2, 4, 8, 16), 1):
            scheduled = coordinator.reconcile_startup((self.blocker,))
            self.assertEqual("retry_scheduled", scheduled.items[0].state)
            attempt = self.attempts()[-1]
            self.assertEqual(
                expected_delay,
                round(
                    (
                        datetime.fromisoformat(attempt.next_eligible_at)
                        - datetime.fromisoformat(attempt.outcome_at)
                    ).total_seconds()
                ),
            )
            self.source.assessment = replace(
                self.source.assessment,
                evidence_sha256=f"{index:x}" * 64,
            )
            self.clock.value = datetime.fromisoformat(
                attempt.next_eligible_at
            ) - timedelta(microseconds=2)
            still_scheduled = coordinator.poll_waiting_media()
            self.assertEqual(
                "retry_scheduled", still_scheduled.items[0].state
            )
            self.assertEqual(index, len(self.executor.calls))
            self.clock.value = datetime.fromisoformat(attempt.next_eligible_at)

        exhausted = coordinator.reconcile_startup((self.blocker,))
        self.assertEqual("failed_safe", exhausted.items[0].state)
        self.assertEqual(5, len(self.executor.calls))

    def test_changed_evidence_with_a_conflicting_effect_quarantines(self) -> None:
        self.executor.transient_failures = 1
        coordinator = self.coordinator()
        coordinator.reconcile_startup((self.blocker,))
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.RETRY_UNLOAD,
                RecoveryReason.UNLOAD_IDENTITY_EXACT,
            ),
            "8" * 64,
        )

        conflict = coordinator.poll_waiting_media()

        self.assertEqual("critical_quarantine", conflict.items[0].state)
        self.assertEqual(
            [("retry_current_cassette", self.blocker.id)], self.executor.calls
        )

    def test_waiting_reassessment_during_backoff_exactly_replays_one_wait(self):
        self.executor.transient_failures = 1
        coordinator = self.coordinator()
        coordinator.reconcile_startup((self.blocker,))
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.WAIT_FOR_MEDIA,
                RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
            ),
            "7" * 64,
        )

        first = coordinator.poll_waiting_media()
        second = coordinator.poll_waiting_media()

        self.assertEqual("waiting_media", first.items[0].state)
        self.assertEqual(first.items, second.items)
        self.assertEqual(2, len(self.attempts()))

    def test_response_loss_continues_the_recorded_action_not_generic_observation(
        self,
    ) -> None:
        cases = (
            (
                RecoveryAction.RECONCILE_COMMANDS,
                RecoveryReason.COMMANDS_NOT_QUIESCENT,
                "observe_command",
                "observed",
            ),
            (
                RecoveryAction.RECONCILE_COMMIT,
                RecoveryReason.COMMIT_EVIDENCE_EXACT,
                "reconcile_commit",
                "commit_reconciled",
            ),
            (
                RecoveryAction.RETRY_IDENTIFICATION,
                RecoveryReason.IDENTIFICATION_RETRY_SAFE,
                "retry_identification",
                "identification_retried",
            ),
            (
                RecoveryAction.RETRY_CURRENT_CASSETTE,
                RecoveryReason.CASSETTE_CHECKPOINT_RETRY_SAFE,
                "retry_current_cassette",
                "resumed",
            ),
            (
                RecoveryAction.RETRY_UNLOAD,
                RecoveryReason.UNLOAD_IDENTITY_EXACT,
                "retry_unload",
                "unload_retried",
            ),
        )
        for action, reason, expected_call, visible_state in cases:
            with self.subTest(decision=action.value):
                self.setUp()
                self.source.assessment = RecoveryAssessment(
                    _decision(action, reason), "a" * 64
                )
                with Catalog(self.database) as catalog:
                    catalog.begin_recovery_attempt(
                        self.blocker.id,
                        1,
                        self.fence,
                        trigger="daemon_restart",
                        evidence_sha256="a" * 64,
                        decision=action.value,
                        recorded_at="2026-08-28T09:30:00+00:00",
                    )
                    self.fence = catalog.claim_daemon_owner(
                        "daemon-response-loss"
                    )
                    self.blocker = catalog.recover_interrupted_operations(
                        self.fence
                    )[0]

                result = self.coordinator().reconcile_startup((self.blocker,))

                self.assertEqual(visible_state, result.items[0].state)
                self.assertEqual(
                    [(expected_call, self.blocker.id)], self.executor.calls
                )
                self.assertEqual("succeeded", self.attempts()[0].state)

    def test_response_loss_quarantines_noop_or_contradictory_action(self) -> None:
        class NoProofExecutor(_Executor):
            def retry_current_cassette(self, blocker, fence):
                self.calls.append(("retry_current_cassette", blocker.id))
                return None

        with Catalog(self.database) as catalog:
            catalog.begin_recovery_attempt(
                self.blocker.id,
                1,
                self.fence,
                trigger="daemon_restart",
                evidence_sha256="a" * 64,
                decision=RecoveryAction.RETRY_CURRENT_CASSETTE.value,
                recorded_at="2026-08-28T09:30:00+00:00",
            )
            self.fence = catalog.claim_daemon_owner("daemon-no-proof")
            self.blocker = catalog.recover_interrupted_operations(self.fence)[0]
        self.executor = NoProofExecutor()
        no_proof = self.coordinator().reconcile_startup((self.blocker,))
        self.assertEqual("critical_quarantine", no_proof.items[0].state)

        self.setUp()
        with Catalog(self.database) as catalog:
            catalog.begin_recovery_attempt(
                self.blocker.id,
                1,
                self.fence,
                trigger="daemon_restart",
                evidence_sha256="a" * 64,
                decision=RecoveryAction.RETRY_CURRENT_CASSETTE.value,
                recorded_at="2026-08-28T09:30:00+00:00",
            )
            self.fence = catalog.claim_daemon_owner("daemon-contradiction")
            self.blocker = catalog.recover_interrupted_operations(self.fence)[0]
        self.source.assessment = RecoveryAssessment(
            _decision(RecoveryAction.RETRY_IDENTIFICATION), "b" * 64
        )
        contradictory = self.coordinator().reconcile_startup((self.blocker,))
        self.assertEqual("critical_quarantine", contradictory.items[0].state)
        self.assertEqual([], self.executor.calls)

    def test_critical_reassessment_is_public_read_only_and_dispatches_no_effect(
        self,
    ) -> None:
        self.source.assessment = RecoveryAssessment(
            _decision(RecoveryAction.ENTER_CRITICAL_QUARANTINE), "d" * 64
        )
        coordinator = self.coordinator()
        critical = coordinator.reconcile_startup((self.blocker,))
        before = self.attempts()
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.RETRY_IDENTIFICATION,
                RecoveryReason.IDENTIFICATION_RETRY_SAFE,
            ),
            "e" * 64,
        )

        reassessed = coordinator.reassess_critical(self.blocker.id)

        self.assertEqual("e" * 64, reassessed.evidence_sha256)
        self.assertEqual(before, self.attempts())
        self.assertEqual("critical_quarantine", critical.items[0].state)
        self.assertEqual([], self.executor.calls)

    def test_automatic_poll_does_not_reassess_sticky_critical_quarantine(
        self,
    ) -> None:
        self.source.assessment = RecoveryAssessment(
            _decision(RecoveryAction.ENTER_CRITICAL_QUARANTINE), "d" * 64
        )
        coordinator = self.coordinator()
        critical = coordinator.reconcile_startup((self.blocker,))
        calls_before_poll = list(self.source.calls)
        self.assertEqual([self.blocker.id], calls_before_poll)
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.RETRY_IDENTIFICATION,
                RecoveryReason.IDENTIFICATION_RETRY_SAFE,
            ),
            "e" * 64,
        )

        attempts_before_poll = self.attempts()
        first_poll = coordinator.poll_waiting_media()
        second_poll = coordinator.poll_waiting_media()

        self.assertEqual("critical_quarantine", critical.items[0].state)
        for polled in (first_poll, second_poll):
            self.assertEqual("critical_quarantine", polled.items[0].state)
            self.assertEqual(
                RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
                polled.items[0].decision,
            )
            self.assertEqual(
                RecoveryReason.OPERATION_STILL_BLOCKING.value,
                polled.items[0].reason,
            )
        self.assertEqual(calls_before_poll, self.source.calls)
        self.assertEqual([], self.executor.calls)
        self.assertEqual(attempts_before_poll, self.attempts())

        reassessed = coordinator.reassess_critical(self.blocker.id)

        self.assertEqual("e" * 64, reassessed.evidence_sha256)
        self.assertEqual(calls_before_poll + [self.blocker.id], self.source.calls)
        self.assertEqual([], self.executor.calls)
        self.assertEqual(attempts_before_poll, self.attempts())

    def test_startup_rolls_forward_old_sticky_quarantine_once_without_effect(self):
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                RecoveryReason.MEDIA_IDENTITY_MISMATCH,
            ),
            "d" * 64,
        )
        original = self.coordinator().reconcile_startup((self.blocker,))
        old_generation = self.fence.generation
        self.assertEqual("critical_quarantine", original.items[0].state)

        with Catalog(self.database) as catalog:
            self.fence = catalog.claim_daemon_owner("daemon-after-critical-restart")
            self.blocker = catalog.recover_interrupted_operations(self.fence)[0]
        self.assertGreater(self.fence.generation, old_generation)
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.RETRY_IDENTIFICATION,
                RecoveryReason.IDENTIFICATION_RETRY_SAFE,
            ),
            "e" * 64,
        )
        restarted = self.coordinator()

        rolled = restarted.reconcile_startup((self.blocker,))
        replayed = restarted.reconcile_startup((self.blocker,))
        attempts_before_poll = self.attempts()
        polled = restarted.poll_waiting_media()

        self.assertEqual("critical_quarantine", rolled.items[0].state)
        self.assertEqual(rolled.items, replayed.items)
        self.assertEqual("critical_quarantine", polled.items[0].state)
        self.assertEqual([], self.executor.calls)
        self.assertEqual(2, len(attempts_before_poll))
        self.assertEqual(old_generation, attempts_before_poll[0].daemon_generation)
        self.assertEqual(
            self.fence.generation, attempts_before_poll[1].daemon_generation
        )
        self.assertEqual("e" * 64, attempts_before_poll[1].evidence_sha256)
        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE.value,
            attempts_before_poll[1].decision,
        )
        self.assertEqual(attempts_before_poll, self.attempts())
        self.assertEqual(
            [self.blocker.id, self.blocker.id, self.blocker.id],
            self.source.calls,
        )

    def test_response_loss_accepts_action_specific_after_effect_receipt(self) -> None:
        class ReceiptOracle(_Executor):
            def prove_incomplete(self, action, blocker, fence):
                return RecoveryEffectReceipt(
                    action.value,
                    blocker.id,
                    fence.owner_generation,
                    "durable-postcondition",
                )

        with Catalog(self.database) as catalog:
            catalog.begin_recovery_attempt(
                self.blocker.id,
                1,
                self.fence,
                trigger="daemon_restart",
                evidence_sha256="a" * 64,
                decision=RecoveryAction.RECONCILE_COMMIT.value,
                recorded_at="2026-08-28T09:30:00+00:00",
            )
            self.fence = catalog.claim_daemon_owner("daemon-after-effect")
            self.blocker = catalog.recover_interrupted_operations(self.fence)[0]
        self.source.assessment = RecoveryAssessment(
            _decision(RecoveryAction.RETRY_UNLOAD), "b" * 64
        )
        self.executor = ReceiptOracle()

        recovered = self.coordinator().reconcile_startup((self.blocker,))

        self.assertEqual("commit_reconciled", recovered.items[0].state)
        self.assertEqual([], self.executor.calls)
        self.assertEqual("succeeded", self.attempts()[0].state)

    def test_concurrent_exact_begin_replay_has_one_durable_effect_owner(self) -> None:
        clock = _ConstantClock()
        entered = threading.Event()
        release = threading.Event()
        calls_lock = threading.Lock()

        class BlockingExecutor(_Executor):
            def retry_current_cassette(self, blocker, fence) -> None:
                with calls_lock:
                    self.calls.append(("retry_current_cassette", blocker.id))
                entered.set()
                if not release.wait(2):
                    raise TimeoutError("test effect was not released")
                return RecoveryEffectReceipt(
                    "retry_current_cassette",
                    blocker.id,
                    fence.owner_generation,
                    "proof:concurrent",
                )

        executor = BlockingExecutor()

        def coordinator(clock_value) -> AutomaticRecoveryCoordinator:
            return AutomaticRecoveryCoordinator(
                lambda: Catalog(self.database),
                self.fence,
                self.source,
                executor,
                clock=clock_value,
            )

        results = []
        errors = []

        def reconcile(instance) -> None:
            try:
                results.append(instance.reconcile_startup((self.blocker,)))
            except BaseException as exc:
                errors.append(exc)

        later_clock = _ConstantClock()
        later_clock.value += timedelta(microseconds=1)
        first = threading.Thread(target=reconcile, args=(coordinator(clock),))
        second = threading.Thread(
            target=reconcile, args=(coordinator(later_clock),)
        )
        first.start()
        self.assertTrue(entered.wait(1))
        second.start()
        second.join(1)
        release.set()
        first.join(2)
        second.join(2)

        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(2, len(results))
        self.assertEqual(
            [("retry_current_cassette", self.blocker.id)], executor.calls
        )
        self.assertEqual(1, len(self.attempts()))

    def test_commit_and_postcommit_response_loss_dispatch_only_the_exact_effect(self):
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.RECONCILE_COMMIT,
                RecoveryReason.COMMIT_EVIDENCE_EXACT,
            ),
            "1" * 64,
        )
        coordinator = self.coordinator()

        coordinator.reconcile_startup((self.blocker,))
        coordinator.reconcile_startup((self.blocker,))
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.RETRY_UNLOAD,
                RecoveryReason.UNLOAD_IDENTITY_EXACT,
            ),
            "2" * 64,
        )
        coordinator.reconcile_startup((self.blocker,))
        coordinator.reconcile_startup((self.blocker,))

        self.assertEqual(
            [
                ("reconcile_commit", self.blocker.id),
                ("retry_unload", self.blocker.id),
            ],
            self.executor.calls,
        )

    def test_stale_daemon_fence_rejects_before_executor_effect(self) -> None:
        coordinator = self.coordinator()
        with Catalog(self.database) as catalog:
            catalog.claim_daemon_owner("daemon-newer")

        with self.assertRaises(StaleDaemonFence):
            coordinator.reconcile_startup((self.blocker,))

        self.assertEqual([], self.executor.calls)
        self.assertEqual((), self.attempts())

    def test_recovery_never_scans_or_mutates_frozen_layout_tables(self) -> None:
        self.source.assessment = RecoveryAssessment(
            _decision(
                RecoveryAction.WAIT_FOR_MEDIA,
                RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
            ),
            "3" * 64,
        )

        def layout_snapshot():
            with Catalog(self.database) as catalog:
                return tuple(
                    tuple(row)
                    for table in (
                        "automatic_jobs",
                        "automatic_cassettes",
                        "automatic_cassette_items",
                        "job_plan_drafts",
                        "job_plan_cassettes",
                        "job_plan_items",
                    )
                    for row in catalog.connection.execute(
                        f"SELECT * FROM {table} ORDER BY rowid"
                    )
                )

        before = layout_snapshot()
        with (
            patch("ltobackup.application.analyze_library") as application_scan,
            patch("ltobackup.scanner.analyze_library") as scanner_scan,
            patch("ltobackup.engine.BackupEngine.scan") as engine_scan,
        ):
            result = self.coordinator().reconcile_startup((self.blocker,))

        self.assertEqual("waiting_media", result.items[0].state)
        application_scan.assert_not_called()
        scanner_scan.assert_not_called()
        engine_scan.assert_not_called()
        self.assertEqual(before, layout_snapshot())


class RecoveryCoordinatorServiceLifecycleTests(unittest.TestCase):
    def test_startup_reconciliation_finishes_before_mutation_admission_opens(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = LinuxSettings(
                state_dir=root / "state",
                socket_path=root / "run" / "daemon.sock",
                source_roots=(root / "source",),
                restore_roots=(root / "restore",),
            )
            paths = LinuxPaths.from_settings(settings)
            backups = BackupManager(paths.catalog_file, paths.backup_dir)
            coordinator = _BlockingCoordinator()
            created_with: list[OperationManager] = []

            def factory(operations: OperationManager):
                created_with.append(operations)
                return coordinator

            service = DaemonService(
                paths,
                settings,
                backups,
                None,
                EventBus(lambda: Catalog(paths.catalog_file)),
                recovery_coordinator_factory=factory,
                shutdown_timeout_seconds=0,
            )
            startup_result = []
            startup_errors = []

            def startup() -> None:
                try:
                    startup_result.append(service.startup())
                except BaseException as exc:
                    startup_errors.append(exc)

            thread = threading.Thread(target=startup)
            thread.start()
            self.assertTrue(coordinator.entered.wait(1))
            self.assertEqual(1, len(created_with))
            self.assertEqual(service.daemon_fence, created_with[0].daemon_fence)
            with self.assertRaises(MutationAdmissionClosed):
                service.start_operation(
                    OperationRequest(kind="diagnostic"),
                    "blocked-during-recovery",
                    Principal("admin", role="admin"),
                )

            coordinator.release.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertEqual([], startup_errors)
            self.assertTrue(startup_result[0].safe_for_admission)
            accepted = service.start_operation(
                OperationRequest(kind="diagnostic"),
                "accepted-after-recovery",
                Principal("admin", role="admin"),
            )
            self.assertEqual("accepted-after-recovery", accepted.idempotency_key)

            service.shutdown(timeout_seconds=0)

            self.assertEqual(
                [
                    "set_transition_callback",
                    ("reconcile_startup", ()),
                    "start",
                    "shutdown",
                ],
                coordinator.calls,
            )

    def test_watcher_transition_reopens_admission_after_blocker_resolves(self):
        blocker = OperationRecord(
            "operation-4",
            "archive.native",
            "recovery_required",
            "writing",
            "blocked",
            "admin",
            "JOB-1",
            4,
            "2026-08-28T09:00:00+00:00",
            None,
        )

        class Operations:
            daemon_fence = DaemonFence("daemon-test", 2)

            def __init__(self):
                self.blockers = (blocker,)
                self.accepting = False

            def stop_accepting(self):
                self.accepting = False

            def start_accepting(self):
                self.accepting = True

            def recover_interrupted(self):
                return self.blockers

            def reconcile_admission_blockers(self):
                return self.blockers

            def shutdown(self, _timeout):
                return ()

        class Coordinator:
            def set_transition_callback(self, callback):
                self.callback = callback

            def reconcile_startup(self, _blockers):
                return RecoveryCoordinatorResult(
                    (
                        RecoveryCoordinatorItem(
                            blocker.id,
                            "waiting_media",
                            "wait_for_media",
                            "waiting_media_retry_safe",
                            1,
                        ),
                    )
                )

            def start(self):
                return None

            def shutdown(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = LinuxSettings(
                state_dir=root / "state",
                socket_path=root / "run" / "daemon.sock",
                source_roots=(root / "source",),
                restore_roots=(root / "restore",),
            )
            paths = LinuxPaths.from_settings(settings)
            operations = Operations()
            coordinator = Coordinator()
            service = DaemonService(
                paths,
                settings,
                BackupManager(paths.catalog_file, paths.backup_dir),
                operations,
                EventBus(lambda: Catalog(paths.catalog_file)),
                recovery_coordinator_factory=lambda _operations: coordinator,
                shutdown_timeout_seconds=0,
            )
            service.startup()
            self.assertFalse(operations.accepting)

            operations.blockers = ()
            coordinator.callback(
                RecoveryCoordinatorResult(
                    (
                        RecoveryCoordinatorItem(
                            blocker.id,
                            "resumed",
                            "retry_current_cassette",
                            "cassette_checkpoint_retry_safe",
                            2,
                        ),
                    )
                )
            )

            self.assertTrue(operations.accepting)
            self.assertTrue(service._accepting_mutations)
            service.shutdown(timeout_seconds=0)
            operations.blockers = (blocker,)
            coordinator.callback(
                RecoveryCoordinatorResult(
                    (
                        RecoveryCoordinatorItem(
                            blocker.id,
                            "resumed",
                            "retry_current_cassette",
                            "cassette_checkpoint_retry_safe",
                            3,
                        ),
                    )
                )
            )
            self.assertFalse(operations.accepting)

    def test_critical_transition_quarantines_drive_scope_but_reopens_management(self):
        blocker = OperationRecord(
            "operation-4",
            "archive.native",
            "recovery_required",
            "writing",
            "blocked",
            "admin",
            "JOB-1",
            4,
            "2026-08-28T09:00:00+00:00",
            None,
        )

        class Operations:
            daemon_fence = DaemonFence("daemon-test", 2)
            accepting = False

            def stop_accepting(self):
                self.accepting = False

            def start_accepting(self):
                self.accepting = True

            def recover_interrupted(self):
                return (blocker,)

            def reconcile_admission_blockers(self):
                return (blocker,)

            def shutdown(self, _timeout):
                return ()

        class Coordinator:
            def set_transition_callback(self, callback):
                self.callback = callback

            def reconcile_startup(self, _blockers):
                return RecoveryCoordinatorResult(())

            def start(self):
                return None

            def shutdown(self):
                return None

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            settings = LinuxSettings(
                state_dir=root / "state",
                socket_path=root / "run" / "daemon.sock",
                source_roots=(root / "source",),
                restore_roots=(root / "restore",),
            )
            paths = LinuxPaths.from_settings(settings)
            operations = Operations()
            coordinator = Coordinator()
            service = DaemonService(
                paths,
                settings,
                BackupManager(paths.catalog_file, paths.backup_dir),
                operations,
                EventBus(lambda: Catalog(paths.catalog_file)),
                recovery_coordinator_factory=lambda _operations: coordinator,
                shutdown_timeout_seconds=0,
            )
            service.startup()

            coordinator.callback(
                RecoveryCoordinatorResult(
                    (
                        RecoveryCoordinatorItem(
                            blocker.id,
                            "critical_quarantine",
                            "enter_critical_quarantine",
                            "media_identity_mismatch",
                            1,
                        ),
                    )
                )
            )

            self.assertTrue(operations.accepting)
            self.assertTrue(service._accepting_mutations)
            self.assertEqual({blocker.id}, service._quarantined_operation_ids)
            service.shutdown(timeout_seconds=0)


if __name__ == "__main__":
    unittest.main()
