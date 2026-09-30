from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.models import (
    CommandExitEvidence,
    CommandQuiescenceReceipt,
    HardwareCommandExecution,
    HardwareTargetBinding,
    OperationFence,
    OperationRecord,
    PhysicalReconciliationReceipt,
    ProcessIdentity,
    SafeRecoveryResolution,
    VerifiedPhysicalQuiescence,
)
from ltobackup.daemon.recovery import (
    AggregateRecoveryProbe,
    CatalogRecoveryStateSource,
    CommitEvidence,
    DurableOperation,
    MediaBinding,
    ReceiptChain,
    RecoveryAction,
    RecoveryContext,
    RecoveryInput,
    RecoveryLineage,
    RecoveryManager,
    RecoveryOutcome,
    RecoveryReason,
    RecoveryStateError,
    ResolutionReceipt,
    decide_recovery,
    recovery_lineage_sha256,
)

T0 = "2026-08-22T10:00:00+00:00"
T1 = "2026-08-22T10:00:01+00:00"
T2 = "2026-08-22T10:00:02+00:00"
T3 = "2026-08-22T10:00:03+00:00"
T4 = "2026-08-22T10:00:04+00:00"
T5 = "2026-08-22T10:00:05+00:00"
T6 = "2026-08-22T10:00:06+00:00"
T7 = "2026-08-22T10:00:07+00:00"
T8 = "2026-08-22T10:00:08+00:00"
T9 = "2026-08-22T10:00:09+00:00"
MEDIA_A = "1" * 64
MEDIA_B = "2" * 64
MANIFEST = "3" * 64
MOUNT_SOURCE = "4" * 64
PROCESS_IDENTIFY = ProcessIdentity("boot-a", 101, 201, 101)
PROCESS_UNMOUNT = ProcessIdentity("boot-a", 102, 202, 102)


def _target(character: str = "a") -> HardwareTargetBinding:
    return HardwareTargetBinding(*(character * 64 for _ in range(4)))


def _seed_resumable_job(catalog: Catalog, source_root: Path) -> None:
    catalog.add_library("recovery-library", "Recovery library", str(source_root))
    catalog.create_automatic_job(
        "job",
        "recovery-library",
        "synthetic-drive",
        "/synthetic/mount",
        [(f"RC{i:04d}", f"SERIAL-{i}", 1, 1) for i in range(1, 5)],
        force_format=True,
    )


def _binding(
    *, identity: str = MEDIA_A, command_id: str = "identify-1", bound_at: str = T3
) -> MediaBinding:
    return MediaBinding(identity, command_id, bound_at)


def _operation(
    phase: str | None,
    *,
    state: str = "recovery_required",
    generation: int = 7,
    sequence: int = 4,
    target: HardwareTargetBinding | None = None,
    binding: MediaBinding | None = None,
    error_code: str | None = None,
    kind: str = "archive.resume",
) -> DurableOperation:
    return DurableOperation(
        operation_id="operation-4",
        state=state,
        phase=phase,
        interrupted_generation=generation,
        cassette_sequence=sequence,
        target=target or _target(),
        expected_mount_source_identity_sha256=MOUNT_SOURCE,
        expected_mount_fstype="fuse.ltfs",
        media_binding=binding,
        started_at=T0,
        error_code=error_code,
        kind=kind,
    )


def _command(
    *,
    command_id: str = "identify-1",
    kind: str = "identify",
    generation: int = 7,
    target: HardwareTargetBinding | None = None,
    media: str | None = None,
    state: str = "quiesced",
    outcome: str | None = "completed",
    process: ProcessIdentity | None = PROCESS_IDENTIFY,
    created_at: str = T1,
    quiesced_at: str | None = T2,
) -> HardwareCommandExecution:
    return HardwareCommandExecution(
        id=command_id,
        operation_id="operation-4",
        issued_generation=generation,
        kind=kind,
        argv_sha256="6" * 64,
        target=target or _target(),
        observed_media_identity_sha256=media,
        state=state,
        process=process,
        exit_outcome=outcome,
        created_at=created_at,
        release_permit_sha256=None,
        release_status=None,
        release_authorized_at=None,
        release_confirmed_at=None,
        released_at=T1 if state == "quiesced" else None,
        exit_observed_at=quiesced_at,
        quiesced_at=quiesced_at,
    )


def _bound_commands() -> tuple[HardwareCommandExecution, ...]:
    return (
        _command(),
        _command(
            command_id="unmount-1",
            kind="unmount",
            media=MEDIA_A,
            process=PROCESS_UNMOUNT,
            created_at=T4,
            quiesced_at=T5,
        ),
    )


def _lineage(
    commands: tuple[HardwareCommandExecution, ...],
    *,
    original_generation: int = 7,
    recovery_generation: int = 8,
    command_ids: tuple[str, ...] | None = None,
    recorded_at: str = T6,
    authenticated: str | None = None,
    expected: str | None = None,
) -> RecoveryLineage:
    ids = (
        tuple(command.id for command in commands)
        if command_ids is None
        else command_ids
    )
    digest = recovery_lineage_sha256(
        lineage_id="lineage-8",
        operation_id="operation-4",
        original_generation=original_generation,
        recovery_generation=recovery_generation,
        prior_lineage_id=None,
        command_ids=ids,
        recorded_at=recorded_at,
    )
    return RecoveryLineage(
        lineage_id="lineage-8",
        operation_id="operation-4",
        original_generation=original_generation,
        recovery_generation=recovery_generation,
        prior_lineage_id=None,
        command_ids=ids,
        recorded_at=recorded_at,
        authenticated_sha256=authenticated or digest,
        expected_sha256=expected or digest,
    )


def _context(
    commands: tuple[HardwareCommandExecution, ...],
    *,
    current_generation: int = 8,
    lineage: RecoveryLineage | None = None,
) -> RecoveryContext:
    return RecoveryContext(
        current_generation=current_generation,
        lineages=(lineage or _lineage(commands),),
    )


def _probe(
    *,
    target: HardwareTargetBinding | None = None,
    media: str | None = MEDIA_A,
    configured_source: str = MOUNT_SOURCE,
    configured_fstype: str = "fuse.ltfs",
    mounted: bool = False,
    mounted_source: str | None = None,
    mounted_fstype: str | None = None,
    loaded: bool = False,
    busy: bool = False,
    processes: tuple[ProcessIdentity, ...] = (),
) -> AggregateRecoveryProbe:
    return AggregateRecoveryProbe(
        target=target or _target(),
        observed_media_identity_sha256=media,
        configured_mount_source_identity_sha256=configured_source,
        configured_mount_fstype=configured_fstype,
        mounted=mounted,
        mounted_source_identity_sha256=mounted_source,
        mounted_fstype=mounted_fstype,
        media_loaded=loaded,
        drive_busy=busy,
        correlated_processes=processes,
    )


def _commit() -> CommitEvidence:
    return CommitEvidence(
        operation_id="operation-4",
        attempt_generation=7,
        target=_target(),
        observed_media_identity_sha256=MEDIA_A,
        unmount_command_id="unmount-1",
        manifest_sha256=MANIFEST,
        provisional_manifest_sha256=MANIFEST,
        recorded_at=T6,
    )


def _command_receipt(
    commands: tuple[HardwareCommandExecution, ...],
    *,
    generation: int = 8,
    command_ids: tuple[str, ...] | None = None,
    evidence: tuple[CommandExitEvidence, ...] | None = None,
    recorded_at: str = T7,
) -> CommandQuiescenceReceipt:
    ids = (
        tuple(command.id for command in commands)
        if command_ids is None
        else command_ids
    )
    exact_evidence = (
        tuple(
            CommandExitEvidence(
                command.id,
                command.process,
                command.exit_outcome,
                command.quiesced_at,
            )
            for command in commands
        )
        if evidence is None
        else evidence
    )
    return CommandQuiescenceReceipt(
        "commands-8", "operation-4", generation, ids, exact_evidence, recorded_at
    )


def _physical_receipt(
    command_receipt: CommandQuiescenceReceipt,
    *,
    generation: int = 8,
    target: HardwareTargetBinding | None = None,
    media: str | None = MEDIA_A,
    loaded: bool = False,
    busy: bool = False,
    processes: tuple[ProcessIdentity, ...] = (),
    recorded_at: str = T8,
) -> PhysicalReconciliationReceipt:
    return PhysicalReconciliationReceipt(
        "physical-8",
        "operation-4",
        generation,
        command_receipt.id,
        target or _target(),
        media,
        False,
        loaded,
        busy,
        processes,
        recorded_at,
    )


def _receipts(
    commands: tuple[HardwareCommandExecution, ...],
    *,
    command: CommandQuiescenceReceipt | None = None,
    physical: PhysicalReconciliationReceipt | None = None,
    resolution: ResolutionReceipt | None = None,
) -> ReceiptChain:
    command = command or _command_receipt(commands)
    physical = physical or _physical_receipt(command)
    resolution = resolution or ResolutionReceipt(
        "resolution-8", "operation-4", 8, command.id, physical.id, T9
    )
    return ReceiptChain(command, physical, resolution)


def _input(
    phase: str | None,
    *,
    operation: DurableOperation | None = None,
    commands: tuple[HardwareCommandExecution, ...] | None = None,
    context: RecoveryContext | None = None,
    probe: AggregateRecoveryProbe | None = None,
    commit: CommitEvidence | None = None,
    receipts: ReceiptChain | None = None,
) -> RecoveryInput:
    operation = operation or _operation(phase, binding=_binding())
    commands = _bound_commands() if commands is None else commands
    context = context or _context(commands)
    return RecoveryInput(
        operation=operation,
        recovery=context,
        commands=commands,
        probe=probe or _probe(media=operation.observed_media_identity_sha256),
        commit_evidence=commit,
        receipts=receipts or ReceiptChain(),
    )


def _create_resolved_catalog(database: Path) -> None:
    with Catalog(database) as catalog:
        catalog.initialize()
        _seed_resumable_job(catalog, database.parent)
        original = catalog.claim_daemon_owner("daemon-1")
        admitted = catalog.admit_operation(
            OperationRecord(
                "operation-4",
                "archive.resume",
                "running",
                "identifying_media",
                "key",
                "admin",
                "job",
                4,
                T0,
                None,
            ),
            original,
            admission_open=True,
            hardware_target=_target(),
        )
        fence = OperationFence(admitted.record.id, original.generation)
        catalog.reserve_hardware_command(fence, "identify-1", "identify", "6" * 64)
        catalog.record_blocked_process("identify-1", fence, PROCESS_IDENTIFY)
        permit = "7" * 64
        catalog.authorize_hardware_command_release("identify-1", fence, permit)
        catalog.confirm_hardware_command_released("identify-1", fence, permit)
        command = catalog.command("identify-1")
        quiesced_at = (
            datetime.fromisoformat(command.released_at) + timedelta(microseconds=1)
        ).isoformat()
        catalog.acknowledge_command_quiescence(
            "identify-1",
            original,
            CommandExitEvidence(
                "identify-1", PROCESS_IDENTIFY, "completed", quiesced_at
            ),
        )

    with Catalog(database) as catalog:
        catalog.initialize()
        recovery = catalog.claim_daemon_owner("daemon-2")
        catalog.recover_interrupted_operations(recovery)
        command_receipt = catalog.create_command_quiescence_receipt(
            "operation-4", recovery
        )
        physical_receipt = catalog.create_physical_reconciliation_receipt(
            "operation-4",
            recovery,
            command_receipt.id,
            VerifiedPhysicalQuiescence(
                target=_target(),
                observed_media_identity_sha256=None,
                mounted=False,
                media_loaded=False,
                drive_busy=False,
                related_processes=(),
            ),
        )
        catalog.resolve_recovery(
            "operation-4",
            recovery,
            SafeRecoveryResolution(
                reason_code="identify-command-physically-reconciled",
                command_receipt_id=command_receipt.id,
                physical_receipt_id=physical_receipt.id,
            ),
        )


class RecoveryDecisionMatrixTests(unittest.TestCase):
    def test_phase_matrix_is_closed_and_fail_safe(self) -> None:
        cases = {
            "identifying_media": RecoveryAction.RETRY_IDENTIFICATION,
            "formatting_media": RecoveryAction.RETRY_CURRENT_CASSETTE,
            "mounting": RecoveryAction.RETRY_CURRENT_CASSETTE,
            "writing": RecoveryAction.RETRY_CURRENT_CASSETTE,
            "writing_manifest": RecoveryAction.RETRY_CURRENT_CASSETTE,
            "finalizing_index": RecoveryAction.RETRY_CURRENT_CASSETTE,
            "unmounting": RecoveryAction.RETRY_CURRENT_CASSETTE,
            "committing": RecoveryAction.RECONCILE_COMMIT,
            "unloading": RecoveryAction.RETRY_UNLOAD,
        }
        for phase, expected in cases.items():
            with self.subTest(phase=phase):
                binding = None if phase == "identifying_media" else _binding()
                commands = (_command(),) if binding is None else _bound_commands()
                operation = _operation(phase, binding=binding)
                probe = _probe(
                    media=None if binding is None else MEDIA_A,
                    loaded=phase in {"identifying_media", "unloading"},
                )
                decision = decide_recovery(
                    _input(
                        phase,
                        operation=operation,
                        commands=commands,
                        context=_context(commands),
                        probe=probe,
                        commit=_commit() if phase == "committing" else None,
                    )
                )
                self.assertEqual(expected, decision.actions[0])
                self.assertFalse(decision.admission_open)

    def test_terminal_open_validates_ledger_not_only_receipt_ids(self) -> None:
        valid_commands = _bound_commands()
        valid_receipts = _receipts(valid_commands)
        mutations = (
            _command(
                command_id="unmount-1",
                kind="unmount",
                media=MEDIA_A,
                state="released",
                outcome=None,
                process=PROCESS_UNMOUNT,
                created_at=T4,
                quiesced_at=None,
            ),
            _command(
                command_id="unmount-1",
                kind="unmount",
                media=MEDIA_A,
                outcome="launch_aborted",
                process=PROCESS_UNMOUNT,
                created_at=T4,
                quiesced_at=T5,
            ),
        )
        for mutated in mutations:
            with self.subTest(state=mutated.state, outcome=mutated.exit_outcome):
                commands = (valid_commands[0], mutated)
                decision = decide_recovery(
                    _input(
                        "unloading",
                        operation=_operation(
                            "unloading", state="cancelled", binding=_binding()
                        ),
                        commands=commands,
                        context=_context(commands),
                        receipts=valid_receipts,
                    )
                )
                self.assertFalse(decision.admission_open)
                self.assertNotEqual(RecoveryReason.RECOVERY_RESOLVED, decision.reason)

    def _assert_commit_evidence_mutation_is_failure_sensitive(
        self, evidence: CommitEvidence
    ) -> None:
        base = _input("committing", commit=_commit())
        valid = decide_recovery(base)
        self.assertEqual(RecoveryReason.COMMIT_EVIDENCE_EXACT, valid.reason)

        decision = decide_recovery(replace(base, commit_evidence=evidence))
        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE, decision.actions[0]
        )
        self.assertEqual(RecoveryReason.COMMIT_EVIDENCE_INCOMPLETE, decision.reason)

    def test_commit_evidence_operation_id_is_failure_sensitive(self) -> None:
        self._assert_commit_evidence_mutation_is_failure_sensitive(
            replace(_commit(), operation_id="other-operation")
        )

    def test_commit_evidence_target_is_failure_sensitive(self) -> None:
        self._assert_commit_evidence_mutation_is_failure_sensitive(
            replace(_commit(), target=_target("b"))
        )

    def test_commit_evidence_media_is_failure_sensitive(self) -> None:
        self._assert_commit_evidence_mutation_is_failure_sensitive(
            replace(_commit(), observed_media_identity_sha256=MEDIA_B)
        )

    def test_commit_evidence_timestamp_after_unmount_is_failure_sensitive(self) -> None:
        self._assert_commit_evidence_mutation_is_failure_sensitive(
            replace(_commit(), recorded_at=T5)
        )

    def test_commit_attempt_and_manifest_are_failure_sensitive(self) -> None:
        for evidence in (
            replace(_commit(), attempt_generation=8),
            replace(_commit(), unmount_command_id="identify-1"),
            replace(_commit(), provisional_manifest_sha256="7" * 64),
        ):
            with self.subTest(evidence=evidence):
                self._assert_commit_evidence_mutation_is_failure_sensitive(evidence)

    def test_commit_requires_clean_exact_configured_physical_probe(self) -> None:
        probes = (
            _probe(
                mounted=True, mounted_source=MOUNT_SOURCE, mounted_fstype="fuse.ltfs"
            ),
            _probe(loaded=True),
            _probe(busy=True),
            _probe(configured_source="7" * 64),
            _probe(configured_fstype="xfs"),
        )
        for probe in probes:
            with self.subTest(probe=probe):
                decision = decide_recovery(
                    _input("committing", probe=probe, commit=_commit())
                )
                self.assertEqual(
                    RecoveryAction.ENTER_CRITICAL_QUARANTINE, decision.actions[0]
                )
                self.assertEqual(RecoveryReason.PHYSICAL_NOT_QUIESCENT, decision.reason)

    def test_commit_rejects_unmount_from_recovery_generation_not_original_attempt(
        self,
    ) -> None:
        identify = _command()
        recovery_unmount = _command(
            command_id="unmount-1",
            kind="unmount",
            generation=8,
            media=MEDIA_A,
            process=PROCESS_UNMOUNT,
            created_at=T7,
            quiesced_at=T8,
        )
        commands = (identify, recovery_unmount)
        lineage = _lineage(commands, command_ids=(identify.id,))
        evidence = CommitEvidence(
            "operation-4",
            7,
            _target(),
            MEDIA_A,
            recovery_unmount.id,
            MANIFEST,
            MANIFEST,
            T9,
        )

        decision = decide_recovery(
            _input(
                "committing",
                commands=commands,
                context=_context(commands, lineage=lineage),
                commit=evidence,
            )
        )

        self.assertEqual(RecoveryReason.COMMIT_EVIDENCE_INCOMPLETE, decision.reason)
        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE, decision.actions[0]
        )

    def test_recovery_generation_requires_authenticated_lineage(self) -> None:
        commands = _bound_commands()
        cases = (
            RecoveryContext(8, ()),
            _context(commands, lineage=_lineage(commands, original_generation=6)),
            _context(commands, lineage=_lineage(commands, command_ids=("identify-1",))),
            _context(commands, lineage=_lineage(commands, expected="7" * 64)),
            _context(
                commands,
                lineage=_lineage(commands, authenticated="7" * 64, expected="7" * 64),
            ),
            _context(commands, lineage=_lineage(commands, recorded_at=T4)),
        )
        for context in cases:
            with self.subTest(context=context):
                decision = decide_recovery(
                    _input(
                        "unloading",
                        commands=commands,
                        context=context,
                        probe=_probe(loaded=True),
                    )
                )
                self.assertFalse(decision.admission_open)
                self.assertIn(
                    decision.reason,
                    {RecoveryReason.LINEAGE_MISSING, RecoveryReason.LINEAGE_MISMATCH},
                )

    def test_same_generation_rejects_stale_command_generation_without_lineage(
        self,
    ) -> None:
        stale = _command(generation=6)
        decision = decide_recovery(
            _input(
                "identifying_media",
                operation=_operation("identifying_media", generation=7, binding=None),
                commands=(stale,),
                context=RecoveryContext(7, ()),
                probe=_probe(media=None, loaded=True),
            )
        )

        self.assertEqual(RecoveryReason.STALE_GENERATION, decision.reason)
        self.assertTrue(decision.operator_required)

    def test_media_binding_timestamp_allows_only_prebinding_identify_null(self) -> None:
        valid = _bound_commands()
        postbinding_null = _command(
            command_id="unmount-1",
            kind="unmount",
            media=None,
            process=PROCESS_UNMOUNT,
            created_at=T4,
            quiesced_at=T5,
        )
        cases = (
            ((valid[0], postbinding_null), _binding()),
            (valid, _binding(command_id="other-identify")),
        )
        for commands, binding in cases:
            with self.subTest(binding=binding):
                decision = decide_recovery(
                    _input(
                        "unloading",
                        operation=_operation("unloading", binding=binding),
                        commands=commands,
                        context=_context(commands),
                        probe=_probe(loaded=True),
                    )
                )
                self.assertEqual(RecoveryReason.MEDIA_BINDING_MISMATCH, decision.reason)
                self.assertTrue(decision.operator_required)

    def test_absent_binding_rejects_non_identify_null_command(self) -> None:
        command = _command(command_id="mount-1", kind="mount", media=None)
        decision = decide_recovery(
            _input(
                "identifying_media",
                operation=_operation("identifying_media", binding=None),
                commands=(command,),
                context=_context((command,)),
                probe=_probe(media=None, loaded=True),
            )
        )

        self.assertEqual(RecoveryReason.MEDIA_BINDING_MISMATCH, decision.reason)
        self.assertTrue(decision.operator_required)

    def test_phase_none_and_persisted_media_mismatch_fail_closed(self) -> None:
        cases = (
            (
                _operation(None, binding=_binding()),
                _probe(loaded=True),
                RecoveryAction.RETRY_CURRENT_CASSETTE,
            ),
            (
                _operation(None, binding=_binding()),
                _probe(
                    mounted=True,
                    mounted_source=MOUNT_SOURCE,
                    mounted_fstype="fuse.ltfs",
                ),
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            ),
            (
                _operation(None, binding=_binding()),
                _probe(busy=True),
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            ),
            (
                _operation(
                    None, binding=_binding(), error_code="media_target_mismatch"
                ),
                _probe(),
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            ),
            (
                _operation(None, binding=_binding()),
                _probe(media=MEDIA_B),
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
            ),
        )
        for operation, probe, expected_action in cases:
            with self.subTest(error=operation.error_code, probe=probe):
                decision = decide_recovery(
                    _input(None, operation=operation, probe=probe)
                )
                self.assertEqual(expected_action, decision.actions[0])
                self.assertEqual(
                    expected_action is RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                    decision.operator_required,
                )

    def test_admission_opens_only_for_exact_current_ordered_receipts(self) -> None:
        commands = _bound_commands()
        decision = decide_recovery(
            _input(
                "unloading",
                operation=_operation(
                    "unloading", state="cancelled", binding=_binding()
                ),
                commands=commands,
                receipts=_receipts(commands),
            )
        )
        self.assertEqual(RecoveryOutcome.RESOLVED, decision.outcome)
        self.assertEqual((RecoveryAction.OPEN_ADMISSION,), decision.actions)
        self.assertTrue(decision.admission_open)

    def test_receipt_mutations_each_keep_admission_closed(self) -> None:
        commands = _bound_commands()
        exact = _receipts(commands)
        stale_command = _command_receipt(commands, generation=7)
        wrong_evidence = _command_receipt(
            commands, evidence=tuple(reversed(exact.command.evidence))
        )
        wrong_physical = _physical_receipt(exact.command, target=_target("b"))
        stale_resolution = ResolutionReceipt(
            "resolution-8", "operation-4", 7, exact.command.id, exact.physical.id, T9
        )
        cases = (
            ReceiptChain(),
            ReceiptChain(stale_command, exact.physical, exact.resolution),
            ReceiptChain(wrong_evidence, exact.physical, exact.resolution),
            ReceiptChain(exact.command, wrong_physical, exact.resolution),
            ReceiptChain(exact.command, exact.physical, stale_resolution),
        )
        for receipts in cases:
            with self.subTest(receipts=receipts):
                decision = decide_recovery(
                    _input(
                        "unloading",
                        operation=_operation(
                            "unloading", state="cancelled", binding=_binding()
                        ),
                        commands=commands,
                        receipts=receipts,
                    )
                )
                self.assertFalse(decision.admission_open)
                self.assertEqual(RecoveryAction.HOLD_ADMISSION, decision.actions[-1])

    def test_postcommit_failures_remain_recovery_required(self) -> None:
        for code, reason, outcome, action, operator_required in (
            (
                "postcommit_backup_failed",
                RecoveryReason.POSTCOMMIT_BACKUP_FAILED,
                RecoveryOutcome.RECOVERY_REQUIRED,
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                True,
            ),
            (
                "unload_failed",
                RecoveryReason.POSTCOMMIT_UNLOAD_FAILED,
                RecoveryOutcome.RETRY,
                RecoveryAction.RETRY_UNLOAD,
                False,
            ),
        ):
            decision = decide_recovery(
                _input(
                    "unloading",
                    operation=_operation(
                        "unloading", binding=_binding(), error_code=code
                    ),
                    probe=_probe(loaded=True),
                )
            )
            self.assertEqual(outcome, decision.outcome)
            self.assertEqual(reason, decision.reason)
            self.assertEqual(action, decision.actions[0])
            self.assertEqual(operator_required, decision.operator_required)


class PublicCatalogModelTests(unittest.TestCase):
    def _assert_catalog_corruption_is_redacted_and_fail_closed(
        self, statement: str, value: str, source_read: str
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            _create_resolved_catalog(database)
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.connection.execute(statement, (value,))
                source = CatalogRecoveryStateSource(
                    catalog,
                    expected_mount_source_identity_sha256=MOUNT_SOURCE,
                    expected_mount_fstype="fuse.ltfs",
                )

                with self.assertRaises(RecoveryStateError) as caught:
                    getattr(source, source_read)("operation-4")

                decision = RecoveryManager(source, _FakeProbeSource()).inspect(
                    "operation-4"
                )

        self.assertEqual(RecoveryReason.DURABLE_EVIDENCE_MISSING, decision.reason)
        self.assertEqual(
            RecoveryAction.ENTER_CRITICAL_QUARANTINE, decision.actions[0]
        )
        self.assertEqual(RecoveryAction.HOLD_ADMISSION, decision.actions[-1])
        self.assertFalse(decision.admission_open)
        self.assertNotIn(value, str(caught.exception))
        self.assertNotIn(value, repr(decision))

    def test_catalog_source_redacts_malformed_resolution_timestamp(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE recovery_resolutions SET resolved_at=? "
            "WHERE operation_id='operation-4'",
            "private-invalid-resolution-time",
            "receipt_chain",
        )

    def test_catalog_source_redacts_malformed_command_receipt_timestamp(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE command_quiescence_receipts SET recorded_at=? "
            "WHERE operation_id='operation-4'",
            "private-invalid-receipt-time",
            "receipt_chain",
        )

    def test_catalog_source_redacts_malformed_physical_receipt_timestamp(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE physical_reconciliation_receipts SET recorded_at=? "
            "WHERE operation_id='operation-4'",
            "private-invalid-physical-time",
            "receipt_chain",
        )

    def test_catalog_source_redacts_malformed_lineage_timestamp(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE operation_recovery_lineages SET recorded_at=? "
            "WHERE operation_id='operation-4'",
            "private-invalid-lineage-time",
            "recovery_context",
        )

    def test_catalog_source_redacts_malformed_command_timestamp(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE hardware_command_executions SET created_at=? WHERE id='identify-1'",
            "private-invalid-command-time",
            "command_ledger",
        )

    def test_catalog_source_redacts_malformed_command_argument_digest(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE hardware_command_executions SET argv_sha256=? "
            "WHERE id='identify-1'",
            "private-invalid-command-identity",
            "command_ledger",
        )

    def test_catalog_source_redacts_malformed_command_process_identity(self) -> None:
        self._assert_catalog_corruption_is_redacted_and_fail_closed(
            "UPDATE hardware_command_executions SET pid=? WHERE id='identify-1'",
            "-4",
            "command_ledger",
        )

    def test_policy_consumes_public_catalog_hardware_command_model(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            _seed_resumable_job(catalog, Path(temporary))
            owner = catalog.claim_daemon_owner("daemon-1")
            record = OperationRecord(
                "operation-4",
                "archive.resume",
                "running",
                "identifying_media",
                "key",
                "admin",
                "job",
                4,
                T0,
                None,
            )
            admitted = catalog.admit_operation(
                record, owner, admission_open=True, hardware_target=_target()
            )
            fence = OperationFence(admitted.record.id, owner.generation)
            catalog.reserve_hardware_command(fence, "identify-1", "identify", "6" * 64)
            command = catalog.command("identify-1")

        self.assertIsInstance(command, HardwareCommandExecution)
        decision = decide_recovery(
            RecoveryInput(
                _operation(
                    "identifying_media", generation=owner.generation, binding=None
                ),
                RecoveryContext(owner.generation, ()),
                (command,),
                _probe(media=None, loaded=True),
                None,
                ReceiptChain(),
            )
        )
        self.assertEqual(RecoveryAction.RECONCILE_COMMANDS, decision.actions[0])

    def test_catalog_source_keeps_admission_closed_when_target_evidence_is_missing(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory() as temporary,
            Catalog(Path(temporary) / "catalog.db") as catalog,
        ):
            catalog.initialize()
            owner = catalog.claim_daemon_owner("daemon-1")
            catalog.admit_operation(
                OperationRecord(
                    "operation-4",
                    "catalog.cleanup",
                    "running",
                    None,
                    "key",
                    "admin",
                    "job",
                    4,
                    T0,
                    None,
                ),
                owner,
                admission_open=True,
            )
            source = CatalogRecoveryStateSource(
                catalog,
                expected_mount_source_identity_sha256=MOUNT_SOURCE,
                expected_mount_fstype="fuse.ltfs",
            )

            decision = RecoveryManager(source, _FakeProbeSource()).inspect(
                "operation-4"
            )

        self.assertEqual(RecoveryReason.DURABLE_EVIDENCE_MISSING, decision.reason)
        self.assertTrue(decision.operator_required)
        self.assertFalse(decision.admission_open)

    def test_catalog_restart_reconstructs_exact_generic_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize()
                _seed_resumable_job(catalog, Path(temporary))
                original = catalog.claim_daemon_owner("daemon-1")
                admitted = catalog.admit_operation(
                    OperationRecord(
                        "operation-4",
                        "archive.resume",
                        "running",
                        "identifying_media",
                        "key",
                        "admin",
                        "job",
                        4,
                        T0,
                        None,
                    ),
                    original,
                    admission_open=True,
                    hardware_target=_target(),
                )
                durable = catalog.get_operation(admitted.record.id)
                self.assertEqual(original.generation, durable["owner_generation"])

            with Catalog(database) as catalog:
                catalog.initialize()
                recovery = catalog.claim_daemon_owner("daemon-2")
                catalog.recover_interrupted_operations(recovery)
                command = catalog.create_command_quiescence_receipt(
                    "operation-4", recovery
                )
                physical = catalog.create_physical_reconciliation_receipt(
                    "operation-4",
                    recovery,
                    command.id,
                    VerifiedPhysicalQuiescence(
                        target=_target(),
                        observed_media_identity_sha256=None,
                        mounted=False,
                        media_loaded=False,
                        drive_busy=False,
                        related_processes=(),
                    ),
                )
                catalog.resolve_recovery(
                    "operation-4",
                    recovery,
                    SafeRecoveryResolution(
                        reason_code="empty-ledger-physically-reconciled",
                        command_receipt_id=command.id,
                        physical_receipt_id=physical.id,
                    ),
                )

            with Catalog(database) as catalog:
                catalog.initialize()
                source = CatalogRecoveryStateSource(
                    catalog,
                    expected_mount_source_identity_sha256=MOUNT_SOURCE,
                    expected_mount_fstype="fuse.ltfs",
                )
                decision = RecoveryManager(source, _FakeProbeSource()).inspect(
                    "operation-4"
                )

                schema = catalog.connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                self.assertEqual(str(SCHEMA_VERSION), schema["value"])
                self.assertEqual(RecoveryReason.RECOVERY_RESOLVED, decision.reason)
                self.assertTrue(decision.admission_open)


class _FakeRecoverySource:
    def __init__(self, operation: DurableOperation) -> None:
        self.value = operation
        self.calls: list[str] = []

    def operation(self, operation_id: str) -> DurableOperation:
        self.calls.append(f"operation:{operation_id}")
        return self.value

    def recovery_context(self, operation_id: str) -> RecoveryContext:
        self.calls.append(f"context:{operation_id}")
        return RecoveryContext(7, ())

    def command_ledger(self, operation_id: str) -> tuple[HardwareCommandExecution, ...]:
        self.calls.append(f"commands:{operation_id}")
        return ()

    def commit_evidence(self, operation_id: str) -> CommitEvidence | None:
        self.calls.append(f"commit:{operation_id}")
        return None

    def receipt_chain(self, operation_id: str) -> ReceiptChain:
        self.calls.append(f"receipts:{operation_id}")
        return ReceiptChain()


class _FakeProbeSource:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def inspect(self, operation: DurableOperation) -> AggregateRecoveryProbe:
        self.calls.append(operation.operation_id)
        return _probe(media=operation.observed_media_identity_sha256)


class RecoveryManagerBoundaryTests(unittest.TestCase):
    def test_never_reads_or_requests_cassettes_one_through_three(self) -> None:
        for sequence in (1, 2, 3):
            source = _FakeRecoverySource(
                _operation("identifying_media", sequence=sequence, binding=None)
            )
            probe = _FakeProbeSource()
            decision = RecoveryManager(source, probe).inspect("operation-4")
            self.assertEqual(
                RecoveryReason.HISTORICAL_MEDIA_PROHIBITED, decision.reason
            )
            self.assertEqual(["operation:operation-4"], source.calls)
            self.assertEqual([], probe.calls)


if __name__ == "__main__":
    unittest.main()
