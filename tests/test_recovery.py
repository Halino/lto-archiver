from __future__ import annotations

import unittest
from dataclasses import replace

from ltobackup.daemon.recovery import (
    ReceiptChain,
    RecoveryAction,
    RecoveryContext,
    RecoveryReason,
    ResolutionReceipt,
    decide_recovery,
)
from tests.test_archive_recovery import (
    MEDIA_A,
    MEDIA_B,
    T9,
    _binding,
    _bound_commands,
    _commit,
    _context,
    _input,
    _operation,
    _physical_receipt,
    _probe,
    _receipts,
    _target,
)


class AutomaticRecoveryPolicyTests(unittest.TestCase):
    def test_native_first_cassette_is_not_misclassified_as_historical_media(self):
        decision = decide_recovery(
            _input(
                "writing",
                operation=_operation(
                    "writing",
                    sequence=1,
                    binding=_binding(),
                    kind="archive.native",
                ),
            )
        )

        self.assertEqual(
            (
                RecoveryAction.RETRY_CURRENT_CASSETTE,
                RecoveryAction.HOLD_ADMISSION,
            ),
            decision.actions,
        )

    def test_safe_interrupted_boundaries_choose_automatic_actions(self) -> None:
        commands = _bound_commands()
        cases = (
            (
                "waiting for expected media",
                _input(
                    None,
                    operation=_operation(None, binding=None),
                    commands=(),
                    context=RecoveryContext(7, ()),
                    probe=_probe(media=None),
                ),
                RecoveryAction.WAIT_FOR_MEDIA,
                RecoveryReason.WAITING_MEDIA_RETRY_SAFE,
            ),
            (
                "identification retry",
                _input(
                    "identifying_media",
                    operation=_operation("identifying_media", binding=None),
                    commands=(),
                    context=RecoveryContext(7, ()),
                    probe=_probe(media=None, loaded=True),
                ),
                RecoveryAction.RETRY_IDENTIFICATION,
                RecoveryReason.IDENTIFICATION_RETRY_SAFE,
            ),
            (
                "commit reconciliation",
                _input("committing", commit=_commit()),
                RecoveryAction.RECONCILE_COMMIT,
                RecoveryReason.COMMIT_EVIDENCE_EXACT,
            ),
            (
                "unload retry",
                _input("unloading", probe=_probe(loaded=True)),
                RecoveryAction.RETRY_UNLOAD,
                RecoveryReason.UNLOAD_IDENTITY_EXACT,
            ),
            (
                "new cassette checkpoint retry",
                _input("formatting_media"),
                RecoveryAction.RETRY_CURRENT_CASSETTE,
                RecoveryReason.CASSETTE_CHECKPOINT_RETRY_SAFE,
            ),
            (
                "append checkpoint retry",
                _input("writing"),
                RecoveryAction.RETRY_CURRENT_CASSETTE,
                RecoveryReason.CASSETTE_CHECKPOINT_RETRY_SAFE,
            ),
        )
        for name, snapshot, expected_action, expected_reason in cases:
            with self.subTest(name=name):
                decision = decide_recovery(snapshot)
                self.assertEqual(
                    (expected_action, RecoveryAction.HOLD_ADMISSION),
                    decision.actions,
                )
                self.assertEqual(expected_reason, decision.reason)
                self.assertFalse(decision.operator_required)

    def test_proof_contradictions_enter_critical_quarantine(self) -> None:
        commands = _bound_commands()
        receipts = _receipts(commands)
        wrong_physical = _physical_receipt(receipts.command, target=_target("b"))
        wrong_resolution = ResolutionReceipt(
            "resolution-8",
            "operation-4",
            7,
            receipts.command.id,
            receipts.physical.id,
            T9,
        )
        cases = (
            (
                "lineage mismatch",
                _input("unloading", context=RecoveryContext(8, ())),
                RecoveryReason.LINEAGE_MISSING,
            ),
            (
                "media identity mismatch",
                _input("unloading", probe=_probe(media=MEDIA_B, loaded=True)),
                RecoveryReason.MEDIA_IDENTITY_MISMATCH,
            ),
            (
                "target mismatch",
                _input("unloading", probe=_probe(target=_target("b"), loaded=True)),
                RecoveryReason.TARGET_MISMATCH,
            ),
            (
                "ownership cannot be proved",
                _input("unloading", probe=_probe(loaded=True, busy=True)),
                RecoveryReason.UNLOAD_NOT_RETRYABLE,
            ),
            (
                "commit proof mismatch",
                _input(
                    "committing",
                    commit=replace(_commit(), provisional_manifest_sha256="7" * 64),
                ),
                RecoveryReason.COMMIT_EVIDENCE_INCOMPLETE,
            ),
            (
                "physical receipt mismatch",
                _input(
                    "unloading",
                    operation=_operation(
                        "unloading", state="cancelled", binding=_binding()
                    ),
                    commands=commands,
                    receipts=ReceiptChain(
                        receipts.command,
                        wrong_physical,
                        receipts.resolution,
                    ),
                ),
                RecoveryReason.RECEIPT_CHAIN_MISMATCH,
            ),
            (
                "receipt generation mismatch",
                _input(
                    "unloading",
                    operation=_operation(
                        "unloading", state="cancelled", binding=_binding()
                    ),
                    commands=commands,
                    receipts=ReceiptChain(
                        receipts.command,
                        receipts.physical,
                        wrong_resolution,
                    ),
                ),
                RecoveryReason.RECEIPT_CHAIN_MISMATCH,
            ),
        )
        for name, snapshot, expected_reason in cases:
            with self.subTest(name=name):
                decision = decide_recovery(snapshot)
                self.assertEqual(
                    (
                        RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                        RecoveryAction.HOLD_ADMISSION,
                    ),
                    decision.actions,
                )
                self.assertEqual(expected_reason, decision.reason)
                self.assertTrue(decision.operator_required)

    def test_wrong_unbound_media_waits_without_consuming_a_retry(self) -> None:
        decision = decide_recovery(
            _input(
                None,
                operation=_operation(None, binding=None),
                commands=(),
                context=RecoveryContext(7, ()),
                probe=_probe(media=MEDIA_A, loaded=True),
            )
        )

        self.assertEqual(
            (RecoveryAction.WAIT_FOR_MEDIA, RecoveryAction.HOLD_ADMISSION),
            decision.actions,
        )
        self.assertFalse(decision.operator_required)

    def test_absent_bound_media_waits_at_every_interrupted_checkpoint(self) -> None:
        for phase in (
            None,
            "formatting_media",
            "mounting",
            "writing",
            "writing_manifest",
            "finalizing_index",
            "unmounting",
        ):
            with self.subTest(phase=phase):
                decision = decide_recovery(
                    _input(
                        phase,
                        operation=_operation(phase, binding=_binding()),
                        probe=_probe(media=None, loaded=False),
                    )
                )

                self.assertEqual(
                    (RecoveryAction.WAIT_FOR_MEDIA, RecoveryAction.HOLD_ADMISSION),
                    decision.actions,
                )
                self.assertEqual(
                    RecoveryReason.WAITING_MEDIA_RETRY_SAFE, decision.reason
                )
                self.assertFalse(decision.operator_required)

    def test_loaded_bound_media_identity_contradiction_remains_critical(self) -> None:
        decision = decide_recovery(
            _input(
                "writing",
                operation=_operation("writing", binding=_binding()),
                probe=_probe(media=MEDIA_B, loaded=True),
            )
        )

        self.assertEqual(
            (
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                RecoveryAction.HOLD_ADMISSION,
            ),
            decision.actions,
        )
        self.assertEqual(RecoveryReason.MEDIA_IDENTITY_MISMATCH, decision.reason)

    def test_absent_bound_media_does_not_mask_exact_commit_reconciliation(
        self,
    ) -> None:
        decision = decide_recovery(
            _input(
                "committing",
                operation=_operation("committing", binding=_binding()),
                probe=_probe(media=None, loaded=False),
                commit=_commit(),
            )
        )

        self.assertEqual(
            (RecoveryAction.RECONCILE_COMMIT, RecoveryAction.HOLD_ADMISSION),
            decision.actions,
        )
        self.assertEqual(RecoveryReason.COMMIT_EVIDENCE_EXACT, decision.reason)
        self.assertFalse(decision.operator_required)

    def test_absent_bound_media_does_not_mask_unloading_proof_states(self) -> None:
        for error_code, expected_reason in (
            (None, RecoveryReason.UNLOAD_NOT_RETRYABLE),
            ("unload_failed", RecoveryReason.POSTCOMMIT_UNLOAD_FAILED),
        ):
            with self.subTest(error_code=error_code):
                decision = decide_recovery(
                    _input(
                        "unloading",
                        operation=_operation(
                            "unloading",
                            binding=_binding(),
                            error_code=error_code,
                        ),
                        probe=_probe(media=None, loaded=False),
                    )
                )

                self.assertEqual(
                    (
                        RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                        RecoveryAction.HOLD_ADMISSION,
                    ),
                    decision.actions,
                )
                self.assertEqual(expected_reason, decision.reason)
                self.assertTrue(decision.operator_required)

    def test_absent_media_does_not_mask_persisted_postcommit_failure(self) -> None:
        decision = decide_recovery(
            _input(
                "unloading",
                operation=_operation(
                    "unloading",
                    binding=_binding(),
                    error_code="postcommit_backup_failed",
                ),
                probe=_probe(media=None, loaded=False),
            )
        )

        self.assertEqual(
            (
                RecoveryAction.ENTER_CRITICAL_QUARANTINE,
                RecoveryAction.HOLD_ADMISSION,
            ),
            decision.actions,
        )
        self.assertEqual(RecoveryReason.POSTCOMMIT_BACKUP_FAILED, decision.reason)


if __name__ == "__main__":
    unittest.main()
