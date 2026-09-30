from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import threading
import time
import unittest
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.models import (
    HardwareTargetBinding,
    MutationAdmissionClosed,
    OperationConflict,
    OperationFence,
    OperationRecord,
    SafeRecoveryResolution,
    StaleOperationFence,
    VerifiedPhysicalQuiescence,
)
from ltobackup.daemon.operations import OperationContext, OperationManager
from ltobackup.errors import CatalogError


class _BlockingCallback:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release_event = threading.Event()

    def __call__(self, _context: OperationContext) -> None:
        self.started.set()
        if not self.release_event.wait(2):
            raise TimeoutError("test callback was not released")

    def wait_until_started(self) -> None:
        if not self.started.wait(1):
            raise AssertionError("callback did not start")

    def release(self) -> None:
        self.release_event.set()


class _BlockingLateCatalogWrite:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.started = threading.Event()
        self.release_event = threading.Event()
        self.finished = threading.Event()
        self.caught: BaseException | None = None

    def __call__(self, context: OperationContext) -> None:
        self.started.set()
        if not self.release_event.wait(2):
            raise TimeoutError("test callback was not released")
        try:
            with Catalog(self.database_path) as catalog:
                catalog.record_phase_sample(
                    context.fence,
                    "writing_manifest",
                    "2026-08-21T12:00:01+00:00",
                    0.25,
                )
        except BaseException as exc:
            self.caught = exc
        finally:
            self.finished.set()

    def wait_until_blocked(self) -> None:
        if not self.started.wait(1):
            raise AssertionError("callback did not reach the fence")

    def release(self) -> None:
        self.release_event.set()

    def result(self, timeout: float) -> BaseException | None:
        if not self.finished.wait(timeout):
            raise AssertionError("callback did not finish")
        return self.caught


class _RejectingExecutor(Executor):
    def submit(self, fn, /, *args, **kwargs):
        raise RuntimeError("executor is shutting down")


class _HoldingExecutor(Executor):
    def __init__(self) -> None:
        self.submissions: list[tuple[object, tuple[object, ...], dict, Future]] = []

    def submit(self, fn, /, *args, **kwargs):
        future = Future()
        self.submissions.append((fn, args, kwargs, future))
        return future


class _InlineExecutor(Executor):
    def submit(self, fn, /, *args, **kwargs):
        future: Future[None] = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as error:
            future.set_exception(error)
        return future


class _ContinuationInsertRaceCatalog(Catalog):
    """Expose a committed continuation only after an operation insert loses."""

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self.operation_lookup_count = 0
        self._missed_existing = False

    def _find_operation_by_key_tx(self, db, idempotency_key):
        self.operation_lookup_count += 1
        row = super()._find_operation_by_key_tx(db, idempotency_key)
        if row is not None and not self._missed_existing:
            self._missed_existing = True
            return None
        return row


class _ContinuationRaceCatalogFactory:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.instances: list[_ContinuationInsertRaceCatalog] = []

    def __call__(self) -> Catalog:
        catalog = _ContinuationInsertRaceCatalog(self.database_path)
        self.instances.append(catalog)
        return catalog


class _CallbackProbe:
    def __init__(self) -> None:
        self.called = threading.Event()
        self._lock = threading.Lock()
        self.call_count = 0

    def __call__(self, _context: OperationContext) -> None:
        with self._lock:
            self.call_count += 1
        self.called.set()


class OperationManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database_path = Path(self.temporary.name) / "catalog.db"
        with Catalog(self.database_path) as catalog:
            catalog.initialize()
            self.daemon_fence = catalog.claim_daemon_owner("daemon-1")
        self.executors: dict[int, ThreadPoolExecutor] = {}
        self.unexpected = _CallbackProbe()

    def manager(self, daemon_fence=None) -> OperationManager:
        executor = ThreadPoolExecutor(max_workers=1)
        manager = OperationManager(
            lambda: Catalog(self.database_path),
            daemon_fence or self.daemon_fence,
            executor=executor,
        )
        self.executors[id(manager)] = executor
        self.addCleanup(executor.shutdown, wait=True, cancel_futures=True)
        return manager

    def drain(self, manager: OperationManager) -> None:
        self.executors[id(manager)].submit(lambda: None).result(timeout=1)

    def test_restore_cassette_requires_atomic_candidate_snapshot(self) -> None:
        manager = self.manager()

        with self.assertRaisesRegex(ValueError, "candidate snapshot is required"):
            manager.start(
                "restore.cassette",
                "restore-without-snapshot",
                "restore-coordinator",
                self.unexpected,
                job_id="RESTORE-RUN-1",
                cassette_sequence=1,
            )

        self.assertEqual(0, self.unexpected.call_count)

    def test_admission_hook_runs_before_inline_worker_callback(self) -> None:
        """Service progress scope must exist before a worker can publish telemetry."""

        order: list[tuple[str, str]] = []
        manager = OperationManager(
            lambda: Catalog(self.database_path),
            self.daemon_fence,
            executor=_InlineExecutor(),
        )
        try:
            record = manager.start(
                "diagnostic",
                "admission-hook-order",
                "admin",
                lambda context: order.append(("callback", context.record.id)),
                on_admitted=lambda admitted: order.append(("admitted", admitted.id)),
            )
        except TypeError as error:
            self.fail(f"operation admission hook is unavailable: {error}")

        self.assertEqual(
            [("admitted", record.id), ("callback", record.id)],
            order,
        )

    def continuation_inputs(
        self,
    ) -> tuple[str, HardwareTargetBinding, str, str]:
        job_id = "AUTO-CONTINUATION"
        source = Path(self.temporary.name) / "source-continuation"
        source.mkdir()
        with Catalog(self.database_path) as catalog:
            catalog.add_library("LIB-CONTINUATION", job_id, str(source))
            catalog.create_automatic_job(
                job_id,
                "LIB-CONTINUATION",
                "drive-continuation",
                "/synthetic/continuation",
                [("CT0001", "SERIAL-CONTINUATION", 1, 7)],
                force_format=True,
            )
            fingerprint = str(
                catalog.latest_layout_epoch(job_id)[
                    "layout_fingerprint_sha256"
                ]
            )
            authorization_id = catalog.authorize_automatic_format_sequence(
                job_id,
                expected_revision=0,
                layout_fingerprint_sha256=fingerprint,
                actor="admin-1",
                idempotency_key="authorize-continuation",
                authorized_at="2026-08-31T18:00:00+00:00",
            )[0]
            catalog.set_automatic_sequence_enabled(
                job_id,
                expected_revision=1,
                layout_fingerprint_sha256=fingerprint,
                actor="admin-1",
                enabled_at="2026-08-31T18:01:00+00:00",
            )
            catalog.update_automatic_job(
                job_id, "waiting_media", current_sequence=1
            )
            catalog.update_automatic_cassette(job_id, 1, "waiting_media")
        key = hashlib.sha256(
            f"{job_id}\0{fingerprint}\0{1}\0{self.daemon_fence.generation}".encode(
                "utf-8"
            )
        ).hexdigest()
        target = HardwareTargetBinding.from_verified_inputs(
            Path(self.temporary.name) / "mount-continuation",
            "tape-continuation",
            "scsi-continuation",
            ("archive.native", job_id, "1", "CT0001", "", ""),
        )
        return key, target, authorization_id, fingerprint

    @staticmethod
    def continuation_audit_count() -> str:
        return (
            "SELECT COUNT(*) FROM audit_entries WHERE action IN "
            "('automatic.sequence.continuation.admitted',"
            "'automatic.sequence.continuation.replayed')"
        )

    def start_continuation(
        self,
        manager: OperationManager,
        key: str,
        target: HardwareTargetBinding,
        authorization_id: str,
        fingerprint: str,
        callback,
        *,
        job_id: str = "AUTO-CONTINUATION",
        cassette_sequence: int = 1,
        principal: str = "sequence-coordinator",
    ) -> OperationRecord:
        return manager.start(
            "archive.native",
            key,
            principal,
            callback,
            job_id=job_id,
            cassette_sequence=cassette_sequence,
            hardware_target=target,
            sequence_authorization_id=authorization_id,
            sequence_layout_fingerprint_sha256=fingerprint,
        )

    def test_continuation_insert_race_replays_winner_without_second_worker(
        self,
    ) -> None:
        key, target, authorization_id, fingerprint = self.continuation_inputs()
        factory = _ContinuationRaceCatalogFactory(self.database_path)
        executor = _HoldingExecutor()
        manager = OperationManager(factory, self.daemon_fence, executor=executor)
        winning_callback = _CallbackProbe()
        losing_callback = _CallbackProbe()

        winner = self.start_continuation(
            manager,
            key,
            target,
            authorization_id,
            fingerprint,
            winning_callback,
        )
        with Catalog(self.database_path) as catalog:
            catalog.finish_operation(
                OperationFence(winner.id, self.daemon_fence.generation),
                "succeeded",
            )
        replayed = self.start_continuation(
            manager,
            key,
            target,
            authorization_id,
            fingerprint,
            losing_callback,
        )

        self.assertEqual(winner.id, replayed.id)
        self.assertEqual(1, len(executor.submissions))
        self.assertEqual(0, losing_callback.call_count)
        self.assertEqual(2, factory.instances[-1].operation_lookup_count)
        with Catalog(self.database_path) as catalog:
            actions = tuple(
                row[0]
                for row in catalog.connection.execute(
                    "SELECT action FROM audit_entries WHERE action IN "
                    "('automatic.sequence.continuation.admitted',"
                    "'automatic.sequence.continuation.replayed') ORDER BY id"
                )
            )
        self.assertEqual(
            (
                "automatic.sequence.continuation.admitted",
                "automatic.sequence.continuation.replayed",
            ),
            actions,
        )

    def test_orphan_continuation_reservation_rejects_public_replay_and_admission(
        self,
    ) -> None:
        key, target, authorization_id, fingerprint = self.continuation_inputs()
        manager = self.manager()
        self.start_continuation(
            manager,
            key,
            target,
            authorization_id,
            fingerprint,
            _CallbackProbe(),
        )
        self.drain(manager)
        with Catalog(self.database_path) as catalog:
            catalog.connection.execute("PRAGMA foreign_keys=OFF")
            catalog.connection.execute(
                "DELETE FROM daemon_operations WHERE idempotency_key=?", (key,)
            )
            catalog.connection.commit()
            catalog.connection.execute("PRAGMA foreign_keys=ON")
            before_audits = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries"
            ).fetchone()[0]
        public_callback = _CallbackProbe()

        with self.assertRaisesRegex(CatalogError, "^idempotency_conflict$"):
            manager.replay(key)
        with self.assertRaisesRegex(CatalogError, "^idempotency_conflict$"):
            manager.start("diagnostic", key, "admin", public_callback)

        self.drain(manager)
        self.assertEqual(0, public_callback.call_count)
        with Catalog(self.database_path) as catalog:
            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM operation_sequence_continuations"
                ).fetchone()[0],
            )
            self.assertEqual(
                0,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations"
                ).fetchone()[0],
            )
            audit_entries = catalog.connection.execute(
                "SELECT COUNT(*) FROM audit_entries"
            ).fetchone()[0]
            self.assertEqual(before_audits, audit_entries)

    def test_continuation_insert_race_mismatches_submit_no_losing_worker(
        self,
    ) -> None:
        key, target, authorization_id, fingerprint = self.continuation_inputs()
        factory = _ContinuationRaceCatalogFactory(self.database_path)
        executor = _HoldingExecutor()
        manager = OperationManager(factory, self.daemon_fence, executor=executor)
        winner = self.start_continuation(
            manager,
            key,
            target,
            authorization_id,
            fingerprint,
            _CallbackProbe(),
        )
        with Catalog(self.database_path) as catalog:
            catalog.finish_operation(
                OperationFence(winner.id, self.daemon_fence.generation),
                "succeeded",
            )
            before_audits = catalog.connection.execute(
                self.continuation_audit_count()
            ).fetchone()[0]
        different_target = HardwareTargetBinding.from_verified_inputs(
            Path(self.temporary.name) / "different-mount",
            "different-tape",
            "different-scsi",
            (
                "archive.native",
                "AUTO-CONTINUATION",
                "1",
                "CT0001",
                "",
                "",
            ),
        )
        attempts = (
            (
                "candidate",
                target,
                authorization_id,
                "different-principal",
            ),
            ("target", different_target, authorization_id, "sequence-coordinator"),
            ("authority", target, "AUTH-MISMATCH", "sequence-coordinator"),
        )

        for mismatch, attempted_target, attempted_authority, principal in attempts:
            with self.subTest(mismatch=mismatch):
                losing_callback = _CallbackProbe()
                with self.assertRaisesRegex(CatalogError, "idempotency_conflict"):
                    self.start_continuation(
                        manager,
                        key,
                        attempted_target,
                        attempted_authority,
                        fingerprint,
                        losing_callback,
                        principal=principal,
                    )
                self.assertEqual(1, len(executor.submissions))
                self.assertEqual(0, losing_callback.call_count)
                self.assertEqual(2, factory.instances[-1].operation_lookup_count)
                with Catalog(self.database_path) as catalog:
                    self.assertEqual(
                        before_audits,
                        catalog.connection.execute(
                            self.continuation_audit_count()
                        ).fetchone()[0],
                    )

    def test_continuation_insert_race_replay_audit_failure_submits_no_callback(
        self,
    ) -> None:
        key, target, authorization_id, fingerprint = self.continuation_inputs()
        factory = _ContinuationRaceCatalogFactory(self.database_path)
        executor = _HoldingExecutor()
        manager = OperationManager(factory, self.daemon_fence, executor=executor)
        winner = self.start_continuation(
            manager,
            key,
            target,
            authorization_id,
            fingerprint,
            _CallbackProbe(),
        )
        with Catalog(self.database_path) as catalog:
            catalog.finish_operation(
                OperationFence(winner.id, self.daemon_fence.generation),
                "succeeded",
            )
            before_audits = catalog.connection.execute(
                self.continuation_audit_count()
            ).fetchone()[0]
        original_audit = Catalog._record_audit_tx
        replay_calls = 0

        def fail_race_replay(*args, **kwargs):
            nonlocal replay_calls
            if args[2] == "automatic.sequence.continuation.replayed":
                replay_calls += 1
                raise sqlite3.IntegrityError("forced race replay audit failure")
            return original_audit(*args, **kwargs)

        losing_callback = _CallbackProbe()
        with (
            patch.object(Catalog, "_record_audit_tx", side_effect=fail_race_replay),
            self.assertRaisesRegex(sqlite3.IntegrityError, "forced race replay"),
        ):
            self.start_continuation(
                manager,
                key,
                target,
                authorization_id,
                fingerprint,
                losing_callback,
            )

        self.assertEqual(1, replay_calls)
        self.assertEqual(1, len(executor.submissions))
        self.assertEqual(0, losing_callback.call_count)
        self.assertEqual(2, factory.instances[-1].operation_lookup_count)
        with Catalog(self.database_path) as catalog:
            self.assertEqual(
                before_audits,
                catalog.connection.execute(
                    self.continuation_audit_count()
                ).fetchone()[0],
            )

    def test_callback_recovery_required_is_not_overwritten_as_succeeded(self) -> None:
        manager = self.manager()

        def require_recovery(context: OperationContext) -> None:
            with Catalog(self.database_path) as catalog:
                catalog.finish_operation(
                    context.fence,
                    "recovery_required",
                    error_class="operator_required",
                    error_code="recovery_required",
                )

        record = manager.start(
            "archive.resume", "needs-recovery", "admin", require_recovery
        )
        self.drain(manager)

        self.assertEqual("recovery_required", manager.operation(record.id).state)

    def test_terminal_operation_with_launch_reserved_command_becomes_recovery_blocker(
        self,
    ) -> None:
        target = HardwareTargetBinding.from_verified_inputs(
            Path(self.temporary.name) / "mount",
            "tape-stable",
            "scsi-stable",
            ("archive.resume", "job-1", "1", "MEDIA-1", "", ""),
        )
        candidate = OperationRecord(
            id="terminal-command",
            kind="archive.resume",
            state="running",
            phase=None,
            idempotency_key="terminal-command-key",
            principal="admin",
            job_id="job-1",
            cassette_sequence=1,
            started_at="2026-08-21T12:00:00+00:00",
            finished_at=None,
        )
        with Catalog(self.database_path) as catalog:
            catalog.add_library("LIB1", "Library", self.temporary.name)
            catalog.create_automatic_job(
                "job-1",
                "LIB1",
                "TAPE0",
                "AUTO",
                [("MEDIA-1", "MEDIA-1", 1, 1)],
                force_format=True,
            )
            admission = catalog.admit_operation(
                candidate,
                self.daemon_fence,
                admission_open=True,
                hardware_target=target,
            )
            fence = OperationFence(admission.record.id, self.daemon_fence.generation)
            catalog.reserve_hardware_command(
                fence, "command-terminal", "mount", "a" * 64
            )
            catalog.finish_operation(fence, "cancelled")

        manager = self.manager()
        blockers = manager.reconcile_admission_blockers()

        self.assertEqual(("terminal-command",), tuple(record.id for record in blockers))
        self.assertEqual("recovery_required", blockers[0].state)
        with Catalog(self.database_path) as catalog:
            self.assertEqual(
                "recovery_required", catalog.get_operation("terminal-command")["state"]
            )

    def test_second_operation_conflicts_and_same_key_replays(self) -> None:
        manager = self.manager()
        callback = _BlockingCallback()
        first = manager.start("archive.resume", "same", "admin", callback)
        callback.wait_until_started()

        self.assertEqual(
            first,
            manager.start("archive.resume", "same", "admin", self.unexpected),
        )
        with self.assertRaises(OperationConflict) as caught:
            manager.start("restore.run", "other", "admin", self.unexpected)
        self.assertEqual(first.id, caught.exception.active.id)
        self.assertEqual(first, manager.replay("same"))
        self.assertIsNone(manager.replay("missing"))
        self.assertIsNone(manager.operation("missing"))
        callback.release()
        self.drain(manager)
        self.assertEqual(0, self.unexpected.call_count)
        self.assertFalse(self.unexpected.called.is_set())

    def test_worker_phase_and_completion_use_the_admitted_fence(self) -> None:
        manager = self.manager()
        sampled = threading.Event()
        release = threading.Event()

        def callback(context: OperationContext) -> None:
            context.record_phase_sample(
                "writing_manifest",
                "2026-08-21T12:00:01+00:00",
                0.25,
            )
            sampled.set()
            if not release.wait(2):
                raise TimeoutError("test callback was not released")

        operation = manager.start("catalog.test", "phase", "admin", callback)
        self.assertTrue(sampled.wait(1))
        self.assertEqual("writing_manifest", manager.operation(operation.id).phase)
        release.set()

        deadline = time.monotonic() + 2
        while manager.operation(operation.id).state == "running":
            if time.monotonic() >= deadline:
                self.fail("operation did not complete")
            time.sleep(0.01)
        self.assertEqual("succeeded", manager.operation(operation.id).state)

    def test_two_managers_resolve_same_and_different_key_races_atomically(self) -> None:
        for keys, expected in (
            (("same", "same"), "replay"),
            (("left", "right"), "conflict"),
        ):
            with self.subTest(expected=expected):
                with Catalog(self.database_path) as catalog:
                    catalog.connection.execute("DELETE FROM daemon_operations")
                    catalog.connection.commit()

                managers = (self.manager(), self.manager())
                callbacks = (_BlockingCallback(), _BlockingCallback())
                barrier = threading.Barrier(3)
                results: list[OperationRecord | BaseException | None] = [None, None]

                def race(index: int) -> None:
                    barrier.wait()
                    try:
                        results[index] = managers[index].start(
                            "catalog.test", keys[index], "admin", callbacks[index]
                        )
                    except BaseException as exc:
                        results[index] = exc

                threads = [
                    threading.Thread(target=race, args=(index,)) for index in range(2)
                ]
                for thread in threads:
                    thread.start()
                barrier.wait()
                for thread in threads:
                    thread.join(2)
                    self.assertFalse(thread.is_alive())
                deadline = time.monotonic() + 1
                while not any(callback.started.is_set() for callback in callbacks):
                    if time.monotonic() >= deadline:
                        self.fail("winning callback did not start")
                    time.sleep(0.01)
                with Catalog(self.database_path) as catalog:
                    active_count = catalog.connection.execute(
                        "SELECT COUNT(*) FROM daemon_operations WHERE state='running'"
                    ).fetchone()[0]
                self.assertEqual(1, active_count)
                self.assertEqual(
                    1, sum(callback.started.is_set() for callback in callbacks)
                )
                if expected == "replay":
                    records = [
                        result
                        for result in results
                        if isinstance(result, OperationRecord)
                    ]
                    self.assertEqual(1, len({record.id for record in records}))
                else:
                    conflicts = sum(
                        isinstance(result, OperationConflict) for result in results
                    )
                    self.assertEqual(1, conflicts)
                for callback in callbacks:
                    callback.release()
                for manager in managers:
                    self.drain(manager)
                self.assertEqual(
                    1, sum(callback.started.is_set() for callback in callbacks)
                )

    def test_restart_marks_running_operation_recovery_required(self) -> None:
        manager = self.manager()
        blocking = _BlockingCallback()
        operation = manager.start("catalog.test", "old-key", "admin", blocking)
        blocking.wait_until_started()
        with Catalog(self.database_path) as catalog:
            restarted_fence = catalog.claim_daemon_owner("daemon-2")
        restarted = self.manager(restarted_fence)

        records = restarted.recover_interrupted()

        self.assertEqual((operation.id,), tuple(record.id for record in records))
        self.assertEqual("recovery_required", records[0].state)
        blocking.release()

    def test_repeated_recovery_does_not_take_over_current_generation(self) -> None:
        manager = self.manager()
        blocking = _BlockingCallback()
        operation = manager.start("catalog.test", "current-key", "admin", blocking)
        blocking.wait_until_started()

        recovered = manager.recover_interrupted()

        self.assertEqual((), recovered)
        self.assertEqual("running", manager.operation(operation.id).state)
        blocking.release()
        self.drain(manager)
        self.assertEqual("succeeded", manager.operation(operation.id).state)

    def test_closed_admission_replays_same_key_but_rejects_new_key(self) -> None:
        manager = self.manager()
        callback = _BlockingCallback()
        first = manager.start("archive.resume", "same", "admin", callback)
        callback.wait_until_started()
        manager.stop_accepting()

        self.assertEqual(
            first,
            manager.start("archive.resume", "same", "admin", self.unexpected),
        )
        with self.assertRaises(MutationAdmissionClosed):
            manager.start("restore.run", "new", "admin", self.unexpected)
        callback.release()
        self.drain(manager)
        self.assertEqual(0, self.unexpected.call_count)

    def test_executor_rejection_does_not_leave_a_running_blocker(self) -> None:
        manager = OperationManager(
            lambda: Catalog(self.database_path),
            self.daemon_fence,
            executor=_RejectingExecutor(),
        )

        with self.assertRaisesRegex(RuntimeError, "executor is shutting down"):
            manager.start("catalog.test", "rejected", "admin", self.unexpected)

        self.assertEqual("failed", manager.replay("rejected").state)
        self.assertEqual(0, self.unexpected.call_count)

    def test_recovery_required_row_remains_the_durable_admission_blocker(self) -> None:
        manager = self.manager()
        callback = _BlockingCallback()
        operation = manager.start("catalog.test", "old-key", "admin", callback)
        callback.wait_until_started()
        manager.mark_unfinished_recovery_required(timeout_seconds=0)
        with Catalog(self.database_path) as catalog:
            restarted_fence = catalog.claim_daemon_owner("daemon-2")
        restarted = self.manager(restarted_fence)
        restarted.start_accepting()

        with self.assertRaises(OperationConflict) as caught:
            restarted.start("restore.run", "new-key", "admin", self.unexpected)
        self.assertEqual(operation.id, caught.exception.active.id)
        self.assertEqual("recovery_required", caught.exception.active.state)
        callback.release()

    def test_late_callback_after_shutdown_timeout_is_fenced_before_write(self) -> None:
        callback = _BlockingLateCatalogWrite(self.database_path)
        old = self.manager()
        operation = old.start("archive.resume", "old-key", "admin", callback)
        callback.wait_until_blocked()
        old.stop_accepting()
        old.mark_unfinished_recovery_required(timeout_seconds=0.01)

        with Catalog(self.database_path) as catalog:
            restarted_fence = catalog.claim_daemon_owner("daemon-2")
        restarted = self.manager(restarted_fence)
        restarted.recover_interrupted()
        restarted.start_accepting()
        with self.assertRaises(OperationConflict):
            restarted.start("restore.run", "new-key", "admin", self.unexpected)
        self.drain(restarted)
        self.assertEqual(0, self.unexpected.call_count)

        with Catalog(self.database_path) as catalog:
            command_receipt = catalog.create_command_quiescence_receipt(
                operation.id, restarted.daemon_fence
            )
            physical_receipt = catalog.create_physical_reconciliation_receipt(
                operation.id,
                restarted.daemon_fence,
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=None,
                    observed_media_identity_sha256=None,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
        resolution = restarted.resolve_recovery(
            operation.id,
            SafeRecoveryResolution(
                reason_code="late-callback-has-no-issued-command",
                command_receipt_id=command_receipt.id,
                physical_receipt_id=physical_receipt.id,
            ),
        )
        second = _BlockingCallback()
        admitted = restarted.start("restore.run", "new-key", "admin", second)
        second.wait_until_started()
        callback.release()

        caught = callback.result(timeout=1)
        self.drain(old)
        self.assertIsInstance(caught, StaleOperationFence)
        with Catalog(self.database_path) as catalog:
            durable = catalog.get_operation(operation.id)
            samples = catalog.connection.execute(
                "SELECT COUNT(*) FROM phase_samples WHERE operation_id=?",
                (operation.id,),
            ).fetchone()[0]
        self.assertIsNone(durable["phase"])
        self.assertEqual(0, samples)
        self.assertEqual("cancelled", resolution.state)
        self.assertEqual("cancelled", restarted.operation(operation.id).state)
        self.assertEqual("new-key", admitted.idempotency_key)
        self.assertEqual("running", restarted.operation(admitted.id).state)
        second.release()


class EventBusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database_path = Path(self.temporary.name) / "catalog.db"
        with Catalog(self.database_path) as catalog:
            catalog.initialize()
        self.factory = lambda: Catalog(self.database_path)

    def test_publish_uses_durable_monotonic_ids_and_replays_valid_cursor(self) -> None:
        bus = EventBus(self.factory)
        first = bus.publish("operation.started", {"operation_id": "one"})
        second = bus.publish("operation.finished", {"operation_id": "one"})

        self.assertLess(first.id, second.id)
        self.assertEqual((second,), bus.replay(first.id, lambda: {"unused": True}))

    def test_no_cursor_and_unavailable_cursors_publish_state_replace(self) -> None:
        bus = EventBus(self.factory)
        published = bus.publish("operation.started", {"operation_id": "one"})

        initial = bus.replay(None, lambda: {"state": "initial"})
        self.assertEqual("state.replace", initial[0].event_type)
        self.assertEqual({"state": "initial"}, initial[0].payload)
        self.assertGreater(initial[0].id, published.id)
        restarted = EventBus(self.factory)
        unavailable = restarted.replay(published.id, lambda: {"state": "after-restart"})
        self.assertEqual("state.replace", unavailable[0].event_type)
        self.assertGreater(unavailable[0].id, initial[0].id)
        ahead = restarted.replay(
            unavailable[0].id + 10, lambda: {"state": "cursor-ahead"}
        )
        self.assertEqual({"state": "cursor-ahead"}, ahead[0].payload)
        self.assertGreater(ahead[0].id, unavailable[0].id)

    def test_explicit_gap_in_retained_history_gets_newer_state_replace(self) -> None:
        bus = EventBus(self.factory)
        other_bus = EventBus(self.factory)
        first = bus.publish("progress", {"index": 1})
        missing = other_bus.publish("progress", {"index": 2})
        latest = bus.publish("progress", {"index": 3})

        replayed = bus.replay(first.id, lambda: {"state": "gap-replacement"})

        self.assertEqual(first.id + 1, missing.id)
        self.assertEqual(missing.id + 1, latest.id)
        self.assertEqual(1, len(replayed))
        self.assertEqual("state.replace", replayed[0].event_type)
        self.assertEqual({"state": "gap-replacement"}, replayed[0].payload)
        self.assertGreater(replayed[0].id, latest.id)

    def test_cursor_older_than_retained_window_gets_state_replace(self) -> None:
        bus = EventBus(self.factory)
        for index in range(2_001):
            bus.publish("progress", {"index": index})

        replayed = bus.replay(0, lambda: {"state": "replacement"})

        self.assertEqual(1, len(replayed))
        self.assertEqual("state.replace", replayed[0].event_type)
        self.assertEqual({"state": "replacement"}, replayed[0].payload)

    def test_state_patches_are_compacted_and_payload_memory_is_bounded(self) -> None:
        bus = EventBus(self.factory, retention=3, max_event_bytes=64)
        first = bus.publish("state.patch", {"progress": {"bytes_completed": 1}})
        latest = bus.publish("state.patch", {"telemetry": {"samples": []}})

        self.assertEqual(
            ({"progress": {"bytes_completed": 1}, "telemetry": {"samples": []}},),
            tuple(event.payload for event in bus.replay(first.id, dict)),
        )
        self.assertEqual(1, len(bus._events))
        with self.assertRaisesRegex(ValueError, "payload"):
            bus.publish("state.patch", {"telemetry": "x" * 65})
        with Catalog(self.database_path) as catalog:
            self.assertEqual(latest.id, catalog.latest_reserved_event_id())

    def test_cursorless_replacements_keep_only_the_latest_snapshot_within_byte_budget(
        self,
    ) -> None:
        bus = EventBus(
            self.factory,
            retention=2_000,
            max_event_bytes=128,
            max_retained_bytes=256,
        )
        for index in range(20):
            bus.replay(None, lambda index=index: {"snapshot": "x" * 80, "id": index})

        self.assertEqual(1, len(bus._events))
        self.assertLessEqual(bus._retained_bytes, 256)

    def test_returned_event_payload_cannot_expand_retained_memory_budget(self) -> None:
        mib = 1024 * 1024
        bus = EventBus(
            self.factory,
            retention=2_000,
            max_event_bytes=4 * mib,
            max_retained_bytes=4 * mib,
        )
        event = bus.publish("state.patch", {"snapshot": "x" * (3 * mib)})

        exposed = event.payload
        exposed["snapshot"] += "x" * (2 * mib)

        self.assertLessEqual(bus._retained_bytes, 4 * mib)
        self.assertEqual(3 * mib, len(event.payload["snapshot"]))
        self.assertEqual(3 * mib, len(bus.replay(0, dict)[0].payload["snapshot"]))

    def test_snapshot_callback_never_runs_while_event_bus_lock_is_held(self) -> None:
        """A telemetry publisher and replay snapshot cannot form an ABBA cycle."""

        from datetime import UTC, datetime

        from ltobackup.daemon.diagnostics import RuntimeDiagnostics

        snapshot_entered = threading.Event()
        allow_snapshot = threading.Event()
        replay_finished = threading.Event()
        bus = EventBus(self.factory)
        diagnostics = RuntimeDiagnostics(
            version="0.11.27",
            monotonic=lambda: 1.0,
            utc_now=lambda: datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
            on_snapshot=lambda _snapshot: bus.publish("state.patch", {"tick": 1}),
        )

        def status_snapshot() -> dict:
            snapshot_entered.set()
            allow_snapshot.wait(1)
            diagnostics.snapshot()
            return {"state": "current"}

        replay = threading.Thread(
            target=lambda: (bus.replay(None, status_snapshot), replay_finished.set())
        )
        replay.start()
        self.assertTrue(snapshot_entered.wait(1))

        publisher = threading.Thread(target=lambda: diagnostics.record_file(1))
        publisher.start()
        allow_snapshot.set()
        self.assertTrue(replay_finished.wait(1))
        replay.join(1)
        publisher.join(1)
        self.assertFalse(replay.is_alive())
        self.assertFalse(publisher.is_alive())


if __name__ == "__main__":
    unittest.main()
