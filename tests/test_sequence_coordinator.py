from __future__ import annotations

import hashlib
import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import Executor, Future, ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon import native_frozen
from ltobackup.daemon.models import (
    HardwareTargetBinding,
    OperationFence,
    OperationRecord,
)
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.sequence_coordinator import (
    NativeSequenceCoordinator,
    SequenceCandidate,
)
from ltobackup.settings import Settings


class _HoldingExecutor(Executor):
    """Keep admitted operations durable without running an archive callback."""

    def __init__(self) -> None:
        self.futures: list[Future[None]] = []

    def submit(self, fn, /, *args, **kwargs):  # type: ignore[no-untyped-def]
        del fn, args, kwargs
        future: Future[None] = Future()
        self.futures.append(future)
        return future


class NativeSequenceCoordinatorTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "catalog.db"
        self.executor = _HoldingExecutor()
        with Catalog(self.database) as catalog:
            catalog.initialize()
            catalog.import_application_settings_once(Settings(), legacy_source_sha256=None)
            catalog.add_library("LIB1", "Library", str(self.root))
            catalog.create_automatic_job(
                "AUTO-ONE",
                "LIB1",
                "TAPE0",
                "AUTO",
                [("TAPE01", "TAPE01", 1, 7), ("TAPE02", "TAPE02", 1, 7)],
                force_format=True,
            )
            epoch = catalog.latest_layout_epoch("AUTO-ONE")
            catalog.connection.execute(
                "INSERT INTO automatic_sequence_state("
                "job_id,state,layout_epoch,layout_fingerprint_sha256,revision,"
                "enabled_by,enabled_at,updated_at) VALUES(?,'disabled',?,?,1,NULL,NULL,?)",
                ("AUTO-ONE", epoch["epoch_number"], epoch["layout_fingerprint_sha256"], "2026-08-30T10:00:00+00:00"),
            )
            catalog.connection.commit()
            self.authorities = catalog.authorize_automatic_format_sequence(
                "AUTO-ONE",
                expected_revision=0,
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="authorizer",
                idempotency_key="authorize-auto-one",
                authorized_at="2026-08-30T10:00:00+00:00",
            )
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='completed' WHERE job_id='AUTO-ONE' AND sequence=1"
            )
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='waiting_media' WHERE job_id='AUTO-ONE' AND sequence=2"
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='waiting_media',current_sequence=2 WHERE id='AUTO-ONE'"
            )
            catalog.connection.commit()
            state = catalog.automatic_sequence_state("AUTO-ONE")
            catalog.set_automatic_sequence_enabled(
                "AUTO-ONE",
                expected_revision=int(state["revision"]),
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="operator-1",
                enabled_at="2026-08-30T10:01:00+00:00",
            )
            fence = catalog.claim_daemon_owner("daemon-one")
        self.operations = OperationManager(
            lambda: Catalog(self.database), fence, executor=self.executor
        )
        self.admitted: list[SequenceCandidate] = []

        def admit(candidate: SequenceCandidate) -> OperationRecord:
            self.admitted.append(candidate)
            target = HardwareTargetBinding.from_verified_inputs(
                self.root / "mount",
                "tape-one",
                "scsi-one",
                ("archive.native", candidate.job_id, str(candidate.cassette_sequence), "TAPE02", "", ""),
            )
            return self.operations.start(
                "archive.native",
                candidate.idempotency_key,
                "sequence-coordinator",
                lambda _context: None,
                job_id=candidate.job_id,
                cassette_sequence=candidate.cassette_sequence,
                hardware_target=target,
                sequence_authorization_id=candidate.authorization_id,
                sequence_layout_fingerprint_sha256=(
                    candidate.layout_fingerprint_sha256
                ),
            )

        self.admit = admit
        self.coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=fence.generation,
            admit=admit,
            poll_interval_seconds=0.05,
        )

    def _with_boundary(self, callback):
        return NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=self.admit,
            reconcile_boundary=callback,
        )

    def test_boundary_gate_defers_admission_until_refresh_is_ready(self):
        ready = False
        coordinator = self._with_boundary(lambda: ready)
        self.assertIsNone(coordinator.reconcile_once())
        self.assertEqual([], self.admitted)
        ready = True
        self.assertIsNotNone(coordinator.reconcile_once())
        self.assertEqual(1, len(self.admitted))

    def test_boundary_refresh_is_not_invoked_while_hardware_is_owned(self):
        self.coordinator.reconcile_once()
        coordinator = self._with_boundary(lambda: self.fail("refresh during active operation"))
        self.assertIsNone(coordinator.reconcile_once())
        self.assertEqual(1, len(self.admitted))

    def test_boundary_callback_can_observe_terminal_job_without_next_candidate(self):
        with Catalog(self.database) as catalog, catalog.transaction() as db:
            db.execute("UPDATE automatic_jobs SET status='completed' WHERE id='AUTO-ONE'")
            db.execute("UPDATE automatic_sequence_state SET state='completed' WHERE job_id='AUTO-ONE'")
        observed = []
        def boundary():
            with Catalog(self.database) as catalog:
                observed.append(catalog.get_automatic_job("AUTO-ONE")["status"])
            return True
        coordinator = self._with_boundary(boundary)
        self.assertIsNone(coordinator.reconcile_once())
        self.assertEqual(["completed"], observed)
        self.assertEqual([], self.admitted)

    def test_successful_eject_admits_exact_next_cassette_once(self) -> None:
        """A duplicate wake must not create a second durable next-cassette operation."""
        admitted = self.coordinator.reconcile_once()
        self.coordinator.reconcile_once()

        self.assertEqual(1, len(self.admitted))
        candidate = self.admitted[0]
        self.assertEqual(("AUTO-ONE", 2), (candidate.job_id, candidate.cassette_sequence))
        self.assertEqual(self.authorities[1], candidate.authorization_id)
        self.assertEqual(
            self._layout_fingerprint(), candidate.layout_fingerprint_sha256
        )
        self.assertEqual(
            hashlib.sha256(
                f"AUTO-ONE\0{candidate.layout_fingerprint_sha256}\0{2}\0"
                f"{self.operations.daemon_fence.generation}".encode("utf-8")
            ).hexdigest(),
            candidate.idempotency_key,
        )
        replay_target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount",
            "tape-one",
            "scsi-one",
            ("archive.native", "AUTO-ONE", "2", "TAPE02", "", ""),
        )
        replayed = self.operations.start(
            "archive.native",
            candidate.idempotency_key,
            "sequence-coordinator",
            lambda _context: self.fail("exact replay dispatched a second callback"),
            job_id=candidate.job_id,
            cassette_sequence=candidate.cassette_sequence,
            hardware_target=replay_target,
            sequence_authorization_id=candidate.authorization_id,
            sequence_layout_fingerprint_sha256=candidate.layout_fingerprint_sha256,
        )
        self.assertEqual(admitted.id, replayed.id)
        self.assertEqual(1, len(self.executor.futures))
        with Catalog(self.database) as catalog:
            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations WHERE job_id='AUTO-ONE' AND cassette_sequence=2"
                ).fetchone()[0],
            )

            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM operation_sequence_continuations "
                    "WHERE operation_id=?",
                    (admitted.id,),
                ).fetchone()[0],
            )

    def test_source_check_blocks_hardware_admission_until_sources_return(self) -> None:
        ready = False
        checked = []

        def check(candidate):
            checked.append(candidate.cassette_sequence)
            return ready

        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=self.coordinator._admit,
            check_sources=check,
        )
        self.assertIsNone(coordinator.reconcile_once())
        self.assertEqual([], self.admitted)
        ready = True
        self.assertIsNotNone(coordinator.reconcile_once())
        self.assertEqual([2, 2], checked)
        self.assertEqual(1, len(self.admitted))

    def test_no_source_walk_while_an_operation_owns_the_checkpoint(self) -> None:
        self.coordinator.reconcile_once()
        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=lambda _candidate: self.fail("unexpected admission"),
            check_sources=lambda _candidate: self.fail("walked active source"),
        )
        self.assertIsNone(coordinator.reconcile_once())

    def test_source_checkpoint_records_failure_once_and_recovers_without_replan(self):
        checker_type = getattr(native_frozen, "NativeSourceCheckpoint", None)
        self.assertTrue(callable(checker_type), "durable source checkpoint is missing")
        now = [0.0]
        report = {
            "cassette_sequence": 2, "state": "blocked", "checked_files": 1,
            "missing_files": 1, "changed_files": 0, "unavailable_libraries": 0,
            "issues": [{"library_id": "LIB1", "relative_path": "gone.bin",
                        "code": "source_missing"}],
        }
        checker = checker_type(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            verify_library=lambda _candidate, _row: (str(self.root), "identity"),
            clock=lambda: now[0],
        )
        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=self.coordinator._admit, check_sources=checker,
        )
        fingerprint = self._layout_fingerprint()
        with patch.object(native_frozen, "inspect_cassette_sources", return_value=report):
            coordinator.reconcile_once()
            coordinator.reconcile_once()
            now[0] = 31.0
            coordinator.reconcile_once()
        self.assertEqual([], self.admitted)
        with Catalog(self.database) as catalog:
            rows = catalog.connection.execute(
                "SELECT payload_json FROM job_management_history WHERE action='job.source_check'"
            ).fetchall()
            self.assertEqual(1, len(rows))
            self.assertEqual("source_missing", json.loads(rows[0][0])["issues"][0]["code"])
        report = {**report, "state": "ready", "missing_files": 0, "issues": []}
        now[0] = 62.0
        with patch.object(native_frozen, "inspect_cassette_sources", return_value=report):
            coordinator.reconcile_once()
        self.assertEqual(1, len(self.admitted))
        self.assertEqual(fingerprint, self._layout_fingerprint())

    def test_source_check_result_is_discarded_if_pause_wins_the_race(self):
        checker_type = getattr(native_frozen, "NativeSourceCheckpoint", None)
        self.assertTrue(callable(checker_type), "durable source checkpoint is missing")

        def pause_during_read(*_args, **_kwargs):
            with Catalog(self.database) as catalog:
                catalog.request_job_pause("AUTO-ONE", actor="operator-1")
            return {"cassette_sequence": 2, "state": "ready", "checked_files": 1,
                    "missing_files": 0, "changed_files": 0, "unavailable_libraries": 0,
                    "issues": []}

        checker = checker_type(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            verify_library=lambda _candidate, _row: (str(self.root), "identity"),
        )
        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=self.coordinator._admit, check_sources=checker,
        )
        with patch.object(native_frozen, "inspect_cassette_sources", side_effect=pause_during_read):
            self.assertIsNone(coordinator.reconcile_once())
        with Catalog(self.database) as catalog:
            self.assertEqual(0, catalog.connection.execute(
                "SELECT COUNT(*) FROM job_management_history WHERE action='job.source_check'"
            ).fetchone()[0])
        self.assertEqual([], self.admitted)

    def test_concurrent_wakes_admit_once_through_the_durable_operation_key(self) -> None:
        """Racing poll and terminal wake callbacks cannot dispatch two operations."""
        with ThreadPoolExecutor(max_workers=4) as workers:
            tuple(workers.map(lambda _value: self.coordinator.reconcile_once(), range(8)))
        self.assertEqual(1, len(self.admitted))

    def test_source_check_discards_result_after_daemon_owner_takeover(self):
        def takeover(*_args, **_kwargs):
            with Catalog(self.database) as catalog:
                catalog.claim_daemon_owner("replacement-daemon")
            return {"cassette_sequence": 2, "state": "ready", "checked_files": 1,
                    "missing_files": 0, "changed_files": 0, "unavailable_libraries": 0,
                    "issues": []}

        checker = native_frozen.NativeSourceCheckpoint(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            verify_library=lambda _candidate, _row: (str(self.root), "identity"),
        )
        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=self.coordinator._admit, check_sources=checker,
        )
        with patch.object(native_frozen, "inspect_cassette_sources", side_effect=takeover):
            self.assertIsNone(coordinator.reconcile_once())
        with Catalog(self.database) as catalog:
            self.assertEqual(0, catalog.connection.execute(
                "SELECT COUNT(*) FROM job_management_history WHERE action='job.source_check'"
            ).fetchone()[0])
        self.assertEqual([], self.admitted)

    def test_crash_after_admission_never_needs_in_memory_bookkeeping(self) -> None:
        """A restart sees the persisted operation if a process dies just after admit."""
        target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount", "tape-one", "scsi-one",
            ("archive.native", "AUTO-ONE", "2", "TAPE02", "", ""),
        )

        def admit_then_crash(candidate: SequenceCandidate) -> OperationRecord:
            record = self.operations.start(
                "archive.native", candidate.idempotency_key, "sequence-coordinator",
                lambda _context: None, job_id=candidate.job_id,
                cassette_sequence=candidate.cassette_sequence, hardware_target=target,
                sequence_authorization_id=candidate.authorization_id,
                sequence_layout_fingerprint_sha256=(
                    candidate.layout_fingerprint_sha256
                ),
            )
            raise RuntimeError(f"crashed after durable admission {record.id}")

        crashing = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=admit_then_crash,
        )
        with self.assertRaisesRegex(RuntimeError, "crashed after durable admission"):
            crashing.reconcile_once()
        restarted = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation + 1,
            admit=lambda candidate: self.fail(f"unexpected restart admission: {candidate}"),
        )
        restarted.reconcile_once()

        with Catalog(self.database) as catalog:
            self.assertEqual(1, catalog.connection.execute(
                "SELECT COUNT(*) FROM daemon_operations WHERE job_id='AUTO-ONE' AND cassette_sequence=2"
            ).fetchone()[0])

    def test_restart_replay_never_redispatches_the_same_waiting_cassette(self) -> None:
        """The durable operation, not in-memory bookkeeping, fences restart replay."""
        self.coordinator.reconcile_once()
        restarted = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation + 1,
            admit=lambda candidate: self.fail(f"unexpected redispatch: {candidate}"),
            poll_interval_seconds=0.05,
        )

        restarted.reconcile_once()

        self.assertEqual(1, len(self.admitted))

    def test_pause_or_recovery_blocker_prevents_continuation(self) -> None:
        """A pause request or any active recovery fence closes automatic admission."""
        with Catalog(self.database) as catalog:
            catalog.request_job_pause("AUTO-ONE", actor="operator-1")
            self.assertEqual("pause_pending", catalog.automatic_sequence_state("AUTO-ONE")["state"])
            self.assertTrue(catalog.acknowledge_job_pause("AUTO-ONE", "unloaded"))
            self.assertEqual("disabled", catalog.automatic_sequence_state("AUTO-ONE")["state"])
            pause_audit = catalog.connection.execute(
                "SELECT payload_json FROM audit_entries WHERE "
                "action='automatic.sequence.pause_checkpoint'"
            ).fetchone()
            self.assertIsNotNone(pause_audit)
            self.assertNotIn("TAPE01", pause_audit["payload_json"])
        self.coordinator.reconcile_once()
        self.assertEqual([], self.admitted)

    def test_running_or_recovery_required_operation_blocks_continuation(self) -> None:
        """No next cassette is admitted while another operation owns recovery."""
        blocker = self.operations.start(
            "diagnostic", "sequence-blocker", "operator-1", lambda _context: None
        )
        with Catalog(self.database) as catalog:
            catalog.finish_operation(
                OperationFence(blocker.id, self.operations.daemon_fence.generation),
                "recovery_required",
                error_class="operator_required",
                error_code="recovery_required",
            )
        self.coordinator.reconcile_once()
        self.assertEqual([], self.admitted)

    def test_append_candidate_needs_no_format_authority(self) -> None:
        """A data-bearing append cassette can continue without destructive authority."""
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET operation='append',planned_files=1,planned_bytes=7 WHERE job_id='AUTO-ONE' AND sequence=2"
            )
            catalog.connection.commit()
            with catalog.transaction() as db:
                epoch = catalog._insert_layout_epoch_tx(
                    db,
                    "AUTO-ONE",
                    kind="extension",
                    plan_id=None,
                    plan_digest_sha256="a" * 64,
                    created_at="2026-08-30T10:01:30+00:00",
                    target_sequences=(2,),
                    target_operations=("append",),
                )
                db.execute(
                    "UPDATE automatic_sequence_state SET layout_epoch=?,"
                    "layout_fingerprint_sha256=? WHERE job_id='AUTO-ONE'",
                    (epoch["epoch_number"], epoch["layout_fingerprint_sha256"]),
                )
        self.coordinator.reconcile_once()
        self.assertEqual(1, len(self.admitted))
        self.assertIsNone(self.admitted[0].authorization_id)

    def test_zero_byte_reserve_is_not_an_admission_candidate(self) -> None:
        """An unpromoted reserve cannot be formatted or admitted empty."""
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET planned_files=0,planned_bytes=0 WHERE job_id='AUTO-ONE' AND sequence=2"
            )
            catalog.connection.commit()
        self.coordinator.reconcile_once()
        self.assertEqual([], self.admitted)

    def test_stale_layout_fails_closed_before_sequence_admission(self) -> None:
        """A newer layout epoch closes continuation until fresh authority exists."""
        with Catalog(self.database) as catalog:
            with catalog.transaction() as db:
                catalog._insert_layout_epoch_tx(  # noqa: SLF001 - stale durable fixture
                    db, "AUTO-ONE", kind="extension", plan_id=None,
                    plan_digest_sha256="e" * 64,
                    created_at="2026-08-30T10:02:00+00:00",
                    target_sequences=(2,), target_operations=("format",),
                )
        self.coordinator.reconcile_once()
        self.assertEqual([], self.admitted)

    def test_append_layout_race_leaves_no_operation_residue(self) -> None:
        """Append continuation revalidates its candidate layout inside admission."""
        with Catalog(self.database) as catalog:
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET operation='append' WHERE job_id='AUTO-ONE' AND sequence=2"
            )
            catalog.connection.commit()
        target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount", "tape-one", "scsi-one",
            ("archive.native", "AUTO-ONE", "2", "TAPE02", "", ""),
        )

        def race(candidate: SequenceCandidate) -> OperationRecord:
            with Catalog(self.database) as catalog:
                with catalog.transaction() as db:
                    catalog._insert_layout_epoch_tx(  # noqa: SLF001 - race fixture
                        db, "AUTO-ONE", kind="extension", plan_id=None,
                        plan_digest_sha256="f" * 64,
                        created_at="2026-08-30T10:04:00+00:00",
                        target_sequences=(2,), target_operations=("append",),
                    )
            return self.operations.start(
                "archive.native", candidate.idempotency_key, "sequence-coordinator",
                lambda _context: None, job_id=candidate.job_id,
                cassette_sequence=candidate.cassette_sequence, hardware_target=target,
                sequence_layout_fingerprint_sha256=candidate.layout_fingerprint_sha256,
            )

        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=race,
        )
        with self.assertRaisesRegex(Exception, "layout"):
            coordinator.reconcile_once()
        with Catalog(self.database) as catalog:
            self.assertEqual(0, catalog.connection.execute(
                "SELECT COUNT(*) FROM daemon_operations WHERE job_id='AUTO-ONE' AND cassette_sequence=2"
            ).fetchone()[0])

    def test_pause_pending_cannot_be_reenabled_before_unloaded_acknowledgement(self) -> None:
        """Resume must preserve the unloaded pause fence until it is acknowledged."""
        with Catalog(self.database) as catalog:
            catalog.request_job_pause("AUTO-ONE", actor="operator-1")
            with self.assertRaisesRegex(Exception, "pause"):
                catalog.enable_automatic_sequence_for_start(
                    "AUTO-ONE", actor="operator-1", enabled_at="2026-08-30T10:03:00+00:00"
                )
            self.assertTrue(catalog.acknowledge_job_pause("AUTO-ONE", "unloaded"))
            self.assertEqual("disabled", catalog.automatic_sequence_state("AUTO-ONE")["state"])

    def test_shutdown_refuses_to_return_while_worker_is_still_admitting(self) -> None:
        """Dependency shutdown must not proceed behind a live coordinator worker."""
        entered = threading.Event()
        release = threading.Event()

        def blocking_admit(_candidate: SequenceCandidate) -> OperationRecord:
            entered.set()
            release.wait(2)
            raise RuntimeError("test stop")

        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=blocking_admit,
            poll_interval_seconds=0.01,
            shutdown_timeout_seconds=0.02,
        )
        coordinator.start()
        self.assertTrue(entered.wait(0.5))
        try:
            with self.assertRaisesRegex(RuntimeError, "did not stop"):
                coordinator.shutdown()
        finally:
            release.set()
            time.sleep(0.02)
            coordinator.shutdown()

    def test_background_admission_error_is_reported(self) -> None:
        """A permanent admission failure is visible instead of being silently retried."""
        reported: list[str] = []
        coordinator = NativeSequenceCoordinator(
            lambda: Catalog(self.database),
            daemon_generation=self.operations.daemon_fence.generation,
            admit=lambda _candidate: (_ for _ in ()).throw(ValueError("permanent")),
            poll_interval_seconds=0.01,
            on_error=lambda error: reported.append(str(error)),
        )
        coordinator.start()
        try:
            deadline = time.monotonic() + 0.5
            while not reported and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual(["permanent"], reported)
        finally:
            coordinator.shutdown()

    def _layout_fingerprint(self) -> str:
        with Catalog(self.database) as catalog:
            return str(catalog.latest_layout_epoch("AUTO-ONE")["layout_fingerprint_sha256"])
