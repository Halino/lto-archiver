"""Temporal integration of native completion, boundary refresh, and admission."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from concurrent.futures import Executor, Future
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.daemon.boundary_coordinator import (
    BoundaryReplanCoordinator,
    BoundarySources,
)
from ltobackup.daemon.boundary_dispatcher import BoundaryDispatcher
from ltobackup.daemon.models import (
    CommandExitEvidence,
    HardwareTargetBinding,
    OperationRecord,
    ProcessIdentity,
)
from ltobackup.daemon.operations import OperationContext, OperationManager
from ltobackup.daemon.sequence_coordinator import (
    NativeSequenceCoordinator,
    SequenceCandidate,
)
from ltobackup.settings import Settings


class _FirstImmediateThenHoldingExecutor(Executor):
    """Complete cassette one inline and retain cassette two as active hardware."""

    def __init__(self) -> None:
        self.futures: list[Future[None]] = []

    def submit(self, fn, /, *args, **kwargs):  # type: ignore[no-untyped-def]
        future: Future[None] = Future()
        self.futures.append(future)
        if len(self.futures) == 1:
            try:
                future.set_result(fn(*args, **kwargs))
            except Exception as exc:  # noqa: BLE001 - transport failures to Future.result().
                future.set_exception(exc)
        return future


class _FakeArchiveHardware:
    """Replace only physical tape I/O while retaining fenced Catalog writes."""

    def __init__(self, factory, daemon_fence) -> None:
        self._factory = factory
        self._daemon_fence = daemon_fence
        self.completed_sequences: list[int] = []

    def complete_first_cassette(self, context: OperationContext) -> None:
        sequence = int(context.record.cassette_sequence or 0)
        if sequence != 1:
            raise AssertionError("only cassette one may complete in the fake archive")

        block_id = "BLOCK-ONE"
        block_root = "blocks/BLOCK-ONE"
        context.transition_phase("writing")
        with self._factory() as catalog:
            catalog.update_automatic_job("JOB1", "writing", current_sequence=1)
            catalog.update_automatic_cassette("JOB1", 1, "writing")
            catalog.register_tape(
                "TAPE01", "TAPE01", "TAPE01", "LTFS", "/fake/tape"
            )
            catalog.create_block(
                block_id,
                "LIB1",
                "TAPE01",
                block_root,
                1,
                7,
                automatic_operation_id=context.record.id,
                automatic_job_id="JOB1",
                automatic_cassette_sequence=1,
            )
            catalog.stage_file_version(
                "LIB1",
                block_id,
                "TAPE01",
                "old",
                f"{block_root}/files/old",
                7,
                1,
                hashlib.sha256(b"olddata").hexdigest(),
            )

        context.transition_phase("finalizing_index")
        context.transition_phase("unmounting")
        context.transition_phase("unloading")
        with self._factory() as catalog:
            self._complete_command(catalog, context, "unload-one", "unload", 0, 101)
            self._complete_command(
                catalog, context, "probe-one", "probe_media", 3, 102
            )
            catalog.complete_block(block_id)
            catalog.update_automatic_cassette(
                "JOB1",
                1,
                "completed",
                tape_id="TAPE01",
                block_id=block_id,
                copied_files=1,
                copied_bytes=7,
            )
            catalog.update_automatic_job("JOB1", "unloading", current_sequence=1)
            self.assert_next_sequence(catalog.advance_automatic_job_after_eject("JOB1", 1))
        self.completed_sequences.append(sequence)

    @staticmethod
    def assert_next_sequence(next_sequence: int | None) -> None:
        if next_sequence != 2:
            raise AssertionError(f"expected cassette 2 after eject, got {next_sequence!r}")

    def _complete_command(
        self,
        catalog: Catalog,
        context: OperationContext,
        command_id: str,
        kind: str,
        exit_code: int,
        pid: int,
    ) -> None:
        process = ProcessIdentity("fake-boot", pid, pid * 10, pid)
        permit = hashlib.sha256(f"permit:{command_id}".encode()).hexdigest()
        catalog.reserve_hardware_command(
            context.fence,
            command_id,
            kind,
            hashlib.sha256(f"argv:{command_id}".encode()).hexdigest(),
        )
        catalog.record_blocked_process(command_id, context.fence, process)
        catalog.authorize_hardware_command_release(command_id, context.fence, permit)
        catalog.confirm_hardware_command_released(command_id, context.fence, permit)
        released_at = catalog.connection.execute(
            "SELECT released_at FROM hardware_command_executions WHERE id=?",
            (command_id,),
        ).fetchone()[0]
        catalog.acknowledge_command_quiescence(
            command_id,
            self._daemon_fence,
            CommandExitEvidence(
                command_id,
                process,
                "completed",
                catalog._precise_utc_now(after=released_at),
                exit_code,
            ),
        )


class BoundaryExchangeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.database = self.root / "catalog.db"
        self.source = self.root / "source"
        self.source.mkdir()
        (self.source / "old").write_bytes(b"olddata")
        os.utime(self.source / "old", ns=(1, 1))
        self.source_identity = self.source.stat()
        self.factory = lambda: Catalog(self.database)

        policy = {
            "settings_revision": 1,
            "selected_media_profile": "LTO-6",
            "default_media_profile": "LTO-6",
            "capacity_reserve_bytes": 100_000_000,
            "minimum_source_file_age_seconds": 0,
            "tape_root_directory": "lto",
            "content_verification_policy": "metadata",
        }
        encoded_policy = json.dumps(policy, sort_keys=True, separators=(",", ":"))
        with self.factory() as catalog:
            catalog.initialize()
            catalog.import_application_settings_once(
                Settings(), legacy_source_sha256=None
            )
            catalog.add_library("LIB1", "Library", str(self.source))
            catalog.create_automatic_job(
                "JOB1",
                "LIB1",
                "TAPE0",
                "AUTO",
                [
                    ("TAPE01", "TAPE01", 1, 7),
                    ("TAPE02", "TAPE02", 1, 7),
                    ("TAPE03", "TAPE03", 0, 0),
                ],
                force_format=True,
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB1", 1, [("LIB1", "old", 7, 1)]
            )
            catalog.replace_automatic_cassette_manifest(
                "JOB1", 2, [("LIB1", "obsolete", 7, 1)]
            )
            with catalog.transaction() as db:
                db.execute(
                    "INSERT INTO job_policy_snapshots("
                    "job_id,settings_revision,policy_json,policy_sha256,created_at) "
                    "VALUES('JOB1',1,?,?,?)",
                    (
                        encoded_policy,
                        hashlib.sha256(encoded_policy.encode()).hexdigest(),
                        datetime.now(UTC).isoformat(),
                    ),
                )
            epoch = catalog.latest_layout_epoch("JOB1")
            catalog.authorize_automatic_format_sequence(
                "JOB1",
                expected_revision=0,
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="admin",
                idempotency_key="authorize-job-one",
                authorized_at="2026-09-12T10:00:00+00:00",
            )
            state = catalog.automatic_sequence_state("JOB1")
            catalog.set_automatic_sequence_enabled(
                "JOB1",
                expected_revision=int(state["revision"]),
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="admin",
                enabled_at="2026-09-12T10:01:00+00:00",
            )
            catalog.update_automatic_job("JOB1", "waiting_media", current_sequence=1)
            catalog.update_automatic_cassette("JOB1", 1, "waiting_media")
            self.initial_fingerprint = str(epoch["layout_fingerprint_sha256"])
            catalog.activate_boundary_replanning()
            self.daemon_fence = catalog.claim_daemon_owner("daemon-one")

    @contextmanager
    def source_context(self, snapshot, *, phase, plan_id):
        del phase, plan_id
        with self.factory() as catalog:
            lease = catalog.connection.execute(
                "SELECT run_id FROM job_incremental_scan_leases WHERE job_id='JOB1'"
            ).fetchone()
        self.assertIsNotNone(lease)
        self.assertEqual(snapshot.run_id, lease[0])

        def verify_library(_library):
            current = self.source.stat()
            self.assertEqual(
                (self.source_identity.st_dev, self.source_identity.st_ino),
                (current.st_dev, current.st_ino),
            )
            return str(self.source.resolve()), "a" * 64

        yield BoundarySources(verify_library=verify_library)

    def test_completion_refreshes_manifest_before_admitting_next_cassette_once(self):
        executor = _FirstImmediateThenHoldingExecutor()
        manager = OperationManager(
            self.factory, self.daemon_fence, executor=executor
        )
        fake_external = _FakeArchiveHardware(self.factory, self.daemon_fence)
        candidates: list[SequenceCandidate] = []

        def admit(candidate: SequenceCandidate) -> OperationRecord:
            candidates.append(candidate)
            with self.factory() as catalog:
                cassette = next(
                    row
                    for row in catalog.list_automatic_cassettes(candidate.job_id)
                    if int(row["sequence"]) == candidate.cassette_sequence
                )
            target = HardwareTargetBinding.from_verified_inputs(
                self.root / "mount",
                "fake-tape-device",
                "fake-scsi-device",
                (
                    "archive.native",
                    candidate.job_id,
                    str(candidate.cassette_sequence),
                    str(cassette["physical_label"]),
                    "",
                    "",
                ),
            )
            return manager.start(
                "archive.native",
                candidate.idempotency_key,
                "sequence-coordinator",
                fake_external.complete_first_cassette,
                job_id=candidate.job_id,
                cassette_sequence=candidate.cassette_sequence,
                hardware_target=target,
                sequence_authorization_id=candidate.authorization_id,
                sequence_layout_fingerprint_sha256=(
                    candidate.layout_fingerprint_sha256
                ),
            )

        boundary = BoundaryDispatcher(
            self.factory,
            daemon_generation=self.daemon_fence.generation,
            coordinator=BoundaryReplanCoordinator(
                self.factory,
                daemon_generation=self.daemon_fence.generation,
                source_context=self.source_context,
            ),
        )
        coordinator = NativeSequenceCoordinator(
            self.factory,
            daemon_generation=self.daemon_fence.generation,
            admit=admit,
            reconcile_boundary=boundary.reconcile_once,
        )

        first = coordinator.reconcile_once()
        self.assertIsNotNone(first)
        executor.futures[0].result()
        self.assertEqual([1], fake_external.completed_sequences)
        self.assertFalse((self.source / "new").exists())
        with self.factory() as catalog:
            completed = catalog.connection.execute(
                "SELECT state FROM daemon_operations WHERE id=?", (first.id,)
            ).fetchone()
            self.assertEqual("succeeded", completed["state"])
            self.assertEqual(
                [("old", 7)],
                [
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT relative_path,size FROM job_manifest_history "
                        "WHERE job_id='JOB1' AND cassette_sequence=1"
                    )
                ],
            )

        # The mutation is deliberately after the first operation has reached
        # its successful, catalog-committed, unloaded terminal checkpoint.
        (self.source / "new").write_bytes(b"new data!")

        self.assertIsNone(coordinator.reconcile_once())
        with self.factory() as catalog:
            refreshed = catalog.latest_layout_epoch("JOB1")
            self.assertNotEqual(
                self.initial_fingerprint,
                refreshed["layout_fingerprint_sha256"],
            )
            self.assertEqual(
                [(2, "new", 9)],
                [
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT sequence,relative_path,size "
                        "FROM automatic_cassette_items WHERE job_id='JOB1' "
                        "ORDER BY sequence,item_sequence"
                    )
                ],
            )
            self.assertEqual(
                0,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM daemon_operations "
                    "WHERE job_id='JOB1' AND cassette_sequence=2"
                ).fetchone()[0],
            )

        second = coordinator.reconcile_once()
        self.assertIsNotNone(second)
        self.assertEqual(2, second.cassette_sequence)
        self.assertNotEqual(
            self.initial_fingerprint, candidates[1].layout_fingerprint_sha256
        )
        self.assertIsNone(coordinator.reconcile_once())
        self.assertEqual([1, 2], [candidate.cassette_sequence for candidate in candidates])
        self.assertEqual(2, len(executor.futures))
        self.assertFalse(executor.futures[1].done())
        with self.factory() as catalog:
            self.assertEqual(
                [(1, "succeeded"), (2, "running")],
                [
                    tuple(row)
                    for row in catalog.connection.execute(
                        "SELECT cassette_sequence,state FROM daemon_operations "
                        "WHERE job_id='JOB1' ORDER BY cassette_sequence"
                    )
                ],
            )
            self.assertEqual(
                1,
                catalog.connection.execute(
                    "SELECT COUNT(*) FROM job_management_history "
                    "WHERE job_id='JOB1' AND action='job.boundary_replan.applied'"
                ).fetchone()[0],
            )


if __name__ == "__main__":
    unittest.main()
