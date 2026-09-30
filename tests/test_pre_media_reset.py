from __future__ import annotations

import tempfile
import time
import unittest
from concurrent.futures import Executor, Future
from contextlib import nullcontext
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from httpx2 import ASGITransport, AsyncClient

from ltobackup.catalog import Catalog, CatalogError
from ltobackup.daemon.api import create_app
from ltobackup.daemon.archive_runtime import ArchiveResumeAdmission, ProductionRecoveryRuntime
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.models import CommandExitEvidence, HardwareTargetBinding, OperationFence, OperationRecord, ProcessIdentity, RecoveryCommandFence
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.service import DaemonService, Principal
from ltobackup.linux_settings import LinuxPaths, LinuxSettings
from ltobackup.tape.command_supervisor import CommandError, CommandReleaseClaim, ExecutionScopeIdentity, _read_boot_id
from ltobackup.tape.linux_ltfs import BackendUnavailable, ProcMountInfoProbe


class PreMediaMountNamespaceTests(unittest.TestCase):
    def test_service_bind_mount_does_not_block_pre_media_reset(self):
        self._check_mounts("", blocked=False)

    def test_ltfs_above_service_bind_still_blocks_reset(self):
        self._check_mounts("685 684 0:49 / {target} rw - fuse.ltfs ltfs rw\n", blocked=True)

    def test_hidden_ltfs_mount_still_blocks_reset(self):
        self._check_mounts(
            "685 684 0:49 / {target} rw - fuse.ltfs ltfs rw\n"
            "686 685 253:0 /mnt/lto-archiver/tape {target} rw - xfs /dev/mapper/rhel-root rw\n",
            blocked=True,
        )

    def _check_mounts(self, extra, *, blocked):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "tape"
            mountinfo = Path(directory) / "mountinfo"
            mountinfo.write_text(
                f"684 648 253:0 /mnt/lto-archiver/tape {target} rw - xfs /dev/mapper/rhel-root rw\n"
                + extra.format(target=target), encoding="utf-8",
            )
            probe = ProcMountInfoProbe(mountinfo)
            runtime = ProductionRecoveryRuntime(
                SimpleNamespace(_settings=SimpleNamespace(mount_path=target)), None,
            )
            # Keep the real mountinfo parser; isolate only process enumeration.
            with patch("ltobackup.daemon.archive_runtime.ProcMountInfoProbe", return_value=probe), \
                 patch.object(Path, "iterdir", return_value=iter(())):
                if blocked:
                    with self.assertRaises(BackendUnavailable):
                        runtime._assert_pre_media_commands_clear(())
                else:
                    runtime._assert_pre_media_commands_clear(())


class _HoldingExecutor(Executor):
    def submit(self, fn, /, *args, **kwargs):
        return Future()


class _Scope:
    def __init__(self, *, populated=False, identity=None, after_close=None, claim=None):
        self.identity = identity or ExecutionScopeIdentity("identify-pending", 1)
        self.populated = populated
        self.closed = False
        self.after_close = after_close
        self.claim = claim

    def claim_unreleased(self, pid, permit_sha256):
        if self.claim is None:
            raise CommandError("broker claim unavailable")
        return self.claim

    def is_populated(self):
        return self.populated

    def signal(self, _signal):
        raise AssertionError("reset must never signal a process")

    def close(self):
        if self.populated:
            raise AssertionError("reset must never close a populated scope")
        self.closed = True
        if self.after_close:
            self.after_close()


class _LifecycleLockOrderProbe:
    """Delegate to the real lock while detecting the admission/reset inversion."""
    def __init__(self, lifecycle_lock, operation_lock):
        self.lifecycle_lock = lifecycle_lock
        self.operation_lock = operation_lock
        self.inverted = False

    def __enter__(self):
        if self.operation_lock._is_owned() and not self.lifecycle_lock._is_owned():
            self.inverted = True
        return self.lifecycle_lock.__enter__()

    def __exit__(self, *args):
        return self.lifecycle_lock.__exit__(*args)


class PreMediaResetTests(unittest.IsolatedAsyncioTestCase):
    """The public reset closes only a stopped pre-media attempt and preserves data."""

    async def asyncSetUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        settings = LinuxSettings(state_dir=root / "state", socket_path=root / "run/daemon.sock")
        self.settings = settings
        self.paths = LinuxPaths.from_settings(settings)
        backups = BackupManager(self.paths.catalog_file, self.paths.backup_dir)
        backups.prepare_and_initialize()
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.add_library("LIB-1", "Library", str(root))
            catalog.create_automatic_job(
                "JOB-1", "LIB-1", "synthetic-drive", str(root / "mount"),
                [("TAPE09", "SERIAL-9", 1, 1)], force_format=True,
            )
            self.owner = catalog.claim_daemon_owner("reset-test")
            self.target = HardwareTargetBinding.from_verified_inputs(
                root / "mount", "tape-by-id", "scsi-by-id",
                ("archive.native", "JOB-1", "1", "TAPE09", "", ""),
            )
            admission = catalog.admit_operation(
                OperationRecord(
                    id="pre-media-operation", kind="archive.native", state="running",
                    phase=None, idempotency_key="original-attempt", principal="admin",
                    job_id="JOB-1", cassette_sequence=1,
                    started_at=datetime.now(UTC).isoformat(), finished_at=None,
                ), self.owner, admission_open=True, hardware_target=self.target,
            )
            fence = OperationFence(admission.record.id, self.owner.generation)
            catalog.reserve_hardware_command(fence, "identify-pending", "identify", "a" * 64)
            catalog.finish_operation(fence, "recovery_required", error_code="recovery_required")
            catalog.update_automatic_job("JOB-1", "waiting_media", current_sequence=1)
            with catalog.transaction() as db:
                db.execute("UPDATE automatic_cassettes SET status='waiting_media' WHERE job_id='JOB-1'")
            self.original_cassette = dict(catalog.connection.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id='JOB-1'"
            ).fetchone())
        self.operations = OperationManager(lambda: Catalog(self.paths.catalog_file), self.owner, executor=_HoldingExecutor())
        self.service = DaemonService(
            self.paths, settings, backups, self.operations,
            EventBus(lambda: Catalog(self.paths.catalog_file)),
        )
        # Only the external broker/host evidence boundary is replaced. All
        # admission, command receipts, reset transactions and API behavior are real.
        self.service._pre_media_reset_reconciler = self._reconcile_empty_scope
        self.principal = Principal(
            "admin", session_binding_sha256="b" * 64, reauthenticated_at=time.time(),
        )
        self.reconciliation_calls = 0
        self.scope_failure = False
        self.late_change = None
        self.service.startup()
        app = create_app(self.service)
        app.dependency_overrides[self.service.principals.require_webui_admin] = lambda: self.principal
        app.dependency_overrides[self.service.principals.require_operator] = lambda: self.principal
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="http://daemon")
        self.url = "/api/v1/operations/pre-media-operation/pre-media-reset"

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        self.operations._futures.clear()
        self.service.shutdown(0.0)

    def _reconcile_empty_scope(self, operation, daemon_fence):
        self.reconciliation_calls += 1
        if self.scope_failure:
            raise CommandError("exact scope is populated or unavailable")
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.acknowledge_command_quiescence(
                "identify-pending", daemon_fence,
                CommandExitEvidence("identify-pending", None, "launch_aborted", datetime.now(UTC).isoformat()),
            )
            receipt = catalog.create_command_quiescence_receipt(operation.id, daemon_fence)
            if self.late_change is not None:
                with catalog.transaction() as db:
                    db.execute(self.late_change)
            return receipt

    async def _proof(self):
        response = await self.client.get(self.url)
        self.assertEqual(200, response.status_code, response.text)
        return response.json()

    async def _post(self, proof, key="reset-once"):
        return await self.client.post(self.url, json=proof, headers={"Idempotency-Key": key})

    def _assert_still_blocked(self):
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("recovery_required", catalog.get_operation("pre-media-operation")["state"])
            self.assertEqual("waiting_media", catalog.connection.execute(
                "SELECT status FROM automatic_jobs WHERE id='JOB-1'"
            ).fetchone()[0])

    async def test_proof_is_available_without_critical_quarantine_and_is_read_only(self):
        proof = await self._proof()
        self.assertEqual("pre-media-operation", proof["operation_id"])
        self.assertEqual("JOB-1", proof["job_id"])
        self.assertEqual(1, proof["cassette_sequence"])
        self.assertEqual(self.owner.generation, proof["daemon_generation"])
        self.assertEqual(64, len(proof["command_ledger_sha256"]))
        self.assertEqual(0, self.reconciliation_calls)
        self._assert_still_blocked()

    async def test_reset_pauses_job_without_altering_cassette_or_claiming_unloaded_media(self):
        response = await self._post(await self._proof())
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual("failed", response.json()["state"])
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("paused", catalog.connection.execute(
                "SELECT status FROM automatic_jobs WHERE id='JOB-1'"
            ).fetchone()[0])
            self.assertEqual("disabled", catalog.automatic_sequence_state("JOB-1")["state"])
            cassette = dict(catalog.connection.execute("SELECT * FROM automatic_cassettes WHERE job_id='JOB-1'").fetchone())
            self.assertEqual(self.original_cassette, cassette)
            self.assertEqual(0, catalog.connection.execute("SELECT count(*) FROM physical_reconciliation_receipts").fetchone()[0])
            self.assertEqual("launch_aborted", catalog.command("identify-pending").exit_outcome)

    async def test_replay_is_durable_and_principal_and_payload_bound(self):
        proof = await self._proof()
        first = await self._post(proof)
        self.assertEqual(200, first.status_code, first.text)
        repeated = await self._post(proof)
        self.assertEqual(first.json(), repeated.json())
        self.assertEqual(1, self.reconciliation_calls)
        altered = await self._post({**proof, "cassette_sequence": 2})
        self.assertEqual(409, altered.status_code, altered.text)
        self.principal = replace(self.principal, name="other-admin")
        other = await self._post(proof)
        self.assertEqual(409, other.status_code, other.text)

    async def test_post_requires_fresh_web_admin_reauthentication(self):
        proof = await self._proof()
        for principal in (Principal("admin"), Principal("operator", role="operator"),
                          replace(self.principal, reauthenticated_at=time.time() - 601)):
            with self.subTest(principal=principal):
                self.principal = principal
                response = await self._post(proof)
                self.assertEqual(403, response.status_code, response.text)
                self._assert_still_blocked()
        self.assertEqual(0, self.reconciliation_calls)

    async def test_populated_or_unavailable_scope_keeps_recovery_blocker(self):
        proof = await self._proof()
        self.scope_failure = True
        response = await self._post(proof)
        self.assertEqual(409, response.status_code, response.text)
        self._assert_still_blocked()

    async def test_phase_change_after_proof_rejects_before_broker_effect(self):
        proof = await self._proof()
        with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
            db.execute("UPDATE daemon_operations SET phase='writing' WHERE id='pre-media-operation'")
        response = await self._post(proof)
        self.assertEqual(409, response.status_code, response.text)
        self.assertEqual(0, self.reconciliation_calls)
        self._assert_still_blocked()

    async def test_phase_change_during_reconciliation_cannot_clear_blocker(self):
        proof = await self._proof()
        self.late_change = "UPDATE daemon_operations SET phase='writing' WHERE id='pre-media-operation'"
        response = await self._post(proof)
        self.assertEqual(409, response.status_code, response.text)
        self._assert_still_blocked()

    async def test_active_local_future_rejects_even_when_durable_state_is_recovery(self):
        proof = await self._proof()
        self.operations._futures["pre-media-operation"] = Future()
        response = await self._post(proof)
        self.assertEqual(409, response.status_code, response.text)
        self.assertEqual(0, self.reconciliation_calls)
        self._assert_still_blocked()

    async def test_reset_uses_admission_lock_order_without_inverse_acquisition(self):
        proof = await self._proof()
        probe = _LifecycleLockOrderProbe(self.service._lifecycle_lock, self.operations._lock)
        self.service._lifecycle_lock = probe
        response = await self._post(proof)
        self.assertEqual(200, response.status_code, response.text)
        self.assertFalse(probe.inverted, "reset takes lifecycle lock while holding operation lock; admission can deadlock")

    async def test_durable_replay_repairs_admission_after_postcommit_refresh_failure(self):
        proof = await self._proof()
        with patch.object(self.service, "_set_admission_blockers_locked", side_effect=RuntimeError("refresh unavailable")):
            first = await self._post(proof)
        self.assertEqual(409, first.status_code, first.text)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("failed", catalog.get_operation("pre-media-operation")["state"])
        replay = await self._post(proof)
        self.assertEqual(200, replay.status_code, replay.text)
        self.assertTrue(self.service.status().accepting_mutations)
        self.assertEqual(1, self.reconciliation_calls)

    async def test_reset_then_explicit_resume_preserves_layout_and_current_cassette(self):
        with Catalog(self.paths.catalog_file) as catalog:
            layout = dict(catalog.latest_layout_epoch("JOB-1"))
        response = await self._post(await self._proof())
        self.assertEqual(200, response.status_code, response.text)
        self.assertEqual({}, self.operations._futures)
        self.service._native_archive_admission = lambda job: ArchiveResumeAdmission(job, 1, self.target)
        self.service._callbacks["archive.native"] = lambda context: None
        resumed = await self.client.post(
            "/api/v1/jobs/JOB-1/resume", json={"format_confirmation_label": "TAPE09"},
            headers={"Idempotency-Key": "explicit-resume-after-reset"},
        )
        self.assertEqual(202, resumed.status_code, resumed.text)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual(layout, dict(catalog.latest_layout_epoch("JOB-1")))
            self.assertEqual(1, catalog.get_automatic_job("JOB-1")["current_sequence"])
            self.assertEqual("enabled", catalog.automatic_sequence_state("JOB-1")["state"])
            self.assertIsNone(catalog.job_management_state("JOB-1")["pause_requested_at"])
            self.assertEqual(self.original_cassette, dict(catalog.connection.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id='JOB-1'"
            ).fetchone()))

    async def test_reset_accepts_large_completed_identification_history_unchanged(self):
        with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
            source = dict(db.execute("SELECT * FROM hardware_command_executions WHERE id='identify-pending'").fetchone())
            source.update(state="quiesced", exit_outcome="completed", boot_id="history-boot",
                          pid=100, process_start_ticks=1, process_group_id=100,
                          released_at=source["created_at"], exit_observed_at=source["created_at"],
                          quiesced_at=source["created_at"], terminal_exit_code=3)
            columns = tuple(source)
            placeholders = ",".join("?" for _ in columns)
            rows = []
            for index in range(10990):
                row = {**source, "id": f"history-{index:05d}", "command_kind": "identify" if index % 2 else "probe_media"}
                rows.append(tuple(row[name] for name in columns))
            db.executemany(f"INSERT INTO hardware_command_executions({','.join(columns)}) VALUES({placeholders})", rows)
            history = [tuple(row) for row in db.execute("SELECT * FROM hardware_command_executions WHERE id LIKE 'history-%' ORDER BY id")]
        response = await self._post(await self._proof())
        self.assertEqual(200, response.status_code, response.text)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual(history, [tuple(row) for row in catalog.connection.execute(
                "SELECT * FROM hardware_command_executions WHERE id LIKE 'history-%' ORDER BY id"
            )])

    def _historical_aborted_process(self):
        process = ProcessIdentity("historical-boot", 248062, 66986910, 248062)
        with Catalog(self.paths.catalog_file) as catalog:
            fence = RecoveryCommandFence("pre-media-operation", self.owner.generation)
            catalog.reserve_hardware_command(fence, "historical-aborted", "identify", "e" * 64)
            catalog.record_blocked_process("historical-aborted", fence, process)
            catalog.acknowledge_command_quiescence(
                "historical-aborted", self.owner,
                CommandExitEvidence("historical-aborted", process, "launch_aborted", datetime.now(UTC).isoformat()),
            )
            return catalog.command("historical-aborted")

    async def test_reset_preserves_aborted_process_history_before_ambiguous_probe(self):
        history = self._historical_aborted_process()
        pending, claim = self._ambiguous_command()
        proof = await self._proof()
        self.service._pre_media_reset_reconciler = lambda operation, fence: self._production_reconcile(
            _Scope(identity=claim.scope, claim=claim)
        )
        response = await self._post(proof)
        self.assertEqual(200, response.status_code, response.text)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual(history, catalog.command(history.id))
            self.assertEqual("terminated", catalog.command(pending.id).exit_outcome)
            self.assertEqual("paused", catalog.get_automatic_job("JOB-1")["status"])

    async def test_aborted_history_still_requires_no_registered_process(self):
        self._historical_aborted_process()
        await self._proof()
        with self.assertRaises(BackendUnavailable):
            self._production_reconcile(_Scope(), process_absent=False)
        self._assert_still_blocked()

    async def test_aborted_history_without_exit_observation_is_rejected(self):
        self._historical_aborted_process()
        with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
            db.execute("UPDATE hardware_command_executions SET exit_observed_at=NULL WHERE id='historical-aborted'")
        response = await self.client.get(self.url)
        self.assertEqual(409, response.status_code)

    def _production_reconcile(self, scope, *, mounted=False, ltfs_process=False, process_absent=True):
        archive = SimpleNamespace(
            _catalog_factory=lambda: Catalog(self.paths.catalog_file), _settings=self.settings,
            _device_identities=object(),
        )
        runtime = ProductionRecoveryRuntime(archive, self.operations)
        supervisor = SimpleNamespace(launcher=SimpleNamespace(open_scope=lambda identity: scope))
        operation = self.operations.operation("pre-media-operation")
        comm = Path(self.temporary.name) / "12345"
        comm.mkdir(exist_ok=True)
        (comm / "comm").write_text("ltfs\n" if ltfs_process else "safe-process\n")
        process_observation = nullcontext() if process_absent is None else patch(
            "ltobackup.daemon.archive_runtime.LinuxProcessProbe.identities_and_groups_absent",
            side_effect=lambda identities: tuple(process_absent for _ in identities),
        )
        with patch("ltobackup.daemon.archive_runtime.FrozenNativeCassettePlan.load", return_value=SimpleNamespace(expected_media=object())), \
             patch("ltobackup.daemon.archive_runtime.LinuxLtfsBackend.target_binding_from", return_value=self.target), \
             patch("ltobackup.daemon.archive_runtime.ProcMountInfoProbe.has_fuse_mount", return_value=mounted), \
             process_observation, \
             patch.object(Path, "iterdir", side_effect=lambda: iter((comm,))), \
             patch.object(runtime, "_recovery_supervisor", return_value=supervisor):
            return runtime.reconcile_pre_media_commands(operation, self.owner)

    def _ambiguous_command(self, *, kind="probe_media", process=None):
        process = process or ProcessIdentity("stopped-boot", 12345, 456, 12345)
        permit = "c" * 64
        with Catalog(self.paths.catalog_file) as catalog:
            fence = RecoveryCommandFence("pre-media-operation", self.owner.generation)
            with catalog.transaction() as db:
                db.execute("UPDATE hardware_command_executions SET command_kind=? WHERE id='identify-pending'", (kind,))
            catalog.record_blocked_process("identify-pending", fence, process)
            catalog.authorize_hardware_command_release("identify-pending", fence, permit)
            catalog.mark_hardware_command_release_ambiguous("identify-pending", self.owner, permit)
            command = catalog.command("identify-pending")
        claim = CommandReleaseClaim(
            ExecutionScopeIdentity("identify-pending", self.owner.generation),
            process.pid, permit, True, False,
        )
        return command, claim

    async def test_ambiguous_released_probe_reset_preserves_release_evidence(self):
        before, claim = self._ambiguous_command()
        scope = _Scope(identity=claim.scope, claim=claim)
        self.service._pre_media_reset_reconciler = lambda *_: self._production_reconcile(scope)
        response = await self._post(await self._proof())
        self.assertEqual(200, response.status_code, response.text)
        self.assertTrue(scope.closed)
        with Catalog(self.paths.catalog_file) as catalog:
            after = catalog.command(before.id)
            self.assertEqual(replace(before, state="quiesced", exit_outcome="terminated",
                                     exit_observed_at=after.exit_observed_at, quiesced_at=after.quiesced_at), after)
            self.assertEqual("paused", catalog.get_automatic_job("JOB-1")["status"])
            self.assertEqual(self.original_cassette, dict(catalog.connection.execute(
                "SELECT * FROM automatic_cassettes WHERE job_id='JOB-1'"
            ).fetchone()))

    async def test_ambiguous_terminated_identify_can_retry_after_partial_reconciliation(self):
        before, claim = self._ambiguous_command(kind="identify")
        self._production_reconcile(_Scope(identity=claim.scope, claim=claim))
        # A new request accepts the durable terminal receipt without reopening
        # the closed scope or inventing a successful command exit.
        scope = _Scope(identity=ExecutionScopeIdentity("must-not-open", 999))
        self.service._pre_media_reset_reconciler = lambda *_: self._production_reconcile(scope)
        response = await self._post(await self._proof())
        self.assertEqual(200, response.status_code, response.text)
        self.assertFalse(scope.closed)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("terminated", catalog.command(before.id).exit_outcome)
            self.assertEqual("ambiguous", catalog.command(before.id).release_status)

    async def test_ambiguous_release_requires_exact_positive_broker_claim(self):
        before, claim = self._ambiguous_command()
        for bad_claim in (None, replace(claim, pid=98765), replace(claim, permit_sha256="d" * 64),
                          replace(claim, scope=ExecutionScopeIdentity("other", self.owner.generation)),
                          replace(claim, released=False, permit_revoked=True), replace(claim, permit_revoked=True)):
            scope = _Scope(identity=claim.scope, claim=bad_claim)
            with self.subTest(claim=bad_claim), self.assertRaises(CommandError):
                self._production_reconcile(scope)
            self.assertFalse(scope.closed)
            with Catalog(self.paths.catalog_file) as catalog:
                self.assertEqual(before, catalog.command(before.id))

    async def test_ambiguous_release_active_process_or_scope_cannot_be_reset(self):
        before, claim = self._ambiguous_command()
        for populated, absent in ((True, True), (False, False)):
            scope = _Scope(identity=claim.scope, claim=claim, populated=populated)
            with self.subTest(populated=populated, absent=absent), self.assertRaises(BackendUnavailable):
                self._production_reconcile(scope, process_absent=absent)
            self.assertFalse(scope.closed)
            with Catalog(self.paths.catalog_file) as catalog:
                self.assertEqual(before, catalog.command(before.id))

    async def test_ambiguous_release_requires_permit_and_pre_media_kind(self):
        self._ambiguous_command()
        for kind in ("format", "mount"):
            with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
                db.execute("UPDATE hardware_command_executions SET command_kind=? WHERE id='identify-pending'", (kind,))
            response = await self.client.get(self.url)
            self.assertEqual(409, response.status_code, response.text)
        with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
            db.execute("UPDATE hardware_command_executions SET command_kind='identify' WHERE id='identify-pending'")
            db.execute("DELETE FROM hardware_command_release_authorizations WHERE command_id='identify-pending'")
        response = await self.client.get(self.url)
        self.assertEqual(409, response.status_code, response.text)

    async def test_ambiguous_release_ledger_drift_after_close_keeps_blocker(self):
        before, claim = self._ambiguous_command()
        def change_ledger():
            with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
                db.execute("UPDATE hardware_command_executions SET argv_sha256=? WHERE id='identify-pending'", ("d" * 64,))
        scope = _Scope(identity=claim.scope, claim=claim, after_close=change_ledger)
        with self.assertRaises(BackendUnavailable):
            self._production_reconcile(scope)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertIsNone(catalog.command(before.id).exit_outcome)
        self._assert_still_blocked()

    async def test_restart_lineage_allows_reset_of_exact_original_ambiguous_command(self):
        before, claim = self._ambiguous_command()
        with Catalog(self.paths.catalog_file) as catalog:
            self.owner = catalog.claim_daemon_owner("reset-test-restarted")
            catalog.recover_interrupted_operations(self.owner)
            proof = catalog.pre_media_reset_proof("pre-media-operation", self.owner)
            original = catalog.hardware_commands_for_operation("pre-media-operation")
        receipt = self._production_reconcile(_Scope(identity=claim.scope, claim=claim))
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.finalize_pre_media_reset(proof, self.owner, original, receipt.id,
                principal="admin", session_binding_sha256="b" * 64, idempotency_key="restart-reset")
            self.assertEqual("paused", catalog.get_automatic_job("JOB-1")["status"])
            after = catalog.command(before.id)
            self.assertEqual(before.issued_generation, after.issued_generation)
            self.assertEqual("ambiguous", after.release_status)
            self.assertEqual("terminated", after.exit_outcome)

    async def test_restart_without_current_lineage_rejects_as_reset_conflict(self):
        self._ambiguous_command()
        with Catalog(self.paths.catalog_file) as catalog:
            current = catalog.claim_daemon_owner("restart-without-recovery")
            with self.assertRaises(CatalogError):
                catalog.pre_media_reset_proof("pre-media-operation", current)

    async def test_restart_rejects_lineage_drift_and_new_recovery_commands(self):
        self._ambiguous_command()
        with Catalog(self.paths.catalog_file) as catalog:
            current = catalog.claim_daemon_owner("restart-validated")
            catalog.recover_interrupted_operations(current)
            lineage = dict(catalog.recovery_lineage_evidence("pre-media-operation")[-1])
            for field, value in (("daemon_owner_id", "different-owner"),
                                 ("lineage_sha256", "0" * 64), ("command_ids_json", "[]")):
                with self.subTest(field=field):
                    with catalog.transaction() as db:
                        db.execute(f"UPDATE operation_recovery_lineages SET {field}=? WHERE id=?", (value, lineage["id"]))
                    with self.assertRaises(CatalogError):
                        catalog.pre_media_reset_proof("pre-media-operation", current)
                    with catalog.transaction() as db:
                        db.execute(f"UPDATE operation_recovery_lineages SET {field}=? WHERE id=?", (lineage[field], lineage["id"]))
            catalog.reserve_hardware_command(
                RecoveryCommandFence("pre-media-operation", current.generation),
                "new-recovery-command", "identify", "f" * 64,
            )
            with self.assertRaises(CatalogError):
                catalog.pre_media_reset_proof("pre-media-operation", current)

    async def test_started_recovery_attempt_keeps_reset_blocked(self):
        self._ambiguous_command()
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.begin_recovery_attempt(
                "pre-media-operation", 1, self.owner, trigger="daemon_restart",
                evidence_sha256="e" * 64, decision="reconcile_commands",
                recorded_at=datetime.now(UTC).isoformat(),
            )
            with self.assertRaises(CatalogError):
                catalog.pre_media_reset_proof("pre-media-operation", self.owner)

    async def test_production_empty_scope_yields_receipt_without_media_probe(self):
        scope = _Scope(identity=ExecutionScopeIdentity("identify-pending", self.owner.generation))
        receipt = self._production_reconcile(scope)
        self.assertTrue(scope.closed)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("launch_aborted", catalog.command("identify-pending").exit_outcome)
            self.assertEqual(1, catalog.connection.execute(
                "SELECT count(*) FROM command_quiescence_receipts WHERE id=?", (receipt.id,)
            ).fetchone()[0])
            self.assertEqual(1, len(catalog.hardware_commands_for_operation("pre-media-operation")))

    async def test_production_populated_and_wrong_scopes_reject_without_close_or_signal(self):
        for scope in (_Scope(populated=True), _Scope(identity=ExecutionScopeIdentity("wrong-command", self.owner.generation))):
            with self.subTest(scope=scope), self.assertRaises(BackendUnavailable):
                self._production_reconcile(scope)
            self.assertFalse(scope.closed)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("launch_reserved", catalog.command("identify-pending").state)

    async def test_production_live_mount_rejects_before_scope_close(self):
        scope = _Scope()
        with self.assertRaises(BackendUnavailable):
            self._production_reconcile(scope, mounted=True)
        self.assertFalse(scope.closed)

    async def test_unrelated_process_name_is_outside_managed_reset_proof(self):
        # Reset proves the registered command ledger quiescent, not arbitrary
        # privileged processes outside the broker's managed execution scopes.
        scope = _Scope()
        self._production_reconcile(scope, ltfs_process=True)
        self.assertTrue(scope.closed)

    async def test_unreadable_unrelated_comm_does_not_block_exact_empty_scope(self):
        scope = _Scope()
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if path.name == "comm":
                raise PermissionError("unrelated SELinux process domain")
            return original_read(path, *args, **kwargs)
        with patch.object(Path, "read_text", read):
            self._production_reconcile(scope)
        self.assertTrue(scope.closed)

    async def test_known_current_boot_pid_unreadable_or_zombie_is_not_absence(self):
        process = ProcessIdentity(_read_boot_id(), 12345, 456, 12345)
        before, claim = self._ambiguous_command(process=process)
        original_open = Path.open
        # /proc stat fields: state, ppid, pgrp ... starttime. The exact zombie
        # still has durable ownership and is deliberately not treated as absent.
        zombie = "12345 (ltfs) " + " ".join(["Z", "1", "12345"] + ["0"] * 16 + ["456"]) + "\n"
        for evidence in (PermissionError("known PID unreadable"), zombie):
            def open_stat(path, *args, **kwargs):
                if str(path) == "/proc/12345/stat":
                    if isinstance(evidence, Exception):
                        raise evidence
                    import io
                    return io.BytesIO(evidence.encode("ascii"))
                return original_open(path, *args, **kwargs)
            scope = _Scope(identity=claim.scope, claim=claim)
            with self.subTest(evidence=type(evidence).__name__), patch.object(Path, "open", open_stat):
                with self.assertRaises((PermissionError, BackendUnavailable)):
                    self._production_reconcile(scope)
            self.assertFalse(scope.closed)
            with Catalog(self.paths.catalog_file) as catalog:
                self.assertEqual(before, catalog.command(before.id))

    async def test_production_late_phase_change_prevents_command_acknowledgement(self):
        def change_phase():
            with Catalog(self.paths.catalog_file) as catalog, catalog.transaction() as db:
                db.execute("UPDATE daemon_operations SET phase='writing' WHERE id='pre-media-operation'")
        scope = _Scope(after_close=change_phase)
        with self.assertRaises(CatalogError):
            self._production_reconcile(scope)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("launch_reserved", catalog.command("identify-pending").state)
            self.assertEqual("recovery_required", catalog.get_operation("pre-media-operation")["state"])

    async def test_production_known_process_appearing_after_close_keeps_blocker(self):
        before, claim = self._ambiguous_command()
        scope = _Scope(identity=claim.scope, claim=claim)
        # A tracked process becoming observable after close still invalidates
        # the receipt even though unrelated global process names are excluded.
        with patch("ltobackup.daemon.archive_runtime.LinuxProcessProbe.identities_and_groups_absent",
                   side_effect=[(True,), (True,), (False,)]):
            with self.assertRaises(BackendUnavailable):
                self._production_reconcile(scope, process_absent=None)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("recovery_required", catalog.get_operation("pre-media-operation")["state"])
            self.assertEqual(0, catalog.connection.execute("SELECT count(*) FROM command_quiescence_receipts").fetchone()[0])
