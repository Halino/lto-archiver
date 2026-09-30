from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stderr
from datetime import datetime, timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from httpx2 import ASGITransport, AsyncClient

from ltobackup.catalog import Catalog
from ltobackup.daemon.api import create_app
from ltobackup.daemon.api_models import OperationRequest
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.main import build_parser
from ltobackup.daemon.models import (
    CommandExitEvidence,
    CommandQuiescenceRequired,
    HardwareTargetBinding,
    MutationAdmissionClosed,
    ProcessIdentity,
    RecoveryAdmissionBlocked,
    SafeRecoveryResolution,
    StaleOperationFence,
    VerifiedPhysicalQuiescence,
)
from ltobackup.daemon.operations import OperationContext, OperationManager
from ltobackup.daemon.service import DaemonService, Principal
from ltobackup.linux_settings import LinuxPaths, LinuxSettings


class _BlockingOperation:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release_event = threading.Event()

    def __call__(self, _context: OperationContext) -> None:
        self.started.set()
        if not self.release_event.wait(10):
            raise TimeoutError("test operation was not released")

    def wait_until_started(self) -> None:
        if not self.started.wait(2):
            raise AssertionError("operation callback did not start")

    def release(self) -> None:
        self.release_event.set()


class _SequenceLifecycle:
    def __init__(self) -> None:
        self.events: list[str] = []

    def start(self) -> None:
        self.events.append("start")

    def wake(self) -> None:
        self.events.append("wake")

    def shutdown(self) -> None:
        self.events.append("shutdown")


class _BlockingStartupReconciler:
    def __init__(self) -> None:
        self.entered = threading.Event()
        self.release_event = threading.Event()

    def __call__(self, _operations: OperationManager) -> None:
        self.entered.set()
        if not self.release_event.wait(10):
            raise TimeoutError("startup reconciliation was not released")

    def wait_until_entered(self) -> None:
        if not self.entered.wait(2):
            raise AssertionError("startup reconciliation did not start")

    def release(self) -> None:
        self.release_event.set()


class _ReleasedCommandOperation:
    def __init__(self, database_path: Path, process: ProcessIdentity) -> None:
        self.database_path = database_path
        self.process = process
        self.command_released = threading.Event()
        self.release_event = threading.Event()
        self.finished = threading.Event()
        self.late_write_error: BaseException | None = None

    def __call__(self, context: OperationContext) -> None:
        with Catalog(self.database_path) as catalog:
            catalog.reserve_hardware_command(
                context.fence,
                "command-shutdown",
                "mount",
                "a" * 64,
            )
            catalog.record_blocked_process(
                "command-shutdown", context.fence, self.process
            )
            permit = "a" * 64
            catalog.authorize_hardware_command_release(
                "command-shutdown", context.fence, permit
            )
            catalog.confirm_hardware_command_released(
                "command-shutdown", context.fence, permit
            )
        self.command_released.set()
        if not self.release_event.wait(10):
            raise TimeoutError("released command callback was not released")
        try:
            context.record_phase_sample(
                "writing_manifest",
                "2026-08-21T12:00:01+00:00",
                0.25,
            )
        except StaleOperationFence as exc:
            self.late_write_error = exc
        finally:
            self.finished.set()

    def wait_until_command_released(self) -> None:
        if not self.command_released.wait(2):
            raise AssertionError("hardware command did not reach released state")

    def release(self) -> None:
        self.release_event.set()

    def wait_until_finished(self) -> None:
        if not self.finished.wait(2):
            raise AssertionError("released command callback did not finish")


class LinuxFoundationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.settings = LinuxSettings(
            state_dir=root / "state",
            socket_path=root / "run" / "daemon.sock",
            source_roots=(root / "source",),
            restore_roots=(root / "restore",),
        )
        self.paths = LinuxPaths.from_settings(self.settings)
        self.backups = BackupManager(
            self.paths.catalog_file,
            self.paths.backup_dir,
        )
        self.backups.prepare_and_initialize()
        self.executors: list[ThreadPoolExecutor] = []
        self.blocking_callbacks: list[
            _BlockingOperation | _ReleasedCommandOperation
        ] = []

    def tearDown(self) -> None:
        for callback in self.blocking_callbacks:
            callback.release()
        for executor in self.executors:
            executor.shutdown(wait=True, cancel_futures=True)

    def _manager(self, owner_id: str) -> OperationManager:
        with Catalog(self.paths.catalog_file) as catalog:
            fence = catalog.claim_daemon_owner(owner_id)
        executor = ThreadPoolExecutor(max_workers=1)
        self.executors.append(executor)
        return OperationManager(
            lambda: Catalog(self.paths.catalog_file),
            fence,
            executor=executor,
        )

    def _service(
        self,
        operations: OperationManager | None,
        *,
        callback=None,
        startup_reconciler=None,
        event_bus: EventBus | None = None,
        shutdown_timeout_seconds: float = 30.0,
        sequence_coordinator_factory=None,
    ) -> DaemonService:
        callbacks = None if callback is None else {"diagnostic": callback}
        options = {
            "operation_callbacks": callbacks,
            "startup_reconciler": startup_reconciler,
        }
        if shutdown_timeout_seconds != 30.0:
            options["shutdown_timeout_seconds"] = shutdown_timeout_seconds
        if sequence_coordinator_factory is not None:
            options["sequence_coordinator_factory"] = sequence_coordinator_factory
        return DaemonService(
            self.paths,
            self.settings,
            self.backups,
            operations,
            event_bus or EventBus(lambda: Catalog(self.paths.catalog_file)),
            **options,
        )

    def test_sequence_coordinator_starts_only_after_safe_startup_and_stops_first(self) -> None:
        """Lifecycle starts continuation after recovery and stops it before operations."""
        lifecycle = _SequenceLifecycle()
        operations = self._manager("daemon-sequence-lifecycle")
        service = self._service(
            operations,
            sequence_coordinator_factory=lambda _operations: lifecycle,
        )

        result = service.startup()
        self.assertTrue(result.safe_for_admission)
        self.assertEqual(["start", "wake"], lifecycle.events)

        service.shutdown(timeout_seconds=0.0)
        self.assertEqual(["start", "wake", "shutdown"], lifecycle.events)

    def _recovery_required_service(self, *, sequence_coordinator_factory=None):
        blocking = _BlockingOperation()
        self.blocking_callbacks.append(blocking)
        original = self._manager("daemon-before-recovery")
        operation = original.start(
            "catalog.test",
            "recovery-key",
            "admin",
            blocking,
        )
        blocking.wait_until_started()
        restarted_manager = self._manager("daemon-recovery")
        events = EventBus(lambda: Catalog(self.paths.catalog_file))
        restarted = self._service(
            restarted_manager,
            event_bus=events,
            sequence_coordinator_factory=sequence_coordinator_factory,
        )
        result = restarted.startup()
        self.assertEqual((operation.id,), result.admission_blocker_ids)
        return operation, restarted_manager, restarted, events

    def test_recovery_transition_starts_previously_blocked_sequence_coordinator(self) -> None:
        """A coordinator skipped during blocked startup starts once recovery becomes safe."""
        lifecycle = _SequenceLifecycle()
        operation, manager, service, _events = self._recovery_required_service(
            sequence_coordinator_factory=lambda _operations: lifecycle,
        )
        self.assertEqual([], lifecycle.events)
        resolution = self._hardware_free_resolution(operation.id, service)
        manager.resolve_recovery(operation.id, resolution)

        service._handle_recovery_transition(SimpleNamespace(quarantined_operation_ids=()))  # noqa: SLF001 - lifecycle transition seam

        self.assertEqual(["start", "wake"], lifecycle.events)
        service._handle_recovery_transition(SimpleNamespace(quarantined_operation_ids=()))  # noqa: SLF001 - idempotency seam
        self.assertEqual(["start", "wake", "wake"], lifecycle.events)
        service.shutdown(timeout_seconds=0.0)

    def test_manual_recovery_resolution_explicitly_wakes_sequence_coordinator(self) -> None:
        """Manual safe recovery does not wait for the coordinator poll interval."""
        operation, _manager, service, _events = self._recovery_required_service()
        lifecycle = _SequenceLifecycle()
        service._sequence_coordinator = lifecycle  # noqa: SLF001 - lifecycle seam

        service.resolve_recovery(operation.id, self._hardware_free_resolution(operation.id, service))

        self.assertEqual(["start", "wake"], lifecycle.events)
        service.shutdown(timeout_seconds=0.0)

    def _hardware_free_resolution(
        self,
        operation_id: str,
        service: DaemonService,
    ) -> SafeRecoveryResolution:
        with Catalog(self.paths.catalog_file) as catalog:
            command_receipt = catalog.create_command_quiescence_receipt(
                operation_id, service.daemon_fence
            )
            physical_receipt = catalog.create_physical_reconciliation_receipt(
                operation_id,
                service.daemon_fence,
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
        return SafeRecoveryResolution(
            reason_code="hardware-free-restart",
            command_receipt_id=command_receipt.id,
            physical_receipt_id=physical_receipt.id,
        )

    def test_default_worker_does_not_keep_python_alive_after_shutdown_timeout(
        self,
    ) -> None:
        script = textwrap.dedent(
            """
            import tempfile
            import threading
            from pathlib import Path

            from ltobackup.catalog import Catalog
            from ltobackup.daemon.api_models import OperationRequest
            from ltobackup.daemon.backups import BackupManager
            from ltobackup.daemon.events import EventBus
            from ltobackup.daemon.operations import OperationManager
            from ltobackup.daemon.service import DaemonService, Principal
            from ltobackup.linux_settings import LinuxPaths, LinuxSettings

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
                backups.prepare_and_initialize()
                with Catalog(paths.catalog_file) as catalog:
                    fence = catalog.claim_daemon_owner("subprocess-daemon")
                operations = OperationManager(
                    lambda: Catalog(paths.catalog_file),
                    fence,
                )
                entered = threading.Event()
                never_release = threading.Event()

                def block(_context):
                    entered.set()
                    never_release.wait(30)

                service = DaemonService(
                    paths,
                    settings,
                    backups,
                    operations,
                    EventBus(lambda: Catalog(paths.catalog_file)),
                    operation_callbacks={"diagnostic": block},
                )
                service.startup()
                service.start_operation(
                    OperationRequest(kind="diagnostic"),
                    "subprocess-block",
                    Principal("admin"),
                )
                assert entered.wait(2)
                service.shutdown(timeout_seconds=0.01)
                leaked = [
                    thread.name
                    for thread in threading.enumerate()
                    if thread is not threading.main_thread() and not thread.daemon
                ]
                assert leaked == [], leaked
                print("bounded-shutdown-ok", flush=True)
            """
        )
        environment = dict(os.environ)
        environment["PYTHONPATH"] = os.pathsep.join(
            value for value in ("src", environment.get("PYTHONPATH")) if value
        )
        started = time.monotonic()
        try:
            completed = subprocess.run(
                [sys.executable, "-c", script],
                cwd=Path(__file__).resolve().parents[1],
                env=environment,
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            self.fail(f"daemon process exceeded shutdown bound: {exc}")
        self.assertLess(time.monotonic() - started, 2.5)
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("bounded-shutdown-ok", completed.stdout)

    async def test_shutdown_timeout_is_cli_configurable_and_owned_by_lifespan(
        self,
    ) -> None:
        arguments = build_parser().parse_args(["--shutdown-timeout-seconds", "0.01"])
        self.assertEqual(0.01, arguments.shutdown_timeout_seconds)

        blocking = _BlockingOperation()
        self.blocking_callbacks.append(blocking)
        events = EventBus(lambda: Catalog(self.paths.catalog_file))
        service = self._service(
            self._manager("daemon-configured-timeout"),
            callback=blocking,
            event_bus=events,
            shutdown_timeout_seconds=arguments.shutdown_timeout_seconds,
        )
        app = create_app(service)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        operation = service.start_operation(
            OperationRequest(kind="diagnostic"),
            "configured-timeout",
            Principal("admin"),
        )
        blocking.wait_until_started()

        started = time.monotonic()
        await lifespan.__aexit__(None, None, None)

        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual("recovery_required", service.operation(operation.id).state)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            events.publish("state.patch", {})

    def test_daemon_log_reader_socket_is_cli_configurable(self) -> None:
        arguments = build_parser().parse_args(
            ["--log-reader-socket", "/run/private-reader/control.sock"]
        )

        self.assertEqual(
            Path("/run/private-reader/control.sock"), arguments.log_reader_socket
        )

    def test_shutdown_timeout_validation_uses_platform_threading_bound(self) -> None:
        accepted = build_parser().parse_args(
            ["--shutdown-timeout-seconds", repr(threading.TIMEOUT_MAX)]
        )
        self.assertEqual(threading.TIMEOUT_MAX, accepted.shutdown_timeout_seconds)
        self._service(None, shutdown_timeout_seconds=threading.TIMEOUT_MAX)

        for invalid in (
            -1.0,
            float("inf"),
            float("-inf"),
            float("nan"),
            True,
            threading.TIMEOUT_MAX * 2,
            1e20,
        ):
            with self.subTest(service_value=invalid), self.assertRaises(ValueError):
                self._service(None, shutdown_timeout_seconds=invalid)

        for invalid_text in ("-1", "inf", "-inf", "nan", "1e20"):
            with (
                self.subTest(cli_value=invalid_text),
                redirect_stderr(StringIO()),
                self.assertRaises(SystemExit),
            ):
                build_parser().parse_args(
                    [f"--shutdown-timeout-seconds={invalid_text}"]
                )

    def test_unsafe_shutdown_override_is_rejected_before_terminal_transition(
        self,
    ) -> None:
        service = self._service(self._manager("daemon-timeout-override"))
        service.startup()

        with self.assertRaises(ValueError):
            service.shutdown(timeout_seconds=1e20)

        self.assertTrue(service.status().accepting_mutations)
        operation = service.start_operation(
            OperationRequest(kind="diagnostic"),
            "after-rejected-timeout",
            Principal("admin"),
        )
        self.assertEqual("after-rejected-timeout", operation.idempotency_key)
        service.shutdown(timeout_seconds=0)

    async def test_shutdown_is_terminal_for_recovery_resolution_and_event_bus(
        self,
    ) -> None:
        operation, _manager, service, events = self._recovery_required_service()
        resolution = self._hardware_free_resolution(operation.id, service)

        service.shutdown(timeout_seconds=0)

        with self.assertRaises(MutationAdmissionClosed):
            service.resolve_recovery(operation.id, resolution)
        with self.assertRaises(MutationAdmissionClosed):
            service.start_operation(
                OperationRequest(kind="diagnostic"),
                "after-terminal-shutdown",
                Principal("admin"),
            )
        self.assertEqual("recovery_required", service.operation(operation.id).state)
        self.assertFalse(service.status().accepting_mutations)
        with self.assertRaisesRegex(RuntimeError, "closed"):
            events.publish("state.patch", {})

    async def test_shutdown_during_startup_cannot_reopen_admission(self) -> None:
        reconciliation = _BlockingStartupReconciler()
        events = EventBus(lambda: Catalog(self.paths.catalog_file))
        service = self._service(
            None,
            startup_reconciler=reconciliation,
            event_bus=events,
        )
        startup_thread = threading.Thread(target=service.startup)
        startup_thread.start()
        reconciliation.wait_until_entered()

        service.shutdown(timeout_seconds=0)
        reconciliation.release()
        startup_thread.join(2)

        self.assertFalse(startup_thread.is_alive())
        self.assertFalse(service.status().accepting_mutations)
        with self.assertRaises(MutationAdmissionClosed):
            service.start_operation(
                OperationRequest(kind="diagnostic"),
                "after-startup-shutdown-race",
                Principal("admin"),
            )
        with self.assertRaisesRegex(RuntimeError, "closed"):
            events.publish("state.patch", {})

    async def test_mutation_before_startup_claims_catalog_returns_admission_closed(
        self,
    ) -> None:
        prepare_entered = threading.Event()
        prepare_release = threading.Event()
        real_prepare = self.backups.prepare_and_initialize

        def blocking_prepare() -> None:
            prepare_entered.set()
            if not prepare_release.wait(10):
                raise TimeoutError("catalog preparation was not released")
            real_prepare()

        service = self._service(None)
        startup_thread = threading.Thread(target=service.startup)
        with patch.object(
            self.backups,
            "prepare_and_initialize",
            side_effect=blocking_prepare,
        ):
            startup_thread.start()
            self.assertTrue(prepare_entered.wait(2))
            try:
                with self.assertRaises(MutationAdmissionClosed):
                    service.start_operation(
                        OperationRequest(kind="diagnostic"),
                        "before-catalog-owner",
                        Principal("admin"),
                    )
            finally:
                prepare_release.set()
                startup_thread.join(2)
        self.assertFalse(startup_thread.is_alive())
        service.shutdown(timeout_seconds=0)

    async def test_shutdown_wins_concurrent_recovery_blocker_recomputation(
        self,
    ) -> None:
        operation, manager, service, events = self._recovery_required_service()
        resolution = self._hardware_free_resolution(operation.id, service)
        reconcile_entered = threading.Event()
        reconcile_release = threading.Event()
        shutdown_request_recorded = threading.Event()
        shutdown_finished = threading.Event()
        resolve_errors = []
        shutdown_errors = []
        start_accepting_calls = []
        real_reconcile = manager.reconcile_admission_blockers
        real_start_accepting = manager.start_accepting
        real_request_shutdown = service._shutdown_requested.set

        def blocking_reconcile():
            reconcile_entered.set()
            if not reconcile_release.wait(10):
                raise TimeoutError("recovery blocker recomputation was not released")
            return real_reconcile()

        def observed_start_accepting():
            start_accepting_calls.append("called")
            return real_start_accepting()

        def observed_request_shutdown() -> None:
            real_request_shutdown()
            shutdown_request_recorded.set()

        def resolve() -> None:
            try:
                service.resolve_recovery(operation.id, resolution)
            except Exception as exc:  # noqa: BLE001 - preserve thread failure for assertion.
                resolve_errors.append(exc)

        def shutdown() -> None:
            try:
                service.shutdown(timeout_seconds=0)
            except Exception as exc:  # noqa: BLE001 - preserve thread failure for assertion.
                shutdown_errors.append(exc)
            finally:
                shutdown_finished.set()

        with (
            patch.object(
                manager,
                "reconcile_admission_blockers",
                side_effect=blocking_reconcile,
            ),
            patch.object(
                manager, "start_accepting", side_effect=observed_start_accepting
            ),
            patch.object(
                service._shutdown_requested,
                "set",
                side_effect=observed_request_shutdown,
            ),
        ):
            resolve_thread = threading.Thread(target=resolve)
            resolve_thread.start()
            self.assertTrue(reconcile_entered.wait(2))
            shutdown_thread = threading.Thread(target=shutdown)
            shutdown_thread.start()
            self.assertTrue(shutdown_request_recorded.wait(2))
            reconcile_release.set()
            resolve_thread.join(2)
            shutdown_thread.join(2)

        self.assertFalse(resolve_thread.is_alive())
        self.assertFalse(shutdown_thread.is_alive())
        self.assertEqual([], resolve_errors)
        self.assertEqual([], shutdown_errors)
        self.assertEqual([], start_accepting_calls)
        self.assertFalse(service.status().accepting_mutations)
        with self.assertRaises(MutationAdmissionClosed):
            service.start_operation(
                OperationRequest(kind="diagnostic"),
                "after-recovery-shutdown-race",
                Principal("admin"),
            )
        with self.assertRaisesRegex(RuntimeError, "closed"):
            events.publish("state.patch", {})

    async def test_api_disconnect_does_not_cancel_and_restart_reconciles_before_admission(
        self,
    ) -> None:
        blocking = _BlockingOperation()
        self.blocking_callbacks.append(blocking)
        original = self._service(self._manager("daemon-original"), callback=blocking)
        original.startup()
        app = create_app(original)
        app.dependency_overrides[original.principals.require_operator] = lambda: (
            Principal("admin", role="admin")
        )

        client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://testserver",
        )
        response = await client.post(
            "/api/v1/operations",
            headers={"Idempotency-Key": "restart-key"},
            json={"kind": "diagnostic"},
        )
        await client.aclose()
        self.assertEqual(202, response.status_code)
        operation_id = response.json()["id"]
        blocking.wait_until_started()
        self.assertEqual("running", original.operation(operation_id).state)

        reconciliation = _BlockingStartupReconciler()
        restarted = self._service(None, startup_reconciler=reconciliation)
        startup_result = []
        startup_error = []

        def run_startup() -> None:
            try:
                startup_result.append(restarted.startup())
            except Exception as exc:  # noqa: BLE001 - preserve thread failure for assertion.
                startup_error.append(exc)

        startup_thread = threading.Thread(target=run_startup)
        startup_thread.start()
        reconciliation.wait_until_entered()
        self.assertEqual("recovery_required", restarted.operation(operation_id).state)
        self.assertEqual(operation_id, restarted.replay("restart-key").id)
        with self.assertRaises(MutationAdmissionClosed):
            restarted.start_operation(
                OperationRequest(kind="diagnostic"),
                "new-during-reconciliation",
                Principal("admin"),
            )

        reconciliation.release()
        startup_thread.join(2)
        self.assertFalse(startup_thread.is_alive())
        self.assertEqual([], startup_error)
        self.assertFalse(startup_result[0].safe_for_admission)
        self.assertEqual((operation_id,), startup_result[0].admission_blocker_ids)
        self.assertEqual(operation_id, restarted.replay("restart-key").id)
        self.assertEqual(
            operation_id,
            restarted.start_operation(
                OperationRequest(kind="diagnostic"),
                "restart-key",
                Principal("admin"),
            ).id,
        )
        with self.assertRaises(RecoveryAdmissionBlocked) as caught:
            restarted.start_operation(
                OperationRequest(kind="diagnostic"),
                "new-after-reconciliation",
                Principal("admin"),
            )
        self.assertEqual(operation_id, caught.exception.active.id)

        with Catalog(self.paths.catalog_file) as catalog:
            command_receipt = catalog.create_command_quiescence_receipt(
                operation_id, restarted.daemon_fence
            )
            physical_receipt = catalog.create_physical_reconciliation_receipt(
                operation_id,
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
        restarted.resolve_recovery(
            operation_id,
            SafeRecoveryResolution(
                reason_code="hardware-free-restart",
                command_receipt_id=command_receipt.id,
                physical_receipt_id=physical_receipt.id,
            ),
        )
        accepted = restarted.start_operation(
            OperationRequest(kind="diagnostic"),
            "new-after-resolution",
            Principal("admin"),
        )
        self.assertEqual("new-after-resolution", accepted.idempotency_key)
        self.assertTrue(restarted.status().accepting_mutations)

        original.shutdown(timeout_seconds=0)
        blocking.release()
        restarted.shutdown(timeout_seconds=2)

    async def test_shutdown_timeout_fences_worker_and_preserves_command_ledger_blocker(
        self,
    ) -> None:
        manager = self._manager("daemon-shutdown")
        service = self._service(manager)
        service.startup()
        process = ProcessIdentity("boot-test", 4321, 991, 4321)
        callback = _ReleasedCommandOperation(self.paths.catalog_file, process)
        self.blocking_callbacks.append(callback)
        source_root = self.settings.source_roots[0]
        source_root.mkdir(parents=True, exist_ok=True)
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.add_library("LIB-SYNTHETIC", "Synthetic library", str(source_root))
            catalog.create_automatic_job(
                "JOB-SYNTHETIC",
                "LIB-SYNTHETIC",
                "synthetic-drive",
                "/synthetic/mount",
                [("SY0001", "SERIAL-1", 1, 1)],
                force_format=True,
            )
        target = HardwareTargetBinding.from_verified_inputs(
            self.paths.state_dir.parent / "synthetic-mount",
            "synthetic-tape",
            "synthetic-scsi",
            ("archive.resume", "JOB-SYNTHETIC", "1", "MEDIA-1", "", ""),
        )
        operation = manager.start(
            "archive.resume",
            "shutdown-key",
            "admin",
            callback,
            job_id="JOB-SYNTHETIC",
            cassette_sequence=1,
            hardware_target=target,
        )
        callback.wait_until_command_released()

        started = time.monotonic()
        service.shutdown(timeout_seconds=0.01)
        self.assertLess(time.monotonic() - started, 1.0)
        self.assertEqual("recovery_required", manager.operation(operation.id).state)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("released", catalog.command("command-shutdown").state)
        with self.assertRaises(MutationAdmissionClosed):
            manager.start(
                "catalog.test", "after-shutdown", "admin", lambda _context: None
            )

        restarted = self._service(None)
        result = restarted.startup()
        self.assertFalse(result.safe_for_admission)
        self.assertEqual((operation.id,), result.admission_blocker_ids)
        with self.assertRaises(RecoveryAdmissionBlocked):
            restarted.start_operation(
                OperationRequest(kind="diagnostic"),
                "blocked-by-command-ledger",
                Principal("admin"),
            )

        callback.release()
        callback.wait_until_finished()
        self.assertIsInstance(callback.late_write_error, StaleOperationFence)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("released", catalog.command("command-shutdown").state)
            with self.assertRaises(CommandQuiescenceRequired):
                catalog.create_command_quiescence_receipt(
                    operation.id, restarted.daemon_fence
                )
            released_at = catalog.command("command-shutdown").released_at
            quiesced_at = (
                datetime.fromisoformat(released_at) + timedelta(microseconds=1)
            ).isoformat()
            catalog.acknowledge_command_quiescence(
                "command-shutdown",
                restarted.daemon_fence,
                CommandExitEvidence(
                    command_id="command-shutdown",
                    process=process,
                    outcome="terminated",
                    quiesced_at=quiesced_at,
                ),
            )
            command_receipt = catalog.create_command_quiescence_receipt(
                operation.id, restarted.daemon_fence
            )
            physical_receipt = catalog.create_physical_reconciliation_receipt(
                operation.id,
                restarted.daemon_fence,
                command_receipt.id,
                VerifiedPhysicalQuiescence(
                    target=target,
                    observed_media_identity_sha256=None,
                    mounted=False,
                    media_loaded=False,
                    drive_busy=False,
                    related_processes=(),
                ),
            )
        restarted.resolve_recovery(
            operation.id,
            SafeRecoveryResolution(
                reason_code="command-and-drive-quiescent",
                command_receipt_id=command_receipt.id,
                physical_receipt_id=physical_receipt.id,
            ),
        )
        self.assertTrue(restarted.status().accepting_mutations)
        restarted.shutdown(timeout_seconds=2)


if __name__ == "__main__":
    unittest.main()
