from __future__ import annotations

import hashlib
import sqlite3
import os
import secrets
import signal
import stat
import sys
import tempfile
import threading
import time
import unittest
from collections.abc import Callable, Iterable
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import call, patch

from ltobackup.catalog import Catalog
from ltobackup.daemon.models import (
    CommandQuiescenceRequired,
    HardwareTargetBinding,
    OperationFence,
    OperationRecord,
    RecoveryCommandFence,
    ProcessIdentity,
    SafeRecoveryResolution,
)
from ltobackup.operational_log import (
    OperationalCorrelation,
    OperationalEvent,
)
from ltobackup.tape import command_supervisor as command_supervisor_module
from ltobackup.tape.command_supervisor import (
    CgroupV2ExecutionScope,
    CgroupV2ExecutionScopeManager,
    CommandError,
    CommandFailed,
    CommandTimeout,
    CompletedCommand,
    ExecutionScopeIdentity,
    ForkExecCommandLauncher,
    LinuxProcessProbe,
    PosixProcessTerminator,
    ProcessGroupExecutionScopeManager,
    ProcessObservation,
    ProcessQuiescenceTimeout,
    ReadOnlyCgroupPrivilegeBoundary,
    SecretArgument,
    SnapshotProcessProbe,
    TestOnlyForkExecCommandLauncher,
    TrackedCommandSupervisor,
    redacted_argv_sha256,
)


def _target() -> HardwareTargetBinding:
    return HardwareTargetBinding.from_verified_inputs(
        Path("/synthetic/mount-a"),
        "synthetic-tape-a",
        "synthetic-scsi-a",
        ("archive.resume", "JOB-SYNTHETIC", "4", "media-a", "", ""),
    )


def _read_available(fd: int) -> bytes:
    try:
        return os.read(fd, 1)
    except BlockingIOError:
        return b""


class FakeScope:
    def __init__(self, identity: ExecutionScopeIdentity, leader_pid: int) -> None:
        self.identity = identity
        self.leader_pid = leader_pid
        self.members: tuple[int, ...] = (leader_pid,)
        self.closed = False
        self.observed_release_permits: set[str] = set()
        self.revoked_release_permits: set[str] = set()
        self.release_claim_error: BaseException | None = None

    def member_pids(self) -> tuple[int, ...]:
        return self.members

    def is_populated(self) -> bool:
        return bool(self.members)

    def signal(self, signum: int) -> None:
        self.members = ()

    def close(self) -> None:
        if self.members:
            raise ProcessQuiescenceTimeout("fake scope is not empty")
        self.closed = True

    def claim_unreleased(self, pid: int, permit_sha256: str):
        if self.release_claim_error is not None:
            raise self.release_claim_error
        if pid != self.leader_pid:
            raise CommandError("synthetic release claim pid mismatch")
        released = permit_sha256 in self.observed_release_permits
        if not released:
            self.revoked_release_permits.add(permit_sha256)
        return command_supervisor_module.CommandReleaseClaim(
            self.identity,
            self.leader_pid,
            permit_sha256,
            released,
            not released,
        )

    def on_process_exit(self) -> None:
        self.members = ()


class TestOnlySameUidPrivilegeBoundary:
    """Allows hardware-free wrapper tests; never valid for production wiring."""

    def validate_supervisor(self) -> None:
        return None

    def prepare_scope(self, scope) -> None:
        return None

    def enter_child(self) -> None:
        return None

    def prepare_release(self, scope, pid: int) -> str:
        encoded = (
            f"{scope.identity.command_id}:{scope.identity.owner_generation}:{pid}:"
            f"{secrets.token_hex(32)}"
        ).encode("ascii")
        self._test_release_permit = hashlib.sha256(encoded).hexdigest()
        self._test_release_completed = False
        self._test_release_scope = scope.identity
        self._test_release_pid = pid
        return self._test_release_permit

    def release(self, scope, pid: int, permit_sha256: str, release_fd: int) -> None:
        del scope, pid
        if permit_sha256 != self._test_release_permit:
            raise CommandError("test release permit changed")
        os.write(release_fd, b"1")
        self._test_release_completed = True

    def claim_unreleased(self, scope, pid: int, permit_sha256: str):
        del scope
        released = (
            permit_sha256 == self._test_release_permit and self._test_release_completed
        )
        return command_supervisor_module.CommandReleaseClaim(
            self._test_release_scope,
            pid,
            permit_sha256,
            released,
            not released,
        )


class ReceiptBroker:
    """Test broker exercising the client contract without a cgroup or IPC."""

    def __init__(
        self,
        *,
        attach_noop: bool = False,
        command_id_override: str | None = None,
        generation_override: int | None = None,
        scope_id: str = "broker-scope-a",
        substitute_on_validate: bool = False,
        copy_request_proof: bool = False,
    ) -> None:
        self.attach_noop = attach_noop
        self.command_id_override = command_id_override
        self.generation_override = generation_override
        self.scope_id = scope_id
        self.substitute_on_validate = substitute_on_validate
        self.copy_request_proof = copy_request_proof
        self.members: tuple[int, ...] = ()
        self.populated = False
        self.revoked = False
        self.receipt_serial = 0
        self.validation_serial = 0
        self.release_serial = 0
        self.killed: list[str] = []
        self.released: list[str] = []
        self.release_permits: dict[str, tuple[tuple[str, int, str, str], int, str]] = {}
        self.release_lock = threading.Lock()
        self.after_unreleased_check: Callable[[], None] = lambda: None

    def create_scope(self, *args):
        if len(args) == 2:
            return self.scope_id
        identity, request_nonce, _supplied_capability = args
        return self._receipt(identity, request_nonce)

    def open_scope(self, *args):
        if len(args) == 2:
            return self.scope_id
        identity, request_nonce, _supplied_capability = args
        return self._receipt(identity, request_nonce)

    def _receipt(self, identity, request_nonce):
        self.receipt_serial += 1
        command_id = self.command_id_override or identity.command_id
        generation = (
            self.generation_override
            if self.generation_override is not None
            else identity.owner_generation
        )
        broker_nonce = (
            request_nonce
            if self.copy_request_proof
            else self.receipt_serial.to_bytes(32, "big")
        )
        broker_proof = (
            request_nonce
            if self.copy_request_proof
            else b"p" * 31 + bytes((self.receipt_serial % 251 + 1,))
        )
        return command_supervisor_module.BrokeredCgroupScopeReceipt(
            protocol_version=1,
            command_id=command_id,
            owner_generation=generation,
            request_nonce=request_nonce,
            scope_id=self.scope_id,
            scope_path_sha256="a" * 64,
            broker_nonce=broker_nonce,
            broker_proof=broker_proof,
            recursive_population=True,
            recursive_members=True,
            cgroup_kill=True,
        )

    def attach(self, receipt, pid: int, supplied_capability) -> None:
        if not self.attach_noop:
            self.members = (pid,)
            self.populated = True

    def validate_scope(self, receipt, challenge, supplied_capability):
        if self.revoked:
            raise RuntimeError("synthetic broker revocation")
        self.validation_serial += 1
        observed_receipt = (
            replace(receipt, scope_id="substituted-scope")
            if self.substitute_on_validate
            else receipt
        )
        return command_supervisor_module.BrokeredCgroupScopeValidation(
            protocol_version=1,
            receipt=observed_receipt,
            challenge=challenge,
            validation_nonce=self.validation_serial.to_bytes(32, "big"),
            broker_proof=b"v" * 31 + bytes((self.validation_serial % 251 + 1,)),
            populated=self.populated,
            member_pids=self.members,
        )

    def prepare_release(self, receipt, pid, request_nonce, supplied_capability):
        del supplied_capability
        if self.revoked:
            raise RuntimeError("synthetic broker revocation")
        if not self.populated or pid not in self.members:
            raise RuntimeError("synthetic scope membership missing")
        self.release_serial += 1
        permit = command_supervisor_module.BrokeredCgroupReleasePermit(
            protocol_version=1,
            receipt=receipt,
            pid=pid,
            request_nonce=request_nonce,
            permit_nonce=self.release_serial.to_bytes(32, "big"),
            broker_proof=b"r" * 31 + bytes((self.release_serial % 251 + 1,)),
        )
        digest = command_supervisor_module._broker_release_permit_sha256(permit)
        with self.release_lock:
            self.release_permits[digest] = (
                self._stable_scope(receipt),
                pid,
                "prepared",
            )
        return permit

    def release_child(
        self, receipt, permit, pid: int, release_fd: int, supplied_capability
    ) -> None:
        del supplied_capability
        if self.revoked:
            raise RuntimeError("synthetic broker revocation")
        digest = command_supervisor_module._broker_release_permit_sha256(permit)
        with self.release_lock:
            if self.release_permits.get(digest) != (
                self._stable_scope(receipt),
                pid,
                "prepared",
            ):
                raise RuntimeError("synthetic release permit mismatch")
            if not self.populated or pid not in self.members:
                raise RuntimeError("synthetic scope membership missing")
            os.write(release_fd, b"1")
            self.release_permits[digest] = (
                self._stable_scope(receipt),
                pid,
                "released",
            )

    def claim_unreleased(
        self,
        receipt,
        pid: int,
        permit_sha256: str,
        challenge,
        supplied_capability,
    ):
        del supplied_capability
        if self.revoked:
            raise RuntimeError("synthetic broker revocation")
        with self.release_lock:
            recorded = self.release_permits.get(permit_sha256)
            exact = (self._stable_scope(receipt), pid)
            if recorded is None or recorded[:2] != exact:
                raise RuntimeError("synthetic release permit mismatch")
            if recorded[2] == "prepared":
                released = False
                permit_revoked = True
                self.release_permits[permit_sha256] = (*exact, "revoked")
            elif recorded[2] == "revoked":
                released = False
                permit_revoked = True
            elif recorded[2] == "released":
                released = True
                permit_revoked = False
            else:
                raise RuntimeError("synthetic release permit state is invalid")
            self.validation_serial += 1
            claim = command_supervisor_module.BrokeredCgroupReleaseClaim(
                protocol_version=1,
                receipt=receipt,
                pid=pid,
                permit_sha256=permit_sha256,
                challenge=challenge,
                claim_nonce=self.validation_serial.to_bytes(32, "big"),
                broker_proof=b"q" * 31 + bytes((self.validation_serial % 251 + 1,)),
                released=released,
                permit_revoked=permit_revoked,
            )
        if permit_revoked:
            self.after_unreleased_check()
        return claim

    @staticmethod
    def _stable_scope(receipt) -> tuple[str, int, str, str]:
        return (
            receipt.command_id,
            receipt.owner_generation,
            receipt.scope_id,
            receipt.scope_path_sha256,
        )

    def member_pids(self, handle: str, supplied_capability) -> tuple[int, ...]:
        return self.members

    def is_populated(self, handle: str, supplied_capability) -> bool:
        return self.populated

    def signal_scope(self, receipt, signum: int, supplied_capability) -> None:
        self.members = ()
        self.populated = False

    def kill_scope(self, receipt, supplied_capability) -> None:
        self.killed.append(self.scope_id)
        self.members = ()
        self.populated = False

    def release_scope(self, receipt, supplied_capability) -> None:
        self.released.append(self.scope_id)


class FakeGate:
    def __init__(
        self,
        identity: ProcessIdentity,
        result: CompletedCommand | BaseException | None = None,
    ) -> None:
        self.identity = identity
        self.result = result or CompletedCommand(0, "", "")
        self.released = False
        self.prepared = False
        self.aborted = False
        self.termination_calls: list[tuple[float, float]] = []
        self.wait_calls: list[float] = []
        self.on_release: Callable[[], None] = lambda: None
        self.on_prepare_release: Callable[[], None] = lambda: None
        self.prepare_error: BaseException | None = None
        self.release_error_before_write: BaseException | None = None
        self.release_error_after_write: BaseException | None = None
        self.release_claim_error: BaseException | None = None
        self.permit_sha256 = hashlib.sha256(
            f"fake:{identity.boot_id}:{identity.pid}:{identity.start_ticks}".encode(
                "ascii"
            )
        ).hexdigest()
        self.scope = FakeScope(ExecutionScopeIdentity("pending", 0), identity.pid)

    def prepare_release(self) -> str:
        self.on_prepare_release()
        if self.prepare_error is not None:
            raise self.prepare_error
        self.prepared = True
        return self.permit_sha256

    def release(self, permit_sha256: str | None = None) -> None:
        self.on_release()
        if self.release_error_before_write is not None:
            raise self.release_error_before_write
        if permit_sha256 is not None and permit_sha256 != self.permit_sha256:
            raise CommandError("synthetic release permit mismatch")
        if permit_sha256 in getattr(self.scope, "revoked_release_permits", ()):
            raise CommandError("synthetic release permit was revoked")
        self.released = True
        if permit_sha256 is not None and hasattr(
            self.scope, "observed_release_permits"
        ):
            self.scope.observed_release_permits.add(permit_sha256)
        if self.release_error_after_write is not None:
            raise self.release_error_after_write

    def claim_unreleased(self, permit_sha256: str):
        if self.release_claim_error is not None:
            raise self.release_claim_error
        if permit_sha256 != self.permit_sha256:
            raise CommandError("synthetic release permit mismatch")
        return self.scope.claim_unreleased(self.identity.pid, permit_sha256)

    def abort_before_release(self) -> None:
        self.aborted = True

    def wait(self, timeout: float) -> CompletedCommand:
        self.wait_calls.append(timeout)
        if isinstance(self.result, BaseException):
            raise self.result
        if hasattr(self.scope, "on_process_exit"):
            self.scope.on_process_exit()
        return self.result

    def abort_and_wait(self, timeout: float) -> CompletedCommand:
        self.abort_before_release()
        return self.wait(timeout)

    def terminate_group(self, term_timeout: float, kill_timeout: float) -> None:
        self.termination_calls.append((term_timeout, kill_timeout))
        self.scope.signal(signal.SIGKILL)


class FakeLauncher:
    def __init__(self, gates: Iterable[FakeGate]) -> None:
        self.gates = iter(gates)
        self.argv: list[tuple[str, ...]] = []
        self.scopes: dict[ExecutionScopeIdentity, object] = {}

    def launch_blocked(
        self,
        argv: tuple[str, ...],
        scope_identity: ExecutionScopeIdentity,
        pass_fds: tuple[int, ...] = (),
    ) -> FakeGate:
        self.argv.append(argv)
        gate = next(self.gates)
        gate.scope.identity = scope_identity
        self.scopes[scope_identity] = gate.scope
        return gate

    def open_scope(self, identity: ExecutionScopeIdentity):
        if identity not in self.scopes:
            scope = FakeScope(identity, -1)
            scope.members = ()
            self.scopes[identity] = scope
        return self.scopes[identity]


class FakeProcessProbe:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.identities: list[ProcessIdentity] = []

    def await_identity_and_group_absent(
        self, identity: ProcessIdentity, timeout: float
    ) -> str:
        self.identities.append(identity)
        if self.fail:
            raise ProcessQuiescenceTimeout(
                "supervised process did not become quiescent"
            )
        return datetime.now(UTC).isoformat(timespec="microseconds")

    def exact_identity_present(self, expected: ProcessIdentity) -> bool:
        return not self.fail

    def identity_and_group_absent(self, expected: ProcessIdentity) -> bool:
        return not self.fail

    def assert_scope_intact(self, expected: ProcessIdentity) -> None:
        if self.fail:
            raise ProcessQuiescenceTimeout("fake scope is not intact")


class FakeTerminator:
    def __init__(self) -> None:
        self.calls: list[tuple[ProcessIdentity, float, float]] = []

    def terminate_group(
        self, identity: ProcessIdentity, term_timeout: float, kill_timeout: float
    ) -> None:
        self.calls.append((identity, term_timeout, kill_timeout))


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class CommandSupervisorTests(unittest.TestCase):
    def test_prelaunch_failure_diagnostics_include_elapsed_time(self) -> None:
        events = []
        sink = type("Sink", (), {"emit": lambda _self, event: events.append(event)})()
        supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)), event_sink=sink)

        def fail_launch(argv, identity, pass_fds):
            scope = FakeScope(identity, -1)
            scope.members = ()
            supervisor.launcher.scopes[identity] = scope
            raise command_supervisor_module.ScopeExchangeError("created", "timeout")

        with patch.object(supervisor.launcher, "launch_blocked", side_effect=fail_launch), patch.object(command_supervisor_module.time, "sleep"), self.assertRaises(CommandError):
            supervisor.reserve_and_launch_blocked(self.fence, "identify", ("identify",))
        self.assertEqual(3, len(events))
        for event in events:
            self.assertEqual("ltfs.launch.timeout", event.code)
            self.assertIsInstance(event.elapsed_ms, int)
            self.assertGreaterEqual(event.elapsed_ms, 0)

    def test_prelaunch_retries_are_bounded_and_restricted_to_readonly_probes(self) -> None:
        for kind, reason, expected in (("identify", "timeout", 3), ("probe_media", "eof", 3), ("format", "timeout", 1), ("mount", "transport", 1), ("identify", "protocol", 1), ("identify", "rejected", 1)):
            with self.subTest(kind=kind, reason=reason):
                supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)))
                attempts = []

                def fail_launch(argv, identity, pass_fds):
                    attempts.append(identity)
                    scope = FakeScope(identity, -1)
                    scope.members = ()
                    supervisor.launcher.scopes[identity] = scope
                    raise command_supervisor_module.ScopeExchangeError("created", reason)

                with patch.object(supervisor.launcher, "launch_blocked", side_effect=fail_launch), patch.object(command_supervisor_module.time, "sleep"), self.assertRaises(CommandError):
                    supervisor.reserve_and_launch_blocked(self.fence, kind, (kind,))
                self.assertEqual(expected, len(attempts))
                for identity in attempts:
                    command = self.catalog.command(identity.command_id)
                    self.assertEqual("quiesced", command.state)
                    self.assertEqual("launch_aborted", command.exit_outcome)
                    self.assertIsNone(command.release_permit_sha256)

    def test_unproven_scope_prevents_retry_and_preserves_reservation(self) -> None:
        supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)))
        attempts = []

        def fail_launch(argv, identity, pass_fds):
            attempts.append(identity)
            raise command_supervisor_module.ScopeExchangeError("created", "timeout")

        with patch.object(supervisor.launcher, "launch_blocked", side_effect=fail_launch), patch.object(supervisor.launcher, "open_scope", side_effect=command_supervisor_module.ScopeExchangeError("opened", "timeout")) as open_scope, patch.object(command_supervisor_module.time, "sleep"), self.assertRaises(CommandError):
            supervisor.reserve_and_launch_blocked(self.fence, "identify", ("identify",))
        self.assertEqual(1, len(attempts))
        self.assertEqual(3, open_scope.call_count)
        self.assertEqual("launch_reserved", self.catalog.command(attempts[0].command_id).state)

    def test_scope_exchange_preserves_only_closed_diagnostic_reason(self) -> None:
        capability = command_supervisor_module.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        for supplied, expected in (("timeout", "timeout"), ("secret/socket/path", "unavailable")):
            failure = RuntimeError("secret internal broker details")
            failure.reason = supplied
            manager = command_supervisor_module.BrokeredCgroupExecutionScopeManager(broker, capability)
            with patch.object(broker, "create_scope", side_effect=failure), self.assertRaises(CommandError) as caught:
                manager.create(ExecutionScopeIdentity("diagnostic", 4))
            self.assertEqual(expected, getattr(caught.exception, "reason", None))
            self.assertNotIn("secret", str(caught.exception))

    def test_transient_prelaunch_failure_retries_only_after_exact_scope_quiescence(self) -> None:
        capability = command_supervisor_module.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        failure = RuntimeError("private transport detail")
        failure.reason = "timeout"
        manager = command_supervisor_module.BrokeredCgroupExecutionScopeManager(broker, capability)
        with patch.object(broker, "create_scope", side_effect=failure), self.assertRaises(CommandError) as caught:
            manager.create(ExecutionScopeIdentity("diagnostic", 4))
        transient = caught.exception
        supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)))
        launcher = supervisor.launcher
        original_launch = launcher.launch_blocked
        attempted = []

        def launch(argv, identity, pass_fds):
            attempted.append(identity)
            if len(attempted) == 1:
                scope = FakeScope(identity, -1)
                scope.members = ()
                launcher.scopes[identity] = scope
                raise transient
            previous = self.catalog.command(attempted[0].command_id)
            self.assertEqual("quiesced", previous.state)
            self.assertEqual("launch_aborted", previous.exit_outcome)
            self.assertTrue(launcher.scopes[attempted[0]].closed)
            return original_launch(argv, identity, pass_fds)

        with patch.object(launcher, "launch_blocked", side_effect=launch), patch.object(command_supervisor_module.time, "sleep"):
            try:
                command_id = supervisor.reserve_and_launch_blocked(self.fence, "identify", ("identify",))
            except CommandError as exc:
                self.fail(f"proven transient prelaunch failure was not retried: {exc}")
        self.assertEqual(2, len(attempted))
        self.assertEqual("launch_blocked", self.catalog.command(command_id).state)

    def test_wrong_returned_gate_is_never_aborted_or_signalled_during_cleanup(self) -> None:
        for proof_available in (False, True):
            with self.subTest(proof_available=proof_available):
                gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
                gate.scope.identity = ExecutionScopeIdentity("unrelated-command", 777)
                supervisor = self.supervisor(gate)
                requested = []

                def wrong_launch(argv, identity, pass_fds):
                    requested.append(identity)
                    return gate

                def open_scope(identity):
                    self.assertEqual(requested[0], identity)
                    if not proof_available:
                        raise CommandError("exact scope evidence unavailable")
                    scope = FakeScope(identity, -1)
                    scope.members = ()
                    return scope

                with patch.object(supervisor.launcher, "launch_blocked", side_effect=wrong_launch), patch.object(
                    supervisor.launcher, "open_scope", side_effect=open_scope
                ), self.assertRaises(CommandError):
                    supervisor.reserve_and_launch_blocked(self.fence, "probe_media", ("probe",))
                self.assertFalse(gate.aborted)
                self.assertFalse(gate.released)
                self.assertFalse(gate.scope.closed)
                self.assertEqual((124,), gate.scope.members)
                command = self.catalog.command(requested[0].command_id)
                self.assertEqual("quiesced" if proof_available else "launch_reserved", command.state)

    def test_launcher_failure_reconciles_only_its_proven_empty_scope(self) -> None:
        failure = RuntimeError("synthetic launcher handshake failed")
        launcher = FakeLauncher([])

        def fail_launch(argv, identity, pass_fds):
            scope = FakeScope(identity, -1)
            scope.members = ()
            launcher.scopes[identity] = scope
            raise failure

        self.catalog.reserve_hardware_command(self.fence, "other-launch", "probe_media", "a" * 64)
        supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)))
        supervisor.launcher = launcher
        with patch.object(launcher, "launch_blocked", side_effect=fail_launch), self.assertRaises(RuntimeError) as caught:
            supervisor.reserve_and_launch_blocked(self.fence, "probe_media", ("probe",))
        self.assertIs(failure, caught.exception)
        identity, scope = next(iter(launcher.scopes.items()))
        command = self.catalog.command(identity.command_id)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("launch_aborted", command.exit_outcome)
        self.assertIsNone(command.process)
        self.assertTrue(scope.closed)
        self.assertEqual("launch_reserved", self.catalog.command("other-launch").state)

    def test_launcher_failure_terminates_exact_populated_scope_before_acknowledging(self) -> None:
        launcher = FakeLauncher([])
        failure = RuntimeError("synthetic launcher handshake failed")

        def fail_launch(argv, identity, pass_fds):
            launcher.scopes[identity] = FakeScope(identity, 777)
            raise failure

        supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)))
        supervisor.launcher = launcher
        with patch.object(launcher, "launch_blocked", side_effect=fail_launch), self.assertRaises(RuntimeError) as caught:
            supervisor.reserve_and_launch_blocked(self.fence, "probe_media", ("probe",))
        self.assertIs(failure, caught.exception)
        identity, scope = next(iter(launcher.scopes.items()))
        self.assertEqual((), scope.members)
        self.assertTrue(scope.closed)
        self.assertEqual("quiesced", self.catalog.command(identity.command_id).state)

    def test_launcher_failure_keeps_reservation_if_scope_proof_is_unavailable_or_wrong(self) -> None:
        for mode in ("unavailable", "wrong_identity", "wrong_generation", "stubborn", "close_failed"):
            with self.subTest(mode=mode):
                launcher = FakeLauncher([])
                failure = RuntimeError("synthetic launcher handshake failed")
                requested = []

                def fail_launch(argv, identity, pass_fds):
                    requested.append(identity)
                    raise failure

                def open_scope(identity):
                    if mode == "unavailable":
                        raise CommandError("scope evidence unavailable")
                    scope = FakeScope(identity, 777)
                    if mode == "wrong_identity":
                        scope.identity = ExecutionScopeIdentity("unrelated-command", identity.owner_generation)
                    elif mode == "wrong_generation":
                        scope.identity = ExecutionScopeIdentity(identity.command_id, identity.owner_generation + 1)
                    elif mode == "stubborn":
                        scope.signal = lambda _signum: None
                    else:
                        scope.members = ()
                        def fail_close():
                            raise CommandError("scope release evidence unavailable")
                        scope.close = fail_close
                    launcher.scopes[identity] = scope
                    return scope

                supervisor = self.supervisor(FakeGate(ProcessIdentity("boot-a", 124, 457, 124)))
                supervisor.launcher = launcher
                supervisor.term_timeout = supervisor.kill_timeout = supervisor.quiescence_timeout = 0.001
                with patch.object(launcher, "launch_blocked", side_effect=fail_launch), patch.object(
                    launcher, "open_scope", side_effect=open_scope
                ), self.assertRaises(CommandError):
                    supervisor.reserve_and_launch_blocked(self.fence, "probe_media", ("probe",))
                self.assertEqual("launch_reserved", self.catalog.command(requested[0].command_id).state)
                if mode in {"wrong_identity", "wrong_generation"}:
                    self.assertEqual((777,), launcher.scopes[requested[0]].members)
                    self.assertFalse(launcher.scopes[requested[0]].closed)

    def test_gate_persistence_failure_is_reconciled_before_original_error_returns(self) -> None:
        original_record = self.catalog.record_blocked_process
        for persisted in (False, True):
            with self.subTest(persisted=persisted):
                gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
                supervisor = self.supervisor(gate)
                failure = RuntimeError("synthetic persistence reply failed")

                def fail_record(command_id, fence, identity):
                    if persisted:
                        original_record(command_id, fence, identity)
                    raise failure

                with patch.object(self.catalog, "record_blocked_process", side_effect=fail_record), self.assertRaises(RuntimeError) as caught:
                    supervisor.reserve_and_launch_blocked(self.fence, "probe_media", ("probe",))
                self.assertIs(failure, caught.exception)
                self.assertTrue(gate.aborted)
                self.assertFalse(gate.released)
                self.assertTrue(gate.scope.closed)
                command = self.catalog.command(gate.scope.identity.command_id)
                self.assertEqual("quiesced", command.state)
                self.assertEqual("launch_aborted", command.exit_outcome)

    def test_persisted_gate_failure_keeps_command_blocked_when_process_absence_is_unproven(self) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
        supervisor = self.supervisor(gate, probe=FakeProcessProbe(fail=True))
        original_record = self.catalog.record_blocked_process

        def fail_record(command_id, fence, identity):
            original_record(command_id, fence, identity)
            raise RuntimeError("synthetic persistence reply failed")

        with patch.object(self.catalog, "record_blocked_process", side_effect=fail_record), self.assertRaises(ProcessQuiescenceTimeout):
            supervisor.reserve_and_launch_blocked(self.fence, "probe_media", ("probe",))
        command = self.catalog.command(gate.scope.identity.command_id)
        self.assertEqual("launch_blocked", command.state)
        self.assertIsNone(command.exit_outcome)
        self.assertFalse(gate.released)
        self.assertFalse(gate.scope.closed)

    def test_production_pass_fds_allow_only_char_devices_or_pinned_root_binary(self):
        executable = os.stat_result((stat.S_IFREG | 0o755, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        writable = os.stat_result((stat.S_IFREG | 0o775, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        character = os.stat_result((stat.S_IFCHR | 0o600, 0, 0, 0, 1000, 0, 0, 0, 0, 0))
        with patch.object(
            command_supervisor_module.os, "fstat", return_value=executable
        ):
            ForkExecCommandLauncher._validate_pass_fds((17,))
        with patch.object(
            command_supervisor_module.os, "fstat", return_value=character
        ):
            ForkExecCommandLauncher._validate_pass_fds((18,))
        with (
            patch.object(command_supervisor_module.os, "fstat", return_value=writable),
            self.assertRaisesRegex(CommandError, "trusted"),
        ):
            ForkExecCommandLauncher._validate_pass_fds((19,))

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.catalog = Catalog(Path(self.temporary.name) / "catalog.db")
        self.catalog.initialize()
        self.catalog.add_library(
            "LIB-SYNTHETIC", "Synthetic library", self.temporary.name
        )
        self.catalog.create_automatic_job(
            "JOB-SYNTHETIC",
            "LIB-SYNTHETIC",
            "synthetic-drive",
            "/synthetic/mount-a",
            [(f"SY{i:04d}", f"SERIAL-{i}", 1, 1) for i in range(1, 5)],
            force_format=True,
        )
        self.daemon_fence = self.catalog.claim_daemon_owner("daemon-a")
        candidate = OperationRecord(
            id="op-a",
            kind="archive.resume",
            state="running",
            phase=None,
            idempotency_key="key-a",
            principal="synthetic-admin",
            job_id="JOB-SYNTHETIC",
            cassette_sequence=4,
            started_at="2026-08-21T12:00:00+00:00",
            finished_at=None,
        )
        self.catalog.admit_operation(
            candidate,
            self.daemon_fence,
            admission_open=True,
            hardware_target=_target(),
        )
        self.fence = OperationFence("op-a", self.daemon_fence.generation)

    def tearDown(self) -> None:
        self.catalog.close()
        self.temporary.cleanup()

    def supervisor(
        self,
        gate: FakeGate,
        *,
        probe: FakeProcessProbe | None = None,
        terminator: FakeTerminator | None = None,
        event_sink=None,
    ) -> TrackedCommandSupervisor:
        return TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=FakeLauncher([gate]),
            process_probe=probe or FakeProcessProbe(),
            process_terminator=terminator or FakeTerminator(),
            quiescence_timeout=2.0,
            term_timeout=0.25,
            kill_timeout=0.5,
            event_sink=event_sink,
            operation_context=OperationalCorrelation(
                operation_id="op-a",
                job_id="JOB-SYNTHETIC",
                cassette_label="SY0004",
                cassette_sequence=4,
            ),
        )

    def test_operational_events_start_only_after_durable_release_and_finish_after_quiescence(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        gate = FakeGate(
            ProcessIdentity("boot-a", 778, 991, 778),
            CompletedCommand(0, "ready\nready\n", ""),
        )
        supervisor = self.supervisor(gate, event_sink=sink)

        command = supervisor.start(
            self.fence,
            "mount",
            ("ltfs", "--password=hunter2", "/synthetic/mount-a"),
        )
        self.assertEqual(["ltfs.command.started"], [event.code for event in sink.events])
        self.assertEqual("released", self.catalog.command(command.command_id).state)

        supervisor.await_completion(command, 1.0)

        self.assertEqual(
            ["ltfs.command.started", "ltfs.command.output", "ltfs.command.succeeded"],
            [event.code for event in sink.events],
        )
        self.assertEqual(2, sink.events[1].repeat_count)
        self.assertNotIn("hunter2", repr(sink.events))
        self.assertEqual("quiesced", self.catalog.command(command.command_id).state)
        self.assertTrue(
            all(event.command_id == command.command_id for event in sink.events)
        )
        self.assertTrue(
            all(
                event.daemon_generation == self.daemon_fence.generation
                for event in sink.events
            )
        )

    def test_operational_event_sink_baseexception_does_not_change_command_failure(self) -> None:
        class ExplodingSink:
            def emit(self, _event: OperationalEvent) -> None:
                raise KeyboardInterrupt

        gate = FakeGate(
            ProcessIdentity("boot-a", 779, 992, 779),
            CompletedCommand(5, "", "password=hunter2\n"),
        )
        with self.assertRaises(CommandFailed) as raised:
            self.supervisor(gate, event_sink=ExplodingSink()).run(
                self.fence, "mount", ("ltfs",), 1.0
            )
        self.assertEqual(5, raised.exception.returncode)

    def test_nonzero_exit_code_is_durable_before_command_failure_is_raised(self) -> None:
        gate = FakeGate(
            ProcessIdentity("boot-a", 784, 997, 784),
            CompletedCommand(3, "", "no medium"),
        )

        with self.assertRaises(CommandFailed) as raised:
            self.supervisor(gate).run(self.fence, "probe_media", ("mt",), 1.0)

        self.assertEqual(3, raised.exception.returncode)
        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertEqual("quiesced", command.state)
        self.assertEqual(3, command.terminal_exit_code)

    def test_abort_before_release_does_not_claim_command_started(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        gate = FakeGate(ProcessIdentity("boot-a", 780, 993, 780))
        gate.prepare_error = RuntimeError("synthetic pre-release failure")
        with self.assertRaisesRegex(RuntimeError, "pre-release"):
            self.supervisor(gate, event_sink=sink).start(
                self.fence, "mount", ("ltfs",)
            )
        self.assertNotIn("ltfs.command.started", [event.code for event in sink.events])

    def test_timeout_event_is_terminal_only_after_quiescence(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        gate = FakeGate(
            ProcessIdentity("boot-a", 781, 994, 781),
            CommandTimeout("mount"),
        )

        with self.assertRaises(CommandTimeout):
            self.supervisor(gate, event_sink=sink).run(
                self.fence, "mount", ("ltfs",), 0.25
            )

        self.assertEqual(
            ["ltfs.command.started", "ltfs.command.timed_out"],
            [event.code for event in sink.events],
        )
        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertEqual("quiesced", command.state)

    def test_explicit_termination_event_is_terminal_only_after_quiescence(self) -> None:
        catalog = self.catalog

        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                if event.code == "ltfs.command.cancelled":
                    command = catalog.hardware_commands_for_operation("op-a")[0]
                    if command.state != "quiesced":
                        raise AssertionError("terminal event preceded durable quiescence")
                self.events.append(event)

        sink = Sink()
        gate = FakeGate(
            ProcessIdentity("boot-a", 783, 996, 783),
            CommandTimeout("mount"),
        )
        supervisor = self.supervisor(gate, event_sink=sink)
        running = supervisor.start(self.fence, "mount", ("ltfs",))

        evidence = supervisor.terminate_and_await(running.command_id)

        self.assertEqual("terminated", evidence.outcome)
        self.assertEqual(
            ["ltfs.command.started", "ltfs.command.cancelled"],
            [event.code for event in sink.events],
        )

    def test_operational_output_is_redacted_and_bounded_to_32_kib(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        payload = "password=hunter2 " + "x" * (40 * 1024)
        gate = FakeGate(
            ProcessIdentity("boot-a", 782, 995, 782),
            CompletedCommand(5, payload, ""),
        )

        with self.assertRaises(CommandFailed):
            self.supervisor(gate, event_sink=sink).run(
                self.fence, "mount", ("ltfs",), 1.0
            )

        output = [event for event in sink.events if event.code == "ltfs.command.output"]
        self.assertLessEqual(
            sum(len(event.message.encode("utf-8")) for event in output), 32 * 1024
        )
        self.assertTrue(output[-1].truncated)
        self.assertNotIn("hunter2", repr(output))

    def test_alternating_output_is_bounded_by_event_count_with_summary(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        sink = Sink()
        payload = "\n".join("a" if index % 2 else "b" for index in range(40_000))
        gate = FakeGate(
            ProcessIdentity("boot-a", 784, 997, 784),
            CompletedCommand(0, payload, ""),
        )

        self.supervisor(gate, event_sink=sink).run(
            self.fence, "mount", ("ltfs",), 1.0
        )

        output = [event for event in sink.events if event.code == "ltfs.command.output"]
        self.assertLessEqual(len(output), 64)
        self.assertTrue(output[-1].truncated)
        self.assertIn("truncated", output[-1].message.lower())
        self.assertLessEqual(
            sum(len(event.message.encode("utf-8")) for event in output), 32 * 1024
        )

    def read_only_boundary(
        self, *, additional_mounts: tuple[str, ...] = ()
    ) -> ReadOnlyCgroupPrivilegeBoundary:
        control_root = Path(self.temporary.name) / "synthetic-cgroup"
        control_root.mkdir(exist_ok=True)
        (control_root / "cgroup.procs").touch()
        mountinfo = Path(self.temporary.name) / "synthetic-mountinfo"
        mountinfo.write_text(
            "\n".join(
                (
                    f"41 32 0:39 / {control_root} ro,nosuid - cgroup2 cgroup rw",
                    *additional_mounts,
                )
            )
            + "\n",
            encoding="utf-8",
        )
        status = Path(self.temporary.name) / "synthetic-status"
        status.write_text(
            "CapInh:\t0000000000000000\n"
            "CapPrm:\t0000000000000000\n"
            "CapEff:\t0000000000000000\n"
            "CapBnd:\t0000000000000000\n"
            "CapAmb:\t0000000000000000\n"
            "NoNewPrivs:\t1\n",
            encoding="ascii",
        )
        return ReadOnlyCgroupPrivilegeBoundary(
            control_root, mountinfo_path=mountinfo, status_path=status
        )

    def test_process_identity_and_target_are_durable_before_exec_release(self) -> None:
        identity = ProcessIdentity("boot-a", 123, 456, 123)
        gate = FakeGate(identity)
        supervisor = self.supervisor(gate)

        def assert_blocked_during_release_preparation() -> None:
            command = self.catalog.hardware_commands_for_operation("op-a")[0]
            self.assertEqual("launch_blocked", command.state)
            self.assertEqual(identity, command.process)
            self.assertEqual(_target(), command.target)

        def assert_durable_before_release() -> None:
            command = self.catalog.hardware_commands_for_operation("op-a")[0]
            self.assertEqual("release_authorized", command.state)
            self.assertEqual("authorized", command.release_status)
            self.assertEqual(gate.permit_sha256, command.release_permit_sha256)
            self.assertIsNone(command.released_at)
            self.assertEqual(identity, command.process)
            self.assertEqual(_target(), command.target)

        gate.on_prepare_release = assert_blocked_during_release_preparation
        gate.on_release = assert_durable_before_release
        result = supervisor.run(self.fence, "format", ("mkltfs", "--device"), 1.0)

        self.assertEqual(0, result.returncode)
        self.assertTrue(gate.prepared)
        self.assertTrue(gate.released)
        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertEqual("quiesced", command.state)
        self.assertEqual("released", command.release_status)
        self.assertEqual("completed", command.exit_outcome)

    def test_release_preparation_failure_aborts_without_durable_authorization(
        self,
    ) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 129, 462, 129))
        gate.prepare_error = CommandError("synthetic preparation failure")

        with self.assertRaisesRegex(CommandError, "preparation"):
            self.supervisor(gate).start(self.fence, "unmount", ("fusermount3",))

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertEqual("quiesced", command.state)
        self.assertEqual("launch_aborted", command.exit_outcome)
        self.assertIsNone(command.release_permit_sha256)
        self.assertFalse(gate.released)

    def _broker_prepare_failure(self, reason, boundary="prepare_release"):
        capability = command_supervisor_module.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        manager = command_supervisor_module.BrokeredCgroupExecutionScopeManager(
            broker, capability,
        )
        scope = manager.create(ExecutionScopeIdentity("prepare-diagnostic", 4))
        scope.attach(4321)
        failure = RuntimeError("secret transport detail must remain private")
        failure.reason = reason
        with patch.object(broker, boundary, side_effect=failure), self.assertRaises(CommandError) as caught:
            scope.prepare_release(4321)
        return caught.exception

    def test_prepare_failure_preserves_only_closed_diagnostic_reason(self):
        for reason, expected in (("timeout", "timeout"), ("secret detail", "unavailable")):
            with self.subTest(reason=reason):
                failure = self._broker_prepare_failure(reason)
                self.assertEqual(getattr(failure, "reason", None), expected)
                self.assertNotIn("secret", str(failure))

    def test_prepare_timeout_retries_probe_only_after_previous_scope_is_closed(self):
        first = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
        first.prepare_error = self._broker_prepare_failure("timeout")
        second = FakeGate(ProcessIdentity("boot-a", 125, 458, 125))
        events = []
        sink = type("Sink", (), {"emit": lambda _self, event: events.append(event)})()
        supervisor = self.supervisor(first, event_sink=sink)
        supervisor.launcher = FakeLauncher([first, second])

        def prior_scope_closed():
            prior = self.catalog.command(first.scope.identity.command_id)
            self.assertEqual(prior.state, "quiesced")
            self.assertEqual(prior.exit_outcome, "launch_aborted")
            self.assertIsNone(prior.release_permit_sha256)
            self.assertTrue(first.scope.closed)
            self.assertFalse(first.released)

        second.on_prepare_release = prior_scope_closed
        with patch.object(command_supervisor_module.time, "sleep"):
            result = supervisor.run(self.fence, "identify", ("identify",), 1.0)
        self.assertEqual(result.returncode, 0)
        self.assertTrue(second.released)
        self.assertEqual(len(supervisor.launcher.argv), 2)
        self.assertIn("ltfs.prepare.timeout", [event.code for event in events])
        self.assertEqual(sum(event.code == "ltfs.command.started" for event in events), 1)

    def test_prepare_failure_never_retries_mutations_or_definite_rejections(self):
        for kind, reason in (("format", "timeout"), ("mount", "eof"),
                             ("identify", "protocol"), ("probe_media", "rejected")):
            with self.subTest(kind=kind, reason=reason):
                gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
                gate.prepare_error = self._broker_prepare_failure(reason)
                supervisor = self.supervisor(gate)
                with patch.object(command_supervisor_module.time, "sleep"), self.assertRaises(CommandError):
                    supervisor.start(self.fence, kind, (kind,))
                self.assertEqual(len(supervisor.launcher.argv), 1)
                self.assertFalse(gate.released)
                self.assertEqual(self.catalog.command(gate.scope.identity.command_id).state, "quiesced")

    def test_prepare_timeout_without_quiescence_never_retries(self):
        gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
        gate.prepare_error = self._broker_prepare_failure("timeout")
        supervisor = self.supervisor(gate, probe=FakeProcessProbe(fail=True))
        with self.assertRaises(ProcessQuiescenceTimeout):
            supervisor.start(self.fence, "identify", ("identify",))
        self.assertEqual(len(supervisor.launcher.argv), 1)
        self.assertFalse(gate.released)
        self.assertEqual(self.catalog.command(gate.scope.identity.command_id).state, "launch_blocked")

    def test_prepare_timeout_retry_budget_is_three_closed_attempts(self):
        gates = [FakeGate(ProcessIdentity("boot-a", pid, pid + 333, pid))
                 for pid in (124, 125, 126)]
        for gate in gates:
            gate.prepare_error = self._broker_prepare_failure("timeout")
        supervisor = self.supervisor(gates[0])
        supervisor.launcher = FakeLauncher(gates)
        with patch.object(command_supervisor_module.time, "sleep"), self.assertRaises(CommandError):
            supervisor.start(self.fence, "probe_media", ("probe",))
        self.assertEqual(len(supervisor.launcher.argv), 3)
        for gate in gates:
            command = self.catalog.command(gate.scope.identity.command_id)
            self.assertEqual(command.state, "quiesced")
            self.assertEqual(command.exit_outcome, "launch_aborted")
            self.assertIsNone(command.release_permit_sha256)
            self.assertFalse(gate.released)
            self.assertTrue(gate.scope.closed)

    def test_prepare_validation_timeout_remains_a_preparation_error(self):
        failure = self._broker_prepare_failure("timeout", boundary="validate_scope")
        self.assertIsInstance(failure, command_supervisor_module.ReleasePreparationError)
        self.assertEqual(failure.reason, "timeout")
        self.assertFalse(failure.quiesced)

    def test_prepare_cleanup_transport_failure_cannot_authorize_retry(self):
        gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
        gate.prepare_error = self._broker_prepare_failure("timeout")
        supervisor = self.supervisor(gate)
        failure = command_supervisor_module.ScopeExchangeError("revalidated", "transport")
        with patch.object(gate.scope, "is_populated", side_effect=failure), self.assertRaises(CommandError):
            supervisor.start(self.fence, "identify", ("identify",))
        self.assertFalse(gate.prepare_error.quiesced)
        self.assertEqual(len(supervisor.launcher.argv), 1)
        self.assertEqual(self.catalog.command(gate.scope.identity.command_id).state, "launch_blocked")
        self.assertFalse(gate.released)

    def test_probe_release_reply_failure_is_never_a_preparation_retry(self):
        gate = FakeGate(ProcessIdentity("boot-a", 124, 457, 124))
        gate.release_error_after_write = CommandError("release response unavailable")
        supervisor = self.supervisor(gate)
        with self.assertRaises(CommandError):
            supervisor.start(self.fence, "identify", ("identify",))
        self.assertEqual(len(supervisor.launcher.argv), 1)
        self.assertTrue(gate.released)
        command = self.catalog.command(gate.scope.identity.command_id)
        self.assertEqual(command.state, "release_authorized")
        self.assertEqual(command.release_status, "ambiguous")
        self.assertNotEqual(command.exit_outcome, "launch_aborted")

    def test_busy_authorization_emits_closed_pre_release_diagnostic(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.events: list[OperationalEvent] = []

            def emit(self, event: OperationalEvent) -> None:
                self.events.append(event)

        gate = FakeGate(ProcessIdentity("boot-a", 133, 466, 133))
        sink = Sink()
        with (
            patch.object(
                self.catalog, "authorize_hardware_command_release",
                side_effect=sqlite3.OperationalError("database is locked"),
            ),
            self.assertRaises(sqlite3.OperationalError),
        ):
            self.supervisor(gate, event_sink=sink).start(
                self.fence, "identify", ("identify",)
            )
        self.assertFalse(gate.released)
        self.assertEqual("quiesced", self.catalog.hardware_commands_for_operation("op-a")[0].state)
        self.assertIn("ltfs.authorize.busy", [event.code for event in sink.events])
        self.assertNotIn("database is locked", repr(sink.events))

    def test_durable_authorization_failure_aborts_before_release(self) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 130, 463, 130))

        with (
            patch.object(
                self.catalog,
                "authorize_hardware_command_release",
                create=True,
                side_effect=RuntimeError("synthetic authorization failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "authorization"),
        ):
            self.supervisor(gate).start(self.fence, "unmount", ("fusermount3",))

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertTrue(gate.prepared)
        self.assertFalse(gate.released)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("launch_aborted", command.exit_outcome)

    def test_broker_revocation_after_authorization_aborts_without_release(self) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 131, 464, 131))
        gate.release_error_before_write = CommandError("synthetic broker revocation")

        with self.assertRaisesRegex(CommandError, "revocation"):
            self.supervisor(gate).start(self.fence, "unmount", ("fusermount3",))

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertTrue(gate.prepared)
        self.assertFalse(gate.released)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("aborted", command.release_status)
        self.assertEqual("launch_aborted", command.exit_outcome)

    def test_error_after_release_byte_is_durable_ambiguity(self) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 132, 465, 132))
        gate.release_error_after_write = CommandError("synthetic post-write failure")

        with self.assertRaisesRegex(CommandError, "post-write"):
            self.supervisor(gate).start(self.fence, "unmount", ("fusermount3",))

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertTrue(gate.released)
        self.assertEqual("release_authorized", command.state)
        self.assertEqual("ambiguous", command.release_status)
        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )

    def test_unavailable_atomic_release_claim_is_durable_ambiguity(self) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 137, 470, 137))
        gate.release_error_before_write = CommandError("synthetic broker failure")
        gate.release_claim_error = CommandError("synthetic claim unavailable")

        with self.assertRaisesRegex(CommandError, "broker failure"):
            self.supervisor(gate).start(self.fence, "unmount", ("fusermount3",))

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertEqual("release_authorized", command.state)
        self.assertEqual("ambiguous", command.release_status)
        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )

    def test_catalog_confirmation_failure_after_release_is_durable_ambiguity(
        self,
    ) -> None:
        gate = FakeGate(ProcessIdentity("boot-a", 133, 466, 133))

        with (
            patch.object(
                self.catalog,
                "confirm_hardware_command_released",
                create=True,
                side_effect=RuntimeError("synthetic confirmation failure"),
            ),
            self.assertRaisesRegex(RuntimeError, "confirmation"),
        ):
            self.supervisor(gate).start(self.fence, "unmount", ("fusermount3",))

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertTrue(gate.released)
        self.assertEqual("release_authorized", command.state)
        self.assertEqual("ambiguous", command.release_status)
        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )

    def test_failure_before_durable_release_closes_gate_without_exec(self) -> None:
        identity = ProcessIdentity("boot-a", 124, 457, 124)
        gate = FakeGate(identity)

        with (
            patch.object(
                self.catalog,
                "record_blocked_process",
                side_effect=RuntimeError("synthetic persistence failure"),
            ),
            self.assertRaises(RuntimeError),
        ):
            self.supervisor(gate).run(self.fence, "unmount", ("fusermount3",), 1.0)

        self.assertTrue(gate.aborted)
        self.assertFalse(gate.released)
        self.assertTrue(gate.scope.closed)

    def test_launch_reserved_recovery_cannot_acknowledge_a_nonempty_scope(self) -> None:
        class StubbornScope(FakeScope):
            def signal(self, signum: int) -> None:
                return None

        command_id = "reserved-command"
        self.catalog.reserve_hardware_command(self.fence, command_id, "mount", "a" * 64)
        identity = ExecutionScopeIdentity(command_id, self.fence.owner_generation)
        launcher = FakeLauncher([])
        scope = StubbornScope(identity, 777)
        launcher.scopes[identity] = scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
            quiescence_timeout=0.05,
            term_timeout=0.01,
            kill_timeout=0.01,
        )

        with self.assertRaises(ProcessQuiescenceTimeout):
            supervisor.reconcile_one(command_id, self.daemon_fence)

        self.assertEqual("launch_reserved", self.catalog.command(command_id).state)
        self.assertFalse(scope.closed)

    def test_pre_release_abort_is_reaped_before_launch_aborted_receipt(self) -> None:
        identity = ProcessIdentity("boot-a", 624, 957, 624)
        gate = FakeGate(identity)
        supervisor = self.supervisor(gate)
        command_id = supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )

        evidence = supervisor.abort_blocked(command_id)

        self.assertEqual("launch_aborted", evidence.outcome)
        self.assertTrue(gate.aborted)
        self.assertEqual([2.0], gate.wait_calls)
        self.assertEqual("quiesced", self.catalog.command(command_id).state)

    def test_long_running_command_remains_released_until_explicit_stop(self) -> None:
        identity = ProcessIdentity("boot-a", 625, 958, 625)
        gate = FakeGate(identity)
        supervisor = self.supervisor(gate)

        running = supervisor.start(
            self.fence, "mount", ("ltfs", "-f", "/synthetic/mount-a")
        )

        self.assertEqual("released", self.catalog.command(running.command_id).state)
        self.assertEqual(identity, running.process)
        self.assertEqual([], gate.wait_calls)

    def test_late_scope_escape_blocks_quiescence_receipt(self) -> None:
        class LateScope:
            def __init__(self) -> None:
                self.identity = ExecutionScopeIdentity("pending", 0)
                self.members: tuple[int, ...] = (627,)

            def member_pids(self) -> tuple[int, ...]:
                return self.members

            def is_populated(self) -> bool:
                return bool(self.members)

            def signal(self, signum: int) -> None:
                return None

            def close(self) -> None:
                return None

        identity = ProcessIdentity("boot-a", 627, 960, 627)
        gate = FakeGate(identity)
        scope = LateScope()
        gate.scope = scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=FakeLauncher([gate]),
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
            quiescence_timeout=0.05,
            term_timeout=0.01,
            kill_timeout=0.01,
        )
        running = supervisor.start(self.fence, "mount", ("ltfs", "-f"))
        supervisor.assert_running(running)
        scope.members = (628,)

        with self.assertRaises(ProcessQuiescenceTimeout):
            supervisor.terminate_and_await(running.command_id)

        self.assertEqual("released", self.catalog.command(running.command_id).state)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        with self.assertRaises(CommandQuiescenceRequired):
            self.catalog.create_command_quiescence_receipt("op-a", current)
        with self.assertRaises(CommandQuiescenceRequired):
            self.catalog.resolve_recovery(
                "op-a",
                current,
                SafeRecoveryResolution(
                    reason_code="synthetic-resolution",
                    command_receipt_id="missing-command-receipt",
                    physical_receipt_id="missing-physical-receipt",
                ),
            )

    def test_cgroup_scope_name_is_command_and_generation_bound_but_redacted(
        self,
    ) -> None:
        first = ExecutionScopeIdentity("synthetic-command-a", 4)
        next_generation = ExecutionScopeIdentity("synthetic-command-a", 5)
        first_name = CgroupV2ExecutionScopeManager._name(first)
        next_name = CgroupV2ExecutionScopeManager._name(next_generation)
        self.assertNotEqual(first_name, next_name)
        self.assertNotIn(first.command_id, first_name)

    def test_cgroup_scope_counts_nested_descendants_as_populated(self) -> None:
        scope_path = Path(self.temporary.name) / "scope"
        nested = scope_path / "nested"
        nested.mkdir(parents=True)
        (scope_path / "cgroup.procs").write_text("", encoding="ascii")
        (scope_path / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        (nested / "cgroup.procs").write_text("4321\n", encoding="ascii")
        (nested / "cgroup.events").write_text(
            "populated 1\nfrozen 0\n", encoding="ascii"
        )
        scope = CgroupV2ExecutionScope(
            ExecutionScopeIdentity("synthetic-command", 4), scope_path
        )

        self.assertEqual((4321,), scope.member_pids())
        with self.assertRaises(ProcessQuiescenceTimeout):
            scope.close()

    def test_brokered_scope_requires_recursive_attestation_and_uses_cgroup_kill(
        self,
    ) -> None:
        from ltobackup.tape import command_supervisor

        for name in (
            "BrokeredCgroupExecutionScopeManager",
            "BrokeredCgroupScopeReceipt",
            "BrokeredCgroupScopeToken",
            "BrokeredCgroupScopeValidation",
        ):
            self.assertTrue(
                hasattr(command_supervisor, name),
                f"production broker capability is missing {name}",
            )
        manager_type = command_supervisor.BrokeredCgroupExecutionScopeManager
        capability_type = command_supervisor.BrokeredCgroupScopeToken
        capability = capability_type(b"synthetic-broker-token-value-32b")

        broker = ReceiptBroker()
        manager = manager_type(broker, capability)
        launcher = ForkExecCommandLauncher(manager, self.read_only_boundary())
        self.assertIs(launcher.scope_manager, manager)
        identity = ExecutionScopeIdentity("synthetic-command", 4)
        scope = manager.create(identity)
        scope.attach(4321)
        self.assertTrue(scope.is_populated())
        self.assertEqual((4321,), scope.member_pids())

        scope.signal(signal.SIGKILL)
        scope.close()

        self.assertEqual(["broker-scope-a"], broker.killed)
        self.assertEqual(["broker-scope-a"], broker.released)
        self.assertNotIn("synthetic-broker-token", repr(capability))

        class IncompleteReceiptBroker(ReceiptBroker):
            def _receipt(self, identity, request_nonce):
                return replace(
                    super()._receipt(identity, request_nonce),
                    recursive_population=False,
                )

        with self.assertRaisesRegex(CommandError, "recursive"):
            manager_type(IncompleteReceiptBroker(), capability).create(identity)

    def test_production_launcher_rejects_direct_client_cgroup_management(
        self,
    ) -> None:
        with self.assertRaisesRegex(CommandError, "attested brokered cgroup"):
            ForkExecCommandLauncher(
                CgroupV2ExecutionScopeManager(), self.read_only_boundary()
            )

    def test_production_rejects_noop_attach_before_vendor_exec(self) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(
            b"synthetic-broker-token-value-32b"
        )

        marker = Path(self.temporary.name) / "noop-attach-must-not-exec"
        launcher = ForkExecCommandLauncher(
            command_supervisor.BrokeredCgroupExecutionScopeManager(
                ReceiptBroker(attach_noop=True), capability
            ),
            self.read_only_boundary(),
        )
        gate = None
        try:
            with (
                patch(
                    "ltobackup.tape.command_supervisor.os.geteuid", return_value=1000
                ),
                patch(
                    "ltobackup.tape.command_supervisor.os.access", return_value=False
                ),
                self.assertRaises(CommandError),
            ):
                gate = launcher.launch_blocked(
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    ExecutionScopeIdentity("synthetic-command", 4),
                )
        finally:
            if gate is not None:
                gate.abort_and_wait(2.0)
                gate.scope.close()

        self.assertFalse(marker.exists())

    def test_broker_receipt_rejects_scope_reuse_across_command_generation(self) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker(scope_id="reused-scope")
        manager = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        )
        first = manager.create(ExecutionScopeIdentity("command-a", 4))
        first.close()

        with self.assertRaisesRegex(CommandError, "reused"):
            manager.create(ExecutionScopeIdentity("command-b", 5))

    def test_broker_receipt_rejects_command_or_generation_mismatch(self) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        identity = ExecutionScopeIdentity("command-a", 4)
        for broker in (
            ReceiptBroker(command_id_override="command-b"),
            ReceiptBroker(generation_override=5),
        ):
            with (
                self.subTest(broker=type(broker).__name__),
                self.assertRaisesRegex(CommandError, "identity"),
            ):
                command_supervisor.BrokeredCgroupExecutionScopeManager(
                    broker, capability
                ).create(identity)

    def test_broker_receipt_rejects_caller_value_echo_as_origin_proof(self) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        manager = command_supervisor.BrokeredCgroupExecutionScopeManager(
            ReceiptBroker(copy_request_proof=True), capability
        )

        with self.assertRaisesRegex(CommandError, "broker-originated"):
            manager.create(ExecutionScopeIdentity("command-a", 4))

    def test_broker_validation_rejects_scope_substitution_during_attach(self) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker(substitute_on_validate=True)
        scope = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        ).create(ExecutionScopeIdentity("command-a", 4))
        try:
            with self.assertRaisesRegex(CommandError, "receipt"):
                scope.attach(4321)
        finally:
            broker.substitute_on_validate = False
            broker.members = ()
            broker.populated = False
            scope.close()

    def test_release_revalidates_broker_receipt_and_revocation_blocks_exec(
        self,
    ) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        launcher = ForkExecCommandLauncher(
            command_supervisor.BrokeredCgroupExecutionScopeManager(broker, capability),
            self.read_only_boundary(),
        )
        marker = Path(self.temporary.name) / "revoked-scope-must-not-exec"
        gate = None
        try:
            with (
                patch(
                    "ltobackup.tape.command_supervisor.os.geteuid", return_value=1000
                ),
                patch(
                    "ltobackup.tape.command_supervisor.os.access", return_value=False
                ),
            ):
                gate = launcher.launch_blocked(
                    (
                        sys.executable,
                        "-c",
                        "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                        str(marker),
                    ),
                    ExecutionScopeIdentity("synthetic-command", 4),
                )
                permit = gate.prepare_release()
                broker.revoked = True
                with self.assertRaises(CommandError):
                    gate.release(permit)
        finally:
            if gate is not None:
                gate.abort_and_wait(2.0)
                broker.revoked = False
                broker.members = ()
                broker.populated = False
                gate.scope.close()

        self.assertFalse(marker.exists())

    def test_broker_release_claim_reports_release_after_fresh_scope_attestation(
        self,
    ) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        manager = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        )
        identity = ExecutionScopeIdentity("command-a", 4)
        scope = manager.create(identity)
        scope.attach(4321)
        permit = scope.prepare_release(4321)
        with self.assertRaisesRegex(CommandError, "already prepared"):
            scope.prepare_release(4321)
        read_fd, write_fd = os.pipe()
        try:
            scope.release_child(4321, permit, write_fd)
            self.assertEqual(b"1", os.read(read_fd, 1))
        finally:
            os.close(read_fd)
            os.close(write_fd)

        reopened = manager.open(identity)
        claim = reopened.claim_unreleased(4321, permit)
        self.assertTrue(claim.released)
        self.assertFalse(claim.permit_revoked)
        broker.members = ()
        broker.populated = False
        scope.close()

    def test_atomic_unreleased_claim_and_release_race_has_exactly_one_winner(
        self,
    ) -> None:
        from ltobackup.tape import command_supervisor

        class DeterministicRaceBroker(ReceiptBroker):
            def __init__(self, winner: str) -> None:
                super().__init__()
                self.winner = winner
                self.atomic_barrier = threading.Barrier(2)
                self.winner_finished = threading.Event()
                self.race_complete = False

            def release_child(self, *args) -> None:
                if self.race_complete:
                    return super().release_child(*args)
                self.atomic_barrier.wait()
                if self.winner == "claim":
                    self.winner_finished.wait(2.0)
                try:
                    return super().release_child(*args)
                finally:
                    if self.winner == "release":
                        self.winner_finished.set()

            def claim_unreleased(self, *args):
                if self.race_complete:
                    return super().claim_unreleased(*args)
                self.atomic_barrier.wait()
                if self.winner == "release":
                    self.winner_finished.wait(2.0)
                try:
                    return super().claim_unreleased(*args)
                finally:
                    if self.winner == "claim":
                        self.winner_finished.set()

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        for expected_winner in ("claim", "release"):
            with self.subTest(expected_winner=expected_winner):
                broker = DeterministicRaceBroker(expected_winner)
                scope = command_supervisor.BrokeredCgroupExecutionScopeManager(
                    broker, capability
                ).create(ExecutionScopeIdentity("command-a", 4))
                scope.attach(4321)
                permit = scope.prepare_release(4321)
                read_fd, write_fd = os.pipe()
                os.set_blocking(read_fd, False)
                start_barrier = threading.Barrier(3)
                release_errors: list[BaseException] = []
                claim_results = []
                claim_errors: list[BaseException] = []

                def release(
                    start_barrier=start_barrier,
                    scope=scope,
                    permit=permit,
                    write_fd=write_fd,
                    release_errors=release_errors,
                ) -> None:
                    start_barrier.wait()
                    try:
                        scope.release_child(4321, permit, write_fd)
                    except BaseException as error:  # noqa: BLE001
                        release_errors.append(error)

                def claim(
                    start_barrier=start_barrier,
                    scope=scope,
                    permit=permit,
                    claim_results=claim_results,
                    claim_errors=claim_errors,
                ) -> None:
                    start_barrier.wait()
                    try:
                        claim_results.append(scope.claim_unreleased(4321, permit))
                    except BaseException as error:  # noqa: BLE001
                        claim_errors.append(error)

                release_thread = threading.Thread(target=release)
                claim_thread = threading.Thread(target=claim)
                release_thread.start()
                claim_thread.start()
                start_barrier.wait()
                release_thread.join(2.0)
                claim_thread.join(2.0)
                broker.race_complete = True
                try:
                    self.assertFalse(release_thread.is_alive())
                    self.assertFalse(claim_thread.is_alive())
                    self.assertEqual([], claim_errors)
                    self.assertEqual(1, len(claim_results))
                    result = claim_results[0]
                    release_won = not release_errors
                    claim_won = result.permit_revoked
                    self.assertNotEqual(release_won, claim_won)
                    self.assertEqual(expected_winner == "release", release_won)
                    self.assertEqual(expected_winner == "claim", claim_won)
                    self.assertEqual(release_won, result.released)
                    self.assertEqual(claim_won, bool(release_errors))
                    released_byte = _read_available(read_fd)
                    self.assertEqual(b"1" if release_won else b"", released_byte)
                    if claim_won:
                        with self.assertRaisesRegex(CommandError, "release failed"):
                            scope.release_child(4321, permit, write_fd)
                finally:
                    os.close(read_fd)
                    os.close(write_fd)
                    broker.members = ()
                    broker.populated = False
                    scope.close()

    def test_reconcile_claim_revokes_permit_before_catalog_records_abort(
        self,
    ) -> None:
        from ltobackup.tape import command_supervisor

        identity = ProcessIdentity("boot-a", 4321, 991, 4321)
        command_id = "command-race"
        scope_identity = ExecutionScopeIdentity(
            command_id, self.daemon_fence.generation
        )
        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        manager = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        )
        original_scope = manager.create(scope_identity)
        original_scope.attach(identity.pid)
        permit = original_scope.prepare_release(identity.pid)
        self.catalog.reserve_hardware_command(
            self.fence, command_id, "unmount", "a" * 64
        )
        self.catalog.record_blocked_process(command_id, self.fence, identity)
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        self.catalog.mark_hardware_command_release_ambiguous(
            command_id, self.daemon_fence, permit
        )
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        reopened_scope = manager.open(scope_identity)
        launcher = FakeLauncher([])
        launcher.scopes[scope_identity] = reopened_scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )
        read_fd, write_fd = os.pipe()
        os.set_blocking(read_fd, False)
        racing_release_errors: list[BaseException] = []

        def race_release_after_unreleased_check() -> None:
            try:
                original_scope.release_child(identity.pid, permit, write_fd)
            except BaseException as error:  # noqa: BLE001 - expected losing race
                racing_release_errors.append(error)

        broker.after_unreleased_check = race_release_after_unreleased_check
        try:
            evidence = supervisor.reconcile_one(command_id, current)

            command = self.catalog.command(command_id)
            self.assertEqual("launch_aborted", evidence.outcome)
            self.assertEqual("quiesced", command.state)
            self.assertEqual("aborted", command.release_status)
            self.assertEqual(1, len(racing_release_errors))
            self.assertEqual(b"", _read_available(read_fd))
            self.assertEqual("revoked", broker.release_permits[permit][2])
            self.assertEqual([], launcher.argv)
        finally:
            os.close(read_fd)
            os.close(write_fd)
            broker.after_unreleased_check = lambda: None
            broker.members = ()
            broker.populated = False

    def test_reconcile_never_aborts_when_atomic_claim_reports_released(self) -> None:
        from ltobackup.tape import command_supervisor

        identity = ProcessIdentity("boot-a", 4322, 992, 4322)
        command_id = "command-release-won"
        scope_identity = ExecutionScopeIdentity(
            command_id, self.daemon_fence.generation
        )
        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        manager = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        )
        original_scope = manager.create(scope_identity)
        original_scope.attach(identity.pid)
        permit = original_scope.prepare_release(identity.pid)
        self.catalog.reserve_hardware_command(
            self.fence, command_id, "unmount", "a" * 64
        )
        self.catalog.record_blocked_process(command_id, self.fence, identity)
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        read_fd, write_fd = os.pipe()
        try:
            original_scope.release_child(identity.pid, permit, write_fd)
            self.assertEqual(b"1", os.read(read_fd, 1))
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.catalog.mark_hardware_command_release_ambiguous(
            command_id, self.daemon_fence, permit
        )
        broker.members = ()
        broker.populated = False
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        reopened_scope = manager.open(scope_identity)
        launcher = FakeLauncher([])
        launcher.scopes[scope_identity] = reopened_scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )

        evidence = supervisor.reconcile_one(command_id, current)

        command = self.catalog.command(command_id)
        self.assertEqual("terminated", evidence.outcome)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("ambiguous", command.release_status)
        self.assertNotEqual("launch_aborted", command.exit_outcome)
        self.assertEqual("released", broker.release_permits[permit][2])
        self.assertEqual([], launcher.argv)

    def test_atomic_release_claim_rejects_pid_scope_and_proof_reuse(self) -> None:
        from ltobackup.tape import command_supervisor

        class SubstitutedClaimBroker(ReceiptBroker):
            def claim_unreleased(self, *args):
                claim = super().claim_unreleased(*args)
                return replace(
                    claim,
                    receipt=replace(claim.receipt, scope_id="substituted-scope"),
                )

        class ReplayedClaimBroker(ReceiptBroker):
            def __init__(self) -> None:
                super().__init__()
                self.first_claim = None

            def claim_unreleased(self, *args):
                claim = super().claim_unreleased(*args)
                if self.first_claim is None:
                    self.first_claim = claim
                    return claim
                return replace(
                    claim,
                    claim_nonce=self.first_claim.claim_nonce,
                    broker_proof=self.first_claim.broker_proof,
                )

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        scope = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        ).create(ExecutionScopeIdentity("command-a", 4))
        scope.attach(4321)
        permit = scope.prepare_release(4321)
        with self.assertRaisesRegex(CommandError, "does not match blocked child"):
            scope.claim_unreleased(4322, permit)
        exact = scope.claim_unreleased(4321, permit)
        self.assertTrue(exact.permit_revoked)
        broker.members = ()
        broker.populated = False
        scope.close()

        broker = SubstitutedClaimBroker()
        scope = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        ).create(ExecutionScopeIdentity("command-a", 4))
        scope.attach(4321)
        permit = scope.prepare_release(4321)
        with self.assertRaisesRegex(CommandError, "changed exact permit"):
            scope.claim_unreleased(4321, permit)
        broker.members = ()
        broker.populated = False
        scope.close()

        broker = ReplayedClaimBroker()
        scope = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        ).create(ExecutionScopeIdentity("command-a", 4))
        scope.attach(4321)
        permit = scope.prepare_release(4321)
        self.assertTrue(scope.claim_unreleased(4321, permit).permit_revoked)
        with self.assertRaisesRegex(CommandError, "claim is not fresh"):
            scope.claim_unreleased(4321, permit)
        broker.members = ()
        broker.populated = False
        scope.close()

    def test_broker_release_permit_proof_cannot_be_reused(self) -> None:
        from ltobackup.tape import command_supervisor

        class ReusedPermitBroker(ReceiptBroker):
            def prepare_release(self, receipt, pid, request_nonce, supplied_capability):
                permit = super().prepare_release(
                    receipt, pid, request_nonce, supplied_capability
                )
                return replace(
                    permit,
                    permit_nonce=b"n" * 32,
                    broker_proof=b"p" * 32,
                )

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReusedPermitBroker()
        manager = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        )
        identity = ExecutionScopeIdentity("command-a", 4)
        first = manager.create(identity)
        first.attach(4321)
        first.prepare_release(4321)
        second = manager.create(identity)
        second.attach(4321)

        with self.assertRaisesRegex(CommandError, "fresh broker proof"):
            second.prepare_release(4321)

        broker.members = ()
        broker.populated = False
        first.close()
        second.close()

    def test_revoked_broker_cannot_supply_negative_release_evidence(self) -> None:
        from ltobackup.tape import command_supervisor

        capability = command_supervisor.BrokeredCgroupScopeToken(b"c" * 32)
        broker = ReceiptBroker()
        scope = command_supervisor.BrokeredCgroupExecutionScopeManager(
            broker, capability
        ).create(ExecutionScopeIdentity("command-a", 4))
        scope.attach(4321)
        permit = scope.prepare_release(4321)
        broker.revoked = True

        with self.assertRaisesRegex(CommandError, "could not be atomically claimed"):
            scope.claim_unreleased(4321, permit)

        broker.revoked = False
        broker.members = ()
        broker.populated = False
        scope.close()

    def test_all_timeouts_must_be_finite_positive_and_bounded(self) -> None:
        identity = ProcessIdentity("boot-a", 626, 959, 626)
        for field, value in (
            ("quiescence_timeout", 0.0),
            ("term_timeout", float("nan")),
            ("kill_timeout", float("inf")),
            ("quiescence_timeout", 100_000.0),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                values = {
                    "catalog": self.catalog,
                    "daemon_fence": self.daemon_fence,
                    "launcher": FakeLauncher([FakeGate(identity)]),
                    "process_probe": FakeProcessProbe(),
                    "process_terminator": FakeTerminator(),
                    "quiescence_timeout": 2.0,
                    "term_timeout": 0.25,
                    "kill_timeout": 0.5,
                }
                values[field] = value
                TrackedCommandSupervisor(**values)
        for value in (0.0, float("nan"), float("inf"), 100_000.0):
            with self.subTest(poll_seconds=value), self.assertRaises(ValueError):
                SnapshotProcessProbe(
                    snapshot=lambda: (),
                    boot_id=lambda: "boot-a",
                    poll_seconds=value,
                )

    def test_parent_eof_before_release_reconciles_as_launch_aborted(self) -> None:
        identity = ProcessIdentity("boot-a", 124, 457, 124)
        gate = FakeGate(identity)
        supervisor = self.supervisor(gate)
        command_id = supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        gate.abort_before_release()
        evidence = supervisor.reconcile_one(command_id, self.daemon_fence)

        self.assertEqual("launch_aborted", evidence.outcome)
        self.assertFalse(gate.released)
        self.assertEqual("quiesced", self.catalog.command(command_id).state)

    def test_parent_eof_after_authorization_reconciles_as_not_executed(self) -> None:
        identity = ProcessIdentity("boot-a", 134, 467, 134)
        gate = FakeGate(identity)
        supervisor = self.supervisor(gate)
        command_id = supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        permit = gate.prepare_release()
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        gate.abort_before_release()

        evidence = supervisor.reconcile_one(command_id, self.daemon_fence)

        command = self.catalog.command(command_id)
        self.assertEqual("launch_aborted", evidence.outcome)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("aborted", command.release_status)
        self.assertFalse(gate.released)

    def test_restart_before_release_uses_unconsumed_permit_as_abort_evidence(
        self,
    ) -> None:
        identity = ProcessIdentity("boot-a", 135, 468, 135)
        gate = FakeGate(identity)
        old_supervisor = self.supervisor(gate)
        command_id = old_supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        permit = gate.prepare_release()
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        gate.abort_and_wait(1.0)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        launcher = FakeLauncher([])
        launcher.scopes[gate.scope.identity] = gate.scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )

        evidence = supervisor.reconcile_one(command_id, current)

        command = self.catalog.command(command_id)
        self.assertEqual("launch_aborted", evidence.outcome)
        self.assertEqual("aborted", command.release_status)
        self.assertEqual("quiesced", command.state)

    def test_restart_after_release_before_confirmation_stays_ambiguous(self) -> None:
        identity = ProcessIdentity("boot-a", 136, 469, 136)
        gate = FakeGate(identity)
        old_supervisor = self.supervisor(gate)
        command_id = old_supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        permit = gate.prepare_release()
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        gate.release(permit)
        gate.wait(1.0)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        launcher = FakeLauncher([])
        launcher.scopes[gate.scope.identity] = gate.scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )

        evidence = supervisor.reconcile_one(command_id, current)

        command = self.catalog.command(command_id)
        self.assertEqual("terminated", evidence.outcome)
        self.assertEqual("ambiguous", command.release_status)
        self.assertEqual("quiesced", command.state)

    def test_restart_can_abort_ambiguous_permit_after_exact_negative_evidence(
        self,
    ) -> None:
        identity = ProcessIdentity("boot-a", 138, 471, 138)
        gate = FakeGate(identity)
        gate.release_error_before_write = CommandError("synthetic broker failure")
        gate.release_claim_error = CommandError("synthetic claim initially unavailable")
        old_supervisor = self.supervisor(gate)

        with self.assertRaisesRegex(CommandError, "broker failure"):
            old_supervisor.start(self.fence, "unmount", ("fusermount3",))

        command_id = self.catalog.hardware_commands_for_operation("op-a")[0].id
        gate.abort_and_wait(1.0)
        database_path = self.catalog.path
        self.catalog.close()
        self.catalog = Catalog(database_path)
        self.catalog.initialize()
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        launcher = FakeLauncher([])
        launcher.scopes[gate.scope.identity] = gate.scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )

        evidence = supervisor.reconcile_one(command_id, current)

        command = self.catalog.command(command_id)
        self.assertEqual("launch_aborted", evidence.outcome)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("aborted", command.release_status)
        self.assertNotEqual("completed", command.exit_outcome)
        receipt = self.catalog.create_command_quiescence_receipt("op-a", current)
        self.assertEqual((command_id,), receipt.command_ids)
        self.assertEqual([], launcher.argv)

    def test_restart_keeps_ambiguous_when_negative_evidence_is_unavailable(
        self,
    ) -> None:
        identity = ProcessIdentity("boot-a", 139, 472, 139)
        gate = FakeGate(identity)
        old_supervisor = self.supervisor(gate)
        command_id = old_supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        permit = gate.prepare_release()
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        self.catalog.mark_hardware_command_release_ambiguous(
            command_id, self.daemon_fence, permit
        )
        gate.abort_and_wait(1.0)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        gate.scope.release_claim_error = CommandError(
            "synthetic broker claim unavailable"
        )
        launcher = FakeLauncher([])
        launcher.scopes[gate.scope.identity] = gate.scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )

        with self.assertRaisesRegex(CommandError, "claim unavailable"):
            supervisor.reconcile_one(command_id, current)

        command = self.catalog.command(command_id)
        self.assertEqual("release_authorized", command.state)
        self.assertEqual("ambiguous", command.release_status)
        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )

    def test_restart_rejects_negative_evidence_for_a_different_release(
        self,
    ) -> None:
        identity = ProcessIdentity("boot-a", 140, 473, 140)
        gate = FakeGate(identity)
        old_supervisor = self.supervisor(gate)
        command_id = old_supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        permit = gate.prepare_release()
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        self.catalog.mark_hardware_command_release_ambiguous(
            command_id, self.daemon_fence, permit
        )
        gate.abort_and_wait(1.0)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        launcher = FakeLauncher([])
        launcher.scopes[gate.scope.identity] = gate.scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=launcher,
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )
        exact = command_supervisor_module.CommandReleaseClaim(
            gate.scope.identity, identity.pid, permit, False, True
        )
        mismatches = (
            replace(
                exact,
                scope=ExecutionScopeIdentity(
                    "different-command", gate.scope.identity.owner_generation
                ),
            ),
            replace(
                exact,
                scope=ExecutionScopeIdentity(command_id, current.generation),
            ),
            replace(exact, pid=identity.pid + 1),
            replace(exact, permit_sha256="f" * 64),
            replace(exact, permit_revoked=False),
            replace(exact, released=True),
        )

        for claim in mismatches:
            with (
                self.subTest(claim=claim),
                patch.object(gate.scope, "claim_unreleased", return_value=claim),
                self.assertRaisesRegex(CommandError, "does not match"),
            ):
                supervisor.reconcile_one(command_id, current)

        command = self.catalog.command(command_id)
        self.assertEqual("release_authorized", command.state)
        self.assertEqual("ambiguous", command.release_status)
        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )

    def test_recovery_does_not_signal_when_exact_process_is_already_absent(
        self,
    ) -> None:
        identity = ProcessIdentity("boot-a", 127, 460, 127)
        gate = FakeGate(identity)
        terminator = FakeTerminator()
        supervisor = self.supervisor(gate, terminator=terminator)
        command_id = supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        permit = gate.prepare_release()
        self.catalog.authorize_hardware_command_release(command_id, self.fence, permit)
        gate.release(permit)
        self.catalog.confirm_hardware_command_released(command_id, self.fence, permit)

        evidence = supervisor.terminate_and_await(command_id, self.daemon_fence)

        self.assertEqual("completed", evidence.outcome)
        self.assertEqual([], terminator.calls)

    def test_reconcile_covers_every_command_with_current_generation_receipt(
        self,
    ) -> None:
        identity = ProcessIdentity("boot-a", 128, 461, 128)
        gate = FakeGate(identity)
        old_supervisor = self.supervisor(gate)
        command_id = old_supervisor.reserve_and_launch_blocked(
            self.fence, "unmount", ("fusermount3",)
        )
        current = self.catalog.claim_daemon_owner("daemon-b")
        recovered = self.catalog.recover_interrupted_operations(current)
        self.assertEqual(("op-a",), tuple(record.id for record in recovered))
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=current,
            launcher=FakeLauncher([]),
            process_probe=FakeProcessProbe(),
            process_terminator=FakeTerminator(),
        )

        receipt = supervisor.reconcile("op-a", current)

        self.assertEqual((command_id,), receipt.command_ids)
        self.assertEqual(current.generation, receipt.reconciled_by_generation)
        self.assertEqual("launch_aborted", receipt.evidence[0].outcome)

    def test_read_only_recovery_closes_only_old_empty_identify_reservation(self):
        command_id = "orphan-identify"
        self.catalog.reserve_hardware_command(self.fence, command_id, "identify", "a" * 64)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        scope = FakeScope(ExecutionScopeIdentity(command_id, self.fence.owner_generation), 0)
        scope.members = ()
        launcher = FakeLauncher([])
        launcher.scopes[scope.identity] = scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog, daemon_fence=current, launcher=launcher,
            process_probe=FakeProcessProbe(), process_terminator=FakeTerminator(),
        )
        supervisor.reconcile_empty_identify_reservation(
            command_id, RecoveryCommandFence("op-a", current.generation)
        )
        self.assertTrue(scope.closed)
        command = self.catalog.command(command_id)
        self.assertEqual("quiesced", command.state)
        self.assertEqual("launch_aborted", command.exit_outcome)
        self.assertIsNone(command.process)
        self.assertEqual("recovery_required", self.catalog.get_operation("op-a")["state"])

    def test_read_only_recovery_never_signals_a_populated_reservation(self):
        command_id = "populated-identify"
        self.catalog.reserve_hardware_command(self.fence, command_id, "identify", "a" * 64)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        scope = FakeScope(ExecutionScopeIdentity(command_id, self.fence.owner_generation), 123)
        launcher = FakeLauncher([])
        launcher.scopes[scope.identity] = scope
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog, daemon_fence=current, launcher=launcher,
            process_probe=FakeProcessProbe(), process_terminator=FakeTerminator(),
        )
        with self.assertRaises(CommandError):
            supervisor.reconcile_empty_identify_reservation(
                command_id, RecoveryCommandFence("op-a", current.generation)
            )
        self.assertEqual((123,), scope.members)
        self.assertFalse(scope.closed)
        self.assertEqual("launch_reserved", self.catalog.command(command_id).state)

    def test_read_only_recovery_refuses_current_generation_and_non_identify_commands(self):
        self.catalog.reserve_hardware_command(self.fence, "old-format", "format", "a" * 64)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        fence = RecoveryCommandFence("op-a", current.generation)
        self.catalog.reserve_hardware_command(fence, "current-identify", "identify", "a" * 64)
        launcher = FakeLauncher([])
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog, daemon_fence=current, launcher=launcher,
            process_probe=FakeProcessProbe(), process_terminator=FakeTerminator(),
        )
        for command_id in ("old-format", "current-identify"):
            with self.subTest(command=command_id), self.assertRaises(CommandError):
                supervisor.reconcile_empty_identify_reservation(command_id, fence)
            self.assertEqual("launch_reserved", self.catalog.command(command_id).state)
        self.assertEqual({}, launcher.scopes)

    def test_read_only_recovery_keeps_blocker_on_scope_close_failure_or_catalog_drift(self):
        for command_id in ("close-failure", "catalog-drift"):
            self.catalog.reserve_hardware_command(self.fence, command_id, "identify", "a" * 64)
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        for command_id in ("close-failure", "catalog-drift"):
            scope = FakeScope(ExecutionScopeIdentity(command_id, self.fence.owner_generation), 0)
            scope.members = ()
            def close():
                if command_id == "close-failure":
                    raise CommandError("release acknowledgement lost")
                self.catalog.connection.execute(
                    "UPDATE hardware_command_executions SET argv_sha256=? WHERE id=?",
                    ("b" * 64, command_id),
                )
                self.catalog.connection.commit()
            scope.close = close
            launcher = FakeLauncher([])
            launcher.scopes[scope.identity] = scope
            supervisor = TrackedCommandSupervisor(
                catalog=self.catalog, daemon_fence=current, launcher=launcher,
                process_probe=FakeProcessProbe(), process_terminator=FakeTerminator(),
            )
            with self.subTest(command=command_id), self.assertRaises(CommandError):
                supervisor.reconcile_empty_identify_reservation(
                    command_id, RecoveryCommandFence("op-a", current.generation),
                )
            self.assertEqual("launch_reserved", self.catalog.command(command_id).state)

    def test_timeout_uses_bounded_term_then_kill_and_acknowledges_absence(self) -> None:
        identity = ProcessIdentity("boot-a", 125, 458, 125)
        gate = FakeGate(identity, CommandTimeout("format"))
        terminator = FakeTerminator()
        probe = FakeProcessProbe()

        with self.assertRaisesRegex(CommandTimeout, "format"):
            self.supervisor(gate, probe=probe, terminator=terminator).run(
                self.fence, "format", ("mkltfs",), 1.0
            )

        self.assertEqual([(0.25, 0.5)], gate.termination_calls)
        self.assertEqual([], terminator.calls)
        self.assertEqual([identity], probe.identities)
        self.assertEqual(
            "terminated",
            self.catalog.hardware_commands_for_operation("op-a")[0].exit_outcome,
        )

    def test_nonquiescent_group_is_never_acknowledged(self) -> None:
        identity = ProcessIdentity("boot-a", 126, 459, 126)
        gate = FakeGate(identity)
        probe = FakeProcessProbe(fail=True)

        with self.assertRaises(ProcessQuiescenceTimeout):
            self.supervisor(gate, probe=probe).run(
                self.fence, "status", ("mt", "status"), 1.0
            )

        self.assertEqual(
            "released", self.catalog.hardware_commands_for_operation("op-a")[0].state
        )

    def test_secret_values_do_not_change_persisted_argument_digest(self) -> None:
        first = redacted_argv_sha256(("tool", "--token", SecretArgument("secret-a")))
        second = redacted_argv_sha256(("tool", "--token", SecretArgument("secret-b")))
        self.assertEqual(first, second)

    def test_pid_reuse_is_not_the_original_identity_but_owned_group_still_blocks(
        self,
    ) -> None:
        expected = ProcessIdentity("boot-a", 200, 10, 200)
        reused = ProcessObservation(ProcessIdentity("boot-a", 200, 99, 999), 1)
        descendant = ProcessObservation(ProcessIdentity("boot-a", 201, 20, 200), 200)
        clock = FakeClock()
        snapshots = iter(((reused, descendant), (reused, descendant)))
        probe = SnapshotProcessProbe(
            snapshot=lambda: next(snapshots),
            boot_id=lambda: "boot-a",
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.1,
        )

        with self.assertRaises(ProcessQuiescenceTimeout):
            probe.await_identity_and_group_absent(expected, 0.1)

    def test_exact_pid_reuse_after_group_exit_is_quiescent(self) -> None:
        expected = ProcessIdentity("boot-a", 200, 10, 200)
        reused = ProcessObservation(ProcessIdentity("boot-a", 200, 99, 999), 1)
        clock = FakeClock()
        probe = SnapshotProcessProbe(
            snapshot=lambda: (reused,),
            boot_id=lambda: "boot-a",
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.1,
        )
        self.assertTrue(probe.await_identity_and_group_absent(expected, 0.1))

    def test_changed_boot_never_matches_stale_process_identity(self) -> None:
        expected = ProcessIdentity("boot-old", 200, 10, 200)
        clock = FakeClock()
        probe = SnapshotProcessProbe(
            snapshot=lambda: (),
            boot_id=lambda: "boot-new",
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.1,
        )
        self.assertTrue(probe.await_identity_and_group_absent(expected, 0.1))

    def test_batch_absence_uses_one_fresh_boot_and_snapshot_in_input_order(self) -> None:
        exact = ProcessIdentity("boot-a", 200, 10, 200)
        absent = ProcessIdentity("boot-a", 300, 10, 300)
        reused = ProcessObservation(ProcessIdentity("boot-a", 300, 99, 999), 1)
        snapshots = [
            (ProcessObservation(exact, 1), reused),
            (),
        ]
        with patch.object(command_supervisor_module, "_proc_snapshot", side_effect=snapshots) as snapshot, patch.object(
            command_supervisor_module, "_read_boot_id", return_value="boot-a"
        ) as boot:
            probe = LinuxProcessProbe()
            self.assertEqual((True, False, True, False), probe.identities_and_groups_absent((absent, exact, absent, exact)))
            self.assertEqual(1, boot.call_count)
            snapshot.assert_called_once_with(boot_id="boot-a")
            self.assertEqual((True, True), probe.identities_and_groups_absent((exact, absent)))
            self.assertEqual(2, boot.call_count)
            self.assertEqual(2, snapshot.call_count)

    def test_batch_absence_preserves_group_and_escaped_descendant_tracking(self) -> None:
        root = ProcessIdentity("boot-a", 300, 10, 300)
        child = ProcessIdentity("boot-a", 301, 11, 300)
        escaped = ProcessIdentity("boot-a", 301, 11, 301)
        group_root = ProcessIdentity("boot-a", 400, 20, 400)
        group_member = ProcessIdentity("boot-a", 401, 21, 400)
        snapshots = iter((
            (ProcessObservation(root, 1), ProcessObservation(child, 300), ProcessObservation(group_member, 1)),
            (ProcessObservation(escaped, 1),),
            (),
        ))
        probe = SnapshotProcessProbe(snapshot=lambda: next(snapshots), boot_id=lambda: "boot-a")
        self.assertEqual((False, False), probe.identities_and_groups_absent((root, group_root)))
        self.assertEqual((False, True), probe.identities_and_groups_absent((root, group_root)))
        self.assertEqual((True, True), probe.identities_and_groups_absent((root, group_root)))
        self.assertEqual({}, probe._tracked_by_root)

    def test_batch_absence_handles_empty_and_old_boot_without_snapshot(self) -> None:
        with patch.object(command_supervisor_module, "_proc_snapshot", side_effect=AssertionError("unneeded snapshot")), patch.object(
            command_supervisor_module, "_read_boot_id", return_value="boot-new"
        ) as boot:
            probe = LinuxProcessProbe()
            self.assertEqual((), probe.identities_and_groups_absent(()))
            boot.assert_not_called()
            old = ProcessIdentity("boot-old", 300, 10, 300)
            self.assertEqual((True, True), probe.identities_and_groups_absent((old, old)))
            boot.assert_called_once_with()

    def test_batch_absence_does_not_convert_failed_observation_into_absence(self) -> None:
        root = ProcessIdentity("boot-a", 300, 10, 300)
        for fail_boot in (False, True):
            with self.subTest(fail_boot=fail_boot):
                failure = OSError("synthetic observation unavailable")
                def boot():
                    if fail_boot:
                        raise failure
                    return "boot-a"
                def snapshot():
                    raise failure
                probe = SnapshotProcessProbe(snapshot=snapshot, boot_id=boot)
                with self.assertRaises(OSError) as caught:
                    probe.identities_and_groups_absent((root,))
                self.assertIs(failure, caught.exception)
                self.assertEqual({}, probe._tracked_by_root)

    def test_proc_snapshot_includes_readable_process_regardless_of_uid(self) -> None:
        proc_root = Path(self.temporary.name) / "proc"
        boot_id = proc_root / "sys" / "kernel" / "random" / "boot_id"
        boot_id.parent.mkdir(parents=True)
        boot_id.write_text("boot-a\n", encoding="ascii")
        foreign = proc_root / "417"
        foreign.mkdir()
        (foreign / "stat").write_text(
            "417 (foreign) S 1 417 417 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 123\n",
            encoding="ascii",
        )

        with patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            observed = command_supervisor_module._proc_snapshot(proc_root)

        self.assertEqual(
            (
                ProcessObservation(
                    ProcessIdentity("boot-a", 417, 123, 417),
                    parent_pid=1,
                ),
            ),
            observed,
        )

    def test_proc_identity_reads_are_binary_without_terminal_detection(self) -> None:
        proc_root = Path(self.temporary.name) / "binary-proc"
        boot_id = proc_root / "sys/kernel/random/boot_id"
        boot_id.parent.mkdir(parents=True)
        boot_id.write_bytes(b"boot-a\n")
        process = proc_root / "417"
        process.mkdir()
        (process / "stat").write_bytes(
            b"417 (foreign) S 1 417 417 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 123\n"
        )

        with patch.object(Path, "read_text", side_effect=AssertionError("text open may issue TCGETS")), patch.object(
            Path, "read_bytes", side_effect=AssertionError("automatic buffering may issue TCGETS")
        ):
            observed = command_supervisor_module._proc_snapshot(proc_root)

        self.assertEqual(ProcessIdentity("boot-a", 417, 123, 417), observed[0].identity)

    def test_binary_proc_identity_reads_preserve_strict_ascii_validation(self) -> None:
        proc_root = Path(self.temporary.name) / "invalid-proc"
        boot_id = proc_root / "sys/kernel/random/boot_id"
        boot_id.parent.mkdir(parents=True)
        boot_id.write_bytes(b"boot-a\n")
        process = proc_root / "417"
        process.mkdir()
        (process / "stat").write_bytes(b"417 (invalid-\xff) S\n")

        self.assertEqual((), command_supervisor_module._proc_snapshot(proc_root))
        boot_id.write_bytes(b"invalid-\xff\n")
        with self.assertRaises(UnicodeDecodeError):
            command_supervisor_module._proc_snapshot(proc_root)

    def test_proc_reader_explicitly_disables_automatic_buffering(self) -> None:
        proc_file = Path(self.temporary.name) / "proc-stat"
        proc_file.write_bytes(b"read-only proc evidence\n")
        original_open = Path.open
        with patch.object(Path, "open", autospec=True, side_effect=original_open) as opened:
            result = command_supervisor_module._read_proc_text(proc_file, "ascii")
        self.assertEqual("read-only proc evidence\n", result)
        opened.assert_called_once_with(proc_file, "rb", buffering=0)

    def test_privilege_proc_reads_are_binary_without_terminal_detection(self) -> None:
        boundary = self.read_only_boundary()
        with patch.object(Path, "read_text", side_effect=AssertionError("text open may issue TCGETS")), patch.object(
            Path, "read_bytes", side_effect=AssertionError("automatic buffering may issue TCGETS")
        ), patch.object(os, "access", return_value=False), patch.object(
            boundary, "_assert_no_cgroup_descriptors"
        ):
            boundary._assert_locked_control_tree()

    def test_descendant_that_escapes_process_group_remains_owned_and_blocks(
        self,
    ) -> None:
        expected = ProcessIdentity("boot-a", 300, 10, 300)
        child = ProcessIdentity("boot-a", 301, 11, 300)
        escaped = ProcessIdentity("boot-a", 301, 11, 301)
        clock = FakeClock()
        snapshots = iter(
            (
                (
                    ProcessObservation(expected, 1),
                    ProcessObservation(child, 300),
                ),
                (ProcessObservation(escaped, 1),),
                (ProcessObservation(escaped, 1),),
            )
        )
        probe = SnapshotProcessProbe(
            snapshot=lambda: next(snapshots),
            boot_id=lambda: "boot-a",
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.1,
        )
        with self.assertRaises(ProcessQuiescenceTimeout):
            probe.await_identity_and_group_absent(expected, 0.2)

    def test_scope_check_rejects_a_descendant_that_escaped_process_group(self) -> None:
        expected = ProcessIdentity("boot-a", 305, 10, 305)
        escaped = ProcessIdentity("boot-a", 306, 11, 306)
        probe = SnapshotProcessProbe(
            snapshot=lambda: (
                ProcessObservation(expected, 1),
                ProcessObservation(escaped, 305),
            ),
            boot_id=lambda: "boot-a",
        )

        with self.assertRaisesRegex(Exception, "escape"):
            probe.assert_scope_intact(expected)

    def test_escape_tracking_survives_term_to_kill_poll_boundaries(self) -> None:
        expected = ProcessIdentity("boot-a", 310, 10, 310)
        child = ProcessIdentity("boot-a", 311, 11, 310)
        escaped = ProcessIdentity("boot-a", 311, 11, 311)
        clock = FakeClock()
        snapshots = iter(
            (
                (
                    ProcessObservation(expected, 1),
                    ProcessObservation(child, 310),
                ),
                (ProcessObservation(escaped, 1),),
            )
        )
        probe = SnapshotProcessProbe(
            snapshot=lambda: next(snapshots),
            boot_id=lambda: "boot-a",
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.1,
        )
        self.assertFalse(probe.identity_and_group_absent(expected))
        self.assertFalse(probe.identity_and_group_absent(expected))

    def test_posix_terminator_escalates_term_to_kill_with_bounded_waits(self) -> None:
        identity = ProcessIdentity("boot-a", 400, 20, 400)

        class Probe:
            def __init__(self) -> None:
                self.waits: list[float] = []

            def exact_identity_present(self, expected: ProcessIdentity) -> bool:
                return expected == identity

            def await_identity_and_group_absent(
                self, expected: ProcessIdentity, timeout: float
            ) -> str:
                self.waits.append(timeout)
                if len(self.waits) == 1:
                    raise ProcessQuiescenceTimeout("still present")
                return "2026-08-21T12:00:03+00:00"

        probe = Probe()
        terminator = PosixProcessTerminator(probe)
        with patch("ltobackup.tape.command_supervisor.os.killpg") as killpg:
            terminator.terminate_group(identity, 0.25, 0.5)
        self.assertEqual(
            [call(400, signal.SIGTERM), call(400, signal.SIGKILL)],
            killpg.call_args_list,
        )
        self.assertEqual([0.25, 0.5], probe.waits)

        with self.assertRaises(ValueError):
            terminator.terminate_group(identity, float("nan"), 0.5)

    def test_command_failure_never_exposes_secret_arguments_or_stderr(self) -> None:
        identity = ProcessIdentity("boot-a", 500, 30, 500)
        gate = FakeGate(identity, CompletedCommand(7, "", "secret-a in stderr"))
        with self.assertRaises(Exception) as raised:
            self.supervisor(gate).run(
                self.fence,
                "status",
                ("tool", "--token", SecretArgument("secret-a")),
                1.0,
            )
        self.assertNotIn("secret-a", str(raised.exception))

    def test_real_parent_eof_wrapper_is_reaped_without_vendor_exec(self) -> None:
        marker = Path(self.temporary.name) / "must-not-exist"
        gate = TestOnlyForkExecCommandLauncher(
            ProcessGroupExecutionScopeManager(), TestOnlySameUidPrivilegeBoundary()
        ).launch_blocked(
            (
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                str(marker),
            )
        )

        result = gate.abort_and_wait(2.0)

        self.assertEqual(125, result.returncode)
        self.assertFalse(marker.exists())
        with self.assertRaises(ChildProcessError):
            os.waitpid(gate.pid, os.WNOHANG)

    def test_real_release_revalidates_boundary_before_vendor_exec(self) -> None:
        marker = Path(self.temporary.name) / "must-not-release"

        class Boundary(TestOnlySameUidPrivilegeBoundary):
            unsafe = False

            def release(
                self, scope, pid: int, permit_sha256: str, release_fd: int
            ) -> None:
                if self.unsafe:
                    raise CommandError("synthetic release boundary changed")
                super().release(scope, pid, permit_sha256, release_fd)

        boundary = Boundary()
        gate = TestOnlyForkExecCommandLauncher(
            ProcessGroupExecutionScopeManager(), boundary
        ).launch_blocked(
            (
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).touch()",
                str(marker),
            )
        )
        boundary.unsafe = True

        with self.assertRaisesRegex(CommandError, "boundary changed"):
            gate.release(gate.prepare_release())
        result = gate.abort_and_wait(2.0)

        self.assertEqual(125, result.returncode)
        self.assertFalse(marker.exists())

    def test_real_wrapper_closes_unapproved_inherited_descriptors_before_exec(
        self,
    ) -> None:
        inherited = Path(self.temporary.name) / "inherited-control-capability"
        inherited.touch()
        fd = os.open(inherited, os.O_RDONLY)
        os.set_inheritable(fd, True)
        gate = TestOnlyForkExecCommandLauncher(
            ProcessGroupExecutionScopeManager(), TestOnlySameUidPrivilegeBoundary()
        ).launch_blocked(
            (
                sys.executable,
                "-c",
                "import os,sys; print(os.path.exists(sys.argv[1]))",
                f"/proc/self/fd/{fd}",
            )
        )
        try:
            permit = gate.prepare_release()
            gate.release(permit)
            result = gate.wait(2.0)
        finally:
            os.close(fd)

        self.assertEqual("False\n", result.stdout)

    def test_real_wrapper_preserves_anchored_fd_across_exec(self) -> None:
        anchor = Path(self.temporary.name) / "anchored-device"
        anchor.write_text("anchored", encoding="ascii")
        fd = os.open(anchor, os.O_PATH | os.O_CLOEXEC)
        probe = LinuxProcessProbe()
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=TestOnlyForkExecCommandLauncher(
                ProcessGroupExecutionScopeManager(),
                TestOnlySameUidPrivilegeBoundary(),
            ),
            process_probe=probe,
            process_terminator=PosixProcessTerminator(probe),
            quiescence_timeout=1.0,
            term_timeout=0.1,
            kill_timeout=0.1,
        )
        try:
            result = supervisor.run(
                self.fence,
                "status",
                (
                    sys.executable,
                    "-c",
                    "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
                    f"/proc/self/fd/{fd}",
                ),
                2.0,
                (fd,),
            )
        finally:
            os.close(fd)

        self.assertEqual("anchored\n", result.stdout)

    def test_real_wrapper_enforces_output_quota_at_write_boundary(self) -> None:
        probe = LinuxProcessProbe()
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=TestOnlyForkExecCommandLauncher(
                ProcessGroupExecutionScopeManager(),
                TestOnlySameUidPrivilegeBoundary(),
            ),
            process_probe=probe,
            process_terminator=PosixProcessTerminator(probe),
            quiescence_timeout=1.0,
            term_timeout=0.1,
            kill_timeout=0.1,
        )

        with self.assertRaisesRegex(CommandError, "output exceeds"):
            supervisor.run(
                self.fence,
                "status",
                (
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'x' * (64 * 1024 + 1))",
                ),
                2.0,
            )

        command = self.catalog.hardware_commands_for_operation("op-a")[0]
        self.assertEqual("quiesced", command.state)
        self.assertEqual("completed", command.exit_outcome)

    def test_real_foreground_process_stays_durable_until_explicit_stop(self) -> None:
        probe = LinuxProcessProbe()
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=TestOnlyForkExecCommandLauncher(
                ProcessGroupExecutionScopeManager(),
                TestOnlySameUidPrivilegeBoundary(),
            ),
            process_probe=probe,
            process_terminator=PosixProcessTerminator(probe),
            quiescence_timeout=1.0,
            term_timeout=0.1,
            kill_timeout=0.1,
        )
        running = supervisor.start(
            self.fence, "mount", (sys.executable, "-c", "import time; time.sleep(30)")
        )

        supervisor.assert_running(running)
        self.assertEqual("released", self.catalog.command(running.command_id).state)
        evidence = supervisor.terminate_and_await(running.command_id)

        self.assertEqual("terminated", evidence.outcome)
        self.assertEqual("quiesced", self.catalog.command(running.command_id).state)
        with self.assertRaises(ChildProcessError):
            os.waitpid(running.process.pid, os.WNOHANG)

    def test_real_daemon_escape_is_rejected_and_never_acknowledged(self) -> None:
        marker = Path(self.temporary.name) / "escaped-pid"
        probe = LinuxProcessProbe()
        supervisor = TrackedCommandSupervisor(
            catalog=self.catalog,
            daemon_fence=self.daemon_fence,
            launcher=TestOnlyForkExecCommandLauncher(
                ProcessGroupExecutionScopeManager(),
                TestOnlySameUidPrivilegeBoundary(),
            ),
            process_probe=probe,
            process_terminator=PosixProcessTerminator(probe),
            quiescence_timeout=0.2,
            term_timeout=0.1,
            kill_timeout=0.1,
        )
        running = supervisor.start(
            self.fence,
            "mount",
            (
                sys.executable,
                "-c",
                (
                    "import os,sys,time; child=os.fork(); "
                    "(os.setsid(),open(sys.argv[1],'w').write(str(os.getpid())),"
                    "time.sleep(30)) if child==0 else time.sleep(30)"
                ),
                str(marker),
            ),
        )
        deadline = time.monotonic() + 2.0
        escaped_pid: int | None = None
        while escaped_pid is None and time.monotonic() < deadline:
            try:
                marker_text = marker.read_text(encoding="ascii")
                if marker_text:
                    escaped_pid = int(marker_text)
                    break
            except FileNotFoundError:
                pass
            time.sleep(0.01)
        if escaped_pid is None:
            self.fail("escaped child did not publish its PID before the deadline")
        try:
            with self.assertRaisesRegex(Exception, "escape"):
                supervisor.assert_running(running)
            with self.assertRaises(ProcessQuiescenceTimeout):
                supervisor.terminate_and_await(running.command_id)
            self.assertEqual("released", self.catalog.command(running.command_id).state)
        finally:
            try:
                os.kill(escaped_pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_real_late_self_escape_pairing_is_rejected_before_vendor_exec(
        self,
    ) -> None:
        marker = Path(self.temporary.name) / "late-escaped-pid"
        probe = LinuxProcessProbe()
        escaped_pid: int | None = None
        try:
            with (
                patch(
                    "ltobackup.tape.command_supervisor.os.geteuid", return_value=1000
                ),
                patch(
                    "ltobackup.tape.command_supervisor.os.access", return_value=False
                ),
                self.assertRaisesRegex(CommandError, "attested brokered cgroup"),
            ):
                supervisor = TrackedCommandSupervisor(
                    catalog=self.catalog,
                    daemon_fence=self.daemon_fence,
                    launcher=ForkExecCommandLauncher(
                        ProcessGroupExecutionScopeManager(), self.read_only_boundary()
                    ),
                    process_probe=probe,
                    process_terminator=PosixProcessTerminator(probe),
                    quiescence_timeout=0.2,
                    term_timeout=0.1,
                    kill_timeout=0.1,
                )
                supervisor.run(
                    self.fence,
                    "mount",
                    (
                        sys.executable,
                        "-c",
                        (
                            "import os,sys,time; child=os.fork(); "
                            "(os.setsid(),open(sys.argv[1],'w').write(str(os.getpid())),"
                            "time.sleep(30)) if child==0 else time.sleep(0.1)"
                        ),
                        str(marker),
                    ),
                    2.0,
                )
            self.assertFalse(marker.exists())
            self.assertEqual((), self.catalog.hardware_commands_for_operation("op-a"))
        finally:
            if self.catalog.hardware_commands_for_operation("op-a"):
                deadline = time.monotonic() + 1.0
                while not marker.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
            if marker.exists():
                escaped_pid = int(marker.read_text(encoding="ascii"))
            if escaped_pid is not None:
                try:
                    os.kill(escaped_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_read_only_boundary_rejects_any_alternate_writable_cgroup_mount(
        self,
    ) -> None:
        alternate = Path(self.temporary.name) / "alternate-cgroup"
        alternate.mkdir()
        boundary = self.read_only_boundary(
            additional_mounts=(
                f"42 32 0:40 / {alternate} rw,nosuid - cgroup2 cgroup rw",
            )
        )

        with (
            patch("ltobackup.tape.command_supervisor.os.geteuid", return_value=1000),
            patch("ltobackup.tape.command_supervisor.os.access", return_value=False),
            self.assertRaisesRegex(CommandError, "writable cgroup"),
        ):
            boundary.validate_supervisor()

    def test_read_only_boundary_rejects_preopened_cgroup_control_fd(self) -> None:
        boundary = self.read_only_boundary()
        control_fd = os.open(boundary.control_root / "cgroup.procs", os.O_RDONLY)
        try:
            with (
                patch(
                    "ltobackup.tape.command_supervisor.os.geteuid", return_value=1000
                ),
                patch(
                    "ltobackup.tape.command_supervisor.os.access", return_value=False
                ),
                self.assertRaisesRegex(CommandError, "cgroup control descriptor"),
            ):
                boundary.validate_supervisor()
        finally:
            os.close(control_fd)

    def test_read_only_boundary_rejects_nonbrokered_scope(self) -> None:
        scope = FakeScope(ExecutionScopeIdentity("synthetic-command", 4), -1)
        scope.members = ()

        with self.assertRaisesRegex(CommandError, "attested brokered cgroup"):
            self.read_only_boundary().prepare_scope(scope)


if __name__ == "__main__":
    unittest.main()
