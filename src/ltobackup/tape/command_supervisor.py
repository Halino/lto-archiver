from __future__ import annotations

import hashlib
import json
import math
import os
import resource
import secrets
import sqlite3
import select
import signal
import stat
import tempfile
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol, cast

from ltobackup.catalog import Catalog
from ltobackup.daemon.models import (
    CommandExitEvidence,
    CommandQuiescenceReceipt,
    DaemonFence,
    HardwareCommandExecution,
    OperationFence,
    ProcessIdentity,
    RecoveryCommandFence,
)
from ltobackup.operational_log import (
    NullOperationalEventSink,
    OperationalCorrelation,
    OperationalEvent,
    OperationalEventSink,
    OperationalSeverity,
    OperationalSource,
    closed_operational_correlation,
    coalesce_operational_lines,
)

_OUTPUT_MEMORY_LIMIT = 64 * 1024
_MAX_OPERATIONAL_OUTPUT_EVENTS = 64
_OPERATIONAL_OUTPUT_SUMMARY_RESERVE = 128
# The extra byte is a saturation sentinel: bounded collection can distinguish
# a legitimate 64 KiB result from output that reached the kernel file quota.
_OUTPUT_FILE_LIMIT = _OUTPUT_MEMORY_LIMIT + 1


class CommandError(RuntimeError):
    pass


class ScopeExchangeError(CommandError):
    """Closed broker diagnostics; no remote exception text crosses this seam."""

    def __init__(self, action: str, reason: object) -> None:
        self.reason = reason if type(reason) is str and reason in {
            "timeout", "eof", "protocol", "rejected", "pre_dispatch", "transport",
        } else "unavailable"
        self.quiesced = False
        super().__init__(f"brokered cgroup scope could not be {action}")


class ReleasePreparationError(ScopeExchangeError):
    """A failed exchange before any authorization or release-byte dispatch."""

    def __init__(self, reason: object) -> None:
        super().__init__("prepared for release", reason)


class CommandTimeout(CommandError):
    def __init__(self, kind: str) -> None:
        self.kind = kind
        super().__init__(f"hardware command timed out: {kind}")


class CommandFailed(CommandError):
    def __init__(self, kind: str, returncode: int) -> None:
        self.kind = kind
        self.returncode = returncode
        super().__init__(f"hardware command failed: {kind} (exit {returncode})")


class ProcessQuiescenceTimeout(CommandError):
    pass


class ProcessIdentityMismatch(CommandError):
    pass


class SecretArgument(str):
    """An argv value whose plaintext must not influence durable metadata."""


@dataclass(frozen=True)
class CompletedCommand:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class RunningCommand:
    command_id: str
    process: ProcessIdentity
    scope: ExecutionScopeIdentity


@dataclass(frozen=True)
class ExecutionScopeIdentity:
    command_id: str
    owner_generation: int


@dataclass(frozen=True)
class CommandReleaseClaim:
    """Atomic broker claim of one exact command gate release permit."""

    scope: ExecutionScopeIdentity
    pid: int
    permit_sha256: str
    released: bool
    permit_revoked: bool


class ExecutionScope(Protocol):
    identity: ExecutionScopeIdentity

    def attach(self, pid: int) -> None: ...

    def member_pids(self) -> tuple[int, ...]: ...

    def is_populated(self) -> bool: ...

    def claim_unreleased(self, pid: int, permit_sha256: str) -> CommandReleaseClaim: ...

    def signal(self, signum: int) -> None: ...

    def close(self) -> None: ...


class ExecutionScopeManager(Protocol):
    def create(self, identity: ExecutionScopeIdentity) -> ExecutionScope: ...

    def open(self, identity: ExecutionScopeIdentity) -> ExecutionScope: ...


class _UnavailableExecutionScopeManager:
    def create(self, identity: ExecutionScopeIdentity) -> ExecutionScope:
        raise CommandError("a safe command privilege boundary is unavailable")

    def open(self, identity: ExecutionScopeIdentity) -> ExecutionScope:
        raise CommandError("a safe command privilege boundary is unavailable")


class CommandPrivilegeBoundary(Protocol):
    def validate_supervisor(self) -> None: ...

    def prepare_scope(self, scope: ExecutionScope) -> None: ...

    def enter_child(self) -> None: ...

    def prepare_release(self, scope: ExecutionScope, pid: int) -> str: ...

    def release(
        self,
        scope: ExecutionScope,
        pid: int,
        permit_sha256: str,
        release_fd: int,
    ) -> None: ...

    def claim_unreleased(
        self, scope: ExecutionScope, pid: int, permit_sha256: str
    ) -> CommandReleaseClaim: ...


class UnavailableCommandPrivilegeBoundary:
    """Fail closed until a separately privileged command broker is configured."""

    def validate_supervisor(self) -> None:
        raise CommandError("a safe command privilege boundary is unavailable")

    def prepare_scope(self, scope: ExecutionScope) -> None:
        raise CommandError("a safe command privilege boundary is unavailable")

    def enter_child(self) -> None:
        raise CommandError("a safe command privilege boundary is unavailable")

    def prepare_release(self, scope: ExecutionScope, pid: int) -> str:
        del scope, pid
        raise CommandError("a safe command privilege boundary is unavailable")

    def release(
        self,
        scope: ExecutionScope,
        pid: int,
        permit_sha256: str,
        release_fd: int,
    ) -> None:
        del scope, pid, permit_sha256, release_fd
        raise CommandError("a safe command privilege boundary is unavailable")

    def claim_unreleased(
        self, scope: ExecutionScope, pid: int, permit_sha256: str
    ) -> CommandReleaseClaim:
        del scope, pid, permit_sha256
        raise CommandError("a safe command privilege boundary is unavailable")


def _decode_proc_mount_path(value: str) -> str:
    return (
        value.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


class ReadOnlyCgroupPrivilegeBoundary:
    """Client side of a brokered scope whose cgroupfs view is read-only."""

    def __init__(
        self,
        control_root: Path = Path("/sys/fs/cgroup"),
        *,
        mountinfo_path: Path = Path("/proc/self/mountinfo"),
        status_path: Path = Path("/proc/self/status"),
        fd_root: Path = Path("/proc/self/fd"),
    ) -> None:
        self.control_root = control_root
        self.mountinfo_path = mountinfo_path
        self.status_path = status_path
        self.fd_root = fd_root

    def validate_supervisor(self) -> None:
        self._assert_locked_control_tree()

    def prepare_scope(self, scope: ExecutionScope) -> None:
        if type(scope) is not BrokeredCgroupExecutionScope:
            raise CommandError(
                "command privilege boundary requires an attested brokered cgroup scope"
            )
        scope.assert_prepared()
        self._assert_locked_control_tree()

    def enter_child(self) -> None:
        self._assert_locked_control_tree()

    def prepare_release(self, scope: ExecutionScope, pid: int) -> str:
        if type(scope) is not BrokeredCgroupExecutionScope:
            raise CommandError(
                "command privilege boundary requires an attested brokered cgroup scope"
            )
        self._assert_locked_control_tree()
        return scope.prepare_release(pid)

    def release(
        self,
        scope: ExecutionScope,
        pid: int,
        permit_sha256: str,
        release_fd: int,
    ) -> None:
        if type(scope) is not BrokeredCgroupExecutionScope:
            raise CommandError(
                "command privilege boundary requires an attested brokered cgroup scope"
            )
        self._assert_locked_control_tree()
        scope.release_child(pid, permit_sha256, release_fd)

    def claim_unreleased(
        self, scope: ExecutionScope, pid: int, permit_sha256: str
    ) -> CommandReleaseClaim:
        if type(scope) is not BrokeredCgroupExecutionScope:
            raise CommandError(
                "command privilege boundary requires an attested brokered cgroup scope"
            )
        return scope.claim_unreleased(pid, permit_sha256)

    def _assert_locked_control_tree(self) -> None:
        try:
            root = self.control_root.resolve(strict=True)
            mount_lines = _read_proc_text(self.mountinfo_path, "utf-8").splitlines()
            status = _read_proc_text(self.status_path, "ascii").splitlines()
        except (OSError, RuntimeError):
            raise CommandError(
                "command privilege boundary could not be verified"
            ) from None
        matching_mount = False
        cgroup_mounts: list[Path] = []
        for line in mount_lines:
            fields = line.split()
            try:
                separator = fields.index("-")
            except ValueError:
                continue
            if len(fields) < 6 or len(fields) <= separator + 1:
                continue
            if fields[separator + 1] != "cgroup2":
                continue
            try:
                mount_point = Path(_decode_proc_mount_path(fields[4])).resolve(
                    strict=True
                )
            except (OSError, RuntimeError):
                raise CommandError(
                    "command privilege boundary could not be verified"
                ) from None
            mount_options = fields[5].split(",")
            if "rw" in mount_options or "ro" not in mount_options:
                raise CommandError(
                    "command privilege boundary exposes a writable cgroup mount"
                )
            cgroup_mounts.append(mount_point)
            if mount_point == root:
                matching_mount = True
        values = {
            fields[0].rstrip(":"): fields[1]
            for line in status
            if len(fields := line.split()) == 2
        }
        if (
            not matching_mount
            or os.geteuid() == 0
            or any(
                values.get(field) != "0000000000000000"
                for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
            )
            or values.get("NoNewPrivs") != "1"
        ):
            raise CommandError("command privilege boundary is not locked")
        control_paths = (root, root / "cgroup.procs")
        try:
            for path in control_paths:
                resolved = path.resolve(strict=True)
                if not resolved.is_relative_to(root):
                    raise CommandError(
                        "command privilege boundary has an invalid control path"
                    )
                if os.access(resolved, os.W_OK, effective_ids=True):
                    raise CommandError("command privilege boundary is writable")
        except (OSError, RuntimeError):
            raise CommandError(
                "command privilege boundary could not be verified"
            ) from None
        self._assert_no_cgroup_descriptors(tuple(cgroup_mounts))

    def _assert_no_cgroup_descriptors(self, cgroup_mounts: tuple[Path, ...]) -> None:
        try:
            descriptors = tuple(self.fd_root.iterdir())
        except OSError:
            raise CommandError(
                "command privilege boundary could not inspect open descriptors"
            ) from None
        for descriptor in descriptors:
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            except OSError:
                raise CommandError(
                    "command privilege boundary could not inspect open descriptors"
                ) from None
            target = target.removesuffix(" (deleted)")
            if not target.startswith("/"):
                continue
            try:
                resolved = Path(target).resolve(strict=False)
            except (OSError, RuntimeError):
                raise CommandError(
                    "command privilege boundary could not inspect open descriptors"
                ) from None
            if any(
                resolved == mount or resolved.is_relative_to(mount)
                for mount in cgroup_mounts
            ):
                raise CommandError(
                    "command privilege boundary inherited a cgroup control descriptor"
                )


@dataclass(frozen=True)
class ProcessObservation:
    identity: ProcessIdentity
    parent_pid: int


class LaunchGate(Protocol):
    identity: ProcessIdentity
    scope: ExecutionScope

    def prepare_release(self) -> str: ...

    def release(self, permit_sha256: str) -> None: ...

    def claim_unreleased(self, permit_sha256: str) -> CommandReleaseClaim: ...

    def abort_before_release(self) -> None: ...

    def abort_and_wait(self, timeout: float) -> CompletedCommand: ...

    def wait(self, timeout: float) -> CompletedCommand: ...

    def terminate_group(self, term_timeout: float, kill_timeout: float) -> None: ...


class CommandLauncher(Protocol):
    def launch_blocked(
        self,
        argv: tuple[str, ...],
        scope_identity: ExecutionScopeIdentity,
        pass_fds: tuple[int, ...] = (),
    ) -> LaunchGate: ...

    def open_scope(self, identity: ExecutionScopeIdentity) -> ExecutionScope: ...


class ProcessProbe(Protocol):
    def exact_identity_present(self, expected: ProcessIdentity) -> bool: ...

    def identity_and_group_absent(self, expected: ProcessIdentity) -> bool: ...

    def assert_scope_intact(self, expected: ProcessIdentity) -> None: ...

    def await_identity_and_group_absent(
        self, identity: ProcessIdentity, timeout: float
    ) -> str: ...


class ProcessTerminator(Protocol):
    def terminate_group(
        self, identity: ProcessIdentity, term_timeout: float, kill_timeout: float
    ) -> None: ...


class TerminableProcessProbe(ProcessProbe, Protocol):
    def exact_identity_present(self, expected: ProcessIdentity) -> bool: ...


def redacted_argv_sha256(argv: tuple[str, ...]) -> str:
    canonical = [
        "<redacted>" if isinstance(value, SecretArgument) else str(value)
        for value in argv
    ]
    encoded = json.dumps(canonical, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    return hashlib.sha256(b"lto-command-v1\0" + encoded).hexdigest()


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


_MAX_TIMEOUT_SECONDS = 86_400.0


def _validated_timeout(value: float, name: str) -> float:
    if not math.isfinite(value) or value <= 0.0 or value > _MAX_TIMEOUT_SECONDS:
        raise ValueError(f"{name} must be finite, positive, and at most 86400 seconds")
    return value


class CgroupV2ExecutionScope:
    def __init__(
        self,
        identity: ExecutionScopeIdentity,
        path: Path,
        control_root: Path = Path("/sys/fs/cgroup"),
    ) -> None:
        self.identity = identity
        self.path = path
        self.control_root = control_root

    def attach(self, pid: int) -> None:
        try:
            (self.path / "cgroup.procs").write_text(str(pid), encoding="ascii")
        except OSError:
            raise CommandError("supervised execution scope could not attach") from None

    def member_pids(self) -> tuple[int, ...]:
        try:
            self.path.stat()
        except FileNotFoundError:
            return ()
        except OSError:
            raise CommandError("supervised execution scope could not be read") from None
        members: set[int] = set()
        try:
            control_files = (self.path / "cgroup.procs",) + tuple(
                child
                for child in self.path.rglob("cgroup.procs")
                if child.parent != self.path
            )
            for control_file in control_files:
                members.update(
                    int(value)
                    for value in control_file.read_text(encoding="ascii").split()
                )
        except FileNotFoundError:
            raise CommandError(
                "supervised execution scope changed during inspection"
            ) from None
        except OSError:
            raise CommandError("supervised execution scope could not be read") from None
        except ValueError:
            raise CommandError("supervised execution scope is malformed") from None
        return tuple(sorted(members))

    def is_populated(self) -> bool:
        try:
            raw = (self.path / "cgroup.events").read_text(encoding="ascii")
        except FileNotFoundError:
            return False
        except OSError:
            raise CommandError("supervised execution scope could not be read") from None
        events = {
            fields[0]: fields[1]
            for line in raw.splitlines()
            if len(fields := line.split()) == 2
        }
        populated = events.get("populated")
        if populated not in {"0", "1"}:
            raise CommandError("supervised execution scope events are malformed")
        if populated == "0" and self.member_pids():
            raise CommandError("supervised execution scope events are inconsistent")
        return populated == "1"

    def claim_unreleased(self, pid: int, permit_sha256: str) -> CommandReleaseClaim:
        del pid, permit_sha256
        raise CommandError("authoritative release claim is unavailable")

    def signal(self, signum: int) -> None:
        members = self.member_pids()
        if signum == signal.SIGKILL and (self.path / "cgroup.kill").exists():
            try:
                (self.path / "cgroup.kill").write_text("1", encoding="ascii")
                return
            except OSError:
                raise CommandError(
                    "supervised execution scope could not be killed"
                ) from None
        for pid in members:
            try:
                pidfd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            except OSError:
                raise CommandError(
                    "supervised execution scope could not be signalled"
                ) from None
            try:
                if pid not in self.member_pids():
                    continue
                try:
                    signal.pidfd_send_signal(pidfd, signum)
                except ProcessLookupError:
                    continue
                except OSError:
                    raise CommandError(
                        "supervised execution scope could not be signalled"
                    ) from None
            finally:
                os.close(pidfd)

    def close(self) -> None:
        if self.is_populated():
            raise ProcessQuiescenceTimeout("supervised execution scope is not empty")
        try:
            descendants = sorted(
                (path for path in self.path.rglob("*") if path.is_dir()),
                key=lambda path: len(path.parts),
                reverse=True,
            )
            for descendant in descendants:
                descendant.rmdir()
            self.path.rmdir()
        except FileNotFoundError:
            return
        except OSError:
            raise CommandError(
                "supervised execution scope could not be released"
            ) from None


class CgroupV2ExecutionScopeManager:
    def __init__(
        self,
        root: Path = Path("/sys/fs/cgroup/lto-archiver.commands"),
        control_root: Path = Path("/sys/fs/cgroup"),
    ) -> None:
        self.root = root
        self.control_root = control_root

    @staticmethod
    def _name(identity: ExecutionScopeIdentity) -> str:
        encoded = f"{identity.owner_generation}:{identity.command_id}".encode("ascii")
        return "command-" + hashlib.sha256(b"lto-scope-v1\0" + encoded).hexdigest()

    def create(self, identity: ExecutionScopeIdentity) -> CgroupV2ExecutionScope:
        path = self.root / self._name(identity)
        try:
            path.mkdir(mode=0o700)
        except OSError:
            raise CommandError(
                "supervised cgroup v2 scope could not be created"
            ) from None
        return CgroupV2ExecutionScope(identity, path, self.control_root)

    def open(self, identity: ExecutionScopeIdentity) -> CgroupV2ExecutionScope:
        return CgroupV2ExecutionScope(
            identity, self.root / self._name(identity), self.control_root
        )


@dataclass(frozen=True)
class BrokeredCgroupScopeToken:
    value: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if type(self.value) is not bytes or not 32 <= len(self.value) <= 4096:
            raise ValueError("brokered cgroup scope token must contain 32-4096 bytes")


@dataclass(frozen=True)
class BrokeredCgroupScopeReceipt:
    """Immutable broker-issued binding; opaque proofs are rechecked by the broker."""

    protocol_version: int
    command_id: str
    owner_generation: int
    request_nonce: bytes = field(repr=False)
    scope_id: str
    scope_path_sha256: str
    broker_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)
    recursive_population: bool
    recursive_members: bool
    cgroup_kill: bool


@dataclass(frozen=True)
class LtfsSessionRequest:
    """Closed digest-only request for one broker-owned LTFS mount session."""

    protocol_version: int
    operation_id: str
    owner_generation: int
    mount_path_sha256: str
    tape_device_identity_sha256: str
    scsi_device_identity_sha256: str
    expected_media_scope_sha256: str
    observed_media_identity_sha256: str
    expected_volume_uuid: str
    expected_prior_generation: int
    read_only: bool
    tape_fd_identity_sha256: str
    scsi_fd_identity_sha256: str
    cgroup_scope_receipt: BrokeredCgroupScopeReceipt
    request_nonce: bytes = field(repr=False)


@dataclass(frozen=True)
class LtfsSessionReceipt:
    """Broker proof for one mounted child and its immutable request."""

    protocol_version: int
    operation_id: str
    receipt_operation_uuid: str
    observed_volume_uuid: str
    observed_prior_generation: int
    read_only: bool
    owner_generation: int
    request_nonce: bytes = field(repr=False)
    session_id: str
    request_sha256: str
    child_pid: int
    child_start_ticks: int
    mount_namespace_sha256: str
    broker_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)
    mounted: bool
    observed_volume_label: str
    observed_media_identity_sha256: str


@dataclass(frozen=True)
class LtfsStandaloneReceipt:
    """Exact terminal receipt durably emitted by the standalone LTFS child."""

    schema: int
    stage: Literal["terminal"]
    operation_id: str
    volume_uuid: str
    prior_generation: int
    new_generation: int
    bytes_valid: bool
    bytes: int
    files_valid: bool
    files: int
    phase_duration_ns: tuple[int, ...]
    capture_duration_ns: int
    device_close_duration_ns: int
    device_close_result_valid: bool
    device_close_result: int
    catalog_ack_duration_ns: int
    media_committed: bool
    catalog_acknowledged: bool
    cleanup_failed: bool
    result: int
    terminal_sha256: str


@dataclass(frozen=True)
class LtfsReadyReceipt:
    """Durable identity seal emitted only after LTFS mount initialization."""

    schema: int
    stage: Literal["ready"]
    operation_id: str
    volume_uuid: str
    prior_generation: int
    read_only: bool
    drive_serial: str
    mam_barcode: str
    mam_volume_serial: str
    ltfs_volume_label: str


@dataclass(frozen=True)
class LtfsFinalizationReceipt:
    """Terminal broker proof that the exact session is unmounted and reaped."""

    protocol_version: int
    session_receipt: LtfsSessionReceipt
    standalone_receipt: LtfsStandaloneReceipt
    request_nonce: bytes = field(repr=False)
    finalization_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)
    unmounted: bool
    child_quiesced: bool


@dataclass(frozen=True)
class BrokeredCgroupScopeValidation:
    """Fresh broker response binding an exact receipt to authoritative state."""

    protocol_version: int
    receipt: BrokeredCgroupScopeReceipt
    challenge: bytes = field(repr=False)
    validation_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)
    populated: bool
    member_pids: tuple[int, ...]


@dataclass(frozen=True)
class BrokeredCgroupReleasePermit:
    """One-shot broker permit bound to one receipt and blocked child."""

    protocol_version: int
    receipt: BrokeredCgroupScopeReceipt
    pid: int
    request_nonce: bytes = field(repr=False)
    permit_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)


@dataclass(frozen=True)
class BrokeredCgroupReleaseClaim:
    """Atomic broker outcome for one exact durable release permit."""

    protocol_version: int
    receipt: BrokeredCgroupScopeReceipt
    pid: int
    permit_sha256: str
    challenge: bytes = field(repr=False)
    claim_nonce: bytes = field(repr=False)
    broker_proof: bytes = field(repr=False)
    released: bool
    permit_revoked: bool


class BrokeredCgroupScopeApi(Protocol):
    """Trusted IPC boundary supplied by deployment.

    Client checks detect malformed, replayed, substituted, and inconsistent
    responses. They do not make a malicious in-process implementation trusted;
    deployment must authenticate this API to its separately privileged broker.
    """

    def create_scope(
        self,
        identity: ExecutionScopeIdentity,
        request_nonce: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupScopeReceipt: ...

    def open_scope(
        self,
        identity: ExecutionScopeIdentity,
        request_nonce: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupScopeReceipt: ...

    def attach(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        capability: BrokeredCgroupScopeToken,
    ) -> None: ...

    def validate_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        challenge: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupScopeValidation: ...

    def prepare_release(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        request_nonce: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupReleasePermit: ...

    def release_child(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        permit: BrokeredCgroupReleasePermit,
        pid: int,
        release_fd: int,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        """Atomically consume the exact prepared permit and write the gate byte.

        This operation and ``claim_unreleased`` must be serialized by the
        broker. It must reject permits already revoked by a negative claim.
        """
        ...

    def claim_unreleased(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        pid: int,
        permit_sha256: str,
        challenge: bytes,
        capability: BrokeredCgroupScopeToken,
    ) -> BrokeredCgroupReleaseClaim:
        """Report released or atomically and irrevocably revoke the permit.

        A prepared permit transitions exactly once to released or revoked.
        Revoked state must survive scope release and make every concurrent or
        later ``release_child`` fail. Repeated exact claims may report the same
        terminal outcome, but must carry a fresh challenge-bound broker proof.
        Missing, reused, or receipt/PID/permit-mismatched state must fail.
        """
        ...

    def signal_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        signum: int,
        capability: BrokeredCgroupScopeToken,
    ) -> None: ...

    def kill_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        capability: BrokeredCgroupScopeToken,
    ) -> None: ...

    def release_scope(
        self,
        receipt: BrokeredCgroupScopeReceipt,
        capability: BrokeredCgroupScopeToken,
    ) -> None: ...


def _is_opaque_broker_value(value: object) -> bool:
    return type(value) is bytes and 32 <= len(value) <= 4096


def _broker_release_permit_sha256(permit: BrokeredCgroupReleasePermit) -> str:
    receipt = permit.receipt
    encoded = json.dumps(
        {
            "protocol_version": permit.protocol_version,
            "command_id": receipt.command_id,
            "owner_generation": receipt.owner_generation,
            "scope_id": receipt.scope_id,
            "scope_path_sha256": receipt.scope_path_sha256,
            "scope_request_nonce": receipt.request_nonce.hex(),
            "scope_broker_nonce": receipt.broker_nonce.hex(),
            "scope_broker_proof": receipt.broker_proof.hex(),
            "pid": permit.pid,
            "request_nonce": permit.request_nonce.hex(),
            "permit_nonce": permit.permit_nonce.hex(),
            "broker_proof": permit.broker_proof.hex(),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return hashlib.sha256(b"lto-broker-release-v1\0" + encoded).hexdigest()


def _validate_broker_receipt(
    receipt: BrokeredCgroupScopeReceipt,
    identity: ExecutionScopeIdentity,
    request_nonce: bytes,
) -> None:
    if (
        type(receipt) is not BrokeredCgroupScopeReceipt
        or receipt.protocol_version != 1
        or type(receipt.protocol_version) is not int
        or type(receipt.command_id) is not str
        or receipt.command_id != identity.command_id
        or type(receipt.owner_generation) is not int
        or receipt.owner_generation != identity.owner_generation
        or type(receipt.request_nonce) is not bytes
        or receipt.request_nonce != request_nonce
    ):
        raise CommandError("brokered cgroup receipt does not match command identity")
    if (
        type(receipt.scope_id) is not str
        or not receipt.scope_id
        or len(receipt.scope_id) > 1024
        or not receipt.scope_id.isascii()
        or not receipt.scope_id.isprintable()
        or "/" in receipt.scope_id
        or "\\" in receipt.scope_id
        or type(receipt.scope_path_sha256) is not str
        or len(receipt.scope_path_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in receipt.scope_path_sha256
        )
    ):
        raise CommandError("brokered cgroup receipt has an invalid scope identity")
    if (
        not _is_opaque_broker_value(receipt.broker_nonce)
        or not _is_opaque_broker_value(receipt.broker_proof)
        or receipt.broker_nonce == request_nonce
        or receipt.broker_proof == request_nonce
        or receipt.broker_nonce == receipt.broker_proof
    ):
        raise CommandError("brokered cgroup receipt lacks broker-originated proof")
    if (
        receipt.recursive_population is not True
        or receipt.recursive_members is not True
        or receipt.cgroup_kill is not True
    ):
        raise CommandError(
            "brokered cgroup authority lacks recursive population and kill attestation"
        )


class BrokeredCgroupExecutionScope:
    """Client view whose authority comes only from fresh trusted-broker responses."""

    def __init__(
        self,
        identity: ExecutionScopeIdentity,
        receipt: BrokeredCgroupScopeReceipt,
        api: BrokeredCgroupScopeApi,
        capability: BrokeredCgroupScopeToken,
        release_nonces: set[bytes],
        release_proofs: set[bytes],
    ) -> None:
        self.identity = identity
        self._receipt = receipt
        self._api = api
        self._capability = capability
        self._attached_pid: int | None = None
        self._validation_nonces: set[bytes] = set()
        self._validation_proofs: set[bytes] = set()
        self._release_permits: dict[str, BrokeredCgroupReleasePermit] = {}
        self._release_nonces = release_nonces
        self._release_proofs = release_proofs
        self._claim_nonces: set[bytes] = set()
        self._claim_proofs: set[bytes] = set()

    @property
    def receipt(self) -> BrokeredCgroupScopeReceipt:
        """Expose only the immutable broker proof needed by an LTFS session."""

        return self._receipt

    def _validated_state(self) -> tuple[bool, tuple[int, ...]]:
        challenge = secrets.token_bytes(32)
        try:
            validation = self._api.validate_scope(
                self._receipt, challenge, self._capability
            )
        except Exception as exc:  # noqa: BLE001 - redact the trusted IPC boundary
            raise ScopeExchangeError("revalidated", getattr(exc, "reason", None)) from None
        if (
            type(validation) is not BrokeredCgroupScopeValidation
            or type(validation.protocol_version) is not int
            or validation.protocol_version != 1
            or type(validation.receipt) is not BrokeredCgroupScopeReceipt
            or validation.receipt != self._receipt
            or type(validation.challenge) is not bytes
            or validation.challenge != challenge
        ):
            raise CommandError("brokered cgroup validation changed the exact receipt")
        if (
            not _is_opaque_broker_value(validation.validation_nonce)
            or not _is_opaque_broker_value(validation.broker_proof)
            or validation.validation_nonce == challenge
            or validation.broker_proof == challenge
            or validation.validation_nonce == validation.broker_proof
            or validation.broker_proof == self._receipt.broker_proof
            or validation.validation_nonce in self._validation_nonces
            or validation.broker_proof in self._validation_proofs
        ):
            raise CommandError("brokered cgroup validation is not fresh")
        members = validation.member_pids
        if (
            type(validation.populated) is not bool
            or type(members) is not tuple
            or any(type(pid) is not int or pid <= 0 for pid in members)
            or len(set(members)) != len(members)
            or validation.populated is not bool(members)
        ):
            raise CommandError("brokered cgroup scope returned inconsistent population")
        self._validation_nonces.add(validation.validation_nonce)
        self._validation_proofs.add(validation.broker_proof)
        return validation.populated, tuple(sorted(members))

    def assert_prepared(self) -> None:
        populated, members = self._validated_state()
        if populated or members:
            raise CommandError("new brokered cgroup scope is not empty")

    def assert_release_ready(self, pid: int) -> None:
        if type(pid) is not int or pid <= 0 or self._attached_pid != pid:
            raise CommandError("brokered cgroup scope has no exact attached process")
        populated, members = self._validated_state()
        if not populated or pid not in members:
            raise CommandError("brokered cgroup scope lost its attached process")

    def prepare_release(self, pid: int) -> str:
        if self._release_permits:
            raise CommandError("brokered command release is already prepared")
        try:
            self.assert_release_ready(pid)
        except ScopeExchangeError as exc:
            raise ReleasePreparationError(exc.reason) from None
        request_nonce = secrets.token_bytes(32)
        try:
            permit = self._api.prepare_release(
                self._receipt, pid, request_nonce, self._capability
            )
        except Exception as exc:  # noqa: BLE001 - redact the trusted IPC boundary
            raise ReleasePreparationError(getattr(exc, "reason", None)) from None
        if (
            type(permit) is not BrokeredCgroupReleasePermit
            or type(permit.protocol_version) is not int
            or permit.protocol_version != 1
            or type(permit.receipt) is not BrokeredCgroupScopeReceipt
            or permit.receipt != self._receipt
            or type(permit.pid) is not int
            or permit.pid != pid
            or type(permit.request_nonce) is not bytes
            or permit.request_nonce != request_nonce
        ):
            raise CommandError("brokered release permit changed command scope")
        if (
            not _is_opaque_broker_value(permit.permit_nonce)
            or not _is_opaque_broker_value(permit.broker_proof)
            or permit.permit_nonce == request_nonce
            or permit.broker_proof == request_nonce
            or permit.permit_nonce == permit.broker_proof
            or permit.permit_nonce in self._release_nonces
            or permit.broker_proof in self._release_proofs
        ):
            raise CommandError("brokered release permit lacks fresh broker proof")
        permit_sha256 = _broker_release_permit_sha256(permit)
        if permit_sha256 in self._release_permits:
            raise CommandError("brokered release permit was reused")
        self._release_nonces.add(permit.permit_nonce)
        self._release_proofs.add(permit.broker_proof)
        self._release_permits[permit_sha256] = permit
        return permit_sha256

    def release_child(self, pid: int, permit_sha256: str, release_fd: int) -> None:
        permit = self._release_permits.get(permit_sha256)
        if permit is None or permit.pid != pid:
            raise CommandError("brokered release permit does not match blocked child")
        self.assert_release_ready(pid)
        try:
            self._api.release_child(
                self._receipt, permit, pid, release_fd, self._capability
            )
        except Exception:  # noqa: BLE001 - redact the trusted IPC boundary
            raise CommandError("brokered command release failed") from None

    def claim_unreleased(self, pid: int, permit_sha256: str) -> CommandReleaseClaim:
        if (
            type(pid) is not int
            or pid <= 0
            or type(permit_sha256) is not str
            or len(permit_sha256) != 64
            or any(character not in "0123456789abcdef" for character in permit_sha256)
        ):
            raise CommandError("brokered release permit identity is malformed")
        local_permit = self._release_permits.get(permit_sha256)
        if local_permit is not None and local_permit.pid != pid:
            raise CommandError("brokered release permit does not match blocked child")
        challenge = secrets.token_bytes(32)
        try:
            claim = self._api.claim_unreleased(
                self._receipt, pid, permit_sha256, challenge, self._capability
            )
        except Exception:  # noqa: BLE001 - redact the trusted IPC boundary
            raise CommandError(
                "brokered command release could not be atomically claimed"
            ) from None
        if (
            type(claim) is not BrokeredCgroupReleaseClaim
            or type(claim.protocol_version) is not int
            or claim.protocol_version != 1
            or type(claim.receipt) is not BrokeredCgroupScopeReceipt
            or claim.receipt != self._receipt
            or type(claim.pid) is not int
            or claim.pid != pid
            or type(claim.permit_sha256) is not str
            or claim.permit_sha256 != permit_sha256
            or type(claim.challenge) is not bytes
            or claim.challenge != challenge
            or type(claim.released) is not bool
            or type(claim.permit_revoked) is not bool
            or claim.released == claim.permit_revoked
        ):
            raise CommandError("brokered release claim changed exact permit")
        if (
            not _is_opaque_broker_value(claim.claim_nonce)
            or not _is_opaque_broker_value(claim.broker_proof)
            or claim.claim_nonce == challenge
            or claim.broker_proof == challenge
            or claim.claim_nonce == claim.broker_proof
            or claim.claim_nonce in self._claim_nonces
            or claim.broker_proof in self._claim_proofs
        ):
            raise CommandError("brokered release claim is not fresh")
        self._claim_nonces.add(claim.claim_nonce)
        self._claim_proofs.add(claim.broker_proof)
        return CommandReleaseClaim(
            self.identity,
            claim.pid,
            permit_sha256,
            claim.released,
            claim.permit_revoked,
        )

    def attach(self, pid: int) -> None:
        if type(pid) is not int or pid <= 0 or self._attached_pid is not None:
            raise CommandError("brokered cgroup scope received an invalid process")
        try:
            self._api.attach(self._receipt, pid, self._capability)
        except Exception:  # noqa: BLE001 - redact the trusted IPC boundary
            raise CommandError(
                "brokered cgroup scope could not attach process"
            ) from None
        populated, members = self._validated_state()
        if not populated or pid not in members:
            raise CommandError(
                "brokered cgroup attach did not establish exact scope membership"
            )
        self._attached_pid = pid

    def member_pids(self) -> tuple[int, ...]:
        _populated, members = self._validated_state()
        return members

    def is_populated(self) -> bool:
        populated, _members = self._validated_state()
        return populated

    def signal(self, signum: int) -> None:
        try:
            if signum == signal.SIGKILL:
                self._api.kill_scope(self._receipt, self._capability)
            else:
                self._api.signal_scope(self._receipt, signum, self._capability)
        except Exception:  # noqa: BLE001 - redact the trusted IPC boundary
            raise CommandError("brokered cgroup scope could not be signalled") from None

    def close(self) -> None:
        if self.is_populated():
            raise ProcessQuiescenceTimeout("brokered cgroup scope is not empty")
        try:
            self._api.release_scope(self._receipt, self._capability)
        except Exception:  # noqa: BLE001 - redact the trusted IPC boundary
            raise CommandError("brokered cgroup scope could not be released") from None


class BrokeredCgroupExecutionScopeManager:
    """Production manager accepting only per-command broker-issued receipts."""

    def __init__(
        self,
        api: BrokeredCgroupScopeApi,
        capability: BrokeredCgroupScopeToken,
    ) -> None:
        if type(capability) is not BrokeredCgroupScopeToken:
            raise CommandError("an exact brokered cgroup scope token is required")
        self._api = api
        self._capability = capability
        self._scope_identities: dict[str, ExecutionScopeIdentity] = {}
        self._scope_paths: dict[str, ExecutionScopeIdentity] = {}
        self._broker_nonces: set[bytes] = set()
        self._broker_proofs: set[bytes] = set()
        self._release_nonces: set[bytes] = set()
        self._release_proofs: set[bytes] = set()

    def _accept_receipt(
        self,
        identity: ExecutionScopeIdentity,
        request_nonce: bytes,
        receipt: BrokeredCgroupScopeReceipt,
    ) -> BrokeredCgroupExecutionScope:
        _validate_broker_receipt(receipt, identity, request_nonce)
        for value, registry in (
            (receipt.scope_id, self._scope_identities),
            (receipt.scope_path_sha256, self._scope_paths),
        ):
            previous = registry.get(value)
            if previous is not None and previous != identity:
                raise CommandError(
                    "brokered cgroup receipt reused a scope across command identities"
                )
            registry[value] = identity
        if (
            receipt.broker_nonce in self._broker_nonces
            or receipt.broker_proof in self._broker_proofs
        ):
            raise CommandError("brokered cgroup receipt reused broker proof")
        self._broker_nonces.add(receipt.broker_nonce)
        self._broker_proofs.add(receipt.broker_proof)
        return BrokeredCgroupExecutionScope(
            identity,
            receipt,
            self._api,
            self._capability,
            self._release_nonces,
            self._release_proofs,
        )

    def create(self, identity: ExecutionScopeIdentity) -> BrokeredCgroupExecutionScope:
        request_nonce = secrets.token_bytes(32)
        try:
            receipt = self._api.create_scope(identity, request_nonce, self._capability)
        except Exception as exc:  # noqa: BLE001 - redact the trusted IPC boundary
            raise ScopeExchangeError("created", getattr(exc, "reason", None)) from None
        return self._accept_receipt(identity, request_nonce, receipt)

    def open(self, identity: ExecutionScopeIdentity) -> BrokeredCgroupExecutionScope:
        request_nonce = secrets.token_bytes(32)
        try:
            receipt = self._api.open_scope(identity, request_nonce, self._capability)
        except Exception as exc:  # noqa: BLE001 - redact the trusted IPC boundary
            raise ScopeExchangeError("opened", getattr(exc, "reason", None)) from None
        return self._accept_receipt(identity, request_nonce, receipt)


class SnapshotProcessProbe:
    """Fail-closed process identity/group quiescence over injectable /proc snapshots."""

    def __init__(
        self,
        *,
        snapshot: Callable[[], tuple[ProcessObservation, ...]],
        boot_id: Callable[[], str],
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 0.05,
        now: Callable[[], str] = _utc_now,
    ) -> None:
        self._snapshot = snapshot
        self._boot_id = boot_id
        self._monotonic = monotonic
        self._sleep = sleep
        self._poll_seconds = _validated_timeout(poll_seconds, "poll_seconds")
        self._now = now
        self._tracked_by_root: dict[
            tuple[str, int, int, int], set[tuple[str, int, int]]
        ] = {}

    def exact_identity_present(self, expected: ProcessIdentity) -> bool:
        if self._boot_id() != expected.boot_id:
            return False
        return any(item.identity == expected for item in self._snapshot())

    def await_identity_and_group_absent(
        self, expected: ProcessIdentity, timeout: float
    ) -> str:
        deadline = self._monotonic() + _validated_timeout(timeout, "timeout")
        root_key = (
            expected.boot_id,
            expected.pid,
            expected.start_ticks,
            expected.process_group_id,
        )
        tracked = self._tracked_by_root.setdefault(root_key, set())
        while True:
            if self._boot_id() != expected.boot_id:
                self._tracked_by_root.pop(root_key, None)
                return self._now()
            observations = self._snapshot()
            owned = self._owned_processes(expected, observations, tracked)
            tracked.update(
                (item.identity.boot_id, item.identity.pid, item.identity.start_ticks)
                for item in owned
            )
            if not owned:
                self._tracked_by_root.pop(root_key, None)
                return self._now()
            if self._monotonic() >= deadline:
                raise ProcessQuiescenceTimeout(
                    "supervised process group did not become quiescent"
                )
            self._sleep(min(self._poll_seconds, max(0.0, deadline - self._monotonic())))

    def identity_and_group_absent(self, expected: ProcessIdentity) -> bool:
        return self.identities_and_groups_absent((expected,))[0]

    def identities_and_groups_absent(
        self, expected: Iterable[ProcessIdentity]
    ) -> tuple[bool, ...]:
        """Assess identities in input order against one fresh shared observation.

        This batches only observation, not ownership: every root retains its
        exact identity, process-group and previously tracked descendant checks.
        No snapshot is retained for a later assessment or release decision.
        """
        identities = tuple(expected)
        if not identities:
            return ()
        boot_id = self._boot_id()
        observations = (
            tuple(self._snapshot_at_boot(boot_id))
            if any(identity.boot_id == boot_id for identity in identities)
            else ()
        )
        return tuple(
            identity.boot_id != boot_id
            or self._identity_and_group_absent_in_snapshot(identity, observations)
            for identity in identities
        )

    def _snapshot_at_boot(self, boot_id: str) -> tuple[ProcessObservation, ...]:
        return self._snapshot()

    def _identity_and_group_absent_in_snapshot(
        self, expected: ProcessIdentity, observations: tuple[ProcessObservation, ...]
    ) -> bool:
        root_key = (
            expected.boot_id,
            expected.pid,
            expected.start_ticks,
            expected.process_group_id,
        )
        tracked = self._tracked_by_root.setdefault(root_key, set())
        owned = self._owned_processes(expected, observations, tracked)
        tracked.update(
            (item.identity.boot_id, item.identity.pid, item.identity.start_ticks)
            for item in owned
        )
        if owned:
            return False
        self._tracked_by_root.pop(root_key, None)
        return True

    def assert_scope_intact(self, expected: ProcessIdentity) -> None:
        if self._boot_id() != expected.boot_id:
            raise ProcessIdentityMismatch("supervised process boot identity changed")
        root_key = (
            expected.boot_id,
            expected.pid,
            expected.start_ticks,
            expected.process_group_id,
        )
        tracked = self._tracked_by_root.setdefault(root_key, set())
        owned = self._owned_processes(expected, self._snapshot(), tracked)
        tracked.update(
            (item.identity.boot_id, item.identity.pid, item.identity.start_ticks)
            for item in owned
        )
        if not any(item.identity == expected for item in owned):
            raise ProcessIdentityMismatch("supervised foreground process exited")
        if any(
            item.identity.process_group_id != expected.process_group_id
            for item in owned
        ):
            raise ProcessIdentityMismatch(
                "supervised command attempted to escape its process group"
            )

    @staticmethod
    def _owned_processes(
        expected: ProcessIdentity,
        observations: tuple[ProcessObservation, ...],
        tracked: set[tuple[str, int, int]],
    ) -> tuple[ProcessObservation, ...]:
        owned = {
            item.identity.pid: item
            for item in observations
            if item.identity == expected
            or (
                item.identity.boot_id == expected.boot_id
                and item.identity.process_group_id == expected.process_group_id
            )
            or (
                item.identity.boot_id,
                item.identity.pid,
                item.identity.start_ticks,
            )
            in tracked
        }
        changed = True
        while changed:
            changed = False
            for item in observations:
                if item.identity.pid not in owned and item.parent_pid in owned:
                    owned[item.identity.pid] = item
                    changed = True
        return tuple(owned.values())


def _read_proc_text(path: Path, encoding: str) -> str:
    # Automatic buffering performs terminal detection on deployed Python builds,
    # even in binary mode. Disable it explicitly, then decode strictly as before.
    # Procfs needs only reads; avoid denied TCGETS ioctls and their audit traffic.
    with path.open("rb", buffering=0) as source:
        return source.read().decode(encoding)


def _read_boot_id(path: Path = Path("/proc/sys/kernel/random/boot_id")) -> str:
    return _read_proc_text(path, "ascii").strip()


def _parse_proc_stat(pid: int, text: str, boot_id: str) -> ProcessObservation:
    close = text.rfind(")")
    if close < 0:
        raise ValueError("malformed process stat")
    fields = text[close + 2 :].split()
    if len(fields) < 20:
        raise ValueError("incomplete process stat")
    return ProcessObservation(
        ProcessIdentity(
            boot_id=boot_id,
            pid=pid,
            start_ticks=int(fields[19]),
            process_group_id=int(fields[2]),
        ),
        parent_pid=int(fields[1]),
    )


def _proc_snapshot(
    proc_root: Path = Path("/proc"), *, boot_id: str | None = None
) -> tuple[ProcessObservation, ...]:
    if boot_id is None:
        boot_id = _read_boot_id(proc_root / "sys/kernel/random/boot_id")
    observed: list[ProcessObservation] = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            observed.append(
                _parse_proc_stat(
                    int(entry.name),
                    _read_proc_text(entry / "stat", "ascii"),
                    boot_id,
                )
            )
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
    return tuple(observed)


class ProcessGroupExecutionScope:
    """Hardware-free test scope; production uses cgroup v2 containment."""

    def __init__(self, identity: ExecutionScopeIdentity) -> None:
        self.identity = identity
        self._process_group_id: int | None = None

    def attach(self, pid: int) -> None:
        self._process_group_id = pid

    def member_pids(self) -> tuple[int, ...]:
        if self._process_group_id is None:
            return ()
        return tuple(
            sorted(
                item.identity.pid
                for item in _proc_snapshot()
                if item.identity.process_group_id == self._process_group_id
            )
        )

    def is_populated(self) -> bool:
        return bool(self.member_pids())

    def claim_unreleased(self, pid: int, permit_sha256: str) -> CommandReleaseClaim:
        del pid, permit_sha256
        raise CommandError("authoritative release claim is unavailable")

    def signal(self, signum: int) -> None:
        if self._process_group_id is None:
            return
        try:
            os.killpg(self._process_group_id, signum)
        except ProcessLookupError:
            return

    def close(self) -> None:
        if self.member_pids():
            raise ProcessQuiescenceTimeout("test execution scope is not empty")


class ProcessGroupExecutionScopeManager:
    def __init__(self) -> None:
        self._scopes: dict[ExecutionScopeIdentity, ProcessGroupExecutionScope] = {}

    def create(self, identity: ExecutionScopeIdentity) -> ProcessGroupExecutionScope:
        scope = ProcessGroupExecutionScope(identity)
        self._scopes[identity] = scope
        return scope

    def open(self, identity: ExecutionScopeIdentity) -> ProcessGroupExecutionScope:
        return self._scopes.setdefault(identity, ProcessGroupExecutionScope(identity))


class LinuxProcessProbe(SnapshotProcessProbe):
    def __init__(self) -> None:
        super().__init__(snapshot=_proc_snapshot, boot_id=_read_boot_id)

    def _snapshot_at_boot(self, boot_id: str) -> tuple[ProcessObservation, ...]:
        return _proc_snapshot(boot_id=boot_id)


class PosixProcessTerminator:
    def __init__(self, process_probe: TerminableProcessProbe) -> None:
        self._probe = process_probe

    def terminate_group(
        self, identity: ProcessIdentity, term_timeout: float, kill_timeout: float
    ) -> None:
        term_timeout = _validated_timeout(term_timeout, "term_timeout")
        kill_timeout = _validated_timeout(kill_timeout, "kill_timeout")
        if not self._probe.exact_identity_present(identity):
            raise ProcessIdentityMismatch(
                "refusing to signal a process group without its exact leader identity"
            )
        try:
            os.killpg(identity.process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            return
        try:
            self._probe.await_identity_and_group_absent(identity, term_timeout)
            return
        except ProcessQuiescenceTimeout:
            pass
        if not self._probe.exact_identity_present(identity):
            raise ProcessIdentityMismatch(
                "process identity changed before kill escalation"
            )
        try:
            os.killpg(identity.process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return
        self._probe.await_identity_and_group_absent(identity, kill_timeout)


class ForkExecLaunchGate:
    def __init__(
        self,
        pid: int,
        identity: ProcessIdentity,
        scope: ExecutionScope,
        release_fd: int,
        stdout_file,
        stderr_file,
        prepare_release: Callable[[], str],
        release: Callable[[str, int], None],
        claim_unreleased: Callable[[str], CommandReleaseClaim],
    ) -> None:
        self.pid = pid
        self.identity = identity
        self.scope = scope
        self._release_fd = release_fd
        self._stdout_file = stdout_file
        self._stderr_file = stderr_file
        self._prepare_release = prepare_release
        self._release = release
        self._claim_unreleased = claim_unreleased
        self._permit_sha256: str | None = None
        self._released = False
        self._waited = False
        self._status: int | None = None
        self._result: CompletedCommand | None = None

    def prepare_release(self) -> str:
        if self._release_fd < 0:
            raise CommandError("launch gate is already closed")
        if self._permit_sha256 is not None:
            raise CommandError("launch gate already has a release permit")
        permit_sha256 = self._prepare_release()
        if (
            type(permit_sha256) is not str
            or len(permit_sha256) != 64
            or any(character not in "0123456789abcdef" for character in permit_sha256)
        ):
            raise CommandError("launch gate received an invalid release permit")
        self._permit_sha256 = permit_sha256
        return permit_sha256

    def release(self, permit_sha256: str) -> None:
        if self._release_fd < 0:
            raise CommandError("launch gate is already closed")
        if permit_sha256 != self._permit_sha256:
            raise CommandError("launch gate release permit changed")
        self._release(permit_sha256, self._release_fd)
        os.close(self._release_fd)
        self._release_fd = -1
        self._released = True

    def claim_unreleased(self, permit_sha256: str) -> CommandReleaseClaim:
        if permit_sha256 != self._permit_sha256:
            raise CommandError("launch gate release permit changed")
        return self._claim_unreleased(permit_sha256)

    def abort_before_release(self) -> None:
        if self._release_fd >= 0:
            os.close(self._release_fd)
            self._release_fd = -1

    def abort_and_wait(self, timeout: float) -> CompletedCommand:
        self.abort_before_release()
        return self.wait(timeout)

    def wait(self, timeout: float) -> CompletedCommand:
        if self._result is not None:
            return self._result
        if self._waited and self._status is None:
            raise CommandError("command result already consumed")
        deadline = time.monotonic() + _validated_timeout(timeout, "timeout")
        while True:
            if self._status is None:
                waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
                if waited_pid == self.pid:
                    self._status = status
            if self._status is not None:
                self._waited = True
                self._result = self._completed_from_status(self._status)
                return self._result
            if time.monotonic() >= deadline:
                raise CommandTimeout("supervised")
            time.sleep(0.02)

    def terminate_group(self, term_timeout: float, kill_timeout: float) -> None:
        term_timeout = _validated_timeout(term_timeout, "term_timeout")
        kill_timeout = _validated_timeout(kill_timeout, "kill_timeout")
        self._assert_exact_identity()
        try:
            os.killpg(self.identity.process_group_id, signal.SIGTERM)
        except ProcessLookupError:
            if self._await_child_exit(term_timeout):
                return
            raise ProcessQuiescenceTimeout("supervised child could not be reaped")
        if self._await_child_exit(term_timeout):
            return
        self._assert_exact_identity()
        try:
            os.killpg(self.identity.process_group_id, signal.SIGKILL)
        except ProcessLookupError:
            return
        if not self._await_child_exit(kill_timeout):
            raise ProcessQuiescenceTimeout(
                "supervised process did not exit after kill escalation"
            )

    def _assert_exact_identity(self) -> None:
        try:
            observed = _parse_proc_stat(
                self.pid,
                _read_proc_text(Path(f"/proc/{self.pid}/stat"), "ascii"),
                _read_boot_id(),
            ).identity
        except (FileNotFoundError, ProcessLookupError, ValueError) as exc:
            raise ProcessIdentityMismatch(
                "supervised process identity is no longer exact"
            ) from exc
        if observed != self.identity:
            raise ProcessIdentityMismatch(
                "supervised process identity is no longer exact"
            )

    def _await_child_exit(self, timeout: float) -> bool:
        deadline = time.monotonic() + max(0.0, timeout)
        while True:
            waited_pid, status = os.waitpid(self.pid, os.WNOHANG)
            if waited_pid == self.pid:
                self._status = status
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)

    def _completed_from_status(self, status: int) -> CompletedCommand:
        try:
            self._stdout_file.seek(0)
            self._stderr_file.seek(0)
            stdout = self._bounded_output(self._stdout_file)
            stderr = self._bounded_output(self._stderr_file)
        finally:
            self._stdout_file.close()
            self._stderr_file.close()
        return CompletedCommand(os.waitstatus_to_exitcode(status), stdout, stderr)

    @staticmethod
    def _bounded_output(stream, maximum: int = _OUTPUT_MEMORY_LIMIT) -> str:
        payload = stream.read(maximum + 1)
        if len(payload) > maximum:
            raise CommandError("supervised command output exceeds memory bound")
        return payload.decode("utf-8", errors="replace")


class _ForkExecCommandLauncherBase:
    """Shared blocked fork/exec mechanics; subclasses choose the trust boundary."""

    def __init__(
        self,
        scope_manager: ExecutionScopeManager,
        privilege_boundary: CommandPrivilegeBoundary,
    ) -> None:
        self.scope_manager = scope_manager
        self.privilege_boundary = privilege_boundary

    def open_scope(self, identity: ExecutionScopeIdentity) -> ExecutionScope:
        return self.scope_manager.open(identity)

    def launch_blocked(
        self,
        argv: tuple[str, ...],
        scope_identity: ExecutionScopeIdentity | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> ForkExecLaunchGate:
        if not argv or not all(
            isinstance(value, str) and "\x00" not in value for value in argv
        ):
            raise ValueError("argv must contain non-NUL strings")
        if not all(isinstance(fd, int) and fd >= 0 for fd in pass_fds):
            raise ValueError("pass_fds must contain non-negative descriptors")
        self._validate_pass_fds(pass_fds)
        self.privilege_boundary.validate_supervisor()
        scope_identity = scope_identity or ExecutionScopeIdentity(uuid.uuid4().hex, 0)
        scope = self.scope_manager.create(scope_identity)
        try:
            self.privilege_boundary.prepare_scope(scope)
        except BaseException:
            scope.close()
            raise
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        ready_read_fd, ready_write_fd = os.pipe2(os.O_CLOEXEC)
        # The gate owns these files across this method's return boundary.
        stdout_file = tempfile.TemporaryFile()  # noqa: SIM115
        stderr_file = tempfile.TemporaryFile()  # noqa: SIM115
        pid = os.fork()
        if pid == 0:  # pragma: no cover - exercised only by Linux integration gates
            try:
                os.close(write_fd)
                os.close(ready_read_fd)
                os.setsid()
                os.dup2(stdout_file.fileno(), 1)
                os.dup2(stderr_file.fileno(), 2)
                # Output is captured in regular files; enforce the quota at
                # the kernel write boundary rather than only while collecting.
                resource.setrlimit(
                    resource.RLIMIT_FSIZE, (_OUTPUT_FILE_LIMIT, _OUTPUT_FILE_LIMIT)
                )
                for fd in pass_fds:
                    os.set_inheritable(fd, True)
                self.privilege_boundary.enter_child()
                self._close_child_descriptors(
                    (0, 1, 2, read_fd, ready_write_fd, *pass_fds)
                )
                os.write(ready_write_fd, b"1")
                os.close(ready_write_fd)
                release_byte = os.read(read_fd, 1)
                os.close(read_fd)
                if release_byte != b"1":
                    os._exit(125)
                os.execv(argv[0], list(argv))
            except BaseException:  # noqa: BLE001 - child must exit without traceback
                os._exit(126)
        os.close(read_fd)
        os.close(ready_write_fd)
        try:
            scope.attach(pid)
            identity = self._wait_for_blocked_identity(pid, ready_read_fd)
        except BaseException:
            os.close(write_fd)
            deadline = time.monotonic() + 2.0
            while True:
                try:
                    waited_pid, _status = os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    break
                if waited_pid == pid:
                    break
                if time.monotonic() >= deadline:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        os.waitpid(pid, 0)
                    except ChildProcessError:
                        pass
                    break
                time.sleep(0.01)
            try:
                scope.close()
            except (CommandError, ProcessQuiescenceTimeout):
                pass
            stdout_file.close()
            stderr_file.close()
            raise
        finally:
            os.close(ready_read_fd)
        return ForkExecLaunchGate(
            pid,
            identity,
            scope,
            write_fd,
            stdout_file,
            stderr_file,
            lambda: self.privilege_boundary.prepare_release(scope, pid),
            lambda permit_sha256, release_fd: self.privilege_boundary.release(
                scope, pid, permit_sha256, release_fd
            ),
            lambda permit_sha256: self.privilege_boundary.claim_unreleased(
                scope, pid, permit_sha256
            ),
        )

    def _validate_pass_fds(self, pass_fds: tuple[int, ...]) -> None:
        raise NotImplementedError

    @staticmethod
    def _close_child_descriptors(keep: tuple[int, ...]) -> None:
        keep_set = set(keep)
        for descriptor in tuple(Path("/proc/self/fd").iterdir()):
            if not descriptor.name.isdigit():
                continue
            fd = int(descriptor.name)
            if fd in keep_set:
                continue
            try:
                os.close(fd)
            except OSError:
                continue

    @staticmethod
    def _wait_for_blocked_identity(pid: int, ready_fd: int) -> ProcessIdentity:
        deadline = time.monotonic() + 2.0
        remaining = max(0.0, deadline - time.monotonic())
        readable, _, _ = select.select((ready_fd,), (), (), remaining)
        if not readable or os.read(ready_fd, 1) != b"1":
            raise CommandError("command privilege boundary could not be established")
        while True:
            try:
                observation = _parse_proc_stat(
                    pid,
                    _read_proc_text(Path(f"/proc/{pid}/stat"), "ascii"),
                    _read_boot_id(),
                )
                if observation.identity.process_group_id == pid:
                    return observation.identity
            except (FileNotFoundError, ProcessLookupError, ValueError):
                pass
            if time.monotonic() >= deadline:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
                raise CommandError("unable to establish blocked process identity")
            time.sleep(0.01)


class ForkExecCommandLauncher(_ForkExecCommandLauncherBase):
    """Production fork/exec launcher requiring broker-attested cgroup authority."""

    def __init__(
        self,
        scope_manager: ExecutionScopeManager | None = None,
        privilege_boundary: CommandPrivilegeBoundary | None = None,
    ) -> None:
        if scope_manager is None and privilege_boundary is None:
            super().__init__(
                _UnavailableExecutionScopeManager(),
                UnavailableCommandPrivilegeBoundary(),
            )
            return
        if (
            type(scope_manager) is not BrokeredCgroupExecutionScopeManager
            or type(privilege_boundary) is not ReadOnlyCgroupPrivilegeBoundary
        ):
            raise CommandError(
                "production command launch requires an attested brokered cgroup scope"
            )
        super().__init__(scope_manager, privilege_boundary)

    @staticmethod
    def _validate_pass_fds(pass_fds: tuple[int, ...]) -> None:
        try:
            for fd in pass_fds:
                status = os.fstat(fd)
                if stat.S_ISCHR(status.st_mode):
                    continue
                if (
                    stat.S_ISREG(status.st_mode)
                    and status.st_uid == 0
                    and stat.S_IMODE(status.st_mode) == 0o755
                ):
                    # The only regular descriptor admitted is the root-owned,
                    # immutable-mode executable pinned by the typed ltfs-info
                    # provider.  The provider executes that inherited fd, not
                    # a path that may be swapped after validation.
                    continue
                raise CommandError(
                    "production command descriptors must be trusted devices or binaries"
                )
        except OSError:
            raise CommandError(
                "production command descriptor could not be verified"
            ) from None


class TestOnlyForkExecCommandLauncher(_ForkExecCommandLauncherBase):
    """Hardware-free launcher that cannot be selected through the production API."""

    def __init__(
        self,
        scope_manager: ExecutionScopeManager,
        privilege_boundary: CommandPrivilegeBoundary,
    ) -> None:
        super().__init__(scope_manager, privilege_boundary)

    @staticmethod
    def _validate_pass_fds(pass_fds: tuple[int, ...]) -> None:
        return None


class TrackedCommandSupervisor:
    def __init__(
        self,
        *,
        catalog: Catalog,
        daemon_fence: DaemonFence,
        launcher: CommandLauncher,
        process_probe: ProcessProbe,
        process_terminator: ProcessTerminator,
        quiescence_timeout: float = 10.0,
        term_timeout: float = 5.0,
        kill_timeout: float = 5.0,
        event_sink: OperationalEventSink | None = None,
        operation_context: OperationalCorrelation | None = None,
    ) -> None:
        self.catalog = catalog
        self.daemon_fence = daemon_fence
        self.launcher = launcher
        self.process_probe = process_probe
        self.process_terminator = process_terminator
        self.quiescence_timeout = _validated_timeout(
            quiescence_timeout, "quiescence_timeout"
        )
        self.term_timeout = _validated_timeout(term_timeout, "term_timeout")
        self.kill_timeout = _validated_timeout(kill_timeout, "kill_timeout")
        self.event_sink = event_sink or NullOperationalEventSink()
        self.operation_context = operation_context or OperationalCorrelation()
        self._live_gates: dict[str, LaunchGate] = {}
        self._command_started_at: dict[str, float] = {}

    def reserve_and_launch_blocked(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        pass_fds: tuple[int, ...] = (),
    ) -> str:
        for attempt in range(3):
            try:
                return self._reserve_and_launch_once(fence, kind, argv, pass_fds)
            except ScopeExchangeError as exc:
                if (kind not in {"identify", "probe_media"} or not exc.quiesced
                        or exc.reason not in {"timeout", "eof", "transport", "pre_dispatch"}
                        or attempt == 2):
                    raise
                time.sleep(0.25 * (attempt + 1))
        raise AssertionError("bounded launch attempts exhausted")

    def _reserve_and_launch_once(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        pass_fds: tuple[int, ...] = (),
    ) -> str:
        command_id = uuid.uuid4().hex
        self.catalog.reserve_hardware_command(
            fence, command_id, kind, redacted_argv_sha256(argv)
        )
        scope_identity = ExecutionScopeIdentity(command_id, fence.owner_generation)
        exchange_started = time.monotonic()
        try:
            gate = self.launcher.launch_blocked(argv, scope_identity, pass_fds)
        except BaseException as exc:
            # A failed launch reply does not prove that no child was created.
            # Reconcile only this reservation using the exact broker scope.
            if isinstance(exc, ScopeExchangeError):
                exc.quiesced = False
                self._emit_command_event(
                    fence, kind, "ltfs.launch." + exc.reason,
                    OperationalSeverity.ERROR, "Command launch exchange failed; verifying its execution scope.",
                    command_id=command_id,
                    elapsed_ms=max(0, int((time.monotonic() - exchange_started) * 1000)),
                )
            for retry in range(3):
                reconciliation_started = time.monotonic()
                try:
                    self.reconcile_one(command_id, self.daemon_fence)
                    break
                except ScopeExchangeError as recovery_error:
                    self._emit_command_event(
                        fence, kind, "ltfs.reconcile." + recovery_error.reason,
                        OperationalSeverity.ERROR, "Command scope reconciliation exchange failed.",
                        command_id=command_id,
                        elapsed_ms=max(0, int((time.monotonic() - reconciliation_started) * 1000)),
                    )
                    if (not isinstance(exc, ScopeExchangeError)
                            or kind not in {"identify", "probe_media"}
                            or recovery_error.reason not in {"timeout", "eof", "transport", "pre_dispatch"}
                            or retry == 2):
                        raise
                    time.sleep(0.25 * (retry + 1))
            if isinstance(exc, ScopeExchangeError):
                exc.quiesced = True
            raise
        if gate.scope.identity != scope_identity:
            # The returned gate is not authorized by this reservation. Do not
            # touch it; reopen only the durable command's exact scope instead.
            self.reconcile_one(command_id, self.daemon_fence)
            raise CommandError("launch scope does not match the durable command")
        self._live_gates[command_id] = gate
        try:
            self.catalog.record_blocked_process(command_id, fence, gate.identity)
        except BaseException:
            # Persistence can fail either before or after committing the PID.
            # Re-read durable state and reap the live gate before acknowledgement.
            self.reconcile_one(command_id, self.daemon_fence)
            raise
        return command_id

    def abort_blocked(self, command_id: str) -> CommandExitEvidence:
        command = self.catalog.command(command_id)
        if (
            command is None
            or command.state != "launch_blocked"
            or command.process is None
        ):
            raise CommandError("command is not blocked before launch")
        gate = self._live_gates.get(command_id)
        if gate is None:
            raise CommandError("live launch gate is unavailable")
        gate.abort_and_wait(self.quiescence_timeout)
        return self._acknowledge_absence(
            command, gate.scope, "launch_aborted", self.daemon_fence
        )

    def start(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        pass_fds: tuple[int, ...] = (),
    ) -> RunningCommand:
        for attempt in range(3):
            try:
                return self._start_once(fence, kind, argv, pass_fds)
            except ReleasePreparationError as exc:
                if (kind not in {"identify", "probe_media"} or not exc.quiesced
                        or exc.reason not in {"timeout", "eof", "transport", "pre_dispatch"}
                        or attempt == 2):
                    raise
                time.sleep(0.25 * (attempt + 1))
        raise AssertionError("bounded preparation attempts exhausted")

    def _start_once(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        pass_fds: tuple[int, ...] = (),
    ) -> RunningCommand:
        command_id = self.reserve_and_launch_blocked(fence, kind, argv, pass_fds)
        gate = self._live_gates[command_id]
        preparation_started = time.monotonic()
        try:
            permit_sha256 = gate.prepare_release()
        except BaseException as exc:
            if isinstance(exc, ReleasePreparationError):
                exc.quiesced = False
            self._emit_command_event(
                fence, kind,
                "ltfs.prepare." + (exc.reason if isinstance(exc, ReleasePreparationError) else "failed"),
                OperationalSeverity.ERROR,
                "Command release preparation failed; verifying its execution scope.",
                command_id=command_id,
                elapsed_ms=max(0, int((time.monotonic() - preparation_started) * 1000)),
            )
            self.abort_blocked(command_id)
            if isinstance(exc, ReleasePreparationError):
                exc.quiesced = True
            raise
        try:
            self.catalog.authorize_hardware_command_release(
                command_id, fence, permit_sha256
            )
        except BaseException as exc:
            busy = (
                isinstance(exc, sqlite3.OperationalError)
                and str(exc).lower() in {"database is locked", "database is busy"}
            )
            self._emit_command_event(
                fence, kind,
                "ltfs.authorize.busy" if busy else "ltfs.authorize.failed",
                OperationalSeverity.WARNING if busy else OperationalSeverity.ERROR,
                "Command release authorization failed before device access.",
                command_id=command_id,
            )
            self.abort_blocked(command_id)
            raise
        try:
            gate.release(permit_sha256)
        except BaseException:
            try:
                durable = self.catalog.command(command_id)
                assert durable is not None
                claim = self._exact_release_claim(
                    durable,
                    gate.scope,
                    permit_sha256,
                    gate.claim_unreleased(permit_sha256),
                )
            except Exception:  # noqa: BLE001 - unavailable proof means ambiguity
                claim = None
            if claim is None or claim.released:
                self.catalog.mark_hardware_command_release_ambiguous(
                    command_id, self.daemon_fence, permit_sha256
                )
            else:
                self._abort_authorized_release(command_id, gate, permit_sha256)
            raise
        try:
            self.catalog.confirm_hardware_command_released(
                command_id, fence, permit_sha256
            )
        except BaseException:
            self.catalog.mark_hardware_command_release_ambiguous(
                command_id, self.daemon_fence, permit_sha256
            )
            raise
        self._command_started_at[command_id] = time.monotonic()
        self._emit_command_event(
            fence,
            kind,
            "ltfs.command.started",
            OperationalSeverity.INFO,
            "LTFS command started.",
            command_id=command_id,
        )
        return RunningCommand(command_id, gate.identity, gate.scope.identity)

    def _correlation_for(
        self,
        fence: OperationFence | RecoveryCommandFence,
        *,
        command_id: str | None = None,
    ) -> OperationalCorrelation:
        supplied = self.operation_context
        return closed_operational_correlation(
            operation_id=fence.operation_id,
            job_id=supplied.job_id,
            cassette_label=supplied.cassette_label,
            cassette_sequence=supplied.cassette_sequence,
            command_id=command_id,
            daemon_generation=fence.owner_generation,
        )

    def _elapsed_ms(self, command_id: str) -> int | None:
        started = self._command_started_at.get(command_id)
        if started is None:
            return None
        return max(0, int((time.monotonic() - started) * 1000))

    def _emit_command_event(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        code: str,
        severity: OperationalSeverity,
        message: str,
        *,
        command_id: str | None = None,
        exit_code: int | None = None,
        repeat_count: int = 1,
        truncated: bool = False,
        elapsed_ms: int | None = None,
    ) -> None:
        correlation = self._correlation_for(fence, command_id=command_id)
        try:
            self.event_sink.emit(
                OperationalEvent(
                    source=OperationalSource.LTFS,
                    severity=severity,
                    code=code,
                    message=message,
                    operation_id=correlation.operation_id,
                    job_id=correlation.job_id,
                    cassette_label=correlation.cassette_label,
                    cassette_sequence=correlation.cassette_sequence,
                    command_id=correlation.command_id,
                    daemon_generation=correlation.daemon_generation,
                    command_kind=kind,
                    exit_code=exit_code,
                    elapsed_ms=elapsed_ms,
                    repeat_count=repeat_count,
                    truncated=truncated,
                )
            )
        except BaseException:  # noqa: BLE001 - diagnostics never change command results
            return

    def _emit_command_output(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        result: CompletedCommand,
        *,
        command_id: str,
    ) -> None:
        try:
            groups, truncated = coalesce_operational_lines(
                (*result.stdout.splitlines(), *result.stderr.splitlines()),
                max_bytes=32 * 1024 - _OPERATIONAL_OUTPUT_SUMMARY_RESERVE,
            )
            group_limit = _MAX_OPERATIONAL_OUTPUT_EVENTS - 1
            selected = groups[:group_limit]
            truncated = truncated or len(groups) > group_limit
            for line, repeat_count in selected:
                if not line:
                    continue
                self._emit_command_event(
                    fence,
                    kind,
                    "ltfs.command.output",
                    OperationalSeverity.INFO if result.returncode == 0 else OperationalSeverity.ERROR,
                    line,
                    command_id=command_id,
                    exit_code=result.returncode,
                    repeat_count=repeat_count,
                )
            if truncated:
                self._emit_command_event(
                    fence,
                    kind,
                    "ltfs.command.output",
                    OperationalSeverity.INFO
                    if result.returncode == 0
                    else OperationalSeverity.ERROR,
                    "Additional LTFS command output was truncated.",
                    command_id=command_id,
                    exit_code=result.returncode,
                    truncated=True,
                )
        except BaseException:  # noqa: BLE001 - diagnostics cannot alter command results
            return

    def _abort_authorized_release(
        self, command_id: str, gate: LaunchGate, permit_sha256: str
    ) -> CommandExitEvidence:
        gate.abort_and_wait(self.quiescence_timeout)
        self.catalog.mark_hardware_command_release_aborted(
            command_id, self.daemon_fence, permit_sha256
        )
        durable = self.catalog.command(command_id)
        assert durable is not None
        return self._acknowledge_absence(
            durable, gate.scope, "launch_aborted", self.daemon_fence
        )

    @staticmethod
    def _exact_release_claim(
        command: HardwareCommandExecution,
        scope: ExecutionScope,
        permit_sha256: str,
        claim: CommandReleaseClaim,
    ) -> CommandReleaseClaim:
        if (
            type(claim) is not CommandReleaseClaim
            or claim.scope != scope.identity
            or claim.scope.command_id != command.id
            or claim.scope.owner_generation != command.issued_generation
            or command.process is None
            or claim.pid != command.process.pid
            or claim.permit_sha256 != permit_sha256
            or type(claim.released) is not bool
            or type(claim.permit_revoked) is not bool
            or claim.released == claim.permit_revoked
        ):
            raise CommandError("release claim does not match the durable command scope")
        return claim

    def assert_running(self, command: RunningCommand) -> None:
        durable = self.catalog.command(command.command_id)
        if (
            durable is None
            or durable.state != "released"
            or durable.process != command.process
            or command.scope
            != ExecutionScopeIdentity(command.command_id, durable.issued_generation)
        ):
            raise CommandError("supervised foreground command is not running")
        self.process_probe.assert_scope_intact(command.process)
        gate = self._live_gates.get(command.command_id)
        scope = (
            gate.scope if gate is not None else self.launcher.open_scope(command.scope)
        )
        if command.process.pid not in scope.member_pids():
            raise CommandError("supervised foreground scope lost its leader")

    def _await_scope_empty(self, scope: ExecutionScope, timeout: float) -> None:
        deadline = time.monotonic() + _validated_timeout(timeout, "scope_timeout")
        while scope.is_populated():
            if time.monotonic() >= deadline:
                raise ProcessQuiescenceTimeout(
                    "supervised execution scope did not become quiescent"
                )
            time.sleep(min(0.02, max(0.0, deadline - time.monotonic())))

    def _terminate_scope(self, scope: ExecutionScope) -> None:
        if not scope.is_populated():
            return
        scope.signal(signal.SIGTERM)
        try:
            self._await_scope_empty(scope, self.term_timeout)
            return
        except ProcessQuiescenceTimeout:
            pass
        scope.signal(signal.SIGKILL)
        self._await_scope_empty(scope, self.kill_timeout)

    def _acknowledge_absence(
        self,
        command: HardwareCommandExecution,
        scope: ExecutionScope,
        outcome: Literal["completed", "terminated", "launch_aborted"],
        daemon_fence: DaemonFence,
        terminal_exit_code: int | None = None,
    ) -> CommandExitEvidence:
        quiesced_at = self.process_probe.await_identity_and_group_absent(
            command.process, self.quiescence_timeout
        )
        self._await_scope_empty(scope, self.quiescence_timeout)
        scope.close()
        evidence = CommandExitEvidence(
            command.id,
            command.process,
            outcome,
            quiesced_at,
            terminal_exit_code,
        )
        self.catalog.acknowledge_command_quiescence(command.id, daemon_fence, evidence)
        self._live_gates.pop(command.id, None)
        return evidence

    def await_completion(
        self, command: RunningCommand, timeout: float
    ) -> CompletedCommand:
        timeout = _validated_timeout(timeout, "timeout")
        gate = self._live_gates.get(command.command_id)
        if gate is None or gate.identity != command.process:
            raise CommandError("live command gate does not match durable identity")
        outcome = "completed"
        escaped = False
        collection_error: CommandError | None = None
        try:
            result = gate.wait(timeout)
        except CommandTimeout:
            gate.terminate_group(self.term_timeout, self.kill_timeout)
            try:
                gate.wait(self.kill_timeout)
            except CommandTimeout:
                pass
            outcome = "terminated"
            result = None
        except CommandError as exc:
            # The child has been reaped before bounded output is collected;
            # persist that quiescence before propagating the redacted failure.
            collection_error = exc
            result = None
        if gate.scope.is_populated():
            escaped = True
            self._terminate_scope(gate.scope)
            outcome = "terminated"
        durable = self.catalog.command(command.command_id)
        assert durable is not None
        self._acknowledge_absence(
            durable,
            gate.scope,
            outcome,
            self.daemon_fence,
            None if result is None or outcome != "completed" else result.returncode,
        )
        elapsed_ms = self._elapsed_ms(command.command_id)
        # The operational correlation is the durable owning operation, not the
        # command identifier.  Reconstruct its exact fence from the command row.
        fence = OperationFence(durable.operation_id, durable.issued_generation)
        if escaped:
            self._emit_command_event(
                fence, durable.kind, "ltfs.command.failed", OperationalSeverity.ERROR,
                "LTFS command escaped its execution scope.",
                command_id=command.command_id,
                elapsed_ms=elapsed_ms,
            )
            self._command_started_at.pop(command.command_id, None)
            raise CommandError("supervised command left processes in its scope")
        if outcome == "terminated":
            self._emit_command_event(
                fence, durable.kind, "ltfs.command.timed_out", OperationalSeverity.ERROR,
                "LTFS command timed out.",
                command_id=command.command_id,
                elapsed_ms=elapsed_ms,
            )
            self._command_started_at.pop(command.command_id, None)
            raise CommandTimeout("supervised")
        if collection_error is not None:
            self._emit_command_event(
                fence, durable.kind, "ltfs.command.failed", OperationalSeverity.ERROR,
                "LTFS command output collection failed.",
                command_id=command.command_id,
                elapsed_ms=elapsed_ms,
            )
            self._command_started_at.pop(command.command_id, None)
            raise collection_error
        assert result is not None
        self._emit_command_output(
            fence, durable.kind, result, command_id=command.command_id
        )
        if result.returncode != 0:
            self._emit_command_event(
                fence, durable.kind, "ltfs.command.failed", OperationalSeverity.ERROR,
                "LTFS command failed.", exit_code=result.returncode, elapsed_ms=elapsed_ms,
                command_id=command.command_id,
            )
            self._command_started_at.pop(command.command_id, None)
            raise CommandFailed(
                self.catalog.command(command.command_id).kind, result.returncode
            )
        self._emit_command_event(
            fence, durable.kind, "ltfs.command.succeeded", OperationalSeverity.INFO,
            "LTFS command succeeded.", exit_code=result.returncode, elapsed_ms=elapsed_ms,
            command_id=command.command_id,
        )
        self._command_started_at.pop(command.command_id, None)
        return result

    def run(
        self,
        fence: OperationFence | RecoveryCommandFence,
        kind: str,
        argv: tuple[str, ...],
        timeout: float,
        pass_fds: tuple[int, ...] = (),
    ) -> CompletedCommand:
        timeout = _validated_timeout(timeout, "timeout")
        command = self.start(fence, kind, argv, pass_fds)
        try:
            return self.await_completion(command, timeout)
        except CommandTimeout as exc:
            raise CommandTimeout(kind) from exc

    def reconcile_empty_identify_reservation(
        self, command_id: str, fence: RecoveryCommandFence,
    ) -> CommandExitEvidence:
        """Close an old, never-launched identify scope; never signal a process."""
        if type(fence) is not RecoveryCommandFence:
            raise CommandError("empty reservation recovery requires a recovery fence")
        self.catalog.assert_command_fence(fence)
        command = self.catalog.command(command_id)
        if (
            command is None
            or command.operation_id != fence.operation_id
            or command.issued_generation >= fence.owner_generation
            or fence.owner_generation != self.daemon_fence.generation
            or command.kind != "identify"
            or command.state != "launch_reserved"
            or command.process is not None
            or command.release_status is not None
            or command.release_permit_sha256 is not None
            or command.released_at is not None
            or command_id in self._live_gates
        ):
            raise CommandError("command is not an old unreleased identify reservation")
        identity = ExecutionScopeIdentity(command.id, command.issued_generation)
        scope = self.launcher.open_scope(identity)
        if scope.identity != identity or scope.is_populated():
            raise CommandError("identify reservation scope is mismatched or populated")
        # The broker checks emptiness again while durably releasing the exact
        # scope. Failure or an ambiguous acknowledgement retains the blocker.
        scope.close()
        self.catalog.assert_command_fence(fence)
        if self.catalog.command(command_id) != command:
            raise CommandError("identify reservation changed during reconciliation")
        evidence = CommandExitEvidence(command_id, None, "launch_aborted", _utc_now())
        self.catalog.acknowledge_command_quiescence(command_id, self.daemon_fence, evidence)
        return evidence

    def reconcile_one(
        self, command_id: str, daemon_fence: DaemonFence
    ) -> CommandExitEvidence:
        command = self.catalog.command(command_id)
        if command is None:
            raise CommandError("hardware command is not registered")
        if command.state == "quiesced":
            outcome = cast(
                Literal["completed", "terminated", "launch_aborted"],
                command.exit_outcome,
            )
            return CommandExitEvidence(
                command.id,
                command.process,
                outcome,
                command.quiesced_at or command.exit_observed_at or _utc_now(),
                command.terminal_exit_code,
            )
        if command.process is None:
            expected_scope = ExecutionScopeIdentity(command.id, command.issued_generation)
            gate = self._live_gates.get(command.id)
            scope = (
                gate.scope if gate is not None else self.launcher.open_scope(expected_scope)
            )
            if scope.identity != expected_scope:
                raise CommandError("reconciliation scope does not match the durable command")
            if gate is not None:
                gate.abort_and_wait(self.quiescence_timeout)
            if scope.is_populated():
                self._terminate_scope(scope)
            self._await_scope_empty(scope, self.quiescence_timeout)
            scope.close()
            evidence = CommandExitEvidence(
                command.id, None, "launch_aborted", _utc_now()
            )
        elif command.state == "launch_blocked":
            gate = self._live_gates.get(command.id)
            if gate is not None:
                if gate.scope.identity != ExecutionScopeIdentity(command.id, command.issued_generation):
                    raise CommandError("reconciliation scope does not match the durable command")
                gate.abort_and_wait(self.quiescence_timeout)
                return self._acknowledge_absence(
                    command, gate.scope, "launch_aborted", daemon_fence
                )
            scope = self.launcher.open_scope(
                ExecutionScopeIdentity(command.id, command.issued_generation)
            )
            if scope.identity != ExecutionScopeIdentity(command.id, command.issued_generation):
                raise CommandError("reconciliation scope does not match the durable command")
            evidence = self._acknowledge_absence(
                command, scope, "launch_aborted", daemon_fence
            )
            return evidence
        elif command.state == "release_authorized":
            if command.release_permit_sha256 is None:
                raise CommandError("durable release authorization lacks a permit")
            permit_sha256 = command.release_permit_sha256
            gate = self._live_gates.get(command.id)
            scope = (
                gate.scope
                if gate is not None
                else self.launcher.open_scope(
                    ExecutionScopeIdentity(command.id, command.issued_generation)
                )
            )
            claim = (
                gate.claim_unreleased(permit_sha256)
                if gate is not None
                else scope.claim_unreleased(command.process.pid, permit_sha256)
            )
            claim = self._exact_release_claim(command, scope, permit_sha256, claim)
            if claim.released:
                self.catalog.mark_hardware_command_release_ambiguous(
                    command.id, daemon_fence, permit_sha256
                )
                return self.terminate_and_await(command.id, daemon_fence)
            if gate is not None and command.release_status != "ambiguous":
                return self._abort_authorized_release(command.id, gate, permit_sha256)
            if gate is not None:
                gate.abort_and_wait(self.quiescence_timeout)
            elif scope.is_populated():
                self._terminate_scope(scope)
            if command.release_status == "ambiguous":
                self.catalog.reconcile_ambiguous_hardware_command_unreleased(
                    command.id,
                    daemon_fence,
                    scope_command_id=claim.scope.command_id,
                    scope_owner_generation=claim.scope.owner_generation,
                    observed_pid=claim.pid,
                    permit_sha256=claim.permit_sha256,
                )
            else:
                self.catalog.mark_hardware_command_release_aborted(
                    command.id, daemon_fence, permit_sha256
                )
            durable = self.catalog.command(command.id)
            assert durable is not None
            return self._acknowledge_absence(
                durable, scope, "launch_aborted", daemon_fence
            )
        else:
            evidence = self.terminate_and_await(command_id, daemon_fence)
            return evidence
        self.catalog.acknowledge_command_quiescence(command_id, daemon_fence, evidence)
        self._live_gates.pop(command_id, None)
        return evidence

    def terminate_and_await(
        self, command_id: str, daemon_fence: DaemonFence | None = None
    ) -> CommandExitEvidence:
        daemon_fence = daemon_fence or self.daemon_fence
        command = self.catalog.command(command_id)
        if command is None or command.process is None:
            raise CommandError("supervised process identity is unavailable")
        gate = self._live_gates.get(command_id)
        scope_identity = ExecutionScopeIdentity(command.id, command.issued_generation)
        scope = (
            gate.scope if gate is not None else self.launcher.open_scope(scope_identity)
        )
        release_ambiguous = command.release_status == "ambiguous"
        outcome = "terminated"
        completed_result: CompletedCommand | None = None
        if gate is not None:
            try:
                completed_result = gate.wait(self.term_timeout)
                if not release_ambiguous:
                    outcome = "completed"
            except CommandTimeout:
                gate.terminate_group(self.term_timeout, self.kill_timeout)
                try:
                    gate.wait(self.kill_timeout)
                except CommandTimeout:
                    pass
        else:
            try:
                if not self.process_probe.identity_and_group_absent(command.process):
                    raise ProcessQuiescenceTimeout(
                        "supervised process is still present"
                    )
                if not release_ambiguous:
                    outcome = "completed"
            except ProcessQuiescenceTimeout:
                self.process_terminator.terminate_group(
                    command.process, self.term_timeout, self.kill_timeout
                )
        escaped = scope.is_populated()
        if escaped:
            self._terminate_scope(scope)
            outcome = "terminated"
        evidence = self._acknowledge_absence(command, scope, outcome, daemon_fence)
        fence = OperationFence(command.operation_id, command.issued_generation)
        elapsed_ms = self._elapsed_ms(command_id)
        if completed_result is not None:
            self._emit_command_output(
                fence, command.kind, completed_result, command_id=command_id
            )
        if completed_result is not None and completed_result.returncode != 0:
            self._emit_command_event(
                fence,
                command.kind,
                "ltfs.command.failed",
                OperationalSeverity.ERROR,
                "LTFS command failed.",
                command_id=command_id,
                exit_code=completed_result.returncode,
                elapsed_ms=elapsed_ms,
            )
            self._command_started_at.pop(command_id, None)
            raise CommandFailed(command.kind, completed_result.returncode)
        if escaped:
            self._emit_command_event(
                fence,
                command.kind,
                "ltfs.command.failed",
                OperationalSeverity.ERROR,
                "LTFS command escaped its execution scope.",
                command_id=command_id,
                elapsed_ms=elapsed_ms,
            )
            self._command_started_at.pop(command_id, None)
            raise CommandError("supervised command left processes in its scope")
        if outcome == "terminated":
            self._emit_command_event(
                fence,
                command.kind,
                "ltfs.command.cancelled",
                OperationalSeverity.WARNING,
                "LTFS command was cancelled.",
                command_id=command_id,
                elapsed_ms=elapsed_ms,
            )
        else:
            self._emit_command_event(
                fence,
                command.kind,
                "ltfs.command.succeeded",
                OperationalSeverity.INFO,
                "LTFS command completed before cancellation.",
                command_id=command_id,
                exit_code=(
                    completed_result.returncode
                    if completed_result is not None
                    else None
                ),
                elapsed_ms=elapsed_ms,
            )
        self._command_started_at.pop(command_id, None)
        return evidence

    def reconcile(
        self, operation_id: str, daemon_fence: DaemonFence
    ) -> CommandQuiescenceReceipt:
        for command in self.catalog.hardware_commands_for_operation(operation_id):
            if command.state != "quiesced":
                self.reconcile_one(command.id, daemon_fence)
        return self.catalog.create_command_quiescence_receipt(
            operation_id, daemon_fence
        )
