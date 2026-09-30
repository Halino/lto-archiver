from __future__ import annotations

import argparse
import contextlib
import grp
import hmac
import os
import pwd
import signal
import socket
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from ltobackup.broker.cgroup import CgroupV2BrokerRoot
from ltobackup.broker.ltfs_session import (
    BrokerLtfsExecutor,
    LtfsSessionPins,
    LtfsStandaloneReceiptRoot,
    ProcMountInfoProbe,
    ProcProcessProbe,
)
from ltobackup.broker.service import CommandBrokerService
from ltobackup.broker.store import BrokerStateStore
from ltobackup.errors import ValidationError
from ltobackup.linux_settings import LinuxSettings, load_linux_settings
from ltobackup.operational_log import (
    JournalOperationalEventSink,
    OperationalEvent,
    OperationalSeverity,
    OperationalSource,
)
from ltobackup.qualification.broker_executor import BrokerQualificationExecutor
from ltobackup.qualification.physical_driver import PhysicalLtfsQualificationDriver
from ltobackup.qualification.physical_runtime import (
    SystemPhysicalLtfsQualificationRuntime,
)

_SYSTEMD_SOCKET_FD = 3
_SERVICE_USER = "lto-archiver"
_SERVICE_GROUP = "lto-archiver"
_DAEMON_CONTEXT = "system_u:system_r:lto_archiver_t:s0"
_CREDENTIAL_DIRECTORY = Path("/run/credentials/lto-archiver-command-broker.service")
_STATE_DATABASE = Path("/var/lib/lto-archiver-broker/state.db")
_STANDALONE_RECEIPT_ROOT = Path("/var/lib/lto-archiver-broker/receipts")
_QUALIFICATION_WORKSPACE_ROOT = Path("/var/lib/lto-archiver-broker/qualification")
_CONFIG_PATH = Path("/etc/lto-archiver/config.toml")
_PROC_ROOT = Path("/proc")
_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
_CGROUP_MEMBERSHIP = Path("/proc/self/cgroup")
_SELINUX_ENFORCE = Path("/sys/fs/selinux/enforce")
_SECRET_BYTES = 32


def _fstat(fd: int) -> os.stat_result:
    return os.fstat(fd)


def _lstat(path: str | os.PathLike[str]) -> os.stat_result:
    return os.lstat(path)


def _registered_unix_listener(path: str, inode: int) -> bool:
    try:
        payload = _read_bounded(Path("/proc/net/unix"), 1_048_576)
        lines = payload.decode("ascii", errors="strict").splitlines()[1:]
    except (RuntimeError, UnicodeDecodeError):
        return False
    matches = 0
    for line in lines:
        fields = line.split(maxsplit=7)
        if (
            len(fields) == 8
            and fields[3] == "00010000"
            and fields[4] == "0005"
            and fields[5] == "01"
            and fields[6].isdecimal()
            and int(fields[6]) == inode
            and fields[7] == path
        ):
            matches += 1
    return matches == 1


def _activated_socket_from_fd(
    fd: int,
    environ: Mapping[str, str],
    *,
    expected_gid: int,
) -> socket.socket:
    """Duplicate and validate the exact single systemd activation socket."""

    if (
        type(fd) is not int
        or fd < 0
        or not isinstance(environ, Mapping)
        or environ.get("LISTEN_PID") != str(os.getpid())
        or environ.get("LISTEN_FDS") != "1"
        or type(expected_gid) is not int
        or not 0 <= expected_gid < 1 << 32
    ):
        raise RuntimeError("command broker activation unavailable")
    duplicate: int | None = None
    listener: socket.socket | None = None
    try:
        duplicate = os.dup(fd)
        os.set_inheritable(duplicate, False)
        listener = socket.socket(fileno=duplicate)
        duplicate = None
        if (
            listener.family != socket.AF_UNIX
            or listener.type & 0xF != socket.SOCK_SEQPACKET
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        ):
            raise RuntimeError("command broker activation unavailable")
        socket_name = listener.getsockname()
        if (
            type(socket_name) is not str
            or not socket_name.startswith("/")
            or "\0" in socket_name
        ):
            raise RuntimeError("command broker activation unavailable")
        descriptor_status = _fstat(listener.fileno())
        path_status = _lstat(socket_name)
        if (
            not stat.S_ISSOCK(descriptor_status.st_mode)
            or not stat.S_ISSOCK(path_status.st_mode)
            or path_status.st_uid != 0
            or path_status.st_gid != expected_gid
            or stat.S_IMODE(path_status.st_mode) != 0o660
            or not _registered_unix_listener(socket_name, descriptor_status.st_ino)
        ):
            raise RuntimeError("command broker activation unavailable")
        result = listener
        listener = None
        return result
    except (OSError, ValueError, TypeError):
        raise RuntimeError("command broker activation unavailable") from None
    finally:
        if listener is not None:
            listener.close()
        if duplicate is not None:
            with contextlib.suppress(OSError):
                os.close(duplicate)


def _read_credentials(directory: Path) -> tuple[bytes, bytes, bytes]:
    """Read the three exact root-owned systemd credential files."""

    if not isinstance(directory, Path) or not directory.is_absolute():
        raise RuntimeError("command broker credentials unavailable")
    directory_fd: int | None = None
    try:
        directory_fd = os.open(
            directory,
            os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        directory_status = _fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_status.st_mode)
            or directory_status.st_uid != 0
            or directory_status.st_gid != 0
            or stat.S_IMODE(directory_status.st_mode) != 0o500
        ):
            raise RuntimeError("command broker credentials unavailable")
        values = tuple(
            _read_credential(name, directory_fd=directory_fd)
            for name in (
                "broker-capability",
                "broker-proof-key",
                "qualification-credential",
            )
        )
        if any(
            hmac.compare_digest(values[left], values[right])
            for left, right in ((0, 1), (0, 2), (1, 2))
        ):
            raise RuntimeError("command broker credentials unavailable")
        return values
    except (OSError, ValueError, TypeError):
        raise RuntimeError("command broker credentials unavailable") from None
    finally:
        if directory_fd is not None:
            with contextlib.suppress(OSError):
                os.close(directory_fd)


def _config_snapshot(status) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
    )


def _load_broker_settings(path: Path, *, expected_gid: int) -> LinuxSettings:
    """Load the fixed RPM config through one exact root-owned descriptor."""

    if (
        not isinstance(path, Path)
        or not path.is_absolute()
        or type(expected_gid) is not int
        or not 0 <= expected_gid < 1 << 32
    ):
        raise RuntimeError("command broker configuration unavailable")
    fd: int | None = None
    try:
        if path.resolve(strict=True) != path:
            raise RuntimeError("command broker configuration unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = _fstat(fd)
        path_before = _lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o640
            or before.st_uid != 0
            or before.st_gid != expected_gid
            or before.st_nlink != 1
            or _config_snapshot(path_before) != _config_snapshot(before)
        ):
            raise RuntimeError("command broker configuration unavailable")
        settings = load_linux_settings(Path(f"/proc/self/fd/{fd}"))
        if _config_snapshot(_fstat(fd)) != _config_snapshot(before) or _config_snapshot(
            _lstat(path)
        ) != _config_snapshot(before):
            raise RuntimeError("command broker configuration unavailable")
        return settings
    except (OSError, RuntimeError, ValidationError, ValueError, TypeError):
        raise RuntimeError("command broker configuration unavailable") from None
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _read_credential(name: str, *, directory_fd: int) -> bytes:
    fd: int | None = None
    try:
        fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        descriptor_status = _fstat(fd)
        path_status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(descriptor_status.st_mode)
            or descriptor_status.st_uid != 0
            or descriptor_status.st_gid != 0
            or stat.S_IMODE(descriptor_status.st_mode) != 0o400
            or descriptor_status.st_nlink != 1
            or (descriptor_status.st_dev, descriptor_status.st_ino)
            != (path_status.st_dev, path_status.st_ino)
        ):
            raise RuntimeError("command broker credentials unavailable")
        value = os.read(fd, _SECRET_BYTES + 1)
        if len(value) != _SECRET_BYTES or os.read(fd, 1):
            raise RuntimeError("command broker credentials unavailable")
        return value
    finally:
        if fd is not None:
            os.close(fd)


def _delegated_root_from_membership(payload: bytes) -> Path:
    if type(payload) is not bytes or not payload or len(payload) > 65_536:
        raise RuntimeError("command broker delegated root unavailable")
    try:
        lines = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        raise RuntimeError("command broker delegated root unavailable") from None
    unified = [line[3:] for line in lines if line.startswith("0::")]
    if len(lines) != 1 or len(unified) != 1 or not unified[0].startswith("/"):
        raise RuntimeError("command broker delegated root unavailable")
    relative = Path(unified[0]).parts[1:]
    if not relative or any(
        part in {"", ".", ".."} or "\\" in part for part in relative
    ):
        raise RuntimeError("command broker delegated root unavailable")
    return Path("/sys/fs/cgroup").joinpath(*relative)


def _read_bounded(path: Path, maximum: int) -> bytes:
    fd: int | None = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(65_536, maximum + 1 - total))
            if not chunk:
                if not chunks:
                    raise RuntimeError("command broker startup unavailable")
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("command broker startup unavailable")
    except OSError:
        raise RuntimeError("command broker startup unavailable") from None
    finally:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)


def _clock() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _argument_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="lto-archiver-command-broker",
        description="Run the privileged LTO Archiver command broker.",
        allow_abbrev=False,
    )


def _notify_systemd_ready(environ: Mapping[str, str]) -> None:
    """Notify initialization/IPC readiness, never hardware authorization.

    Only the main process calls this, after startup reconciliation and before
    serving. The ordinary authenticated readiness RPC still evaluates clean
    state, including any pending finalization monitors.
    """
    try:
        address = environ.get("NOTIFY_SOCKET") if isinstance(environ, Mapping) else None
        if (
            type(address) is not str
            or len(address) < 2
            or address[0] not in {"/", "@"}
            or "\0" in address
        ):
            raise ValueError
        target = "\0" + address[1:] if address.startswith("@") else address
        payload = b"READY=1"
        with socket.socket(
            socket.AF_UNIX, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC
        ) as notification:
            notification.settimeout(5.0)
            if notification.sendto(payload, target) != len(payload):
                raise ValueError
    except (OSError, TypeError, ValueError):
        raise RuntimeError("command broker notification unavailable") from None


def main(argv: Sequence[str] | None = None) -> int:
    """Run the root broker from its exact systemd activation contract."""

    _argument_parser().parse_args(argv)
    listener: socket.socket | None = None
    store: BrokerStateStore | None = None
    cgroup: CgroupV2BrokerRoot | None = None
    pins: LtfsSessionPins | None = None
    receipt_root: LtfsStandaloneReceiptRoot | None = None
    qualification_runtime: SystemPhysicalLtfsQualificationRuntime | None = None
    service: CommandBrokerService | None = None
    previous_handlers: dict[int, object] = {}
    operational_events = JournalOperationalEventSink(
        syslog_identifier="lto-archiver-command-broker"
    )
    try:
        account = pwd.getpwnam(_SERVICE_USER)
        group = grp.getgrnam(_SERVICE_GROUP)
        if account.pw_gid != group.gr_gid:
            raise RuntimeError("command broker identity unavailable")
        listener = _activated_socket_from_fd(
            _SYSTEMD_SOCKET_FD, os.environ, expected_gid=group.gr_gid
        )
        capability, proof_key, qualification_credential = _read_credentials(
            _CREDENTIAL_DIRECTORY
        )
        settings = _load_broker_settings(_CONFIG_PATH, expected_gid=group.gr_gid)
        pins = LtfsSessionPins.open(
            mount_path=settings.mount_path,
            tape_device_path=settings.tape_device_path,
            scsi_device_path=settings.scsi_device_path,
        )
        receipt_root = LtfsStandaloneReceiptRoot.open(_STANDALONE_RECEIPT_ROOT)
        qualification_runtime = SystemPhysicalLtfsQualificationRuntime(
            settings=settings,
            receipt_root=receipt_root,
            workspace_root=_QUALIFICATION_WORKSPACE_ROOT,
        )
        qualification_executor = BrokerQualificationExecutor(
            PhysicalLtfsQualificationDriver(runtime=qualification_runtime),
            credential=qualification_credential,
        )
        boot_id = _read_bounded(_BOOT_ID_PATH, 128).decode("ascii").strip()
        delegated_root = _delegated_root_from_membership(
            _read_bounded(_CGROUP_MEMBERSHIP, 65_536)
        )
        enforcing_payload = _read_bounded(_SELINUX_ENFORCE, 2)
        if enforcing_payload not in {b"0", b"0\n", b"1", b"1\n"}:
            raise RuntimeError("command broker SELinux state unavailable")
        store = BrokerStateStore.open(_STATE_DATABASE, boot_id=boot_id, clock=_clock)
        cgroup = CgroupV2BrokerRoot.open(delegated_root, _PROC_ROOT, _BOOT_ID_PATH)
        service = CommandBrokerService(
            store,
            cgroup,
            capability=capability,
            proof_key=proof_key,
            daemon_uid=account.pw_uid,
            daemon_gid=group.gr_gid,
            enforcing=enforcing_payload.startswith(b"1"),
            daemon_context=_DAEMON_CONTEXT,
            ltfs_pins=pins,
            ltfs_receipt_root=receipt_root,
            ltfs_executor=BrokerLtfsExecutor(),
            # Task 6 must keep the broker in the host mount namespace; these
            # probes intentionally observe /proc/self from that future unit.
            ltfs_mountinfo_probe=ProcMountInfoProbe(),
            ltfs_process_probe=ProcProcessProbe(),
            qualification_executor=qualification_executor,
            event_sink=operational_events,
        )

        def request_shutdown(_signum: int, _frame: object) -> None:
            if service is not None:
                service.shutdown()

        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, request_shutdown)
        service.reconcile_startup()
        _notify_systemd_ready(os.environ)
        operational_events.emit(
            OperationalEvent(
                OperationalSource.COMMAND_BROKER,
                OperationalSeverity.INFO,
                "command_broker.started",
                "Command broker started.",
            )
        )
        service.serve(listener)
        operational_events.emit(
            OperationalEvent(
                OperationalSource.COMMAND_BROKER,
                OperationalSeverity.INFO,
                "command_broker.stopped",
                "Command broker stopped.",
            )
        )
        return 0
    except Exception:  # noqa: BLE001 - startup is deliberately fail-closed/redacted
        operational_events.emit(
            OperationalEvent(
                OperationalSource.COMMAND_BROKER,
                OperationalSeverity.ERROR,
                "command_broker.failed",
                "Command broker failed.",
            )
        )
        return 2
    finally:
        if service is not None:
            service.close()
        if qualification_runtime is not None:
            qualification_runtime.close()
        if pins is not None:
            pins.close()
        if receipt_root is not None:
            receipt_root.close()
        if cgroup is not None:
            cgroup.close()
        if store is not None:
            store.close()
        if listener is not None:
            listener.close()
        for signum, handler in previous_handlers.items():
            with contextlib.suppress(ValueError):
                signal.signal(signum, handler)


if __name__ == "__main__":
    sys.exit(main())
