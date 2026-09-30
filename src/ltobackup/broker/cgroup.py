from __future__ import annotations

import contextlib
import ctypes
import hashlib
import os
import re
import signal as signal_module
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self

from ltobackup.broker.store import (
    BrokerStateConflict,
    BrokerStateStore,
    BrokerStateUnavailable,
    ScopeRecord,
)

CGROUP2_SUPER_MAGIC = 0x63677270
PROC_SUPER_MAGIC = 0x9FA0

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_TRAVERSAL_FLAGS = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_WRITE_FLAGS = os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_CONTROL_BYTES = 65_536
_MAX_CGROUP_DIRECTORIES = 4_096
_MAX_CGROUP_DEPTH = 64
_MAX_MEMBER_PID = 1 << 31
_FREEZE_TIMEOUT_SECONDS = 1.0
_CONTROLLER = re.compile(r"[a-z][a-z0-9_]*\Z")


class CgroupUnavailable(RuntimeError):
    """The delegated cgroup root cannot be trusted."""

    code = "state.unavailable"

    def __init__(self) -> None:
        super().__init__("command broker cgroup unavailable")


class CgroupConflict(RuntimeError):
    """The requested operation contradicts the bound cgroup identity."""

    code = "scope.conflict"

    def __init__(self) -> None:
        super().__init__("command broker cgroup conflict")


@dataclass(frozen=True)
class CgroupBinding:
    scope_id: str = field(repr=False)
    device: int = field(repr=False)
    inode: int = field(repr=False)


@dataclass(frozen=True)
class CgroupValidation:
    scope_id: str = field(repr=False)
    populated: bool
    member_pids: tuple[int, ...]


@dataclass(frozen=True)
class ProcessIdentityProof:
    pid: int
    start_ticks: int


@dataclass(frozen=True)
class _ProcessIdentity:
    pid: int
    start_ticks: int
    device: int
    inode: int


class _OpenDispatcher:
    def __get__(self, instance: object, owner: type[CgroupV2BrokerRoot]):
        if instance is None:
            return owner._open_root
        return instance._open_scope


def _filesystem_magic(fd: int) -> int:
    buffer = (ctypes.c_byte * 256)()
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.fstatfs(ctypes.c_int(fd), ctypes.byref(buffer))
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return int(ctypes.cast(buffer, ctypes.POINTER(ctypes.c_long)).contents.value)


def _secure_root(fd: int) -> bool:
    status = os.fstat(fd)
    return (
        os.geteuid() == 0
        and stat.S_ISDIR(status.st_mode)
        and status.st_uid == 0
        and status.st_gid == 0
        and stat.S_IMODE(status.st_mode) & 0o022 == 0
    )


def _make_cgroup(name: str, *, dir_fd: int) -> None:
    os.mkdir(name, mode=0o700, dir_fd=dir_fd)


def _write_control(name: str, payload: bytes, *, dir_fd: int) -> None:
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dir_fd)
    try:
        written = os.write(fd, payload)
        if written != len(payload):
            raise OSError("short cgroup control write")
    finally:
        os.close(fd)


def _remove_cgroup(name: str, *, dir_fd: int) -> None:
    os.rmdir(name, dir_fd=dir_fd)


def _pidfd_open(pid: int) -> int:
    return os.pidfd_open(pid, 0)


def _pidfd_send_signal(pidfd: int, signum: int) -> None:
    signal_module.pidfd_send_signal(pidfd, signum)


def _open_absolute_directory(path: Path) -> int:
    parts = path.parts
    if (
        not path.is_absolute()
        or not parts
        or parts[0] != os.sep
        or any(part in {"", ".", ".."} for part in parts[1:])
    ):
        raise CgroupUnavailable
    current = os.open(os.sep, _DIRECTORY_FLAGS)
    try:
        for part in parts[1:]:
            next_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = next_fd
        result = current
        current = -1
        return result
    finally:
        if current >= 0:
            os.close(current)


def _read_file(name: str, *, dir_fd: int) -> bytes:
    fd = os.open(name, _FILE_READ_FLAGS, dir_fd=dir_fd)
    try:
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, min(4096, _MAX_CONTROL_BYTES + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_CONTROL_BYTES:
                raise CgroupConflict
    finally:
        os.close(fd)


def _read_relative_file(root_fd: int, parts: tuple[str, ...]) -> bytes:
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise CgroupUnavailable
    current = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, _TRAVERSAL_FLAGS, dir_fd=current)
            os.close(current)
            current = next_fd
        return _read_file(parts[-1], dir_fd=current)
    finally:
        os.close(current)


def _parse_boot_id(payload: bytes) -> str:
    try:
        value = payload.decode("ascii", errors="strict").strip()
        parsed = uuid.UUID(value)
    except (UnicodeDecodeError, ValueError, AttributeError):
        raise CgroupUnavailable from None
    if str(parsed) != value or parsed.version is None:
        raise CgroupUnavailable
    return value


def _parse_events(payload: bytes) -> dict[str, bool]:
    try:
        lines = payload.decode("ascii", errors="strict").splitlines()
    except UnicodeDecodeError:
        raise CgroupConflict from None
    values: dict[str, bool] = {}
    for line in lines:
        fields = line.split()
        if (
            len(fields) != 2
            or fields[0] in values
            or not _CONTROLLER.fullmatch(fields[0])
            or fields[1] not in {"0", "1"}
        ):
            raise CgroupConflict
        values[fields[0]] = fields[1] == "1"
    if "populated" not in values:
        raise CgroupConflict
    return values


def _parse_members(payload: bytes) -> tuple[int, ...]:
    try:
        fields = payload.decode("ascii", errors="strict").split()
    except UnicodeDecodeError:
        raise CgroupConflict from None
    members: set[int] = set()
    for field_value in fields:
        if not field_value.isdecimal() or field_value.startswith("0"):
            raise CgroupConflict
        pid = int(field_value)
        if not 0 < pid < _MAX_MEMBER_PID:
            raise CgroupConflict
        members.add(pid)
    return tuple(sorted(members))


def _parse_start_ticks(payload: bytes, expected_pid: int) -> int:
    prefix = str(expected_pid).encode("ascii") + b" ("
    if not payload.startswith(prefix) or not payload.endswith(b"\n"):
        raise CgroupConflict
    closing = payload.rfind(b") ")
    if closing < len(prefix):
        raise CgroupConflict
    fields = payload[closing + 2 :].split()
    if len(fields) < 20:
        raise CgroupConflict
    start_value = fields[19]
    if not start_value.isdigit():
        raise CgroupConflict
    start_ticks = int(start_value)
    if start_ticks < 0 or start_ticks >= 1 << 63:
        raise CgroupConflict
    return start_ticks


class CgroupV2BrokerRoot:
    """Dirfd-anchored authority for one delegated command cgroup subtree."""

    def __init__(
        self,
        root_fd: int,
        proc_fd: int,
        boot_parts: tuple[str, ...],
        boot_id: str,
    ) -> None:
        self._root_fd = root_fd
        self._proc_fd = proc_fd
        self._boot_parts = boot_parts
        self._boot_id = boot_id
        self._closed = False
        self._released: set[tuple[str, int, int]] = set()

    open = _OpenDispatcher()

    @classmethod
    def _open_root(
        cls,
        root: Path,
        proc_root: Path,
        boot_id_path: Path,
    ) -> Self:
        if not all(
            isinstance(value, Path) for value in (root, proc_root, boot_id_path)
        ):
            raise CgroupUnavailable
        try:
            relative_boot = boot_id_path.relative_to(proc_root)
        except ValueError:
            raise CgroupUnavailable from None
        boot_parts = relative_boot.parts
        if not boot_parts or any(part in {"", ".", ".."} for part in boot_parts):
            raise CgroupUnavailable
        root_fd: int | None = None
        proc_fd: int | None = None
        try:
            root_fd = _open_absolute_directory(root)
            proc_fd = _open_absolute_directory(proc_root)
            if (
                _filesystem_magic(root_fd) != CGROUP2_SUPER_MAGIC
                or _filesystem_magic(proc_fd) != PROC_SUPER_MAGIC
                or not _secure_root(root_fd)
            ):
                raise CgroupUnavailable
            cls._validate_root_controls(root_fd)
            boot_id = _parse_boot_id(_read_relative_file(proc_fd, boot_parts))
            result = cls(root_fd, proc_fd, boot_parts, boot_id)
            root_fd = None
            proc_fd = None
            return result
        except (CgroupUnavailable, CgroupConflict):
            raise CgroupUnavailable from None
        except (OSError, ValueError, TypeError):
            raise CgroupUnavailable from None
        finally:
            if root_fd is not None:
                os.close(root_fd)
            if proc_fd is not None:
                os.close(proc_fd)

    @staticmethod
    def _validate_root_controls(root_fd: int) -> None:
        controllers = _read_file("cgroup.controllers", dir_fd=root_fd)
        try:
            controller_names = controllers.decode("ascii", errors="strict").split()
        except UnicodeDecodeError:
            raise CgroupUnavailable from None
        if any(_CONTROLLER.fullmatch(name) is None for name in controller_names):
            raise CgroupUnavailable
        _parse_events(_read_file("cgroup.events", dir_fd=root_fd))
        for name, flags in (
            ("cgroup.procs", _FILE_READ_FLAGS),
            ("cgroup.kill", _FILE_WRITE_FLAGS),
            ("cgroup.freeze", _FILE_READ_FLAGS),
        ):
            fd = os.open(name, flags, dir_fd=root_fd)
            os.close(fd)

    @staticmethod
    def scope_path_sha256(command_id: str, owner_generation: int) -> str:
        if (
            type(command_id) is not str
            or not command_id
            or not command_id.isascii()
            or not command_id.isprintable()
            or "/" in command_id
            or "\\" in command_id
            or type(owner_generation) is not int
            or not 0 <= owner_generation < 1 << 63
        ):
            raise CgroupConflict
        canonical = f"{owner_generation}:{command_id}".encode("ascii")
        return hashlib.sha256(b"lto-scope-v1\0" + canonical).hexdigest()

    @classmethod
    def scope_name(cls, command_id: str, owner_generation: int) -> str:
        return "command-" + cls.scope_path_sha256(command_id, owner_generation)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.close(self._root_fd)
        os.close(self._proc_fd)

    def __enter__(self) -> Self:
        self._assert_open()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _assert_open(self) -> None:
        if self._closed:
            raise CgroupUnavailable

    def validate_readiness(self) -> None:
        """Verify the live delegated root without allocating a command scope."""

        self._assert_open()
        self._validate_root_controls(self._root_fd)
        self._check_boot()

    def _check_boot(self) -> None:
        self._assert_open()
        try:
            current = _parse_boot_id(
                _read_relative_file(self._proc_fd, self._boot_parts)
            )
        except CgroupUnavailable:
            raise CgroupConflict from None
        if current != self._boot_id:
            raise CgroupConflict

    def _check_record(self, record: ScopeRecord, *, bound: bool) -> str:
        self._check_boot()
        if (
            type(record) is not ScopeRecord
            or record.state != "ACTIVE"
            or record.boot_id != self._boot_id
            or record.scope_path_sha256
            != self.scope_path_sha256(record.command_id, record.owner_generation)
            or not record.scope_id
            or not record.scope_id.isascii()
            or not record.scope_id.isprintable()
            or "/" in record.scope_id
            or "\\" in record.scope_id
            or (record.cgroup_device is None) == bound
            or (record.cgroup_inode is None) == bound
        ):
            raise CgroupConflict
        return self.scope_name(record.command_id, record.owner_generation)

    def create(self, record: ScopeRecord, store: BrokerStateStore) -> ScopeRecord:
        name = self._check_record(record, bound=False)
        if type(store) is not BrokerStateStore:
            raise CgroupConflict
        created = False
        try:
            _make_cgroup(name, dir_fd=self._root_fd)
            created = True
            scope_fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=self._root_fd)
            try:
                self._validate_scope_controls(scope_fd)
                status = os.fstat(scope_fd)
            finally:
                os.close(scope_fd)
            bound_record = store.bind_cgroup(
                record, device=status.st_dev, inode=status.st_ino
            )
            return bound_record
        except FileExistsError:
            raise CgroupConflict from None
        except (BrokerStateConflict, BrokerStateUnavailable):
            if created:
                with contextlib.suppress(OSError):
                    _remove_cgroup(name, dir_fd=self._root_fd)
            raise CgroupConflict from None
        except CgroupConflict:
            if created:
                with contextlib.suppress(OSError):
                    _remove_cgroup(name, dir_fd=self._root_fd)
            raise
        except (OSError, ValueError, TypeError):
            if created:
                with contextlib.suppress(OSError):
                    _remove_cgroup(name, dir_fd=self._root_fd)
            raise CgroupConflict from None

    @staticmethod
    def _validate_scope_controls(scope_fd: int) -> None:
        _parse_events(_read_file("cgroup.events", dir_fd=scope_fd))
        _parse_members(_read_file("cgroup.procs", dir_fd=scope_fd))
        for name, flags in (
            ("cgroup.kill", _FILE_WRITE_FLAGS),
            ("cgroup.freeze", _FILE_READ_FLAGS),
        ):
            fd = os.open(name, flags, dir_fd=scope_fd)
            os.close(fd)

    def _scope_fd(self, record: ScopeRecord) -> tuple[int, str]:
        name = self._check_record(record, bound=True)
        try:
            fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=self._root_fd)
            status = os.fstat(fd)
            anchored = os.stat(name, dir_fd=self._root_fd, follow_symlinks=False)
            if (
                not stat.S_ISDIR(anchored.st_mode)
                or status.st_dev != anchored.st_dev
                or status.st_ino != anchored.st_ino
                or status.st_dev != record.cgroup_device
                or status.st_ino != record.cgroup_inode
            ):
                raise CgroupConflict
            self._validate_scope_controls(fd)
            return fd, name
        except CgroupConflict:
            with contextlib.suppress(UnboundLocalError, OSError):
                os.close(fd)
            raise
        except (OSError, ValueError, TypeError):
            with contextlib.suppress(UnboundLocalError, OSError):
                os.close(fd)
            raise CgroupConflict from None

    def _open_scope(self, record: ScopeRecord) -> CgroupBinding:
        fd, _name = self._scope_fd(record)
        try:
            status = os.fstat(fd)
            return CgroupBinding(record.scope_id, status.st_dev, status.st_ino)
        finally:
            os.close(fd)

    @staticmethod
    def _child_directories(fd: int) -> tuple[str, ...]:
        names: list[str] = []
        for name in os.listdir(fd):
            status = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode):
                raise CgroupConflict
            if stat.S_ISDIR(status.st_mode):
                if name in {"", ".", ".."} or "/" in name or "\\" in name:
                    raise CgroupConflict
                names.append(name)
            elif not stat.S_ISREG(status.st_mode):
                raise CgroupConflict
        return tuple(sorted(names))

    def _snapshot(
        self, record: ScopeRecord
    ) -> tuple[CgroupValidation, tuple[tuple[str, ...], ...]]:
        root_fd, _name = self._scope_fd(record)
        opened: list[tuple[tuple[str, ...], int]] = [((), root_fd)]
        try:
            index = 0
            members: set[int] = set()
            root_populated = False
            descendant_populated = False
            while index < len(opened):
                relative, fd = opened[index]
                index += 1
                events = _parse_events(_read_file("cgroup.events", dir_fd=fd))
                current_members = _parse_members(_read_file("cgroup.procs", dir_fd=fd))
                members.update(current_members)
                if not relative:
                    root_populated = events["populated"]
                elif events["populated"]:
                    descendant_populated = True
                if len(relative) >= _MAX_CGROUP_DEPTH:
                    if self._child_directories(fd):
                        raise CgroupConflict
                    continue
                for child_name in self._child_directories(fd):
                    if len(opened) >= _MAX_CGROUP_DIRECTORIES:
                        raise CgroupConflict
                    child_fd = os.open(child_name, _DIRECTORY_FLAGS, dir_fd=fd)
                    opened.append((relative + (child_name,), child_fd))
            if not root_populated and (members or descendant_populated):
                raise CgroupConflict
            self.open(record)
            return (
                CgroupValidation(
                    record.scope_id, root_populated, tuple(sorted(members))
                ),
                tuple(relative for relative, _fd in opened),
            )
        except CgroupConflict:
            raise
        except (OSError, ValueError, TypeError):
            raise CgroupConflict from None
        finally:
            for _relative, fd in reversed(opened):
                with contextlib.suppress(OSError):
                    os.close(fd)

    def validate(self, record: ScopeRecord) -> CgroupValidation:
        validation, _directories = self._snapshot(record)
        return validation

    def _process_identity(self, pid: int, daemon_uid: int) -> _ProcessIdentity:
        if (
            type(pid) is not int
            or not 0 < pid < _MAX_MEMBER_PID
            or type(daemon_uid) is not int
            or not 0 <= daemon_uid < 1 << 32
        ):
            raise CgroupConflict
        self._check_boot()
        try:
            process_fd = os.open(str(pid), _DIRECTORY_FLAGS, dir_fd=self._proc_fd)
            try:
                status = os.fstat(process_fd)
                if status.st_uid != daemon_uid:
                    raise CgroupConflict
                start_ticks = _parse_start_ticks(
                    _read_file("stat", dir_fd=process_fd), pid
                )
                return _ProcessIdentity(pid, start_ticks, status.st_dev, status.st_ino)
            finally:
                os.close(process_fd)
        except CgroupConflict:
            raise
        except (OSError, ValueError, TypeError):
            raise CgroupConflict from None

    def attach(
        self,
        record: ScopeRecord,
        pid: int,
        *,
        daemon_uid: int,
        store: BrokerStateStore,
    ) -> ProcessIdentityProof:
        if type(store) is not BrokerStateStore:
            raise CgroupConflict
        try:
            record = store.require_cgroup_scope(record)
        except (BrokerStateConflict, BrokerStateUnavailable):
            raise CgroupConflict from None

        if record.pid is not None:
            if pid != record.pid:
                raise CgroupConflict
            try:
                identity_before = self._process_identity(pid, daemon_uid)
                validation = self.validate(record)
                identity_after = self._process_identity(pid, daemon_uid)
                if (
                    identity_before != identity_after
                    or identity_before.start_ticks != record.process_start_ticks
                    or identity_after.start_ticks != record.process_start_ticks
                    or not validation.populated
                    or pid not in validation.member_pids
                ):
                    raise CgroupConflict
                return ProcessIdentityProof(pid, identity_before.start_ticks)
            except (CgroupConflict, OSError, ValueError, TypeError):
                self._contain_broken(record, store)
                raise CgroupConflict from None

        try:
            validation = self.validate(record)
        except (CgroupConflict, OSError, ValueError, TypeError):
            self._contain_broken(record, store)
            raise CgroupConflict from None
        if validation.populated or validation.member_pids:
            self._contain_broken(record, store)
            raise CgroupConflict

        before = self._process_identity(pid, daemon_uid)
        scope_fd, _name = self._scope_fd(record)
        write_attempted = False
        try:
            write_attempted = True
            _write_control("cgroup.procs", f"{pid}\n".encode("ascii"), dir_fd=scope_fd)
            after_write = self._process_identity(pid, daemon_uid)
            if after_write != before:
                raise CgroupConflict
            validation = self.validate(record)
            after_validation = self._process_identity(pid, daemon_uid)
            if (
                after_validation != before
                or not validation.populated
                or validation.member_pids != (pid,)
            ):
                raise CgroupConflict
            store.attach_cgroup_process(record, pid=pid, start_ticks=before.start_ticks)
            return ProcessIdentityProof(pid, before.start_ticks)
        except (
            BrokerStateConflict,
            BrokerStateUnavailable,
            CgroupConflict,
            OSError,
            ValueError,
            TypeError,
        ):
            if write_attempted:
                self._contain_broken(record, store)
            raise CgroupConflict from None
        finally:
            os.close(scope_fd)

    @staticmethod
    def _events_frozen(scope_fd: int) -> bool:
        events = _parse_events(_read_file("cgroup.events", dir_fd=scope_fd))
        if "frozen" not in events:
            raise CgroupConflict
        return events["frozen"]

    def _confirm_frozen(self, scope_fd: int, frozen: bool) -> None:
        deadline = time.monotonic() + _FREEZE_TIMEOUT_SECONDS
        while self._events_frozen(scope_fd) is not frozen:
            if time.monotonic() >= deadline:
                raise CgroupConflict
            time.sleep(0.001)

    def _await_quiescent(self, record: ScopeRecord) -> None:
        deadline = time.monotonic() + _FREEZE_TIMEOUT_SECONDS
        while True:
            validation = self.validate(record)
            if not validation.populated and not validation.member_pids:
                return
            if time.monotonic() >= deadline:
                raise CgroupConflict
            time.sleep(0.001)

    def _hold_frozen(self, record: ScopeRecord) -> None:
        scope_fd, _name = self._scope_fd(record)
        try:
            _write_control("cgroup.freeze", b"1\n", dir_fd=scope_fd)
            self._confirm_frozen(scope_fd, True)
        finally:
            os.close(scope_fd)

    def _contain_broken(self, record: ScopeRecord, store: BrokerStateStore) -> None:
        state_durable = False
        try:
            store.break_cgroup_scope(record)
            state_durable = True
        except (BrokerStateConflict, BrokerStateUnavailable):
            pass

        quiescent = False
        try:
            self.kill(record)
            self._await_quiescent(record)
            quiescent = True
        except (CgroupConflict, OSError, ValueError, TypeError):
            pass

        if state_durable and quiescent:
            return
        if not quiescent:
            try:
                self._hold_frozen(record)
            except (CgroupConflict, OSError, ValueError, TypeError):
                raise CgroupUnavailable from None
        raise CgroupUnavailable

    def signal(
        self,
        record: ScopeRecord,
        signum: int,
        *,
        daemon_uid: int,
        store: BrokerStateStore,
    ) -> None:
        if (
            not isinstance(signum, int)
            or isinstance(signum, bool)
            or signum != signal_module.SIGTERM
        ):
            raise CgroupConflict
        if type(store) is not BrokerStateStore:
            raise CgroupConflict
        try:
            record = store.require_cgroup_scope(record)
        except (BrokerStateConflict, BrokerStateUnavailable):
            raise CgroupConflict from None
        scope_fd, _name = self._scope_fd(record)
        freeze_requested = False
        thaw_failed = False
        operation_error: BaseException | None = None
        try:
            freeze_requested = True
            _write_control("cgroup.freeze", b"1\n", dir_fd=scope_fd)
            self._confirm_frozen(scope_fd, True)
            members = self.validate(record).member_pids
            for pid in members:
                before = self._process_identity(pid, daemon_uid)
                pidfd = _pidfd_open(pid)
                try:
                    after = self._process_identity(pid, daemon_uid)
                    if after != before or pid not in self.validate(record).member_pids:
                        raise CgroupConflict
                    _pidfd_send_signal(pidfd, signum)
                finally:
                    os.close(pidfd)
        except (CgroupConflict, OSError, ValueError, TypeError) as error:
            operation_error = error
        finally:
            if freeze_requested:
                try:
                    _write_control("cgroup.freeze", b"0\n", dir_fd=scope_fd)
                    self._confirm_frozen(scope_fd, False)
                except (CgroupConflict, OSError, ValueError, TypeError) as error:
                    operation_error = error
                    thaw_failed = True
            os.close(scope_fd)
        if thaw_failed:
            self._contain_broken(record, store)
            raise CgroupConflict from None
        if operation_error is not None:
            raise CgroupConflict from None

    def kill(self, record: ScopeRecord) -> None:
        scope_fd, _name = self._scope_fd(record)
        try:
            _write_control("cgroup.kill", b"1\n", dir_fd=scope_fd)
        except (OSError, ValueError, TypeError):
            raise CgroupConflict from None
        finally:
            os.close(scope_fd)

    @staticmethod
    def _open_relative_directory(root_fd: int, parts: tuple[str, ...]) -> int:
        current = os.dup(root_fd)
        try:
            for part in parts:
                next_fd = os.open(part, _DIRECTORY_FLAGS, dir_fd=current)
                os.close(current)
                current = next_fd
            result = current
            current = -1
            return result
        finally:
            if current >= 0:
                os.close(current)

    def release(self, record: ScopeRecord) -> None:
        if type(record) is ScopeRecord and record.cgroup_device is not None:
            released_key = (
                record.scope_id,
                record.cgroup_device,
                record.cgroup_inode,
            )
            if released_key in self._released:
                return
        validation, directories = self._snapshot(record)
        if validation.populated or validation.member_pids:
            raise CgroupConflict
        scope_fd, name = self._scope_fd(record)
        try:
            for relative in sorted(directories[1:], key=len, reverse=True):
                parent_fd = self._open_relative_directory(scope_fd, relative[:-1])
                try:
                    _remove_cgroup(relative[-1], dir_fd=parent_fd)
                finally:
                    os.close(parent_fd)
            self.open(record)
            _remove_cgroup(name, dir_fd=self._root_fd)
        except CgroupConflict:
            raise
        except (OSError, ValueError, TypeError):
            raise CgroupConflict from None
        finally:
            os.close(scope_fd)
        self._released.add(released_key)
