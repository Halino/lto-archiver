#!/usr/bin/python3.11 -I
from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import stat
import sys
from collections.abc import Mapping
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages")
sys.path.insert(0, "/usr/lib/python3.11/site-packages")

from ltobackup.errors import ValidationError
from ltobackup.linux_settings import LinuxSettings, load_linux_settings

_SYSTEMD_DIRECTORY = Path("/etc/systemd/system")
_DROPIN_NAME = "20-lto-device-policy.conf"
_UNITS = frozenset(
    {
        "lto-archiver-archive-runner-qualification.service",
        "lto-archiver-command-broker.service",
        "lto-archiver-ltfs-qualification.service",
        "lto-archiverd.service",
    }
)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_REGULAR_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC


class PublicationDurabilityError(RuntimeError):
    """Publication or rollback durability could not be established."""


class _PreparedDropin:
    def __init__(
        self,
        *,
        unit: str,
        directory_name: str,
        directory_fd: int,
        directory_identity: tuple[int, int, int],
        directory_mode: int,
        directory_nlink: int,
        directory_created: bool,
    ) -> None:
        self.unit = unit
        self.directory_name = directory_name
        self.directory_fd = directory_fd
        self.directory_identity = directory_identity
        self.directory_mode = directory_mode
        self.directory_nlink = directory_nlink
        self.directory_created = directory_created
        self.old_identity: tuple[int, int, int] | None = None
        self.temporary_name: str | None = None
        self.temporary_identity: tuple[int, int, int] | None = None
        self.backup_name: str | None = None
        self.published = False


def _device_allow_path(path: Path) -> str:
    value = str(path)
    if (
        not path.is_absolute()
        or not value.startswith("/dev/")
        or not value.isascii()
        or not value.isprintable()
        or any(character.isspace() for character in value)
        or "\\" in value
    ):
        raise RuntimeError
    return value


def render_dropins(settings: LinuxSettings) -> dict[str, str]:
    if type(settings) is not LinuxSettings:
        raise RuntimeError
    try:
        settings.validate()
        tape = _device_allow_path(settings.tape_device_path)
        scsi = _device_allow_path(settings.scsi_device_path)
    except (OSError, RuntimeError, ValidationError, ValueError, TypeError):
        raise RuntimeError from None
    common = f"DeviceAllow={tape} rw\nDeviceAllow={scsi} rw\n"
    return {
        "lto-archiver-archive-runner-qualification.service": (
            "[Service]\nDeviceAllow=\n" + common
        ),
        "lto-archiver-command-broker.service": (
            "[Service]\nDeviceAllow=\nDeviceAllow=/dev/fuse rw\n" + common
        ),
        "lto-archiver-ltfs-qualification.service": (
            # Linux SG authorizes READ ATTRIBUTE on an O_RDWR descriptor;
            # ltfs-info itself admits only its fixed read-only opcode set.
            f"[Service]\nDeviceAllow=\nDeviceAllow={scsi} rw\n"
        ),
        "lto-archiverd.service": "[Service]\nDeviceAllow=\n" + common,
    }


def _validate_character_device(path: Path) -> int:
    try:
        link = path.lstat()
        target = path.stat()
    except OSError:
        raise RuntimeError from None
    if (
        not stat.S_ISLNK(link.st_mode)
        or link.st_uid != 0
        or not stat.S_ISCHR(target.st_mode)
        or target.st_uid != 0
    ):
        raise RuntimeError
    return target.st_rdev


def _validate_host(settings: LinuxSettings) -> None:
    tape = _validate_character_device(settings.tape_device_path)
    scsi = _validate_character_device(settings.scsi_device_path)
    try:
        fuse = Path("/dev/fuse").stat(follow_symlinks=False)
        mount = settings.mount_path.stat(follow_symlinks=False)
        canonical_mount = settings.mount_path.resolve(strict=True)
    except OSError:
        raise RuntimeError from None
    if (
        tape == scsi
        or not stat.S_ISCHR(fuse.st_mode)
        or fuse.st_uid != 0
        or not stat.S_ISDIR(mount.st_mode)
        or settings.mount_path != canonical_mount
        or mount.st_mode & stat.S_IWOTH
    ):
        raise RuntimeError


def _write_all(fd: int, payload: bytes) -> None:
    written = 0
    while written < len(payload):
        count = os.write(fd, payload[written:])
        if count <= 0:
            raise RuntimeError
        written += count


def _open_owned_directory(
    path: Path | str,
    *,
    dir_fd: int | None = None,
    expected_uid: int,
    expected_gid: int,
) -> int:
    fd = -1
    try:
        fd = os.open(path, _DIRECTORY_FLAGS, dir_fd=dir_fd)
        status = os.fstat(fd)
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != expected_uid
            or status.st_gid != expected_gid
            or stat.S_IMODE(status.st_mode) & 0o022
        ):
            raise RuntimeError
        return fd
    except (OSError, RuntimeError):
        if fd >= 0:
            os.close(fd)
        raise RuntimeError from None


def _identity(status: os.stat_result) -> tuple[int, int, int]:
    return status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode)


def _entry_status(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _same_identity(
    status: os.stat_result | None,
    expected: tuple[int, int, int] | None,
) -> bool:
    return status is not None and expected is not None and _identity(status) == expected


def _validate_dropin_status(
    status: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_nlink: int,
) -> None:
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_uid != expected_uid
        or status.st_gid != expected_gid
        or stat.S_IMODE(status.st_mode) != 0o644
        or status.st_nlink != expected_nlink
    ):
        raise RuntimeError


def _root_directory_seal(
    status: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        *_identity(status),
        status.st_uid,
        status.st_gid,
        stat.S_IMODE(status.st_mode),
        status.st_nlink,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _validate_live_directory(
    root_fd: int,
    prepared: _PreparedDropin,
    root_seal: tuple[int, int, int, int, int, int, int, int, int],
    *,
    expected_uid: int,
    expected_gid: int,
    require_root_seal: bool = True,
) -> None:
    if require_root_seal and _root_directory_seal(os.fstat(root_fd)) != root_seal:
        raise RuntimeError

    def validate(status: os.stat_result) -> None:
        if (
            not stat.S_ISDIR(status.st_mode)
            or _identity(status) != prepared.directory_identity
            or status.st_uid != expected_uid
            or status.st_gid != expected_gid
            or stat.S_IMODE(status.st_mode) != prepared.directory_mode
            or status.st_nlink != prepared.directory_nlink
        ):
            raise RuntimeError

    validate(os.fstat(prepared.directory_fd))
    validate(
        os.stat(
            prepared.directory_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    )
    reopened = os.open(prepared.directory_name, _DIRECTORY_FLAGS, dir_fd=root_fd)
    try:
        validate(os.fstat(reopened))
    finally:
        os.close(reopened)
    validate(
        os.stat(
            prepared.directory_name,
            dir_fd=root_fd,
            follow_symlinks=False,
        )
    )
    if require_root_seal and _root_directory_seal(os.fstat(root_fd)) != root_seal:
        raise RuntimeError


def _open_transaction_directory(
    root_fd: int,
    unit: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> _PreparedDropin:
    directory_name = f"{unit}.d"
    created = False
    try:
        os.mkdir(directory_name, mode=0o755, dir_fd=root_fd)
        created = True
        os.fsync(root_fd)
    except FileExistsError:
        pass
    try:
        directory_fd = _open_owned_directory(
            directory_name,
            dir_fd=root_fd,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    except BaseException:
        if created:
            with contextlib.suppress(OSError):
                os.rmdir(directory_name, dir_fd=root_fd)
                os.fsync(root_fd)
        raise
    directory_status = os.fstat(directory_fd)
    return _PreparedDropin(
        unit=unit,
        directory_name=directory_name,
        directory_fd=directory_fd,
        directory_identity=_identity(directory_status),
        directory_mode=stat.S_IMODE(directory_status.st_mode),
        directory_nlink=directory_status.st_nlink,
        directory_created=created,
    )


def _prepare_dropin(
    root_fd: int,
    prepared: _PreparedDropin,
    payload: bytes,
    root_seal: tuple[int, int, int, int, int, int, int, int, int],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    directory_fd = prepared.directory_fd
    _validate_live_directory(
        root_fd,
        prepared,
        root_seal,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    existing = _entry_status(directory_fd, _DROPIN_NAME)
    if existing is not None:
        _validate_dropin_status(
            existing,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_nlink=1,
        )
        existing_fd = os.open(_DROPIN_NAME, _REGULAR_FLAGS, dir_fd=directory_fd)
        try:
            opened = os.fstat(existing_fd)
            _validate_dropin_status(
                opened,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                expected_nlink=1,
            )
            if _identity(opened) != _identity(existing):
                raise RuntimeError
            prepared.old_identity = _identity(opened)
        finally:
            os.close(existing_fd)
        _validate_live_directory(
            root_fd,
            prepared,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )

    temporary = f".lto-device-policy.new.{os.getpid()}.{secrets.token_hex(8)}"
    file_fd = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=directory_fd,
    )
    prepared.temporary_name = temporary
    prepared.temporary_identity = _identity(os.fstat(file_fd))
    try:
        _write_all(file_fd, payload)
        os.fchmod(file_fd, 0o644)
        os.fsync(file_fd)
        staged = os.fstat(file_fd)
        _validate_dropin_status(
            staged,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_nlink=1,
        )
        if _identity(staged) != prepared.temporary_identity:
            raise RuntimeError
    finally:
        os.close(file_fd)
    if not _same_identity(
        _entry_status(directory_fd, temporary), prepared.temporary_identity
    ):
        raise RuntimeError

    if prepared.old_identity is not None:
        backup = f".lto-device-policy.old.{os.getpid()}.{secrets.token_hex(8)}"
        _validate_live_directory(
            root_fd,
            prepared,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        os.link(
            _DROPIN_NAME,
            backup,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        prepared.backup_name = backup
        if not _same_identity(
            _entry_status(directory_fd, backup), prepared.old_identity
        ) or not _same_identity(
            _entry_status(directory_fd, _DROPIN_NAME), prepared.old_identity
        ):
            raise RuntimeError
        _validate_live_directory(
            root_fd,
            prepared,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    _validate_live_directory(
        root_fd,
        prepared,
        root_seal,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    os.fsync(directory_fd)
    _validate_live_directory(
        root_fd,
        prepared,
        root_seal,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def _unlink_identity_bound(
    directory_fd: int,
    name: str | None,
    expected: tuple[int, int, int] | None,
) -> None:
    if name is None:
        return
    current = _entry_status(directory_fd, name)
    if current is None:
        return
    if not _same_identity(current, expected):
        raise RuntimeError
    os.unlink(name, dir_fd=directory_fd)


def _rollback_dropin(
    root_fd: int,
    prepared: _PreparedDropin,
    root_seal: tuple[int, int, int, int, int, int, int, int, int],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if not prepared.published:
        return
    _validate_live_directory(
        root_fd,
        prepared,
        root_seal,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        require_root_seal=False,
    )
    current = _entry_status(prepared.directory_fd, _DROPIN_NAME)
    if not _same_identity(current, prepared.temporary_identity):
        raise RuntimeError
    if prepared.old_identity is None:
        os.unlink(_DROPIN_NAME, dir_fd=prepared.directory_fd)
    else:
        if not _same_identity(
            _entry_status(prepared.directory_fd, prepared.backup_name or ""),
            prepared.old_identity,
        ):
            raise RuntimeError
        os.replace(
            prepared.backup_name,
            _DROPIN_NAME,
            src_dir_fd=prepared.directory_fd,
            dst_dir_fd=prepared.directory_fd,
        )
        prepared.backup_name = None
        if not _same_identity(
            _entry_status(prepared.directory_fd, _DROPIN_NAME),
            prepared.old_identity,
        ):
            raise RuntimeError
    prepared.published = False
    _validate_live_directory(
        root_fd,
        prepared,
        root_seal,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        require_root_seal=False,
    )
    os.fsync(prepared.directory_fd)
    _validate_live_directory(
        root_fd,
        prepared,
        root_seal,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        require_root_seal=False,
    )


def _cleanup_dropin(prepared: _PreparedDropin) -> None:
    _unlink_identity_bound(
        prepared.directory_fd,
        prepared.temporary_name,
        prepared.temporary_identity,
    )
    prepared.temporary_name = None
    _unlink_identity_bound(
        prepared.directory_fd,
        prepared.backup_name,
        prepared.old_identity,
    )
    prepared.backup_name = None


def _remove_created_directory(root_fd: int, prepared: _PreparedDropin) -> None:
    if not prepared.directory_created:
        return
    current = _entry_status(root_fd, prepared.directory_name)
    if current is None:
        return
    if (
        not stat.S_ISDIR(current.st_mode)
        or _identity(current) != prepared.directory_identity
    ):
        raise RuntimeError
    os.rmdir(prepared.directory_name, dir_fd=root_fd)
    os.fsync(root_fd)


def _validate_write_arguments(
    rendered: Mapping[str, str],
    systemd_directory: Path,
    expected_uid: int,
    expected_gid: int,
) -> dict[str, bytes]:
    if (
        not isinstance(rendered, Mapping)
        or set(rendered) != _UNITS
        or any(type(value) is not str for value in rendered.values())
        or not isinstance(systemd_directory, Path)
        or not systemd_directory.is_absolute()
        or type(expected_uid) is not int
        or type(expected_gid) is not int
        or expected_uid < 0
        or expected_gid < 0
    ):
        raise RuntimeError
    try:
        return {
            unit: rendered[unit].encode("ascii", errors="strict")
            for unit in sorted(_UNITS)
        }
    except (UnicodeError, ValueError, TypeError):
        raise RuntimeError from None


def _validate_all_live(
    root_fd: int,
    prepared_dropins: list[_PreparedDropin],
    root_seal: tuple[int, int, int, int, int, int, int, int, int],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    for prepared in prepared_dropins:
        _validate_live_directory(
            root_fd,
            prepared,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )


def write_dropins(
    rendered: Mapping[str, str],
    systemd_directory: Path = _SYSTEMD_DIRECTORY,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> tuple[Path, ...]:
    payloads = _validate_write_arguments(
        rendered, systemd_directory, expected_uid, expected_gid
    )
    root_fd = _open_owned_directory(
        systemd_directory,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    prepared_dropins: list[_PreparedDropin] = []
    root_seal: tuple[int, int, int, int, int, int, int, int, int] | None = None
    committed = False
    try:
        for unit in sorted(_UNITS):
            prepared_dropins.append(
                _open_transaction_directory(
                    root_fd,
                    unit,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
            )
        root_seal = _root_directory_seal(os.fstat(root_fd))
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        for prepared in prepared_dropins:
            _prepare_dropin(
                root_fd,
                prepared,
                payloads[prepared.unit],
                root_seal,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        os.fsync(root_fd)
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )

        for prepared in prepared_dropins:
            _validate_live_directory(
                root_fd,
                prepared,
                root_seal,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            current = _entry_status(prepared.directory_fd, _DROPIN_NAME)
            if prepared.old_identity is None:
                if current is not None:
                    raise RuntimeError
            elif not _same_identity(current, prepared.old_identity):
                raise RuntimeError
            os.replace(
                prepared.temporary_name,
                _DROPIN_NAME,
                src_dir_fd=prepared.directory_fd,
                dst_dir_fd=prepared.directory_fd,
            )
            prepared.temporary_name = None
            prepared.published = True
            if not _same_identity(
                _entry_status(prepared.directory_fd, _DROPIN_NAME),
                prepared.temporary_identity,
            ):
                raise RuntimeError
            _validate_live_directory(
                root_fd,
                prepared,
                root_seal,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            os.fsync(prepared.directory_fd)
            _validate_live_directory(
                root_fd,
                prepared,
                root_seal,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        os.fsync(root_fd)
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        committed = True

        for prepared in prepared_dropins:
            _cleanup_dropin(prepared)
        for prepared in prepared_dropins:
            os.fsync(prepared.directory_fd)
            _validate_live_directory(
                root_fd,
                prepared,
                root_seal,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        os.fsync(root_fd)
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    except (OSError, RuntimeError, UnicodeError, ValueError, TypeError) as error:
        cleanup_errors: list[BaseException] = []
        if not committed and root_seal is not None:
            for prepared in reversed(prepared_dropins):
                try:
                    _rollback_dropin(
                        root_fd,
                        prepared,
                        root_seal,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                    )
                except (OSError, RuntimeError) as rollback_error:
                    cleanup_errors.append(rollback_error)
        for prepared in prepared_dropins:
            try:
                _cleanup_dropin(prepared)
            except (OSError, RuntimeError) as cleanup_error:
                cleanup_errors.append(cleanup_error)
        for prepared in reversed(prepared_dropins):
            try:
                if root_seal is not None:
                    _validate_live_directory(
                        root_fd,
                        prepared,
                        root_seal,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                        require_root_seal=False,
                    )
                os.fsync(prepared.directory_fd)
                if root_seal is not None:
                    _validate_live_directory(
                        root_fd,
                        prepared,
                        root_seal,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                        require_root_seal=False,
                    )
                if not committed:
                    _remove_created_directory(root_fd, prepared)
            except (OSError, RuntimeError) as cleanup_error:
                cleanup_errors.append(cleanup_error)
        with contextlib.suppress(OSError):
            os.fsync(root_fd)
        if cleanup_errors:
            raise PublicationDurabilityError from cleanup_errors[0]
        raise RuntimeError from error
    finally:
        for prepared in prepared_dropins:
            os.close(prepared.directory_fd)
        os.close(root_fd)
    return tuple(
        systemd_directory / f"{unit}.d" / _DROPIN_NAME for unit in sorted(_UNITS)
    )


def _read_dropin(
    directory_fd: int,
    *,
    expected_uid: int,
    expected_gid: int,
) -> bytes:
    opened = os.open(_DROPIN_NAME, _REGULAR_FLAGS, dir_fd=directory_fd)
    try:
        status = os.fstat(opened)
        _validate_dropin_status(
            status,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_nlink=1,
        )
        chunks: list[bytes] = []
        while True:
            chunk = os.read(opened, 4096)
            if not chunk:
                break
            chunks.append(chunk)
        if not _same_identity(
            _entry_status(directory_fd, _DROPIN_NAME), _identity(status)
        ):
            raise RuntimeError
        return b"".join(chunks)
    finally:
        os.close(opened)


def verify_dropins(
    rendered: Mapping[str, str],
    systemd_directory: Path = _SYSTEMD_DIRECTORY,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> tuple[Path, ...]:
    payloads = _validate_write_arguments(
        rendered, systemd_directory, expected_uid, expected_gid
    )
    root_fd = _open_owned_directory(
        systemd_directory,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    root_seal = _root_directory_seal(os.fstat(root_fd))
    prepared_dropins: list[_PreparedDropin] = []
    try:
        for unit in sorted(_UNITS):
            directory_fd = _open_owned_directory(
                f"{unit}.d",
                dir_fd=root_fd,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            directory_status = os.fstat(directory_fd)
            prepared_dropins.append(
                _PreparedDropin(
                    unit=unit,
                    directory_name=f"{unit}.d",
                    directory_fd=directory_fd,
                    directory_identity=_identity(directory_status),
                    directory_mode=stat.S_IMODE(directory_status.st_mode),
                    directory_nlink=directory_status.st_nlink,
                    directory_created=False,
                )
            )
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        for prepared in prepared_dropins:
            _validate_live_directory(
                root_fd,
                prepared,
                root_seal,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            try:
                if any(
                    entry.name.startswith(".lto-device-policy.")
                    for entry in os.scandir(prepared.directory_fd)
                ):
                    raise RuntimeError
                if (
                    _read_dropin(
                        prepared.directory_fd,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                    )
                    != payloads[prepared.unit]
                ):
                    raise RuntimeError
            finally:
                _validate_live_directory(
                    root_fd,
                    prepared,
                    root_seal,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
        _validate_all_live(
            root_fd,
            prepared_dropins,
            root_seal,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    except (OSError, RuntimeError):
        raise RuntimeError from None
    finally:
        for prepared in prepared_dropins:
            os.close(prepared.directory_fd)
        os.close(root_fd)
    return tuple(
        systemd_directory / f"{unit}.d" / _DROPIN_NAME for unit in sorted(_UNITS)
    )


def configure(
    config: Path,
    systemd_directory: Path = _SYSTEMD_DIRECTORY,
) -> tuple[Path, ...]:
    if os.geteuid() != 0:
        raise RuntimeError
    settings = load_linux_settings(config)
    _validate_host(settings)
    return write_dropins(render_dropins(settings), systemd_directory)


def verify_configuration(
    config: Path,
    systemd_directory: Path = _SYSTEMD_DIRECTORY,
) -> tuple[Path, ...]:
    settings = load_linux_settings(config)
    _validate_host(settings)
    return verify_dropins(render_dropins(settings), systemd_directory)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/lto-archiver/config.toml"),
    )
    parser.add_argument("--systemd-directory", type=Path, default=_SYSTEMD_DIRECTORY)
    parser.add_argument("--verify-only", action="store_true")
    try:
        args = parser.parse_args(argv)
        if args.verify_only:
            verify_configuration(args.config, args.systemd_directory)
        else:
            configure(args.config, args.systemd_directory)
        return 0
    except (OSError, RuntimeError, ValidationError, ValueError, TypeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("device policy configuration failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
