from __future__ import annotations

import contextlib
import os
import socket
import stat
from collections.abc import Mapping
from pathlib import Path


def _pathname_identity(
    status: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_ctime_ns,
    )


def activated_unix_listener(
    fd: int,
    environ: Mapping[str, str],
    *,
    socket_type: int,
    fd_name: str,
    expected_uid: int,
    expected_gid: int,
    expected_mode: int,
    expected_path: Path,
) -> socket.socket:
    """Duplicate and validate the one named systemd Unix listener."""

    if (
        type(fd) is not int
        or fd < 0
        or not isinstance(environ, Mapping)
        or environ.get("LISTEN_PID") != str(os.getpid())
        or environ.get("LISTEN_FDS") != "1"
        or environ.get("LISTEN_FDNAMES") != fd_name
        or socket_type not in (socket.SOCK_STREAM, socket.SOCK_SEQPACKET)
        or type(expected_uid) is not int
        or type(expected_gid) is not int
        or min(expected_uid, expected_gid) < 0
        or type(expected_mode) is not int
        or not 0 <= expected_mode <= 0o777
        or not isinstance(expected_path, Path)
        or not expected_path.is_absolute()
        or "\0" in str(expected_path)
    ):
        raise RuntimeError("systemd socket activation unavailable")

    duplicate: int | None = None
    listener: socket.socket | None = None
    try:
        duplicate = os.dup(fd)
        os.set_inheritable(duplicate, False)
        listener = socket.socket(fileno=duplicate)
        duplicate = None
        path = listener.getsockname()
        descriptor_status = os.fstat(listener.fileno())
        path_status_before = os.lstat(path)
        if (
            listener.family != socket.AF_UNIX
            or listener.type & 0xF != socket_type
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
            or type(path) is not str
            or not path.startswith("/")
            or "\0" in path
            or path != str(expected_path)
            or not stat.S_ISSOCK(descriptor_status.st_mode)
            or not stat.S_ISSOCK(path_status_before.st_mode)
            or path_status_before.st_uid != expected_uid
            or path_status_before.st_gid != expected_gid
            or stat.S_IMODE(path_status_before.st_mode) != expected_mode
        ):
            raise RuntimeError("systemd socket activation unavailable")
        path_status_after = os.lstat(path)
        if _pathname_identity(path_status_before) != _pathname_identity(
            path_status_after
        ):
            raise RuntimeError("systemd socket activation unavailable")
        result = listener
        listener = None
        return result
    except (OSError, TypeError, ValueError):
        raise RuntimeError("systemd socket activation unavailable") from None
    finally:
        if listener is not None:
            listener.close()
        if duplicate is not None:
            with contextlib.suppress(OSError):
                os.close(duplicate)
