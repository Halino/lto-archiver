from __future__ import annotations

import argparse
import contextlib
import os
import pwd
import socket
import threading
from collections.abc import Mapping

_SYSTEMD_LISTEN_FD = 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lto-archiver-log-reader", allow_abbrev=False)
    parser.add_argument("--socket-fd", type=_socket_fd, default=_SYSTEMD_LISTEN_FD)
    return parser


def activated_listener(
    fd: int,
    environ: Mapping[str, str] | None = None,
) -> socket.socket:
    """Duplicate and verify the one systemd-activated Unix stream listener."""

    environment = os.environ if environ is None else environ
    if (
        type(fd) is not int
        or fd != _SYSTEMD_LISTEN_FD
        or not isinstance(environment, Mapping)
        or environment.get("LISTEN_PID") != str(os.getpid())
        or environment.get("LISTEN_FDS") != "1"
        or environment.get("LISTEN_FDNAMES") != "log-reader"
    ):
        raise RuntimeError("journal reader activation unavailable")
    duplicate: int | None = None
    listener: socket.socket | None = None
    try:
        duplicate = os.dup(fd)
        os.set_inheritable(duplicate, False)
        listener = socket.socket(fileno=duplicate)
        duplicate = None
        if (
            listener.family != socket.AF_UNIX
            or listener.type & 0xF != socket.SOCK_STREAM
            or listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 1
        ):
            raise RuntimeError("journal reader activation unavailable")
        result = listener
        listener = None
        return result
    except (OSError, TypeError, ValueError):
        raise RuntimeError("journal reader activation unavailable") from None
    finally:
        if listener is not None:
            listener.close()
        if duplicate is not None:
            with contextlib.suppress(OSError):
                os.close(duplicate)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if os.geteuid() != 0:
        raise RuntimeError("journal reader runtime unavailable")
    try:
        from .service import JournalReaderService

        daemon = pwd.getpwnam("lto-archiver")
        service = JournalReaderService(
            daemon_uid=daemon.pw_uid, daemon_gid=daemon.pw_gid
        )
        with activated_listener(args.socket_fd) as listener:
            listener.settimeout(1.0)
            service.serve(listener, threading.Event())
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        raise RuntimeError("journal reader runtime unavailable") from None
    return 0


def _socket_fd(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "socket descriptor must be non-negative"
        ) from exc
    if result != _SYSTEMD_LISTEN_FD:
        raise argparse.ArgumentTypeError("socket descriptor must be 3")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
