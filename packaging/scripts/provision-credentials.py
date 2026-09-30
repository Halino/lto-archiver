#!/usr/bin/python3.11
from __future__ import annotations

import argparse
import contextlib
import os
import secrets
import stat
import sys
from pathlib import Path

NAMES = (
    "broker-capability",
    "broker-proof-key",
    "qualification-credential",
    "share-broker-capability",
    "share-broker-proof-key",
    "share-store-request-key",
    "share-request-key",
)


def _read_valid(
    directory_fd: int,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> bytes | None:
    fd: int | None = None
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd
        )
    except FileNotFoundError:
        return None
    try:
        status = os.fstat(fd)
        path_status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        value = os.read(fd, 33)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o400
            or status.st_uid != expected_uid
            or status.st_gid != expected_gid
            or status.st_nlink != 1
            or (status.st_dev, status.st_ino)
            != (path_status.st_dev, path_status.st_ino)
            or len(value) != 32
            or os.read(fd, 1)
        ):
            raise RuntimeError
        return value
    finally:
        if fd is not None:
            os.close(fd)


def _create(
    directory_fd: int,
    name: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> bytes:
    value = secrets.token_bytes(32)
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
        dir_fd=directory_fd,
    )
    succeeded = False
    try:
        status = os.fstat(fd)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o400
            or status.st_uid != expected_uid
            or status.st_gid != expected_gid
            or status.st_nlink != 1
        ):
            raise RuntimeError
        written = 0
        while written < len(value):
            count = os.write(fd, value[written:])
            if count <= 0:
                raise RuntimeError
            written += count
        os.fsync(fd)
        succeeded = True
    finally:
        os.close(fd)
        if not succeeded:
            with contextlib.suppress(OSError):
                os.unlink(name, dir_fd=directory_fd)
    return value


def provision(
    directory: Path,
    *,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    if not directory.is_absolute():
        raise RuntimeError
    if type(expected_uid) is not int or type(expected_gid) is not int:
        raise RuntimeError
    if expected_uid < 0 or expected_gid < 0:
        raise RuntimeError
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_fd = os.open(
        directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        status = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o700
            or status.st_uid != expected_uid
            or status.st_gid != expected_gid
        ):
            raise RuntimeError
        values = {
            name: _read_valid(
                directory_fd,
                name,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            for name in NAMES
        }
        for name in NAMES:
            if values[name] is None:
                values[name] = _create(
                    directory_fd,
                    name,
                    expected_uid=expected_uid,
                    expected_gid=expected_gid,
                )
        os.fsync(directory_fd)
        provisioned = tuple(values[name] for name in NAMES)
        if any(value is None for value in provisioned) or len(set(provisioned)) != len(
            provisioned
        ):
            raise RuntimeError
    finally:
        os.close(directory_fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--directory",
        type=Path,
        default=Path("/etc/lto-archiver/credentials"),
    )
    try:
        args = parser.parse_args(argv)
        provision(args.directory)
        return 0
    except (OSError, RuntimeError, ValueError, TypeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("credential provisioning failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
