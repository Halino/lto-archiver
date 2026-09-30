"""Publish a verified RPM tree through anchored Linux directory descriptors."""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import errno
import hashlib
import os
import secrets
import stat
import sys
from pathlib import Path

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_REGULAR_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_RENAME_NOREPLACE = 1
_MANIFEST_NAME = "SHA256SUMS"
_MANIFEST_TOP_LEVEL = frozenset(
    {"RPMS", "SRPMS", "SOURCES", "SPECS", "VERIFICATION", "DEPLOY"}
)
_MAIN_OPTIONAL_PAYLOAD = frozenset(
    {
        ("VERIFICATION", "main-rpm.json"),
        ("VERIFICATION", "packaging-gate.json"),
        ("VERIFICATION", "packaging-gate.json.asc"),
        ("DEPLOY", "main-rpm-contract.json"),
        ("DEPLOY", "verify-main-rpm.py"),
    }
)
_SealedIdentity = tuple[int, int, int, int, int, int, int, int, int]


class PublicationDurabilityError(RuntimeError):
    """Publication or rollback durability could not be established."""


def _identity(status: os.stat_result) -> tuple[int, int, int]:
    return status.st_dev, status.st_ino, stat.S_IFMT(status.st_mode)


def _same_directory(status: os.stat_result, expected: tuple[int, int, int]) -> bool:
    return stat.S_ISDIR(status.st_mode) and _identity(status) == expected


def _sealed_identity(
    status: os.stat_result,
) -> _SealedIdentity:
    return (
        status.st_dev,
        status.st_ino,
        stat.S_IFMT(status.st_mode),
        status.st_uid,
        stat.S_IMODE(status.st_mode),
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
        status.st_nlink,
    )


def _open_output_parent(
    output_argument: str, *, create_parents: bool
) -> tuple[int, str]:
    if not output_argument or "\0" in output_argument:
        raise RuntimeError
    path = Path(output_argument)
    if path.name in ("", ".", "..") or any(
        component == ".." for component in path.parts
    ):
        raise RuntimeError
    if path.is_absolute():
        current = os.open("/", _DIRECTORY_FLAGS)
        components = path.parts[1:-1]
    else:
        current = os.open(".", _DIRECTORY_FLAGS)
        components = path.parts[:-1]
    try:
        for component in components:
            if component in ("", "."):
                continue
            try:
                following = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create_parents:
                    raise
                try:
                    os.mkdir(component, 0o755, dir_fd=current)
                except FileExistsError:
                    pass
                else:
                    os.fsync(current)
                following = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            os.close(current)
            current = following
        return current, path.name
    except BaseException:
        os.close(current)
        raise


def _entry_status(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _require_absent(directory_fd: int, name: str) -> None:
    if _entry_status(directory_fd, name) is not None:
        raise FileExistsError(errno.EEXIST, "output exists")


def _open_directory_at(directory_fd: int, name: str) -> int:
    opened = os.open(name, _DIRECTORY_FLAGS, dir_fd=directory_fd)
    status = os.fstat(opened)
    if not stat.S_ISDIR(status.st_mode):
        os.close(opened)
        raise RuntimeError
    return opened


def _create_directory_at(directory_fd: int, name: str, mode: int) -> int:
    os.mkdir(name, mode, dir_fd=directory_fd)
    opened: int | None = None
    created_identity: tuple[int, int, int] | None = None
    try:
        opened = _open_directory_at(directory_fd, name)
        created_identity = _identity(os.fstat(opened))
        os.fchmod(opened, mode)
        os.fsync(opened)
        os.fsync(directory_fd)
        pathname_status = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not _same_directory(pathname_status, created_identity):
            raise RuntimeError
        result = opened
        opened = None
        return result
    except BaseException:
        if created_identity is not None:
            current = _entry_status(directory_fd, name)
            if current is not None and _same_directory(current, created_identity):
                with contextlib.suppress(OSError):
                    os.rmdir(name, dir_fd=directory_fd)
                with contextlib.suppress(OSError):
                    os.fsync(directory_fd)
        raise
    finally:
        if opened is not None:
            os.close(opened)


def _create_staging_container(
    parent_fd: int, output_name: str
) -> tuple[str, int, tuple[int, int, int]]:
    prefix = f".{output_name[:64]}.staging."
    for _ in range(128):
        name = prefix + secrets.token_hex(12)
        try:
            opened = _create_directory_at(parent_fd, name, 0o700)
        except FileExistsError:
            continue
        return name, opened, _identity(os.fstat(opened))
    raise RuntimeError


def _open_regular_beneath(root_fd: int, components: tuple[str, ...]) -> int:
    if not components or any(component in ("", ".", "..") for component in components):
        raise RuntimeError
    current = os.dup(root_fd)
    try:
        for component in components[:-1]:
            following = _open_directory_at(current, component)
            os.close(current)
            current = following
        opened = os.open(components[-1], _REGULAR_READ_FLAGS, dir_fd=current)
        status = os.fstat(opened)
        pathname_status = os.stat(components[-1], dir_fd=current, follow_symlinks=False)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or _identity(status) != _identity(pathname_status)
        ):
            os.close(opened)
            raise RuntimeError
        return opened
    finally:
        os.close(current)


def _open_artifacts(root_fd: int) -> dict[tuple[str, ...], int]:
    artifacts: dict[tuple[str, ...], int] = {}

    def visit(directory_fd: int, prefix: tuple[str, ...]) -> None:
        for entry in sorted(os.scandir(directory_fd), key=lambda item: item.name):
            if entry.name in ("", ".", ".."):
                raise RuntimeError
            status = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            relative = (*prefix, entry.name)
            if stat.S_ISDIR(status.st_mode):
                child_fd = _open_directory_at(directory_fd, entry.name)
                try:
                    visit(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif entry.name.endswith(".rpm"):
                opened = os.open(entry.name, _REGULAR_READ_FLAGS, dir_fd=directory_fd)
                opened_status = os.fstat(opened)
                if (
                    not stat.S_ISREG(opened_status.st_mode)
                    or _identity(opened_status) != _identity(status)
                    or opened_status.st_nlink != 1
                ):
                    os.close(opened)
                    raise RuntimeError
                artifacts[relative] = opened

    try:
        for top_level in ("RPMS", "SRPMS"):
            directory_fd = _open_directory_at(root_fd, top_level)
            try:
                visit(directory_fd, (top_level,))
            finally:
                os.close(directory_fd)
        if not artifacts:
            raise RuntimeError
        return artifacts
    except BaseException:
        for descriptor in artifacts.values():
            os.close(descriptor)
        raise


def _open_build_payload(
    root_fd: int, source_archive: str, spec_name: str
) -> dict[tuple[str, ...], int]:
    payload: dict[tuple[str, ...], int] = {}
    try:
        payload[("SOURCES", source_archive)] = _open_regular_beneath(
            root_fd, ("SOURCES", source_archive)
        )
        payload[("SPECS", spec_name)] = _open_regular_beneath(
            root_fd, ("SPECS", spec_name)
        )
        if spec_name == "lto-archiver-python-runtime.spec":
            for name in (
                f"{source_archive}.sha256",
                "runtime_install.py",
                "runtime-payload-authority.json",
            ):
                payload[("SOURCES", name)] = _open_regular_beneath(
                    root_fd, ("SOURCES", name)
                )
        payload.update(_open_artifacts(root_fd))
        optional_present = any(
            _entry_status(root_fd, directory) is not None
            for directory in ("VERIFICATION", "DEPLOY")
        )
        if optional_present:
            for relative in sorted(_MAIN_OPTIONAL_PAYLOAD):
                payload[relative] = _open_regular_beneath(root_fd, relative)
        return payload
    except BaseException:
        for descriptor in payload.values():
            os.close(descriptor)
        raise


def _open_or_create_directory_path(root_fd: int, components: tuple[str, ...]) -> int:
    current = os.dup(root_fd)
    try:
        for component in components:
            if component in ("", ".", ".."):
                raise RuntimeError
            try:
                os.mkdir(component, 0o755, dir_fd=current)
            except FileExistsError:
                pass
            else:
                os.fsync(current)
            following = _open_directory_at(current, component)
            os.close(current)
            current = following
        result = current
        current = -1
        return result
    finally:
        if current >= 0:
            os.close(current)


def _copy_regular(
    source_fd: int,
    destination_root_fd: int,
    destination_components: tuple[str, ...],
) -> tuple[int, _SealedIdentity]:
    destination_parent_fd = _open_or_create_directory_path(
        destination_root_fd, destination_components[:-1]
    )
    destination_fd: int | None = None
    pinned_fd: int | None = None
    sealed: _SealedIdentity | None = None
    succeeded = False
    try:
        os.lseek(source_fd, 0, os.SEEK_SET)
        destination_fd = os.open(
            destination_components[-1],
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=destination_parent_fd,
        )
        while True:
            chunk = os.read(source_fd, 1024 * 1024)
            if not chunk:
                break
            offset = 0
            while offset < len(chunk):
                written = os.write(destination_fd, chunk[offset:])
                if written <= 0:
                    raise RuntimeError
                offset += written
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
        pinned_fd = os.open(
            destination_components[-1],
            _REGULAR_READ_FLAGS,
            dir_fd=destination_parent_fd,
        )
        pinned_status = os.fstat(pinned_fd)
        pathname_status = os.stat(
            destination_components[-1],
            dir_fd=destination_parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(pinned_status.st_mode)
            or pinned_status.st_nlink != 1
            or pinned_status.st_uid != os.getuid()
            or stat.S_IMODE(pinned_status.st_mode) != 0o444
            or _sealed_identity(pinned_status) != _sealed_identity(pathname_status)
        ):
            raise RuntimeError
        sealed = _sealed_identity(pinned_status)
        os.fsync(destination_parent_fd)
        succeeded = True
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        if not succeeded and pinned_fd is not None:
            os.close(pinned_fd)
        if not succeeded:
            with contextlib.suppress(OSError):
                os.unlink(destination_components[-1], dir_fd=destination_parent_fd)
                os.fsync(destination_parent_fd)
        os.close(destination_parent_fd)
    if pinned_fd is None or sealed is None:
        raise RuntimeError
    return pinned_fd, sealed


def _create_regular_bytes(
    destination_root_fd: int,
    destination_components: tuple[str, ...],
    content: bytes,
) -> tuple[int, _SealedIdentity]:
    destination_parent_fd = _open_or_create_directory_path(
        destination_root_fd, destination_components[:-1]
    )
    destination_fd: int | None = None
    pinned_fd: int | None = None
    sealed: _SealedIdentity | None = None
    succeeded = False
    try:
        destination_fd = os.open(
            destination_components[-1],
            os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o400,
            dir_fd=destination_parent_fd,
        )
        offset = 0
        while offset < len(content):
            written = os.write(destination_fd, content[offset:])
            if written <= 0:
                raise RuntimeError
            offset += written
        os.fchmod(destination_fd, 0o444)
        os.fsync(destination_fd)
        pinned_fd = os.open(
            destination_components[-1],
            _REGULAR_READ_FLAGS,
            dir_fd=destination_parent_fd,
        )
        pinned_status = os.fstat(pinned_fd)
        pathname_status = os.stat(
            destination_components[-1],
            dir_fd=destination_parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(pinned_status.st_mode)
            or pinned_status.st_nlink != 1
            or pinned_status.st_uid != os.getuid()
            or stat.S_IMODE(pinned_status.st_mode) != 0o444
            or _sealed_identity(pinned_status) != _sealed_identity(pathname_status)
        ):
            raise RuntimeError
        sealed = _sealed_identity(pinned_status)
        os.fsync(destination_parent_fd)
        succeeded = True
    finally:
        if destination_fd is not None:
            os.close(destination_fd)
        if not succeeded and pinned_fd is not None:
            os.close(pinned_fd)
        if not succeeded:
            with contextlib.suppress(OSError):
                os.unlink(destination_components[-1], dir_fd=destination_parent_fd)
                os.fsync(destination_parent_fd)
        os.close(destination_parent_fd)
    if pinned_fd is None or sealed is None:
        raise RuntimeError
    return pinned_fd, sealed


def _manifest_bytes(digests: dict[tuple[str, ...], str]) -> bytes:
    rows: list[bytes] = []
    for components in sorted(digests, key=lambda item: b"/".join(os.fsencode(part) for part in item)):
        if (
            not components
            or components[0] not in _MANIFEST_TOP_LEVEL
            or any(part in ("", ".", "..") or "\\" in part for part in components)
            or components == (_MANIFEST_NAME,)
        ):
            raise RuntimeError
        relative = "/".join(components)
        digest = digests[components]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise RuntimeError
        rows.append(f"{digest}  {relative}\n".encode("ascii"))
    if not rows:
        raise RuntimeError
    return b"".join(rows)


def _verify_manifest(root_fd: int) -> dict[tuple[str, ...], str]:
    manifest_fd = _open_regular_beneath(root_fd, (_MANIFEST_NAME,))
    try:
        status = os.fstat(manifest_fd)
        if (
            status.st_nlink != 1
            or status.st_uid != os.getuid()
            or stat.S_IMODE(status.st_mode) != 0o444
            or status.st_size <= 0
            or status.st_size > 4 * 1024 * 1024
        ):
            raise RuntimeError
        content = bytearray()
        while True:
            chunk = os.read(manifest_fd, 64 * 1024)
            if not chunk:
                break
            content.extend(chunk)
    finally:
        os.close(manifest_fd)
    try:
        text = bytes(content).decode("ascii")
    except UnicodeDecodeError as error:
        raise RuntimeError from error
    if not text.endswith("\n") or "\r" in text:
        raise RuntimeError
    parsed: dict[tuple[str, ...], str] = {}
    previous_name: bytes | None = None
    for row in text.splitlines():
        if len(row) < 67 or row[64:66] != "  ":
            raise RuntimeError
        digest, relative = row[:64], row[66:]
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise RuntimeError
        if (
            not relative
            or relative.startswith("/")
            or "\\" in relative
            or relative == _MANIFEST_NAME
        ):
            raise RuntimeError
        components = tuple(relative.split("/"))
        if (
            components[0] not in _MANIFEST_TOP_LEVEL
            or any(part in ("", ".", "..") for part in components)
            or components in parsed
        ):
            raise RuntimeError
        encoded_name = relative.encode("ascii")
        if previous_name is not None and encoded_name <= previous_name:
            raise RuntimeError
        previous_name = encoded_name
        parsed[components] = digest
    for components, expected_digest in parsed.items():
        descriptor = _open_regular_beneath(root_fd, components)
        try:
            if _digest(descriptor) != expected_digest:
                raise RuntimeError
        finally:
            os.close(descriptor)
    return parsed


def _matching_digest(first_fd: int, second_fd: int) -> str | None:
    digest = hashlib.sha256()
    os.lseek(first_fd, 0, os.SEEK_SET)
    os.lseek(second_fd, 0, os.SEEK_SET)
    while True:
        first_chunk = os.read(first_fd, 1024 * 1024)
        second_chunk = os.read(second_fd, 1024 * 1024)
        if first_chunk != second_chunk:
            return None
        if not first_chunk:
            return digest.hexdigest()
        digest.update(first_chunk)


def _digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            return digest.hexdigest()
        digest.update(chunk)


def _verify_sealed_regular(
    root_fd: int,
    components: tuple[str, ...],
    pinned_fd: int,
    expected: _SealedIdentity,
) -> None:
    pinned_status = os.fstat(pinned_fd)
    if (
        not stat.S_ISREG(pinned_status.st_mode)
        or pinned_status.st_nlink != 1
        or pinned_status.st_uid != os.getuid()
        or stat.S_IMODE(pinned_status.st_mode) != 0o444
        or _sealed_identity(pinned_status) != expected
    ):
        raise RuntimeError
    reopened = _open_regular_beneath(root_fd, components)
    try:
        if _sealed_identity(os.fstat(reopened)) != expected:
            raise RuntimeError
    finally:
        os.close(reopened)


def _capture_payload_seals(
    payload: dict[tuple[str, ...], int],
) -> dict[tuple[str, ...], _SealedIdentity]:
    seals = {}
    for relative, descriptor in payload.items():
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise RuntimeError
        seals[relative] = _sealed_identity(status)
    return seals


def _verify_input_payload(
    root_fd: int,
    payload: dict[tuple[str, ...], int],
    seals: dict[tuple[str, ...], _SealedIdentity],
    digests: dict[tuple[str, ...], str],
) -> None:
    if payload.keys() != seals.keys() or payload.keys() != digests.keys():
        raise RuntimeError
    for relative, descriptor in payload.items():
        if (
            _sealed_identity(os.fstat(descriptor)) != seals[relative]
            or _digest(descriptor) != digests[relative]
        ):
            raise RuntimeError
        reopened = _open_regular_beneath(root_fd, relative)
        try:
            if _sealed_identity(os.fstat(reopened)) != seals[relative]:
                raise RuntimeError
        finally:
            os.close(reopened)


def _verify_staged_payload(
    root_fd: int,
    payload: dict[tuple[str, ...], int],
    seals: dict[tuple[str, ...], _SealedIdentity],
    digests: dict[tuple[str, ...], str],
) -> None:
    expected_files = set(payload)
    expected_directories = {
        (directory,)
        for directory in (
            "BUILD",
            "BUILDROOT",
            "RPMS",
            "SOURCES",
            "SPECS",
            "SRPMS",
        )
    }
    for relative in expected_files:
        expected_directories.update(
            relative[:length] for length in range(1, len(relative))
        )
    found_files: set[tuple[str, ...]] = set()
    found_directories: set[tuple[str, ...]] = set()

    def visit(directory_fd: int, prefix: tuple[str, ...]) -> None:
        for entry in sorted(os.scandir(directory_fd), key=lambda item: item.name):
            if entry.name in ("", ".", ".."):
                raise RuntimeError
            status = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
            relative = (*prefix, entry.name)
            if stat.S_ISDIR(status.st_mode):
                found_directories.add(relative)
                child_fd = _open_directory_at(directory_fd, entry.name)
                try:
                    visit(child_fd, relative)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(status.st_mode):
                found_files.add(relative)
            else:
                raise RuntimeError

    visit(root_fd, ())
    if (
        found_files != expected_files
        or found_directories != expected_directories
        or payload.keys() != seals.keys()
        or payload.keys() != digests.keys()
    ):
        raise RuntimeError
    for relative, descriptor in payload.items():
        if _digest(descriptor) != digests[relative]:
            raise RuntimeError
        _verify_sealed_regular(root_fd, relative, descriptor, seals[relative])


def _verify_artifact_set(root_fd: int, payload: dict[tuple[str, ...], int]) -> None:
    expected = {
        relative: _identity(os.fstat(descriptor))
        for relative, descriptor in payload.items()
        if relative[0] in ("RPMS", "SRPMS")
    }
    current = _open_artifacts(root_fd)
    try:
        if current.keys() != expected.keys() or any(
            _identity(os.fstat(descriptor)) != expected[relative]
            for relative, descriptor in current.items()
        ):
            raise RuntimeError
    finally:
        for descriptor in current.values():
            os.close(descriptor)


def _verify_optional_payload_set(
    root_fd: int, payload: dict[tuple[str, ...], int]
) -> None:
    expected = {
        relative
        for relative in payload
        if relative[0] in ("VERIFICATION", "DEPLOY")
    }
    if expected and expected != _MAIN_OPTIONAL_PAYLOAD:
        raise RuntimeError
    found: set[tuple[str, ...]] = set()
    for directory in ("VERIFICATION", "DEPLOY"):
        status = _entry_status(root_fd, directory)
        if status is None:
            if expected:
                raise RuntimeError
            continue
        directory_fd = _open_directory_at(root_fd, directory)
        try:
            for entry in os.scandir(directory_fd):
                entry_status = os.stat(
                    entry.name, dir_fd=directory_fd, follow_symlinks=False
                )
                if not stat.S_ISREG(entry_status.st_mode):
                    raise RuntimeError
                found.add((directory, entry.name))
        finally:
            os.close(directory_fd)
    if found != expected:
        raise RuntimeError


def _verify_source_state(
    root_path: Path,
    root_fd: int,
    root_identity: tuple[int, int, int],
    payload: dict[tuple[str, ...], int],
    seals: dict[tuple[str, ...], _SealedIdentity],
    digests: dict[tuple[str, ...], str],
) -> None:
    _verify_input_payload(root_fd, payload, seals, digests)
    _verify_artifact_set(root_fd, payload)
    _verify_optional_payload_set(root_fd, payload)
    reopened_root = os.open(root_path, _DIRECTORY_FLAGS)
    try:
        if not _same_directory(os.fstat(reopened_root), root_identity):
            raise RuntimeError
    finally:
        os.close(reopened_root)


def _clear_directory(directory_fd: int) -> None:
    for entry in list(os.scandir(directory_fd)):
        status = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False)
        if stat.S_ISDIR(status.st_mode):
            child_fd = _open_directory_at(directory_fd, entry.name)
            child_identity = _identity(os.fstat(child_fd))
            try:
                _clear_directory(child_fd)
            finally:
                os.close(child_fd)
            current = _entry_status(directory_fd, entry.name)
            if current is not None and _same_directory(current, child_identity):
                os.rmdir(entry.name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        else:
            os.unlink(entry.name, dir_fd=directory_fd)
            os.fsync(directory_fd)


def _rename_noreplace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise RuntimeError
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_directory_fd,
        os.fsencode(source_name),
        destination_directory_fd,
        os.fsencode(destination_name),
        _RENAME_NOREPLACE,
    )
    if result != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _verify_path_parent_identity(
    output_argument: str, expected: tuple[int, int, int], output_name: str
) -> None:
    reopened, reopened_name = _open_output_parent(output_argument, create_parents=False)
    try:
        if reopened_name != output_name or not _same_directory(
            os.fstat(reopened), expected
        ):
            raise RuntimeError
    finally:
        os.close(reopened)


def publish(
    *,
    source_root: Path,
    second_source_root: Path,
    source_archive: str,
    spec_name: str,
    output_argument: str,
) -> None:
    for name in (source_archive, spec_name):
        if not name or "/" in name or name in (".", "..") or "\0" in name:
            raise RuntimeError
    source_root_fd = os.open(source_root, _DIRECTORY_FLAGS)
    try:
        second_source_root_fd = os.open(second_source_root, _DIRECTORY_FLAGS)
    except BaseException:
        os.close(source_root_fd)
        raise
    source_root_identity = _identity(os.fstat(source_root_fd))
    second_source_root_identity = _identity(os.fstat(second_source_root_fd))
    first_payload: dict[tuple[str, ...], int] = {}
    second_payload: dict[tuple[str, ...], int] = {}
    first_seals: dict[tuple[str, ...], _SealedIdentity] = {}
    second_seals: dict[tuple[str, ...], _SealedIdentity] = {}
    expected_digests: dict[tuple[str, ...], str] = {}
    staged_digests: dict[tuple[str, ...], str] = {}
    staged_payload: dict[tuple[str, ...], int] = {}
    staged_seals: dict[tuple[str, ...], _SealedIdentity] = {}
    parent_fd: int | None = None
    container_fd: int | None = None
    stage_fd: int | None = None
    container_name: str | None = None
    container_identity: tuple[int, int, int] | None = None
    stage_identity: tuple[int, int, int] | None = None
    output_name: str | None = None
    renamed = False
    committed = False
    try:
        first_payload = _open_build_payload(source_root_fd, source_archive, spec_name)
        first_seals = _capture_payload_seals(first_payload)
        second_payload = _open_build_payload(
            second_source_root_fd, source_archive, spec_name
        )
        second_seals = _capture_payload_seals(second_payload)
        if first_payload.keys() != second_payload.keys():
            raise RuntimeError
        for relative, first_fd in first_payload.items():
            digest = _matching_digest(first_fd, second_payload[relative])
            if digest is None:
                raise RuntimeError
            expected_digests[relative] = digest
        _verify_source_state(
            source_root,
            source_root_fd,
            source_root_identity,
            first_payload,
            first_seals,
            expected_digests,
        )
        _verify_source_state(
            second_source_root,
            second_source_root_fd,
            second_source_root_identity,
            second_payload,
            second_seals,
            expected_digests,
        )
        parent_fd, output_name = _open_output_parent(
            output_argument, create_parents=True
        )
        parent_identity = _identity(os.fstat(parent_fd))
        _require_absent(parent_fd, output_name)
        container_name, container_fd, container_identity = _create_staging_container(
            parent_fd, output_name
        )
        # The tree lives below a 0700 container. Even if a writer renames the
        # container entry, renameat2 still addresses this original directory.
        stage_fd = _create_directory_at(container_fd, "tree", 0o755)
        stage_identity = _identity(os.fstat(stage_fd))

        for directory in ("BUILD", "BUILDROOT", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            opened = _create_directory_at(stage_fd, directory, 0o755)
            os.close(opened)
        for relative, source_fd in first_payload.items():
            staged_fd, sealed = _copy_regular(source_fd, stage_fd, relative)
            staged_payload[relative] = staged_fd
            staged_seals[relative] = sealed
        manifest_content = _manifest_bytes(expected_digests)
        manifest_relative = (_MANIFEST_NAME,)
        manifest_fd, manifest_seal = _create_regular_bytes(
            stage_fd, manifest_relative, manifest_content
        )
        staged_payload[manifest_relative] = manifest_fd
        staged_seals[manifest_relative] = manifest_seal
        staged_digests = {
            **expected_digests,
            manifest_relative: hashlib.sha256(manifest_content).hexdigest(),
        }

        _verify_source_state(
            source_root,
            source_root_fd,
            source_root_identity,
            first_payload,
            first_seals,
            expected_digests,
        )
        _verify_source_state(
            second_source_root,
            second_source_root_fd,
            second_source_root_identity,
            second_payload,
            second_seals,
            expected_digests,
        )

        os.fsync(stage_fd)
        os.fsync(container_fd)
        stage_path_status = os.stat("tree", dir_fd=container_fd, follow_symlinks=False)
        if not _same_directory(
            os.fstat(stage_fd), stage_identity
        ) or not _same_directory(stage_path_status, stage_identity):
            raise RuntimeError
        container_path_status = os.stat(
            container_name, dir_fd=parent_fd, follow_symlinks=False
        )
        if not _same_directory(
            os.fstat(container_fd), container_identity
        ) or not _same_directory(container_path_status, container_identity):
            raise RuntimeError
        _verify_path_parent_identity(output_argument, parent_identity, output_name)
        _verify_staged_payload(stage_fd, staged_payload, staged_seals, staged_digests)
        if _verify_manifest(stage_fd) != expected_digests:
            raise RuntimeError
        _require_absent(parent_fd, output_name)
        _rename_noreplace(container_fd, "tree", parent_fd, output_name)
        renamed = True
        _verify_staged_payload(stage_fd, staged_payload, staged_seals, staged_digests)
        if _verify_manifest(stage_fd) != expected_digests:
            raise RuntimeError
        _verify_source_state(
            source_root,
            source_root_fd,
            source_root_identity,
            first_payload,
            first_seals,
            expected_digests,
        )
        _verify_source_state(
            second_source_root,
            second_source_root_fd,
            second_source_root_identity,
            second_payload,
            second_seals,
            expected_digests,
        )
        published_status = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
        if not _same_directory(published_status, stage_identity):
            raise RuntimeError
        _verify_path_parent_identity(output_argument, parent_identity, output_name)
        os.fsync(container_fd)
        current_container = _entry_status(parent_fd, container_name)
        if current_container is None or not _same_directory(
            current_container, container_identity
        ):
            raise RuntimeError
        os.rmdir(container_name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        committed = True
    finally:
        cleanup_errors: list[BaseException] = []
        if stage_fd is not None and not committed:
            try:
                _clear_directory(stage_fd)
            except (OSError, RuntimeError) as error:
                cleanup_errors.append(error)
            if renamed:
                if parent_fd is not None and output_name is not None:
                    current = _entry_status(parent_fd, output_name)
                    if current is not None and _same_directory(current, stage_identity):
                        try:
                            os.rmdir(output_name, dir_fd=parent_fd)
                            os.fsync(parent_fd)
                        except OSError as error:
                            cleanup_errors.append(error)
            elif container_fd is not None:
                current = _entry_status(container_fd, "tree")
                if current is not None and _same_directory(current, stage_identity):
                    try:
                        os.rmdir("tree", dir_fd=container_fd)
                        os.fsync(container_fd)
                    except OSError as error:
                        cleanup_errors.append(error)
        if stage_fd is not None:
            os.close(stage_fd)
        if (
            parent_fd is not None
            and container_fd is not None
            and container_name is not None
            and container_identity is not None
        ):
            current = _entry_status(parent_fd, container_name)
            if current is not None and _same_directory(current, container_identity):
                try:
                    os.rmdir(container_name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                except OSError as error:
                    cleanup_errors.append(error)
        if container_fd is not None:
            os.close(container_fd)
        if parent_fd is not None:
            os.close(parent_fd)
        for descriptor in first_payload.values():
            os.close(descriptor)
        for descriptor in second_payload.values():
            os.close(descriptor)
        for descriptor in staged_payload.values():
            os.close(descriptor)
        os.close(source_root_fd)
        os.close(second_source_root_fd)
        if cleanup_errors:
            raise PublicationDurabilityError from cleanup_errors[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--second-source-root", type=Path, required=True)
    parser.add_argument("--source-archive", required=True)
    parser.add_argument("--spec-name", required=True)
    parser.add_argument("--output", required=True)
    try:
        arguments = parser.parse_args(argv)
        publish(
            source_root=arguments.source_root,
            second_source_root=arguments.second_source_root,
            source_archive=arguments.source_archive,
            spec_name=arguments.spec_name,
            output_argument=arguments.output,
        )
        return 0
    except PublicationDurabilityError:
        with contextlib.suppress(OSError):
            sys.stderr.write("RPM publication durability is uncertain\n")
        return 2
    except (OSError, RuntimeError, ValueError, TypeError, UnicodeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("RPM atomic publication failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
