from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from ..errors import CopyError, OperationCancelled


class SourceChanged(CopyError):
    """The source no longer matches the immutable job plan."""


class UnsafeCopyPath(CopyError):
    """A source or destination path cannot be safely anchored."""


PhaseCallback = Callable[[dict[str, Any]], None]


def _never_stop() -> bool:
    return False


def _no_phase_event(event: dict[str, Any]) -> None:
    del event


def _no_fence_check() -> None:
    return None


@dataclass(frozen=True)
class CopyRequest:
    source: Path
    destination: Path
    expected_size: int
    expected_mtime_ns: int
    buffer_bytes: int
    stop_requested: Callable[[], bool] = _never_stop
    phase_callback: PhaseCallback = _no_phase_event
    fence_check: Callable[[], None] = _no_fence_check

    def __post_init__(self) -> None:
        object.__setattr__(self, "source", Path(self.source))
        object.__setattr__(self, "destination", Path(self.destination))
        if self.expected_size < 0:
            raise ValueError("expected_size must be non-negative")
        if self.buffer_bytes <= 0:
            raise ValueError("buffer_bytes must be positive")


@dataclass(frozen=True)
class CopyResult:
    sha256: str
    bytes_copied: int
    read_seconds: float
    write_seconds: float
    close_seconds: float


@dataclass(frozen=True)
class _FileIdentity:
    device: int
    inode: int

    @classmethod
    def from_stat(cls, details: os.stat_result) -> _FileIdentity:
        return cls(device=details.st_dev, inode=details.st_ino)


@dataclass(frozen=True)
class _FrozenSourceState:
    identity: _FileIdentity
    ctime_ns: int
    link_count: int

    @classmethod
    def from_stat(cls, details: os.stat_result) -> _FrozenSourceState:
        return cls(
            identity=_FileIdentity.from_stat(details),
            ctime_ns=details.st_ctime_ns,
            link_count=details.st_nlink,
        )


@dataclass(frozen=True)
class _AnchoredPath:
    requested_path: Path
    parent_fd: int
    parent_identity: _FileIdentity
    name: str


@dataclass(frozen=True)
class _CloseFailure:
    label: str
    error: BaseException


def _directory_open_flags() -> int:
    path_flag = getattr(os, "O_PATH", None)
    return (
        (path_flag if isinstance(path_flag, int) else os.O_RDONLY)
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | os.O_NOFOLLOW
    )


def _destination_reference_flags() -> int:
    path_flag = getattr(os, "O_PATH", None)
    if not isinstance(path_flag, int):
        raise UnsafeCopyPath("Linux O_PATH support is required for safe copy")
    return path_flag | os.O_CLOEXEC | os.O_NOFOLLOW


def _anchor_path(
    path: Path,
    error_type: type[CopyError],
    label: str,
) -> _AnchoredPath:
    """Anchor a file name beneath dirfds; dirfds are not data-file handles."""

    path = Path(path)
    parts = path.parts
    if not parts or path.name in {"", ".", ".."} or ".." in parts:
        raise error_type(f"{label} path is not a safe file path")

    if path.is_absolute():
        root = os.path.sep
        parent_parts = parts[1:-1]
    else:
        root = "."
        parent_parts = parts[:-1]

    opened_fds: list[int] = []
    try:
        opened_fds.append(os.open(root, _directory_open_flags()))
        for component in parent_parts:
            opened_fds.append(
                os.open(
                    component,
                    _directory_open_flags(),
                    dir_fd=opened_fds[-1],
                )
            )
        parent_fd = opened_fds[-1]
        parent_details = os.fstat(parent_fd)
    except OSError as exc:
        failures = _close_raw_fds_once(opened_fds, f"{label} path")
        _add_failure_notes(exc, failures)
        raise error_type(f"{label} parent path is not safely reachable") from exc

    ancestor_failures = _close_raw_fds_once(
        opened_fds[:-1],
        f"{label} ancestor",
    )
    if ancestor_failures:
        final_failures = _close_raw_fds_once([parent_fd], f"{label} parent")
        failure = error_type(f"{label} path descriptor closure failed")
        _add_failure_notes(failure, ancestor_failures + final_failures)
        raise failure from ancestor_failures[0].error

    return _AnchoredPath(
        requested_path=path,
        parent_fd=parent_fd,
        parent_identity=_FileIdentity.from_stat(parent_details),
        name=path.name,
    )


def _assert_parent_reachable(
    anchor: _AnchoredPath,
    error_type: type[CopyError],
    label: str,
) -> None:
    reached = _anchor_path(anchor.requested_path, error_type, label)
    try:
        if reached.parent_identity != anchor.parent_identity:
            raise error_type(f"{label} parent identity changed")
    finally:
        active_error = sys.exc_info()[1]
        failures = _close_raw_fds_once([reached.parent_fd], f"{label} parent")
        if active_error is not None:
            _add_failure_notes(active_error, failures)
        elif failures:
            failure = error_type(f"{label} parent descriptor close failed")
            _add_failure_notes(failure, failures)
            raise failure from failures[0].error


def _open_source_file(anchor: _AnchoredPath):
    try:
        descriptor = os.open(
            anchor.name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
            dir_fd=anchor.parent_fd,
        )
    except OSError as exc:
        if exc.errno in {errno.ELOOP, errno.ENOENT}:
            raise SourceChanged("frozen source path changed before open") from exc
        raise
    try:
        return open(
            descriptor,
            "rb",
            buffering=0,
            closefd=True,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _open_destination_file(anchor: _AnchoredPath):
    descriptor = os.open(
        anchor.name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
        dir_fd=anchor.parent_fd,
    )
    try:
        return open(
            descriptor,
            "wb",
            buffering=0,
            closefd=True,
        )
    except BaseException:
        os.close(descriptor)
        raise


def _open_destination_reference(
    anchor: _AnchoredPath,
    expected_identity: _FileIdentity,
) -> int:
    """Pin the created inode without adding another data-file handle."""

    try:
        descriptor = os.open(
            anchor.name,
            _destination_reference_flags(),
            dir_fd=anchor.parent_fd,
        )
    except OSError as exc:
        raise UnsafeCopyPath("destination reference could not be opened") from exc
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or _FileIdentity.from_stat(details) != expected_identity
        ):
            raise UnsafeCopyPath("destination changed before inode pinning")
    except BaseException as exc:
        failures = _close_raw_fds_once(
            [descriptor],
            "destination reference descriptor",
        )
        _add_failure_notes(exc, failures)
        raise
    return descriptor


def _frozen_source_stat(
    request: CopyRequest,
    anchor: _AnchoredPath,
) -> os.stat_result:
    try:
        details = os.stat(
            anchor.name,
            dir_fd=anchor.parent_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError as exc:
        raise SourceChanged("frozen source is no longer available") from exc
    if not stat.S_ISREG(details.st_mode):
        raise SourceChanged("frozen source is not a regular file")
    _verify_frozen_metadata(request, details)
    return details


def _verify_frozen_metadata(
    request: CopyRequest,
    details: os.stat_result,
) -> None:
    if (
        details.st_size != request.expected_size
        or details.st_mtime_ns != request.expected_mtime_ns
    ):
        raise SourceChanged("frozen source size or modification time changed")


def _verify_open_source(
    request: CopyRequest,
    details: os.stat_result,
    expected_state: _FrozenSourceState,
) -> None:
    if not stat.S_ISREG(details.st_mode):
        raise SourceChanged("opened source is not a regular file")
    if _FileIdentity.from_stat(details) != expected_state.identity:
        raise SourceChanged("frozen source identity changed")
    if (
        details.st_ctime_ns != expected_state.ctime_ns
        or details.st_nlink != expected_state.link_count
    ):
        raise SourceChanged("frozen source change time or hardlink count changed")
    _verify_frozen_metadata(request, details)


def _verify_source_after_copy(
    request: CopyRequest,
    source_handle,
    source_anchor: _AnchoredPath,
    expected_state: _FrozenSourceState,
    bytes_copied: int,
) -> None:
    if bytes_copied != request.expected_size:
        raise SourceChanged("frozen source byte count changed during copy")
    _verify_open_source(
        request,
        os.fstat(source_handle.fileno()),
        expected_state,
    )
    _verify_source_path(request, source_anchor, expected_state)


def _digest_exact_source(
    request: CopyRequest,
    source_handle,
    buffer: bytearray,
) -> tuple[bytes, float]:
    """Hash exactly the planned bytes with bounded memory and live fences."""

    source_handle.seek(0)
    digest = hashlib.sha256()
    digested_bytes = 0
    read_seconds = 0.0
    while digested_bytes < request.expected_size:
        request.fence_check()
        if request.stop_requested():
            raise OperationCancelled("copy cancelled")
        started = time.monotonic()
        try:
            count = source_handle.readinto(buffer)
        finally:
            read_seconds += time.monotonic() - started
        if not count:
            raise SourceChanged("frozen source byte count changed during verification")
        if count < 0 or count > len(buffer):
            raise CopyError("invalid source verification read length")
        if digested_bytes + count > request.expected_size:
            raise SourceChanged("frozen source byte count changed during verification")
        digest.update(memoryview(buffer)[:count])
        digested_bytes += count
    return digest.digest(), read_seconds


def _verify_source_path(
    request: CopyRequest,
    source_anchor: _AnchoredPath,
    expected_state: _FrozenSourceState,
) -> None:
    _assert_parent_reachable(source_anchor, SourceChanged, "source")
    try:
        path_details = os.stat(
            source_anchor.name,
            dir_fd=source_anchor.parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise SourceChanged("frozen source path changed during copy") from exc
    _verify_open_source(request, path_details, expected_state)


def _verify_destination_after_copy(
    anchor: _AnchoredPath,
    expected_identity: _FileIdentity,
    reference_fd: int,
    expected_mtime_ns: int,
) -> None:
    try:
        reference_details = os.fstat(reference_fd)
    except OSError as exc:
        raise UnsafeCopyPath("destination inode reference is unavailable") from exc
    reference_identity = _FileIdentity.from_stat(reference_details)
    if (
        not stat.S_ISREG(reference_details.st_mode)
        or reference_identity != expected_identity
        or reference_details.st_mtime_ns != expected_mtime_ns
    ):
        raise UnsafeCopyPath("destination inode reference changed")
    try:
        details = os.stat(
            anchor.name,
            dir_fd=anchor.parent_fd,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise UnsafeCopyPath("destination path changed during copy") from exc
    if (
        not stat.S_ISREG(details.st_mode)
        or _FileIdentity.from_stat(details) != reference_identity
        or details.st_mtime_ns != expected_mtime_ns
    ):
        raise UnsafeCopyPath("destination identity changed during copy")


def _close_raw_fds_once(
    descriptors: list[int],
    label: str,
) -> list[_CloseFailure]:
    failures: list[_CloseFailure] = []
    for descriptor in reversed(descriptors):
        try:
            os.close(descriptor)
        except BaseException as exc:  # noqa: BLE001 - never retry an ambiguous close.
            failures.append(_CloseFailure(label, exc))
    return failures


def _add_failure_notes(
    primary: BaseException,
    failures: list[_CloseFailure],
) -> None:
    for failure in failures:
        primary.add_note(
            f"secondary {failure.label} close failure: "
            f"{type(failure.error).__name__}: {failure.error}"
        )


def _raise_close_failures(failures: list[_CloseFailure]) -> NoReturn:
    primary = failures[0]
    _add_failure_notes(primary.error, failures[1:])
    raise primary.error


def _close_handles(
    destination_handle, source_handle
) -> tuple[float, list[_CloseFailure]]:
    """Close and time only the two data-file handles, destination first."""

    duration = 0.0
    failures: list[_CloseFailure] = []
    for label, handle in (
        ("destination handle", destination_handle),
        ("source handle", source_handle),
    ):
        if handle is None:
            continue
        started = time.monotonic()
        try:
            handle.close()
        except BaseException as exc:  # noqa: BLE001 - close must not skip the other handle.
            failures.append(_CloseFailure(label, exc))
        finally:
            duration += time.monotonic() - started
    return duration, failures


def _close_parent_fds(*anchors: _AnchoredPath | None) -> list[_CloseFailure]:
    failures: list[_CloseFailure] = []
    for label, anchor in zip(
        ("destination parent descriptor", "source parent descriptor"),
        anchors,
        strict=True,
    ):
        if anchor is None:
            continue
        try:
            os.close(anchor.parent_fd)
        except BaseException as exc:  # noqa: BLE001 - every dirfd must be attempted.
            failures.append(_CloseFailure(label, exc))
    return failures


def _verify_closed_copy_paths(
    request: CopyRequest,
    source_anchor: _AnchoredPath,
    source_state: _FrozenSourceState,
    destination_anchor: _AnchoredPath,
    destination_identity: _FileIdentity,
    destination_reference_fd: int,
) -> None:
    _verify_source_path(request, source_anchor, source_state)
    _assert_parent_reachable(
        destination_anchor,
        UnsafeCopyPath,
        "destination",
    )
    _verify_destination_after_copy(
        destination_anchor,
        destination_identity,
        destination_reference_fd,
        request.expected_mtime_ns,
    )


def _phase_event(event: str, duration: float, bytes_copied: int) -> dict[str, Any]:
    return {
        "event": event,
        "duration_seconds": duration,
        "bytes_copied": bytes_copied,
    }


def copy_frozen_file(request: CopyRequest) -> CopyResult:
    """Copy with two data handles; internal dirfds and O_PATH pin are non-data."""

    source_anchor: _AnchoredPath | None = None
    destination_anchor: _AnchoredPath | None = None
    source_handle = None
    destination_handle = None
    destination_identity: _FileIdentity | None = None
    destination_reference_fd: int | None = None
    read_seconds = 0.0
    write_seconds = 0.0
    close_seconds = 0.0
    bytes_copied = 0
    hasher = hashlib.sha256()

    try:
        try:
            try:
                source_anchor = _anchor_path(request.source, SourceChanged, "source")
                initial = _frozen_source_stat(request, source_anchor)
                source_state = _FrozenSourceState.from_stat(initial)
                source_handle = _open_source_file(source_anchor)
                _verify_open_source(
                    request,
                    os.fstat(source_handle.fileno()),
                    source_state,
                )
                _assert_parent_reachable(source_anchor, SourceChanged, "source")

                buffer = bytearray(request.buffer_bytes)
                source_digest_before, verification_seconds = _digest_exact_source(
                    request,
                    source_handle,
                    buffer,
                )
                read_seconds += verification_seconds
                _verify_open_source(
                    request,
                    os.fstat(source_handle.fileno()),
                    source_state,
                )
                _verify_source_path(request, source_anchor, source_state)

                destination_anchor = _anchor_path(
                    request.destination,
                    UnsafeCopyPath,
                    "destination",
                )
                _assert_parent_reachable(
                    destination_anchor,
                    UnsafeCopyPath,
                    "destination",
                )
                request.fence_check()
                if request.stop_requested():
                    raise OperationCancelled("copy cancelled")
                destination_handle = _open_destination_file(destination_anchor)
                _verify_open_source(
                    request,
                    os.fstat(source_handle.fileno()),
                    source_state,
                )
                destination_identity = _FileIdentity.from_stat(
                    os.fstat(destination_handle.fileno())
                )
                destination_reference_fd = _open_destination_reference(
                    destination_anchor,
                    destination_identity,
                )

                source_handle.seek(0)
                while True:
                    started = time.monotonic()
                    try:
                        count = source_handle.readinto(buffer)
                    finally:
                        read_seconds += time.monotonic() - started
                    if not count:
                        break
                    if count < 0 or count > len(buffer):
                        raise CopyError("invalid source read length")
                    chunk = memoryview(buffer)[:count]
                    hasher.update(chunk)
                    while chunk:
                        request.fence_check()
                        if request.stop_requested():
                            raise OperationCancelled("copy cancelled")
                        started = time.monotonic()
                        try:
                            written = destination_handle.write(chunk)
                        finally:
                            write_seconds += time.monotonic() - started
                        if not written:
                            raise CopyError("zero-byte destination write")
                        if written < 0 or written > len(chunk):
                            raise CopyError("invalid destination write length")
                        chunk = chunk[written:]
                    bytes_copied += count

                _verify_source_after_copy(
                    request,
                    source_handle,
                    source_anchor,
                    source_state,
                    bytes_copied,
                )
                source_digest_after, verification_seconds = _digest_exact_source(
                    request,
                    source_handle,
                    buffer,
                )
                read_seconds += verification_seconds
                if not (source_digest_before == hasher.digest() == source_digest_after):
                    raise SourceChanged("frozen source content changed during copy")
                _verify_source_after_copy(
                    request,
                    source_handle,
                    source_anchor,
                    source_state,
                    bytes_copied,
                )
                _assert_parent_reachable(
                    destination_anchor,
                    UnsafeCopyPath,
                    "destination",
                )
                request.fence_check()
                if request.stop_requested():
                    raise OperationCancelled("copy cancelled")
                destination_atime_ns = os.fstat(
                    destination_handle.fileno()
                ).st_atime_ns
                started = time.monotonic()
                try:
                    os.utime(
                        destination_handle.fileno(),
                        ns=(destination_atime_ns, request.expected_mtime_ns),
                    )
                finally:
                    write_seconds += time.monotonic() - started
                _verify_destination_after_copy(
                    destination_anchor,
                    destination_identity,
                    destination_reference_fd,
                    request.expected_mtime_ns,
                )
                request.phase_callback(
                    _phase_event("file.read.complete", read_seconds, bytes_copied)
                )
                request.phase_callback(
                    _phase_event("file.write.complete", write_seconds, bytes_copied)
                )
            finally:
                active_error = sys.exc_info()[1]
                close_seconds, close_failures = _close_handles(
                    destination_handle,
                    source_handle,
                )
                if active_error is not None:
                    _add_failure_notes(active_error, close_failures)
                elif close_failures:
                    _raise_close_failures(close_failures)

            _verify_closed_copy_paths(
                request,
                source_anchor,
                source_state,
                destination_anchor,
                destination_identity,
                destination_reference_fd,
            )
            request.phase_callback(
                _phase_event("file.close.complete", close_seconds, bytes_copied)
            )
            _verify_closed_copy_paths(
                request,
                source_anchor,
                source_state,
                destination_anchor,
                destination_identity,
                destination_reference_fd,
            )
        finally:
            active_error = sys.exc_info()[1]
            reference_failures = _close_raw_fds_once(
                (
                    [destination_reference_fd]
                    if destination_reference_fd is not None
                    else []
                ),
                "destination reference descriptor",
            )
            parent_failures = _close_parent_fds(
                destination_anchor,
                source_anchor,
            )
            close_failures = reference_failures + parent_failures
            if active_error is not None:
                _add_failure_notes(active_error, close_failures)
            elif close_failures:
                _raise_close_failures(close_failures)
    except BaseException as exc:
        if destination_identity is not None:
            exc.add_note(
                "partial destination retained because pathname cleanup cannot be "
                "made inode-conditional"
            )
        raise

    return CopyResult(
        sha256=hasher.hexdigest(),
        bytes_copied=bytes_copied,
        read_seconds=read_seconds,
        write_seconds=write_seconds,
        close_seconds=close_seconds,
    )
