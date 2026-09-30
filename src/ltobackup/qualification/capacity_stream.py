"""Internal bounded synthetic stream; not an LTFS qualification entry point.

The caller owns media identity, mount admission, exclusive directory access,
and durable off-tape storage of every record. Successful writes, fsync, and
close are host acknowledgements only, never proof of LTFS finalization.
"""

from __future__ import annotations

import errno
import hashlib
import os
from collections.abc import Callable, Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CapacityStreamPolicy:
    seed: bytes
    payload_ceiling_bytes: int
    file_bytes: int
    chunk_bytes: int = 1048576

    def __post_init__(self) -> None:
        if type(self.seed) is not bytes or len(self.seed) != 32:
            raise ValueError("seed must be exactly 32 bytes")
        for value in (self.payload_ceiling_bytes, self.file_bytes, self.chunk_bytes):
            if type(value) is not int or value <= 0:
                raise ValueError("stream sizes must be positive integers")
        if self.payload_ceiling_bytes > 100_000_000_000_000:
            raise ValueError("payload ceiling must not exceed 100 TB")
        if self.file_bytes > self.payload_ceiling_bytes:
            raise ValueError("file size must not exceed payload ceiling")
        if self.chunk_bytes > 16 * 1024 * 1024:
            raise ValueError("chunk size must not exceed 16 MiB")
        if (
            self.payload_ceiling_bytes + self.file_bytes - 1
        ) // self.file_bytes > 100_000:
            raise ValueError("policy must require at most 100000 files")


@dataclass(frozen=True)
class CompletedFile:
    ordinal: int
    name: str
    bytes: int
    sha256: str


@dataclass(frozen=True)
class CapacityStreamResult:
    completed_files: tuple[CompletedFile, ...]
    acknowledged_bytes: int
    complete_bytes: int
    stop_reason: str


def _close(fd: int, *, suppress_errors: bool = False) -> None:
    """Close once: Linux releases the descriptor even on delayed I/O errors."""
    try:
        os.close(fd)
    except OSError:
        if not suppress_errors:
            raise


@contextmanager
def _owned_fd(fd: int) -> Iterator[int]:
    try:
        yield fd
    except BaseException:
        _close(fd, suppress_errors=True)
        raise
    else:
        _close(fd)


@contextmanager
def _pinned_directory(directory: Path) -> Iterator[int]:
    if not directory.is_absolute() or directory == Path("/") or ".." in directory.parts:
        raise ValueError("directory must be an absolute non-root path without '..'")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        fd = stack.enter_context(_owned_fd(os.open("/", flags)))
        for component in directory.parts[1:]:
            fd = stack.enter_context(_owned_fd(os.open(component, flags, dir_fd=fd)))
        if os.listdir(fd):
            raise ValueError("capacity stream directory must already be empty")
        yield fd


def run_capacity_stream(
    directory: Path,
    policy: CapacityStreamPolicy,
    *,
    record: Callable[[dict[str, object]], None],
    stop_requested: Callable[[], bool],
) -> CapacityStreamResult:
    """Write reproducible chunk-sized payloads up to an explicit ceiling.

    Records are synchronous; the caller must durably store each off tape
    before returning. This function neither measures free space nor mounts,
    formats, finalizes, retries, or removes data.
    """
    if type(policy) is not CapacityStreamPolicy:
        raise ValueError("policy must be a validated CapacityStreamPolicy")
    if not callable(record) or not callable(stop_requested):
        raise TypeError("record and stop_requested must be callable")
    completed: list[CompletedFile] = []
    acknowledged_bytes = 0
    complete_bytes = 0
    stop_reason = "ceiling"
    with _pinned_directory(directory) as directory_fd:
        record(
            {
                "event": "capacity-start",
                "seed_hex": policy.seed.hex(),
                "payload_ceiling_bytes": policy.payload_ceiling_bytes,
                "file_bytes": policy.file_bytes,
                "chunk_bytes": policy.chunk_bytes,
            }
        )
        while acknowledged_bytes < policy.payload_ceiling_bytes:
            if stop_requested():
                stop_reason = "cancelled"
                break
            ordinal = len(completed)
            name = f"capacity-{ordinal:06d}.bin"
            target_bytes = min(
                policy.file_bytes, policy.payload_ceiling_bytes - acknowledged_bytes
            )
            record(
                {
                    "event": "file-start",
                    "ordinal": ordinal,
                    "name": name,
                    "target_bytes": target_bytes,
                }
            )
            file_bytes = 0
            digest = hashlib.sha256()
            io_error: OSError | None = None
            io_error_cause: OSError | None = None
            errors: list[dict[str, object]] = []
            try:
                fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                stop_reason = "enospc"
                break
            try:
                chunk_index = 0
                while file_bytes < target_bytes:
                    if stop_requested():
                        stop_reason = "cancelled"
                        break
                    domain = (
                        b"ltobackup-capacity-v1\0"
                        + policy.seed
                        + ordinal.to_bytes(8, "big")
                        + chunk_index.to_bytes(8, "big")
                    )
                    chunk = hashlib.shake_256(domain).digest(
                        min(policy.chunk_bytes, target_bytes - file_bytes)
                    )
                    offset = 0
                    while offset < len(chunk):
                        if stop_requested():
                            stop_reason = "cancelled"
                            break
                        try:
                            count = os.write(fd, memoryview(chunk)[offset:])
                            if count == 0:
                                raise OSError(
                                    errno.EIO, "payload write acknowledged zero bytes"
                                )
                        except OSError as exc:
                            io_error = exc
                            errors.append({"phase": "write", "errno": exc.errno})
                            break
                        digest.update(memoryview(chunk)[offset : offset + count])
                        offset += count
                        file_bytes += count
                        acknowledged_bytes += count
                    if io_error is not None or stop_reason == "cancelled":
                        break
                    record(
                        {
                            "event": "progress",
                            "ordinal": ordinal,
                            "name": name,
                            "bytes": file_bytes,
                            "acknowledged_bytes": acknowledged_bytes,
                            "complete_bytes": complete_bytes,
                        }
                    )
                    chunk_index += 1
                if io_error is None and stop_reason != "cancelled":
                    if stop_requested():
                        stop_reason = "cancelled"
                    else:
                        try:
                            # os.write is unbuffered; there is no Python buffer to flush.
                            os.fsync(fd)
                        except OSError as exc:
                            io_error = exc
                            errors.append({"phase": "fsync", "errno": exc.errno})
            except BaseException:
                _close(fd, suppress_errors=True)
                raise
            else:
                try:
                    _close(fd)
                except OSError as exc:
                    errors.append({"phase": "close", "errno": exc.errno})
                    if io_error is None or (
                        io_error.errno == errno.ENOSPC and exc.errno != errno.ENOSPC
                    ):
                        io_error_cause = io_error
                        io_error = exc
            if io_error is None and stop_requested():
                stop_reason = "cancelled"
            if io_error is not None or stop_reason == "cancelled":
                if io_error is not None:
                    stop_reason = (
                        "enospc" if io_error.errno == errno.ENOSPC else "error"
                    )
                record(
                    {
                        "event": "file-partial",
                        "ordinal": ordinal,
                        "name": name,
                        "bytes": file_bytes,
                        "sha256": digest.hexdigest(),
                        "acknowledged_bytes": acknowledged_bytes,
                        "complete_bytes": complete_bytes,
                        "stop_reason": stop_reason,
                        "error_errno": io_error.errno if io_error is not None else None,
                        "errors": errors,
                    }
                )
                if io_error is not None and io_error.errno != errno.ENOSPC:
                    if io_error_cause is not None:
                        raise io_error from io_error_cause
                    raise io_error
                break
            item = CompletedFile(ordinal, name, file_bytes, digest.hexdigest())
            completed.append(item)
            complete_bytes += file_bytes
            record(
                {
                    "event": "file-complete",
                    "ordinal": ordinal,
                    "name": name,
                    "bytes": file_bytes,
                    "sha256": item.sha256,
                    "acknowledged_bytes": acknowledged_bytes,
                    "complete_bytes": complete_bytes,
                }
            )
        result = CapacityStreamResult(
            tuple(completed), acknowledged_bytes, complete_bytes, stop_reason
        )
        record(
            {
                "event": "stopped",
                "stop_reason": result.stop_reason,
                "acknowledged_bytes": acknowledged_bytes,
                "complete_bytes": complete_bytes,
            }
        )
        return result
