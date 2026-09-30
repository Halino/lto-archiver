from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import re
import secrets
import stat
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Literal

from ..errors import ValidationError
from .restore_destination import RestoreDestinationLease

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
_RENAME_NOREPLACE = 1


class RestoreCopyError(ValidationError):
    code = "restore_copy_error"


class RestorePathError(RestoreCopyError):
    code = "restore_path_invalid"


class RestoreCopyVerificationError(RestoreCopyError):
    code = "restore_copy_verification_failed"


class RestoreCopyCancelled(RestoreCopyError):
    code = "restore_copy_cancelled"


@dataclass(frozen=True)
class RestoreConflictEvidence:
    canonical_destination: str
    observed_size: int
    observed_sha256: str


@dataclass
class _ObservedDestination:
    evidence: RestoreConflictEvidence
    descriptor: int
    device: int
    inode: int
    ctime_ns: int

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


class RestoreCopyConflict(RestoreCopyError):
    code = "restore_destination_conflict"

    def __init__(self, evidence: RestoreConflictEvidence) -> None:
        super().__init__(self.code)
        self.evidence = evidence


@dataclass
class _SingleUseCapability:
    lock: threading.Lock = field(default_factory=threading.Lock)
    spent: bool = False

    def claim(self) -> None:
        with self.lock:
            if self.spent:
                raise RestoreCopyError("restore replacement capability is spent")
            self.spent = True


@dataclass(frozen=True)
class RestoreReplacementAuthorization:
    """Internal token built only after durable one-time authorization consumption."""

    authorization_id: str
    run_id: str
    item_sequence: int
    file_version_id: int
    canonical_destination: str
    observed_size: int
    observed_sha256: str
    library_id: str
    relative_path: str
    tape_relative_path: str
    expected_size: int
    expected_sha256: str
    state: Literal["consumed"]
    consumed_by_operation_id: str
    _capability: _SingleUseCapability = field(
        default_factory=_SingleUseCapability,
        init=False,
        repr=False,
        compare=False,
    )

    def claim_once(self) -> None:
        self._capability.claim()


@dataclass(frozen=True)
class RestoreCopyRequest:
    tape_root: Path
    destination_lease: RestoreDestinationLease
    library_id: str
    relative_path: str
    tape_relative_path: str
    expected_size: int
    expected_sha256: str
    replacement_authorization: RestoreReplacementAuthorization | None
    buffer_bytes: int
    stop_requested: Callable[[], bool]
    progress: Callable[[int], None]
    fence_check: Callable[[], None] = lambda: None


@dataclass(frozen=True)
class RestoreCopyResult:
    state: Literal["restored", "skipped_verified"]
    destination: Path
    bytes_copied: int
    sha256: str


def _relative_components(value: object, field: str, *, single: bool = False) -> tuple[str, ...]:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RestorePathError(f"invalid {field}")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or (single and len(path.parts) != 1)
    ):
        raise RestorePathError(f"invalid {field}")
    return path.parts


def _validated_request(
    request: RestoreCopyRequest,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    if type(request) is not RestoreCopyRequest:
        raise RestoreCopyError("invalid restore copy request")
    library = _relative_components(request.library_id, "library id", single=True)
    relative = _relative_components(request.relative_path, "relative path")
    tape_relative = _relative_components(request.tape_relative_path, "tape path")
    if (
        type(request.expected_size) is not int
        or not 0 <= request.expected_size <= 2**63 - 1
        or type(request.expected_sha256) is not str
        or _SHA256.fullmatch(request.expected_sha256) is None
        or type(request.buffer_bytes) is not int
        or not 1 <= request.buffer_bytes <= 64 * 1024**2
        or not callable(request.stop_requested)
        or not callable(request.progress)
        or not callable(request.fence_check)
        or type(request.destination_lease) is not RestoreDestinationLease
        or request.destination_lease.destination_kind != "local"
    ):
        raise RestoreCopyError("invalid restore copy request")
    return library, relative, tape_relative


def _open_root(path: Path, field: str) -> tuple[int, Path]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise RestorePathError(f"invalid {field}")
    try:
        canonical = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise RestorePathError(f"invalid {field}") from None
    if canonical != path:
        raise RestorePathError(f"invalid {field}")
    try:
        descriptor = os.open(path, _DIRECTORY_FLAGS)
    except OSError:
        raise RestorePathError(f"invalid {field}") from None
    try:
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise RestorePathError(f"invalid {field}")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, canonical


def _walk_directory(
    root_fd: int,
    components: tuple[str, ...],
    *,
    create: bool,
    private_destination: bool = False,
) -> int:
    current = os.dup(root_fd)
    try:
        for component in components:
            try:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                if not create:
                    raise RestorePathError("restore source directory is absent") from None
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                    next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
                except FileExistsError:
                    next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except OSError:
                raise RestorePathError("unsafe restore directory") from None
            if private_destination:
                details = os.fstat(next_fd)
                if details.st_uid != os.geteuid() or details.st_mode & 0o022:
                    os.close(next_fd)
                    raise RestorePathError(
                        "restore destination component is not daemon-owned"
                    )
            os.close(current)
            current = next_fd
        return current
    except BaseException:
        os.close(current)
        raise


def _open_source(root_fd: int, components: tuple[str, ...]) -> int:
    parent = _walk_directory(root_fd, components[:-1], create=False)
    try:
        descriptor = os.open(components[-1], _READ_FLAGS, dir_fd=parent)
    except OSError:
        raise RestorePathError("unsafe or absent restore source") from None
    finally:
        os.close(parent)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RestorePathError("restore source is not a regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def _hash_open_file(descriptor: int, buffer_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    while True:
        block = os.read(descriptor, buffer_bytes)
        if not block:
            break
        total += len(block)
        digest.update(block)
    return total, digest.hexdigest()


def _inspect_existing(
    parent_fd: int,
    name: str,
    *,
    canonical_destination: str,
    buffer_bytes: int,
) -> _ObservedDestination | None:
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_fd)
    except FileNotFoundError:
        return None
    except OSError:
        raise RestorePathError("unsafe restore destination") from None
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o022
    ):
        os.close(descriptor)
        raise RestorePathError(
            "restore destination is not an exclusive daemon-owned regular file"
        )
    observed_size, observed_sha256 = _hash_open_file(descriptor, buffer_bytes)
    evidence = RestoreConflictEvidence(
        canonical_destination=canonical_destination,
        observed_size=observed_size,
        observed_sha256=observed_sha256,
    )
    if observed_size != metadata.st_size:
        os.close(descriptor)
        raise RestoreCopyConflict(evidence)
    return _ObservedDestination(
        evidence=evidence,
        descriptor=descriptor,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        ctime_ns=metadata.st_ctime_ns,
    )


def _conflict_matches_expected(
    observation: _ObservedDestination, request: RestoreCopyRequest
) -> bool:
    return (
        observation.evidence.observed_size == request.expected_size
        and observation.evidence.observed_sha256 == request.expected_sha256
    )


def _assert_observed_path(
    parent_fd: int,
    name: str,
    observation: _ObservedDestination,
    *,
    canonical_destination: str,
    buffer_bytes: int,
) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        raise RestoreCopyConflict(observation.evidence) from None
    if (
        stat.S_ISREG(current.st_mode)
        and current.st_dev == observation.device
        and current.st_ino == observation.inode
        and current.st_ctime_ns == observation.ctime_ns
    ):
        return
    changed = _inspect_existing(
        parent_fd,
        name,
        canonical_destination=canonical_destination,
        buffer_bytes=buffer_bytes,
    )
    if changed is None:
        raise RestoreCopyConflict(observation.evidence)
    try:
        raise RestoreCopyConflict(changed.evidence)
    finally:
        changed.close()


def _validate_replacement_authorization(
    authorization: RestoreReplacementAuthorization | None,
    request: RestoreCopyRequest,
    evidence: RestoreConflictEvidence,
) -> None:
    if type(authorization) is not RestoreReplacementAuthorization:
        raise RestoreCopyConflict(evidence)
    bindings = (
        authorization.state == "consumed",
        bool(authorization.authorization_id),
        bool(authorization.run_id),
        type(authorization.item_sequence) is int and authorization.item_sequence >= 1,
        type(authorization.file_version_id) is int and authorization.file_version_id >= 1,
        bool(authorization.consumed_by_operation_id),
        authorization.canonical_destination == evidence.canonical_destination,
        authorization.observed_size == evidence.observed_size,
        authorization.observed_sha256 == evidence.observed_sha256,
        authorization.library_id == request.library_id,
        authorization.relative_path == request.relative_path,
        authorization.tape_relative_path == request.tape_relative_path,
        authorization.expected_size == request.expected_size,
        authorization.expected_sha256 == request.expected_sha256,
    )
    if not all(bindings):
        raise RestoreCopyConflict(evidence)


def _write_all(descriptor: int, block: bytes) -> None:
    view = memoryview(block)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short restore destination write")
        view = view[written:]


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise OSError(errno.ENOSYS, "renameat2 is unavailable")
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error = ctypes.get_errno()
    if error in {errno.EEXIST, errno.ENOTEMPTY}:
        raise FileExistsError(error, os.strerror(error), destination)
    raise OSError(error, os.strerror(error), destination)


def copy_selected_restore_item(request: RestoreCopyRequest) -> RestoreCopyResult:
    """Copy one frozen plan item without following source or destination links."""

    library, relative, tape_relative = _validated_request(request)
    request.fence_check()
    tape_root_fd, _ = _open_root(request.tape_root, "tape root")
    destination_root_fd = -1
    source_fd = -1
    destination_parent_fd = -1
    partial_name: str | None = None
    partial_fd = -1
    existing: _ObservedDestination | None = None
    current: _ObservedDestination | None = None
    try:
        try:
            destination_root_fd = request.destination_lease.acquire_copy_root()
        except (OSError, ValidationError) as exc:
            message = "destination lease is busy" if "busy" in str(exc) else "destination lease is not live"
            raise RestorePathError(message) from None
        if not stat.S_ISDIR(os.fstat(destination_root_fd).st_mode):
            raise RestorePathError("destination lease root is not a directory")
        canonical_root = request.destination_lease.canonical_root
        request.fence_check()
        source_fd = _open_source(tape_root_fd, tape_relative)
        source_metadata = os.fstat(source_fd)
        if source_metadata.st_size != request.expected_size:
            raise RestoreCopyVerificationError("restore source size mismatch")

        destination_components = (*library, *relative)
        destination_parent_fd = _walk_directory(
            destination_root_fd,
            destination_components[:-1],
            create=True,
            private_destination=True,
        )
        destination_name = destination_components[-1]
        destination = canonical_root.joinpath(*destination_components)
        canonical_destination = str(destination)
        existing = _inspect_existing(
            destination_parent_fd,
            destination_name,
            canonical_destination=canonical_destination,
            buffer_bytes=request.buffer_bytes,
        )
        if existing is not None and _conflict_matches_expected(existing, request):
            _assert_observed_path(
                destination_parent_fd,
                destination_name,
                existing,
                canonical_destination=canonical_destination,
                buffer_bytes=request.buffer_bytes,
            )
            return RestoreCopyResult(
                state="skipped_verified",
                destination=destination,
                bytes_copied=0,
                sha256=existing.evidence.observed_sha256,
            )
        if existing is not None:
            _validate_replacement_authorization(
                request.replacement_authorization, request, existing.evidence
            )
            assert request.replacement_authorization is not None
            request.replacement_authorization.claim_once()
        elif request.replacement_authorization is not None:
            raise RestoreCopyError("stale restore replacement authorization")

        candidate_partial = f".restore.partial-{secrets.token_hex(16)}"
        partial_fd = os.open(
            candidate_partial,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            0o600,
            dir_fd=destination_parent_fd,
        )
        partial_name = candidate_partial
        copied = 0
        digest = hashlib.sha256()
        while True:
            request.fence_check()
            if request.stop_requested():
                raise RestoreCopyCancelled("restore copy cancelled")
            block = os.read(source_fd, request.buffer_bytes)
            if not block:
                break
            _write_all(partial_fd, block)
            copied += len(block)
            digest.update(block)
            request.progress(len(block))
        if request.stop_requested():
            raise RestoreCopyCancelled("restore copy cancelled")
        os.fsync(partial_fd)
        os.close(partial_fd)
        partial_fd = -1
        observed_sha256 = digest.hexdigest()
        if copied != request.expected_size or observed_sha256 != request.expected_sha256:
            raise RestoreCopyVerificationError("restore source verification mismatch")

        current = _inspect_existing(
            destination_parent_fd,
            destination_name,
            canonical_destination=canonical_destination,
            buffer_bytes=request.buffer_bytes,
        )
        if existing is None:
            if current is not None:
                raise RestoreCopyConflict(current.evidence)
        else:
            if current is None:
                raise RestoreCopyConflict(existing.evidence)
            if (
                current.device != existing.device
                or current.inode != existing.inode
                or current.evidence != existing.evidence
            ):
                raise RestoreCopyConflict(current.evidence)
            _validate_replacement_authorization(
                request.replacement_authorization, request, current.evidence
            )
        if existing is None:
            try:
                _rename_noreplace(
                    destination_parent_fd,
                    partial_name,
                    destination_name,
                )
            except FileExistsError:
                competing = _inspect_existing(
                    destination_parent_fd,
                    destination_name,
                    canonical_destination=canonical_destination,
                    buffer_bytes=request.buffer_bytes,
                )
                if competing is None:
                    raise RestoreCopyError("restore destination publication raced")
                try:
                    raise RestoreCopyConflict(competing.evidence) from None
                finally:
                    competing.close()
        else:
            os.replace(
                partial_name,
                destination_name,
                src_dir_fd=destination_parent_fd,
                dst_dir_fd=destination_parent_fd,
            )
        partial_name = None
        os.fsync(destination_parent_fd)
        return RestoreCopyResult(
            state="restored",
            destination=destination,
            bytes_copied=copied,
            sha256=observed_sha256,
        )
    finally:
        if current is not None:
            current.close()
        if existing is not None:
            existing.close()
        if partial_fd >= 0:
            os.close(partial_fd)
        if partial_name is not None and destination_parent_fd >= 0:
            try:
                os.unlink(partial_name, dir_fd=destination_parent_fd)
            except FileNotFoundError:
                pass
        for descriptor in (
            destination_parent_fd,
            source_fd,
            tape_root_fd,
        ):
            if descriptor >= 0:
                os.close(descriptor)
        if destination_root_fd >= 0:
            request.destination_lease.release_copy_root(destination_root_fd)
