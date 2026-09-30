from __future__ import annotations

import errno
import fcntl
import os
import re
import stat
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Self

from ..errors import ValidationError
from ..share_broker.protocol import ShareMountReceiptV1
from ..share_broker.systemd import mount_unit_name

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LOCAL_KEYS = frozenset({"kind", "root", "anchor"})
_MANAGED_KEYS = frozenset(
    {
        "kind",
        "root",
        "anchor",
        "share_id",
        "config_revision",
        "credential_generation",
        "mount_target",
        "filesystem_type",
        "source_sha256",
        "read_only",
        "mount_identity_sha256",
    }
)


class RestoreDestinationAdmissionError(ValidationError):
    code = "restore_destination_not_admitted"


class RestoreDestinationNotWritable(RestoreDestinationAdmissionError):
    code = "restore_destination_not_writable"


@dataclass
class _DescriptorOwner:
    descriptor: int | None
    copy_lock: threading.Lock = field(default_factory=threading.Lock)
    state_lock: threading.Lock = field(default_factory=threading.Lock)

    def close(self) -> None:
        with self.state_lock:
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None

    def duplicate(self) -> int:
        with self.state_lock:
            if self.descriptor is None:
                raise RestoreDestinationAdmissionError(
                    "restore destination lease is closed"
                )
            return os.dup(self.descriptor)


@dataclass(frozen=True)
class ManagedShareIdentity:
    share_id: str
    config_revision: int
    credential_generation: int
    mount_target: Path
    filesystem_type: Literal["nfs", "nfs4", "cifs"]
    source_sha256: str
    read_only: bool
    mount_identity_sha256: str


@dataclass(frozen=True)
class RestoreDestinationLease:
    _owner: _DescriptorOwner
    canonical_root: Path
    destination_kind: Literal["local", "managed_share"]
    managed_share_identity: ManagedShareIdentity | None = None

    @property
    def root_fd(self) -> int:
        with self._owner.state_lock:
            descriptor = self._owner.descriptor
            if descriptor is None:
                raise RestoreDestinationAdmissionError(
                    "restore destination lease is closed"
                )
            return descriptor

    def close(self) -> None:
        self._owner.close()

    def acquire_copy_root(self) -> int:
        if not self._owner.copy_lock.acquire(blocking=False):
            raise RestoreDestinationAdmissionError("restore destination lease is busy")
        try:
            return self._owner.duplicate()
        except BaseException:
            self._owner.copy_lock.release()
            raise

    def release_copy_root(self, descriptor: int) -> None:
        try:
            os.close(descriptor)
        finally:
            self._owner.copy_lock.release()

    def __enter__(self) -> Self:
        _ = self.root_fd
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()


def _closed_mapping(value: object, keys: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or frozenset(value) != keys:
        raise RestoreDestinationAdmissionError("invalid restore destination snapshot")
    return value


def _absolute_path(value: object, field: str) -> Path:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise RestoreDestinationAdmissionError(f"invalid {field}")
    pure = PurePosixPath(value)
    if (
        not pure.is_absolute()
        or pure.as_posix() != value
        or any(part in {".", ".."} for part in pure.parts)
    ):
        raise RestoreDestinationAdmissionError(f"invalid {field}")
    return Path(value)


def _open_anchor(anchor: Path) -> tuple[int, Path]:
    try:
        canonical = anchor.resolve(strict=True)
    except (OSError, RuntimeError):
        raise RestoreDestinationAdmissionError("restore anchor is unavailable") from None
    if canonical != anchor:
        raise RestoreDestinationAdmissionError("restore anchor is not canonical")
    try:
        descriptor = os.open(anchor, _DIRECTORY_FLAGS)
    except OSError:
        raise RestoreDestinationAdmissionError("restore anchor is unsafe") from None
    try:
        _require_private_daemon_directory(descriptor, "restore anchor")
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor, canonical


def _require_private_daemon_directory(descriptor: int, label: str) -> None:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_mode & 0o022
    ):
        raise RestoreDestinationAdmissionError(
            f"{label} is not an exclusive daemon-owned directory"
        )


def _lock_destination_root(descriptor: int) -> None:
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno in {
            errno.EACCES,
            errno.EAGAIN,
            errno.EINVAL,
            errno.ENOSYS,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            raise RestoreDestinationAdmissionError(
                "restore destination exclusive lock is unavailable"
            ) from None
        raise RestoreDestinationAdmissionError(
            "restore destination exclusive lock failed"
        ) from None


def _open_root_below_anchor(root: Path, anchor: Path) -> tuple[int, Path]:
    try:
        relative = root.relative_to(anchor)
    except ValueError:
        raise RestoreDestinationAdmissionError("restore root escapes its anchor") from None
    anchor_fd, canonical_anchor = _open_anchor(anchor)
    current = anchor_fd
    try:
        for component in relative.parts:
            try:
                next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
            except FileNotFoundError:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=current)
                    next_fd = os.open(component, _DIRECTORY_FLAGS, dir_fd=current)
                except OSError:
                    raise RestoreDestinationAdmissionError(
                        "restore root cannot be created safely"
                    ) from None
            except OSError:
                raise RestoreDestinationAdmissionError("restore root is unsafe") from None
            try:
                _require_private_daemon_directory(next_fd, "restore root component")
            except BaseException:
                os.close(next_fd)
                raise
            os.close(current)
            current = next_fd
        canonical_root = canonical_anchor.joinpath(relative)
        try:
            observed = Path(f"/proc/self/fd/{current}").resolve(strict=True)
        except (OSError, RuntimeError):
            raise RestoreDestinationAdmissionError("restore root identity is unavailable") from None
        if observed != canonical_root:
            raise RestoreDestinationAdmissionError("restore root identity changed")
        _lock_destination_root(current)
        return current, canonical_root
    except BaseException:
        os.close(current)
        raise


class RestoreDestinationVerifier:
    def __init__(self, *, management_service: object | None = None) -> None:
        self._management_service = management_service

    def admit(self, plan: Mapping[str, Any]) -> RestoreDestinationLease:
        if not isinstance(plan, Mapping):
            raise RestoreDestinationAdmissionError("invalid restore plan")
        destination_root = _absolute_path(plan.get("destination_root"), "destination root")
        raw = plan.get("destination")
        if not isinstance(raw, Mapping):
            raise RestoreDestinationAdmissionError("missing restore destination snapshot")
        kind = raw.get("kind")
        if kind == "local":
            snapshot = _closed_mapping(raw, _LOCAL_KEYS)
            root = _absolute_path(snapshot["root"], "destination root")
            anchor = _absolute_path(snapshot["anchor"], "destination anchor")
            if root != destination_root:
                raise RestoreDestinationAdmissionError("restore destination snapshot changed")
            descriptor, canonical_root = _open_root_below_anchor(root, anchor)
            return RestoreDestinationLease(
                _owner=_DescriptorOwner(descriptor),
                canonical_root=canonical_root,
                destination_kind="local",
            )
        if kind == "managed_share":
            snapshot = _closed_mapping(raw, _MANAGED_KEYS)
            self._admit_managed_share(destination_root, snapshot)
            raise AssertionError("managed share admission must not return")
        raise RestoreDestinationAdmissionError("invalid restore destination kind")

    def _admit_managed_share(
        self, destination_root: Path, snapshot: Mapping[str, Any]
    ) -> None:
        root = _absolute_path(snapshot["root"], "destination root")
        anchor = _absolute_path(snapshot["anchor"], "destination anchor")
        mount_target = _absolute_path(snapshot["mount_target"], "managed mount target")
        share_id = snapshot["share_id"]
        config_revision = snapshot["config_revision"]
        credential_generation = snapshot["credential_generation"]
        filesystem_type = snapshot["filesystem_type"]
        source_sha256 = snapshot["source_sha256"]
        read_only = snapshot["read_only"]
        mount_identity_sha256 = snapshot["mount_identity_sha256"]
        if (
            root != destination_root
            or anchor != mount_target
            or type(share_id) is not str
            or not share_id
            or len(share_id) > 128
            or type(config_revision) is not int
            or config_revision < 1
            or type(credential_generation) is not int
            or credential_generation < 0
            or filesystem_type not in {"nfs", "nfs4", "cifs"}
            or type(source_sha256) is not str
            or _SHA256.fullmatch(source_sha256) is None
            or read_only is not True
            or type(mount_identity_sha256) is not str
            or _SHA256.fullmatch(mount_identity_sha256) is None
        ):
            raise RestoreDestinationAdmissionError("invalid managed destination snapshot")
        try:
            root.relative_to(anchor)
        except ValueError:
            raise RestoreDestinationAdmissionError("managed destination escapes mount") from None
        inspector = getattr(self._management_service, "inspect_managed_share_mount", None)
        if not callable(inspector):
            raise RestoreDestinationAdmissionError("managed share inspection unavailable")
        try:
            receipt = inspector(share_id)
        except Exception:  # noqa: BLE001 - do not expose broker inspection detail
            raise RestoreDestinationAdmissionError("managed share inspection failed") from None
        if (
            type(receipt) is not ShareMountReceiptV1
            or receipt.action != "mount.inspect"
            or receipt.result != "mounted"
            or receipt.safe_error_code is not None
            or receipt.share_id != share_id
            or receipt.config_revision != config_revision
            or receipt.credential_generation != credential_generation
            or receipt.unit_name != mount_unit_name(mount_target)
            or receipt.filesystem_type != filesystem_type
            or receipt.source_sha256 != source_sha256
            or receipt.read_only is not True
            or receipt.mount_identity_sha256 != mount_identity_sha256
        ):
            raise RestoreDestinationAdmissionError("managed share evidence changed")
        # The current broker deliberately admits source mounts read-only.  It cannot
        # safely authorize writes until a separately reviewed destination contract exists.
        raise RestoreDestinationNotWritable("managed restore destination is read-only")
