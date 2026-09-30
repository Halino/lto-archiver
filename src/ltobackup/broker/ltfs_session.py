from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import select
import signal
import stat
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal

from ltobackup.tape.command_supervisor import (
    LtfsReadyReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)

_TOOL_FLAGS = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC
_MOUNT_FLAGS = _TOOL_FLAGS | os.O_DIRECTORY
_READ_FLAGS = os.O_RDONLY | os.O_CLOEXEC
_LTFS_MODE = 0o755
_FUSERMOUNT_MODE = 0o4755
_PINSET_CREATION_TOKEN = object()
_VALIDATED_CREATION_TOKEN = object()
_RECEIPT_ROOT_CREATION_TOKEN = object()
_RECEIPT_OPERATION_NAMESPACE = uuid.UUID("8b5099bd-c78e-5b2d-9c30-8acaa77836c8")
_STANDALONE_RECEIPT_KEYS = (
    "schema",
    "stage",
    "operation_id",
    "volume_uuid",
    "prior_generation",
    "new_generation",
    "bytes_valid",
    "bytes",
    "files_valid",
    "files",
    "phase_duration_ns",
    "capture_duration_ns",
    "device_close_duration_ns",
    "device_close_result_valid",
    "device_close_result",
    "catalog_ack_duration_ns",
    "media_committed",
    "catalog_acknowledged",
    "cleanup_failed",
    "result",
)
_MAX_STANDALONE_RECEIPT_BYTES = 8192

DeviceRole = Literal["tape", "scsi"]


class LtfsPinningError(RuntimeError):
    """Redacted fail-closed result for an invalid LTFS resource anchor."""

    def __init__(self) -> None:
        super().__init__("LTFS session pinning unavailable")


class LtfsLifecycleUnavailable(RuntimeError):
    """Redacted result for an uncertain privileged LTFS lifecycle."""

    def __init__(self) -> None:
        super().__init__("LTFS session lifecycle unavailable")


def _fstat(fd: int):
    return os.fstat(fd)


def _stat_path(path: Path):
    return os.stat(path, follow_symlinks=False)


def _digest(domain: bytes, value: object) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(domain + b"\0" + canonical).hexdigest()


def _target_digest(domain: str, value: object) -> str:
    return _digest(b"lto-target-v1\0" + domain.encode("ascii"), value)


def _exact_path(path: Path, *, directory: bool) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise LtfsPinningError
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise LtfsPinningError from None
    if resolved != path:
        raise LtfsPinningError
    try:
        status = _stat_path(path)
    except OSError:
        raise LtfsPinningError from None
    if directory != stat.S_ISDIR(status.st_mode):
        raise LtfsPinningError
    return path


def mount_path_identity_sha256(path: Path) -> str:
    """Derive the existing HardwareTargetBinding mount digest."""

    exact = _exact_path(path, directory=True)
    return _target_digest("mount-path", str(exact))


def _tool_snapshot(status) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
    )


def _mount_snapshot(status) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
    )


def _device_snapshot(status) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_nlink,
        status.st_uid,
        status.st_gid,
        status.st_rdev,
    )


def _link_snapshot(status) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
        status.st_size,
        status.st_mtime_ns,
    )


def _validate_tool_status(status, role: Literal["ltfs", "fusermount"]) -> None:
    if role == "ltfs":
        required_mode = _LTFS_MODE
    elif role == "fusermount":
        required_mode = _FUSERMOUNT_MODE
    else:
        raise LtfsPinningError
    if (
        not stat.S_ISREG(status.st_mode)
        or stat.S_IMODE(status.st_mode) != required_mode
        or status.st_uid != 0
        or status.st_gid != 0
        or status.st_nlink != 1
        or status.st_size <= 0
    ):
        raise LtfsPinningError


def _validate_mount_status(status) -> None:
    if not stat.S_ISDIR(status.st_mode) or stat.S_IMODE(status.st_mode) & 0o022:
        raise LtfsPinningError


def _validate_device_status(status) -> None:
    if not stat.S_ISCHR(status.st_mode) or status.st_uid != 0 or status.st_nlink != 1:
        raise LtfsPinningError


def _validate_device_link_status(status) -> None:
    if not stat.S_ISLNK(status.st_mode) or status.st_uid != 0 or status.st_gid != 0:
        raise LtfsPinningError


def _configured_device_path(path: Path, role: DeviceRole, device_root: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute():
        raise LtfsPinningError
    root = _exact_path(device_root, directory=True)
    candidate = Path(os.path.normpath(str(path)))
    if candidate != path:
        raise LtfsPinningError
    try:
        parts = candidate.relative_to(root).parts
    except ValueError:
        raise LtfsPinningError from None
    if role == "tape":
        valid_namespace = len(parts) == 3 and parts[:2] == ("tape", "by-id")
    elif role == "scsi":
        prefix = "lto-archiver-scsi-"
        valid_namespace = (
            len(parts) == 1
            and parts[0].startswith(prefix)
            and len(parts[0]) > len(prefix)
        )
    else:
        valid_namespace = False
    if not valid_namespace:
        raise LtfsPinningError
    try:
        if candidate.parent.resolve(strict=True) != candidate.parent:
            raise LtfsPinningError
        link_status = _stat_path(candidate)
    except (OSError, RuntimeError):
        raise LtfsPinningError from None
    _validate_device_link_status(link_status)
    _validate_by_id_basename(candidate.name)
    return candidate


def _validate_by_id_basename(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 255
        or value in {".", ".."}
        or not value.isascii()
        or not value.isprintable()
        or "/" in value
        or "\\" in value
    ):
        raise LtfsPinningError
    return value


def _validate_receipt_uuid(value: str) -> str:
    if type(value) is not str or len(value) != 36:
        raise LtfsPinningError
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, ValueError):
        raise LtfsPinningError from None
    if (
        str(parsed) != value
        or parsed.version not in {1, 2, 3, 4, 5}
        or parsed.variant != uuid.RFC_4122
    ):
        raise LtfsPinningError
    return value


def _validate_ready_identity(value: object, *, maximum: int = 255) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > maximum
        or value != value.strip(" ")
        or not value.isascii()
        or not value.isprintable()
    ):
        raise LtfsPinningError
    return value


def _ready_media_identity_sha256(ready: LtfsReadyReceipt) -> str:
    return _target_digest(
        "observed-media",
        (
            ready.drive_serial,
            ready.mam_barcode,
            ready.mam_volume_serial,
            ready.ltfs_volume_label,
            ready.volume_uuid,
        ),
    )


def _validate_catalog_operation_id(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 1024
        or not value.isascii()
        or not value.isprintable()
        or "/" in value
        or "\\" in value
    ):
        raise LtfsPinningError
    return value


def derive_receipt_operation_uuid(
    *, operation_id: str, owner_generation: int, request_sha256: str
) -> str:
    """Derive the LTFS UUID without changing the catalog operation identity."""

    checked_operation = _validate_catalog_operation_id(operation_id)
    if (
        type(owner_generation) is not int
        or not 0 <= owner_generation < 1 << 63
        or type(request_sha256) is not str
        or len(request_sha256) != 64
        or any(character not in "0123456789abcdef" for character in request_sha256)
    ):
        raise LtfsPinningError
    canonical = json.dumps(
        {
            "domain": "lto-ltfs-standalone-receipt-operation-v1",
            "operation_id": checked_operation,
            "owner_generation": owner_generation,
            "request_sha256": request_sha256,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return str(uuid.uuid5(_RECEIPT_OPERATION_NAMESPACE, canonical))


class LtfsStandaloneReceiptRoot:
    """Pinned root-only authority for broker-derived LTFS receipt targets."""

    def __init__(
        self,
        *,
        path: Path,
        fd: int,
        snapshot: tuple[int, ...],
        _creation_token: object,
    ) -> None:
        if _creation_token is not _RECEIPT_ROOT_CREATION_TOKEN:
            raise LtfsPinningError
        self._path = path
        self._fd = fd
        self._snapshot = snapshot
        self._closed = False

    @classmethod
    def open(cls, path: Path) -> LtfsStandaloneReceiptRoot:
        if not isinstance(path, Path) or not path.is_absolute():
            raise LtfsPinningError
        fd = -1
        try:
            if path.resolve(strict=True) != path:
                raise LtfsPinningError
            fd = os.open(
                path,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            descriptor_status = _fstat(fd)
            path_status = _stat_path(path)
            snapshot = _mount_snapshot(descriptor_status)
            if (
                not stat.S_ISDIR(descriptor_status.st_mode)
                or stat.S_IMODE(descriptor_status.st_mode) != 0o700
                or descriptor_status.st_nlink != 2
                or descriptor_status.st_uid != 0
                or descriptor_status.st_gid != 0
                or _mount_snapshot(path_status) != snapshot
            ):
                raise LtfsPinningError
            result = cls(
                path=path,
                fd=fd,
                snapshot=snapshot,
                _creation_token=_RECEIPT_ROOT_CREATION_TOKEN,
            )
            fd = -1
            return result
        except (OSError, RuntimeError, ValueError, TypeError):
            raise LtfsPinningError from None
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)

    def _assert_anchor(self) -> None:
        if self._closed:
            raise LtfsPinningError
        try:
            if (
                _mount_snapshot(_fstat(self._fd)) != self._snapshot
                or _mount_snapshot(_stat_path(self._path)) != self._snapshot
            ):
                raise LtfsPinningError
        except OSError:
            raise LtfsPinningError from None

    @property
    def path(self) -> Path:
        self._assert_anchor()
        return self._path

    def target_path(
        self,
        *,
        operation_id: str,
        owner_generation: int,
        request_sha256: str,
    ) -> Path:
        self._assert_anchor()
        basename = self._target_basename(
            operation_id=operation_id,
            owner_generation=owner_generation,
            request_sha256=request_sha256,
        )
        for candidate in (
            basename,
            f"{basename}.ready",
            f"{basename}.ready.tmp",
            f"{basename}.pending",
            f"{basename}.pending.tmp",
            f"{basename}.tmp",
        ):
            if not self._path_absent(candidate):
                raise LtfsPinningError
        self._assert_anchor()
        return self._path / basename

    @staticmethod
    def _target_basename(
        *, operation_id: str, owner_generation: int, request_sha256: str
    ) -> str:
        checked_operation = _validate_receipt_uuid(operation_id)
        if (
            type(owner_generation) is not int
            or not 0 <= owner_generation < 1 << 63
            or type(request_sha256) is not str
            or len(request_sha256) != 64
            or any(character not in "0123456789abcdef" for character in request_sha256)
        ):
            raise LtfsPinningError
        canonical = json.dumps(
            {
                "operation_id": checked_operation,
                "owner_generation": owner_generation,
                "request_sha256": request_sha256,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        basename = (
            hashlib.sha256(b"lto-ltfs-standalone-receipt-v1\0" + canonical).hexdigest()
            + ".json"
        )
        return basename

    def _path_absent(self, basename: str) -> bool:
        try:
            os.stat(basename, dir_fd=self._fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        except OSError:
            raise LtfsPinningError from None
        return False

    @staticmethod
    def _receipt_file_snapshot(status) -> tuple[int, ...]:
        return (
            status.st_dev,
            status.st_ino,
            status.st_mode,
            status.st_nlink,
            status.st_uid,
            status.st_gid,
            status.st_size,
            status.st_mtime_ns,
        )

    def _read_receipt_file(self, basename: str) -> tuple[dict[str, object], bytes]:
        fd = -1
        try:
            fd = os.open(
                basename,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._fd,
            )
            before = _fstat(fd)
            snapshot = self._receipt_file_snapshot(before)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != 0
                or before.st_gid != 0
                or before.st_nlink != 1
                or not 0 < before.st_size <= _MAX_STANDALONE_RECEIPT_BYTES
                or self._receipt_file_snapshot(_stat_path(self._path / basename))
                != snapshot
            ):
                raise LtfsPinningError
            payload = os.read(fd, _MAX_STANDALONE_RECEIPT_BYTES + 1)
            if (
                not payload
                or len(payload) > _MAX_STANDALONE_RECEIPT_BYTES
                or os.read(fd, 1)
                or self._receipt_file_snapshot(_fstat(fd)) != snapshot
                or self._receipt_file_snapshot(_stat_path(self._path / basename))
                != snapshot
            ):
                raise LtfsPinningError
            source = json.loads(
                payload.decode("ascii", errors="strict"),
                object_pairs_hook=self._reject_duplicate_pairs,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            raise LtfsPinningError from None
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        if type(source) is not dict:
            raise LtfsPinningError
        canonical = (
            json.dumps(source, ensure_ascii=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if canonical != payload:
            raise LtfsPinningError
        return source, payload

    def wait_ready(
        self,
        *,
        operation_id: str,
        owner_generation: int,
        request_sha256: str,
        expected_media_identity_sha256: str,
        expected_read_only: bool,
        timeout: float,
        child_running: Callable[[], bool] | None = None,
    ) -> LtfsReadyReceipt:
        self._assert_anchor()
        basename = self._target_basename(
            operation_id=operation_id,
            owner_generation=owner_generation,
            request_sha256=request_sha256,
        )
        if (
            type(timeout) not in (int, float)
            or type(timeout) is bool
            or not 0 < float(timeout) <= 86_400
            or (child_running is not None and not callable(child_running))
        ):
            raise LtfsPinningError
        deadline = time.monotonic() + float(timeout)
        while self._path_absent(f"{basename}.ready") or not self._path_absent(
            f"{basename}.ready.tmp"
        ):
            try:
                if child_running is not None and child_running() is not True:
                    raise LtfsPinningError
            except LtfsPinningError:
                raise
            except Exception:
                raise LtfsPinningError from None
            if time.monotonic() >= deadline:
                raise LtfsPinningError
            time.sleep(0.02)
        source, _payload = self._read_receipt_file(f"{basename}.ready")
        if tuple(source) != (
            "schema",
            "stage",
            "operation_id",
            "volume_uuid",
            "prior_generation",
            "read_only",
            "drive_serial",
            "mam_barcode",
            "mam_volume_serial",
            "ltfs_volume_label",
        ):
            raise LtfsPinningError
        ready = LtfsReadyReceipt(
            schema=self._exact_uint64(source["schema"]),
            stage=source["stage"],
            operation_id=_validate_receipt_uuid(source["operation_id"]),
            volume_uuid=_validate_receipt_uuid(source["volume_uuid"]),
            prior_generation=self._exact_uint64(source["prior_generation"]),
            read_only=source["read_only"],
            drive_serial=_validate_ready_identity(source["drive_serial"]),
            mam_barcode=_validate_ready_identity(source["mam_barcode"], maximum=32),
            mam_volume_serial=_validate_ready_identity(
                source["mam_volume_serial"], maximum=32
            ),
            ltfs_volume_label=_validate_ready_identity(source["ltfs_volume_label"]),
        )
        if (
            ready.schema != 1
            or ready.stage != "ready"
            or ready.operation_id != operation_id
            or ready.prior_generation == 0
            or type(ready.read_only) is not bool
            or ready.read_only is not expected_read_only
            or _ready_media_identity_sha256(ready) != expected_media_identity_sha256
            or not self._path_absent(basename)
            or not self._path_absent(f"{basename}.pending")
            or not self._path_absent(f"{basename}.ready.tmp")
            or not self._path_absent(f"{basename}.pending.tmp")
            or not self._path_absent(f"{basename}.tmp")
        ):
            raise LtfsPinningError
        self._assert_anchor()
        return ready

    @staticmethod
    def _exact_uint64(value: object) -> int:
        if type(value) is not int or not 0 <= value < 1 << 64:
            raise LtfsPinningError
        return value

    @staticmethod
    def _exact_int32(value: object) -> int:
        if type(value) is not int or not -(1 << 31) <= value < 1 << 31:
            raise LtfsPinningError
        return value

    @staticmethod
    def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise LtfsPinningError
            result[key] = value
        return result

    def read_terminal(
        self,
        *,
        operation_id: str,
        owner_generation: int,
        request_sha256: str,
    ) -> LtfsStandaloneReceipt:
        self._assert_anchor()
        basename = self._target_basename(
            operation_id=operation_id,
            owner_generation=owner_generation,
            request_sha256=request_sha256,
        )
        fd = -1
        try:
            fd = os.open(
                basename,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self._fd,
            )
            before = _fstat(fd)
            path_before = _stat_path(self._path / basename)
            snapshot = self._receipt_file_snapshot(before)
            if (
                not stat.S_ISREG(before.st_mode)
                or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != 0
                or before.st_gid != 0
                or before.st_nlink != 1
                or not 0 < before.st_size <= _MAX_STANDALONE_RECEIPT_BYTES
                or self._receipt_file_snapshot(path_before) != snapshot
            ):
                raise LtfsPinningError
            payload = os.read(fd, _MAX_STANDALONE_RECEIPT_BYTES + 1)
            if (
                not payload
                or len(payload) > _MAX_STANDALONE_RECEIPT_BYTES
                or os.read(fd, 1)
                or self._receipt_file_snapshot(_fstat(fd)) != snapshot
                or self._receipt_file_snapshot(_stat_path(self._path / basename))
                != snapshot
            ):
                raise LtfsPinningError
            source = json.loads(
                payload.decode("ascii", errors="strict"),
                object_pairs_hook=self._reject_duplicate_pairs,
            )
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
            raise LtfsPinningError from None
        finally:
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        if type(source) is not dict or tuple(source) != _STANDALONE_RECEIPT_KEYS:
            raise LtfsPinningError
        canonical = (
            json.dumps(source, ensure_ascii=True, separators=(",", ":")) + "\n"
        ).encode("ascii")
        if canonical != payload:
            raise LtfsPinningError
        phases = source["phase_duration_ns"]
        if type(phases) is not list or len(phases) != 11:
            raise LtfsPinningError
        checked_phases = tuple(self._exact_uint64(value) for value in phases)
        receipt = LtfsStandaloneReceipt(
            schema=self._exact_uint64(source["schema"]),
            stage=source["stage"],
            operation_id=_validate_receipt_uuid(source["operation_id"]),
            volume_uuid=_validate_receipt_uuid(source["volume_uuid"]),
            prior_generation=self._exact_uint64(source["prior_generation"]),
            new_generation=self._exact_uint64(source["new_generation"]),
            bytes_valid=source["bytes_valid"],
            bytes=self._exact_uint64(source["bytes"]),
            files_valid=source["files_valid"],
            files=self._exact_uint64(source["files"]),
            phase_duration_ns=checked_phases,
            capture_duration_ns=self._exact_uint64(source["capture_duration_ns"]),
            device_close_duration_ns=self._exact_uint64(
                source["device_close_duration_ns"]
            ),
            device_close_result_valid=source["device_close_result_valid"],
            device_close_result=self._exact_int32(source["device_close_result"]),
            catalog_ack_duration_ns=self._exact_uint64(
                source["catalog_ack_duration_ns"]
            ),
            media_committed=source["media_committed"],
            catalog_acknowledged=source["catalog_acknowledged"],
            cleanup_failed=source["cleanup_failed"],
            result=self._exact_int32(source["result"]),
            terminal_sha256=hashlib.sha256(payload).hexdigest(),
        )
        bool_fields = (
            receipt.bytes_valid,
            receipt.files_valid,
            receipt.device_close_result_valid,
            receipt.media_committed,
            receipt.catalog_acknowledged,
            receipt.cleanup_failed,
        )
        if (
            receipt.schema != 1
            or receipt.stage != "terminal"
            or receipt.operation_id != operation_id
            or any(type(value) is not bool for value in bool_fields)
            or receipt.new_generation == 0
            or receipt.new_generation < receipt.prior_generation
            or (not receipt.bytes_valid and receipt.bytes != 0)
            or (not receipt.files_valid and receipt.files != 0)
            or receipt.media_committed is not True
            or receipt.catalog_acknowledged is not True
            or receipt.device_close_result_valid is not True
            or receipt.cleanup_failed is not (receipt.result != 0)
            or receipt.cleanup_failed is not False
            or receipt.result != 0
            or receipt.device_close_result != 0
            or not self._path_absent(f"{basename}.ready")
            or not self._path_absent(f"{basename}.pending")
            or not self._path_absent(f"{basename}.tmp")
        ):
            raise LtfsPinningError
        self._assert_anchor()
        return receipt

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        fd = self._fd
        self._fd = -1
        with contextlib.suppress(OSError):
            os.close(fd)


def _read_scsi_serial(device_root: Path) -> str:
    try:
        data = (device_root / "vpd_pg80").read_bytes()
        if 4 <= len(data) <= 4096:
            length = int.from_bytes(data[2:4], "big")
            if length <= len(data) - 4:
                serial = data[4 : 4 + length].decode("ascii", errors="strict").strip()
                if serial:
                    return _validate_serial(serial)
    except (OSError, UnicodeError):
        pass
    try:
        serial = (device_root / "serial").read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        raise LtfsPinningError from None
    return _validate_serial(serial)


def _validate_serial(serial: str) -> str:
    if (
        type(serial) is not str
        or not serial
        or len(serial) > 256
        or not serial.isascii()
        or not serial.isprintable()
        or serial != serial.strip()
    ):
        raise LtfsPinningError
    return serial


def _stable_device_from_fd(
    fd: int,
    role: DeviceRole,
    by_id_basename: str,
    sys_class: Path,
) -> tuple[str, str]:
    try:
        device_name = Path(f"/proc/self/fd/{fd}").resolve(strict=True).name
    except (OSError, RuntimeError):
        raise LtfsPinningError from None
    if (role == "tape" and not device_name.startswith(("st", "nst"))) or (
        role == "scsi" and not device_name.startswith("sg")
    ):
        raise LtfsPinningError
    class_name = "scsi_tape" if role == "tape" else "scsi_generic"
    device_root = sys_class / class_name / device_name / "device"
    try:
        canonical_unit = device_root.resolve(strict=True)
    except (OSError, RuntimeError):
        raise LtfsPinningError from None
    serial = _read_scsi_serial(device_root)
    stable_json = json.dumps(
        {"by_id": by_id_basename, "serial": serial},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    unit_sha256 = hashlib.sha256(
        b"lto-scsi-unit-v1\0" + str(canonical_unit).encode("utf-8")
    ).hexdigest()
    return stable_json, unit_sha256


def _hash_pinned_tool(fd: int, expected_status) -> str:
    read_fd = -1
    try:
        read_fd = os.open(f"/proc/self/fd/{fd}", _READ_FLAGS)
        before = _fstat(read_fd)
        if _tool_snapshot(before) != _tool_snapshot(expected_status):
            raise LtfsPinningError
        digest = hashlib.sha256()
        while True:
            chunk = os.read(read_fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after = _fstat(read_fd)
        if _tool_snapshot(after) != _tool_snapshot(before):
            raise LtfsPinningError
        return digest.hexdigest()
    except (OSError, ValueError):
        raise LtfsPinningError from None
    finally:
        if read_fd >= 0:
            try:
                os.close(read_fd)
            except OSError:
                pass


def _duplicate_fd(fd: int) -> int:
    if type(fd) is not int or fd < 0:
        raise LtfsPinningError
    try:
        return fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
    except (OSError, ValueError):
        raise LtfsPinningError from None


def _device_identity_from_status(status, role: DeviceRole) -> str:
    if role not in {"tape", "scsi"}:
        raise LtfsPinningError
    _validate_device_status(status)
    return _digest(
        b"lto-device-fd-v1",
        {
            "device": status.st_dev,
            "group": status.st_gid,
            "inode": status.st_ino,
            "mode": stat.S_IMODE(status.st_mode),
            "owner": status.st_uid,
            "role": role,
            "rdev": status.st_rdev,
            "type": stat.S_IFMT(status.st_mode),
        },
    )


def device_fd_identity_sha256(fd: int, role: DeviceRole) -> str:
    """Hash one already-open device descriptor without reopening a path."""

    if type(fd) is not int:
        raise LtfsPinningError
    try:
        before = _fstat(fd)
        result = _device_identity_from_status(before, role)
        after = _fstat(fd)
    except (OSError, ValueError, TypeError, AttributeError):
        raise LtfsPinningError from None
    if _device_snapshot(after) != _device_snapshot(before):
        raise LtfsPinningError
    return result


@dataclass(frozen=True)
class _PinnedDeviceTarget:
    role: DeviceRole
    fd: int = field(repr=False)
    configured_path: Path = field(repr=False)
    link_snapshot: tuple[int, ...] = field(repr=False)
    kernel_snapshot: tuple[int, ...] = field(repr=False)
    target_identity_sha256: str
    fd_identity_sha256: str
    stable_identity_json: str = field(repr=False)
    scsi_unit_identity_sha256: str
    sys_class: Path = field(repr=False)


@dataclass(frozen=True)
class PinnedToolIdentity:
    role: Literal["ltfs", "fusermount"]
    fd: int = field(repr=False)
    device: int
    inode: int
    size: int
    mtime_ns: int
    content_sha256: str
    identity_sha256: str
    _path: Path = field(repr=False, compare=False)
    _snapshot: tuple[int, ...] = field(repr=False, compare=False)


def _assert_tool_anchor(tool: PinnedToolIdentity, fd: int) -> None:
    try:
        descriptor_status = _fstat(fd)
        path_status = _stat_path(tool._path)
    except OSError:
        raise LtfsPinningError from None
    _validate_tool_status(descriptor_status, tool.role)
    if (
        _tool_snapshot(descriptor_status) != tool._snapshot
        or _tool_snapshot(path_status) != tool._snapshot
        or _hash_pinned_tool(fd, descriptor_status) != tool.content_sha256
        or _tool_snapshot(_fstat(fd)) != tool._snapshot
        or _tool_snapshot(_stat_path(tool._path)) != tool._snapshot
    ):
        raise LtfsPinningError


@dataclass(frozen=True)
class _PinnedMountRoot:
    fd: int = field(repr=False)
    path: Path
    path_sha256: str
    snapshot: tuple[int, ...] = field(repr=False)


@dataclass
class ValidatedLtfsSessionTargets:
    """Owned descriptor anchors returned only after all validation succeeds."""

    request: LtfsSessionRequest = field(repr=False)
    _ltfs: PinnedToolIdentity = field(repr=False)
    _fusermount: PinnedToolIdentity = field(repr=False)
    mount_path: Path
    _mount_snapshot: tuple[int, ...] = field(repr=False)
    _ltfs_fd: int = field(repr=False)
    _fusermount_fd: int = field(repr=False)
    tape_fd: int = field(repr=False)
    scsi_fd: int = field(repr=False)
    tape_fd_identity_sha256: str
    scsi_fd_identity_sha256: str
    _creation_token: object = field(repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        if self._creation_token is not _VALIDATED_CREATION_TOKEN:
            raise LtfsPinningError

    @property
    def ltfs_fd(self) -> int:
        if self._closed:
            raise LtfsPinningError
        _assert_tool_anchor(self._ltfs, self._ltfs_fd)
        return self._ltfs_fd

    @property
    def ltfs_exec_path(self) -> Path:
        return Path(f"/proc/self/fd/{self.ltfs_fd}")

    @property
    def fusermount_fd(self) -> int:
        if self._closed:
            raise LtfsPinningError
        _assert_tool_anchor(self._fusermount, self._fusermount_fd)
        return self._fusermount_fd

    @property
    def fusermount_exec_path(self) -> Path:
        return Path(f"/proc/self/fd/{self.fusermount_fd}")

    def assert_launch_anchors(self) -> None:
        """Revalidate every lease anchor immediately before privileged exec."""

        if self._closed:
            raise LtfsPinningError
        self._assert_tool_and_device_anchors()
        try:
            mount_status = _stat_path(self.mount_path)
            _validate_mount_status(mount_status)
            if _mount_snapshot(mount_status) != self._mount_snapshot:
                raise LtfsPinningError
        except (OSError, ValueError, TypeError, AttributeError):
            raise LtfsPinningError from None

    def assert_finalization_anchors(self) -> None:
        """Revalidate immutable tool and device leases after FUSE covers the root."""

        if self._closed:
            raise LtfsPinningError
        self._assert_tool_and_device_anchors()

    def _assert_tool_and_device_anchors(self) -> None:
        _assert_tool_anchor(self._ltfs, self._ltfs_fd)
        _assert_tool_anchor(self._fusermount, self._fusermount_fd)
        try:
            if (
                device_fd_identity_sha256(self.tape_fd, "tape")
                != self.tape_fd_identity_sha256
                or device_fd_identity_sha256(self.scsi_fd, "scsi")
                != self.scsi_fd_identity_sha256
            ):
                raise LtfsPinningError
        except (OSError, ValueError, TypeError, AttributeError):
            raise LtfsPinningError from None

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        descriptors = (
            self._ltfs_fd,
            self._fusermount_fd,
            self.tape_fd,
            self.scsi_fd,
        )
        self._ltfs_fd = -1
        self._fusermount_fd = -1
        self.tape_fd = -1
        self.scsi_fd = -1
        for fd in descriptors:
            try:
                os.close(fd)
            except OSError:
                pass


@dataclass(frozen=True)
class LtfsProcessObservation:
    pid: int
    start_ticks: int
    mount_namespace_sha256: str


@dataclass(frozen=True)
class LtfsMountObservation:
    target: Path
    fs_type: str
    source: str


@dataclass
class LtfsBlockedLaunch:
    pid: int
    pidfd: int = field(repr=False)
    gate_fd: int = field(repr=False)
    released: bool = False
    reaped: bool = False


def _decode_mountinfo_field(value: str) -> str:
    result = value
    for encoded, decoded in (("\\040", " "), ("\\011", "\t"), ("\\134", "\\")):
        result = result.replace(encoded, decoded)
    if "\\" in result or "\0" in result:
        raise LtfsLifecycleUnavailable
    return result


class ProcMountInfoProbe:
    """Bounded exact observer for the broker's host mount namespace."""

    def __init__(
        self,
        path: Path = Path("/proc/self/mountinfo"),
        *,
        timeout: float = 1_800.0,
        interval: float = 0.05,
    ) -> None:
        if (
            not isinstance(path, Path)
            or not path.is_absolute()
            or type(timeout) not in (int, float)
            or type(timeout) is bool
            or not 0 < float(timeout) <= 86_400.0
            or type(interval) not in (int, float)
            or type(interval) is bool
            or not 0 < float(interval) <= 1.0
        ):
            raise LtfsLifecycleUnavailable
        self._path = path
        self._timeout = float(timeout)
        self._interval = float(interval)

    def _matching(self, target: Path) -> tuple[LtfsMountObservation, ...]:
        try:
            payload = self._path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise LtfsLifecycleUnavailable from None
        matches: list[LtfsMountObservation] = []
        for line in payload.splitlines():
            fields = line.split()
            try:
                separator = fields.index("-")
            except ValueError:
                raise LtfsLifecycleUnavailable from None
            if len(fields) < 6 or separator + 2 >= len(fields):
                raise LtfsLifecycleUnavailable
            mount_target = Path(_decode_mountinfo_field(fields[4]))
            if mount_target == target:
                matches.append(
                    LtfsMountObservation(
                        mount_target,
                        fields[separator + 1],
                        _decode_mountinfo_field(fields[separator + 2]),
                    )
                )
        return tuple(matches)

    def await_mounted(self, target: Path) -> LtfsMountObservation:
        deadline = time.monotonic() + self._timeout
        while True:
            matches = self._matching(target)
            if matches:
                if (
                    len(matches) != 1
                    or matches[0].fs_type != "fuse.ltfs"
                    or matches[0].source != "ltfs"
                ):
                    raise LtfsLifecycleUnavailable
                return matches[0]
            if time.monotonic() >= deadline:
                raise LtfsLifecycleUnavailable
            time.sleep(self._interval)

    def await_unmounted(self, target: Path) -> bool:
        deadline = time.monotonic() + self._timeout
        while True:
            matches = self._matching(target)
            if not matches:
                return True
            if (
                len(matches) != 1
                or matches[0].fs_type != "fuse.ltfs"
                or matches[0].source != "ltfs"
            ):
                raise LtfsLifecycleUnavailable
            if time.monotonic() >= deadline:
                raise LtfsLifecycleUnavailable
            time.sleep(self._interval)


class ProcProcessProbe:
    """Read one exact process start identity and mount namespace."""

    @staticmethod
    def observe(pid: int) -> LtfsProcessObservation | None:
        if type(pid) is not int or not 0 < pid < 1 << 31:
            raise LtfsLifecycleUnavailable
        try:
            payload = Path(f"/proc/{pid}/stat").read_bytes()
            namespace = os.readlink(f"/proc/{pid}/ns/mnt")
        except FileNotFoundError:
            return None
        except OSError:
            raise LtfsLifecycleUnavailable from None
        prefix = str(pid).encode("ascii") + b" ("
        closing = payload.rfind(b") ")
        fields = payload[closing + 2 :].split() if closing >= len(prefix) else ()
        if (
            not payload.startswith(prefix)
            or len(fields) < 20
            or not fields[19].isdigit()
        ):
            raise LtfsLifecycleUnavailable
        start_ticks = int(fields[19])
        if not 0 < start_ticks < 1 << 63:
            raise LtfsLifecycleUnavailable
        namespace_sha256 = hashlib.sha256(
            b"lto-mount-namespace-v1\0" + namespace.encode("ascii", errors="strict")
        ).hexdigest()
        return LtfsProcessObservation(pid, start_ticks, namespace_sha256)


class BrokerLtfsExecutor:
    """Broker-local blocked fork/exec with no caller-controlled command seam."""

    _READY_TIMEOUT = 2.0
    _REAP_TIMEOUT = 10.0

    @staticmethod
    def _validate_exec(argv: tuple[str, ...], pass_fds: tuple[int, ...]) -> None:
        if (
            type(argv) is not tuple
            or not argv
            or not all(
                type(value) is str and value and "\0" not in value for value in argv
            )
            or type(pass_fds) is not tuple
            or not pass_fds
            or len(set(pass_fds)) != len(pass_fds)
            or not all(type(fd) is int and fd >= 3 for fd in pass_fds)
            or argv[0] != f"/proc/self/fd/{pass_fds[0]}"
        ):
            raise LtfsLifecycleUnavailable
        try:
            for fd in pass_fds:
                os.fstat(fd)
        except OSError:
            raise LtfsLifecycleUnavailable from None

    @staticmethod
    def _close_child_fds(keep: tuple[int, ...]) -> None:
        keep_set = set(keep)
        for path in tuple(Path("/proc/self/fd").iterdir()):
            if not path.name.isdigit():
                continue
            fd = int(path.name)
            if fd not in keep_set:
                with contextlib.suppress(OSError):
                    os.close(fd)

    @classmethod
    def _wait_child(cls, pid: int, *, timeout: float) -> int:
        deadline = time.monotonic() + timeout
        while True:
            try:
                waited, status = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                raise LtfsLifecycleUnavailable from None
            if waited == pid:
                return status
            if time.monotonic() >= deadline:
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
                try:
                    waited, status = os.waitpid(pid, 0)
                except ChildProcessError:
                    raise LtfsLifecycleUnavailable from None
                if waited != pid:
                    raise LtfsLifecycleUnavailable
                return status
            time.sleep(0.02)

    def spawn_blocked(
        self, argv: tuple[str, ...], *, pass_fds: tuple[int, ...]
    ) -> LtfsBlockedLaunch:
        self._validate_exec(argv, pass_fds)
        gate_read = gate_write = ready_read = ready_write = null_fd = -1
        try:
            gate_read, gate_write = os.pipe2(os.O_CLOEXEC)
            ready_read, ready_write = os.pipe2(os.O_CLOEXEC)
            null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
            pid = os.fork()
        except OSError:
            for fd in (gate_read, gate_write, ready_read, ready_write, null_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            raise LtfsLifecycleUnavailable from None
        if pid == 0:  # pragma: no cover - production Linux integration boundary
            try:
                os.close(gate_write)
                os.close(ready_read)
                for standard in (0, 1, 2):
                    os.dup2(null_fd, standard)
                for fd in pass_fds:
                    os.set_inheritable(fd, True)
                self._close_child_fds((0, 1, 2, gate_read, ready_write, *pass_fds))
                os.write(ready_write, b"1")
                os.close(ready_write)
                released = os.read(gate_read, 1)
                os.close(gate_read)
                if released != b"1":
                    os._exit(125)
                os.execv(argv[0], list(argv))
            except BaseException:  # noqa: BLE001
                os._exit(126)
        os.close(gate_read)
        os.close(ready_write)
        os.close(null_fd)
        pidfd = -1
        try:
            readable, _, _ = select.select((ready_read,), (), (), self._READY_TIMEOUT)
            if not readable or os.read(ready_read, 1) != b"1":
                raise LtfsLifecycleUnavailable
            pidfd = os.pidfd_open(pid, 0)
            return LtfsBlockedLaunch(pid, pidfd, gate_write)
        except (OSError, ValueError, LtfsLifecycleUnavailable):
            with contextlib.suppress(OSError):
                os.close(gate_write)
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(pid, 0)
            if pidfd >= 0:
                with contextlib.suppress(OSError):
                    os.close(pidfd)
            raise LtfsLifecycleUnavailable from None
        finally:
            os.close(ready_read)

    @staticmethod
    def release_launch(launch: LtfsBlockedLaunch) -> None:
        if type(launch) is not LtfsBlockedLaunch or launch.released or launch.reaped:
            raise LtfsLifecycleUnavailable
        try:
            if os.write(launch.gate_fd, b"1") != 1:
                raise OSError
            os.close(launch.gate_fd)
        except OSError:
            raise LtfsLifecycleUnavailable from None
        launch.gate_fd = -1
        launch.released = True

    def run_fusermount(
        self, argv: tuple[str, ...], *, pass_fds: tuple[int, ...]
    ) -> int:
        self._validate_exec(argv, pass_fds)
        pid = os.fork()
        if pid == 0:  # pragma: no cover - production Linux integration boundary
            try:
                null_fd = os.open("/dev/null", os.O_RDWR | os.O_CLOEXEC)
                for standard in (0, 1, 2):
                    os.dup2(null_fd, standard)
                for fd in pass_fds:
                    os.set_inheritable(fd, True)
                self._close_child_fds((0, 1, 2, *pass_fds))
                os.execv(argv[0], list(argv))
            except BaseException:  # noqa: BLE001
                os._exit(126)
        status = self._wait_child(pid, timeout=self._REAP_TIMEOUT)
        return os.waitstatus_to_exitcode(status)

    def terminate_reap(
        self,
        launch: LtfsBlockedLaunch,
        *,
        pid: int,
        start_ticks: int,
    ) -> bool:
        if (
            type(launch) is not LtfsBlockedLaunch
            or launch.pid != pid
            or type(start_ticks) is not int
            or start_ticks <= 0
            or launch.reaped
        ):
            raise LtfsLifecycleUnavailable
        if launch.gate_fd >= 0:
            with contextlib.suppress(OSError):
                os.close(launch.gate_fd)
            launch.gate_fd = -1
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            raise LtfsLifecycleUnavailable from None
        if waited == 0:
            status = self._wait_child(pid, timeout=self._REAP_TIMEOUT)
        launch.reaped = True
        with contextlib.suppress(OSError):
            os.close(launch.pidfd)
        launch.pidfd = -1
        if os.waitstatus_to_exitcode(status) != 0:
            raise LtfsLifecycleUnavailable
        return True

    def reap_natural(
        self,
        launch: LtfsBlockedLaunch,
        *,
        pid: int,
        start_ticks: int,
        timeout: float = 300.0,
    ) -> bool:
        """Wait for finalization without ever signalling the tape-writing child."""

        if (
            type(launch) is not LtfsBlockedLaunch
            or launch.pid != pid
            or type(start_ticks) is not int
            or start_ticks <= 0
            or launch.reaped
            or type(timeout) not in (int, float)
            or type(timeout) is bool
            or not 0 < float(timeout) <= 86_400
        ):
            raise LtfsLifecycleUnavailable
        if launch.gate_fd >= 0:
            raise LtfsLifecycleUnavailable
        try:
            readable, _, _ = select.select((launch.pidfd,), (), (), float(timeout))
            if not readable:
                raise LtfsLifecycleUnavailable
            waited, status = os.waitpid(pid, 0)
        except (OSError, ChildProcessError, ValueError):
            raise LtfsLifecycleUnavailable from None
        if waited != pid:
            raise LtfsLifecycleUnavailable
        launch.reaped = True
        with contextlib.suppress(OSError):
            os.close(launch.pidfd)
        launch.pidfd = -1
        if os.waitstatus_to_exitcode(status) != 0:
            raise LtfsLifecycleUnavailable
        return True


class LtfsSessionPins:
    """Startup-pinned, closed authority for one configured LTFS target."""

    def __init__(
        self,
        *,
        ltfs: PinnedToolIdentity,
        fusermount: PinnedToolIdentity,
        mount: _PinnedMountRoot,
        tape_target: _PinnedDeviceTarget,
        scsi_target: _PinnedDeviceTarget,
        _creation_token: object,
    ) -> None:
        if _creation_token is not _PINSET_CREATION_TOKEN:
            raise LtfsPinningError
        self._ltfs = ltfs
        self._fusermount = fusermount
        self._mount = mount
        self._tape_target = tape_target
        self._scsi_target = scsi_target
        self._closed = False

    @property
    def ltfs_tool_identity_sha256(self) -> str:
        return self._ltfs.identity_sha256

    @property
    def fusermount_tool_identity_sha256(self) -> str:
        return self._fusermount.identity_sha256

    @classmethod
    def open(
        cls,
        *,
        ltfs_path: Path = Path("/usr/bin/ltfs"),
        fusermount_path: Path = Path("/usr/bin/fusermount"),
        mount_path: Path,
        tape_device_path: Path,
        scsi_device_path: Path,
        device_root: Path = Path("/dev"),
        sys_class: Path = Path("/sys/class"),
    ) -> LtfsSessionPins:
        opened: list[int] = []
        try:
            ltfs = cls._pin_tool("ltfs", ltfs_path)
            opened.append(ltfs.fd)
            fusermount = cls._pin_tool("fusermount", fusermount_path)
            opened.append(fusermount.fd)
            mount = cls._pin_mount(mount_path)
            opened.append(mount.fd)
            tape_target = cls._pin_device_target(
                "tape", tape_device_path, device_root, sys_class
            )
            opened.append(tape_target.fd)
            scsi_target = cls._pin_device_target(
                "scsi", scsi_device_path, device_root, sys_class
            )
            opened.append(scsi_target.fd)
            if (
                tape_target.target_identity_sha256 == scsi_target.target_identity_sha256
                or tape_target.fd_identity_sha256 == scsi_target.fd_identity_sha256
                or tape_target.scsi_unit_identity_sha256
                != scsi_target.scsi_unit_identity_sha256
            ):
                raise LtfsPinningError
            pins = cls(
                ltfs=ltfs,
                fusermount=fusermount,
                mount=mount,
                tape_target=tape_target,
                scsi_target=scsi_target,
                _creation_token=_PINSET_CREATION_TOKEN,
            )
            pins._assert_static_anchors()
            return pins
        except (
            LtfsPinningError,
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
        ):
            for fd in opened:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise LtfsPinningError from None

    @staticmethod
    def _pin_tool(
        role: Literal["ltfs", "fusermount"], path: Path
    ) -> PinnedToolIdentity:
        exact = _exact_path(path, directory=False)
        fd = -1
        try:
            fd = os.open(exact, _TOOL_FLAGS)
            descriptor_status = _fstat(fd)
            path_status = _stat_path(exact)
            _validate_tool_status(descriptor_status, role)
            if _tool_snapshot(path_status) != _tool_snapshot(descriptor_status):
                raise LtfsPinningError
            content_sha256 = _hash_pinned_tool(fd, descriptor_status)
            final_status = _fstat(fd)
            final_path_status = _stat_path(exact)
            if _tool_snapshot(final_status) != _tool_snapshot(
                descriptor_status
            ) or _tool_snapshot(final_path_status) != _tool_snapshot(descriptor_status):
                raise LtfsPinningError
            identity_sha256 = _digest(
                b"lto-pinned-tool-v1",
                {
                    "content_sha256": content_sha256,
                    "device": descriptor_status.st_dev,
                    "inode": descriptor_status.st_ino,
                    "mtime_ns": descriptor_status.st_mtime_ns,
                    "role": role,
                    "size": descriptor_status.st_size,
                },
            )
            return PinnedToolIdentity(
                role=role,
                fd=fd,
                device=descriptor_status.st_dev,
                inode=descriptor_status.st_ino,
                size=descriptor_status.st_size,
                mtime_ns=descriptor_status.st_mtime_ns,
                content_sha256=content_sha256,
                identity_sha256=identity_sha256,
                _path=exact,
                _snapshot=_tool_snapshot(descriptor_status),
            )
        except (
            LtfsPinningError,
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
        ):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise LtfsPinningError from None

    @staticmethod
    def _pin_mount(path: Path) -> _PinnedMountRoot:
        exact = _exact_path(path, directory=True)
        fd = -1
        try:
            fd = os.open(exact, _MOUNT_FLAGS)
            descriptor_status = _fstat(fd)
            path_status = _stat_path(exact)
            _validate_mount_status(descriptor_status)
            if _mount_snapshot(path_status) != _mount_snapshot(descriptor_status):
                raise LtfsPinningError
            return _PinnedMountRoot(
                fd=fd,
                path=exact,
                path_sha256=_target_digest("mount-path", str(exact)),
                snapshot=_mount_snapshot(descriptor_status),
            )
        except (
            LtfsPinningError,
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
        ):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise LtfsPinningError from None

    @staticmethod
    def _pin_device_target(
        role: DeviceRole,
        path: Path,
        device_root: Path,
        sys_class: Path,
    ) -> _PinnedDeviceTarget:
        configured = _configured_device_path(path, role, device_root)
        fd = -1
        try:
            link_status = _stat_path(configured)
            link_snapshot = _link_snapshot(link_status)
            fd = os.open(configured, os.O_PATH | os.O_CLOEXEC)
            kernel_status = _fstat(fd)
            _validate_device_status(kernel_status)
            kernel_snapshot = _device_snapshot(kernel_status)
            stable_json, unit_sha256 = _stable_device_from_fd(
                fd, role, configured.name, sys_class
            )
            fd_sha256 = _device_identity_from_status(kernel_status, role)
            target_domain = "tape-device" if role == "tape" else "generic-scsi"
            target_sha256 = _target_digest(target_domain, stable_json)
            if (
                _link_snapshot(_stat_path(configured)) != link_snapshot
                or _device_snapshot(_fstat(fd)) != kernel_snapshot
            ):
                raise LtfsPinningError
            return _PinnedDeviceTarget(
                role=role,
                fd=fd,
                configured_path=configured,
                link_snapshot=link_snapshot,
                kernel_snapshot=kernel_snapshot,
                target_identity_sha256=target_sha256,
                fd_identity_sha256=fd_sha256,
                stable_identity_json=stable_json,
                scsi_unit_identity_sha256=unit_sha256,
                sys_class=sys_class,
            )
        except (
            LtfsPinningError,
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
        ):
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise LtfsPinningError from None

    def _assert_tool_intact(self, tool: PinnedToolIdentity) -> None:
        _assert_tool_anchor(tool, tool.fd)

    def assert_readiness_anchors(self) -> None:
        """Revalidate both executable anchors without touching media state."""

        if self._closed:
            raise LtfsPinningError
        self._assert_tool_intact(self._ltfs)
        self._assert_tool_intact(self._fusermount)

    def _assert_mount_intact(self) -> None:
        try:
            descriptor_status = _fstat(self._mount.fd)
            path_status = _stat_path(self._mount.path)
        except OSError:
            raise LtfsPinningError from None
        _validate_mount_status(descriptor_status)
        if (
            _mount_snapshot(descriptor_status) != self._mount.snapshot
            or _mount_snapshot(path_status) != self._mount.snapshot
        ):
            raise LtfsPinningError

    @staticmethod
    def _assert_device_target_intact(target: _PinnedDeviceTarget) -> None:
        reopened = -1
        try:
            link_status = _stat_path(target.configured_path)
            _validate_device_link_status(link_status)
            if _link_snapshot(link_status) != target.link_snapshot:
                raise LtfsPinningError
            pinned_status = _fstat(target.fd)
            if _device_snapshot(pinned_status) != target.kernel_snapshot:
                raise LtfsPinningError
            stable_json, unit_sha256 = _stable_device_from_fd(
                target.fd,
                target.role,
                target.configured_path.name,
                target.sys_class,
            )
            if (
                stable_json != target.stable_identity_json
                or unit_sha256 != target.scsi_unit_identity_sha256
                or _target_digest(
                    "tape-device" if target.role == "tape" else "generic-scsi",
                    stable_json,
                )
                != target.target_identity_sha256
            ):
                raise LtfsPinningError
            reopened = os.open(target.configured_path, os.O_PATH | os.O_CLOEXEC)
            if _device_snapshot(_fstat(reopened)) != target.kernel_snapshot:
                raise LtfsPinningError
            if (
                _link_snapshot(_stat_path(target.configured_path))
                != target.link_snapshot
            ):
                raise LtfsPinningError
        except (OSError, RuntimeError):
            raise LtfsPinningError from None
        finally:
            if reopened >= 0:
                try:
                    os.close(reopened)
                except OSError:
                    pass

    def _assert_static_anchors(self) -> None:
        if self._closed:
            raise LtfsPinningError
        self._assert_tool_intact(self._ltfs)
        self._assert_tool_intact(self._fusermount)
        self._assert_mount_intact()
        self._assert_device_target_intact(self._tape_target)
        self._assert_device_target_intact(self._scsi_target)
        if (
            self._tape_target.scsi_unit_identity_sha256
            != self._scsi_target.scsi_unit_identity_sha256
        ):
            raise LtfsPinningError

    @staticmethod
    def _validate_device_fd(
        fd: int,
        role: DeviceRole,
        policy: _PinnedDeviceTarget,
        request_fd_digest: str,
    ) -> tuple[str, tuple[int, ...]]:
        before = _fstat(fd)
        digest = _device_identity_from_status(before, role)
        after = _fstat(fd)
        snapshot = _device_snapshot(before)
        if (
            _device_snapshot(after) != snapshot
            or snapshot != policy.kernel_snapshot
            or digest != policy.fd_identity_sha256
            or digest != request_fd_digest
        ):
            raise LtfsPinningError
        return digest, snapshot

    def validate_request(
        self,
        request: LtfsSessionRequest,
        *,
        tape_fd: int,
        scsi_fd: int,
    ) -> ValidatedLtfsSessionTargets:
        ltfs_anchor = -1
        fusermount_anchor = -1
        tape_anchor = -1
        scsi_anchor = -1
        try:
            if type(request) is not LtfsSessionRequest or request.protocol_version != 1:
                raise LtfsPinningError
            if (
                request.mount_path_sha256 != self._mount.path_sha256
                or request.tape_device_identity_sha256
                != self._tape_target.target_identity_sha256
                or request.scsi_device_identity_sha256
                != self._scsi_target.target_identity_sha256
                or request.tape_fd_identity_sha256
                != self._tape_target.fd_identity_sha256
                or request.scsi_fd_identity_sha256
                != self._scsi_target.fd_identity_sha256
            ):
                raise LtfsPinningError
            self._assert_static_anchors()
            ltfs_anchor = _duplicate_fd(self._ltfs.fd)
            _assert_tool_anchor(self._ltfs, ltfs_anchor)
            fusermount_anchor = _duplicate_fd(self._fusermount.fd)
            _assert_tool_anchor(self._fusermount, fusermount_anchor)
            tape_anchor = _duplicate_fd(tape_fd)
            tape_digest, tape_snapshot = self._validate_device_fd(
                tape_anchor,
                "tape",
                self._tape_target,
                request.tape_fd_identity_sha256,
            )
            scsi_anchor = _duplicate_fd(scsi_fd)
            scsi_digest, scsi_snapshot = self._validate_device_fd(
                scsi_anchor,
                "scsi",
                self._scsi_target,
                request.scsi_fd_identity_sha256,
            )
            if tape_snapshot == scsi_snapshot or tape_snapshot[6] == scsi_snapshot[6]:
                raise LtfsPinningError
            self._assert_static_anchors()
            if (
                _device_snapshot(_fstat(tape_anchor)) != tape_snapshot
                or _device_snapshot(_fstat(scsi_anchor)) != scsi_snapshot
            ):
                raise LtfsPinningError
            result = ValidatedLtfsSessionTargets(
                request=request,
                _ltfs=self._ltfs,
                _fusermount=self._fusermount,
                mount_path=self._mount.path,
                _mount_snapshot=self._mount.snapshot,
                _ltfs_fd=ltfs_anchor,
                _fusermount_fd=fusermount_anchor,
                tape_fd=tape_anchor,
                scsi_fd=scsi_anchor,
                tape_fd_identity_sha256=tape_digest,
                scsi_fd_identity_sha256=scsi_digest,
                _creation_token=_VALIDATED_CREATION_TOKEN,
            )
            ltfs_anchor = -1
            fusermount_anchor = -1
            tape_anchor = -1
            scsi_anchor = -1
            return result
        except (
            LtfsPinningError,
            OSError,
            ValueError,
            TypeError,
            AttributeError,
            OverflowError,
        ):
            raise LtfsPinningError from None
        finally:
            for fd in (
                ltfs_anchor,
                fusermount_anchor,
                tape_anchor,
                scsi_anchor,
            ):
                if fd >= 0:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for fd in (
            self._ltfs.fd,
            self._fusermount.fd,
            self._mount.fd,
            self._tape_target.fd,
            self._scsi_target.fd,
        ):
            try:
                os.close(fd)
            except OSError:
                pass
