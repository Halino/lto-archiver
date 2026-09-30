from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .shares import EndpointPolicy, ShareValidationError

_SETTING_KEYS = frozenset(
    {
        "state_dir",
        "socket_path",
        "socket_group",
        "tape_device_path",
        "scsi_device_path",
        "mount_path",
        "managed_source_mount_root",
        "source_roots",
        "restore_roots",
        "share_endpoint_cidrs",
        "share_endpoint_dns_suffixes",
        "buffer_bytes",
    }
)
_GROUP_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,31}$")
_TAPE_ID_NAMESPACE = Path("/dev/tape/by-id")
_SCSI_DEVICE_ROOT = Path("/dev")
_SCSI_ALIAS_PREFIX = "lto-archiver-scsi-"
MANAGED_SOURCE_MOUNT_ROOT = Path("/mnt/lto-archiver/sources")


@dataclass(frozen=True)
class LinuxPaths:
    state_dir: Path
    catalog_file: Path
    backup_dir: Path
    migration_dir: Path
    socket_path: Path

    @classmethod
    def for_root(cls, root: Path, socket_path: Path) -> LinuxPaths:
        root = Path(root).resolve(strict=False)
        return cls(
            root,
            root / "catalog.db",
            root / "backups",
            root / "migrations",
            Path(socket_path),
        )

    @classmethod
    def from_settings(cls, settings: LinuxSettings) -> LinuxPaths:
        return cls.for_root(settings.state_dir, settings.socket_path)


@dataclass(frozen=True)
class LinuxSettings:
    state_dir: Path = Path("/var/lib/lto-archiver")
    socket_path: Path = Path("/run/lto-archiver/daemon.sock")
    socket_group: str = "lto-web"
    tape_device_path: Path = Path("/dev/tape/by-id/configure-drive-nst")
    scsi_device_path: Path = Path("/dev/lto-archiver-scsi-configure-drive")
    mount_path: Path = Path("/mnt/lto-archiver/tape")
    managed_source_mount_root: Path = MANAGED_SOURCE_MOUNT_ROOT
    source_roots: tuple[Path, ...] = ()
    restore_roots: tuple[Path, ...] = ()
    share_endpoint_cidrs: tuple[str, ...] = (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
        "fe80::/10",
    )
    share_endpoint_dns_suffixes: tuple[str, ...] = (".lan", ".local")
    buffer_bytes: int = 8 * 1024 * 1024

    def validate(self) -> None:
        paths = self._all_paths()
        if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
            raise ValidationError(
                "state, socket, device, mount, managed source, source, and "
                "restore paths must be absolute"
            )
        if self.managed_source_mount_root != MANAGED_SOURCE_MOUNT_ROOT:
            raise ValidationError(
                "managed_source_mount_root must be the packaged path "
                f"{MANAGED_SOURCE_MOUNT_ROOT}"
            )

        try:
            resolved_state = _resolved(self.state_dir)
            resolved_socket = _resolved(self.socket_path)
            resolved_mount = _resolved(self.mount_path)
            resolved_managed_source_mount_root = _resolved(
                self.managed_source_mount_root
            )
            resolved_roots = tuple(
                _resolved(path) for path in (*self.source_roots, *self.restore_roots)
            )
        except (OSError, RuntimeError) as exc:
            raise ValidationError(
                f"configured paths cannot be resolved: {exc}"
            ) from exc

        protected_paths = (
            resolved_state,
            resolved_socket,
            resolved_mount,
            resolved_managed_source_mount_root,
            *resolved_roots,
        )
        if any(
            _paths_overlap(left, right)
            for index, left in enumerate(protected_paths)
            for right in protected_paths[index + 1 :]
        ):
            raise ValidationError(
                "state, socket, mount, managed source, source, and restore paths "
                "must not overlap"
            )

        if not _is_stable_tape_id(self.tape_device_path) or not _is_stable_scsi_id(
            self.scsi_device_path
        ):
            raise ValidationError(
                "tape and generic-SCSI devices require stable device aliases"
            )
        if not isinstance(self.socket_group, str) or not _GROUP_NAME.fullmatch(
            self.socket_group
        ):
            raise ValidationError("socket_group must be a valid local group name")
        if isinstance(self.buffer_bytes, bool) or not isinstance(
            self.buffer_bytes, int
        ):
            raise ValidationError(
                "buffer_bytes must be an integer between 1 MiB and 64 MiB"
            )
        if not 1024 * 1024 <= self.buffer_bytes <= 64 * 1024 * 1024:
            raise ValidationError("buffer_bytes must be between 1 MiB and 64 MiB")
        if not (
            _is_string_collection(self.share_endpoint_cidrs)
            and _is_string_collection(self.share_endpoint_dns_suffixes)
        ):
            raise ValidationError(
                "share endpoint policy values must be string collections"
            )
        try:
            EndpointPolicy(
                tuple(self.share_endpoint_cidrs),
                tuple(self.share_endpoint_dns_suffixes),
            )
        except ShareValidationError as exc:
            raise ValidationError(f"invalid share endpoint policy: {exc}") from exc

    def safe_summary(self) -> dict[str, object]:
        return {
            "source_root_count": len(self.source_roots)
            if _is_path_collection(self.source_roots)
            else 0,
            "restore_root_count": len(self.restore_roots)
            if _is_path_collection(self.restore_roots)
            else 0,
            "buffer_bytes": self.buffer_bytes,
            "socket_group": self.socket_group,
            "stable_tape_id_configured": _is_stable_tape_id(self.tape_device_path),
            "stable_scsi_id_configured": _is_stable_scsi_id(self.scsi_device_path),
        }

    def _all_paths(self) -> tuple[Any, ...]:
        source_roots = (
            self.source_roots
            if _is_path_collection(self.source_roots)
            else (self.source_roots,)
        )
        restore_roots = (
            self.restore_roots
            if _is_path_collection(self.restore_roots)
            else (self.restore_roots,)
        )
        return (
            self.state_dir,
            self.socket_path,
            self.tape_device_path,
            self.scsi_device_path,
            self.mount_path,
            self.managed_source_mount_root,
            *source_roots,
            *restore_roots,
        )


def load_linux_settings(path: Path) -> LinuxSettings:
    try:
        with Path(path).open("rb") as stream:
            raw = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ValidationError(
            f"unable to load Linux settings from {path}: {exc}"
        ) from exc
    if not isinstance(raw, dict):  # pragma: no cover - tomllib always returns a table
        raise ValidationError("Linux settings must be a TOML table")

    unknown = sorted(set(raw) - _SETTING_KEYS)
    if unknown:
        raise ValidationError(f"unknown Linux settings key(s): {', '.join(unknown)}")
    try:
        values = dict(raw)
        for field in (
            "state_dir",
            "socket_path",
            "tape_device_path",
            "scsi_device_path",
            "mount_path",
            "managed_source_mount_root",
        ):
            if field in values:
                values[field] = _toml_path(values[field], field)
        for field in ("source_roots", "restore_roots"):
            if field in values:
                values[field] = _toml_paths(values[field], field)
        for field in ("share_endpoint_cidrs", "share_endpoint_dns_suffixes"):
            if field in values:
                values[field] = _toml_strings(values[field], field)
        settings = LinuxSettings(**values)
        settings.validate()
    except ValidationError:
        raise
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValidationError(f"invalid Linux settings: {exc}") from exc
    return settings


def _toml_path(value: object, field: str) -> Path:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be a TOML string path")
    return Path(value)


def _toml_paths(value: object, field: str) -> tuple[Path, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"{field} must be a TOML array of string paths")
    return tuple(Path(item) for item in value)


def _toml_strings(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValidationError(f"{field} must be a TOML array of strings")
    return tuple(value)


def _resolved(path: Path) -> Path:
    return path.resolve(strict=False)


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def _is_stable_tape_id(path: object) -> bool:
    return (
        isinstance(path, Path)
        and _lexical(path).parent == _lexical(_TAPE_ID_NAMESPACE)
        and _lexical(path).name.endswith("-nst")
        and len(_lexical(path).name) > 4
    )


def _is_stable_scsi_id(path: object) -> bool:
    if not isinstance(path, Path):
        return False
    candidate = _lexical(path)
    return (
        candidate.parent == _lexical(_SCSI_DEVICE_ROOT)
        and candidate.name.startswith(_SCSI_ALIAS_PREFIX)
        and len(candidate.name) > len(_SCSI_ALIAS_PREFIX)
    )


def _is_under_namespace(path: object, namespace: Path) -> bool:
    if not isinstance(path, Path) or not path.is_absolute():
        return False
    candidate = _lexical(path)
    namespace = _lexical(namespace)
    return candidate != namespace and candidate.is_relative_to(namespace)


def _lexical(path: Path) -> Path:
    """Normalize path components without dereferencing device symlinks."""

    return Path(os.path.normpath(str(path)))


def _is_path_collection(value: object) -> bool:
    return isinstance(value, (tuple, list))


def _is_string_collection(value: object) -> bool:
    return isinstance(value, (tuple, list)) and all(
        isinstance(item, str) for item in value
    )
