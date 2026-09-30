from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ltobackup.shares import (
    NfsShareConfig,
    ShareConfig,
    ShareValidationError,
    SmbShareConfig,
    derive_mount_target,
    normalize_share_id,
)


class SystemdMountError(RuntimeError):
    """A redacted transient-unit or mount-evidence failure."""

    def __init__(self, safe_error_code: str = "share_mount_failed") -> None:
        self.safe_error_code = safe_error_code
        super().__init__(safe_error_code)


class SystemdManager(Protocol):
    def start_transient_mount(
        self, unit_name: str, properties: tuple[tuple[str, object], ...]
    ) -> None: ...

    def stop_unit(self, unit_name: str) -> None: ...

    def unit_active(self, unit_name: str) -> bool: ...

    def list_mount_units(self) -> tuple[str, ...]: ...


class MountProbe(Protocol):
    def inspect(self, target: Path) -> MountEvidence | None: ...


class TargetDirectories(Protocol):
    def prepare(self, target: Path) -> bool: ...

    def cleanup_new(self, target: Path) -> None: ...


@dataclass(frozen=True)
class MountEvidence:
    target: Path
    filesystem_type: str
    source: str
    read_only: bool

    def __post_init__(self) -> None:
        if (
            not isinstance(self.target, Path)
            or not self.target.is_absolute()
            or type(self.filesystem_type) is not str
            or not self.filesystem_type
            or type(self.source) is not str
            or not self.source
            or type(self.read_only) is not bool
        ):
            raise ValueError("invalid mount evidence")

    @property
    def identity_sha256(self) -> str:
        canonical = json.dumps(
            {
                "filesystem_type": self.filesystem_type,
                "read_only": self.read_only,
                "source": self.source,
                "target": str(self.target),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(b"lto-share-mount-identity-v1\0" + canonical).hexdigest()


class ProcMountInfoProbe:
    def __init__(self, path: Path = Path("/proc/self/mountinfo")) -> None:
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("mountinfo path must be absolute")

    def inspect(self, target: Path) -> MountEvidence | None:
        try:
            payload = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SystemdMountError from None
        matches = []
        for line in payload.splitlines():
            fields = line.split()
            try:
                separator = fields.index("-")
            except ValueError:
                continue
            if separator < 6 or len(fields) < separator + 4:
                continue
            try:
                observed_target = Path(_decode_mountinfo(fields[4]))
                filesystem_type = fields[separator + 1]
                source = _decode_mountinfo(fields[separator + 2])
                mount_options = set(fields[5].split(","))
                super_options = set(fields[separator + 3].split(","))
            except (UnicodeError, ValueError):
                raise SystemdMountError from None
            if observed_target == target:
                matches.append(
                    MountEvidence(
                        observed_target,
                        filesystem_type,
                        source,
                        "ro" in mount_options or "ro" in super_options,
                    )
                )
        if len(matches) > 1:
            raise SystemdMountError("share_identity_changed")
        return matches[0] if matches else None

    def targets_under(self, root: Path) -> tuple[Path, ...]:
        root = Path(root)
        if not root.is_absolute():
            raise SystemdMountError
        try:
            payload = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SystemdMountError from None
        lines = [line for line in payload.splitlines() if line.strip()]
        if not lines:
            raise SystemdMountError
        targets: set[Path] = set()
        for line in lines:
            fields = line.split()
            try:
                separator = fields.index("-", 6)
                major, colon, minor = fields[2].partition(":")
                if (
                    len(fields) < 10
                    or separator < 6
                    or len(fields) < separator + 4
                    or not fields[0].isdigit()
                    or not fields[1].isdigit()
                    or colon != ":"
                    or not major.isdigit()
                    or not minor.isdigit()
                    or not fields[3].startswith("/")
                    or not fields[4].startswith("/")
                ):
                    raise ValueError
                target = Path(_decode_mountinfo(fields[4]))
            except (IndexError, UnicodeError, ValueError):
                raise SystemdMountError from None
            if target != root and target.is_relative_to(root):
                targets.add(target)
        return tuple(sorted(targets, key=str))


class AnchoredTargetDirectories:
    """Create fixed per-share mountpoints beneath one trusted root."""

    def __init__(self, root: Path, *, owner_uid: int, owner_gid: int) -> None:
        self.root = Path(root)
        if (
            not self.root.is_absolute()
            or type(owner_uid) is not int
            or type(owner_gid) is not int
            or not 0 <= owner_uid < 1 << 32
            or not 0 <= owner_gid < 1 << 32
        ):
            raise ValueError("invalid target directory policy")
        self.owner_uid = owner_uid
        self.owner_gid = owner_gid

    def prepare(self, target: Path) -> bool:
        name = self._target_name(target)
        root_fd = self._open_root()
        created = False
        try:
            try:
                os.mkdir(name, mode=0o750, dir_fd=root_fd)
                created = True
            except FileExistsError:
                pass
            target_fd = os.open(
                name,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=root_fd,
            )
            try:
                if created:
                    os.fchown(target_fd, self.owner_uid, self.owner_gid)
                    os.fchmod(target_fd, 0o750)
                self._validate_directory(os.fstat(target_fd), mode=0o750)
            finally:
                os.close(target_fd)
            return created
        except (OSError, ValueError):
            if created:
                try:
                    os.rmdir(name, dir_fd=root_fd)
                except OSError:
                    pass
            raise SystemdMountError("share_mount_failed") from None
        finally:
            os.close(root_fd)

    def cleanup_new(self, target: Path) -> None:
        name = self._target_name(target)
        try:
            root_fd = self._open_root()
            try:
                status = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                self._validate_directory(status, mode=0o750)
                os.rmdir(name, dir_fd=root_fd)
            finally:
                os.close(root_fd)
        except (OSError, ValueError):
            raise SystemdMountError("share_recovery_required") from None

    def _open_root(self) -> int:
        try:
            descriptor = os.open(
                self.root,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            try:
                self._validate_directory(os.fstat(descriptor), mode=0o750)
            except Exception:
                os.close(descriptor)
                raise
            return descriptor
        except (OSError, ValueError):
            raise SystemdMountError("share_mount_failed") from None

    def _validate_directory(self, status: os.stat_result, *, mode: int) -> None:
        if (
            not stat.S_ISDIR(status.st_mode)
            or status.st_uid != self.owner_uid
            or status.st_gid != self.owner_gid
            or stat.S_IMODE(status.st_mode) != mode
        ):
            raise ValueError("untrusted target directory")

    def _target_name(self, target: Path) -> str:
        candidate = Path(target)
        if candidate.parent != self.root or candidate.name in {"", ".", ".."}:
            raise SystemdMountError("share_mount_failed")
        return candidate.name


class SystemdMountAdapter:
    """Construct and verify only deterministic read-only transient mounts."""

    def __init__(
        self,
        manager: SystemdManager,
        probe: MountProbe,
        *,
        managed_root: Path,
        service_uid: int,
        service_gid: int,
        timeout_seconds: int = 90,
        stop_timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 0.05,
        target_directories: TargetDirectories | None = None,
    ) -> None:
        self.manager = manager
        self.probe = probe
        self.managed_root = Path(managed_root)
        if (
            not self.managed_root.is_absolute()
            or type(service_uid) is not int
            or type(service_gid) is not int
            or not 0 <= service_uid < 1 << 32
            or not 0 <= service_gid < 1 << 32
            or type(timeout_seconds) is not int
            or not 5 <= timeout_seconds <= 600
            or type(stop_timeout_seconds) not in {int, float}
            or type(stop_timeout_seconds) is bool
            or not 0 < float(stop_timeout_seconds) <= 600
            or type(poll_interval_seconds) not in {int, float}
            or type(poll_interval_seconds) is bool
            or not 0 < float(poll_interval_seconds) <= float(stop_timeout_seconds)
        ):
            raise ValueError("invalid systemd mount policy")
        self.service_uid = service_uid
        self.service_gid = service_gid
        self.timeout_seconds = timeout_seconds
        self.stop_timeout_seconds = float(stop_timeout_seconds)
        self.poll_interval_seconds = float(poll_interval_seconds)
        self.target_directories = target_directories or AnchoredTargetDirectories(
            self.managed_root,
            owner_uid=0,
            owner_gid=self.service_gid,
        )

    def mount(
        self,
        share_id: str,
        config: ShareConfig,
        *,
        credential_path: Path | None = None,
        admitted_address: str | None = None,
    ) -> MountEvidence:
        share_id = _share_id(share_id)
        target = derive_mount_target(self.managed_root, share_id)
        unit_name = mount_unit_name(target)
        source, fs_type, options = self._mount_fields(
            config, credential_path, admitted_address=admitted_address
        )
        properties: tuple[tuple[str, object], ...] = (
            ("Description", f"LTO Archiver managed source {share_id}"),
            ("What", source),
            ("Where", str(target)),
            ("Type", fs_type),
            ("Options", options),
            ("TimeoutUSec", self.timeout_seconds * 1_000_000),
            ("CollectMode", "inactive-or-failed"),
        )
        created_target = self.target_directories.prepare(target)
        attempted = False
        try:
            attempted = True
            self.manager.start_transient_mount(unit_name, properties)
            if self.manager.unit_active(unit_name) is not True:
                raise SystemdMountError
            evidence = self.probe.inspect(target)
            self._verify_evidence(evidence, config, target, source)
            if evidence is None:  # narrowed by verifier
                raise SystemdMountError
            return evidence
        except SystemdMountError:
            if attempted:
                self._cleanup(unit_name, target)
            if created_target:
                self.target_directories.cleanup_new(target)
            raise
        except Exception:  # noqa: BLE001 - redact manager/helper diagnostics
            if attempted:
                self._cleanup(unit_name, target)
            if created_target:
                self.target_directories.cleanup_new(target)
            raise SystemdMountError from None

    def inspect(
        self,
        share_id: str,
        config: ShareConfig,
        *,
        admitted_address: str | None = None,
    ) -> MountEvidence | None:
        share_id = _share_id(share_id)
        target = derive_mount_target(self.managed_root, share_id)
        unit_name = mount_unit_name(target)
        active = self.manager.unit_active(unit_name)
        evidence = self.probe.inspect(target)
        if not active and evidence is None:
            return None
        if active is not True:
            raise SystemdMountError("share_identity_changed")
        source = _remote_source(config, server_override=admitted_address)
        self._verify_evidence(evidence, config, target, source)
        return evidence

    def unmount(self, share_id: str) -> None:
        share_id = _share_id(share_id)
        target = derive_mount_target(self.managed_root, share_id)
        unit_name = mount_unit_name(target)
        try:
            self.manager.stop_unit(unit_name)
            self._await_gone(unit_name, target)
        except SystemdMountError:
            raise
        except Exception:  # noqa: BLE001 - redact manager/helper diagnostics
            raise SystemdMountError("share_recovery_required") from None

    def unit_name(self, share_id: str) -> str:
        return mount_unit_name(
            derive_mount_target(self.managed_root, _share_id(share_id))
        )

    def assert_ready(self) -> None:
        try:
            units = tuple(self.manager.list_mount_units())
            target_enumerator = getattr(self.probe, "targets_under", None)
            if not callable(target_enumerator):
                raise TypeError
            targets = tuple(target_enumerator(self.managed_root))
            if any(
                type(unit) is not str or not unit.endswith(".mount") for unit in units
            ) or any(
                not isinstance(target, Path)
                or not target.is_absolute()
                or target == self.managed_root
                or not target.is_relative_to(self.managed_root)
                for target in targets
            ):
                raise ValueError
        except Exception:  # noqa: BLE001 - redact readiness boundary diagnostics
            raise SystemdMountError("share_broker_unavailable") from None

    def fence_unknown_units(self, known_share_ids: tuple[str, ...]) -> int:
        known_units = {self.unit_name(share_id) for share_id in known_share_ids}
        known_targets = {
            derive_mount_target(self.managed_root, _share_id(share_id))
            for share_id in known_share_ids
        }
        root_unit = mount_unit_name(self.managed_root)
        managed_prefix = root_unit.removesuffix(".mount") + "-"
        try:
            candidates = tuple(self.manager.list_mount_units())
            target_enumerator = getattr(self.probe, "targets_under", None)
            kernel_targets = (
                tuple(target_enumerator(self.managed_root))
                if callable(target_enumerator)
                else ()
            )
        except Exception:  # noqa: BLE001 - redact manager diagnostics
            raise SystemdMountError("share_recovery_required") from None
        unknown = set(
            {
                unit
                for unit in candidates
                if type(unit) is str
                and unit.startswith(managed_prefix)
                and unit.endswith(".mount")
                and unit not in known_units
            }
        )
        target_by_unit: dict[str, Path] = {}
        for target in kernel_targets:
            if (
                not isinstance(target, Path)
                or not target.is_absolute()
                or target == self.managed_root
                or not target.is_relative_to(self.managed_root)
            ):
                raise SystemdMountError("share_recovery_required")
            if target not in known_targets:
                unit = mount_unit_name(target)
                unknown.add(unit)
                target_by_unit[unit] = target
        try:
            for unit in sorted(unknown):
                self.manager.stop_unit(unit)
                target = target_by_unit.get(unit)
                if target is not None:
                    self._await_gone(unit, target)
                elif self.manager.unit_active(unit) is not False:
                    raise SystemdMountError("share_recovery_required")
        except SystemdMountError:
            raise
        except Exception:  # noqa: BLE001 - redact manager diagnostics
            raise SystemdMountError("share_recovery_required") from None
        return len(unknown)

    def _cleanup(self, unit_name: str, target: Path) -> None:
        try:
            self.manager.stop_unit(unit_name)
            self._await_gone(unit_name, target)
        except SystemdMountError:
            raise
        except Exception:  # noqa: BLE001 - redact manager/helper diagnostics
            raise SystemdMountError("share_recovery_required") from None

    def _await_gone(self, unit_name: str, target: Path) -> None:
        deadline = time.monotonic() + self.stop_timeout_seconds
        while True:
            if (
                self.manager.unit_active(unit_name) is False
                and self.probe.inspect(target) is None
            ):
                return
            if time.monotonic() >= deadline:
                raise SystemdMountError("share_recovery_required")
            time.sleep(self.poll_interval_seconds)

    def _mount_fields(
        self,
        config: ShareConfig,
        credential_path: Path | None,
        *,
        admitted_address: str | None,
    ) -> tuple[str, str, str]:
        if type(config) is NfsShareConfig:
            if credential_path is not None:
                raise SystemdMountError
            options = (
                "ro,nosuid,nodev,noexec,hard,sec=sys,"
                f"vers={config.version},timeo={config.timeout_seconds * 10},"
                f"retrans={config.retransmissions}"
            )
            return (
                _remote_source(config, server_override=admitted_address),
                "nfs",
                options,
            )
        if type(config) is SmbShareConfig:
            if (
                not isinstance(credential_path, Path)
                or not credential_path.is_absolute()
                or any(
                    character in str(credential_path) for character in (",", "\n", "\r")
                )
            ):
                raise SystemdMountError("share_credentials_required")
            encryption = ",seal" if config.encryption_required else ""
            options = (
                "ro,nosuid,nodev,noexec,"
                f"vers={config.dialect}{encryption},uid={self.service_uid},"
                f"gid={self.service_gid},file_mode=0440,dir_mode=0550,"
                f"credentials={credential_path}"
            )
            return (
                _remote_source(config, server_override=admitted_address),
                "cifs",
                options,
            )
        raise SystemdMountError

    @staticmethod
    def _verify_evidence(
        evidence: MountEvidence | None,
        config: ShareConfig,
        target: Path,
        source: str,
    ) -> None:
        allowed_fs = (
            {"nfs"}
            if type(config) is NfsShareConfig and config.version == "3"
            else {"nfs", "nfs4"}
        )
        if type(config) is SmbShareConfig:
            allowed_fs = {"cifs"}
        if (
            evidence is None
            or evidence.target != target
            or evidence.filesystem_type not in allowed_fs
            or evidence.source != source
            or evidence.read_only is not True
        ):
            raise SystemdMountError("share_identity_changed")


def mount_unit_name(target: Path) -> str:
    path = Path(target)
    if not path.is_absolute() or path == Path("/"):
        raise SystemdMountError
    encoded = []
    for byte in os.fsencode(str(path).lstrip("/")):
        if byte == ord("/"):
            encoded.append("-")
        elif (
            ord("a") <= byte <= ord("z")
            or ord("A") <= byte <= ord("Z")
            or ord("0") <= byte <= ord("9")
            or byte in (ord("_"), ord("."))
        ):
            encoded.append(chr(byte))
        else:
            encoded.append(f"\\x{byte:02x}")
    unit = "".join(encoded) + ".mount"
    if len(unit.encode("ascii")) > 255:
        raise SystemdMountError
    return unit


def source_identity_sha256(source: str) -> str:
    if (
        type(source) is not str
        or not source
        or any(ord(character) < 32 or ord(character) == 127 for character in source)
    ):
        raise SystemdMountError
    return hashlib.sha256(
        b"lto-share-remote-source-v1\0" + source.encode("utf-8")
    ).hexdigest()


def _remote_source(config: ShareConfig, *, server_override: str | None = None) -> str:
    if server_override is None:
        server_value = config.server
    else:
        try:
            server_value = str(ipaddress.ip_address(server_override))
        except (TypeError, ValueError):
            raise SystemdMountError("share_endpoint_not_allowed") from None
    if type(config) is NfsShareConfig:
        server = f"[{server_value}]" if ":" in server_value else server_value
        return f"{server}:{config.export}"
    if type(config) is SmbShareConfig:
        return f"//{server_value}/{config.share}"
    raise SystemdMountError


def _share_id(value: str) -> str:
    try:
        return normalize_share_id(value)
    except (ShareValidationError, TypeError):
        raise SystemdMountError from None


def _decode_mountinfo(value: str) -> str:
    result = bytearray()
    encoded = value.encode("utf-8")
    index = 0
    while index < len(encoded):
        if encoded[index] == 92 and index + 3 < len(encoded):
            candidate = encoded[index + 1 : index + 4]
            if all(48 <= byte <= 55 for byte in candidate):
                result.append(int(candidate, 8))
                index += 4
                continue
        result.append(encoded[index])
        index += 1
    return os.fsdecode(bytes(result))
