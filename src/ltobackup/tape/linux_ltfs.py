from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ltobackup.broker.client import (
    LtfsSessionAdmission,
    LtfsSessionApi,
    LtfsSessionHandle,
    LtfsSessionRecoveryAdmission,
)
from ltobackup.catalog import Catalog
from ltobackup.daemon.models import (
    HardwareTargetBinding,
    MediaTargetMismatch,
    OperationFence,
    RecoveryCommandFence,
    media_identity_sha256,
)
from ltobackup.errors import ValidationError
from ltobackup.linux_settings import LinuxSettings

from .backend import CommandSupervisor, UnmountObserver
from .command_supervisor import (
    CommandError,
    CommandFailed,
    CompletedCommand,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
)
from .models import (
    BackendHealth,
    ExpectedMedia,
    MediaIdentity,
    MediaIdentityFields,
    MountedTape,
    TapeTelemetry,
    UnmountResult,
)


class BackendUnavailable(RuntimeError):
    pass


class MediaProbeUnavailable(BackendUnavailable):
    def __init__(self) -> None:
        super().__init__("media identity probe unavailable")


class MediaIdentityError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "observed media or drive identity did not match the admitted target"
        )


class MountStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class _MountInfoRecord:
    mount_id: int
    parent_id: int
    mount_target: str
    filesystem_type: str
    source: str


@dataclass(frozen=True)
class StableDeviceIdentity:
    by_id_basename: str
    serial_token: str
    scsi_unit_identity: str

    def canonical_json(self) -> str:
        return json.dumps(
            {"by_id": self.by_id_basename, "serial": self.serial_token},
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )


@dataclass
class AnchoredDevicePair:
    tape: StableDeviceIdentity
    scsi: StableDeviceIdentity
    tape_exec_path: Path
    scsi_exec_path: Path
    pass_fds: tuple[int, ...] = ()

    def close(self) -> None:
        for fd in self.pass_fds:
            try:
                os.close(fd)
            except OSError:
                continue
        self.pass_fds = ()


@dataclass(frozen=True)
class ToolOverrides:
    sg_inq: Path | None = None
    mkltfs: Path | None = None
    mt: Path | None = None


@dataclass
class _TrackedLtfsSession:
    handle: LtfsSessionHandle


class DeviceIdentityProvider(Protocol):
    def resolve(self, path: Path) -> StableDeviceIdentity: ...

    def open_pair(self, tape_path: Path, scsi_path: Path) -> AnchoredDevicePair: ...


class MediaIdentityProbe(Protocol):
    def preflight(self) -> None: ...

    def identify_preformat(self) -> MediaIdentityFields: ...

    def identify_unmounted(self) -> MediaIdentityFields: ...

    def identify_mounted(self, path: Path) -> MediaIdentityFields: ...


class UnavailableMediaIdentityProbe:
    def preflight(self) -> None:
        raise MediaProbeUnavailable()

    def identify_preformat(self) -> MediaIdentityFields:
        raise MediaProbeUnavailable()

    def identify_unmounted(self) -> MediaIdentityFields:
        raise MediaProbeUnavailable()

    def identify_mounted(self, path: Path) -> MediaIdentityFields:
        raise MediaProbeUnavailable()


class MountProbe(Protocol):
    def is_mounted(self, path: Path, *, filesystem_type: str, source: str) -> bool: ...

    def await_mounted(
        self,
        path: Path,
        expected: bool,
        timeout: float,
        *,
        filesystem_type: str,
        source: str,
    ) -> None: ...

    def await_unmounted(self, path: Path, timeout: float) -> None: ...


def _decode_mountinfo_path(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


class ProcMountInfoProbe:
    def __init__(
        self,
        mountinfo_path: Path = Path("/proc/self/mountinfo"),
        *,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_seconds: float = 0.05,
    ) -> None:
        self.mountinfo_path = mountinfo_path
        self._monotonic = monotonic
        self._sleep = sleep
        self._poll_seconds = _validated_seconds(poll_seconds, "poll_seconds", 60.0)

    def is_mounted(
        self, path: Path, *, filesystem_type: str = "fuse.ltfs", source: str = "ltfs"
    ) -> bool:
        records = self._path_stack_records(path)
        mount_ids = {record.mount_id for record in records}
        if not records or len(mount_ids) != len(records):
            return False
        covered_mount_ids = {
            record.parent_id for record in records if record.parent_id in mount_ids
        }
        effective = tuple(
            record for record in records if record.mount_id not in covered_mount_ids
        )
        return bool(
            len(effective) == 1
            and effective[0].filesystem_type == filesystem_type
            and effective[0].source == source
        )

    def is_path_mounted(self, path: Path) -> bool:
        return bool(self._path_records(path))

    def has_fuse_mount(self, path: Path) -> bool:
        return any(
            filesystem_type.startswith("fuse") or source == "ltfs"
            for filesystem_type, source in self._path_records(path)
        )

    def _path_records(self, path: Path) -> tuple[tuple[str, str], ...]:
        return tuple(
            (record.filesystem_type, record.source)
            for record in self._path_stack_records(path)
        )

    def _path_stack_records(self, path: Path) -> tuple[_MountInfoRecord, ...]:
        target = str(Path(path).resolve(strict=False))
        return tuple(
            record for record in self._records() if record.mount_target == target
        )

    def _records(self) -> tuple[_MountInfoRecord, ...]:
        try:
            lines = self.mountinfo_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise MountStateError("mount state could not be read") from exc
        records: list[_MountInfoRecord] = []
        for line in lines:
            fields = line.split()
            try:
                separator = fields.index("-")
                mount_id = int(fields[0])
                parent_id = int(fields[1])
            except (IndexError, ValueError):
                continue
            if len(fields) >= 5 and len(fields) > separator + 2:
                records.append(
                    _MountInfoRecord(
                        mount_id=mount_id,
                        parent_id=parent_id,
                        mount_target=_decode_mountinfo_path(fields[4]),
                        filesystem_type=fields[separator + 1],
                        source=_decode_mountinfo_path(fields[separator + 2]),
                    )
                )
        return tuple(records)

    def await_mounted(
        self,
        path: Path,
        expected: bool,
        timeout: float,
        *,
        filesystem_type: str = "fuse.ltfs",
        source: str = "ltfs",
    ) -> None:
        deadline = self._monotonic() + _validated_seconds(
            timeout, "mount_timeout", 3_600.0
        )
        while (
            self.is_mounted(path, filesystem_type=filesystem_type, source=source)
            != expected
        ):
            if self._monotonic() >= deadline:
                raise MountStateError("mount state did not reach the expected value")
            self._sleep(min(self._poll_seconds, max(0.0, deadline - self._monotonic())))

    def await_unmounted(self, path: Path, timeout: float) -> None:
        deadline = self._monotonic() + _validated_seconds(
            timeout, "unmount_timeout", 3_600.0
        )
        while True:
            records = self._path_records(path)
            if any(
                filesystem_type.startswith("fuse")
                and (filesystem_type, source) != ("fuse.ltfs", "ltfs")
                for filesystem_type, source in records
            ):
                raise MountStateError("unexpected FUSE mount remains at LTFS target")
            if ("fuse.ltfs", "ltfs") not in records:
                return
            if self._monotonic() >= deadline:
                raise MountStateError("mount path did not become unmounted")
            self._sleep(min(self._poll_seconds, max(0.0, deadline - self._monotonic())))


class SysfsDeviceIdentityProvider:
    """Resolve stable by-id names and SCSI VPD page 0x80 without helpers."""

    def __init__(
        self,
        sys_class: Path = Path("/sys/class"),
        device_root: Path | None = None,
    ) -> None:
        self.sys_class = Path(sys_class)
        if device_root is not None:
            self.device_root = Path(device_root)
        elif self.sys_class == Path("/sys/class"):
            self.device_root = Path("/dev")
        else:
            # Tests use a temporary /sys/class tree alongside a temporary /dev
            # tree.  Keep the namespace predicate identical to production while
            # allowing those fixtures without permitting arbitrary parents.
            self.device_root = self.sys_class.parent.parent / "dev"

    def resolve(self, path: Path) -> StableDeviceIdentity:
        candidate = Path(path)
        if not candidate.is_absolute() or not self._is_stable_namespace(candidate):
            raise BackendUnavailable("a stable device identity is required")
        try:
            device_name = candidate.resolve(strict=True).name
        except (OSError, RuntimeError):
            raise BackendUnavailable(
                "a stable device identity could not be verified"
            ) from None
        class_name = (
            "scsi_tape" if device_name.startswith(("st", "nst")) else "scsi_generic"
        )
        device_root = self.sys_class / class_name / device_name / "device"
        try:
            canonical_unit = device_root.resolve(strict=True)
        except (OSError, RuntimeError):
            raise BackendUnavailable(
                "the configured device SCSI unit could not be verified"
            ) from None
        serial = self._read_serial(device_root)
        if not serial:
            raise BackendUnavailable("a stable device serial could not be verified")
        unit_identity = hashlib.sha256(
            b"lto-scsi-unit-v1\0" + str(canonical_unit).encode("utf-8")
        ).hexdigest()
        return StableDeviceIdentity(candidate.name, serial, unit_identity)

    def _is_stable_namespace(self, candidate: Path) -> bool:
        tape_namespace = self.device_root / "tape" / "by-id"
        is_tape = candidate.parent == tape_namespace and bool(candidate.name)
        prefix = "lto-archiver-scsi-"
        is_scsi = (
            candidate.parent == self.device_root
            and candidate.name.startswith(prefix)
            and len(candidate.name) > len(prefix)
        )
        return is_tape or is_scsi

    def open_pair(self, tape_path: Path, scsi_path: Path) -> AnchoredDevicePair:
        flags = os.O_CLOEXEC | os.O_PATH
        opened: list[int] = []
        try:
            for path in (tape_path, scsi_path):
                opened.append(os.open(path, flags))
            tape = self._resolve_anchored(tape_path.name, opened[0])
            scsi = self._resolve_anchored(scsi_path.name, opened[1])
            return AnchoredDevicePair(
                tape=tape,
                scsi=scsi,
                tape_exec_path=Path(f"/proc/self/fd/{opened[0]}"),
                scsi_exec_path=Path(f"/proc/self/fd/{opened[1]}"),
                pass_fds=tuple(opened),
            )
        except BackendUnavailable:
            for fd in opened:
                os.close(fd)
            raise
        except (OSError, RuntimeError, ValueError):
            for fd in opened:
                os.close(fd)
            raise BackendUnavailable(
                "device anchors could not be established"
            ) from None

    def _resolve_anchored(self, by_id_basename: str, fd: int) -> StableDeviceIdentity:
        try:
            device_name = Path(f"/proc/self/fd/{fd}").resolve(strict=True).name
        except (OSError, RuntimeError):
            raise BackendUnavailable(
                "anchored device identity could not be verified"
            ) from None
        class_name = (
            "scsi_tape" if device_name.startswith(("st", "nst")) else "scsi_generic"
        )
        device_root = self.sys_class / class_name / device_name / "device"
        try:
            canonical_unit = device_root.resolve(strict=True)
        except (OSError, RuntimeError):
            raise BackendUnavailable(
                "anchored SCSI unit could not be verified"
            ) from None
        serial = self._read_serial(device_root)
        if not serial:
            raise BackendUnavailable("anchored device serial could not be verified")
        unit_identity = hashlib.sha256(
            b"lto-scsi-unit-v1\0" + str(canonical_unit).encode("utf-8")
        ).hexdigest()
        return StableDeviceIdentity(by_id_basename, serial, unit_identity)

    @staticmethod
    def _read_serial(device_root: Path) -> str:
        try:
            data = (device_root / "vpd_pg80").read_bytes()
            if len(data) >= 4:
                length = int.from_bytes(data[2:4], "big")
                serial = data[4 : 4 + length].decode("ascii", errors="strict").strip()
                if serial:
                    return serial
        except (OSError, UnicodeError):
            pass
        try:
            return (device_root / "serial").read_text(encoding="ascii").strip()
        except (OSError, UnicodeError):
            return ""


def resolve_executable(override: Path | None, name: str) -> Path:
    candidate = Path(override) if override is not None else None
    if candidate is None:
        found = shutil.which(name)
        candidate = Path(found) if found else None
    if (
        candidate is None
        or not candidate.is_absolute()
        or not candidate.is_file()
        or not os.access(candidate, os.X_OK)
    ):
        raise BackendUnavailable(f"required executable is unavailable: {name}")
    return candidate


def _validated_seconds(value: float, name: str, maximum: float) -> float:
    if not math.isfinite(value) or value <= 0.0 or value > maximum:
        raise ValueError(f"{name} must be finite, positive, and within platform bounds")
    return value


class LinuxLtfsBackend:
    _TOOLS = ("sg_inq", "mkltfs", "mt")

    def __init__(
        self,
        *,
        settings: LinuxSettings,
        expected: ExpectedMedia,
        fence: OperationFence | RecoveryCommandFence,
        catalog: Catalog,
        supervisor: CommandSupervisor,
        ltfs_sessions: LtfsSessionApi,
        device_identities: DeviceIdentityProvider | None = None,
        mount_probe: MountProbe | None = None,
        media_identity_probe: MediaIdentityProbe | None = None,
        tool_overrides: ToolOverrides | None = None,
        executable_resolver: Callable[[Path | None, str], Path] = resolve_executable,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        command_timeout: float = 300.0,
        release_timeout: float = 30.0,
        media_wait_timeout: float = 300.0,
        media_poll_seconds: float = 1.0,
    ) -> None:
        self.settings = settings
        self.expected = expected
        self._restore_volume_label: str | None = None
        self.fence = fence
        self.catalog = catalog
        self.supervisor = supervisor
        self.ltfs_sessions = ltfs_sessions
        self._active_ltfs_sessions: dict[str, _TrackedLtfsSession] = {}
        self._admission_media_snapshot: tuple[MediaIdentity, int, str] | None = None
        self._preformat_media_snapshot: tuple[MediaIdentity, str] | None = None
        self._preformat_rejection_recorded = False
        self.device_identities = device_identities or SysfsDeviceIdentityProvider()
        self.mount_probe = mount_probe or ProcMountInfoProbe()
        self.media_identity_probe = (
            media_identity_probe or UnavailableMediaIdentityProbe()
        )
        self.tool_overrides = tool_overrides or ToolOverrides()
        self.executable_resolver = executable_resolver
        self.monotonic = monotonic
        self.sleep = sleep
        self.command_timeout = _validated_seconds(
            command_timeout, "command_timeout", 86_400.0
        )
        self.release_timeout = _validated_seconds(
            release_timeout, "release_timeout", 3_600.0
        )
        self.media_wait_timeout = _validated_seconds(
            media_wait_timeout, "media_wait_timeout", 86_400.0
        )
        self.media_poll_seconds = _validated_seconds(
            media_poll_seconds, "media_poll_seconds", 60.0
        )
        if self.media_poll_seconds > self.media_wait_timeout:
            raise ValueError("media_poll_seconds cannot exceed media_wait_timeout")

    def bind_restore_volume_label(self, volume_label: str) -> None:
        """Bind the separately frozen LTFS label for one restore cassette."""

        if self.expected.operation_kind != "restore.cassette":
            raise MediaIdentityError()
        if (
            type(volume_label) is not str
            or not volume_label
            or len(volume_label) > 255
            or volume_label != volume_label.strip(" ")
            or not volume_label.isascii()
            or not volume_label.isprintable()
            or self._admission_media_snapshot is not None
        ):
            raise MediaIdentityError()
        self._restore_volume_label = volume_label

    @classmethod
    def target_binding_from(
        cls,
        settings: LinuxSettings,
        expected: ExpectedMedia,
        device_identities: DeviceIdentityProvider,
    ) -> HardwareTargetBinding:
        cls._validate_stable_paths(settings)
        tape = device_identities.resolve(settings.tape_device_path)
        scsi = device_identities.resolve(settings.scsi_device_path)
        cls._assert_same_scsi_unit(tape, scsi)
        return HardwareTargetBinding.from_verified_inputs(
            settings.mount_path.resolve(strict=False),
            tape.canonical_json(),
            scsi.canonical_json(),
            expected.target_scope(),
        )

    def target_binding(
        self, expected: ExpectedMedia | None = None
    ) -> HardwareTargetBinding:
        return self.target_binding_from(
            self.settings, expected or self.expected, self.device_identities
        )

    @staticmethod
    def _validate_stable_paths(settings: LinuxSettings) -> None:
        try:
            settings.validate()
        except ValidationError:
            raise BackendUnavailable(
                "stable tape and SCSI configuration is required"
            ) from None

    def preflight(self) -> BackendHealth:
        self._validate_stable_paths(self.settings)
        pair = self.device_identities.open_pair(
            self.settings.tape_device_path, self.settings.scsi_device_path
        )
        try:
            self._assert_same_scsi_unit(pair.tape, pair.scsi)
        finally:
            pair.close()
        for name in self._TOOLS:
            self._tool(name)
        unavailable = False
        try:
            self.media_identity_probe.preflight()
        except Exception:  # noqa: BLE001 - normalize an injected provider boundary
            unavailable = True
        if unavailable:
            raise MediaProbeUnavailable() from None
        return BackendHealth(True, self._TOOLS)

    @staticmethod
    def _assert_same_scsi_unit(
        tape: StableDeviceIdentity, scsi: StableDeviceIdentity
    ) -> None:
        if tape.scsi_unit_identity != scsi.scsi_unit_identity:
            raise BackendUnavailable(
                "configured tape and generic-SCSI paths do not identify one SCSI unit"
            )

    def _open_admitted_device_pair(self) -> AnchoredDevicePair:
        self._validate_stable_paths(self.settings)
        pair = self.device_identities.open_pair(
            self.settings.tape_device_path, self.settings.scsi_device_path
        )
        try:
            self._assert_same_scsi_unit(pair.tape, pair.scsi)
            observed_target = HardwareTargetBinding.from_verified_inputs(
                self.settings.mount_path.resolve(strict=False),
                pair.tape.canonical_json(),
                pair.scsi.canonical_json(),
                self.expected.target_scope(),
            )
            admitted_target = self.catalog.hardware_target_binding(
                self.fence.operation_id
            )
            if admitted_target != observed_target:
                raise BackendUnavailable(
                    "anchored devices do not match the admitted hardware target"
                )
            return pair
        except Exception:
            pair.close()
            raise

    def _tool(self, name: str) -> Path:
        override = getattr(self.tool_overrides, name)
        return self.executable_resolver(override, name)

    def _run(
        self,
        kind: str,
        argv: tuple[str, ...],
        timeout: float | None = None,
        pass_fds: tuple[int, ...] = (),
    ) -> CompletedCommand:
        self._validate_stable_paths(self.settings)
        return self.supervisor.run(
            self.fence,
            kind,
            argv,
            self.command_timeout if timeout is None else timeout,
            pass_fds,
        )

    def identify(self) -> MediaIdentity:
        pair = self._open_admitted_device_pair()
        try:
            result = self._run(
                "identify",
                (str(self._tool("sg_inq")), str(pair.scsi_exec_path)),
                pass_fds=pair.pass_fds,
            )
        finally:
            pair.close()
        drive_serial = self._parse_drive_serial(result.stdout)
        fields = self._probe_unmounted_media()
        expected_ltfs_label = self._restore_volume_label or self.expected.volume_label
        if (
            fields.ltfs_volume_label is None
            or fields.ltfs_volume_uuid is None
            or fields.index_generation is None
        ):
            raise MediaIdentityError()
        identity = MediaIdentity(
            drive_serial=drive_serial,
            mam_barcode=fields.mam_barcode,
            mam_volume_serial=fields.mam_volume_serial,
            ltfs_volume_label=fields.ltfs_volume_label,
            ltfs_volume_uuid=fields.ltfs_volume_uuid,
        )
        observed_hash = media_identity_sha256(identity.canonical_fields())
        if (
            identity.drive_serial != pair.scsi.serial_token
            or identity.mam_barcode != self.expected.volume_label
            or (
                self.expected.volume_serial is not None
                and identity.mam_volume_serial != self.expected.volume_serial
            )
            or identity.volume_label != expected_ltfs_label
            or (
                self.expected.volume_uuid is not None
                and identity.ltfs_volume_uuid != self.expected.volume_uuid
            )
        ):
            if (
                isinstance(self.fence, OperationFence)
                and self.catalog.observed_media_binding(self.fence.operation_id)
                is not None
            ):
                try:
                    self.catalog.bind_observed_media_identity(self.fence, observed_hash)
                except MediaTargetMismatch:
                    pass
            raise MediaIdentityError()
        if isinstance(self.fence, OperationFence):
            try:
                self.catalog.bind_observed_media_identity(self.fence, observed_hash)
            except MediaTargetMismatch:
                raise MediaIdentityError() from None
        elif (
            self.catalog.observed_media_binding(self.fence.operation_id)
            != observed_hash
        ):
            raise MediaIdentityError()
        self._admission_media_snapshot = (
            identity,
            fields.index_generation,
            observed_hash,
        )
        return identity

    @staticmethod
    def _validate_media_fields(fields: MediaIdentityFields) -> None:
        if LinuxLtfsBackend._media_field_rejection_codes(fields):
            raise MediaIdentityError()

    @staticmethod
    def _media_field_rejection_codes(fields: object) -> tuple[str, ...]:
        if type(fields) is not MediaIdentityFields:
            return ("fields_type_invalid",)
        rejection_codes: list[str] = []
        for name, value, maximum in (
            ("mam_barcode", fields.mam_barcode, 32),
            ("mam_volume_serial", fields.mam_volume_serial, 32),
            ("ltfs_volume_label", fields.ltfs_volume_label, 255),
        ):
            if value is not None and (
                type(value) is not str
                or not 0 < len(value) <= maximum
                or value != value.strip(" ")
                or not value.isascii()
                or not value.isprintable()
            ):
                rejection_codes.append(f"{name}_invalid")
        if fields.ltfs_volume_uuid is not None:
            try:
                if str(uuid.UUID(fields.ltfs_volume_uuid)) != fields.ltfs_volume_uuid:
                    raise ValueError
            except (AttributeError, TypeError, ValueError):
                rejection_codes.append("ltfs_volume_uuid_invalid")
        if fields.index_generation is not None and (
            type(fields.index_generation) is not int
            or not 0 < fields.index_generation < 1 << 64
        ):
            rejection_codes.append("index_generation_invalid")
        return tuple(rejection_codes)

    def _record_media_identity_rejection(self, reason_codes: list[str]) -> None:
        if self._preformat_rejection_recorded:
            return
        self.catalog.record_audit(
            "system",
            "ltfs.preformat_identity",
            "rejected",
            self.fence.operation_id,
            None,
            {"reason_codes": reason_codes},
        )
        self._preformat_rejection_recorded = True

    def _probe_unmounted_media(self) -> MediaIdentityFields:
        return self._probe_media(self.media_identity_probe.identify_unmounted)

    def _probe_preformat_media(self) -> MediaIdentityFields:
        probe = getattr(self.media_identity_probe, "identify_preformat", None)
        if not callable(probe):
            probe = self.media_identity_probe.identify_unmounted
        return self._probe_media(probe)

    def _probe_media(
        self, probe: Callable[[], MediaIdentityFields]
    ) -> MediaIdentityFields:
        failed = False
        unavailable = False
        try:
            fields = probe()
            rejection_codes = list(self._media_field_rejection_codes(fields))
            if rejection_codes:
                self._record_media_identity_rejection(rejection_codes)
            self._validate_media_fields(fields)
        except BackendUnavailable:
            unavailable = True
            fields = MediaIdentityFields()
        except CommandFailed as exc:
            if type(exc.returncode) is int and 0 < exc.returncode <= 255:
                code = f"probe_command_exit_{exc.returncode}"
            elif type(exc.returncode) is int and -255 <= exc.returncode < 0:
                code = f"probe_command_signal_{-exc.returncode}"
            else:
                code = "probe_command_failed"
            self._record_media_identity_rejection([code])
            failed = True
            fields = MediaIdentityFields()
        except CommandError:
            self._record_media_identity_rejection(["probe_command_error"])
            failed = True
            fields = MediaIdentityFields()
        except Exception:  # noqa: BLE001 - normalize an injected provider boundary
            self._record_media_identity_rejection(["probe_boundary_failed"])
            failed = True
            fields = MediaIdentityFields()
        if unavailable:
            raise MediaProbeUnavailable() from None
        if failed:
            raise MediaIdentityError()
        return fields

    def _probe_mounted_media(self) -> MediaIdentityFields:
        failed = False
        unavailable = False
        try:
            fields = self.media_identity_probe.identify_mounted(
                self.settings.mount_path
            )
            self._validate_media_fields(fields)
        except BackendUnavailable:
            unavailable = True
            fields = MediaIdentityFields()
        except Exception:  # noqa: BLE001 - normalize an injected provider boundary
            failed = True
            fields = MediaIdentityFields()
        if unavailable:
            raise MediaProbeUnavailable() from None
        if failed:
            raise MediaIdentityError()
        return fields

    def _verify_drive_identity(self, pair: AnchoredDevicePair) -> None:
        result = self._run(
            "inquiry",
            (str(self._tool("sg_inq")), str(pair.scsi_exec_path)),
            pass_fds=pair.pass_fds,
        )
        if self._parse_drive_serial(result.stdout) != pair.scsi.serial_token:
            raise MediaIdentityError()

    @staticmethod
    def _parse_drive_serial(output: str) -> str:
        match = re.search(
            r"^[ \t]*Unit serial number:\s*(\S.*)$", output, flags=re.MULTILINE
        )
        if match is None:
            raise MediaIdentityError()
        return match.group(1).strip()

    def wait_for_media(self, expected: ExpectedMedia, stop: Callable[[], bool]) -> bool:
        if expected != self.expected:
            raise MediaIdentityError()
        deadline = self.monotonic() + self.media_wait_timeout
        while not stop():
            try:
                self.identify()
                return True
            except MediaIdentityError:
                remaining = deadline - self.monotonic()
                if remaining <= 0.0:
                    return False
                self.sleep(min(self.media_poll_seconds, remaining))
        return False

    def identify_preformat(self) -> MediaIdentity:
        """Seal an authorized pre-format identity, including virgin media."""

        if not isinstance(self.fence, OperationFence):
            raise MediaIdentityError()
        self.catalog.require_consumed_format_confirmation(
            self.fence,
            self.expected.job_id,
            self.expected.cassette_sequence,
            self.expected.volume_label,
        )
        pair = self._open_admitted_device_pair()
        try:
            result = self._run(
                "identify",
                (str(self._tool("sg_inq")), str(pair.scsi_exec_path)),
                pass_fds=pair.pass_fds,
            )
        finally:
            pair.close()
        drive_serial = self._parse_drive_serial(result.stdout)
        fields = self._probe_preformat_media()
        blank_ltfs = (
            fields.ltfs_volume_label is None
            and fields.ltfs_volume_uuid is None
            and fields.index_generation is None
        )
        complete_ltfs = (
            fields.ltfs_volume_label is not None
            and fields.ltfs_volume_uuid is not None
            and fields.index_generation is not None
        )
        rejection_codes: list[str] = []
        if drive_serial != pair.scsi.serial_token:
            rejection_codes.append("drive_serial_mismatch")
        if self.expected.volume_serial is not None and (
            fields.mam_barcode != self.expected.volume_label
            or fields.mam_volume_serial != self.expected.volume_serial
        ):
            rejection_codes.append("expected_serial_mismatch")
        if (
            fields.mam_barcode is not None
            and fields.mam_barcode != self.expected.volume_label
        ):
            rejection_codes.append("mam_label_mismatch")
        if fields.mam_volume_serial is None:
            rejection_codes.append("mam_serial_missing")
        if not (blank_ltfs or complete_ltfs):
            rejection_codes.append("ltfs_tuple_incomplete")
        if (
            fields.ltfs_volume_label is not None
            and fields.ltfs_volume_label != self.expected.volume_label
        ):
            rejection_codes.append("ltfs_label_mismatch")
        if (
            self.expected.volume_uuid is not None
            and fields.ltfs_volume_uuid is not None
            and fields.ltfs_volume_uuid != self.expected.volume_uuid
        ):
            rejection_codes.append("ltfs_uuid_mismatch")
        if rejection_codes:
            self._record_media_identity_rejection(rejection_codes)
            raise MediaIdentityError()
        identity = MediaIdentity(
            drive_serial=drive_serial,
            mam_barcode=fields.mam_barcode,
            mam_volume_serial=fields.mam_volume_serial,
            ltfs_volume_label=fields.ltfs_volume_label,
            ltfs_volume_uuid=fields.ltfs_volume_uuid,
        )
        digest = media_identity_sha256(identity.canonical_fields())
        try:
            self.catalog.bind_observed_media_identity(self.fence, digest)
        except MediaTargetMismatch:
            raise MediaIdentityError() from None
        self._preformat_media_snapshot = (identity, digest)
        self._admission_media_snapshot = None
        return identity

    def wait_for_preformat_media(
        self, expected: ExpectedMedia, stop: Callable[[], bool]
    ) -> bool:
        if expected != self.expected:
            raise MediaIdentityError()
        deadline = self.monotonic() + self.media_wait_timeout
        while not stop():
            try:
                self.identify_preformat()
                return True
            except MediaIdentityError:
                remaining = deadline - self.monotonic()
                if remaining <= 0.0:
                    return False
                self.sleep(min(self.media_poll_seconds, remaining))
        return False

    def format(self, expected: ExpectedMedia) -> None:
        if expected != self.expected:
            raise MediaIdentityError()
        preformat = self._preformat_media_snapshot
        if preformat is None:
            raise MediaIdentityError()
        preformat_identity, preformat_digest = preformat
        if (
            self.catalog.observed_media_binding(self.fence.operation_id)
            != preformat_digest
        ):
            self._preformat_media_snapshot = None
            raise MediaIdentityError()
        pair = self._open_admitted_device_pair()
        try:
            try:
                self._verify_drive_identity(pair)
                fields = self._probe_preformat_media()
                current_identity = MediaIdentity(
                    drive_serial=pair.scsi.serial_token,
                    mam_barcode=fields.mam_barcode,
                    mam_volume_serial=fields.mam_volume_serial,
                    ltfs_volume_label=fields.ltfs_volume_label,
                    ltfs_volume_uuid=fields.ltfs_volume_uuid,
                )
                if (
                    current_identity.canonical_fields()
                    != preformat_identity.canonical_fields()
                    or media_identity_sha256(current_identity.canonical_fields())
                    != preformat_digest
                ):
                    raise MediaIdentityError()
            except BaseException:
                self._preformat_media_snapshot = None
                raise
            # The admitted tape/SCSI descriptors remain open from the continuity
            # probe through mkltfs, inside the same fenced hardware operation.
            self._preformat_media_snapshot = None
            label = expected.volume_label
            barcode_arguments = (
                ("--tape-serial", label)
                if len(label) == 6
                and label.isascii()
                and all(
                    character.isdigit() or "A" <= character <= "Z"
                    for character in label
                )
                else ()
            )
            self._run(
                "format",
                (
                    str(self._tool("mkltfs")),
                    "--device",
                    str(pair.scsi_exec_path),
                    "--force",
                    "--volume-name",
                    label,
                    *barcode_arguments,
                ),
                pass_fds=pair.pass_fds,
            )
        finally:
            pair.close()
        post_identity, post_generation, post_digest = self._identify_postformat(
            preformat_identity
        )
        self.catalog.rebind_observed_media_after_confirmed_format(
            self.fence,
            pre_media_identity_sha256=preformat_digest,
            post_media_identity_sha256=post_digest,
            pre_observed_serial=preformat_identity.mam_volume_serial,
            observed_label=post_identity.ltfs_volume_label,
            observed_serial=post_identity.mam_volume_serial,
            post_volume_uuid=post_identity.ltfs_volume_uuid,
            post_index_generation=post_generation,
        )
        self._preformat_media_snapshot = None
        self._admission_media_snapshot = (
            post_identity,
            post_generation,
            post_digest,
        )

    def _identify_postformat(
        self, preformat_identity: MediaIdentity
    ) -> tuple[MediaIdentity, int, str]:
        if (
            type(preformat_identity) is not MediaIdentity
            or preformat_identity.mam_volume_serial is None
        ):
            raise MediaIdentityError()
        pair = self._open_admitted_device_pair()
        try:
            result = self._run(
                "identify",
                (str(self._tool("sg_inq")), str(pair.scsi_exec_path)),
                pass_fds=pair.pass_fds,
            )
        finally:
            pair.close()
        drive_serial = self._parse_drive_serial(result.stdout)
        fields = self._probe_unmounted_media()
        if (
            drive_serial != pair.scsi.serial_token
            or fields.mam_barcode != self.expected.volume_label
            or fields.mam_volume_serial != preformat_identity.mam_volume_serial
            or fields.ltfs_volume_label != self.expected.volume_label
            or fields.ltfs_volume_uuid is None
            or fields.index_generation is None
            or (
                self.expected.volume_uuid is not None
                and fields.ltfs_volume_uuid != self.expected.volume_uuid
            )
        ):
            raise MediaIdentityError()
        identity = MediaIdentity(
            drive_serial=drive_serial,
            mam_barcode=fields.mam_barcode,
            mam_volume_serial=fields.mam_volume_serial,
            ltfs_volume_label=fields.ltfs_volume_label,
            ltfs_volume_uuid=fields.ltfs_volume_uuid,
        )
        return (
            identity,
            fields.index_generation,
            media_identity_sha256(identity.canonical_fields()),
        )

    def mount(self, *, read_only: bool) -> MountedTape:
        if type(read_only) is not bool:
            raise MediaIdentityError()
        snapshot = self._admission_media_snapshot
        if snapshot is None:
            raise MediaIdentityError()
        snapshot_identity, snapshot_generation, snapshot_digest = snapshot
        self._prepare_new_ltfs_mount()
        pair = self._open_admitted_device_pair()
        handle: LtfsSessionHandle | None = None
        tracked: _TrackedLtfsSession | None = None
        try:
            self._verify_drive_identity(pair)
            self.catalog.assert_command_fence(self.fence)
            admitted_target = self.catalog.hardware_target_binding(
                self.fence.operation_id
            )
            observed_media = self.catalog.observed_media_binding(
                self.fence.operation_id
            )
            if observed_media != snapshot_digest:
                raise MediaIdentityError()
            current_target = HardwareTargetBinding.from_verified_inputs(
                self.settings.mount_path.resolve(strict=False),
                pair.tape.canonical_json(),
                pair.scsi.canonical_json(),
                self.expected.target_scope(),
            )
            if admitted_target != current_target or observed_media is None:
                raise BackendUnavailable(
                    "LTFS session no longer matches the admitted physical target"
                )
            if (
                type(pair.pass_fds) is not tuple
                or len(pair.pass_fds) != 2
                or any(type(fd) is not int or fd < 0 for fd in pair.pass_fds)
                or pair.pass_fds[0] == pair.pass_fds[1]
            ):
                raise BackendUnavailable("LTFS device anchors are unavailable")
            handle = self.ltfs_sessions.start_ltfs_session(
                LtfsSessionAdmission(
                    operation_id=self.fence.operation_id,
                    owner_generation=self.fence.owner_generation,
                    mount_path_sha256=admitted_target.mount_path_sha256,
                    tape_device_identity_sha256=(
                        admitted_target.tape_device_identity_sha256
                    ),
                    scsi_device_identity_sha256=(
                        admitted_target.scsi_device_identity_sha256
                    ),
                    expected_media_scope_sha256=(
                        admitted_target.expected_media_scope_sha256
                    ),
                    observed_media_identity_sha256=observed_media,
                    expected_volume_uuid=snapshot_identity.ltfs_volume_uuid,
                    expected_prior_generation=snapshot_generation,
                    read_only=read_only,
                ),
                tape_fd=pair.pass_fds[0],
                scsi_fd=pair.pass_fds[1],
            )
        finally:
            pair.close()
        try:
            if (
                type(handle) is not LtfsSessionHandle
                or type(handle.receipt) is not LtfsSessionReceipt
                or handle.receipt.operation_id != self.fence.operation_id
                or handle.receipt.owner_generation != self.fence.owner_generation
                or handle.receipt.mounted is not True
                or (
                    handle.receipt.observed_volume_uuid
                    != snapshot_identity.ltfs_volume_uuid
                )
                or handle.receipt.observed_prior_generation != snapshot_generation
                or handle.receipt.observed_volume_label
                != snapshot_identity.ltfs_volume_label
                or handle.receipt.observed_media_identity_sha256 != snapshot_digest
            ):
                raise BackendUnavailable("LTFS session receipt is unavailable")
            if handle.receipt.session_id in self._active_ltfs_sessions:
                raise BackendUnavailable("LTFS session receipt was reused")
            tracked = _TrackedLtfsSession(
                handle=handle,
            )
            self._active_ltfs_sessions[handle.receipt.session_id] = tracked
            self.mount_probe.await_mounted(
                self.settings.mount_path,
                True,
                self.release_timeout,
                filesystem_type="fuse.ltfs",
                source="ltfs",
            )
            self.ltfs_sessions.observe_ltfs_session(handle)
        except BaseException:
            if type(handle) is LtfsSessionHandle:
                try:
                    self.ltfs_sessions.finalize_ltfs_session(handle)
                finally:
                    if tracked is not None:
                        self._active_ltfs_sessions.pop(handle.receipt.session_id, None)
            raise
        return MountedTape(self.settings.mount_path, read_only, handle.receipt)

    def _prepare_new_ltfs_mount(self) -> None:
        tracked_sessions = tuple(self._active_ltfs_sessions.values())
        if not tracked_sessions:
            return
        raise BackendUnavailable("an LTFS mount lifecycle is already active")

    def recover_pending_ltfs_session(self) -> LtfsFinalizationReceipt | None:
        if type(self.fence) not in {OperationFence, RecoveryCommandFence}:
            raise BackendUnavailable("an exact LTFS outcome fence is required")
        self.catalog.assert_command_fence(self.fence)
        admitted_target = self.catalog.hardware_target_binding(self.fence.operation_id)
        observed_media = self.catalog.observed_media_binding(self.fence.operation_id)
        current_target = self.target_binding()
        if admitted_target != current_target or observed_media is None:
            raise BackendUnavailable(
                "pending LTFS cleanup no longer matches the admitted target"
            )
        original_generation = (
            self.fence.owner_generation
            if type(self.fence) is OperationFence
            else self.catalog.ltfs_recovery_session_generation(self.fence)
        )
        return self.ltfs_sessions.recover_pending_ltfs_session(
            LtfsSessionRecoveryAdmission(
                fence=self.fence,
                original_owner_generation=original_generation,
                mount_path_sha256=admitted_target.mount_path_sha256,
                tape_device_identity_sha256=(
                    admitted_target.tape_device_identity_sha256
                ),
                scsi_device_identity_sha256=(
                    admitted_target.scsi_device_identity_sha256
                ),
                expected_media_scope_sha256=(
                    admitted_target.expected_media_scope_sha256
                ),
                observed_media_identity_sha256=observed_media,
            )
        )

    def unmount(self, mounted: MountedTape, observer: UnmountObserver) -> UnmountResult:
        if mounted.path.resolve(strict=False) != self.settings.mount_path.resolve(
            strict=False
        ):
            raise MountStateError("mounted target does not match the admitted target")
        if type(mounted.session_receipt) is not LtfsSessionReceipt:
            raise MountStateError("mounted session receipt is unavailable")
        tracked = self._active_ltfs_sessions.get(mounted.session_receipt.session_id)
        if (
            type(tracked) is not _TrackedLtfsSession
            or tracked.handle.receipt != mounted.session_receipt
            or mounted.session_receipt.operation_id != self.fence.operation_id
            or mounted.session_receipt.owner_generation != self.fence.owner_generation
        ):
            raise MountStateError("mounted session receipt is unavailable")
        handle = tracked.handle
        self.catalog.assert_command_fence(self.fence)
        started = self.monotonic()
        observer.finalization_started()
        finalized = self.monotonic()
        observer.mount_release_started()
        self.catalog.assert_command_fence(self.fence)
        try:
            finalization_receipt = self.ltfs_sessions.finalize_ltfs_session(handle)
        finally:
            self._active_ltfs_sessions.pop(handle.receipt.session_id, None)
        self.mount_probe.await_unmounted(self.settings.mount_path, self.release_timeout)
        released = self.monotonic()
        return UnmountResult(
            max(0.0, finalized - started),
            max(0.0, released - finalized),
            finalization_receipt,
        )

    def unload(self) -> CompletedCommand:
        pair = self._open_admitted_device_pair()
        try:
            return self._run(
                "unload",
                (
                    str(self._tool("mt")),
                    "-f",
                    str(pair.tape_exec_path),
                    "eject",
                ),
                pass_fds=pair.pass_fds,
            )
        finally:
            pair.close()

    def telemetry(self) -> TapeTelemetry:
        pair = self._open_admitted_device_pair()
        try:
            result = self._run(
                "status",
                (
                    str(self._tool("mt")),
                    "-f",
                    str(pair.tape_exec_path),
                    "status",
                ),
                pass_fds=pair.pass_fds,
            )
        finally:
            pair.close()
        values = dict(
            re.findall(
                r"^(remaining_bytes|position_bytes)=(\d+)$", result.stdout, re.MULTILINE
            )
        )
        return TapeTelemetry(
            available=True,
            remaining_bytes=int(values["remaining_bytes"])
            if "remaining_bytes" in values
            else None,
            position_bytes=int(values["position_bytes"])
            if "position_bytes" in values
            else None,
        )
