"""Fixed command grammar for manual physical LTFS qualification."""

from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from ltobackup.broker.ltfs_session import LtfsStandaloneReceiptRoot
from ltobackup.daemon.models import HardwareTargetBinding, media_identity_sha256
from ltobackup.linux_settings import LinuxSettings
from ltobackup.tape.command_supervisor import LtfsStandaloneReceipt
from ltobackup.tape.linux_ltfs import SysfsDeviceIdentityProvider
from ltobackup.tape.models import MediaIdentity

from .broker_models import BrokerQualificationExecution, BrokerQualificationRequest
from .plan import (
    SUPPORTED_QUALIFICATION_OPERATIONS,
    QualificationOperation,
    QualificationRefused,
    qualification_success_exit_codes,
)

_CONFIG = "/etc/ltfs.conf"
_TAPE = "/dev/tape/by-id/configured-nst"
_SCSI = "/dev/lto-archiver-scsi-configured"
_MOUNT = "/mnt/lto-archiver/tape"
_RECEIPTS = "/var/lib/lto-archiver-broker/receipts"
_RECEIPT_NAMESPACE = uuid.UUID("993e3bb9-3d3c-4b2b-85ed-86a77bfd937f")
_TOOL_PATHS = {
    "ltfs": Path("/usr/bin/ltfs"),
    "mkltfs": Path("/usr/bin/mkltfs"),
    "ltfsck": Path("/usr/bin/ltfsck"),
    "ltfs-info": Path("/usr/bin/ltfs-info"),
    "fusermount": Path("/usr/bin/fusermount"),
    "mt": Path("/usr/bin/mt"),
}
_DEVICE_CONFIG = Path("/etc/lto-ltfs/device.json")
_ARTIFACT_ATTESTATION = Path("/etc/lto-archiver/qualification-artifacts.json")
_ADMIN_GROUP = "lto-admin"
_TERMINAL_TIMEOUT = 86_400.0
_MAX_MANIFEST_FILE_BYTES = 16 * 1024 * 1024
_MAX_MANIFEST_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_LTFS_EVENT_STREAM_BYTES = 64 * 1024
_LTFS_EVENT_DIAGNOSTIC_TIMEOUT = 1.0
_LTFS_EVENT_CODE_ALLOWLIST = frozenset({"device.identity.mismatch"})
_COMMAND_FAILURE_PHASES = frozenset(
    {
        f"pre_{operation.value}_probe"
        for operation in SUPPORTED_QUALIFICATION_OPERATIONS
    }
    | {
        f"post_{operation.value}_probe"
        for operation in SUPPORTED_QUALIFICATION_OPERATIONS
    }
    | {
        f"{operation.value}_command"
        for operation in SUPPORTED_QUALIFICATION_OPERATIONS
    }
    | {
        f"{operation.value}_terminal_probe"
        for operation in SUPPORTED_QUALIFICATION_OPERATIONS
    }
    | {"repair_precheck"}
)
_COMMAND_FAILURE_REASONS = frozenset(
    {
        "exit_status",
        "identity_mismatch",
        "output_malformed",
        "output_oversized",
        "output_unexpected",
        "schema_invalid",
    }
)


def _report_command_failure(
    tool: str,
    phase: str,
    returncode: object,
    *,
    reason: str = "exit_status",
) -> None:
    if (
        tool not in _TOOL_PATHS
        or phase not in _COMMAND_FAILURE_PHASES
        or reason not in _COMMAND_FAILURE_REASONS
    ):
        raise QualificationRefused("physical LTFS command diagnostic is invalid")
    exit_code: int | str = returncode if type(returncode) is int else "invalid"
    print(
        f"LTFS command failed: tool={tool} phase={phase} exit={exit_code} "
        f"reason={reason}",
        file=sys.stderr,
        flush=True,
    )


def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if type(key) is not str or key in result:
            raise QualificationRefused("physical LTFS evidence is invalid")
        result[key] = value
    return result


def _tool_snapshot(status: os.stat_result) -> tuple[int, ...]:
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


def _sha256_descriptor(descriptor: int, size: int) -> str:
    if type(size) is not int or not 0 < size <= 64 * 1024 * 1024:
        raise QualificationRefused("physical LTFS tool size is invalid")
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise QualificationRefused("physical LTFS tool changed")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise QualificationRefused("physical LTFS tool changed")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return digest.hexdigest()
    except OSError:
        raise QualificationRefused("physical LTFS tool is unavailable") from None


def _load_tool_attestation() -> dict[str, str]:
    descriptor = -1
    try:
        descriptor = os.open(
            _ARTIFACT_ATTESTATION,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o400
            or status.st_uid != 0
            or status.st_gid != 0
            or status.st_nlink != 1
            or not 0 < status.st_size <= 16 * 1024
        ):
            raise QualificationRefused("physical LTFS artifact authority is invalid")
        raw = os.read(descriptor, 16 * 1024 + 1)
        if len(raw) != status.st_size or os.read(descriptor, 1):
            raise QualificationRefused("physical LTFS artifact authority changed")
        value = json.loads(raw, object_pairs_hook=_closed_pairs)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        raise QualificationRefused(
            "physical LTFS artifact authority is unavailable"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if (
        type(value) is not dict
        or frozenset(value)
        != frozenset(
            {
                "schema",
                "linux_tree_sha256",
                "ltfs_tree_sha256",
                "ltfs_rpm_sha256",
                "tool_sha256",
            }
        )
        or value["schema"] != 2
        or type(value["tool_sha256"]) is not dict
        or any(
            type(value[key]) is not str
            or len(value[key]) != 64
            or any(character not in "0123456789abcdef" for character in value[key])
            for key in (
                "linux_tree_sha256",
                "ltfs_tree_sha256",
                "ltfs_rpm_sha256",
            )
        )
        or raw
        != (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "ascii"
        )
    ):
        raise QualificationRefused("physical LTFS artifact authority is invalid")
    return value["tool_sha256"]


@dataclass(frozen=True, slots=True)
class _PhysicalSnapshot:
    payload: dict[str, object]
    observed_sha256: str


def _collect_redacted_event_stream(
    descriptor: int, *, expected_operation_id: str
) -> str:
    payload = bytearray()
    invalid = False
    try:
        while chunk := os.read(descriptor, 8 * 1024):
            if invalid:
                continue
            if len(payload) + len(chunk) > _MAX_LTFS_EVENT_STREAM_BYTES:
                payload.clear()
                invalid = True
                continue
            payload.extend(chunk)
    except OSError:
        invalid = True
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    try:
        if (
            invalid
            or not payload
            or not payload.endswith(b"\n")
            or str(uuid.UUID(expected_operation_id)) != expected_operation_id
        ):
            return "invalid"
        result = "invalid"
        lines = bytes(payload).split(b"\n")
        for line in lines[:-1]:
            if not line:
                return "invalid"
            event = json.loads(line, object_pairs_hook=_closed_pairs)
            if (
                type(event) is not dict
                or type(event.get("schema")) is not int
                or event["schema"] != 1
                or event.get("operation_id") != expected_operation_id
                or type(event.get("code")) is not str
                or event["code"] not in _LTFS_EVENT_CODE_ALLOWLIST
            ):
                return "invalid"
            result = event["code"]
        return result
    except (
        UnicodeError,
        json.JSONDecodeError,
        QualificationRefused,
        RecursionError,
        ValueError,
    ):
        return "invalid"


class _RedactedLtfsEventCapture:
    def __init__(self, descriptor: int, *, expected_operation_id: str) -> None:
        self._descriptor = descriptor
        self._expected_operation_id = expected_operation_id
        self._diagnostic = "invalid"
        self._done = threading.Event()

    def collect(self) -> None:
        try:
            self._diagnostic = _collect_redacted_event_stream(
                self._descriptor,
                expected_operation_id=self._expected_operation_id,
            )
        finally:
            self._done.set()

    def diagnostic(self) -> str:
        if not self._done.wait(_LTFS_EVENT_DIAGNOSTIC_TIMEOUT):
            return "invalid"
        if self._diagnostic not in _LTFS_EVENT_CODE_ALLOWLIST:
            return "invalid"
        return self._diagnostic


class _SystemCommands:
    """Execute fixed package tools without shell expansion or retries."""

    def __init__(self, expected_tool_sha256: dict[str, str] | None = None) -> None:
        expected_tool_sha256 = (
            _load_tool_attestation()
            if expected_tool_sha256 is None
            else expected_tool_sha256
        )
        if (
            type(expected_tool_sha256) is not dict
            or frozenset(expected_tool_sha256) != frozenset(_TOOL_PATHS)
            or any(
                type(value) is not str
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
                for value in expected_tool_sha256.values()
            )
        ):
            raise QualificationRefused("physical LTFS tool attestation is invalid")
        try:
            admin_gid = grp.getgrnam(_ADMIN_GROUP).gr_gid
            if type(admin_gid) is not int or not 0 <= admin_gid < 1 << 32:
                raise ValueError
        except (KeyError, OSError, ValueError, TypeError):
            raise QualificationRefused(
                "physical LTFS tool ownership is unavailable"
            ) from None
        self._pins: dict[str, tuple[int, tuple[int, ...]]] = {}
        try:
            for name, path in _TOOL_PATHS.items():
                descriptor = -1
                try:
                    descriptor = os.open(
                        path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                    )
                    status = os.fstat(descriptor)
                    path_status = path.stat(follow_symlinks=False)
                    snapshot = (
                        status.st_dev,
                        status.st_ino,
                        status.st_mode,
                        status.st_nlink,
                        status.st_uid,
                        status.st_gid,
                        status.st_size,
                        status.st_mtime_ns,
                    )
                    expected_gid = admin_gid if name == "mkltfs" else 0
                    expected_mode = (
                        0o4755
                        if name == "fusermount"
                        else 0o750
                        if name == "mkltfs"
                        else 0o755
                    )
                    if (
                        not stat.S_ISREG(status.st_mode)
                        or status.st_uid != 0
                        or status.st_gid != expected_gid
                        or status.st_nlink != 1
                        or stat.S_IMODE(status.st_mode) != expected_mode
                        or (
                            path_status.st_dev,
                            path_status.st_ino,
                            path_status.st_mode,
                            path_status.st_nlink,
                            path_status.st_uid,
                            path_status.st_gid,
                            path_status.st_size,
                            path_status.st_mtime_ns,
                        )
                        != snapshot
                    ):
                        raise QualificationRefused("physical LTFS tool is not trusted")
                    if (
                        _sha256_descriptor(descriptor, status.st_size)
                        != expected_tool_sha256[name]
                    ):
                        raise QualificationRefused(
                            "physical LTFS tool attestation changed"
                        )
                    if _tool_snapshot(os.fstat(descriptor)) != snapshot:
                        raise QualificationRefused("physical LTFS tool changed")
                    self._pins[name] = (descriptor, snapshot)
                    descriptor = -1
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        pins, self._pins = self._pins, {}
        for descriptor, _snapshot in pins.values():
            try:
                os.close(descriptor)
            except OSError:
                pass

    def _argv(self, argv: tuple[str, ...]) -> tuple[tuple[str, ...], int]:
        if not argv or argv[0] not in self._pins:
            raise QualificationRefused("physical LTFS tool is not allowlisted")
        descriptor, expected = self._pins[argv[0]]
        status = os.fstat(descriptor)
        current = _tool_snapshot(status)
        if current != expected:
            raise QualificationRefused("physical LTFS tool changed")
        return (f"/proc/self/fd/{descriptor}", *argv[1:]), descriptor

    def run(self, argv: tuple[str, ...], *, timeout: float):
        try:
            exact_argv, descriptor = self._argv(argv)
            capture_probe = argv[0] == "ltfs-info"
            return subprocess.run(
                exact_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE if capture_probe else subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout,
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/bin:/usr/sbin",
                },
                pass_fds=(descriptor,),
            )
        except (OSError, subprocess.SubprocessError):
            raise QualificationRefused("physical LTFS command is unavailable") from None

    def start(self, argv: tuple[str, ...]):
        event_reader = -1
        event_descriptor = -1
        try:
            exact_argv, descriptor = self._argv(argv)
            if (
                exact_argv[1:2] != ("-f",)
                or len(exact_argv) < 3
                or not exact_argv[2].startswith("--operation-id=")
            ):
                raise QualificationRefused("physical LTFS mount grammar is invalid")
            operation_id = exact_argv[2].removeprefix("--operation-id=")
            try:
                if str(uuid.UUID(operation_id)) != operation_id:
                    raise ValueError
            except (AttributeError, ValueError):
                raise QualificationRefused(
                    "physical LTFS mount grammar is invalid"
                ) from None
            event_reader, event_descriptor = os.pipe2(os.O_CLOEXEC)
            exact_argv = (
                exact_argv[0],
                "-f",
                f"--event-fd={event_descriptor}",
                "--event-schema=1",
                *exact_argv[2:],
            )
            process = subprocess.Popen(
                exact_argv,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=None,
                env={
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PATH": "/usr/bin:/usr/sbin",
                },
                close_fds=True,
                pass_fds=(descriptor, event_descriptor),
            )
            os.close(event_descriptor)
            event_descriptor = -1
            capture = _RedactedLtfsEventCapture(
                event_reader,
                expected_operation_id=operation_id,
            )
            setattr(process, "ltfs_event_diagnostic", capture.diagnostic)
            drain = threading.Thread(
                target=capture.collect,
                name="lto-ltfs-event-drain",
                daemon=True,
            )
            drain.start()
            event_reader = -1
            return process
        except OSError:
            raise QualificationRefused("physical LTFS mount is unavailable") from None
        finally:
            if event_reader >= 0:
                os.close(event_reader)
            if event_descriptor >= 0:
                os.close(event_descriptor)


class PhysicalLtfsStageCommands:
    """Construct the only command shapes accepted by the physical runtime.

    Executable and device paths are fixed package/configuration authorities.
    The request contributes identity values only; it cannot contribute an
    executable, device path, mount point, option, or workspace path.
    """

    def __init__(
        self,
        *,
        tape_path: Path = Path(_TAPE),
        scsi_path: Path = Path(_SCSI),
        mount_path: Path = Path(_MOUNT),
        receipt_root: Path = Path(_RECEIPTS),
    ) -> None:
        if (
            not isinstance(tape_path, Path)
            or not isinstance(scsi_path, Path)
            or not isinstance(mount_path, Path)
            or not isinstance(receipt_root, Path)
            or not tape_path.is_absolute()
            or not scsi_path.is_absolute()
            or not mount_path.is_absolute()
            or not receipt_root.is_absolute()
            or not tape_path.is_relative_to(Path("/dev/tape/by-id"))
            or scsi_path.parent != Path("/dev")
            or not scsi_path.name.startswith("lto-archiver-scsi-")
            or len(scsi_path.name) <= len("lto-archiver-scsi-")
        ):
            raise QualificationRefused("physical LTFS command paths are invalid")
        self._tape_path = os.fspath(tape_path)
        self._scsi_path = os.fspath(scsi_path)
        self._mount_path = os.fspath(mount_path)
        self._receipt_root = os.fspath(receipt_root)

    @staticmethod
    def _operation_id(
        request: BrokerQualificationRequest, *, phase: str = "primary"
    ) -> str:
        if phase not in {"primary", "verify"}:
            raise QualificationRefused("physical LTFS receipt phase is invalid")
        return str(
            uuid.uuid5(
                _RECEIPT_NAMESPACE,
                f"{request.run_id}:{request.stage_ordinal}:{phase}:"
                f"{request.request_sha256}",
            )
        )

    def _receipt_path(
        self, request: BrokerQualificationRequest, *, phase: str = "primary"
    ) -> str:
        operation_id = PhysicalLtfsStageCommands._operation_id(request, phase=phase)
        canonical = json.dumps(
            {
                "operation_id": operation_id,
                "owner_generation": request.stage_ordinal,
                "request_sha256": request.request_sha256,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        name = hashlib.sha256(
            b"lto-ltfs-standalone-receipt-v1\0" + canonical
        ).hexdigest()
        return f"{self._receipt_root}/{name}.json"

    def _mount(
        self,
        request: BrokerQualificationRequest,
        *,
        read_only: bool,
        eject: bool,
        phase: str = "primary",
    ) -> tuple[str, ...]:
        options = (
            f"config_file={_CONFIG}",
            f"devname={self._scsi_path}",
            "sync_type=unmount",
            "eject" if eject else "noeject",
            f"standalone_receipt={self._receipt_path(request, phase=phase)}",
            *(("ro",) if read_only else ()),
        )
        return (
            "ltfs",
            "-f",
            f"--operation-id={self._operation_id(request, phase=phase)}",
            self._mount_path,
            "-o",
            ",".join(options),
        )

    def _mkltfs(
        self,
        request: BrokerQualificationRequest,
        destructive_flag: str | None,
    ) -> tuple[str, ...]:
        # mkltfs calls this option a tape serial, but LTFS writes it as the
        # six-character ANSI cartridge barcode.  The database tape_serial is
        # the distinct MAM volume serial and must never be substituted here.
        barcode = request.expected_physical_label
        barcode_arguments = (
            ("--tape-serial", barcode)
            if len(barcode) == 6
            and barcode.isascii()
            and all(
                character.isdigit() or "A" <= character <= "Z" for character in barcode
            )
            else ()
        )
        base = (
            "mkltfs",
            "--config",
            _CONFIG,
            "--device",
            self._scsi_path,
            "--volume-name",
            request.expected_physical_label,
            *barcode_arguments,
            "--no-compression",
            "--force",
            "--quiet",
        )
        return base if destructive_flag is None else (*base, destructive_flag)

    def for_operation(
        self,
        operation: QualificationOperation,
        request: BrokerQualificationRequest,
    ) -> tuple[tuple[str, ...], ...]:
        if (
            type(operation) is QualificationOperation
            and operation not in SUPPORTED_QUALIFICATION_OPERATIONS
        ):
            raise QualificationRefused("physical LTFS operation is unsupported")
        if (
            type(operation) is not QualificationOperation
            or type(request) is not BrokerQualificationRequest
            or request.operation is not operation
        ):
            raise QualificationRefused("physical LTFS command request is invalid")
        if operation is QualificationOperation.FORMAT:
            return (self._mkltfs(request, None),)
        if operation is QualificationOperation.WIPE:
            return (self._mkltfs(request, "--wipe"),)
        if operation is QualificationOperation.REPAIR:
            return (
                (
                    "ltfsck",
                    "--config",
                    _CONFIG,
                    self._scsi_path,
                ),
                (
                    "ltfsck",
                    "--config",
                    _CONFIG,
                    "--full-recovery",
                    self._scsi_path,
                ),
            )
        if operation is QualificationOperation.UNLOAD:
            return (self._mount(request, read_only=True, eject=True),)
        if operation is QualificationOperation.LOAD:
            return (("mt", "-f", self._tape_path, "load"),)
        if operation is QualificationOperation.EJECT:
            return (("mt", "-f", self._tape_path, "eject"),)
        if operation is QualificationOperation.READ_ONLY:
            return (self._mount(request, read_only=True, eject=False),)
        if operation in {
            QualificationOperation.ADDITIVE_WRITE,
            QualificationOperation.OVERWRITE,
        }:
            return (self._mount(request, read_only=False, eject=False),)
        raise QualificationRefused("physical LTFS operation is not allowlisted")


class SystemPhysicalLtfsQualificationRuntime:
    """Execute one pre-authorized stage against the configured physical tape.

    The caller supplies no paths or options.  Every invocation re-probes the
    drive and medium and compares the complete broker-sealed identity before a
    command can cross its dispatch boundary.
    """

    def __init__(
        self,
        *,
        settings: LinuxSettings,
        receipt_root: LtfsStandaloneReceiptRoot,
        workspace_root: Path,
        commands: object | None = None,
        device_provider: object | None = None,
    ) -> None:
        if type(settings) is not LinuxSettings:
            raise TypeError("invalid physical LTFS settings")
        settings.validate()
        if type(receipt_root) is not LtfsStandaloneReceiptRoot:
            raise TypeError("invalid physical LTFS receipt root")
        if not isinstance(workspace_root, Path) or not workspace_root.is_absolute():
            raise TypeError("invalid physical LTFS workspace")
        self._settings = settings
        self._receipt_root = receipt_root
        self._workspace_root = workspace_root
        owns_commands = commands is None
        self._commands = _SystemCommands() if owns_commands else commands
        try:
            self._device_provider = (
                SysfsDeviceIdentityProvider()
                if device_provider is None
                else device_provider
            )
            self._grammar = PhysicalLtfsStageCommands(
                tape_path=settings.tape_device_path,
                scsi_path=settings.scsi_device_path,
                mount_path=settings.mount_path,
                receipt_root=receipt_root.path,
            )
            self._assert_workspace()
        except BaseException:
            if owns_commands:
                self.close()
            raise

    def close(self) -> None:
        close = getattr(self._commands, "close", None)
        if callable(close):
            close()

    def _assert_workspace(self) -> None:
        try:
            status = self._workspace_root.stat(follow_symlinks=False)
            resolved = self._workspace_root.resolve(strict=True)
        except OSError:
            raise QualificationRefused(
                "physical LTFS workspace is unavailable"
            ) from None
        if (
            resolved != self._workspace_root
            or not stat.S_ISDIR(status.st_mode)
            or stat.S_IMODE(status.st_mode) != 0o700
            or status.st_uid != os.geteuid()
            or status.st_gid != os.getegid()
            or status.st_nlink < 2
        ):
            raise QualificationRefused("physical LTFS workspace is unavailable")

    def _device_authority(self) -> dict[str, object]:
        descriptor = -1
        try:
            descriptor = os.open(
                _DEVICE_CONFIG, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            admin_gid = grp.getgrnam(_ADMIN_GROUP).gr_gid
            status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_uid != 0
                or status.st_gid != admin_gid
                or stat.S_IMODE(status.st_mode) != 0o640
                or status.st_nlink != 1
                or not 0 < status.st_size <= 4096
            ):
                raise QualificationRefused("physical LTFS device authority is invalid")
            raw = os.read(descriptor, 4097)
            if len(raw) != status.st_size:
                raise QualificationRefused("physical LTFS device authority changed")
            value = json.loads(raw, object_pairs_hook=_closed_pairs)
        except (KeyError, OSError, UnicodeError, json.JSONDecodeError):
            raise QualificationRefused(
                "physical LTFS device authority is unavailable"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if type(value) is not dict or frozenset(value) != frozenset(
            {"nst_path", "sg_path", "serial", "wwid"}
        ):
            raise QualificationRefused("physical LTFS device authority is invalid")
        return value

    def _probe(
        self,
        request: BrokerQualificationRequest,
        *,
        allow_blank: bool,
        phase: str,
        bind_prior_media: bool = True,
    ) -> _PhysicalSnapshot:
        probe_mode = "pre-format" if allow_blank else "unmounted"
        completed = self._commands.run(
            ("ltfs-info", "--json", "--mode", probe_mode), timeout=30.0
        )
        if completed.returncode != 0:
            _report_command_failure("ltfs-info", phase, completed.returncode)
            raise QualificationRefused("physical LTFS probe failed")
        if len(completed.stdout) > 4096:
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="output_oversized"
            )
            raise QualificationRefused("physical LTFS probe failed")
        try:
            payload = json.loads(
                completed.stdout.decode("utf-8", errors="strict"),
                object_pairs_hook=_closed_pairs,
            )
        except (
            UnicodeError,
            json.JSONDecodeError,
            AttributeError,
            QualificationRefused,
        ):
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="output_malformed"
            )
            raise QualificationRefused("physical LTFS probe is invalid") from None
        keys = frozenset(
            {
                "schema",
                "media_state",
                "tape_by_id",
                "scsi_by_id",
                "drive_serial",
                "mam_barcode",
                "mam_volume_serial",
                "ltfs_volume_label",
                "ltfs_volume_uuid",
                "index_generation",
            }
        )
        if (
            type(payload) is not dict
            or frozenset(payload) != keys
            or payload["schema"] != 2
        ):
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="schema_invalid"
            )
            raise QualificationRefused("physical LTFS probe is invalid")
        try:
            self._assert_device_binding(request)
        except Exception:
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="identity_mismatch"
            )
            raise
        mam_volume_serial = payload["mam_volume_serial"]
        if (
            payload["tape_by_id"] != str(self._settings.tape_device_path)
            or payload["scsi_by_id"] != str(self._settings.scsi_device_path)
            or payload["drive_serial"] != request.expected_drive_serial
            or type(mam_volume_serial) is not str
            or not 0 < len(mam_volume_serial) <= 255
            or not mam_volume_serial.isascii()
            or not mam_volume_serial.isprintable()
            or (
                request.expected_mam_medium_serial is not None
                and mam_volume_serial != request.expected_mam_medium_serial
            )
        ):
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="identity_mismatch"
            )
            raise QualificationRefused("physical LTFS identity mismatch")
        label = payload["ltfs_volume_label"]
        volume_uuid = payload["ltfs_volume_uuid"]
        generation = payload["index_generation"]
        if payload["media_state"] == "ltfs":
            try:
                parsed_uuid = uuid.UUID(volume_uuid)
            except (ValueError, AttributeError, TypeError):
                _report_command_failure(
                    "ltfs-info",
                    phase,
                    completed.returncode,
                    reason="identity_mismatch",
                )
                raise QualificationRefused(
                    "physical LTFS media identity is invalid"
                ) from None
            if (
                str(parsed_uuid) != volume_uuid
                or parsed_uuid.variant != uuid.RFC_4122
                or parsed_uuid.version not in {1, 2, 3, 4, 5}
                or payload["mam_barcode"] != request.expected_physical_label
                or label != request.expected_physical_label
                or type(generation) is not int
                or not 0 < generation < 1 << 64
            ):
                _report_command_failure(
                    "ltfs-info",
                    phase,
                    completed.returncode,
                    reason="identity_mismatch",
                )
                raise QualificationRefused("physical LTFS media identity is invalid")
        elif payload["media_state"] == "unidentified":
            if (
                not allow_blank
                or (
                    payload["mam_barcode"] is not None
                    and payload["mam_barcode"]
                    != request.expected_physical_label
                )
                or label is not None
                or volume_uuid is not None
                or generation is not None
            ):
                _report_command_failure(
                    "ltfs-info",
                    phase,
                    completed.returncode,
                    reason="identity_mismatch",
                )
                raise QualificationRefused("physical LTFS media state is incomplete")
        else:
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="identity_mismatch"
            )
            raise QualificationRefused("physical LTFS media state is incomplete")
        if (
            bind_prior_media
            and request.expected_volume_uuid is not None
            and (
                volume_uuid != request.expected_volume_uuid
                or generation != request.expected_generation
            )
        ):
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="identity_mismatch"
            )
            raise QualificationRefused("physical LTFS generation changed")
        observed = MediaIdentity(
            drive_serial=payload["drive_serial"],
            mam_barcode=payload["mam_barcode"],
            mam_volume_serial=payload["mam_volume_serial"],
            ltfs_volume_label=label,
            ltfs_volume_uuid=volume_uuid,
        )
        observed_sha256 = media_identity_sha256(observed.canonical_fields())
        if (
            bind_prior_media
            and observed_sha256 != request.observed_media_identity_sha256
        ):
            _report_command_failure(
                "ltfs-info", phase, completed.returncode, reason="identity_mismatch"
            )
            raise QualificationRefused("physical LTFS media digest changed")
        return _PhysicalSnapshot(payload, observed_sha256)

    def _assert_device_binding(self, request: BrokerQualificationRequest) -> None:
        authority = self._device_authority()
        if (
            authority["nst_path"] != str(self._settings.tape_device_path)
            or authority["sg_path"] != str(self._settings.scsi_device_path)
            or authority["serial"] != request.expected_drive_serial
            or authority["wwid"] != request.expected_drive_wwid
        ):
            raise QualificationRefused("physical LTFS device authority mismatch")
        tape = self._device_provider.resolve(self._settings.tape_device_path)
        scsi = self._device_provider.resolve(self._settings.scsi_device_path)
        binding = HardwareTargetBinding.from_verified_inputs(
            self._settings.mount_path,
            tape.canonical_json(),
            scsi.canonical_json(),
            ("qualification", "qualification", "1", "label", "serial", ""),
        )
        if (
            tape.scsi_unit_identity != scsi.scsi_unit_identity
            or binding.tape_device_identity_sha256
            != request.tape_device_identity_sha256
            or binding.scsi_device_identity_sha256
            != request.scsi_device_identity_sha256
        ):
            raise QualificationRefused("physical LTFS device tuple changed")

    def _stage_directory(self, request: BrokerQualificationRequest) -> Path:
        self._assert_workspace()
        run = self._workspace_root / request.run_id
        stage = (
            self._workspace_root
            / request.run_id
            / f"{request.stage_ordinal:04d}-{request.operation.value}"
        )
        try:
            run.mkdir(mode=0o700, exist_ok=True)
            stage.mkdir(mode=0o700, exist_ok=False)
        except OSError:
            raise QualificationRefused("physical LTFS stage already exists") from None
        return stage

    @staticmethod
    def _hash_file(path: Path, expected: os.stat_result) -> str:
        if not 0 <= expected.st_size <= _MAX_MANIFEST_FILE_BYTES:
            raise QualificationRefused("physical LTFS content is too large")
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (
                    expected.st_dev,
                    expected.st_ino,
                    expected.st_size,
                    expected.st_mtime_ns,
                )
            ):
                raise QualificationRefused("physical LTFS content changed")
            digest = hashlib.sha256()
            remaining = before.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise QualificationRefused("physical LTFS content changed")
                digest.update(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            if (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
            ) != (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ):
                raise QualificationRefused("physical LTFS content changed")
            return digest.hexdigest()
        except OSError:
            raise QualificationRefused("physical LTFS content is unavailable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _xattrs(path: Path) -> list[dict[str, object]]:
        try:
            names = sorted(os.listxattr(path, follow_symlinks=False))
            records = []
            for name in names:
                if (
                    type(name) is not str
                    or not name
                    or not name.isascii()
                    or len(name.encode("ascii")) > 255
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for character in name
                    )
                ):
                    raise QualificationRefused("physical LTFS xattr is unsupported")
                value = os.getxattr(path, name, follow_symlinks=False)
                if len(value) > 4096:
                    raise QualificationRefused("physical LTFS xattr is too large")
                records.append(
                    {
                        "name": name,
                        "value": base64.b64encode(value).decode("ascii"),
                    }
                )
            return records
        except OSError:
            raise QualificationRefused("physical LTFS xattr is unavailable") from None

    @staticmethod
    def _manifest(root: Path) -> str:
        records: list[dict[str, object]] = []
        total_bytes = 0
        if root.exists():
            for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
                status = path.lstat()
                relative = path.relative_to(root).as_posix()
                if path.is_symlink():
                    raise QualificationRefused("physical LTFS content contains symlink")
                if path.is_dir():
                    records.append(
                        {
                            "kind": "directory",
                            "path": relative,
                            "xattrs": SystemPhysicalLtfsQualificationRuntime._xattrs(
                                path
                            ),
                        }
                    )
                elif path.is_file():
                    total_bytes += status.st_size
                    if total_bytes > _MAX_MANIFEST_TOTAL_BYTES:
                        raise QualificationRefused("physical LTFS content is too large")
                    records.append(
                        {
                            "kind": "file",
                            "path": relative,
                            "sha256": SystemPhysicalLtfsQualificationRuntime._hash_file(
                                path, status
                            ),
                            "size": status.st_size,
                            "xattrs": SystemPhysicalLtfsQualificationRuntime._xattrs(
                                path
                            ),
                        }
                    )
                else:
                    raise QualificationRefused("physical LTFS content is unsupported")
        encoded = json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(
            b"lto-physical-content-manifest/v1\0" + encoded
        ).hexdigest()

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = -1
        try:
            descriptor = os.open(
                path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            os.fsync(descriptor)
        except OSError:
            raise QualificationRefused("physical LTFS content is not durable") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _content_action(
        self, operation: QualificationOperation, request: BrokerQualificationRequest
    ) -> str:
        owned = self._settings.mount_path / ".lto-qualification" / request.run_id
        if operation is QualificationOperation.READ_ONLY:
            return self._manifest(owned)
        if operation is QualificationOperation.ADDITIVE_WRITE:
            owned.mkdir(parents=True, mode=0o700, exist_ok=False)
            original = owned / "payload.bin"
            original.write_bytes(
                hashlib.sha256(
                    b"lto-qualification-payload/v1\0"
                    + request.request_sha256.encode("ascii")
                ).digest()
            )
            with original.open("ab") as stream:
                stream.write(b"\nappend\n")
                stream.flush()
                os.fsync(stream.fileno())
            renamed = owned / "qualified.bin"
            original.rename(renamed)
            with renamed.open("r+b") as stream:
                stream.truncate(24)
                stream.flush()
                os.fsync(stream.fileno())
            os.setxattr(
                renamed,
                "user.lto_qualification",
                request.request_sha256.encode("ascii"),
                follow_symlinks=False,
            )
            with renamed.open("rb") as stream:
                os.fsync(stream.fileno())
            sparse = owned / "sparse.bin"
            with sparse.open("xb") as stream:
                stream.seek(1024 * 1024)
                stream.write(b"SPARSE-END")
                stream.flush()
                os.fsync(stream.fileno())
            nested = owned / "directory"
            nested.mkdir(mode=0o700)
            nested_file = nested / "nested.bin"
            with nested_file.open("xb") as stream:
                stream.write(b"nested-content")
                stream.flush()
                os.fsync(stream.fileno())
            deleted = owned / "delete.bin"
            deleted.write_bytes(b"delete")
            deleted.unlink()
            self._sync_directory(nested)
            self._sync_directory(owned)
            self._sync_directory(owned.parent)
            self._sync_directory(self._settings.mount_path)
            return self._manifest(owned)
        if operation is QualificationOperation.OVERWRITE:
            target = owned / "qualified.bin"
            if not target.is_file() or target.is_symlink():
                raise QualificationRefused("physical LTFS overwrite target is absent")
            with target.open("r+b") as stream:
                stream.seek(0)
                stream.write(b"QUALIFIED-OVERWRITE")
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
            self._sync_directory(owned)
            return self._manifest(owned)
        return hashlib.sha256(
            b"lto-physical-stage-no-content/v1\0" + request.request_sha256.encode()
        ).hexdigest()

    def _write_evidence(
        self,
        stage: Path,
        request: BrokerQualificationRequest,
        *,
        child_exit_code: int,
        content_sha256: str,
        terminal_sha256: str | None,
        receipt_chain_sha256s: tuple[str, ...] = (),
    ) -> BrokerQualificationExecution:
        payload = (
            json.dumps(
                {
                    "child_exit_code": child_exit_code,
                    "content_manifest_sha256": content_sha256,
                    "operation": request.operation.value,
                    "request_sha256": request.request_sha256,
                    "run_id": request.run_id,
                    "schema": 1,
                    "stage_ordinal": request.stage_ordinal,
                    "terminal_receipt_chain_sha256s": list(receipt_chain_sha256s),
                    "terminal_sha256": terminal_sha256,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("ascii")
        evidence = stage / "evidence.json"
        descriptor = os.open(
            evidence,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            written = 0
            while written < len(payload):
                count = os.write(descriptor, payload[written:])
                if count <= 0:
                    raise QualificationRefused("physical LTFS evidence is unavailable")
                written += count
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        self._sync_directory(stage.parent)
        self._sync_directory(self._workspace_root)
        evidence_sha256 = hashlib.sha256(payload).hexdigest()
        return BrokerQualificationExecution(
            terminal_receipt_sha256=terminal_sha256 or evidence_sha256,
            child_exit_code=child_exit_code,
            evidence_sha256=evidence_sha256,
        )

    def _execute_mount_cycle(
        self,
        operation: QualificationOperation,
        request: BrokerQualificationRequest,
        *,
        prior: _PhysicalSnapshot,
        phase: str,
        expected_generation: int,
        content_operation: QualificationOperation,
    ) -> tuple[str, LtfsStandaloneReceipt]:
        read_only = content_operation in {
            QualificationOperation.READ_ONLY,
            QualificationOperation.UNLOAD,
            QualificationOperation.EJECT,
        }
        operation_id = self._grammar._operation_id(request, phase=phase)
        target = self._receipt_root.target_path(
            operation_id=operation_id,
            owner_generation=request.stage_ordinal,
            request_sha256=request.request_sha256,
        )
        expected_target = Path(self._grammar._receipt_path(request, phase=phase))
        if target != expected_target:
            raise QualificationRefused("physical LTFS receipt target changed")
        argv = (
            self._grammar.for_operation(operation, request)[0]
            if phase == "primary"
            else self._grammar._mount(
                request, read_only=True, eject=False, phase="verify"
            )
        )
        process = self._commands.start(argv)
        child_exited = threading.Event()
        child_outcome: list[int | BaseException] = []

        def wait_for_child() -> None:
            try:
                child_outcome.append(process.wait())
            except BaseException as error:  # noqa: BLE001 - preserve ambiguity
                child_outcome.append(error)
            finally:
                child_exited.set()

        child_waiter = threading.Thread(
            target=wait_for_child,
            name="lto-ltfs-child-waiter",
            daemon=True,
        )
        child_waiter.start()
        cycle_phase = "ready_receipt"
        content_error: BaseException | None = None
        try:
            ready = self._receipt_root.wait_ready(
                operation_id=operation_id,
                owner_generation=request.stage_ordinal,
                request_sha256=request.request_sha256,
                expected_media_identity_sha256=request.observed_media_identity_sha256,
                expected_read_only=read_only,
                timeout=300.0,
                child_running=lambda: not child_exited.is_set(),
            )
            cycle_phase = "mounted_identity"
            if (
                ready.volume_uuid != request.expected_volume_uuid
                or ready.prior_generation != expected_generation
                or ready.mam_barcode != request.expected_physical_label
                or ready.ltfs_volume_label != request.expected_physical_label
                or ready.mam_volume_serial != prior.payload["mam_volume_serial"]
                or (
                    request.expected_mam_medium_serial is not None
                    and ready.mam_volume_serial != request.expected_mam_medium_serial
                )
                or ready.drive_serial != request.expected_drive_serial
            ):
                raise QualificationRefused(
                    "physical LTFS mounted identity mismatch"
                )
            cycle_phase = "content"
            content_sha256 = self._content_action(content_operation, request)
        except BaseException as error:  # noqa: BLE001 - mounted media must finalize
            if cycle_phase == "content" and isinstance(error, OSError):
                print(
                    f"LTFS content action failed: errno={error.errno}",
                    file=sys.stderr,
                    flush=True,
                )
                content_error = QualificationRefused(
                    "physical LTFS content action failed"
                )
            else:
                if cycle_phase != "content":
                    print(
                        f"LTFS mount cycle failed: phase={cycle_phase}",
                        file=sys.stderr,
                        flush=True,
                    )
                content_error = error
        unmount_error: BaseException | None = None
        try:
            unmount = self._commands.run(
                ("fusermount", "-u", "--", str(self._settings.mount_path)),
                timeout=300.0,
            )
            if unmount.returncode != 0:
                unmount_error = QualificationRefused("physical LTFS unmount failed")
        except BaseException as error:  # noqa: BLE001 - started LTFS must finalize
            unmount_error = error
        if not child_exited.wait(_TERMINAL_TIMEOUT):
            raise QualificationRefused(
                "physical LTFS finalization remains ambiguous"
            )
        child_waiter.join()
        if len(child_outcome) != 1 or type(child_outcome[0]) is not int:
            raise QualificationRefused(
                "physical LTFS finalization remains ambiguous"
            )
        child_exit = child_outcome[0]
        if child_exit != 0:
            if cycle_phase == "ready_receipt":
                diagnostic = "invalid"
                read_diagnostic = getattr(process, "ltfs_event_diagnostic", None)
                if callable(read_diagnostic):
                    try:
                        candidate = read_diagnostic()
                    except BaseException:  # noqa: BLE001 - redact all failures
                        candidate = "invalid"
                    if (
                        type(candidate) is str
                        and candidate in _LTFS_EVENT_CODE_ALLOWLIST
                    ):
                        diagnostic = candidate
                print(
                    f"LTFS mount child failed: event={diagnostic} exit={child_exit}",
                    file=sys.stderr,
                    flush=True,
                )
            raise QualificationRefused("physical LTFS finalization failed")
        if unmount_error is not None:
            raise unmount_error from None
        if content_error is not None:
            raise content_error from None
        receipt = self._receipt_root.read_terminal(
            operation_id=operation_id,
            owner_generation=request.stage_ordinal,
            request_sha256=request.request_sha256,
        )
        if (
            receipt.volume_uuid != request.expected_volume_uuid
            or receipt.prior_generation != expected_generation
            or (read_only and receipt.new_generation != expected_generation)
        ):
            raise QualificationRefused("physical LTFS terminal generation mismatch")
        return content_sha256, receipt

    def _execute_mount(
        self,
        operation: QualificationOperation,
        request: BrokerQualificationRequest,
        stage: Path,
        prior: _PhysicalSnapshot,
    ) -> BrokerQualificationExecution:
        if request.expected_generation is None:
            raise QualificationRefused("physical LTFS generation is unavailable")
        content_sha256, primary = self._execute_mount_cycle(
            operation,
            request,
            prior=prior,
            phase="primary",
            expected_generation=request.expected_generation,
            content_operation=operation,
        )
        receipt_chain = [primary.terminal_sha256]
        terminal = primary
        if operation in {
            QualificationOperation.ADDITIVE_WRITE,
            QualificationOperation.OVERWRITE,
        }:
            if primary.new_generation <= request.expected_generation:
                raise QualificationRefused(
                    "physical LTFS write did not advance generation"
                )
            verified_sha256, terminal = self._execute_mount_cycle(
                operation,
                request,
                prior=prior,
                phase="verify",
                expected_generation=primary.new_generation,
                content_operation=QualificationOperation.READ_ONLY,
            )
            if verified_sha256 != content_sha256:
                raise QualificationRefused("physical LTFS readback digest mismatch")
            receipt_chain.append(terminal.terminal_sha256)
        if operation is QualificationOperation.UNLOAD:
            terminal_probe_returncode = self._require_terminal_media_state(operation)
            content_sha256 = hashlib.sha256(
                b"lto-physical-terminal-state/v1\0"
                + content_sha256.encode("ascii")
                + str(terminal_probe_returncode).encode("ascii")
            ).hexdigest()
        return self._write_evidence(
            stage,
            request,
            child_exit_code=0,
            content_sha256=content_sha256,
            terminal_sha256=terminal.terminal_sha256,
            receipt_chain_sha256s=tuple(receipt_chain),
        )

    def _require_terminal_media_state(
        self,
        operation: QualificationOperation,
    ) -> int:
        expected_returncode = {
            QualificationOperation.WIPE: 5,
            QualificationOperation.UNLOAD: 3,
            QualificationOperation.EJECT: 3,
        }.get(operation)
        if expected_returncode is None:
            raise QualificationRefused(
                "physical LTFS terminal probe is not allowlisted"
            )
        completed = self._commands.run(
            ("ltfs-info", "--json", "--mode", "unmounted"), timeout=30.0
        )
        if completed.returncode != expected_returncode or completed.stdout != b"":
            if completed.returncode != expected_returncode:
                _report_command_failure(
                    "ltfs-info",
                    f"{operation.value}_terminal_probe",
                    completed.returncode,
                )
            else:
                _report_command_failure(
                    "ltfs-info",
                    f"{operation.value}_terminal_probe",
                    completed.returncode,
                    reason="output_unexpected",
                )
            detail = (
                "physical LTFS medium remains formatted"
                if operation is QualificationOperation.WIPE
                else "physical LTFS eject state is ambiguous"
                if operation is QualificationOperation.EJECT
                else "physical LTFS unloaded state is ambiguous"
            )
            raise QualificationRefused(detail)
        return expected_returncode

    def execute(
        self,
        operation: QualificationOperation,
        request: BrokerQualificationRequest,
    ) -> BrokerQualificationExecution:
        if (
            type(operation) is not QualificationOperation
            or operation not in SUPPORTED_QUALIFICATION_OPERATIONS
            or type(request) is not BrokerQualificationRequest
            or request.operation is not operation
        ):
            raise QualificationRefused("physical LTFS stage is invalid")
        request.require_execution_authority()
        prior = None
        if operation is QualificationOperation.LOAD:
            self._assert_device_binding(request)
        else:
            prior = self._probe(
                request,
                allow_blank=operation is QualificationOperation.FORMAT,
                phase=f"pre_{operation.value}_probe",
            )
        stage = self._stage_directory(request)
        if operation in {
            QualificationOperation.READ_ONLY,
            QualificationOperation.ADDITIVE_WRITE,
            QualificationOperation.OVERWRITE,
            QualificationOperation.UNLOAD,
        }:
            if prior is None:
                raise QualificationRefused("physical LTFS prior identity is unavailable")
            return self._execute_mount(operation, request, stage, prior)
        commands = self._grammar.for_operation(operation, request)
        repair_check_returncode: int | None = None
        if operation is QualificationOperation.REPAIR:
            checked = self._commands.run(commands[0], timeout=_TERMINAL_TIMEOUT)
            repair_check_returncode = checked.returncode
            if repair_check_returncode not in qualification_success_exit_codes(
                operation
            ):
                _report_command_failure(
                    "ltfsck", "repair_precheck", repair_check_returncode
                )
                raise QualificationRefused("physical LTFS read-only check failed")
            argv = commands[1]
        else:
            argv = commands[0]
        completed = self._commands.run(argv, timeout=_TERMINAL_TIMEOUT)
        accepted = qualification_success_exit_codes(operation)
        if completed.returncode not in accepted:
            _report_command_failure(
                argv[0], f"{operation.value}_command", completed.returncode
            )
            raise QualificationRefused("physical LTFS command failed")
        content_sha256 = hashlib.sha256(
            b"lto-physical-command-evidence/v1\0"
            + request.request_sha256.encode("ascii")
            + str(completed.returncode).encode("ascii")
        ).hexdigest()
        if repair_check_returncode is not None:
            content_sha256 = hashlib.sha256(
                b"lto-physical-repair-precheck/v1\0"
                + content_sha256.encode("ascii")
                + str(repair_check_returncode).encode("ascii")
            ).hexdigest()
        if operation in {
            QualificationOperation.WIPE,
            QualificationOperation.EJECT,
        }:
            terminal_probe_returncode = self._require_terminal_media_state(operation)
            content_sha256 = hashlib.sha256(
                b"lto-physical-terminal-state/v1\0"
                + content_sha256.encode("ascii")
                + str(terminal_probe_returncode).encode("ascii")
            ).hexdigest()
        if operation in {
            QualificationOperation.FORMAT,
            QualificationOperation.REPAIR,
            QualificationOperation.LOAD,
        }:
            # The CLI performs the catalog-bound post-probe.  The broker also
            # requires at least the exact labels/serials before returning.
            post = self._probe(
                request,
                allow_blank=False,
                phase=f"post_{operation.value}_probe",
                bind_prior_media=operation is QualificationOperation.LOAD,
            )
            if operation is QualificationOperation.FORMAT and prior is not None:
                if (
                    post.payload["media_state"] != "ltfs"
                    or post.payload["mam_barcode"]
                    != request.expected_physical_label
                    or post.payload["ltfs_volume_label"]
                    != request.expected_physical_label
                    or type(post.payload["index_generation"]) is not int
                    or post.payload["index_generation"] <= 0
                ):
                    raise QualificationRefused(
                        "physical LTFS post-format identity is invalid"
                    )
                if (
                    post.payload["mam_volume_serial"]
                    != prior.payload["mam_volume_serial"]
                ):
                    raise QualificationRefused(
                        "physical LTFS format MAM identity changed"
                    )
                if (
                    post.payload["ltfs_volume_uuid"]
                    == prior.payload["ltfs_volume_uuid"]
                ):
                    raise QualificationRefused(
                        "physical LTFS format did not replace UUID"
                    )
            if operation is QualificationOperation.REPAIR and (
                request.expected_volume_uuid is None
                or request.expected_generation is None
                or post.payload["ltfs_volume_uuid"] != request.expected_volume_uuid
                or post.payload["index_generation"] < request.expected_generation
            ):
                raise QualificationRefused("physical LTFS repair identity changed")
            content_sha256 = post.observed_sha256
        return self._write_evidence(
            stage,
            request,
            child_exit_code=completed.returncode,
            content_sha256=content_sha256,
            terminal_sha256=None,
        )
