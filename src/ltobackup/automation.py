from __future__ import annotations

import ctypes
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol

from .catalog import Catalog
from .errors import CapacityError, CopyError, OperationCancelled, ValidationError
from .models import VolumeInfo
from .media import get_lto_media_profile
from .settings import AppPaths, Settings
from .volume import assert_registered_tape, inspect_volume, require_ltfs


ProgressCallback = Callable[[dict], None]
StopRequested = Callable[[], bool]
BackupCallback = Callable[
    [list[str], str, Path | VolumeInfo, ProgressCallback | None, StopRequested], dict
]


@dataclass(frozen=True)
class CassetteLabel:
    physical_label: str
    tape_serial: str


def _used_drive_letters() -> set[str]:
    if os.name != "nt":
        return set()
    mask = int(ctypes.windll.kernel32.GetLogicalDrives())  # type: ignore[attr-defined]
    return {
        chr(ord("A") + index)
        for index in range(26)
        if mask & (1 << index)
    }


def choose_mount_path(requested: Path, used_letters: set[str] | None = None) -> Path:
    """Resolve AUTO to a free Windows drive letter, preferring L: for LTFS."""
    value = str(requested).strip().upper().rstrip("\\/")
    used = {
        str(letter).strip().upper().rstrip(":\\/")
        for letter in (_used_drive_letters() if used_letters is None else used_letters)
    }
    if value in {"", "AUTO", "AUTOMATICA", "AUTOMATICO"}:
        for letter in "LMNOPQRSTUVWXYZKJIHGFED":
            if letter not in used:
                return Path(f"{letter}:\\")
        raise ValidationError("Nessuna lettera di unita disponibile per il mount LTFS")
    if not re.fullmatch(r"[D-Z]:", value):
        raise ValidationError("La lettera LTFS deve essere AUTO oppure compresa tra D: e Z:")
    letter = value[0]
    if letter in used:
        raise ValidationError(f"La lettera di unita {value} e gia in uso")
    return Path(value + "\\")


def _mount_path_visible(path: Path) -> bool:
    value = str(path).strip().upper().rstrip("\\/")
    if os.name == "nt" and re.fullmatch(r"[A-Z]:", value):
        return value[0] in _used_drive_letters()
    return path.exists()


def normalize_cassette_labels(
    values: list[str] | tuple[str, ...],
    *,
    media_key: str = "LTO-6",
) -> list[CassetteLabel]:
    profile = get_lto_media_profile(media_key)
    suffix = profile.barcode_suffix
    result: list[CassetteLabel] = []
    serials: set[str] = set()
    labels: set[str] = set()
    for raw in values:
        label = raw.strip().upper()
        if not label:
            continue
        if re.fullmatch(r"[A-Z0-9]{6}", label):
            serial = label
        elif re.fullmatch(rf"[A-Z0-9]{{6}}{re.escape(suffix)}", label):
            serial = label[:6]
        elif re.fullmatch(r"[A-Z0-9]{6}(?:L[0-9A-Z]|P[0-9A-Z])", label):
            raise ValidationError(
                f"Etichetta {label}: il suffisso deve essere {suffix} per una cassetta {profile.key}"
            )
        else:
            raise ValidationError(
                f"Etichetta {label or raw!r} non valida: usare 6 caratteri A-Z/0-9 "
                f"oppure il barcode a 8 caratteri terminante in {suffix}"
            )
        if label in labels or serial in serials:
            raise ValidationError(f"Etichetta o seriale LTFS duplicata: {label}")
        labels.add(label)
        serials.add(serial)
        result.append(CassetteLabel(label, serial))
    if not result:
        raise ValidationError("Indicare almeno un'etichetta cassetta")
    return result


class StoreOpenInterface(Protocol):
    def wait_for_media(self, stop_requested: StopRequested) -> bool: ...
    def format(self, cassette: CassetteLabel) -> None: ...
    def mount(self, stop_requested: StopRequested) -> Path: ...
    def unmount_and_eject(self) -> None: ...


@dataclass(frozen=True)
class StoreOpenMapping:
    letter: str
    device_name: str
    serial_number: str
    command_line: str
    managed_by: str = ""


class StoreOpenPlatform(Protocol):
    def list_mappings(self) -> Mapping[str, StoreOpenMapping]: ...
    def service_state(self) -> str: ...
    def mapping_visible(self, letter: str) -> bool: ...
    def write_mapping(self, mapping: StoreOpenMapping) -> None: ...
    def delete_mapping(self, letter: str) -> None: ...
    def start_service(self) -> None: ...
    def stop_service(self) -> None: ...


class WindowsStoreOpenPlatform:
    REGISTRY_ROOT = r"SOFTWARE\HPE\LTFS\Mappings"
    SERVICE_NAME = "FUSE4WinSvc"

    def list_mappings(self) -> dict[str, StoreOpenMapping]:
        if os.name != "nt":
            raise ValidationError("Le mappature StoreOpen sono disponibili solo su Windows")
        import winreg

        result: dict[str, StoreOpenMapping] = {}
        access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.REGISTRY_ROOT, 0, access)
        except FileNotFoundError:
            return result
        with root:
            index = 0
            while True:
                try:
                    name = winreg.EnumKey(root, index)
                except OSError:
                    break
                index += 1
                with winreg.OpenKey(root, name, 0, access) as key:
                    try:
                        managed_by = str(winreg.QueryValueEx(key, "ManagedBy")[0])
                    except OSError:
                        managed_by = ""
                    result[name.upper()] = StoreOpenMapping(
                        letter=name.upper(),
                        device_name=str(winreg.QueryValueEx(key, "DeviceName")[0]),
                        serial_number=str(winreg.QueryValueEx(key, "SerialNumber")[0]),
                        command_line=str(winreg.QueryValueEx(key, "CommandLine")[0]),
                        managed_by=managed_by,
                    )
        return result

    def mapping_visible(self, letter: str) -> bool:
        return _mount_path_visible(Path(f"{letter}:\\"))

    def write_mapping(self, mapping: StoreOpenMapping) -> None:
        import winreg

        access = winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        root = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, self.REGISTRY_ROOT, 0, access)
        with root, winreg.CreateKeyEx(root, mapping.letter, 0, access) as key:
            winreg.SetValueEx(key, "DeviceName", 0, winreg.REG_SZ, mapping.device_name)
            winreg.SetValueEx(key, "SerialNumber", 0, winreg.REG_SZ, mapping.serial_number)
            winreg.SetValueEx(key, "CommandLine", 0, winreg.REG_SZ, mapping.command_line)
            winreg.SetValueEx(key, "ManagedBy", 0, winreg.REG_SZ, mapping.managed_by)

    def delete_mapping(self, letter: str) -> None:
        import winreg

        access = winreg.KEY_WRITE | winreg.KEY_WOW64_64KEY
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, self.REGISTRY_ROOT, 0, access) as root:
            if hasattr(winreg, "DeleteKeyEx"):
                winreg.DeleteKeyEx(root, letter, winreg.KEY_WOW64_64KEY, 0)
            else:
                winreg.DeleteKey(root, letter)

    @staticmethod
    def _run_sc(*arguments: str) -> subprocess.CompletedProcess[str]:
        completed = subprocess.run(
            ["sc.exe", *arguments],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return completed

    def service_state(self) -> str:
        completed = self._run_sc("query", self.SERVICE_NAME)
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
            raise CopyError(f"Impossibile interrogare il servizio StoreOpen: {detail}")
        match = re.search(r"(?:STATE|STATO)\s*:\s*(\d+)", completed.stdout, re.IGNORECASE)
        if not match:
            raise CopyError("Risposta non riconosciuta dal servizio StoreOpen")
        return {
            1: "stopped", 2: "start_pending", 3: "stop_pending", 4: "running",
        }.get(int(match.group(1)), "other")

    def _wait_for_state(self, expected: str, timeout_seconds: float | None) -> None:
        deadline = (
            time.monotonic() + timeout_seconds
            if timeout_seconds is not None else None
        )
        while deadline is None or time.monotonic() < deadline:
            if self.service_state() == expected:
                return
            time.sleep(1)
        assert timeout_seconds is not None
        raise CopyError(
            f"Il servizio StoreOpen non ha raggiunto lo stato {expected} "
            f"entro {timeout_seconds:g} secondi"
        )

    def start_service(self) -> None:
        completed = self._run_sc("start", self.SERVICE_NAME)
        if completed.returncode and self.service_state() != "running":
            detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
            raise CopyError(f"Avvio del servizio StoreOpen fallito: {detail}")
        self._wait_for_state("running", 60)

    def stop_service(self) -> None:
        if self.service_state() == "stopped":
            return
        completed = self._run_sc("stop", self.SERVICE_NAME)
        if completed.returncode and self.service_state() != "stopped":
            detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
            raise CopyError(f"Arresto del servizio StoreOpen fallito: {detail}")
        self._wait_for_state("stopped", None)


class WindowsStoreOpenMappingService:
    OWNER = "LTOArchiver"

    def __init__(self, platform: StoreOpenPlatform | None = None):
        self.platform = platform or WindowsStoreOpenPlatform()
        self.owned_mapping: StoreOpenMapping | None = None

    @staticmethod
    def _matches_legacy_mapping(
        existing: StoreOpenMapping, desired: StoreOpenMapping
    ) -> bool:
        if (
            existing.device_name != desired.device_name
            or existing.serial_number != desired.serial_number
        ):
            return False
        expected_command = re.sub(
            r"\s[D-Z]:\s",
            f" {existing.letter}: ",
            desired.command_line,
            count=1,
            flags=re.IGNORECASE,
        )
        return existing.command_line == expected_command

    def cleanup_state(self, desired: StoreOpenMapping) -> None:
        """Remove only inactive StoreOpen mappings created by LTO Archiver."""
        existing = self.platform.list_mappings()
        if not existing:
            return
        owned = {
            letter: mapping
            for letter, mapping in existing.items()
            if mapping.managed_by == self.OWNER
            or self._matches_legacy_mapping(mapping, desired)
        }
        self._cleanup_mappings(existing, owned)

    def cleanup_owned_state(self) -> None:
        """Release a stale mapping owned by LTO Archiver before formatting."""
        existing = self.platform.list_mappings()
        if not existing:
            return
        owned = {
            letter: mapping
            for letter, mapping in existing.items()
            if mapping.managed_by == self.OWNER
        }
        self._cleanup_mappings(existing, owned)

    def _cleanup_mappings(
        self,
        existing: Mapping[str, StoreOpenMapping],
        owned: Mapping[str, StoreOpenMapping],
    ) -> None:
        foreign = set(existing) - set(owned)
        if foreign:
            names = ", ".join(sorted(existing))
            raise ValidationError(
                f"Esistono gia mappature StoreOpen ({names}); rimuoverle prima di avviare il job"
            )
        state = self.platform.service_state()
        stuck_volume = any(
            self.platform.mapping_visible(letter) for letter in owned
        )
        if state == "stopped" and stuck_volume:
            self.platform.start_service()
            state = "running"
        if state != "stopped":
            self.platform.stop_service()
        for letter, stale in owned.items():
            while self.platform.mapping_visible(letter):
                time.sleep(1)
            current = self.platform.list_mappings().get(letter)
            if current != stale:
                raise ValidationError(
                    f"La mappatura StoreOpen {letter}: e cambiata; pulizia annullata"
                )
            self.platform.delete_mapping(letter)

    def create_mapping(
        self, letter: str, device_name: str, serial_number: str, command_line: str
    ) -> None:
        normalized = letter.strip().upper().rstrip(":\\/")
        if not re.fullmatch(r"[D-Z]", normalized):
            raise ValidationError(f"Lettera StoreOpen non valida: {letter}")
        mapping = StoreOpenMapping(
            normalized, device_name, serial_number, command_line, self.OWNER
        )
        self.cleanup_state(mapping)
        existing = self.platform.list_mappings()
        if existing:
            names = ", ".join(sorted(existing))
            raise ValidationError(
                f"Esistono gia mappature StoreOpen ({names}); rimuoverle prima di avviare il job"
            )
        if self.platform.service_state() != "stopped":
            raise ValidationError(
                "Il servizio StoreOpen e gia attivo senza una mappatura gestita dal job"
            )
        self.platform.write_mapping(mapping)
        self.owned_mapping = mapping

    def start(self) -> None:
        if self.owned_mapping is None:
            raise ValidationError("Nessuna mappatura StoreOpen preparata")
        self.platform.start_service()

    def stop(self) -> None:
        self.platform.stop_service()

    def remove_mapping(self, letter: str) -> None:
        normalized = letter.strip().upper().rstrip(":\\/")
        if self.owned_mapping is None or self.owned_mapping.letter != normalized:
            raise ValidationError(f"La mappatura StoreOpen {normalized}: non appartiene al job")
        current = self.platform.list_mappings().get(normalized)
        if current != self.owned_mapping:
            raise ValidationError(
                f"La mappatura StoreOpen {normalized}: e cambiata; rimozione annullata"
            )
        self.platform.delete_mapping(normalized)
        self.owned_mapping = None


def parse_unit_serial_vpd(payload: bytes) -> str:
    if len(payload) < 4 or payload[1] != 0x80:
        raise ValidationError("Risposta SCSI VPD 0x80 non valida")
    length = (payload[2] << 8) | payload[3]
    if length <= 0 or length > len(payload) - 4:
        raise ValidationError("Lunghezza del seriale SCSI non valida")
    serial = payload[4:4 + length].decode("ascii", errors="strict").strip("\0 ")
    if not serial:
        raise ValidationError("Il drive non ha restituito un seriale SCSI")
    return serial


@dataclass(frozen=True)
class TapePosition:
    beginning_of_partition: bool = False
    end_of_partition: bool = False
    partition: int = 0
    first_logical_object: int | None = None
    last_logical_object: int | None = None
    buffered_objects: int = 0
    buffered_bytes: int | None = None


@dataclass(frozen=True)
class TapeTelemetrySnapshot:
    available: bool
    beginning_of_partition: bool = False
    end_of_partition: bool = False
    partition: int = 0
    first_logical_object: int | None = None
    last_logical_object: int | None = None
    buffered_objects: int = 0
    buffered_bytes: int | None = None
    tape_alerts: tuple[int, ...] = ()
    alert_query_available: bool = True
    detail: str = ""


def parse_read_position_short(payload: bytes) -> TapePosition:
    """Parse the 20-byte SSC READ POSITION short-form response."""

    if len(payload) < 20:
        raise ValidationError("Risposta SCSI READ POSITION incompleta")
    flags = payload[0]
    location_unknown = bool(flags & 0x20)
    byte_count_unknown = bool(flags & 0x10)
    return TapePosition(
        beginning_of_partition=bool(flags & 0x80),
        end_of_partition=bool(flags & 0x40),
        partition=payload[1],
        first_logical_object=(
            None if location_unknown else int.from_bytes(payload[4:8], "big")
        ),
        last_logical_object=(
            None if location_unknown else int.from_bytes(payload[8:12], "big")
        ),
        buffered_objects=int.from_bytes(payload[13:16], "big"),
        buffered_bytes=(
            None if byte_count_unknown else int.from_bytes(payload[16:20], "big")
        ),
    )


def parse_log_sense_parameters(payload: bytes, *, expected_page: int) -> dict[int, bytes]:
    """Parse an SPC LOG SENSE page into its parameter values."""

    if len(payload) < 4 or payload[0] & 0x3F != expected_page:
        raise ValidationError("Risposta SCSI LOG SENSE non valida")
    page_length = int.from_bytes(payload[2:4], "big")
    end = min(len(payload), 4 + page_length)
    offset = 4
    result: dict[int, bytes] = {}
    while offset < end:
        if offset + 4 > end:
            raise ValidationError("Parametro SCSI LOG SENSE incompleto")
        code = int.from_bytes(payload[offset:offset + 2], "big")
        value_length = payload[offset + 3]
        value_start = offset + 4
        value_end = value_start + value_length
        if value_end > end:
            raise ValidationError("Valore SCSI LOG SENSE incompleto")
        result[code] = payload[value_start:value_end]
        offset = value_end
    return result


def classify_tape_activity(
    current: TapeTelemetrySnapshot,
    previous: TapeTelemetrySnapshot | None,
) -> str:
    if not current.available:
        return "unavailable"
    if current.tape_alerts:
        return "alert"
    if (current.buffered_bytes or 0) > 0 or current.buffered_objects > 0:
        return "buffered"
    if previous and previous.available and (
        current.partition != previous.partition
        or current.first_logical_object != previous.first_logical_object
        or current.last_logical_object != previous.last_logical_object
    ):
        return "positioning"
    return "idle"


class TapeTelemetryMonitor:
    """Poll read-only drive telemetry without making the backup depend on it."""

    def __init__(
        self,
        provider: Callable[[], TapeTelemetrySnapshot],
        callback: ProgressCallback,
        *,
        poll_seconds: float = 5.0,
    ):
        self.provider = provider
        self.callback = callback
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._run,
            name="lto-read-only-telemetry",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
            self._thread = None

    def _run(self) -> None:
        previous: TapeTelemetrySnapshot | None = None
        while not self._stop.is_set():
            try:
                snapshot = self.provider()
            except Exception as exc:
                snapshot = TapeTelemetrySnapshot(
                    available=False,
                    detail=str(exc),
                    alert_query_available=False,
                )
            self.callback({
                "event": "tape.telemetry",
                "activity": classify_tape_activity(snapshot, previous),
                "available": snapshot.available,
                "beginning_of_partition": snapshot.beginning_of_partition,
                "end_of_partition": snapshot.end_of_partition,
                "partition": snapshot.partition,
                "first_logical_object": snapshot.first_logical_object,
                "last_logical_object": snapshot.last_logical_object,
                "buffered_objects": snapshot.buffered_objects,
                "buffered_bytes": snapshot.buffered_bytes,
                "tape_alerts": list(snapshot.tape_alerts),
                "alert_query_available": snapshot.alert_query_available,
                "detail": snapshot.detail,
            })
            if snapshot.available:
                previous = snapshot
            if self._stop.wait(self.poll_seconds):
                break


class _ScsiPassThroughDirect(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_ushort),
        ("ScsiStatus", ctypes.c_ubyte),
        ("PathId", ctypes.c_ubyte),
        ("TargetId", ctypes.c_ubyte),
        ("Lun", ctypes.c_ubyte),
        ("CdbLength", ctypes.c_ubyte),
        ("SenseInfoLength", ctypes.c_ubyte),
        ("DataIn", ctypes.c_ubyte),
        ("DataTransferLength", ctypes.c_ulong),
        ("TimeOutValue", ctypes.c_ulong),
        ("DataBuffer", ctypes.c_void_p),
        ("SenseInfoOffset", ctypes.c_ulong),
        ("Cdb", ctypes.c_ubyte * 16),
    ]


class _ScsiPassThroughDirectWithSense(ctypes.Structure):
    _fields_ = [
        ("packet", _ScsiPassThroughDirect),
        ("sense", ctypes.c_ubyte * 32),
    ]


class WindowsTapeDevice:
    """Win32 tape control for presence, drive identity, load and unload."""

    ERROR_NO_MEDIA_IN_DRIVE = 1112
    ERROR_MEDIA_CHANGED = 1110
    ERROR_BUS_RESET = 1111
    ERROR_NOT_READY = 21
    ERROR_NOT_SUPPORTED = 50
    NO_ERROR = 0
    TAPE_LOAD = 0
    TAPE_UNLOAD = 1
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    IOCTL_SCSI_PASS_THROUGH_DIRECT = 0x0004D014
    SCSI_IOCTL_DATA_IN = 1

    def __init__(self, device_name: str = "TAPE0", poll_seconds: float = 3.0):
        self.device_name = device_name
        self.poll_seconds = poll_seconds

    @property
    def path(self) -> str:
        return rf"\\.\{self.device_name}"

    def wait_for_media(self, stop_requested: StopRequested) -> bool:
        if os.name != "nt":
            raise ValidationError("Il controllo automatico del drive e disponibile solo su Windows")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(self.path, 0x80000000 | 0x40000000, 0, None, 3, 0, None)
        if handle == self.INVALID_HANDLE_VALUE:
            raise CopyError(f"Impossibile aprire il drive {self.path}: errore Windows {ctypes.get_last_error()}")
        try:
            get_status = kernel32.GetTapeStatus
            get_status.argtypes = [ctypes.c_void_p]
            get_status.restype = ctypes.c_uint32
            prepare = kernel32.PrepareTape
            prepare.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int]
            prepare.restype = ctypes.c_uint32
            while not stop_requested():
                status = int(get_status(handle))
                if status == self.NO_ERROR:
                    load_status = int(prepare(handle, self.TAPE_LOAD, False))
                    if load_status in (
                        self.NO_ERROR, self.ERROR_MEDIA_CHANGED, self.ERROR_NOT_SUPPORTED
                    ):
                        return True
                    if load_status not in (self.ERROR_NO_MEDIA_IN_DRIVE, self.ERROR_NOT_READY):
                        raise CopyError(f"Caricamento del nastro fallito: errore Windows {load_status}")
                elif status not in (
                    self.ERROR_NO_MEDIA_IN_DRIVE,
                    self.ERROR_MEDIA_CHANGED,
                    self.ERROR_BUS_RESET,
                    self.ERROR_NOT_READY,
                ):
                    raise CopyError(f"Controllo del nastro fallito: errore Windows {status}")
                time.sleep(self.poll_seconds)
            return False
        finally:
            kernel32.CloseHandle(handle)

    def read_unit_serial(self) -> str:
        payload = self._scsi_data_in(
            bytes((0x12, 0x01, 0x80, 0x00, 0xFF, 0x00)),
            255,
            timeout_seconds=30,
        )
        return parse_unit_serial_vpd(payload)

    def _scsi_data_in(
        self,
        cdb: bytes,
        allocation_length: int,
        *,
        timeout_seconds: int = 10,
    ) -> bytes:
        if os.name != "nt":
            raise ValidationError("La telemetria del drive e disponibile solo su Windows")
        if not 1 <= len(cdb) <= 16 or allocation_length <= 0:
            raise ValidationError("Richiesta SCSI non valida")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(
            self.path, 0x80000000 | 0x40000000, 0x1 | 0x2, None, 3, 0, None
        )
        if handle == self.INVALID_HANDLE_VALUE:
            raise CopyError(
                f"Impossibile aprire il drive {self.path} in sola lettura diagnostica: "
                f"errore Windows {ctypes.get_last_error()}"
            )
        try:
            data = ctypes.create_string_buffer(allocation_length)
            request = _ScsiPassThroughDirectWithSense()
            request.packet.Length = ctypes.sizeof(_ScsiPassThroughDirect)
            request.packet.CdbLength = len(cdb)
            request.packet.SenseInfoLength = len(request.sense)
            request.packet.DataIn = self.SCSI_IOCTL_DATA_IN
            request.packet.DataTransferLength = len(data)
            request.packet.TimeOutValue = timeout_seconds
            request.packet.DataBuffer = ctypes.addressof(data)
            request.packet.SenseInfoOffset = _ScsiPassThroughDirectWithSense.sense.offset
            for index, value in enumerate(cdb):
                request.packet.Cdb[index] = value
            returned = ctypes.c_ulong()
            device_io = kernel32.DeviceIoControl
            device_io.argtypes = [
                ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_uint32,
                ctypes.c_void_p, ctypes.c_uint32, ctypes.POINTER(ctypes.c_ulong),
                ctypes.c_void_p,
            ]
            device_io.restype = ctypes.c_int
            succeeded = device_io(
                handle,
                self.IOCTL_SCSI_PASS_THROUGH_DIRECT,
                ctypes.byref(request),
                ctypes.sizeof(request),
                ctypes.byref(request),
                ctypes.sizeof(request),
                ctypes.byref(returned),
                None,
            )
            if not succeeded:
                raise CopyError(
                    f"Interrogazione SCSI del drive fallita: errore Windows "
                    f"{ctypes.get_last_error()}"
                )
            if request.packet.ScsiStatus:
                raise CopyError(
                    f"Interrogazione SCSI del drive fallita: stato "
                    f"{request.packet.ScsiStatus}"
                )
            return data.raw
        finally:
            kernel32.CloseHandle(handle)

    def read_position(self) -> TapePosition:
        # SSC READ POSITION, service action 0: short form. This command does not
        # move the medium or alter the drive state.
        return parse_read_position_short(
            self._scsi_data_in(bytes((0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0)), 20)
        )

    def read_tape_alerts(self) -> tuple[int, ...]:
        # SPC LOG SENSE current cumulative values, TapeAlert page 0x2E.
        allocation_length = 1024
        cdb = bytearray(10)
        cdb[0] = 0x4D
        cdb[2] = 0x2E
        cdb[7:9] = allocation_length.to_bytes(2, "big")
        parameters = parse_log_sense_parameters(
            self._scsi_data_in(bytes(cdb), allocation_length),
            expected_page=0x2E,
        )
        return tuple(
            code for code, value in sorted(parameters.items())
            if any(value)
        )

    def read_telemetry(self) -> TapeTelemetrySnapshot:
        position = self.read_position()
        alerts: tuple[int, ...] = ()
        alert_query_available = True
        detail = ""
        try:
            alerts = self.read_tape_alerts()
        except (CopyError, ValidationError) as exc:
            alert_query_available = False
            detail = str(exc)
        return TapeTelemetrySnapshot(
            available=True,
            beginning_of_partition=position.beginning_of_partition,
            end_of_partition=position.end_of_partition,
            partition=position.partition,
            first_logical_object=position.first_logical_object,
            last_logical_object=position.last_logical_object,
            buffered_objects=position.buffered_objects,
            buffered_bytes=position.buffered_bytes,
            tape_alerts=alerts,
            alert_query_available=alert_query_available,
            detail=detail,
        )

    def unload(self) -> None:
        if os.name != "nt":
            raise ValidationError("L'espulsione automatica e disponibile solo su Windows")
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        create_file = kernel32.CreateFileW
        create_file.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ]
        create_file.restype = ctypes.c_void_p
        handle = create_file(self.path, 0x80000000 | 0x40000000, 0, None, 3, 0, None)
        if handle == self.INVALID_HANDLE_VALUE:
            raise CopyError(
                f"Impossibile aprire il drive {self.path} per l'espulsione: "
                f"errore Windows {ctypes.get_last_error()}"
            )
        try:
            prepare = kernel32.PrepareTape
            prepare.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int]
            prepare.restype = ctypes.c_uint32
            status = int(prepare(handle, self.TAPE_UNLOAD, False))
            if status not in (self.NO_ERROR, self.ERROR_NO_MEDIA_IN_DRIVE):
                raise CopyError(f"Espulsione del nastro fallita: errore Windows {status}")
        finally:
            kernel32.CloseHandle(handle)


class StoreOpenController:
    def __init__(
        self,
        device_name: str,
        mount_path: Path,
        state_dir: Path,
        install_dir: Path = Path(r"C:\Program Files\HPE\LTFS"),
        poll_seconds: float = 3.0,
        force_format: bool = False,
        format_timeout_seconds: float = 3600.0,
    ):
        self.device_name = device_name
        self.requested_mount_path = Path(mount_path)
        self.mount_path = Path(mount_path)
        self.state_dir = Path(state_dir)
        self.install_dir = Path(install_dir)
        self.poll_seconds = poll_seconds
        self.force_format = force_format
        self.format_timeout_seconds = format_timeout_seconds
        self.device = WindowsTapeDevice(device_name, poll_seconds)
        self.mapping_service = WindowsStoreOpenMappingService()
        self.mapping_active = False
        self.eject_pending = False
        self.mounted_volume: VolumeInfo | None = None
        self._unmount_progress: ProgressCallback | None = None

    def set_unmount_progress(self, progress: ProgressCallback | None) -> None:
        self._unmount_progress = progress

    def wait_for_media(self, stop_requested: StopRequested) -> bool:
        return self.device.wait_for_media(stop_requested)

    def format(self, cassette: CassetteLabel) -> None:
        formatter = self.install_dir / "mkltfs.exe"
        if not formatter.is_file():
            raise ValidationError(f"Formatter StoreOpen non trovato: {formatter}")
        self.mapping_service.cleanup_owned_state()
        command = self.format_command(cassette)
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=self.format_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise CopyError(
                "Formattazione LTFS non completata entro il tempo massimo "
                f"di {self.format_timeout_seconds:g} secondi"
            ) from exc
        if completed.returncode:
            detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
            raise CopyError(f"Formattazione LTFS fallita. Dettaglio: {detail}")

    def format_command(self, cassette: CassetteLabel) -> list[str]:
        formatter = self.install_dir / "mkltfs.exe"
        command = [str(formatter), "-q", "-d", self.device_name]
        if self.force_format:
            command.append("--force")
        command.extend(["-s", cassette.tape_serial, "-n", cassette.physical_label])
        return command

    def mount(self, stop_requested: StopRequested) -> Path:
        executable = self.install_dir / "ltfs.exe"
        if not executable.is_file():
            raise ValidationError(f"Eseguibile StoreOpen non trovato: {executable}")
        self.mount_path = choose_mount_path(self.requested_mount_path)
        mount_target = str(self.mount_path).rstrip("\\/")
        letter = mount_target[0]
        serial_number = self.device.read_unit_serial()
        command_line = (
            f'"{executable}" {mount_target} -o devname={self.device_name} '
            "-o sync_type=unmount -d"
        )
        self.mapping_service.create_mapping(
            letter, self.device_name, serial_number, command_line
        )
        self.mapping_active = True
        try:
            self.mapping_service.start()
        except Exception as exc:
            self._cleanup_failed_mount(exc)
        deadline = time.monotonic() + 600
        while time.monotonic() < deadline:
            if stop_requested():
                self.unmount_and_eject()
                raise OperationCancelled("Job interrotto durante il mount LTFS")
            try:
                volume = inspect_volume(self.mount_path)
                if volume.filesystem.upper() == "LTFS":
                    self.mounted_volume = volume
                    return self.mount_path
            except OSError:
                pass
            except ValidationError as exc:
                if "arresto dell'albero del probe" in str(exc):
                    self._cleanup_failed_mount(exc)
            time.sleep(self.poll_seconds)
        self.unmount_and_eject()
        raise CopyError("Mount LTFS non disponibile dopo 10 minuti")

    def _cleanup_failed_mount(self, original: Exception) -> None:
        try:
            self.unmount_and_eject()
        except Exception as cleanup:
            raise CopyError(
                f"Mount StoreOpen fallito: {original}. Anche la pulizia e fallita: {cleanup}"
            ) from original
        raise CopyError(f"Mount StoreOpen fallito: {original}") from original

    def _run_unmount_stage(
        self,
        stage: str,
        stage_number: int,
        operation: Callable[[], None],
        progress: ProgressCallback | None,
    ) -> None:
        if progress is None:
            operation()
            return
        started_at = time.monotonic()

        def emit(status: str) -> None:
            try:
                progress({
                        "event": "unmount.progress",
                        "stage": stage,
                        "status": status,
                        "stage_number": stage_number,
                        "stage_total": 3,
                        "elapsed_seconds": max(0.0, time.monotonic() - started_at),
                })
            except Exception:
                # Unmount/eject is safety-critical; telemetry is not.
                pass

        emit("pending")
        heartbeat_stop = threading.Event()

        def heartbeat() -> None:
            while not heartbeat_stop.wait(1.0):
                emit("pending")

        monitor = threading.Thread(
            target=heartbeat,
            name=f"lto-unmount-{stage}",
            daemon=True,
        )
        monitor.start()
        try:
            operation()
        except BaseException:
            emit("failed")
            raise
        finally:
            heartbeat_stop.set()
            if monitor.is_alive():
                monitor.join(timeout=2.0)
        emit("complete")

    def unmount_and_eject(self, progress: ProgressCallback | None = None) -> None:
        progress = progress or self._unmount_progress
        if not self.mapping_active and not self.eject_pending:
            return
        if self.mapping_active:
            letter = str(self.mount_path).strip().upper().rstrip(":\\/")[0]
            self._run_unmount_stage(
                "index_sync", 1, self.mapping_service.stop, progress
            )

            def release_mapping() -> None:
                while _mount_path_visible(self.mount_path):
                    time.sleep(self.poll_seconds)
                self.mapping_service.remove_mapping(letter)

            self._run_unmount_stage(
                "mapping_release", 2, release_mapping, progress
            )
            self.mapping_active = False
            self.eject_pending = True
        self._run_unmount_stage("eject", 3, self.device.unload, progress)
        self.eject_pending = False


class TapeWriteProgress:
    """Enrich backup events with live, cassette-wide write telemetry."""

    def __init__(
        self,
        *,
        job_id: str,
        sequence: int,
        physical_label: str,
        cassette_planned_bytes: int,
        job_copied_bytes: int,
        job_planned_bytes: int,
        callback: ProgressCallback | None,
        operation: str = "format",
        clock: Callable[[], float] = time.monotonic,
    ):
        self.job_id = job_id
        self.sequence = sequence
        self.physical_label = physical_label
        self.operation = operation
        self.cassette_planned_bytes = max(0, cassette_planned_bytes)
        self.job_copied_before = max(0, job_copied_bytes)
        self.job_planned_bytes = max(0, job_planned_bytes)
        self.callback = callback
        self.clock = clock
        self.cassette_copied_bytes = 0
        self.cassette_copied_files = 0
        self.current_file_bytes = 0
        self.started_at: float | None = None
        self.last_at: float | None = None
        self.last_total = 0
        self.write_bps = 0.0
        self.average_write_bps = 0.0
        self.tape_total_bytes = 0
        self.tape_initial_free_bytes = 0
        self.tape_usable_bytes = 0
        self.tape_reserve_bytes = 0
        self.tape_application_limit_bytes = 0
        self.tape_ltfs_overhead_bytes = 0

    def __call__(self, event: dict) -> None:
        enriched = dict(event)
        kind = str(event.get("event") or "")
        now: float | None = None
        if kind == "tape.capacity":
            self.tape_total_bytes = max(0, int(event.get("total_bytes") or 0))
            self.tape_initial_free_bytes = max(
                0,
                int(
                    event.get("ltfs_data_free_bytes")
                    if event.get("ltfs_data_free_bytes") is not None
                    else event.get("free_bytes") or 0
                ),
            )
            self.tape_usable_bytes = max(0, int(event.get("usable_bytes") or 0))
            self.tape_reserve_bytes = max(0, int(event.get("reserve_bytes") or 0))
            self.tape_application_limit_bytes = max(
                0, int(event.get("application_limit_bytes") or 0)
            )
            self.tape_ltfs_overhead_bytes = max(
                0, int(event.get("ltfs_overhead_bytes") or 0)
            )
        elif kind == "file.start":
            self.current_file_bytes = 0
            if self.started_at is None:
                now = self.clock()
                self.started_at = now
                self.last_at = now
        elif kind == "file.progress":
            current = max(0, int(event.get("copied_bytes") or 0))
            delta = max(0, current - self.current_file_bytes)
            self.current_file_bytes = current
            self.cassette_copied_bytes += delta
            now = self.clock()
            if self.started_at is None:
                self.started_at = now
                self.last_at = now
            interval = now - (self.last_at if self.last_at is not None else now)
            if interval > 0:
                self.write_bps = (self.cassette_copied_bytes - self.last_total) / interval
            elapsed = now - self.started_at
            if elapsed > 0:
                self.average_write_bps = self.cassette_copied_bytes / elapsed
            self.last_at = now
            self.last_total = self.cassette_copied_bytes
        elif kind == "file.complete":
            self.cassette_copied_files += 1

        # The effective cassette rate deliberately includes LTFS close/flush
        # time and gaps between files.  Refresh it on every event emitted while
        # the cassette is active, not only when another byte-progress callback
        # happens to arrive.
        if self.started_at is not None:
            if now is None:
                now = self.clock()
            cassette_elapsed = max(0.0, now - self.started_at)
            self.average_write_bps = (
                self.cassette_copied_bytes / cassette_elapsed
                if cassette_elapsed > 0 and self.cassette_copied_bytes > 0
                else 0.0
            )
        else:
            cassette_elapsed = 0.0

        job_copied = self.job_copied_before + self.cassette_copied_bytes
        job_percent = (
            min(100.0, job_copied * 100.0 / self.job_planned_bytes)
            if self.job_planned_bytes else 0.0
        )
        tape_consumed = self.tape_ltfs_overhead_bytes + self.cassette_copied_bytes
        tape_remaining = max(0, self.tape_usable_bytes - tape_consumed)
        tape_percent = (
            min(100.0, tape_consumed * 100.0 / self.tape_usable_bytes)
            if self.tape_usable_bytes else 0.0
        )
        cassette_eta = (
            max(0, self.cassette_planned_bytes - self.cassette_copied_bytes)
            / self.average_write_bps
            if self.average_write_bps > 0 else None
        )
        job_eta = (
            max(0, self.job_planned_bytes - job_copied) / self.average_write_bps
            if self.average_write_bps > 0 else None
        )
        enriched.update(
            job_id=self.job_id,
            sequence=self.sequence,
            physical_label=self.physical_label,
            operation=self.operation,
            cassette_planned_bytes=self.cassette_planned_bytes,
            cassette_copied_bytes=self.cassette_copied_bytes,
            cassette_copied_files=self.cassette_copied_files,
            job_planned_bytes=self.job_planned_bytes,
            job_copied_bytes=job_copied,
            job_progress_percent=job_percent,
            write_bps=self.write_bps,
            average_write_bps=self.average_write_bps,
            cassette_elapsed_seconds=cassette_elapsed,
            cassette_eta_seconds=cassette_eta,
            job_eta_seconds=job_eta,
            tape_total_bytes=self.tape_total_bytes,
            tape_initial_free_bytes=self.tape_initial_free_bytes,
            tape_usable_bytes=self.tape_usable_bytes,
            tape_remaining_bytes=tape_remaining,
            tape_reserve_bytes=self.tape_reserve_bytes,
            tape_application_limit_bytes=self.tape_application_limit_bytes,
            tape_ltfs_overhead_bytes=self.tape_ltfs_overhead_bytes,
            tape_used_percent=tape_percent,
        )
        if self.callback:
            self.callback(enriched)


class AutomaticJobRunner:
    def __init__(
        self,
        paths: AppPaths,
        settings: Settings,
        *,
        storeopen: StoreOpenInterface | None = None,
        backup: BackupCallback,
        telemetry_monitor_factory: Callable[
            [Callable[[], TapeTelemetrySnapshot], ProgressCallback], TapeTelemetryMonitor
        ] = TapeTelemetryMonitor,
    ):
        self.paths = paths
        self.settings = settings
        self.storeopen = storeopen
        self.backup = backup
        self.telemetry_monitor_factory = telemetry_monitor_factory

    def run(
        self,
        job_id: str,
        *,
        progress: ProgressCallback | None = None,
        stop_requested: StopRequested,
    ) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            job = dict(catalog.get_automatic_job(job_id))
            library_ids = [
                row["library_id"] for row in catalog.list_automatic_job_libraries(job_id)
            ]
        controller = self.storeopen or StoreOpenController(
            job["device_name"], Path(job["mount_path"]), self.paths.state_dir,
            force_format=bool(job["force_format"]),
        )
        while True:
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.initialize()
                step_row = catalog.next_automatic_cassette(job_id)
                if step_row is None:
                    catalog.update_automatic_job(job_id, "completed")
                    self._emit(progress, "automatic.completed", job_id=job_id)
                    return
                step = dict(step_row)
                cassette_rows = [dict(row) for row in catalog.list_automatic_cassettes(job_id)]
                job_planned_bytes = sum(int(row["planned_bytes"]) for row in cassette_rows)
                job_copied_bytes = sum(
                    int(row["copied_bytes"])
                    for row in cassette_rows
                    if row["status"] == "completed"
                )
                if step["status"] not in {"pending", "waiting_media"}:
                    message = (
                        f"La cassetta {step['physical_label']} e rimasta nello stato incerto "
                        f"{step['status']}; non viene riformattata automaticamente"
                    )
                    catalog.update_automatic_job(job_id, "failed", current_sequence=step["sequence"], error=message)
                    raise CopyError(message)
                catalog.update_automatic_job(job_id, "waiting_media", current_sequence=step["sequence"])
                catalog.update_automatic_cassette(job_id, step["sequence"], "waiting_media")
            self._emit(
                progress,
                "automatic.waiting_media",
                job_id=job_id,
                sequence=step["sequence"],
                total=job["total_cassettes"],
                physical_label=step["physical_label"],
                operation=step.get("operation", "format"),
            )
            if not controller.wait_for_media(stop_requested):
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_job(job_id, "paused", current_sequence=step["sequence"])
                self._emit(progress, "automatic.paused", job_id=job_id)
                return
            if stop_requested():
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_job(job_id, "paused", current_sequence=step["sequence"])
                return

            cassette = CassetteLabel(step["physical_label"], step["tape_serial"])
            active_tape_progress: TapeWriteProgress | None = None
            set_unmount_progress = getattr(controller, "set_unmount_progress", None)
            if callable(set_unmount_progress):
                def forward_unmount(event: dict) -> None:
                    payload = dict(event)
                    name = str(payload.pop("event", "unmount.progress"))
                    if payload.get("status") == "complete":
                        try:
                            with Catalog(self.paths.catalog_file) as timing_catalog:
                                timing_catalog.initialize()
                                timing_catalog.event(
                                    "automatic.unmount.timing",
                                    {
                                        "job_id": job_id,
                                        "sequence": int(step["sequence"]),
                                        "physical_label": cassette.physical_label,
                                        "stage": str(payload.get("stage") or ""),
                                        "elapsed_seconds": max(
                                            0.0,
                                            float(payload.get("elapsed_seconds") or 0.0),
                                        ),
                                    },
                                )
                        except Exception:
                            # Timing history is diagnostic and must not block unmount.
                            pass
                    if active_tape_progress is not None:
                        active_tape_progress({"event": name, **payload})
                    else:
                        self._emit(
                            progress,
                            name,
                            job_id=job_id,
                            sequence=int(step["sequence"]),
                            physical_label=cassette.physical_label,
                            **payload,
                        )

                set_unmount_progress(forward_unmount)
            result: dict | None = None
            try:
                operation = str(step.get("operation") or "format")
                if operation == "format":
                    self._state(job_id, step["sequence"], "formatting", progress, cassette)
                    controller.format(cassette)
                    if bool(step.get("reuse_registered", 0)):
                        with Catalog(self.paths.catalog_file) as catalog:
                            catalog.initialize()
                            catalog.commit_registered_tape_reformat(
                                job_id, int(step["sequence"])
                            )
                self._state(job_id, step["sequence"], "mounting", progress, cassette)
                mounted_path = controller.mount(stop_requested)
                mounted_volume = getattr(controller, "mounted_volume", None)
                if operation == "append":
                    if mounted_volume is None:
                        mounted_volume = inspect_volume(mounted_path)
                    require_ltfs(mounted_volume)
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        tape_id = str(step.get("tape_id") or cassette.physical_label)
                        tape = catalog.get_tape(tape_id)
                        if str(tape["cassette_number"]).casefold() != cassette.physical_label.casefold():
                            raise ValidationError(
                                f"Cassetta errata: attesa {cassette.physical_label}, "
                                f"catalogata {tape['cassette_number']}"
                            )
                        assert_registered_tape(tape, mounted_volume)
                        if str(tape["volume_label"]).casefold() != mounted_volume.label.casefold():
                            raise ValidationError(
                                f"Etichetta LTFS errata: attesa {tape['volume_label']}, "
                                f"montata {mounted_volume.label}"
                            )
                self._state(job_id, step["sequence"], "writing", progress, cassette)
                tape_progress = TapeWriteProgress(
                    job_id=job_id,
                    sequence=int(step["sequence"]),
                    physical_label=cassette.physical_label,
                    operation=operation,
                    cassette_planned_bytes=int(step["planned_bytes"]),
                    job_copied_bytes=job_copied_bytes,
                    job_planned_bytes=job_planned_bytes,
                    callback=progress,
                )
                active_tape_progress = tape_progress
                telemetry_monitor: TapeTelemetryMonitor | None = None
                device = getattr(controller, "device", None)
                provider = getattr(device, "read_telemetry", None)
                if progress and callable(provider):
                    def telemetry_callback(event: dict) -> None:
                        progress({
                            **event,
                            "job_id": job_id,
                            "sequence": int(step["sequence"]),
                            "physical_label": cassette.physical_label,
                        })

                    try:
                        telemetry_monitor = self.telemetry_monitor_factory(
                            provider, telemetry_callback
                        )
                        telemetry_monitor.start()
                    except Exception as exc:
                        telemetry_monitor = None
                        telemetry_callback({
                            "event": "tape.telemetry",
                            "activity": "unavailable",
                            "available": False,
                            "detail": str(exc),
                        })
                try:
                    result = self.backup(
                        library_ids,
                        cassette.physical_label,
                        mounted_volume or mounted_path,
                        tape_progress,
                        stop_requested,
                    )
                finally:
                    if telemetry_monitor is not None:
                        telemetry_monitor.stop()
                self._state(job_id, step["sequence"], "unmounting", progress, cassette)
                controller.unmount_and_eject()
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    if result.get("commit_required"):
                        catalog.complete_blocks(list(result.get("block_ids", [])))
                        try:
                            catalog.backup_to(
                                self.paths.catalog_backup_file(
                                    self.settings.catalog_backup_directory
                                )
                            )
                        except Exception as backup_error:
                            catalog.event(
                                "catalog.backup.warning",
                                {
                                    "block_ids": list(result.get("block_ids", [])),
                                    "error": str(backup_error),
                                },
                            )
                            self._emit(
                                progress,
                                "catalog.backup.warning",
                                job_id=job_id,
                                error=str(backup_error),
                            )
                    catalog.update_automatic_cassette(
                        job_id,
                        step["sequence"],
                        "completed",
                        tape_id=cassette.physical_label,
                        block_id=result.get("block_id") or ",".join(result.get("block_ids", [])),
                        copied_files=int(result.get("copied_files", 0)),
                        copied_bytes=int(result.get("copied_bytes", 0)),
                    )
                self._emit(
                    progress,
                    "automatic.ejected",
                    job_id=job_id,
                    sequence=step["sequence"],
                    physical_label=cassette.physical_label,
                    operation=operation,
                )
            except CapacityError as exc:
                if operation != "append":
                    try:
                        controller.unmount_and_eject()
                    except Exception as cleanup_exc:
                        exc.add_note(f"Smontaggio/espulsione non riusciti: {cleanup_exc}")
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_cassette(
                            job_id, step["sequence"], "failed", error=str(exc)
                        )
                        catalog.update_automatic_job(
                            job_id, "failed", current_sequence=step["sequence"], error=str(exc)
                        )
                    raise
                try:
                    self._state(job_id, step["sequence"], "unmounting", progress, cassette)
                    controller.unmount_and_eject()
                except Exception as cleanup_exc:
                    detail = f"{exc} | smontaggio/espulsione non riusciti: {cleanup_exc}"
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_cassette(
                            job_id, step["sequence"], "failed", error=detail
                        )
                        catalog.update_automatic_job(
                            job_id, "failed", current_sequence=step["sequence"], error=detail
                        )
                    raise CopyError(detail) from cleanup_exc
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_cassette(
                        job_id,
                        step["sequence"],
                        "completed",
                        copied_files=0,
                        copied_bytes=0,
                    )
                    next_step = catalog.next_automatic_cassette(job_id)
                    needs_more_media = next_step is None
                    if needs_more_media:
                        missing_message = (
                            "Lo spazio reale della cassetta APPEND e esaurito e restano file "
                            "da copiare. Aggiungere cassette allo stesso job."
                        )
                        catalog.update_automatic_job(
                            job_id,
                            "failed",
                            current_sequence=step["sequence"],
                            error=missing_message,
                        )
                self._emit(
                    progress,
                    "automatic.append_full",
                    job_id=job_id,
                    sequence=step["sequence"],
                    physical_label=cassette.physical_label,
                    detail=str(exc),
                    operation=operation,
                )
                if needs_more_media:
                    self._emit(
                        progress,
                        "automatic.failed",
                        job_id=job_id,
                        error=missing_message,
                    )
                    return
                continue
            except OperationCancelled as exc:
                try:
                    controller.unmount_and_eject()
                except Exception as cleanup_exc:
                    detail = f"{exc} | smontaggio/espulsione non riusciti: {cleanup_exc}"
                    with Catalog(self.paths.catalog_file) as catalog:
                        catalog.initialize()
                        catalog.update_automatic_cassette(
                            job_id, step["sequence"], "failed", error=detail
                        )
                        catalog.update_automatic_job(
                            job_id, "failed", current_sequence=step["sequence"], error=detail
                        )
                    self._emit(progress, "automatic.failed", job_id=job_id, error=detail)
                    raise CopyError(detail) from cleanup_exc
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    if result and result.get("commit_required"):
                        catalog.fail_blocks(list(result.get("block_ids", [])), str(exc))
                    catalog.reset_automatic_cassette(job_id, step["sequence"], str(exc))
                self._emit(
                    progress,
                    "automatic.paused",
                    job_id=job_id,
                    sequence=step["sequence"],
                    physical_label=cassette.physical_label,
                    restart_cassette=True,
                    operation=operation,
                )
                return
            except BaseException as exc:
                cleanup_error = ""
                try:
                    controller.unmount_and_eject()
                except Exception as cleanup_exc:
                    cleanup_error = f" | smontaggio/espulsione non riusciti: {cleanup_exc}"
                detail = f"{exc}{cleanup_error}"
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    if result and result.get("commit_required"):
                        catalog.fail_blocks(list(result.get("block_ids", [])), detail)
                    catalog.update_automatic_cassette(
                        job_id, step["sequence"], "failed", error=detail
                    )
                    catalog.update_automatic_job(
                        job_id, "failed", current_sequence=step["sequence"], error=detail
                    )
                self._emit(progress, "automatic.failed", job_id=job_id, error=detail)
                raise
            remaining_files = int(result.get("remaining_files", 0))
            if "remaining_files" in result and remaining_files == 0:
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.reserve_remaining_automatic_cassettes(job_id, step["sequence"])
                    catalog.update_automatic_job(
                        job_id, "completed", current_sequence=step["sequence"]
                    )
                self._emit(progress, "automatic.completed", job_id=job_id)
                return
            if step["sequence"] == job["total_cassettes"] and remaining_files:
                message = (
                    f"Le etichette pianificate sono terminate, ma restano {remaining_files} file. "
                    "Aggiungere cassette allo stesso job."
                )
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_job(
                        job_id, "failed", current_sequence=step["sequence"], error=message
                    )
                self._emit(progress, "automatic.failed", job_id=job_id, error=message)
                return
            if stop_requested():
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.update_automatic_job(job_id, "paused", current_sequence=step["sequence"])
                self._emit(progress, "automatic.paused", job_id=job_id)
                return

    def _state(
        self,
        job_id: str,
        sequence: int,
        status: str,
        progress: ProgressCallback | None,
        cassette: CassetteLabel,
    ) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.update_automatic_job(job_id, status, current_sequence=sequence)
            catalog.update_automatic_cassette(job_id, sequence, status)
            operation = next(
                row["operation"]
                for row in catalog.list_automatic_cassettes(job_id)
                if int(row["sequence"]) == int(sequence)
            )
        self._emit(
            progress,
            f"automatic.{status}",
            job_id=job_id,
            sequence=sequence,
            physical_label=cassette.physical_label,
            operation=operation,
        )

    @staticmethod
    def _emit(callback: ProgressCallback | None, event: str, **payload: object) -> None:
        if callback:
            callback({"event": event, **payload})
