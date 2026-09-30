from __future__ import annotations

import ctypes
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from .systemd import SystemdMountError

_UNIT = re.compile(r"^[A-Za-z0-9_.\\x-]{1,249}\.mount$")
_PROPERTY_NAMES = (
    "Description",
    "What",
    "Where",
    "Type",
    "Options",
    "TimeoutUSec",
    "CollectMode",
)
_SYSTEMD_DESTINATION = b"org.freedesktop.systemd1"
_SYSTEMD_MANAGER_PATH = b"/org/freedesktop/systemd1"
_SYSTEMD_MANAGER_INTERFACE = b"org.freedesktop.systemd1.Manager"
_DBUS_PROPERTIES_INTERFACE = b"org.freedesktop.DBus.Properties"


class SystemdDbusTransport(Protocol):
    def start_transient_mount(
        self, unit_name: str, properties: tuple[tuple[str, object], ...]
    ) -> None: ...

    def stop_unit(self, unit_name: str) -> None: ...

    def unit_active_state(self, unit_name: str) -> str: ...

    def list_mount_units(self) -> tuple[str, ...]: ...


class SystemdUnitNotFound(RuntimeError):
    """Exact systemd NoSuchUnit result for an already-collected unit."""


class LinuxSystemdManager:
    """Closed in-process systemd D-Bus boundary for transient mount units."""

    def __init__(
        self,
        *,
        transport: SystemdDbusTransport | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        if (
            type(poll_interval_seconds) not in {int, float}
            or type(poll_interval_seconds) is bool
            or not 0 < float(poll_interval_seconds) <= 1
        ):
            raise ValueError("invalid systemd manager policy")
        self._transport = transport or _LibSystemdTransport()
        self._monotonic = monotonic
        self._sleep = sleep
        self._poll_interval_seconds = float(poll_interval_seconds)

    def start_transient_mount(
        self, unit_name: str, properties: tuple[tuple[str, object], ...]
    ) -> None:
        checked_unit = _unit_name(unit_name)
        checked_properties = _mount_properties(properties)
        timeout_seconds = dict(checked_properties)["TimeoutUSec"] / 1_000_000
        try:
            self._transport.start_transient_mount(checked_unit, checked_properties)
            deadline = self._monotonic() + timeout_seconds
            while True:
                state = self._transport.unit_active_state(checked_unit)
                if state == "active":
                    return
                if state == "failed" or self._monotonic() >= deadline:
                    raise SystemdMountError
                self._sleep(self._poll_interval_seconds)
        except SystemdMountError:
            raise
        except Exception:  # noqa: BLE001 - redact D-Bus diagnostics
            raise SystemdMountError from None

    def stop_unit(self, unit_name: str) -> None:
        try:
            self._transport.stop_unit(_unit_name(unit_name))
        except SystemdUnitNotFound:
            return
        except Exception:  # noqa: BLE001 - redact D-Bus diagnostics
            raise SystemdMountError("share_recovery_required") from None

    def unit_active(self, unit_name: str) -> bool:
        try:
            state = self._transport.unit_active_state(_unit_name(unit_name))
            if state in {"active", "activating", "deactivating", "reloading"}:
                return True
            if state in {"inactive", "failed", "dead"}:
                return False
            raise ValueError
        except SystemdUnitNotFound:
            return False
        except Exception:  # noqa: BLE001 - redact D-Bus diagnostics
            raise SystemdMountError("share_recovery_required") from None

    def list_mount_units(self) -> tuple[str, ...]:
        try:
            candidates = tuple(self._transport.list_mount_units())
            if any(type(unit) is not str for unit in candidates):
                raise ValueError
            return tuple(
                sorted(
                    {unit for unit in candidates if _UNIT.fullmatch(unit) is not None}
                )
            )
        except Exception:  # noqa: BLE001 - redact D-Bus diagnostics
            raise SystemdMountError("share_recovery_required") from None


class _SdBusError(ctypes.Structure):
    _fields_ = [
        ("name", ctypes.c_char_p),
        ("message", ctypes.c_char_p),
        ("need_free", ctypes.c_int),
    ]


class _LibSystemdTransport:
    """Minimal libsystemd sd-bus client; no shell or helper process exists."""

    def __init__(self, library: object | None = None) -> None:
        self._library = library or ctypes.CDLL("libsystemd.so.0", use_errno=True)
        self._configure()
        bus = ctypes.c_void_p()
        result = self._library.sd_bus_default_system(ctypes.byref(bus))
        if result < 0 or not bus.value:
            if bus.value:
                self._library.sd_bus_unref(bus)
            raise RuntimeError("systemd D-Bus unavailable")
        self._bus = bus

    def _configure(self) -> None:
        error_pointer = ctypes.POINTER(_SdBusError)
        void_pointer = ctypes.c_void_p
        void_pointer_pointer = ctypes.POINTER(void_pointer)
        self._library.sd_bus_default_system.argtypes = [void_pointer_pointer]
        self._library.sd_bus_default_system.restype = ctypes.c_int
        self._library.sd_bus_message_new_method_call.argtypes = [
            void_pointer,
            void_pointer_pointer,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
        ]
        self._library.sd_bus_message_new_method_call.restype = ctypes.c_int
        self._library.sd_bus_message_open_container.argtypes = [
            void_pointer,
            ctypes.c_char,
            ctypes.c_char_p,
        ]
        self._library.sd_bus_message_open_container.restype = ctypes.c_int
        self._library.sd_bus_message_close_container.argtypes = [void_pointer]
        self._library.sd_bus_message_close_container.restype = ctypes.c_int
        self._library.sd_bus_message_append_basic.argtypes = [
            void_pointer,
            ctypes.c_char,
            void_pointer,
        ]
        self._library.sd_bus_message_append_basic.restype = ctypes.c_int
        self._library.sd_bus_message_enter_container.argtypes = [
            void_pointer,
            ctypes.c_char,
            ctypes.c_char_p,
        ]
        self._library.sd_bus_message_enter_container.restype = ctypes.c_int
        self._library.sd_bus_message_exit_container.argtypes = [void_pointer]
        self._library.sd_bus_message_exit_container.restype = ctypes.c_int
        self._library.sd_bus_message_read_basic.argtypes = [
            void_pointer,
            ctypes.c_char,
            void_pointer,
        ]
        self._library.sd_bus_message_read_basic.restype = ctypes.c_int
        self._library.sd_bus_message_skip.argtypes = [void_pointer, ctypes.c_char_p]
        self._library.sd_bus_message_skip.restype = ctypes.c_int
        self._library.sd_bus_call.argtypes = [
            void_pointer,
            void_pointer,
            ctypes.c_uint64,
            error_pointer,
            void_pointer_pointer,
        ]
        self._library.sd_bus_call.restype = ctypes.c_int
        self._library.sd_bus_message_unref.argtypes = [void_pointer]
        self._library.sd_bus_message_unref.restype = ctypes.c_void_p
        self._library.sd_bus_unref.argtypes = [void_pointer]
        self._library.sd_bus_unref.restype = ctypes.c_void_p
        self._library.sd_bus_error_free.argtypes = [error_pointer]
        self._library.sd_bus_error_free.restype = ctypes.POINTER(_SdBusError)

    def start_transient_mount(
        self, unit_name: str, properties: tuple[tuple[str, object], ...]
    ) -> None:
        def build(message: ctypes.c_void_p) -> None:
            self._append_string(message, unit_name)
            self._append_string(message, "replace")
            self._open(message, "a", "(sv)")
            for name, value in properties:
                self._open(message, "r", "sv")
                self._append_string(message, name)
                signature = "t" if type(value) is int else "s"
                self._open(message, "v", signature)
                if signature == "t":
                    self._append_uint64(message, value)
                else:
                    self._append_string(message, value)
                self._close(message)
                self._close(message)
            self._close(message)
            self._open(message, "a", "(sa(sv))")
            self._close(message)

        self._call("StartTransientUnit", build)

    def stop_unit(self, unit_name: str) -> None:
        self._call(
            "StopUnit",
            lambda message: (
                self._append_string(message, unit_name),
                self._append_string(message, "replace"),
            ),
        )

    def unit_active_state(self, unit_name: str) -> str:
        unit_path = self._call_string(
            "GetUnit", lambda message: self._append_string(message, unit_name), "o"
        )

        def build(message: ctypes.c_void_p) -> None:
            self._append_string(message, "org.freedesktop.systemd1.Unit")
            self._append_string(message, "ActiveState")

        return self._call_variant_string(
            unit_path.encode("utf-8"),
            _DBUS_PROPERTIES_INTERFACE,
            "Get",
            build,
        )

    def list_mount_units(self) -> tuple[str, ...]:
        def build(message: ctypes.c_void_p) -> None:
            self._open(message, "a", "s")
            self._close(message)
            self._open(message, "a", "s")
            self._append_string(message, "*.mount")
            self._close(message)

        reply = self._call("ListUnitsByPatterns", build, retain_reply=True)
        try:
            if (
                self._library.sd_bus_message_enter_container(
                    reply, b"a", b"(ssssssouso)"
                )
                < 0
            ):
                raise RuntimeError
            units: list[str] = []
            while True:
                entered = self._library.sd_bus_message_enter_container(
                    reply, b"r", b"ssssssouso"
                )
                if entered == 0:
                    break
                if entered < 0:
                    raise RuntimeError
                units.append(self._read_string(reply, "s"))
                if self._library.sd_bus_message_skip(reply, b"sssssouso") < 0:
                    raise RuntimeError
                if self._library.sd_bus_message_exit_container(reply) < 0:
                    raise RuntimeError
            if self._library.sd_bus_message_exit_container(reply) < 0:
                raise RuntimeError
            return tuple(units)
        finally:
            self._library.sd_bus_message_unref(reply)

    def _call_string(
        self,
        member: str,
        builder: Callable[[ctypes.c_void_p], object],
        signature: str,
    ) -> str:
        reply = self._call(member, builder, retain_reply=True)
        try:
            return self._read_string(reply, signature)
        finally:
            self._library.sd_bus_message_unref(reply)

    def _call_variant_string(
        self,
        path: bytes,
        interface: bytes,
        member: str,
        builder: Callable[[ctypes.c_void_p], object],
    ) -> str:
        reply = self._call(
            member,
            builder,
            path=path,
            interface=interface,
            retain_reply=True,
        )
        try:
            if self._library.sd_bus_message_enter_container(reply, b"v", b"s") <= 0:
                raise RuntimeError
            value = self._read_string(reply, "s")
            if self._library.sd_bus_message_exit_container(reply) < 0:
                raise RuntimeError
            return value
        finally:
            self._library.sd_bus_message_unref(reply)

    def _call(
        self,
        member: str,
        builder: Callable[[ctypes.c_void_p], object],
        *,
        path: bytes = _SYSTEMD_MANAGER_PATH,
        interface: bytes = _SYSTEMD_MANAGER_INTERFACE,
        retain_reply: bool = False,
    ) -> ctypes.c_void_p | None:
        message = ctypes.c_void_p()
        reply = ctypes.c_void_p()
        error = _SdBusError()
        try:
            result = self._library.sd_bus_message_new_method_call(
                self._bus,
                ctypes.byref(message),
                _SYSTEMD_DESTINATION,
                path,
                interface,
                member.encode("ascii"),
            )
            if result < 0 or not message.value:
                raise RuntimeError
            builder(message)
            result = self._library.sd_bus_call(
                self._bus,
                message,
                ctypes.c_uint64(0),
                ctypes.byref(error),
                ctypes.byref(reply),
            )
            if result < 0:
                if error.name == b"org.freedesktop.systemd1.NoSuchUnit":
                    raise SystemdUnitNotFound
                if error.name == b"org.freedesktop.DBus.Error.AccessDenied":
                    raise SystemdMountError("share_mount_authorization_failed")
                raise RuntimeError
            if not reply.value:
                raise RuntimeError
            if retain_reply:
                retained = reply
                reply = ctypes.c_void_p()
                return retained
            return None
        finally:
            if reply.value:
                self._library.sd_bus_message_unref(reply)
            if message.value:
                self._library.sd_bus_message_unref(message)
            self._library.sd_bus_error_free(ctypes.byref(error))

    def _open(self, message: ctypes.c_void_p, kind: str, contents: str) -> None:
        if (
            self._library.sd_bus_message_open_container(
                message, kind.encode("ascii"), contents.encode("ascii")
            )
            < 0
        ):
            raise RuntimeError

    def _close(self, message: ctypes.c_void_p) -> None:
        if self._library.sd_bus_message_close_container(message) < 0:
            raise RuntimeError

    def _append_string(self, message: ctypes.c_void_p, value: str) -> None:
        encoded = value.encode("utf-8")
        encoded_pointer = ctypes.c_char_p(encoded)
        if (
            b"\0" in encoded
            or self._library.sd_bus_message_append_basic(message, b"s", encoded_pointer)
            < 0
        ):
            raise RuntimeError

    def _append_uint64(self, message: ctypes.c_void_p, value: int) -> None:
        encoded = ctypes.c_uint64(value)
        if (
            self._library.sd_bus_message_append_basic(
                message, b"t", ctypes.byref(encoded)
            )
            < 0
        ):
            raise RuntimeError

    def _read_string(self, message: ctypes.c_void_p, signature: str) -> str:
        value = ctypes.c_char_p()
        if (
            self._library.sd_bus_message_read_basic(
                message, signature.encode("ascii"), ctypes.byref(value)
            )
            <= 0
            or not value.value
        ):
            raise RuntimeError
        return value.value.decode("utf-8")

    def __del__(self) -> None:
        bus = getattr(self, "_bus", None)
        if bus is not None and bus.value:
            self._library.sd_bus_unref(bus)
            self._bus = ctypes.c_void_p()


def _unit_name(value: object) -> str:
    if type(value) is not str or _UNIT.fullmatch(value) is None:
        raise SystemdMountError
    return value


def _mount_properties(
    value: object,
) -> tuple[tuple[str, object], ...]:
    if (
        type(value) is not tuple
        or tuple(name for name, _item in value) != _PROPERTY_NAMES
    ):
        raise SystemdMountError
    properties = dict(value)
    if (
        any(
            type(properties[name]) is not str
            for name in _PROPERTY_NAMES
            if name != "TimeoutUSec"
        )
        or type(properties["TimeoutUSec"]) is not int
        or not 5_000_000 <= properties["TimeoutUSec"] <= 600_000_000
        or properties["Type"] not in {"nfs", "cifs"}
        or not Path(properties["Where"]).is_absolute()
        or properties["CollectMode"] != "inactive-or-failed"
        or not {"ro", "nosuid", "nodev", "noexec"}.issubset(
            set(properties["Options"].split(","))
        )
    ):
        raise SystemdMountError
    return value
