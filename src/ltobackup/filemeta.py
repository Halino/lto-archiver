from __future__ import annotations

import ctypes
import os
from pathlib import Path
from typing import Any

from .util import native_path


def collect_file_metadata(path: Path, source_stat=None) -> dict[str, Any]:
    """Collect portable and Windows/SMB metadata without making backup depend on it."""
    details = source_stat or path.stat()
    errors: list[str] = []
    result: dict[str, Any] = {
        "created_ns": int(getattr(details, "st_birthtime_ns", details.st_ctime_ns)),
        "accessed_ns": int(details.st_atime_ns),
        "source_mode": int(details.st_mode),
        "windows_attributes": getattr(details, "st_file_attributes", None),
        "owner_name": None,
        "owner_sid": None,
        "security_descriptor": None,
        "alternate_streams": [],
    }
    if os.name == "nt":
        try:
            result.update(_windows_security(path))
        except (OSError, AttributeError, ValueError, ctypes.ArgumentError) as exc:
            errors.append(f"sicurezza: {exc}")
        try:
            result["alternate_streams"] = _windows_streams(path)
        except (OSError, AttributeError, ValueError, ctypes.ArgumentError) as exc:
            errors.append(f"flussi alternativi: {exc}")
    result["metadata_state"] = "partial" if errors else "complete"
    result["metadata_error"] = "; ".join(errors) or None
    return result


def describe_windows_attributes(value: int | None) -> str:
    if value is None:
        return "Non registrati"
    names = (
        (0x00000001, "Sola lettura"),
        (0x00000002, "Nascosto"),
        (0x00000004, "Sistema"),
        (0x00000020, "Archivio"),
        (0x00000080, "Normale"),
        (0x00000100, "Temporaneo"),
        (0x00000200, "Sparso"),
        (0x00000800, "Compresso"),
        (0x00001000, "Offline"),
        (0x00002000, "Non indicizzato"),
        (0x00004000, "Cifrato"),
        (0x00080000, "Recall on data access"),
    )
    labels = [label for bit, label in names if value & bit]
    return ", ".join(labels) if labels else "Nessuno"


def _windows_security(path: Path) -> dict[str, str | None]:
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    flags = 0x00000001 | 0x00000002 | 0x00000004
    get_security = advapi32.GetNamedSecurityInfoW
    get_security.argtypes = (
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    get_security.restype = wintypes.DWORD
    status = get_security(
        native_path(path), 1, flags,
        ctypes.byref(owner), ctypes.byref(group), ctypes.byref(dacl), None,
        ctypes.byref(descriptor),
    )
    if status:
        raise OSError(status, ctypes.FormatError(status), str(path))
    try:
        owner_sid = _sid_to_string(advapi32, kernel32, owner)
        owner_name = _sid_to_account(advapi32, owner)
        text_pointer = wintypes.LPWSTR()
        text_length = wintypes.ULONG()
        convert = advapi32.ConvertSecurityDescriptorToStringSecurityDescriptorW
        convert.argtypes = (
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
            ctypes.POINTER(wintypes.LPWSTR), ctypes.POINTER(wintypes.ULONG),
        )
        convert.restype = wintypes.BOOL
        if not convert(descriptor, 1, flags, ctypes.byref(text_pointer), ctypes.byref(text_length)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            security_descriptor = text_pointer.value
        finally:
            kernel32.LocalFree(text_pointer)
        return {
            "owner_name": owner_name,
            "owner_sid": owner_sid,
            "security_descriptor": security_descriptor,
        }
    finally:
        if descriptor:
            kernel32.LocalFree(descriptor)


def _sid_to_string(advapi32, kernel32, sid: ctypes.c_void_p) -> str | None:
    if not sid:
        return None
    from ctypes import wintypes

    pointer = wintypes.LPWSTR()
    convert = advapi32.ConvertSidToStringSidW
    convert.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    convert.restype = wintypes.BOOL
    if not convert(sid, ctypes.byref(pointer)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return pointer.value
    finally:
        kernel32.LocalFree(pointer)


def _sid_to_account(advapi32, sid: ctypes.c_void_p) -> str | None:
    if not sid:
        return None
    from ctypes import wintypes

    name_length = wintypes.DWORD()
    domain_length = wintypes.DWORD()
    use = wintypes.DWORD()
    lookup = advapi32.LookupAccountSidW
    lookup.argtypes = (
        wintypes.LPCWSTR, ctypes.c_void_p, wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD), wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
    )
    lookup.restype = wintypes.BOOL
    lookup(None, sid, None, ctypes.byref(name_length), None, ctypes.byref(domain_length), ctypes.byref(use))
    error = ctypes.get_last_error()
    if error not in (0, 122):
        return None
    name = ctypes.create_unicode_buffer(max(1, name_length.value))
    domain = ctypes.create_unicode_buffer(max(1, domain_length.value))
    if not lookup(
        None, sid, name, ctypes.byref(name_length), domain,
        ctypes.byref(domain_length), ctypes.byref(use),
    ):
        return None
    return f"{domain.value}\\{name.value}" if domain.value else name.value


def _windows_streams(path: Path) -> list[dict[str, Any]]:
    from ctypes import wintypes

    class StreamData(ctypes.Structure):
        _fields_ = (("size", ctypes.c_longlong), ("name", wintypes.WCHAR * 296))

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(StreamData), wintypes.DWORD)
    find_first.restype = wintypes.HANDLE
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = (wintypes.HANDLE, ctypes.POINTER(StreamData))
    find_next.restype = wintypes.BOOL
    find_close = kernel32.FindClose
    find_close.argtypes = (wintypes.HANDLE,)
    find_close.restype = wintypes.BOOL
    data = StreamData()
    handle = find_first(native_path(path), 0, ctypes.byref(data), 0)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        error = ctypes.get_last_error()
        if error in (2, 38):
            return []
        raise ctypes.WinError(error)
    streams: list[dict[str, Any]] = []
    try:
        while True:
            raw_name = data.name
            if raw_name and raw_name != "::$DATA":
                name = raw_name
                if name.startswith(":"):
                    name = name[1:]
                if name.endswith(":$DATA"):
                    name = name[:-6]
                streams.append({"name": name, "size": int(data.size)})
            if not find_next(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error == 38:
                    break
                raise ctypes.WinError(error)
    finally:
        find_close(handle)
    return streams
