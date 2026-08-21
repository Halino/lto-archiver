from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path


LTFS_ATTRIBUTE_UNIT_BYTES = 1024**2
LTFSATTR_PATHS = (
    Path(r"C:\Program Files\HPE\LTFS\ltfsattr.exe"),
    Path(r"C:\Program Files\IBM\LTFS\ltfsattr.exe"),
)


def _parse_ltfs_mebibytes(output: str) -> int:
    values = re.findall(r"(?<![\w.])-?\d+(?![\w.])", output)
    if not values:
        raise ValueError("ltfsattr non ha restituito un valore numerico")
    mebibytes = int(values[-1])
    if mebibytes < 0:
        raise ValueError("ltfsattr ha restituito uno spazio negativo")
    return mebibytes * LTFS_ATTRIBUTE_UNIT_BYTES


def _find_ltfsattr() -> Path | None:
    for candidate in LTFSATTR_PATHS:
        if candidate.is_file():
            return candidate
    discovered = shutil.which("ltfsattr.exe") or shutil.which("ltfsattr")
    return Path(discovered) if discovered else None


def _read_ltfs_attribute(tool: Path, attribute: str, root: Path) -> int:
    completed = subprocess.run(
        [str(tool), "-p", attribute, str(root)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if completed.returncode:
        detail = (completed.stderr or completed.stdout or "errore non specificato").strip()
        raise OSError(f"ltfsattr {attribute}: {detail}")
    return _parse_ltfs_mebibytes(completed.stdout)


def probe_volume(path: Path) -> dict[str, object]:
    root = Path(os.path.abspath(path))
    if not root.drive:
        raise OSError(f"Percorso volume privo di lettera: {root}")
    root = Path(root.drive + "\\")
    usage = shutil.disk_usage(root)

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_volume_information = kernel32.GetVolumeInformationW
    volume_name = ctypes.create_unicode_buffer(261)
    filesystem_name = ctypes.create_unicode_buffer(261)
    serial_number = ctypes.c_uint32()
    maximum_component = ctypes.c_uint32()
    flags = ctypes.c_uint32()
    result = get_volume_information(
        str(root),
        volume_name,
        len(volume_name),
        ctypes.byref(serial_number),
        ctypes.byref(maximum_component),
        ctypes.byref(flags),
        filesystem_name,
        len(filesystem_name),
    )
    if not result:
        error = ctypes.get_last_error()
        detail = ctypes.FormatError(error).strip()
        raise OSError(error, detail, str(root))

    payload = {
        "filesystem": filesystem_name.value.upper(),
        "label": volume_name.value,
        "serial": f"{serial_number.value:08X}",
        "total_bytes": usage.total,
        "free_bytes": usage.free,
    }
    if filesystem_name.value.upper() == "LTFS":
        tool = _find_ltfsattr()
        if tool is not None:
            try:
                payload["ltfs_data_total_bytes"] = _read_ltfs_attribute(
                    tool, "ltfs.mediaDataPartitionTotalCapacity", root
                )
                payload["ltfs_data_free_bytes"] = _read_ltfs_attribute(
                    tool, "ltfs.mediaDataPartitionAvailableSpace", root
                )
            except (OSError, ValueError, subprocess.TimeoutExpired):
                # The generic volume values remain available for old StoreOpen
                # releases; the caller still applies deterministic LTFS overhead.
                pass
    return payload


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        print("Uso interno: volume_probe <lettera-volume>", file=sys.stderr)
        return 2
    try:
        print(json.dumps(probe_volume(Path(arguments[0])), ensure_ascii=False))
        return 0
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
