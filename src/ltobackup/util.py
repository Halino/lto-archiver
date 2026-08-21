from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO, Callable, Iterable

from .errors import CopyError, OperationCancelled, ValidationError


LTFS_SLOW_CLOSE_SECONDS = 120.0


SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def validate_id(value: str, kind: str) -> str:
    if not SAFE_ID.fullmatch(value):
        raise ValidationError(
            f"{kind} non valido: usare 1-64 caratteri tra lettere, numeri, punto, trattino e underscore"
        )
    return value


def human_bytes(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            return f"{amount:.2f} {unit}"
        amount /= 1024
    return f"{value} B"


def safe_join(root: Path, relative_path: str) -> Path:
    normalized = relative_path.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    windows_path = PureWindowsPath(relative_path)
    if posix_path.is_absolute() or windows_path.is_absolute() or windows_path.drive or windows_path.root:
        raise ValidationError(f"Percorso relativo non sicuro: {relative_path}")
    parts = posix_path.parts
    if not parts or any(part in ("", ".", "..") for part in parts):
        raise ValidationError(f"Percorso relativo non sicuro: {relative_path}")
    candidate = root.joinpath(*parts)
    root_abs = os.path.abspath(root)
    candidate_abs = os.path.abspath(candidate)
    try:
        contained = os.path.commonpath((root_abs, candidate_abs)) == root_abs
    except ValueError as exc:
        raise ValidationError(f"Percorso fuori dalla radice: {relative_path}") from exc
    if not contained:
        raise ValidationError(f"Percorso fuori dalla radice: {relative_path}")
    return candidate


def native_path(path: Path) -> str:
    value = os.path.abspath(path)
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def copy_and_hash(
    source: Path,
    destination: Path,
    buffer_bytes: int,
    progress: Callable[[int], None] | None = None,
    *,
    activity: Callable[[dict], None] | None = None,
    durable: bool = True,
    stop_requested: Callable[[], bool] | None = None,
    streaming_destination: bool = False,
) -> str:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if streaming_destination and os.name == "nt":
        from .winio import WindowsStreamingUnsupported, copy_and_hash_windows_copyfile

        try:
            return copy_and_hash_windows_copyfile(
                source,
                destination,
                buffer_bytes,
                progress,
                activity=activity,
                stop_requested=stop_requested,
            )
        except WindowsStreamingUnsupported as exc:
            raise CopyError(
                "Scrittura ottimizzata obbligatoria non disponibile sul volume LTFS: "
                f"{exc}"
            ) from exc
    digest = hashlib.sha256()
    copied = 0
    try:
        with open(native_path(source), "rb", buffering=0) as src, open(
            native_path(destination), "xb", buffering=0
        ) as dst:
            buffer = bytearray(buffer_bytes)
            view = memoryview(buffer)
            while True:
                if stop_requested and stop_requested():
                    raise OperationCancelled("Copia interrotta dall'operatore")
                count = src.readinto(buffer)
                if not count:
                    break
                chunk = view[:count]
                digest.update(chunk)
                if activity:
                    activity(
                        {
                            "phase": "write.pending",
                            "copied_bytes": copied,
                            "pending_bytes": count,
                        }
                    )
                dst.write(chunk)
                copied += count
                if activity:
                    activity(
                        {
                            "phase": "write.complete",
                            "copied_bytes": copied,
                            "pending_bytes": 0,
                        }
                    )
                if progress:
                    progress(copied)
            if activity:
                activity(
                    {
                        "phase": "flush.pending",
                        "copied_bytes": copied,
                        "pending_bytes": 0,
                    }
                )
            dst.flush()
            if activity:
                activity(
                    {
                        "phase": "flush.complete",
                        "copied_bytes": copied,
                        "pending_bytes": 0,
                    }
                )
            if durable:
                os.fsync(dst.fileno())
            if activity:
                activity(
                    {
                        "phase": "close.pending",
                        "copied_bytes": copied,
                        "pending_bytes": 0,
                    }
                )
            dst.close()
            if activity:
                activity(
                    {
                        "phase": "close.complete",
                        "copied_bytes": copied,
                        "pending_bytes": 0,
                    }
                )
    except OperationCancelled:
        raise
    except FileExistsError as exc:
        raise CopyError(f"File temporaneo già esistente: {destination}") from exc
    except OSError as exc:
        raise CopyError(f"Errore copiando {source} -> {destination}: {exc}") from exc
    return digest.hexdigest()


def sha256_file(path: Path, buffer_bytes: int) -> str:
    digest = hashlib.sha256()
    with open(native_path(path), "rb", buffering=0) as stream:
        while chunk := stream.read(buffer_bytes):
            digest.update(chunk)
    return digest.hexdigest()


def write_json_atomic(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


class RunLock(AbstractContextManager["RunLock"]):
    def __init__(self, path: Path):
        self.path = path
        self._stream: BinaryIO | None = None

    def __enter__(self) -> "RunLock":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stream = open(self.path, "a+b")
        self._stream.seek(0)
        if self._stream.read(1) == b"":
            self._stream.seek(0)
            self._stream.write(b"0")
            self._stream.flush()
        self._stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self._stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self._stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            self._stream.close()
            self._stream = None
            raise ValidationError("Un'altra operazione LTO è già in esecuzione") from exc
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if not self._stream:
            return
        stream = self._stream
        try:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
        finally:
            stream.close()
            self._stream = None


def json_lines(records: Iterable[dict]) -> str:
    return "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records)
