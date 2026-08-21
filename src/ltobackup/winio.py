from __future__ import annotations

import ctypes
import hashlib
import os
import queue
import threading
import time
from pathlib import Path
from typing import Callable

from .errors import CopyError, OperationCancelled


GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
CREATE_NEW = 1
FILE_ATTRIBUTE_NORMAL = 0x00000080
FILE_FLAG_NO_BUFFERING = 0x20000000
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x04
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
COPY_FILE_FAIL_IF_EXISTS = 0x00000001
PROGRESS_CONTINUE = 0
PROGRESS_CANCEL = 1
ERROR_REQUEST_ABORTED = 1235
DEFAULT_HASH_WAIT_TIMEOUT_SECONDS = 300.0
DEFAULT_HASH_CANCEL_GRACE_SECONDS = 1.0


class WindowsStreamingUnsupported(OSError):
    """The destination rejected the mandatory sequential Windows open mode."""


def _windows_error(prefix: str) -> OSError:
    code = ctypes.get_last_error()
    return OSError(code, f"{prefix}: {ctypes.FormatError(code).strip()}")


def _windows_native_path(path: Path) -> str:
    """Return an extended-length Windows path without relying on OS policy."""

    value = os.path.abspath(path)
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return value
    if value.startswith("\\\\"):
        return "\\\\?\\UNC\\" + value[2:]
    return "\\\\?\\" + value


def _kernel32():
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
    )
    kernel32.CreateFileW.restype = ctypes.c_void_p
    kernel32.WriteFile.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_void_p,
    )
    kernel32.WriteFile.restype = ctypes.c_int
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    kernel32.VirtualAlloc.argtypes = (
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_uint32,
        ctypes.c_uint32,
    )
    kernel32.VirtualAlloc.restype = ctypes.c_void_p
    kernel32.VirtualFree.argtypes = (ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32)
    kernel32.VirtualFree.restype = ctypes.c_int
    return kernel32


class _AlignedBuffer:
    def __init__(self, kernel32, size: int):
        self.kernel32 = kernel32
        self.size = size
        self.address = kernel32.VirtualAlloc(
            None, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        if not self.address:
            raise _windows_error("VirtualAlloc non riuscita")
        array_type = ctypes.c_ubyte * size
        self.array = array_type.from_address(self.address)
        self.view = memoryview(self.array).cast("B")

    def close(self) -> None:
        if self.address:
            self.view.release()
            if not self.kernel32.VirtualFree(self.address, 0, MEM_RELEASE):
                raise _windows_error("VirtualFree non riuscita")
            self.address = 0


class _NativeDestination:
    def __init__(self, kernel32, path: Path):
        self.kernel32 = kernel32
        self.path = path
        self.handle = kernel32.CreateFileW(
            _windows_native_path(path),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            None,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )
        if self.handle == INVALID_HANDLE_VALUE:
            self.handle = None
            error = _windows_error(f"Apertura sequenziale non supportata per {path}")
            raise WindowsStreamingUnsupported(*error.args) from error

    def write(self, address: int, count: int) -> None:
        written = ctypes.c_uint32()
        if not self.kernel32.WriteFile(
            self.handle, ctypes.c_void_p(address), count, ctypes.byref(written), None
        ):
            raise _windows_error(f"WriteFile non riuscita per {self.path}")
        if int(written.value) != count:
            raise OSError(
                f"WriteFile incompleta per {self.path}: {written.value} di {count} byte"
            )

    def close(self) -> None:
        if self.handle is not None:
            handle, self.handle = self.handle, None
            if not self.kernel32.CloseHandle(handle):
                raise _windows_error(f"Chiusura non riuscita per {self.path}")


class WindowsStreamingCloseBatch:
    """Close LTFS data handles serially, optionally behind a bounded producer queue."""

    def __init__(
        self,
        *,
        background: bool = False,
        max_pending: int = 2,
        expected_files: int | None = None,
        progress: Callable[[dict], None] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ):
        self._pending: list[_NativeDestination] = []
        self._background = bool(background)
        self._expected_files = (
            max(0, int(expected_files)) if expected_files is not None else None
        )
        self._progress = progress
        self._monotonic = monotonic
        self._started_at: float | None = None
        self._submitted = 0
        self._closed = 0
        self._first_error: BaseException | None = None
        self._lock = threading.Lock()
        self._finish_started = False
        self._sentinel = object()
        self._queue: queue.Queue[object] | None = None
        self._worker: threading.Thread | None = None
        self.finished = False
        if self._background:
            self._queue = queue.Queue(maxsize=max(1, int(max_pending)))
            self._worker = threading.Thread(
                target=self._close_worker,
                name="lto-windows-close-pipeline",
                daemon=True,
            )
            self._worker.start()

    @property
    def pending_count(self) -> int:
        if self._background:
            with self._lock:
                return max(0, self._submitted - self._closed)
        return len(self._pending)

    def defer(self, writer: _NativeDestination) -> None:
        if self.finished:
            raise RuntimeError("Lotto di chiusura Windows gia concluso")
        if self._background:
            with self._lock:
                if self._first_error is not None:
                    raise self._first_error
                self._submitted += 1
            assert self._queue is not None
            self._queue.put(writer)
            return
        self._pending.append(writer)

    def close_path(self, path: Path) -> None:
        if self._background:
            self.finish()
            return
        absolute = os.path.abspath(path).casefold()
        for index, writer in enumerate(self._pending):
            if os.path.abspath(writer.path).casefold() == absolute:
                self._pending.pop(index).close()
                return

    def _progress_event(self, status: str, writer: _NativeDestination) -> dict:
        with self._lock:
            now = self._monotonic()
            if self._started_at is None:
                self._started_at = now
            elapsed = max(0.0, now - self._started_at)
            total = self._expected_files if self._expected_files is not None else self._submitted
            closed = self._closed
        average = elapsed / closed if closed else None
        return {
            "status": status,
            "current_path": str(writer.path),
            "closed_files": closed,
            "pending_files": max(0, total - closed),
            "total_files": total,
            "elapsed_seconds": elapsed,
            "average_close_seconds": average,
            "eta_seconds": average * max(0, total - closed) if average is not None else None,
        }

    def _report(self, status: str, writer: _NativeDestination) -> None:
        if self._progress:
            try:
                self._progress(self._progress_event(status, writer))
            except Exception:
                # Telemetry is best effort. A GUI/reporting failure must never
                # strand an LTFS data handle or stop the close worker.
                pass

    def _close_worker(self) -> None:
        assert self._queue is not None
        while True:
            item = self._queue.get()
            try:
                if item is self._sentinel:
                    return
                writer = item
                self._report("pending", writer)
                status = "complete"
                try:
                    writer.close()
                except BaseException as exc:
                    status = "failed"
                    with self._lock:
                        if self._first_error is None:
                            self._first_error = exc
                finally:
                    with self._lock:
                        self._closed += 1
                self._report(status, writer)
            finally:
                self._queue.task_done()

    def finish(
        self,
        *,
        progress: Callable[[dict], None] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if self.finished:
            return
        if self._background:
            if progress is not None:
                self._progress = progress
            if not self._finish_started:
                self._finish_started = True
                assert self._queue is not None
                self._queue.put(self._sentinel)
            assert self._worker is not None
            self._worker.join()
            self.finished = True
            if self._first_error is not None:
                raise self._first_error
            return
        first_error: BaseException | None = None
        total_files = len(self._pending)
        closed_files = 0
        started_at = monotonic()
        while self._pending:
            writer = self._pending.pop(0)
            if progress:
                progress({
                    "status": "pending",
                    "current_path": str(writer.path),
                    "closed_files": closed_files,
                    "pending_files": total_files - closed_files,
                    "total_files": total_files,
                    "elapsed_seconds": max(0.0, monotonic() - started_at),
                    "average_close_seconds": (
                        max(0.0, monotonic() - started_at) / closed_files
                        if closed_files else None
                    ),
                    "eta_seconds": None,
                })
            try:
                writer.close()
            except BaseException as exc:
                if first_error is None:
                    first_error = exc
            closed_files += 1
            elapsed = max(0.0, monotonic() - started_at)
            average = elapsed / closed_files
            if progress:
                progress({
                    "status": "complete",
                    "current_path": str(writer.path),
                    "closed_files": closed_files,
                    "pending_files": total_files - closed_files,
                    "total_files": total_files,
                    "elapsed_seconds": elapsed,
                    "average_close_seconds": average,
                    "eta_seconds": average * (total_files - closed_files),
                })
        self.finished = True
        if first_error is not None:
            raise first_error


def _sha256_file_cancellable(
    path: Path,
    buffer_bytes: int,
    should_cancel: Callable[[], bool],
) -> str:
    digest = hashlib.sha256()
    buffer = bytearray(max(1, int(buffer_bytes)))
    with open(_windows_native_path(path), "rb", buffering=0) as stream:
        while True:
            if should_cancel():
                raise OperationCancelled("Calcolo SHA-256 interrotto dall'operatore")
            count = stream.readinto(buffer)
            if not count:
                break
            digest.update(memoryview(buffer)[:count])
    return digest.hexdigest()


def _copy_file_ex(
    source: Path,
    destination: Path,
    on_progress: Callable[[int, int], None],
    should_cancel: Callable[[], bool],
) -> None:
    if os.name != "nt":
        raise WindowsStreamingUnsupported("CopyFileEx e disponibile solo su Windows")
    kernel32 = _kernel32()
    progress_routine_type = ctypes.WINFUNCTYPE(
        ctypes.c_uint32,
        ctypes.c_longlong,
        ctypes.c_longlong,
        ctypes.c_longlong,
        ctypes.c_longlong,
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    copy_file = kernel32.CopyFileExW
    copy_file.argtypes = (
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        progress_routine_type,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_uint32,
    )
    copy_file.restype = ctypes.c_int
    cancelled = ctypes.c_int(0)

    callback_failure: list[BaseException] = []

    def report(
        total: int,
        transferred: int,
        _stream_size: int,
        _stream_transferred: int,
        _stream_number: int,
        _reason: int,
        _source_handle: int,
        _destination_handle: int,
        _data: int,
    ) -> int:
        try:
            on_progress(max(0, int(total)), max(0, int(transferred)))
            return PROGRESS_CANCEL if should_cancel() else PROGRESS_CONTINUE
        except BaseException as exc:
            callback_failure.append(exc)
            cancelled.value = 1
            return PROGRESS_CANCEL

    callback = progress_routine_type(report)
    if copy_file(
        _windows_native_path(source),
        _windows_native_path(destination),
        callback,
        None,
        ctypes.byref(cancelled),
        COPY_FILE_FAIL_IF_EXISTS,
    ):
        if callback_failure:
            raise callback_failure[0]
        return
    code = ctypes.get_last_error()
    if callback_failure:
        raise callback_failure[0]
    if should_cancel() or code == ERROR_REQUEST_ABORTED:
        raise OperationCancelled("Copia interrotta dall'operatore")
    raise _windows_error(f"CopyFileEx non riuscita per {destination}")


def copy_and_hash_windows_copyfile(
    source: Path,
    destination: Path,
    buffer_bytes: int,
    progress: Callable[[int], None] | None = None,
    *,
    activity: Callable[[dict], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
    copy_file: Callable[
        [Path, Path, Callable[[int, int], None], Callable[[], bool]], None
    ] = _copy_file_ex,
    hash_file: Callable[[Path, int, Callable[[], bool]], str] = _sha256_file_cancellable,
    hash_wait_timeout_seconds: float = DEFAULT_HASH_WAIT_TIMEOUT_SECONDS,
    cancel_wait_timeout_seconds: float = DEFAULT_HASH_CANCEL_GRACE_SECONDS,
    monotonic: Callable[[], float] = time.monotonic,
) -> str:
    """Use the Explorer-class Windows copy path while hashing the SMB source."""
    cancel = threading.Event()
    hash_result: list[str] = []
    hash_completed_at: list[float] = []
    hash_failure: list[BaseException] = []
    close_pending = False
    started_at = monotonic()
    data_complete_at: float | None = None
    copy_return_at: float | None = None
    try:
        planned_total = max(0, int(source.stat().st_size))
    except OSError:
        planned_total = 0
    last_total = planned_total
    last_transferred = 0
    io_mode = "windows_copyfileex_parallel_hash"

    def should_cancel() -> bool:
        return (
            cancel.is_set()
            or bool(hash_failure)
            or bool(stop_requested and stop_requested())
        )

    def calculate_hash() -> None:
        try:
            result = hash_file(source, buffer_bytes, should_cancel)
            hash_completed_at.append(monotonic())
            hash_result.append(result)
        except BaseException as exc:
            hash_failure.append(exc)
            cancel.set()

    if activity:
        activity({
            "phase": "strategy.selected",
            "io_mode": io_mode,
            "copied_bytes": 0,
            "pending_bytes": 0,
        })
    hash_worker = threading.Thread(
        target=calculate_hash,
        name="lto-windows-source-hash",
        daemon=True,
    )
    hash_worker.start()

    def report(total: int, transferred: int) -> None:
        nonlocal close_pending, data_complete_at, last_total, last_transferred
        observed_at = monotonic()
        last_total = max(last_total, int(total))
        last_transferred = max(last_transferred, int(transferred))
        if activity:
            activity({
                "phase": "write.complete",
                "io_mode": io_mode,
                "copied_bytes": last_transferred,
                "pending_bytes": max(0, last_total - last_transferred),
            })
        if progress:
            progress(last_transferred)
        if last_total > 0 and last_transferred >= last_total and not close_pending:
            close_pending = True
            data_complete_at = observed_at
            if activity:
                activity({
                    "phase": "close.pending",
                    "io_mode": io_mode,
                    "copied_bytes": last_transferred,
                    "pending_bytes": 0,
                    "data_complete_seconds": max(0.0, observed_at - started_at),
                })

    copy_failure: BaseException | None = None
    try:
        if activity:
            activity({
                "phase": "write.pending",
                "io_mode": io_mode,
                "copied_bytes": 0,
                "pending_bytes": planned_total,
            })
        if progress:
            progress(0)
        if should_cancel():
            if hash_failure:
                raise hash_failure[0]
            raise OperationCancelled("Copia interrotta dall'operatore")
        copy_file(source, destination, report, should_cancel)
    except BaseException as exc:
        copy_failure = exc
        cancel.set()

    copy_return_at = monotonic()
    if copy_failure is None and should_cancel():
        copy_failure = OperationCancelled("Copia interrotta dall'operatore")
        cancel.set()

    if copy_failure is None:
        if not close_pending:
            close_pending = True
            data_complete_at = copy_return_at
            if activity:
                activity({
                    "phase": "close.pending",
                    "io_mode": io_mode,
                    "copied_bytes": last_transferred,
                    "pending_bytes": 0,
                    "data_complete_seconds": max(
                        0.0, data_complete_at - started_at
                    ),
                })
        if activity:
            activity({
                "phase": "close.complete",
                "io_mode": io_mode,
                "copied_bytes": last_transferred,
                "pending_bytes": 0,
                "data_complete_seconds": max(
                    0.0, (data_complete_at or copy_return_at) - started_at
                ),
                "copy_return_seconds": max(0.0, copy_return_at - started_at),
                "close_elapsed_seconds": max(
                    0.0, copy_return_at - (data_complete_at or copy_return_at)
                ),
            })

    wait_timeout = (
        cancel_wait_timeout_seconds
        if copy_failure is not None
        else hash_wait_timeout_seconds
    )
    hash_worker.join(timeout=max(0.0, float(wait_timeout)))
    if hash_worker.is_alive():
        cancel.set()
        timeout_error = CopyError(
            "Timeout del calcolo SHA-256 sulla sorgente SMB; "
            "il worker non ha risposto alla richiesta di arresto"
        )
        if copy_failure is not None:
            copy_failure.add_note(str(timeout_error))
        else:
            hash_worker.join(timeout=max(0.0, float(cancel_wait_timeout_seconds)))
            raise timeout_error

    meaningful_hash_failure = next(
        (
            exc for exc in hash_failure
            if not isinstance(exc, OperationCancelled)
        ),
        None,
    )
    if meaningful_hash_failure is not None:
        if (
            copy_failure is not None
            and copy_failure is not meaningful_hash_failure
        ):
            raise meaningful_hash_failure from copy_failure
        raise meaningful_hash_failure
    if copy_failure is not None:
        raise copy_failure

    if hash_failure:
        raise hash_failure[0]
    if not hash_result:
        raise RuntimeError("Calcolo SHA-256 terminato senza risultato")
    if not hash_completed_at:
        raise RuntimeError("Calcolo SHA-256 terminato senza timestamp")
    if activity:
        hash_complete_at = hash_completed_at[0]
        activity({
            "phase": "hash.complete",
            "io_mode": io_mode,
            "copied_bytes": last_transferred,
            "pending_bytes": 0,
            "hash_complete_seconds": max(0.0, hash_complete_at - started_at),
        })
        activity({
            "phase": "timing.complete",
            "io_mode": io_mode,
            "copied_bytes": last_transferred,
            "pending_bytes": 0,
            "data_complete_seconds": max(
                0.0, (data_complete_at or copy_return_at or started_at) - started_at
            ),
            "copy_return_seconds": max(
                0.0, (copy_return_at or started_at) - started_at
            ),
            "close_elapsed_seconds": max(
                0.0,
                (copy_return_at or started_at)
                - (data_complete_at or copy_return_at or started_at),
            ),
            "hash_complete_seconds": max(0.0, hash_complete_at - started_at),
        })
    return hash_result[0]


def copy_and_hash_windows_streaming(
    source: Path,
    destination: Path,
    buffer_bytes: int,
    progress: Callable[[int], None] | None = None,
    *,
    activity: Callable[[dict], None] | None = None,
    stop_requested: Callable[[], bool] | None = None,
    native_source: Callable[[Path], str] = lambda path: os.path.abspath(path),
    close_batch: WindowsStreamingCloseBatch | None = None,
) -> str:
    """Overlap SMB reads and cached sequential writes with three buffers."""

    if os.name != "nt":
        raise WindowsStreamingUnsupported("Percorso I/O Windows non disponibile")
    destination.parent.mkdir(parents=True, exist_ok=True)
    kernel32 = _kernel32()
    block_size = max(1, buffer_bytes)
    buffers = [_AlignedBuffer(kernel32, block_size) for _ in range(3)]
    writer: _NativeDestination | None = None
    free_buffers: queue.Queue[int] = queue.Queue()
    pending: queue.Queue[tuple[int, int] | None] = queue.Queue(maxsize=len(buffers))
    failure: list[BaseException] = []
    abort = threading.Event()
    copied = 0
    digest = hashlib.sha256()
    for index in range(len(buffers)):
        free_buffers.put(index)

    try:
        writer = _NativeDestination(kernel32, destination)
        if activity:
            activity({
                "phase": "strategy.selected",
                "io_mode": "windows_cached_sequential_pipeline",
                "copied_bytes": 0,
                "pending_bytes": 0,
            })

        def write_worker() -> None:
            nonlocal copied
            try:
                while True:
                    item = pending.get()
                    if item is None:
                        return
                    if stop_requested and stop_requested():
                        raise OperationCancelled("Copia interrotta dall'operatore")
                    index, count = item
                    if activity:
                        activity({
                            "phase": "write.pending",
                            "io_mode": "windows_cached_sequential_pipeline",
                            "copied_bytes": copied,
                            "pending_bytes": count,
                        })
                    writer.write(buffers[index].address, count)
                    copied += count
                    if activity:
                        activity({
                            "phase": "write.complete",
                            "io_mode": "windows_cached_sequential_pipeline",
                            "copied_bytes": copied,
                            "pending_bytes": 0,
                        })
                    if progress:
                        progress(copied)
                    free_buffers.put(index)
            except BaseException as exc:
                failure.append(exc)
                abort.set()

        worker = threading.Thread(
            target=write_worker, name="lto-windows-stream-writer", daemon=True
        )
        worker.start()
        try:
            with open(native_source(source), "rb", buffering=0) as source_stream:
                held: tuple[int, int] | None = None
                while True:
                    if stop_requested and stop_requested():
                        raise OperationCancelled("Copia interrotta dall'operatore")
                    while True:
                        if failure:
                            raise failure[0]
                        try:
                            index = free_buffers.get(timeout=0.1)
                            break
                        except queue.Empty:
                            if abort.is_set() and failure:
                                raise failure[0]
                    count = 0
                    while count < block_size:
                        if activity:
                            activity({
                                "phase": "read.pending",
                                "io_mode": "windows_cached_sequential_pipeline",
                                "copied_bytes": copied,
                                "pending_bytes": 0,
                            })
                        read = source_stream.readinto(buffers[index].view[count:])
                        if activity:
                            activity({
                                "phase": "read.complete",
                                "io_mode": "windows_cached_sequential_pipeline",
                                "copied_bytes": copied,
                                "pending_bytes": max(0, int(read or 0)),
                            })
                        if not read:
                            break
                        count += read
                    if not count:
                        free_buffers.put(index)
                        if held is not None:
                            pending.put(held)
                        break
                    digest.update(buffers[index].view[:count])
                    if held is not None:
                        pending.put(held)
                    held = (index, count)
            pending.put(None)
            worker.join()
            if failure:
                raise failure[0]
        except BaseException:
            abort.set()
            if worker.is_alive():
                try:
                    pending.put_nowait(None)
                except queue.Full:
                    pass
                worker.join()
            raise

        if close_batch is None:
            if activity:
                activity({
                    "phase": "close.pending",
                    "io_mode": "windows_cached_sequential_pipeline",
                    "copied_bytes": copied,
                    "pending_bytes": 0,
                })
            writer.close()
            if activity:
                activity({
                    "phase": "close.complete",
                    "io_mode": "windows_cached_sequential_pipeline",
                    "copied_bytes": copied,
                    "pending_bytes": 0,
                })
        else:
            if activity:
                activity({
                    "phase": "close_queue.pending",
                    "io_mode": "windows_cached_sequential_pipeline",
                    "copied_bytes": copied,
                    "pending_bytes": 0,
                })
            close_batch.defer(writer)
            writer = None
            if activity:
                activity({
                    "phase": "close_queue.complete",
                    "io_mode": "windows_cached_sequential_pipeline",
                    "copied_bytes": copied,
                    "pending_bytes": 0,
                })
        return digest.hexdigest()
    finally:
        if writer is not None and writer.handle is not None:
            writer.close()
        for buffer in buffers:
            buffer.close()
