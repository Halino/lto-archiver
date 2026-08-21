from __future__ import annotations

import ctypes
import hashlib
import io
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup import winio
from ltobackup.errors import CopyError, OperationCancelled, ValidationError
from ltobackup.winio import WindowsStreamingUnsupported
from ltobackup.filemeta import collect_file_metadata
from ltobackup.util import RunLock, copy_and_hash, safe_join


class UtilTests(unittest.TestCase):
    def test_copyfileex_pipeline_surfaces_hash_failure_before_native_start(self) -> None:
        hash_failed = threading.Event()

        def hash_file(_path, _buffer_bytes, _should_cancel):
            hash_failed.set()
            raise OSError("initial SMB hash failed")

        def progress(copied_bytes):
            self.assertEqual(0, copied_bytes)
            self.assertTrue(hash_failed.wait(1.0))

        with self.assertRaisesRegex(OSError, "initial SMB hash failed") as raised:
            winio.copy_and_hash_windows_copyfile(
                Path("source.bin"),
                Path("destination.bin"),
                64 * 1024,
                progress=progress,
                copy_file=lambda *_args: self.fail("native copy must not start"),
                hash_file=hash_file,
            )
        self.assertIsNot(raised.exception, raised.exception.__cause__)

    def test_copyfileex_pipeline_preserves_hash_failure_over_native_cancellation(self) -> None:
        copy_started = threading.Event()
        hash_failed = threading.Event()

        def hash_file(_path, _buffer_bytes, _should_cancel):
            self.assertTrue(copy_started.wait(1.0))
            hash_failed.set()
            raise OSError("SMB hash failed")

        def copy_file(_src, _dst, _on_progress, should_cancel):
            copy_started.set()
            self.assertTrue(hash_failed.wait(1.0))
            self.assertTrue(should_cancel())
            raise OperationCancelled("native copy cancelled")

        with self.assertRaisesRegex(OSError, "SMB hash failed"):
            winio.copy_and_hash_windows_copyfile(
                Path("source.bin"),
                Path("destination.bin"),
                64 * 1024,
                copy_file=copy_file,
                hash_file=hash_file,
            )

    def test_copyfileex_pipeline_times_out_a_blocked_hash_worker(self) -> None:
        release = threading.Event()

        def hash_file(_path, _buffer_bytes, _should_cancel):
            release.wait(1.0)
            return "a" * 64

        def copy_file(_src, _dst, on_progress, _should_cancel):
            on_progress(10, 10)

        try:
            with self.assertRaisesRegex(CopyError, "Timeout.*SHA-256"):
                winio.copy_and_hash_windows_copyfile(
                    Path("source.bin"),
                    Path("destination.bin"),
                    64 * 1024,
                    copy_file=copy_file,
                    hash_file=hash_file,
                    hash_wait_timeout_seconds=0.01,
                )
        finally:
            release.set()

    def test_copyfileex_pipeline_reports_exact_copy_close_and_hash_durations(self) -> None:
        main_times = iter((100.0, 110.0, 115.0))
        hash_timestamped = threading.Event()
        activities: list[dict] = []

        def monotonic():
            if threading.current_thread().name == "lto-windows-source-hash":
                hash_timestamped.set()
                return 118.0
            return next(main_times)

        def copy_file(_src, _dst, on_progress, _should_cancel):
            self.assertTrue(hash_timestamped.wait(1.0))
            on_progress(10, 10)

        winio.copy_and_hash_windows_copyfile(
            Path("source.bin"),
            Path("destination.bin"),
            64 * 1024,
            activity=activities.append,
            copy_file=copy_file,
            hash_file=lambda *_args: "a" * 64,
            monotonic=monotonic,
        )

        close = next(row for row in activities if row["phase"] == "close.complete")
        timing = next(row for row in activities if row["phase"] == "timing.complete")
        self.assertEqual(10.0, close["data_complete_seconds"])
        self.assertEqual(5.0, close["close_elapsed_seconds"])
        self.assertEqual(15.0, close["copy_return_seconds"])
        self.assertEqual(18.0, timing["hash_complete_seconds"])

    def test_copyfileex_timestamps_hash_when_worker_really_finishes(self) -> None:
        main_times = iter((100.0, 110.0, 115.0))
        hash_timestamped = threading.Event()
        activities: list[dict] = []

        def monotonic():
            if threading.current_thread().name == "lto-windows-source-hash":
                hash_timestamped.set()
                return 105.0
            return next(main_times)

        def copy_file(_src, _dst, on_progress, _should_cancel):
            self.assertTrue(hash_timestamped.wait(1.0))
            on_progress(10, 10)

        winio.copy_and_hash_windows_copyfile(
            Path("source.bin"),
            Path("destination.bin"),
            64 * 1024,
            activity=activities.append,
            copy_file=copy_file,
            hash_file=lambda *_args: "a" * 64,
            monotonic=monotonic,
        )

        timing = next(row for row in activities if row["phase"] == "timing.complete")
        self.assertEqual(5.0, timing["hash_complete_seconds"])
        self.assertEqual(15.0, timing["copy_return_seconds"])

    @unittest.skipUnless(__import__("os").name == "nt", "Windows CopyFileEx callback")
    def test_native_copyfileex_surfaces_progress_callback_failure(self) -> None:
        class FakeCopyFile:
            def __init__(self) -> None:
                self.argtypes = None
                self.restype = None
                self.callback_result = None

            def __call__(self, _source, _destination, callback, *_args):
                self.callback_result = callback(10, 5, 10, 5, 1, 0, 0, 0, 0)
                return 0

        copy_file = FakeCopyFile()
        kernel = SimpleNamespace(CopyFileExW=copy_file)

        with patch("ltobackup.winio._kernel32", return_value=kernel):
            with self.assertRaisesRegex(RuntimeError, "progress callback failed"):
                winio._copy_file_ex(
                    Path("source.bin"),
                    Path("destination.bin"),
                    lambda *_args: (_ for _ in ()).throw(
                        RuntimeError("progress callback failed")
                    ),
                    lambda: False,
                )

        self.assertEqual(winio.PROGRESS_CANCEL, copy_file.callback_result)

    @unittest.skipUnless(__import__("os").name == "nt", "Windows long paths")
    def test_native_copyfileex_uses_extended_length_paths(self) -> None:
        class FakeCopyFile:
            def __init__(self) -> None:
                self.argtypes = None
                self.restype = None
                self.paths = None

            def __call__(self, source, destination, *_args):
                self.paths = (source, destination)
                return 1

        copy_file = FakeCopyFile()
        kernel = SimpleNamespace(CopyFileExW=copy_file)
        long_name = "nested/" * 45 + "archive.mxf"

        with patch("ltobackup.winio._kernel32", return_value=kernel):
            winio._copy_file_ex(
                Path("C:/source") / long_name,
                Path("L:/destination") / long_name,
                lambda *_args: None,
                lambda: False,
            )

        self.assertTrue(copy_file.paths[0].startswith("\\\\?\\"))
        self.assertTrue(copy_file.paths[1].startswith("\\\\?\\"))

    def test_copyfileex_pipeline_hashes_in_parallel_and_reports_close(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "destination.bin"
            payload = (b"copyfileex-ltfs-" * 4096) + b"tail"
            source.write_bytes(payload)
            hash_started = threading.Event()
            activities: list[dict] = []

            def hash_file(path, buffer_bytes, should_cancel):
                self.assertEqual(source, path)
                self.assertEqual(64 * 1024, buffer_bytes)
                self.assertFalse(should_cancel())
                hash_started.set()
                return hashlib.sha256(path.read_bytes()).hexdigest()

            def copy_file(src, dst, on_progress, should_cancel):
                self.assertTrue(hash_started.wait(1.0))
                self.assertFalse(should_cancel())
                dst.write_bytes(src.read_bytes())
                on_progress(len(payload), len(payload))

            digest = winio.copy_and_hash_windows_copyfile(
                source,
                destination,
                64 * 1024,
                activity=activities.append,
                copy_file=copy_file,
                hash_file=hash_file,
            )

            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
            self.assertEqual(payload, destination.read_bytes())
            self.assertEqual(
                [
                    "strategy.selected",
                    "write.pending",
                    "write.complete",
                    "close.pending",
                    "close.complete",
                    "hash.complete",
                    "timing.complete",
                ],
                [event["phase"] for event in activities],
            )
            self.assertTrue(
                all(
                    event.get("io_mode") == "windows_copyfileex_parallel_hash"
                    for event in activities
                )
            )
            pending = next(event for event in activities if event["phase"] == "write.pending")
            self.assertEqual(len(payload), pending["pending_bytes"])

    def test_copyfileex_pipeline_honors_stop_before_native_copy(self) -> None:
        stop = False
        hash_cancelled = threading.Event()

        def progress(copied_bytes):
            nonlocal stop
            self.assertEqual(0, copied_bytes)
            stop = True

        def hash_file(_path, _buffer_bytes, should_cancel):
            while not should_cancel():
                threading.Event().wait(0.01)
            hash_cancelled.set()
            raise OperationCancelled("hash cancelled")

        def copy_file(_src, _dst, _on_progress, _should_cancel):
            self.fail("CopyFileEx non deve partire dopo uno stop iniziale")

        with self.assertRaises(OperationCancelled):
            winio.copy_and_hash_windows_copyfile(
                Path("source.bin"),
                Path("destination.bin"),
                64 * 1024,
                progress=progress,
                stop_requested=lambda: stop,
                copy_file=copy_file,
                hash_file=hash_file,
            )

        self.assertTrue(hash_cancelled.wait(1.0))

    def test_copyfileex_pipeline_cancels_copy_and_hash_together(self) -> None:
        stop = False
        hash_cancelled = threading.Event()

        def hash_file(_path, _buffer_bytes, should_cancel):
            while not should_cancel():
                threading.Event().wait(0.01)
            hash_cancelled.set()
            raise OperationCancelled("hash cancelled")

        def copy_file(_src, _dst, on_progress, should_cancel):
            nonlocal stop
            on_progress(100, 25)
            stop = True
            if should_cancel():
                raise OperationCancelled("copy cancelled")

        with self.assertRaises(OperationCancelled):
            winio.copy_and_hash_windows_copyfile(
                Path("source.bin"),
                Path("destination.bin"),
                64 * 1024,
                stop_requested=lambda: stop,
                copy_file=copy_file,
                hash_file=hash_file,
            )

        self.assertTrue(hash_cancelled.wait(1.0))

    @unittest.skipUnless(__import__("os").name == "nt", "Windows streaming I/O")
    def test_windows_streaming_reports_a_blocking_smb_read(self) -> None:
        release = threading.Event()
        entered = threading.Event()
        activities: list[dict] = []
        errors: list[BaseException] = []

        class BlockingSource(io.BytesIO):
            def readinto(self, buffer) -> int:
                entered.set()
                release.wait(timeout=2.0)
                return super().readinto(buffer)

        source = BlockingSource(b"abcdefgh")

        def copy() -> None:
            try:
                with tempfile.TemporaryDirectory() as temporary:
                    winio.copy_and_hash_windows_streaming(
                        Path("source.bin"),
                        Path(temporary) / "destination.bin",
                        8,
                        activity=activities.append,
                    )
            except BaseException as exc:
                errors.append(exc)

        with patch("ltobackup.winio.open", return_value=source, create=True):
            worker = threading.Thread(target=copy)
            worker.start()
            self.assertTrue(entered.wait(timeout=1.0), errors)
            self.assertEqual("read.pending", activities[-1]["phase"])
            release.set()
            worker.join(timeout=2.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)
        self.assertTrue(any(row["phase"] == "read.complete" for row in activities))

    @unittest.skipUnless(__import__("os").name == "nt", "Windows streaming I/O")
    def test_windows_streaming_reports_close_queue_backpressure(self) -> None:
        release = threading.Event()
        entered = threading.Event()
        activities: list[dict] = []
        errors: list[BaseException] = []

        class BlockingCloseBatch:
            def defer(self, writer) -> None:
                entered.set()
                release.wait(timeout=2.0)
                writer.close()

        def copy() -> None:
            try:
                with tempfile.TemporaryDirectory() as temporary:
                    source = Path(temporary) / "source.bin"
                    source.write_bytes(b"abcdefgh")
                    winio.copy_and_hash_windows_streaming(
                        source,
                        Path(temporary) / "destination.bin",
                        8,
                        activity=activities.append,
                        close_batch=BlockingCloseBatch(),
                    )
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=copy)
        worker.start()
        self.assertTrue(entered.wait(timeout=1.0), errors)
        self.assertEqual("close_queue.pending", activities[-1]["phase"])
        release.set()
        worker.join(timeout=2.0)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)
        self.assertEqual("close_queue.complete", activities[-1]["phase"])

    def test_background_close_starts_before_batch_finish(self) -> None:
        close_started = threading.Event()
        allow_close = threading.Event()

        class SlowWriter:
            path = Path("first.bin")

            def close(self) -> None:
                close_started.set()
                allow_close.wait(timeout=2.0)

        batch = winio.WindowsStreamingCloseBatch(
            background=True,
            max_pending=1,
            expected_files=1,
        )
        batch.defer(SlowWriter())

        self.assertTrue(
            close_started.wait(timeout=1.0),
            "CloseHandle deve iniziare mentre il lotto e ancora in scrittura",
        )
        self.assertFalse(batch.finished)
        allow_close.set()
        batch.finish()
        self.assertTrue(batch.finished)

    def test_background_close_queue_applies_bounded_backpressure(self) -> None:
        first_close_started = threading.Event()
        allow_first_close = threading.Event()
        third_defer_returned = threading.Event()

        class Writer:
            def __init__(self, index: int):
                self.path = Path(f"file-{index}.bin")
                self.index = index

            def close(self) -> None:
                if self.index == 1:
                    first_close_started.set()
                    allow_first_close.wait(timeout=2.0)

        batch = winio.WindowsStreamingCloseBatch(
            background=True,
            max_pending=1,
            expected_files=3,
        )
        batch.defer(Writer(1))
        self.assertTrue(first_close_started.wait(timeout=1.0))
        batch.defer(Writer(2))

        producer = threading.Thread(
            target=lambda: (batch.defer(Writer(3)), third_defer_returned.set()),
            daemon=True,
        )
        producer.start()
        self.assertFalse(
            third_defer_returned.wait(timeout=0.1),
            "la coda piena deve rallentare il producer invece di accumulare handle",
        )
        allow_first_close.set()
        self.assertTrue(third_defer_returned.wait(timeout=1.0))
        producer.join(timeout=1.0)
        batch.finish()

    def test_background_close_ignores_progress_callback_failure(self) -> None:
        closed: list[str] = []

        class Writer:
            def __init__(self, name: str):
                self.path = Path(name)

            def close(self) -> None:
                closed.append(self.path.name)

        def broken_progress(_event: dict) -> None:
            raise RuntimeError("GUI non disponibile")

        batch = winio.WindowsStreamingCloseBatch(
            background=True,
            max_pending=1,
            expected_files=2,
            progress=broken_progress,
        )
        batch.defer(Writer("first.bin"))
        batch.defer(Writer("second.bin"))
        batch.finish()

        self.assertEqual(["first.bin", "second.bin"], closed)
        self.assertTrue(batch.finished)

    def test_windows_streaming_batch_reports_real_close_progress_and_eta(self) -> None:
        clock = [100.0]

        class FakeWriter:
            def __init__(self, name: str, duration: float):
                self.path = Path(name)
                self.duration = duration

            def close(self) -> None:
                clock[0] += self.duration

        batch = winio.WindowsStreamingCloseBatch()
        batch.defer(FakeWriter("first.bin", 2.0))
        batch.defer(FakeWriter("second.bin", 4.0))
        events: list[dict] = []

        batch.finish(progress=events.append, monotonic=lambda: clock[0])

        completed = [event for event in events if event["status"] == "complete"]
        self.assertEqual(
            [
                {
                    "closed_files": 1,
                    "pending_files": 1,
                    "total_files": 2,
                    "elapsed_seconds": 2.0,
                    "average_close_seconds": 2.0,
                    "eta_seconds": 2.0,
                },
                {
                    "closed_files": 2,
                    "pending_files": 0,
                    "total_files": 2,
                    "elapsed_seconds": 6.0,
                    "average_close_seconds": 3.0,
                    "eta_seconds": 0.0,
                },
            ],
            [
                {
                    key: event[key]
                    for key in (
                        "closed_files", "pending_files", "total_files",
                        "elapsed_seconds", "average_close_seconds", "eta_seconds",
                    )
                }
                for event in completed
            ],
        )

    def test_windows_streaming_batch_never_closes_a_data_file_early(self) -> None:
        class FakeWriter:
            def __init__(self, index: int):
                self.path = Path(f"file-{index}.bin")
                self.closed = False

            def close(self) -> None:
                self.closed = True

        batch = winio.WindowsStreamingCloseBatch()
        writers = [FakeWriter(index) for index in range(600)]
        for writer in writers:
            batch.defer(writer)

        self.assertFalse(any(writer.closed for writer in writers))
        self.assertEqual(len(writers), batch.pending_count)
        batch.finish()
        self.assertTrue(all(writer.closed for writer in writers))

    @unittest.skipUnless(__import__("os").name == "nt", "Windows streaming I/O")
    def test_windows_streaming_batch_defers_file_closes_until_finish(self) -> None:
        batch_type = getattr(winio, "WindowsStreamingCloseBatch", None)
        self.assertIsNotNone(
            batch_type,
            "la chiusura dei file dati LTFS deve essere differita alla fine del lotto",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = [root / "source-a.bin", root / "source-b.bin"]
            destinations = [root / "tape-a.bin", root / "tape-b.bin"]
            payloads = [b"A" * 131_071, b"B" * 196_613]
            for source, payload in zip(sources, payloads, strict=True):
                source.write_bytes(payload)

            batch = batch_type()
            for source, destination in zip(sources, destinations, strict=True):
                winio.copy_and_hash_windows_streaming(
                    source,
                    destination,
                    64 * 1024,
                    close_batch=batch,
                )

            self.assertEqual(2, batch.pending_count)
            self.assertFalse(batch.finished)
            batch.finish()

            self.assertTrue(batch.finished)
            self.assertEqual(0, batch.pending_count)
            self.assertEqual(payloads, [path.read_bytes() for path in destinations])

    def test_windows_ltfs_destination_uses_cached_sequential_open(self) -> None:
        class FakeKernel:
            def __init__(self) -> None:
                self.flags = 0

            def CreateFileW(
                self, _path, _access, _share, _security, _creation, flags, _template
            ):
                self.flags = flags
                return 42

            def CloseHandle(self, _handle) -> int:
                return 1

        kernel = FakeKernel()
        destination = winio._NativeDestination(kernel, Path("L:/archive.bin"))
        try:
            self.assertTrue(kernel.flags & winio.FILE_FLAG_SEQUENTIAL_SCAN)
            self.assertFalse(kernel.flags & winio.FILE_FLAG_NO_BUFFERING)
        finally:
            destination.close()

    @unittest.skipUnless(__import__("os").name == "nt", "Windows streaming I/O")
    def test_windows_copyfileex_preserves_unaligned_content_and_parallel_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "destination.bin"
            payload = (b"LTO-STREAM-" * 100_003) + b"tail"
            source.write_bytes(payload)
            activities: list[dict] = []

            digest = copy_and_hash(
                source,
                destination,
                64 * 1024,
                activity=activities.append,
                durable=False,
                streaming_destination=True,
            )

            self.assertEqual(payload, destination.read_bytes())
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
            strategy = next(
                event for event in activities if event["phase"] == "strategy.selected"
            )
            self.assertEqual("windows_copyfileex_parallel_hash", strategy["io_mode"])
            self.assertFalse(
                any(
                    event.get("io_mode") == "windows_unbuffered_pipeline_tail"
                    for event in activities
                )
            )

    @unittest.skipUnless(__import__("os").name == "nt", "Windows streaming I/O")
    def test_optimized_tape_copy_never_falls_back_to_the_portable_writer(self) -> None:
        activities: list[dict] = []

        with patch(
            "ltobackup.winio.copy_and_hash_windows_copyfile",
            side_effect=WindowsStreamingUnsupported("StoreOpen non supporta la modalita"),
        ):
            with self.assertRaisesRegex(
                CopyError, "Scrittura ottimizzata obbligatoria non disponibile"
            ):
                copy_and_hash(
                    Path("source.bin"),
                    Path("destination.bin"),
                    64 * 1024,
                    activity=activities.append,
                    durable=False,
                    streaming_destination=True,
                )

        self.assertFalse(any(row.get("phase") == "strategy.fallback" for row in activities))

    def test_ltfs_copy_reports_pending_activity_while_close_is_blocked(self) -> None:
        source = io.BytesIO(b"abcdefgh")
        release = threading.Event()
        entered = threading.Event()
        activities: list[dict] = []
        errors: list[BaseException] = []

        class BlockingCloseWriter(io.BytesIO):
            def close(self) -> None:
                entered.set()
                release.wait(2)

        destination = BlockingCloseWriter()

        def copy() -> None:
            try:
                copy_and_hash(
                    Path("source.bin"),
                    Path("destination.bin"),
                    8,
                    durable=False,
                    activity=activities.append,
                )
            except BaseException as exc:
                errors.append(exc)

        with (
            patch("pathlib.Path.mkdir"),
            patch("ltobackup.util.open", side_effect=[source, destination], create=True),
        ):
            worker = threading.Thread(target=copy)
            worker.start()
            self.assertTrue(entered.wait(1), errors)
            self.assertEqual(
                {
                    "phase": "close.pending",
                    "copied_bytes": 8,
                    "pending_bytes": 0,
                },
                activities[-1],
            )
            release.set()
            worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)

    def test_ltfs_copy_reports_pending_activity_while_flush_is_blocked(self) -> None:
        source = io.BytesIO(b"abcdefgh")
        release = threading.Event()
        entered = threading.Event()
        activities: list[dict] = []
        errors: list[BaseException] = []

        class BlockingFlushWriter(io.BytesIO):
            def flush(self) -> None:
                entered.set()
                release.wait(2)

            def close(self) -> None:
                pass

        destination = BlockingFlushWriter()

        def copy() -> None:
            try:
                copy_and_hash(
                    Path("source.bin"),
                    Path("destination.bin"),
                    8,
                    durable=False,
                    activity=activities.append,
                )
            except BaseException as exc:
                errors.append(exc)

        with (
            patch("pathlib.Path.mkdir"),
            patch("ltobackup.util.open", side_effect=[source, destination], create=True),
        ):
            worker = threading.Thread(target=copy)
            worker.start()
            self.assertTrue(entered.wait(1), errors)
            self.assertEqual(
                {
                    "phase": "flush.pending",
                    "copied_bytes": 8,
                    "pending_bytes": 0,
                },
                activities[-1],
            )
            release.set()
            worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)

    def test_ltfs_copy_reports_pending_activity_before_a_blocking_write_returns(self) -> None:
        source = io.BytesIO(b"abcdefgh")
        release = threading.Event()
        entered = threading.Event()
        activities: list[dict] = []
        errors: list[BaseException] = []

        class BlockingWriter(io.BytesIO):
            def write(self, data) -> int:
                entered.set()
                release.wait(2)
                return super().write(data)

            def close(self) -> None:
                pass

        destination = BlockingWriter()

        def copy() -> None:
            try:
                copy_and_hash(
                    Path("source.bin"),
                    Path("destination.bin"),
                    8,
                    durable=False,
                    activity=activities.append,
                )
            except BaseException as exc:
                errors.append(exc)

        with (
            patch("pathlib.Path.mkdir"),
            patch("ltobackup.util.open", side_effect=[source, destination], create=True),
        ):
            worker = threading.Thread(target=copy)
            worker.start()
            self.assertTrue(entered.wait(1), errors)
            self.assertEqual(
                {
                    "phase": "write.pending",
                    "copied_bytes": 0,
                    "pending_bytes": 8,
                },
                activities[0],
            )
            release.set()
            worker.join(2)

        self.assertFalse(worker.is_alive())
        self.assertEqual([], errors)
        self.assertEqual(b"abcdefgh", destination.getvalue())

    def test_ltfs_copy_can_skip_per_file_fsync_without_changing_content_or_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "destination.bin"
            source.write_bytes(b"0123456789" * 100)

            with patch("ltobackup.util.os.fsync") as fsync:
                digest = copy_and_hash(source, destination, 64, durable=False)

            fsync.assert_not_called()
            self.assertEqual(source.read_bytes(), destination.read_bytes())
            self.assertEqual(
                "ab6c5f3237f551d208fc2ca5225a4cca20b3fd638794a804f0ed5549d5041734",
                digest,
            )

    def test_copy_checks_stop_request_between_buffers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bin"
            destination = root / "destination.bin"
            source.write_bytes(b"x" * 128)
            stop = False

            def progress(_copied: int) -> None:
                nonlocal stop
                stop = True

            with self.assertRaises(OperationCancelled):
                copy_and_hash(
                    source,
                    destination,
                    32,
                    progress=progress,
                    durable=False,
                    stop_requested=lambda: stop,
                )

            self.assertLess(destination.stat().st_size, source.stat().st_size)

    def test_safe_join_rejects_absolute_drive_and_unc_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for unsafe in ("/absolute/file", r"C:\absolute\file", r"C:relative", r"\\server\share\file"):
                with self.subTest(unsafe=unsafe):
                    with self.assertRaises(ValidationError):
                        safe_join(root, unsafe)

    @unittest.skipUnless(__import__("os").name == "nt", "Windows lock behavior")
    def test_run_lock_closes_stream_when_unlock_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            lock = RunLock(Path(temporary) / "run.lock")
            lock.__enter__()
            stream = lock._stream
            with patch("msvcrt.locking", side_effect=OSError("unlock failed")):
                with self.assertRaisesRegex(OSError, "unlock failed"):
                    lock.__exit__(None, None, None)
            self.assertIsNone(lock._stream)
            assert stream is not None
            self.assertTrue(stream.closed)

    def test_ctypes_metadata_error_produces_partial_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "file.bin"
            path.write_bytes(b"data")
            with (
                patch("ltobackup.filemeta.os.name", "nt"),
                patch(
                    "ltobackup.filemeta._windows_security",
                    side_effect=ctypes.ArgumentError("bad argument"),
                ),
                patch("ltobackup.filemeta._windows_streams", return_value=[]),
            ):
                metadata = collect_file_metadata(path)

            self.assertEqual("partial", metadata["metadata_state"])
            self.assertIn("bad argument", metadata["metadata_error"])


if __name__ == "__main__":
    unittest.main()
