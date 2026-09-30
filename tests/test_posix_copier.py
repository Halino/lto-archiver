from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import ltobackup.tape.copier as copier_module
from ltobackup.daemon.models import StaleOperationFence
from ltobackup.errors import CopyError, OperationCancelled
from ltobackup.tape.copier import (
    CopyRequest,
    SourceChanged,
    UnsafeCopyPath,
    copy_frozen_file,
)
from ltobackup.util import ltfs_tape_relative_path

PATH_FIXTURE = (
    ("Caffè/episodio.mkv", "Caffè/episodio.mkv"),
    ("I Flintstones /episode.mkv", "~lto1~I Flintstones%20/episode.mkv"),
    ("I Flintstones%20/episode.mkv", "I Flintstones%20/episode.mkv"),
    ("~lto1~literal/file.mkv", "~lto1~~lto1~literal/file.mkv"),
    ("CON.txt", "~lto1~CON.txt"),
)


class _TrackedHandle:
    def __init__(self, raw, tracker, role: str):
        self._raw = raw
        self._tracker = tracker
        self._role = role
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._raw.closed

    def fileno(self) -> int:
        return self._raw.fileno()

    def readinto(self, buffer) -> int:
        self._tracker.read_buffer_lengths.append(len(buffer))
        count = self._raw.readinto(buffer)
        if count:
            self._tracker.source_data_reads += 1
        if (
            count
            and self._tracker.mutate_source_after_read
            and self._tracker.source_data_reads
            >= self._tracker.source_reads_before_mutation
        ):
            self._tracker.mutate_source_after_read = False
            source = self._tracker.source
            source_stat = source.stat()
            os.utime(
                source,
                ns=(source_stat.st_atime_ns, source_stat.st_mtime_ns + 1_000_000),
            )
        if (
            count
            and self._tracker.mutate_hardlink_after_read
            and self._tracker.source_data_reads
            >= self._tracker.source_reads_before_mutation
        ):
            self._tracker.mutate_hardlink_after_read = False
            self._tracker.mutate_source_hardlink()
        return count

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        result = self._raw.seek(offset, whence)
        if self._role == "source":
            self._tracker.source_seek_count += 1
            if (
                self._tracker.mutate_hardlink_on_source_seek
                == self._tracker.source_seek_count
            ):
                self._tracker.mutate_hardlink_on_source_seek = None
                self._tracker.mutate_source_hardlink()
        return result

    def write(self, data) -> int | None:
        if self._tracker.replace_destination_on_write:
            self._tracker.replace_destination_on_write = False
            os.unlink(self._tracker.destination)
            fd = os.open(
                self._tracker.destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(fd, b"competitor")
            finally:
                os.close(fd)
            raise OSError("injected destination replacement")
        if self._tracker.replace_destination_after_write:
            self._tracker.replace_destination_after_write = False
            written = self._raw.write(data)
            os.unlink(self._tracker.destination)
            fd = os.open(
                self._tracker.destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(fd, b"competitor-after-write")
            finally:
                os.close(fd)
            return written
        if self._tracker.fail_write:
            raise OSError("injected write failure")
        if self._tracker.zero_write:
            return 0
        if self._tracker.short_write_bytes is not None:
            count = min(self._tracker.short_write_bytes, len(data))
            return self._raw.write(data[:count])
        return self._raw.write(data)

    def close(self) -> None:
        if self._closed:
            return
        if self._role == "destination":
            details = os.fstat(self._raw.fileno())
            self._tracker.closed_destination_identity = (
                details.st_dev,
                details.st_ino,
            )
        try:
            self._raw.close()
        finally:
            self._closed = True
            self._tracker.active[self._role] -= 1
            self._tracker.file_handle_closed = True
        if self._tracker.replace_destination_on_close and self._role == "destination":
            self._tracker.replace_destination_on_close = False
            os.unlink(self._tracker.destination)
            fd = os.open(
                self._tracker.destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(fd, b"competitor-after-close")
            finally:
                os.close(fd)
            details = os.stat(self._tracker.destination, follow_symlinks=False)
            self._tracker.replacement_identity = (details.st_dev, details.st_ino)
        if self._tracker.fail_destination_close and self._role == "destination":
            raise OSError("destination-close")
        if self._tracker.fail_source_close and self._role == "source":
            raise OSError("source-close")

    def __getattr__(self, name):
        return getattr(self._raw, name)


class _TrackingOpen:
    def __init__(self, source: Path, destination: Path):
        self.source = source
        self.destination = destination
        self._open = open
        self.handles: list[_TrackedHandle] = []
        self.active = {"source": 0, "destination": 0}
        self.maximum = {"source": 0, "destination": 0, "total": 0}
        self.read_buffer_lengths: list[int] = []
        self.fail_write = False
        self.zero_write = False
        self.short_write_bytes: int | None = None
        self.fail_destination_close = False
        self.fail_source_close = False
        self.file_handle_closed = False
        self.mutate_source_after_read = False
        self.mutate_hardlink_after_read = False
        self.source_data_reads = 0
        self.source_seek_count = 0
        self.source_reads_before_mutation = 1
        self.mutate_hardlink_on_source_seek: int | None = None
        self.source_hardlink: Path | None = None
        self.frozen_source_mtime_ns = 0
        self.mutated_source_ctime_ns: int | None = None
        self.replace_destination_on_write = False
        self.replace_destination_after_write = False
        self.replace_destination_on_close = False
        self.closed_destination_identity: tuple[int, int] | None = None
        self.replacement_identity: tuple[int, int] | None = None

    def mutate_source_hardlink(self) -> None:
        hardlink = self.source_hardlink
        assert hardlink is not None
        frozen = hardlink.stat()
        fd = os.open(hardlink, os.O_WRONLY)
        try:
            os.pwrite(fd, b"Z" * frozen.st_size, 0)
        finally:
            os.close(fd)
        os.utime(
            hardlink,
            ns=(frozen.st_atime_ns, self.frozen_source_mtime_ns),
        )
        self.mutated_source_ctime_ns = hardlink.stat().st_ctime_ns

    def __call__(self, path, mode="r", *args, **kwargs):
        raw = self._open(path, mode, *args, **kwargs)
        role = "destination" if "x" in mode or "w" in mode else "source"
        self.active[role] += 1
        self.maximum[role] = max(self.maximum[role], self.active[role])
        self.maximum["total"] = max(self.maximum["total"], sum(self.active.values()))
        handle = _TrackedHandle(raw, self, role)
        self.handles.append(handle)
        return handle


class _StepClock:
    def __init__(self, step: float = 0.25):
        self._now = -step
        self._step = step

    def __call__(self) -> float:
        self._now += self._step
        return self._now


class _FrozenCtimeStat:
    def __init__(self, status: os.stat_result, ctime_ns: int):
        self._status = status
        self.st_ctime_ns = ctime_ns

    def __getattr__(self, name):
        return getattr(self._status, name)


class PosixCopierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source.bin"
        self.destination = self.root / "tape" / "destination.bin"
        self.destination.parent.mkdir()
        self.payload = b"abcdefghijk"
        self.source.write_bytes(self.payload)
        self.source_stat = self.source.stat()

    def request(self, **changes) -> CopyRequest:
        values = {
            "source": self.source,
            "destination": self.destination,
            "expected_size": self.source_stat.st_size,
            "expected_mtime_ns": self.source_stat.st_mtime_ns,
            "buffer_bytes": 4,
            "stop_requested": lambda: False,
            "phase_callback": lambda event: None,
            "fence_check": lambda: None,
        }
        values.update(changes)
        return CopyRequest(**values)

    def test_literal_logical_paths_map_to_distinct_exact_ltfs_paths(self) -> None:
        self.assertEqual(
            PATH_FIXTURE,
            tuple(
                (logical, ltfs_tape_relative_path(logical))
                for logical, _physical in PATH_FIXTURE
            ),
        )
        self.assertEqual(
            len(PATH_FIXTURE), len({physical for _logical, physical in PATH_FIXTURE})
        )

    def test_copier_uses_exact_unicode_and_escaped_destination_without_label_interpolation(self) -> None:
        destination = self.root / "tape" / "libraries" / "LIB-A" / "blocks" / "BLOCK-A"
        destination = destination / "~lto1~~lto1~literal" / "Caffè.mkv"
        destination.parent.mkdir(parents=True)
        request = self.request(destination=destination)

        result = copy_frozen_file(request)

        self.assertEqual(self.payload, destination.read_bytes())
        self.assertEqual(len(self.payload), result.bytes_copied)
        self.assertNotIn("AB1234", destination.parts)
        self.assertEqual("~lto1~~lto1~literal", destination.parent.name)

    def test_hashes_inline_closes_handles_and_reports_separate_timings(self):
        events = []
        tracker = _TrackingOpen(self.source, self.destination)
        clock = _StepClock()
        request = self.request(
            buffer_bytes=32,
            phase_callback=events.append,
        )

        with (
            patch("builtins.open", tracker),
            patch("ltobackup.tape.copier.time.monotonic", clock),
            patch("ltobackup.tape.copier.os.fsync", side_effect=AssertionError),
        ):
            result = copy_frozen_file(request)

        self.assertEqual(hashlib.sha256(self.payload).hexdigest(), result.sha256)
        self.assertEqual(len(self.payload), result.bytes_copied)
        self.assertEqual(1.0, result.read_seconds)
        self.assertEqual(0.5, result.write_seconds)
        self.assertEqual(0.5, result.close_seconds)
        self.assertEqual(self.payload, self.destination.read_bytes())
        self.assertEqual(
            request.expected_mtime_ns,
            self.destination.stat().st_mtime_ns,
        )
        self.assertEqual(
            ["file.read.complete", "file.write.complete", "file.close.complete"],
            [event["event"] for event in events],
        )
        self.assertEqual(result.read_seconds, events[0]["duration_seconds"])
        self.assertEqual(result.write_seconds, events[1]["duration_seconds"])
        self.assertEqual(result.close_seconds, events[2]["duration_seconds"])
        self.assertEqual(1, tracker.maximum["source"])
        self.assertEqual(1, tracker.maximum["destination"])
        self.assertEqual(2, tracker.maximum["total"])
        self.assertTrue(all(handle.closed for handle in tracker.handles))
        with self.destination.open("ab") as handle:
            handle.write(b"x")

    def test_uses_one_bounded_reusable_read_buffer(self):
        tracker = _TrackingOpen(self.source, self.destination)

        with patch("builtins.open", tracker):
            copy_frozen_file(self.request(buffer_bytes=3))

        self.assertTrue(tracker.read_buffer_lengths)
        self.assertEqual({3}, set(tracker.read_buffer_lengths))

    def test_changed_source_is_rejected_before_destination_creation(self):
        self.source.write_bytes(b"changed")

        with self.assertRaises(SourceChanged):
            copy_frozen_file(self.request())

        self.assertFalse(self.destination.exists())

    def test_missing_frozen_source_is_reported_as_changed_before_destination(self):
        self.source.unlink()

        with self.assertRaises(SourceChanged):
            copy_frozen_file(self.request())

        self.assertFalse(self.destination.exists())

    def test_source_symlink_is_rejected_before_destination_creation(self):
        target = self.root / "target.bin"
        target.write_bytes(self.payload)
        self.source.unlink()
        self.source.symlink_to(target)
        target_stat = target.stat()

        with self.assertRaises(SourceChanged):
            copy_frozen_file(
                self.request(
                    expected_size=target_stat.st_size,
                    expected_mtime_ns=target_stat.st_mtime_ns,
                )
            )

        self.assertFalse(self.destination.exists())

    def test_source_inode_swap_between_stat_and_open_is_rejected(self):
        original_os_open = os.open
        swap_armed = True

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swap_armed
            if (
                swap_armed
                and dir_fd is not None
                and not flags & os.O_DIRECTORY
                and not flags & os.O_CREAT
            ):
                swap_armed = False
                frozen = self.source.stat()
                moved = self.source.with_suffix(".moved")
                os.rename(self.source, moved)
                fd = original_os_open(
                    self.source,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    os.write(fd, moved.read_bytes())
                finally:
                    os.close(fd)
                os.utime(
                    self.source,
                    ns=(frozen.st_atime_ns, frozen.st_mtime_ns),
                )
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch("ltobackup.tape.copier.os.open", swapping_open),
            self.assertRaises(SourceChanged),
        ):
            copy_frozen_file(self.request())

        self.assertFalse(self.destination.exists())

    def test_source_symlink_swap_between_stat_and_open_is_source_changed(self):
        original_os_open = os.open
        swap_armed = True

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swap_armed
            if (
                swap_armed
                and dir_fd is not None
                and not flags & os.O_DIRECTORY
                and not flags & os.O_CREAT
            ):
                swap_armed = False
                moved = self.source.with_suffix(".moved")
                os.rename(self.source, moved)
                os.symlink(moved, self.source)
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch("ltobackup.tape.copier.os.open", swapping_open),
            self.assertRaises(SourceChanged),
        ):
            copy_frozen_file(self.request())

        self.assertFalse(self.destination.exists())

    def test_source_mutation_during_copy_retains_owned_partial(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.mutate_source_after_read = True
        tracker.source_reads_before_mutation = 4

        with (
            patch("builtins.open", tracker),
            self.assertRaises(SourceChanged),
        ):
            copy_frozen_file(self.request())

        self.assertTrue(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_same_size_hardlink_write_with_restored_mtime_is_rejected(self):
        hardlink = self.root / "source-hardlink.bin"
        os.link(self.source, hardlink)
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.mutate_hardlink_after_read = True
        tracker.source_hardlink = hardlink
        tracker.frozen_source_mtime_ns = self.source_stat.st_mtime_ns

        with (
            patch("builtins.open", tracker),
            self.assertRaises(SourceChanged),
        ):
            copy_frozen_file(self.request())

        self.assertIsNotNone(tracker.mutated_source_ctime_ns)

    def test_unchanged_preexisting_source_hardlink_is_accepted(self):
        hardlink = self.root / "unchanged-source-hardlink.bin"
        os.link(self.source, hardlink)

        result = copy_frozen_file(self.request())

        self.assertEqual(hashlib.sha256(self.payload).hexdigest(), result.sha256)
        self.assertEqual(self.payload, self.destination.read_bytes())
        self.assertEqual(2, self.source.stat().st_nlink)

    def test_same_tick_hardlink_writes_are_rejected_in_every_digest_window(self):
        original_stat = os.stat
        original_fstat = os.fstat

        timings = {
            "between digest-before and copy": {"seek": 2},
            "during copy": {"read": 4},
            "between copy and digest-after": {"seek": 3},
        }
        for timing, trigger in timings.items():
            for iteration in range(4):
                case = f"{timing}-{iteration}"
                source = self.root / f"same-tick-source-{case}.bin"
                hardlink = self.root / f"same-tick-hardlink-{case}.bin"
                destination = self.destination.with_name(f"same-tick-{case}.bin")
                source.write_bytes(self.payload)
                frozen = source.stat()
                os.link(source, hardlink)
                source_identity = (frozen.st_dev, frozen.st_ino)
                tracker = _TrackingOpen(source, destination)
                tracker.mutate_hardlink_after_read = "read" in trigger
                tracker.source_reads_before_mutation = trigger.get("read", 1)
                tracker.mutate_hardlink_on_source_seek = trigger.get("seek")
                tracker.source_hardlink = hardlink
                tracker.frozen_source_mtime_ns = frozen.st_mtime_ns

                def freeze_source_ctime(
                    status: os.stat_result,
                    *,
                    expected_identity=source_identity,
                    expected_ctime_ns=frozen.st_ctime_ns,
                ):
                    if (status.st_dev, status.st_ino) == expected_identity:
                        return _FrozenCtimeStat(status, expected_ctime_ns)
                    return status

                def same_tick_stat(*args, **kwargs):
                    return freeze_source_ctime(original_stat(*args, **kwargs))

                def same_tick_fstat(*args, **kwargs):
                    return freeze_source_ctime(original_fstat(*args, **kwargs))

                with self.subTest(timing=timing, iteration=iteration):
                    with (
                        patch("builtins.open", tracker),
                        patch("ltobackup.tape.copier.os.stat", same_tick_stat),
                        patch("ltobackup.tape.copier.os.fstat", same_tick_fstat),
                        self.assertRaises(SourceChanged),
                    ):
                        copy_frozen_file(
                            self.request(
                                source=source,
                                destination=destination,
                                expected_size=frozen.st_size,
                                expected_mtime_ns=frozen.st_mtime_ns,
                            )
                        )

                    self.assertEqual(
                        frozen.st_ctime_ns,
                        tracker.mutated_source_ctime_ns,
                    )

    def test_stale_fence_before_destination_creation_leaves_no_destination(self):
        def stale() -> None:
            raise StaleOperationFence("stale")

        with self.assertRaises(StaleOperationFence):
            copy_frozen_file(self.request(fence_check=stale))

        self.assertFalse(self.destination.exists())

    def test_stale_fence_between_buffers_closes_and_retains_owned_partial(self):
        checks = 0
        tracker = _TrackingOpen(self.source, self.destination)

        def stale_between_copy_buffers() -> None:
            nonlocal checks
            checks += 1
            if checks == 6:
                raise StaleOperationFence("stale")

        with (
            patch("builtins.open", tracker),
            self.assertRaises(StaleOperationFence),
        ):
            copy_frozen_file(self.request(fence_check=stale_between_copy_buffers))

        self.assertEqual(6, checks)
        self.assertTrue(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_stop_request_closes_source_before_destination_creation(self):
        tracker = _TrackingOpen(self.source, self.destination)

        with (
            patch("builtins.open", tracker),
            self.assertRaises(OperationCancelled),
        ):
            copy_frozen_file(self.request(stop_requested=lambda: True))

        self.assertFalse(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_cancelled_empty_file_never_creates_destination(self):
        self.source.write_bytes(b"")
        source_stat = self.source.stat()

        with self.assertRaises(OperationCancelled):
            copy_frozen_file(
                self.request(
                    expected_size=0,
                    expected_mtime_ns=source_stat.st_mtime_ns,
                    stop_requested=lambda: True,
                )
            )

        self.assertFalse(self.destination.exists())

    def test_short_writes_are_completed_and_each_attempt_is_fenced(self):
        checks = 0
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.short_write_bytes = 2

        def count_fence() -> None:
            nonlocal checks
            checks += 1

        with patch("builtins.open", tracker):
            result = copy_frozen_file(self.request(fence_check=count_fence))

        expected_write_attempts = 6
        expected_digest_reads = 6
        self.assertEqual(
            1 + expected_write_attempts + expected_digest_reads + 1,
            checks,
        )
        self.assertEqual(self.payload, self.destination.read_bytes())
        self.assertEqual(len(self.payload), result.bytes_copied)

    def test_stale_fence_immediately_before_timestamp_retains_partial(self):
        frozen_mtime_ns = 1_700_000_000_000_000_000
        os.utime(self.source, ns=(frozen_mtime_ns, frozen_mtime_ns))
        self.source_stat = self.source.stat()
        checks = 0

        def stale_before_timestamp() -> None:
            nonlocal checks
            checks += 1
            if checks == 5:
                raise StaleOperationFence("stale before timestamp")

        with self.assertRaisesRegex(StaleOperationFence, "before timestamp"):
            copy_frozen_file(
                self.request(buffer_bytes=32, fence_check=stale_before_timestamp)
            )

        self.assertEqual(5, checks)
        self.assertTrue(self.destination.exists())
        self.assertNotEqual(
            self.source_stat.st_mtime_ns,
            self.destination.stat().st_mtime_ns,
        )

    def test_timestamp_uses_destination_descriptor_and_preserves_atime(self):
        frozen_mtime_ns = 1_700_000_000_000_000_000
        os.utime(self.source, ns=(frozen_mtime_ns, frozen_mtime_ns))
        self.source_stat = self.source.stat()
        real_utime = os.utime
        calls: list[tuple[object, tuple[int, int]]] = []

        def recording_utime(target, *, ns):
            calls.append((target, ns))
            real_utime(target, ns=ns)

        with patch("ltobackup.tape.copier.os.utime", recording_utime):
            copy_frozen_file(self.request(buffer_bytes=32))

        self.assertEqual(1, len(calls))
        target, timestamps = calls[0]
        self.assertIs(type(target), int)
        self.assertEqual(self.source_stat.st_mtime_ns, timestamps[1])
        self.assertNotEqual(self.source_stat.st_mtime_ns, timestamps[0])

    def test_timestamp_failure_closes_handles_and_emits_no_completion(self):
        tracker = _TrackingOpen(self.source, self.destination)
        events = []

        with (
            patch("builtins.open", tracker),
            patch(
                "ltobackup.tape.copier.os.utime",
                side_effect=OSError("timestamp-write-failed"),
            ),
            self.assertRaisesRegex(OSError, "timestamp-write-failed"),
        ):
            copy_frozen_file(self.request(phase_callback=events.append))

        self.assertTrue(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))
        self.assertEqual([], events)

    def test_zero_byte_write_is_an_error_and_retains_owned_partial(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.zero_write = True

        with (
            patch("builtins.open", tracker),
            self.assertRaisesRegex(CopyError, "zero-byte destination write"),
        ):
            copy_frozen_file(self.request())

        self.assertTrue(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_write_failure_closes_both_handles_and_retains_owned_partial(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.fail_write = True

        with patch("builtins.open", tracker), self.assertRaises(OSError):
            copy_frozen_file(self.request())

        self.assertTrue(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_close_failure_still_closes_source_and_retains_owned_partial(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.fail_destination_close = True

        with patch("builtins.open", tracker), self.assertRaises(OSError):
            copy_frozen_file(self.request())

        self.assertTrue(self.destination.exists())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_existing_destination_is_never_overwritten_or_removed(self):
        self.destination.write_bytes(b"existing")

        with self.assertRaises(FileExistsError):
            copy_frozen_file(self.request())

        self.assertEqual(b"existing", self.destination.read_bytes())

    def test_destination_symlink_is_never_followed_or_removed(self):
        target = self.root / "valuable.bin"
        target.write_bytes(b"valuable")
        self.destination.symlink_to(target)

        with self.assertRaises(FileExistsError):
            copy_frozen_file(self.request())

        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(b"valuable", target.read_bytes())

    def test_destination_creation_race_preserves_competing_file(self):
        original_os_open = os.open
        race_armed = True

        def racing_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal race_armed
            if flags & os.O_CREAT and race_armed:
                race_armed = False
                fd = original_os_open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=dir_fd,
                )
                try:
                    os.write(fd, b"racer")
                finally:
                    os.close(fd)
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch("ltobackup.tape.copier.os.open", racing_open),
            self.assertRaises(FileExistsError),
        ):
            copy_frozen_file(self.request())

        self.assertEqual(b"racer", self.destination.read_bytes())

    def test_destination_parent_symlink_swap_cannot_escape_anchored_directory(self):
        original_os_open = os.open
        moved_parent = self.destination.parent.with_name("tape-moved")
        outside_parent = self.destination.parent.with_name("outside")
        swap_armed = True

        def swapping_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal swap_armed
            if flags & os.O_CREAT and swap_armed:
                swap_armed = False
                outside_parent.mkdir()
                os.rename(self.destination.parent, moved_parent)
                os.symlink(outside_parent, self.destination.parent)
            return original_os_open(path, flags, mode, dir_fd=dir_fd)

        with (
            patch("ltobackup.tape.copier.os.open", swapping_open),
            self.assertRaises(CopyError),
        ):
            copy_frozen_file(self.request())

        outside_destination = outside_parent / self.destination.name
        self.assertFalse(outside_destination.exists())
        self.assertTrue((moved_parent / self.destination.name).exists())

    def test_destination_parent_symlink_is_rejected_before_file_creation(self):
        real_parent = self.destination.parent.with_name("real-tape")
        os.rename(self.destination.parent, real_parent)
        os.symlink(real_parent, self.destination.parent)

        with self.assertRaises(UnsafeCopyPath):
            copy_frozen_file(self.request())

        self.assertFalse((real_parent / self.destination.name).exists())

    def test_source_parent_symlink_is_rejected_before_destination_creation(self):
        real_source_parent = self.root / "real-source"
        real_source_parent.mkdir()
        real_source = real_source_parent / self.source.name
        real_source.write_bytes(self.payload)
        source_parent_link = self.root / "source-link"
        source_parent_link.symlink_to(real_source_parent)
        real_stat = real_source.stat()

        with self.assertRaises(SourceChanged):
            copy_frozen_file(
                self.request(
                    source=source_parent_link / real_source.name,
                    expected_size=real_stat.st_size,
                    expected_mtime_ns=real_stat.st_mtime_ns,
                )
            )

        self.assertFalse(self.destination.exists())

    def test_destination_replacement_after_write_is_rejected_and_preserved(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.replace_destination_after_write = True

        with patch("builtins.open", tracker), self.assertRaises(UnsafeCopyPath):
            copy_frozen_file(self.request(buffer_bytes=32))

        self.assertEqual(b"competitor-after-write", self.destination.read_bytes())

    def test_destination_replacement_during_close_is_rejected_and_preserved(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.replace_destination_on_close = True

        with patch("builtins.open", tracker), self.assertRaises(UnsafeCopyPath):
            copy_frozen_file(self.request(buffer_bytes=32))

        self.assertEqual(b"competitor-after-close", self.destination.read_bytes())

    def test_destination_reference_prevents_simulated_inode_reuse(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.replace_destination_on_close = True
        original_open = os.open
        original_close = os.close
        original_fstat = os.fstat
        original_from_stat = copier_module._FileIdentity.from_stat
        reference_fds: set[int] = set()
        reference_fstats_after_replacement = 0
        saw_reference = False

        def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal saw_reference
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if (
                getattr(os, "O_PATH", 0)
                and flags & os.O_PATH
                and not flags & os.O_DIRECTORY
                and path == self.destination.name
            ):
                saw_reference = True
                reference_fds.add(descriptor)
            return descriptor

        def tracking_close(descriptor: int) -> None:
            reference_fds.discard(descriptor)
            original_close(descriptor)

        def tracking_fstat(descriptor: int):
            nonlocal reference_fstats_after_replacement
            if descriptor in reference_fds and tracker.replacement_identity is not None:
                reference_fstats_after_replacement += 1
            return original_fstat(descriptor)

        def collide_without_reference(details):
            identity = original_from_stat(details)
            actual = (identity.device, identity.inode)
            if (
                tracker.closed_destination_identity is not None
                and actual == tracker.replacement_identity
                and not reference_fds
            ):
                device, inode = tracker.closed_destination_identity
                return copier_module._FileIdentity(device=device, inode=inode)
            return identity

        with (
            patch("builtins.open", tracker),
            patch("ltobackup.tape.copier.os.open", tracking_open),
            patch("ltobackup.tape.copier.os.close", tracking_close),
            patch("ltobackup.tape.copier.os.fstat", tracking_fstat),
            patch.object(
                copier_module._FileIdentity,
                "from_stat",
                side_effect=collide_without_reference,
            ),
            self.assertRaises(UnsafeCopyPath),
        ):
            copy_frozen_file(self.request(buffer_bytes=32))

        self.assertTrue(saw_reference)
        self.assertGreaterEqual(reference_fstats_after_replacement, 1)
        self.assertEqual(set(), reference_fds)
        self.assertEqual(b"competitor-after-close", self.destination.read_bytes())

    def test_destination_reference_close_failure_is_not_retried_or_leaked(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.replace_destination_on_close = True
        original_open = os.open
        original_close = os.close
        reference_fd: int | None = None
        reference_close_attempts = 0

        def tracking_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal reference_fd
            descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
            if (
                getattr(os, "O_PATH", 0)
                and flags & os.O_PATH
                and not flags & os.O_DIRECTORY
                and path == self.destination.name
            ):
                reference_fd = descriptor
            return descriptor

        def close_reference_then_error(descriptor: int) -> None:
            nonlocal reference_close_attempts
            original_close(descriptor)
            if descriptor == reference_fd:
                reference_close_attempts += 1
                raise OSError("destination-reference-close")

        with (
            patch("builtins.open", tracker),
            patch("ltobackup.tape.copier.os.open", tracking_open),
            patch("ltobackup.tape.copier.os.close", close_reference_then_error),
            self.assertRaises(UnsafeCopyPath) as caught,
        ):
            copy_frozen_file(self.request())

        self.assertIsNotNone(reference_fd)
        self.assertEqual(1, reference_close_attempts)
        notes = "\n".join(getattr(caught.exception, "__notes__", ()))
        self.assertIn("destination-reference-close", notes)
        self.assertEqual(b"competitor-after-close", self.destination.read_bytes())
        with self.assertRaises(OSError):
            os.fstat(reference_fd)

    def test_missing_o_path_support_fails_closed(self):
        with (
            patch.object(copier_module.os, "O_PATH", None),
            self.assertRaisesRegex(UnsafeCopyPath, "O_PATH"),
        ):
            copy_frozen_file(self.request())

        self.assertTrue(self.destination.exists())

    def test_destination_replacement_in_close_callback_is_rejected(self):
        def replace_after_close_event(event) -> None:
            if event["event"] != "file.close.complete":
                return
            os.unlink(self.destination)
            fd = os.open(
                self.destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                os.write(fd, b"competitor-after-callback")
            finally:
                os.close(fd)

        with self.assertRaises(UnsafeCopyPath):
            copy_frozen_file(self.request(phase_callback=replace_after_close_event))

        self.assertEqual(b"competitor-after-callback", self.destination.read_bytes())

    def test_ancestor_close_failure_does_not_leak_newly_opened_dirfd(self):
        original_close = os.close
        close_failed = False

        def open_fds() -> set[int]:
            descriptors = set()
            for name in os.listdir("/proc/self/fd"):
                descriptor = int(name)
                try:
                    os.fstat(descriptor)
                except OSError:
                    continue
                descriptors.add(descriptor)
            return descriptors

        def close_once_then_error(descriptor: int) -> None:
            nonlocal close_failed
            original_close(descriptor)
            if not close_failed:
                close_failed = True
                raise OSError("ancestor-close")

        before = open_fds()
        after = before
        try:
            with (
                patch("ltobackup.tape.copier.os.close", close_once_then_error),
                self.assertRaises(CopyError),
            ):
                copy_frozen_file(self.request())
            after = open_fds()
            self.assertEqual(before, after)
        finally:
            for leaked in open_fds() - before:
                original_close(leaked)

    def test_all_handle_and_parent_close_errors_are_preserved(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.fail_destination_close = True
        tracker.fail_source_close = True
        original_close = os.close
        parent_close_failed = False

        def fail_parent_close_after_file_close(descriptor: int) -> None:
            nonlocal parent_close_failed
            original_close(descriptor)
            if tracker.file_handle_closed and not parent_close_failed:
                parent_close_failed = True
                raise OSError("parent-close")

        with (
            patch("builtins.open", tracker),
            patch("ltobackup.tape.copier.os.close", fail_parent_close_after_file_close),
            self.assertRaisesRegex(OSError, "destination-close") as caught,
        ):
            copy_frozen_file(self.request())

        notes = "\n".join(getattr(caught.exception, "__notes__", ()))
        self.assertIn("source-close", notes)
        self.assertIn("parent-close", notes)

    def test_cleanup_never_removes_replacement_destination(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.replace_destination_on_write = True

        with patch("builtins.open", tracker), self.assertRaises(OSError):
            copy_frozen_file(self.request())

        self.assertEqual(b"competitor", self.destination.read_bytes())
        self.assertTrue(all(handle.closed for handle in tracker.handles))

    def test_failure_never_attempts_non_atomic_pathname_cleanup(self):
        tracker = _TrackingOpen(self.source, self.destination)
        tracker.fail_write = True

        with (
            patch("builtins.open", tracker),
            patch(
                "ltobackup.tape.copier.os.unlink",
                side_effect=AssertionError("pathname cleanup is forbidden"),
            ),
            self.assertRaises(OSError),
        ):
            copy_frozen_file(self.request())

        self.assertEqual(b"", self.destination.read_bytes())

    def test_rejects_non_positive_buffer_before_opening_any_handle(self):
        tracker = _TrackingOpen(self.source, self.destination)

        with (
            patch("builtins.open", tracker),
            self.assertRaisesRegex(ValueError, "buffer_bytes"),
        ):
            copy_frozen_file(self.request(buffer_bytes=0))

        self.assertEqual([], tracker.handles)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
