"""Bounded synthetic writes must preserve exact evidence on interruption."""

import errno
import hashlib
import importlib
import importlib.util
import os
import stat
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


class CapacityStreamTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(
            importlib.util.find_spec("ltobackup.qualification.capacity_stream"),
            "the bounded capacity stream API is missing",
        )
        self.stream = importlib.import_module("ltobackup.qualification.capacity_stream")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.events = []
        descriptors = set(os.listdir("/proc/self/fd"))
        self.addCleanup(
            lambda: self.assertEqual(set(os.listdir("/proc/self/fd")), descriptors)
        )

    def policy(self, **changes):
        values = {
            "seed": bytes(range(32)),
            "payload_ceiling_bytes": 35,
            "file_bytes": 16,
            "chunk_bytes": 8,
        }
        values.update(changes)
        return self.stream.CapacityStreamPolicy(**values)

    def run_stream(self, **kwargs):
        return self.stream.run_capacity_stream(
            self.directory,
            kwargs.pop("policy", self.policy()),
            record=kwargs.pop("record", self.events.append),
            stop_requested=kwargs.pop("stop_requested", lambda: False),
            **kwargs,
        )

    def test_exact_ceiling_and_independent_payload_vectors(self):
        result = self.run_stream()
        self.assertEqual(result.stop_reason, "ceiling")
        self.assertEqual(result.acknowledged_bytes, 35)
        self.assertEqual(result.complete_bytes, 35)
        self.assertIsInstance(result.completed_files, tuple)
        self.assertEqual([item.bytes for item in result.completed_files], [16, 16, 3])
        self.assertEqual([item.ordinal for item in result.completed_files], [0, 1, 2])
        contents = [
            (self.directory / item.name).read_bytes() for item in result.completed_files
        ]
        # Independently calculated with OpenSSL dgst -shake256 -xoflen 8:
        # domain ASCII "ltobackup-capacity-v1" + NUL, seed bytes 0..31,
        # then unsigned big-endian 64-bit file ordinal and chunk index.
        self.assertEqual(contents[0].hex(), "53f6a3e9442fecbe52a5bc2016f53332")
        self.assertEqual(contents[1].hex(), "c4d10e560afea64b0f6b75b0c77bb554")
        self.assertEqual(
            result.completed_files[0].sha256,
            "4b6e779615881e0dbb0cf95e2d73a0f4bc260f21dcd619a2dc0df0554dbe9988",
        )
        self.assertEqual(
            result.completed_files[1].sha256,
            "88e7a400b9446f3f80bbbfc4b454876cae89e027b4999669980ed6bbdc0d5d9e",
        )
        chunks = [
            content[index : index + 8] for content in contents[:2] for index in (0, 8)
        ]
        self.assertEqual(len(set(chunks)), 4)
        for item, content in zip(result.completed_files, contents):
            self.assertEqual(item.sha256, hashlib.sha256(content).hexdigest())

    def test_invalid_policy_values_are_rejected(self):
        bad_values = {
            "seed": [b"", b"x" * 31, b"x" * 33, bytearray(32), "x" * 32, 32],
            "payload_ceiling_bytes": [True, 0, -1, 35.0, "35", 100_000_000_000_001],
            "file_bytes": [True, 0, -1, 16.0, "16", 36],
            "chunk_bytes": [True, 0, -1, 8.0, "8", 16 * 1024 * 1024 + 1],
        }
        for key, values in bad_values.items():
            for value in values:
                with (
                    self.subTest(field=key, value=value),
                    self.assertRaises(ValueError),
                ):
                    self.policy(**{key: value})
        with self.assertRaises(ValueError):
            self.policy(payload_ceiling_bytes=100_001, file_bytes=1)

    def test_policy_and_completed_evidence_are_immutable(self):
        policy = self.policy()
        with self.assertRaises(FrozenInstanceError):
            policy.seed = b"x" * 32
        result = self.run_stream(policy=policy)
        with self.assertRaises(FrozenInstanceError):
            result.complete_bytes = 0
        with self.assertRaises(FrozenInstanceError):
            result.completed_files[0].bytes = 0

    def test_intents_precede_files_and_progress_precedes_completion(self):
        def record(event):
            if event["event"] == "capacity-start":
                self.assertEqual(list(self.directory.iterdir()), [])
                self.assertEqual(event["seed_hex"], bytes(range(32)).hex())
                self.assertEqual(event["payload_ceiling_bytes"], 35)
                self.assertEqual(event["file_bytes"], 16)
                self.assertEqual(event["chunk_bytes"], 8)
            elif event["event"] == "file-start":
                self.assertFalse((self.directory / event["name"]).exists())
            elif event["event"] == "progress":
                self.assertEqual(
                    (self.directory / event["name"]).stat().st_size, event["bytes"]
                )
            self.events.append(event)

        result = self.run_stream(record=record)
        self.assertEqual(
            [event["event"] for event in self.events],
            [
                "capacity-start",
                "file-start",
                "progress",
                "progress",
                "file-complete",
                "file-start",
                "progress",
                "progress",
                "file-complete",
                "file-start",
                "progress",
                "file-complete",
                "stopped",
            ],
        )
        self.assertEqual(self.events[-1]["complete_bytes"], result.complete_bytes)
        self.assertEqual(
            self.events[-1]["acknowledged_bytes"], result.acknowledged_bytes
        )

    def test_existing_content_is_preserved(self):
        existing = self.directory / "keep"
        existing.write_bytes(b"preserve me")
        with self.assertRaises(ValueError):
            self.run_stream()
        self.assertEqual(existing.read_bytes(), b"preserve me")
        self.assertEqual(list(self.directory.iterdir()), [existing])
        self.assertEqual(self.events, [])

    def test_missing_directory_is_not_created(self):
        self.directory /= "missing" / Path("nested")
        with self.assertRaises(FileNotFoundError):
            self.run_stream()
        self.assertFalse(self.directory.parent.exists())

    def test_root_relative_and_parent_traversal_paths_are_rejected(self):
        for path in (
            Path("/"),
            Path("relative"),
            self.directory / ".." / self.directory.name,
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.stream.run_capacity_stream(
                    path,
                    self.policy(),
                    record=self.events.append,
                    stop_requested=lambda: False,
                )
        self.assertEqual(self.events, [])

    def test_symlink_leaf_and_ancestor_are_rejected(self):
        target = self.directory / "target"
        target.mkdir()
        (target / "nested").mkdir()
        link = self.directory / "link"
        link.symlink_to(target, target_is_directory=True)
        for path in (link, link / "nested"):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                self.stream.run_capacity_stream(
                    path,
                    self.policy(),
                    record=self.events.append,
                    stop_requested=lambda: False,
                )
        self.assertEqual(list((target / "nested").iterdir()), [])
        self.assertEqual(self.events, [])

    def test_directory_is_pinned_when_path_is_replaced(self):
        destination = self.directory / "destination"
        destination.mkdir()
        pinned = self.directory / "pinned"
        outside = self.directory / "outside"
        outside.mkdir()

        def record(event):
            self.events.append(event)
            if event["event"] == "capacity-start":
                destination.rename(pinned)
                destination.symlink_to(outside, target_is_directory=True)

        result = self.stream.run_capacity_stream(
            destination, self.policy(), record=record, stop_requested=lambda: False
        )
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(sum(item.stat().st_size for item in pinned.iterdir()), 35)
        self.assertEqual(result.complete_bytes, 35)

    def test_exclusive_file_open_preserves_a_racing_symlink_target(self):
        target = self.directory.parent / (self.directory.name + "-target")
        target.write_bytes(b"preserve me")
        self.addCleanup(target.unlink)

        def record(event):
            self.events.append(event)
            if event["event"] == "file-start":
                (self.directory / event["name"]).symlink_to(target)

        with self.assertRaises(FileExistsError):
            self.run_stream(record=record)
        self.assertEqual(target.read_bytes(), b"preserve me")

    def test_short_writes_do_not_skip_payload_offsets(self):
        real_write = os.write

        def short_write(fd, payload):
            return real_write(fd, payload[:3])

        with patch.object(self.stream.os, "write", side_effect=short_write):
            result = self.run_stream()
        first = self.directory / result.completed_files[0].name
        self.assertEqual(first.read_bytes().hex(), "53f6a3e9442fecbe52a5bc2016f53332")
        self.assertEqual(result.acknowledged_bytes, 35)

    def test_enospc_mid_chunk_preserves_exact_acknowledged_and_complete_bytes(self):
        real_write = os.write
        budget = 27

        def bounded_write(fd, payload):
            nonlocal budget
            if budget == 0:
                raise OSError(errno.ENOSPC, "injected full filesystem")
            count = real_write(fd, payload[:budget])
            budget -= count
            return count

        with patch.object(self.stream.os, "write", side_effect=bounded_write):
            result = self.run_stream()
        self.assertEqual(result.stop_reason, "enospc")
        self.assertEqual(result.acknowledged_bytes, 27)
        self.assertEqual(result.complete_bytes, 16)
        self.assertEqual(len(result.completed_files), 1)
        self.assertEqual(
            sorted(item.stat().st_size for item in self.directory.iterdir()), [11, 16]
        )
        partial = self.events[-2]
        self.assertEqual(partial["event"], "file-partial")
        self.assertEqual(partial["bytes"], 11)
        self.assertEqual(partial["acknowledged_bytes"], 27)
        self.assertEqual(partial["complete_bytes"], 16)
        self.assertEqual(
            partial["sha256"],
            hashlib.sha256((self.directory / partial["name"]).read_bytes()).hexdigest(),
        )

    def test_enospc_open_stops_without_creating_a_file(self):
        real_open = os.open

        def full_open(path, flags, *args, **kwargs):
            if flags & os.O_CREAT:
                raise OSError(errno.ENOSPC, "injected full directory")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(self.stream.os, "open", side_effect=full_open):
            result = self.run_stream()
        self.assertEqual(result.stop_reason, "enospc")
        self.assertEqual(result.acknowledged_bytes, 0)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_enospc_fsync_leaves_a_partial_file(self):
        with patch.object(
            self.stream.os, "fsync", side_effect=OSError(errno.ENOSPC, "injected sync")
        ):
            result = self.run_stream()
        self.assertEqual(result.stop_reason, "enospc")
        self.assertEqual(result.acknowledged_bytes, 16)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(result.completed_files, ())
        self.assertEqual(self.events[-2]["event"], "file-partial")
        self.assertEqual(len(list(self.directory.iterdir())), 1)

    def test_enospc_close_leaves_a_partial_file(self):
        real_close = os.close

        def full_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise OSError(errno.ENOSPC, "injected delayed close error")

        with patch.object(self.stream.os, "close", side_effect=full_close):
            result = self.run_stream()
        self.assertEqual(result.stop_reason, "enospc")
        self.assertEqual(result.acknowledged_bytes, 16)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(result.completed_files, ())
        self.assertEqual(self.events[-2]["event"], "file-partial")

    def test_write_enospc_then_close_eio_surfaces_close_error_with_both_phases(self):
        real_write = os.write
        real_close = os.close
        write_error = OSError(errno.ENOSPC, "injected full filesystem")
        close_error = OSError(errno.EIO, "injected close I/O failure")

        def fail_after_three(fd, payload):
            if os.fstat(fd).st_size:
                raise write_error
            return real_write(fd, payload[:3])

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise close_error

        with (
            patch.object(self.stream.os, "write", side_effect=fail_after_three),
            patch.object(self.stream.os, "close", side_effect=failed_close),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, close_error)
        self.assertIs(raised.exception.__cause__, write_error)
        partial = self.events[-1]
        self.assertEqual(partial["event"], "file-partial")
        self.assertEqual(partial["stop_reason"], "error")
        self.assertEqual(partial["acknowledged_bytes"], 3)
        self.assertEqual(partial["complete_bytes"], 0)
        self.assertEqual(
            partial["errors"],
            [
                {"phase": "write", "errno": errno.ENOSPC},
                {"phase": "close", "errno": errno.EIO},
            ],
        )
        self.assertEqual(
            [item.stat().st_size for item in self.directory.iterdir()], [3]
        )

    def test_fsync_enospc_then_close_eio_surfaces_close_error_with_both_phases(self):
        real_close = os.close
        sync_error = OSError(errno.ENOSPC, "injected full filesystem at sync")
        close_error = OSError(errno.EIO, "injected close I/O failure")

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise close_error

        with (
            patch.object(self.stream.os, "fsync", side_effect=sync_error),
            patch.object(self.stream.os, "close", side_effect=failed_close),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, close_error)
        self.assertIs(raised.exception.__cause__, sync_error)
        partial = self.events[-1]
        self.assertEqual(partial["event"], "file-partial")
        self.assertEqual(partial["stop_reason"], "error")
        self.assertEqual(partial["acknowledged_bytes"], 16)
        self.assertEqual(partial["complete_bytes"], 0)
        self.assertEqual(
            partial["errors"],
            [
                {"phase": "fsync", "errno": errno.ENOSPC},
                {"phase": "close", "errno": errno.EIO},
            ],
        )
        self.assertEqual(
            [item.stat().st_size for item in self.directory.iterdir()], [16]
        )

    def test_two_enospc_errors_return_enospc_with_both_phases(self):
        real_close = os.close

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise OSError(errno.ENOSPC, "injected full filesystem at close")

        with (
            patch.object(
                self.stream.os,
                "fsync",
                side_effect=OSError(errno.ENOSPC, "injected sync"),
            ),
            patch.object(self.stream.os, "close", side_effect=failed_close),
        ):
            result = self.run_stream()
        self.assertEqual(result.stop_reason, "enospc")
        self.assertEqual(result.acknowledged_bytes, 16)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(result.completed_files, ())
        partial = self.events[-2]
        self.assertEqual(partial["event"], "file-partial")
        self.assertEqual(
            partial.get("errors"),
            [
                {"phase": "fsync", "errno": errno.ENOSPC},
                {"phase": "close", "errno": errno.ENOSPC},
            ],
        )

    def test_original_fatal_write_error_is_preserved_with_secondary_close_evidence(
        self,
    ):
        real_close = os.close
        write_error = OSError(errno.EIO, "injected fatal write")

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise OSError(errno.ENOSPC, "injected close failure")

        with (
            patch.object(self.stream.os, "write", side_effect=write_error),
            patch.object(self.stream.os, "close", side_effect=failed_close),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, write_error)
        partial = self.events[-1]
        self.assertEqual(partial["event"], "file-partial")
        self.assertEqual(partial["acknowledged_bytes"], 0)
        self.assertEqual(partial["complete_bytes"], 0)
        self.assertEqual(
            partial.get("errors"),
            [
                {"phase": "write", "errno": errno.EIO},
                {"phase": "close", "errno": errno.ENOSPC},
            ],
        )

    def test_non_enospc_write_error_surfaces_with_partial_evidence(self):
        real_write = os.write
        failure = OSError(errno.EIO, "injected write I/O error")

        def fail_after_three(fd, payload):
            if os.fstat(fd).st_size:
                raise failure
            return real_write(fd, payload[:3])

        with (
            patch.object(self.stream.os, "write", side_effect=fail_after_three),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.events[-1]["event"], "file-partial")
        self.assertEqual(self.events[-1]["bytes"], 3)
        self.assertEqual(self.events[-1]["complete_bytes"], 0)
        self.assertEqual(
            [item.stat().st_size for item in self.directory.iterdir()], [3]
        )

    def test_non_enospc_fsync_error_is_not_counted_complete(self):
        failure = OSError(errno.EIO, "injected sync I/O error")
        with (
            patch.object(self.stream.os, "fsync", side_effect=failure),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.events[-1]["event"], "file-partial")
        self.assertEqual(self.events[-1]["bytes"], 16)
        self.assertEqual(self.events[-1]["complete_bytes"], 0)

    def test_non_enospc_close_error_is_not_counted_complete(self):
        real_close = os.close
        failure = OSError(errno.EIO, "injected close I/O error")

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise failure

        with (
            patch.object(self.stream.os, "close", side_effect=failed_close),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.events[-1]["event"], "file-partial")
        self.assertEqual(self.events[-1]["bytes"], 16)
        self.assertEqual(self.events[-1]["complete_bytes"], 0)

    def test_zero_write_is_an_io_error_without_retry(self):
        calls = 0

        def zero_write(fd, payload):
            nonlocal calls
            calls += 1
            self.assertEqual(calls, 1, "a zero-byte write must stop immediately")
            return 0

        with (
            patch.object(self.stream.os, "write", side_effect=zero_write),
            self.assertRaises(OSError) as raised,
        ):
            self.run_stream()
        self.assertEqual(raised.exception.errno, errno.EIO)
        self.assertEqual(self.events[-1]["event"], "file-partial")
        self.assertEqual(self.events[-1]["bytes"], 0)

    def test_cancellation_before_start_creates_no_file(self):
        result = self.run_stream(stop_requested=lambda: True)
        self.assertEqual(result.stop_reason, "cancelled")
        self.assertEqual(result.acknowledged_bytes, 0)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(list(self.directory.iterdir()), [])
        self.assertEqual(
            [event["event"] for event in self.events], ["capacity-start", "stopped"]
        )

    def test_cancellation_mid_file_preserves_partial_without_completion(self):
        cancelled = False

        def record(event):
            nonlocal cancelled
            self.events.append(event)
            if event["event"] == "progress":
                cancelled = True

        result = self.run_stream(record=record, stop_requested=lambda: cancelled)
        self.assertEqual(result.stop_reason, "cancelled")
        self.assertEqual(result.acknowledged_bytes, 8)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(result.completed_files, ())
        self.assertEqual(
            [item.stat().st_size for item in self.directory.iterdir()], [8]
        )
        self.assertEqual(self.events[-2]["event"], "file-partial")

    def test_cancellation_after_last_chunk_does_not_complete_interrupted_file(self):
        result = self.run_stream(
            policy=self.policy(payload_ceiling_bytes=8, file_bytes=8),
            stop_requested=lambda: any(
                event["event"] == "progress" for event in self.events
            ),
        )
        self.assertEqual(result.stop_reason, "cancelled")
        self.assertEqual(result.acknowledged_bytes, 8)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(result.completed_files, ())

    def test_cancellation_during_short_write_stops_before_next_write(self):
        real_write = os.write
        cancelled = False

        def cancelling_write(fd, payload):
            nonlocal cancelled
            count = real_write(fd, payload[:3])
            cancelled = True
            return count

        with patch.object(self.stream.os, "write", side_effect=cancelling_write):
            result = self.run_stream(stop_requested=lambda: cancelled)
        self.assertEqual(result.stop_reason, "cancelled")
        self.assertEqual(result.acknowledged_bytes, 3)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(
            [item.stat().st_size for item in self.directory.iterdir()], [3]
        )

    def test_record_failure_at_each_event_stops_payload_writes(self):
        for failed_event, expected_sizes in (
            ("capacity-start", []),
            ("file-start", []),
            ("progress", [8]),
            ("file-complete", [16]),
            ("stopped", [3, 16, 16]),
        ):
            with (
                self.subTest(event=failed_event),
                tempfile.TemporaryDirectory() as directory,
            ):
                failure = OSError(errno.ENOSPC, "injected off-tape ledger failure")
                records = []

                def record(
                    event, failed_event=failed_event, failure=failure, records=records
                ):
                    if event["event"] == failed_event:
                        raise failure
                    records.append(event)

                with self.assertRaises(OSError) as raised:
                    self.stream.run_capacity_stream(
                        Path(directory),
                        self.policy(),
                        record=record,
                        stop_requested=lambda: False,
                    )
                self.assertIs(raised.exception, failure)
                self.assertEqual(
                    sorted(item.stat().st_size for item in Path(directory).iterdir()),
                    expected_sizes,
                )
                self.assertFalse(
                    any(event["event"] == "file-partial" for event in records)
                )

    def test_close_failure_does_not_mask_callback_error(self):
        real_close = os.close
        failure = RuntimeError("injected ledger error")

        def record(event):
            self.events.append(event)
            if event["event"] == "progress":
                raise failure

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise OSError(errno.EIO, "injected close error")

        with (
            patch.object(self.stream.os, "close", side_effect=failed_close),
            self.assertRaises(RuntimeError) as raised,
        ):
            self.run_stream(record=record)
        self.assertIs(raised.exception, failure)
        self.assertEqual(
            [item.stat().st_size for item in self.directory.iterdir()], [8]
        )

    def test_close_error_is_not_swallowed_by_a_callers_unrelated_except_block(self):
        real_close = os.close
        failure = OSError(errno.EIO, "injected close error")

        def failed_close(fd):
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                raise failure

        with patch.object(self.stream.os, "close", side_effect=failed_close):
            try:
                raise RuntimeError("unrelated previously handled exception")
            except RuntimeError:
                with self.assertRaises(OSError) as raised:
                    self.run_stream()
        self.assertIs(raised.exception, failure)
        self.assertEqual(self.events[-1]["event"], "file-partial")
        self.assertEqual(self.events[-1]["complete_bytes"], 0)

    def test_cancellation_during_close_keeps_the_interrupted_file_partial(self):
        real_close = os.close
        cancelled = False

        def cancelling_close(fd):
            nonlocal cancelled
            is_file = stat.S_ISREG(os.fstat(fd).st_mode)
            real_close(fd)
            if is_file:
                cancelled = True

        with patch.object(self.stream.os, "close", side_effect=cancelling_close):
            result = self.run_stream(stop_requested=lambda: cancelled)
        self.assertEqual(result.stop_reason, "cancelled")
        self.assertEqual(result.acknowledged_bytes, 16)
        self.assertEqual(result.complete_bytes, 0)
        self.assertEqual(result.completed_files, ())

    def test_unvalidated_policy_substitutions_create_no_payload(self):
        class UnvalidatedPolicy(self.stream.CapacityStreamPolicy):
            def __post_init__(self):
                pass

        values = {
            "seed": bytes(32),
            "payload_ceiling_bytes": 35,
            "file_bytes": 16,
            "chunk_bytes": 8,
        }
        for policy in (None, SimpleNamespace(**values), UnvalidatedPolicy(**values)):
            with self.subTest(policy=type(policy)), self.assertRaises(ValueError):
                self.run_stream(policy=policy)
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(self.events, [])

    def test_noncallable_callbacks_are_rejected_before_start_intent(self):
        for key in ("record", "stop_requested"):
            with self.subTest(callback=key), self.assertRaises(TypeError):
                self.run_stream(**{key: None})
            self.assertEqual(list(self.directory.iterdir()), [])
            self.assertEqual(self.events, [])

    def test_digest_initialization_failure_leaks_no_descriptor_or_payload_file(self):
        failure = RuntimeError("injected digest initialization failure")
        with (
            patch.object(self.stream.hashlib, "sha256", side_effect=failure),
            self.assertRaises(RuntimeError) as raised,
        ):
            self.run_stream()
        self.assertIs(raised.exception, failure)
        self.assertEqual(list(self.directory.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
