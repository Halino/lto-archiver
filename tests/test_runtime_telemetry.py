from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread

from ltobackup.daemon.telemetry import TelemetryAccumulator, TelemetryPhase

MIB = 1024 * 1024


class FakeClock:
    def __init__(self) -> None:
        self.monotonic_value = 100.0
        self.utc_value = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
        self.monotonic_calls = 0

    def monotonic(self) -> float:
        self.monotonic_calls += 1
        return self.monotonic_value

    def utc_now(self) -> datetime:
        return self.utc_value

    def advance(self, seconds: float) -> None:
        self.monotonic_value += seconds
        self.utc_value += timedelta(seconds=seconds)


class TelemetryAccumulatorTests(unittest.TestCase):
    def test_stalled_current_rate_expires_with_one_gap_and_recovers(self) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic, utc_now=clock.utc_now,
        )
        clock.advance(1)
        accumulator.record_progress(100 * MIB)
        clock.advance(5)
        self.assertEqual(100 * MIB, accumulator.snapshot().current_bytes_per_second)
        clock.advance(55)
        stalled = accumulator.snapshot()
        self.assertIsNone(stalled.current_bytes_per_second)
        self.assertAlmostEqual(100 * MIB / 61, stalled.effective_bytes_per_second)
        self.assertEqual(60, stalled.to_api_telemetry()["current_sample_age_seconds"])
        self.assertTrue(stalled.to_api_telemetry()["current_sample_stale"])
        self.assertEqual((100 * MIB, None), tuple(s.bytes_per_second for s in stalled.samples))
        self.assertEqual(stalled.samples, accumulator.record_progress(0).samples)
        clock.advance(1)
        recovered = accumulator.record_progress(MIB)
        self.assertIsNotNone(recovered.current_bytes_per_second)
        self.assertFalse(recovered.to_api_telemetry()["current_sample_stale"])
        self.assertEqual(0, recovered.to_api_telemetry()["current_sample_age_seconds"])

    def test_operation_window_reports_intra_file_bytes_before_completion(self) -> None:
        """Removing byte-progress ingestion must make live first-file telemetry fail."""
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        clock.advance(10)
        accumulator.record_file(8 * MIB)
        accumulator.add_duration("close", 7.0)
        clock.advance(90)
        rebased = accumulator.begin_window()

        self.assertEqual(1, rebased.files_completed)
        self.assertEqual(8 * MIB, rebased.bytes_completed)
        self.assertIsNone(rebased.current_bytes_per_second)
        self.assertIsNone(rebased.effective_bytes_per_second)
        self.assertEqual((), rebased.samples)
        self.assertEqual(0.0, rebased.durations.close_seconds)
        self.assertIsNone(rebased.current_phase)

        clock.advance(1)
        accumulator.record_progress(2 * MIB)

        snapshot = accumulator.snapshot()
        self.assertEqual(1, snapshot.files_completed)
        self.assertEqual(10 * MIB, snapshot.bytes_completed)
        self.assertEqual(2 * MIB, snapshot.current_bytes_per_second)
        self.assertEqual(2 * MIB, snapshot.effective_bytes_per_second)
        self.assertEqual(1, len(snapshot.samples))

    def test_completing_a_progressed_file_does_not_count_its_bytes_twice(self) -> None:
        """Changing completion to add the full file size must fail this contract."""
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        accumulator.begin_window()
        clock.advance(1)
        accumulator.record_progress(3 * MIB)
        clock.advance(1)

        accumulator.complete_file()

        snapshot = accumulator.snapshot()
        self.assertEqual(1, snapshot.files_completed)
        self.assertEqual(3 * MIB, snapshot.bytes_completed)
        self.assertEqual(3 * MIB / 2, snapshot.effective_bytes_per_second)

    def test_intra_file_samples_are_bounded_and_forced_at_file_completion(self) -> None:
        """Removing throttling must flood SSE when the copy buffer is small."""
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        accumulator.begin_window()

        for _ in range(9):
            clock.advance(0.1)
            accumulator.record_progress(MIB)

        partial = accumulator.snapshot()
        self.assertEqual(9 * MIB, partial.bytes_completed)
        self.assertEqual((), partial.samples)

        clock.advance(0.2)
        accumulator.record_progress(MIB)
        self.assertEqual(1, len(accumulator.snapshot().samples))

        clock.advance(0.1)
        accumulator.record_progress(MIB)
        completed = accumulator.complete_file()
        self.assertEqual(2, len(completed.samples))
        self.assertEqual(1, completed.files_completed)
        self.assertEqual(11 * MIB, completed.bytes_completed)

    def test_new_operation_window_discards_uncommitted_failed_file_bytes(self) -> None:
        """Retrying a failed partial file must not double-count its discarded bytes."""
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        accumulator.begin_window()
        clock.advance(1)
        accumulator.record_progress(4 * MIB)

        clock.advance(1)
        accumulator.begin_window()
        clock.advance(1)
        accumulator.record_progress(10 * MIB)
        accumulator.complete_file()

        snapshot = accumulator.snapshot()
        self.assertEqual(1, snapshot.files_completed)
        self.assertEqual(10 * MIB, snapshot.bytes_completed)

    def test_per_file_throttling_keeps_byte_units_and_api_mib_units_coherent(
        self,
    ) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
            sample_every_files=2,
        )

        clock.advance(1)
        accumulator.record_file(MIB)
        clock.advance(1)
        accumulator.record_file(3 * MIB)

        snapshot = accumulator.snapshot()
        self.assertEqual(2, snapshot.files_completed)
        self.assertEqual(4 * MIB, snapshot.bytes_completed)
        self.assertEqual(2 * MIB, snapshot.current_bytes_per_second)
        self.assertEqual(2 * MIB, snapshot.effective_bytes_per_second)
        self.assertEqual(1, len(snapshot.samples))
        self.assertEqual(2 * MIB, snapshot.samples[0].bytes_per_second)
        self.assertEqual(
            {
                "current_mib_per_second": 2.0,
                "effective_mib_per_second": 2.0,
                "current_sample_age_seconds": 0.0,
                "current_sample_stale": False,
                "samples": (
                    {
                        "event_id": 1,
                        "occurred_at": "2026-08-22T10:00:02Z",
                        "mib_per_second": 2.0,
                    },
                ),
                "durations": {
                    "copy_seconds": 0.0,
                    "close_seconds": 0.0,
                    "finalization_seconds": 0.0,
                    "unmount_seconds": 0.0,
                    "unload_seconds": 0.0,
                },
            },
            snapshot.to_api_telemetry(),
        )

    def test_unavailable_observation_is_an_explicit_gap_and_rebases_rate(self) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
            sample_every_files=1,
            max_samples=3,
        )
        clock.advance(1)
        accumulator.record_file(MIB)
        clock.advance(1)
        accumulator.mark_unavailable()
        clock.advance(2)
        accumulator.record_file(4 * MIB)
        clock.advance(1)
        accumulator.mark_unavailable()

        samples = accumulator.snapshot().samples
        self.assertEqual((2, 3, 4), tuple(sample.event_id for sample in samples))
        self.assertEqual(
            (None, 2 * MIB, None),
            tuple(sample.bytes_per_second for sample in samples),
        )

    def test_finalization_unmount_and_unload_durations_are_monotonic(self) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )

        for phase, seconds in (
            ("finalization", 7.5),
            ("unmount", 2.0),
            ("unload", 1.25),
        ):
            accumulator.start_phase(phase)
            clock.advance(seconds)
            accumulator.finish_phase(phase)

        durations = accumulator.snapshot().durations
        self.assertEqual(7.5, durations.finalization_seconds)
        self.assertEqual(2.0, durations.unmount_seconds)
        self.assertEqual(1.25, durations.unload_seconds)

    def test_close_forces_pending_sample_and_returns_a_stable_closed_snapshot(
        self,
    ) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
            sample_every_files=10,
        )
        accumulator.start_phase("finalization")
        clock.advance(2)
        accumulator.record_file(2 * MIB)

        closed = accumulator.close()
        clock.advance(50)

        self.assertTrue(closed.closed)
        self.assertEqual(1 * MIB, closed.current_bytes_per_second)
        self.assertEqual(2.0, closed.durations.finalization_seconds)
        self.assertEqual(closed, accumulator.snapshot())
        with self.assertRaisesRegex(RuntimeError, "closed"):
            accumulator.record_file(1)

    def test_concurrent_file_and_duration_updates_do_not_lose_counts(self) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
            sample_every_files=10_000,
        )
        barrier = Barrier(9)

        def update() -> None:
            barrier.wait()
            for _ in range(500):
                accumulator.record_file(7)
                accumulator.add_duration("close", 0.001)

        threads = [Thread(target=update) for _ in range(8)]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join()

        snapshot = accumulator.snapshot()
        self.assertEqual(4_000, snapshot.files_completed)
        self.assertEqual(28_000, snapshot.bytes_completed)
        self.assertAlmostEqual(4.0, snapshot.durations.close_seconds, places=9)

    def test_backward_monotonic_clock_rejects_update_without_partial_counts(
        self,
    ) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        clock.monotonic_value -= 1

        with self.assertRaisesRegex(ValueError, "backwards"):
            accumulator.record_file(99)

        clock.monotonic_value += 1
        snapshot = accumulator.snapshot()
        self.assertEqual(0, snapshot.files_completed)
        self.assertEqual(0, snapshot.bytes_completed)

    def test_close_after_gap_does_not_invent_a_zero_rate_sample(self) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
            sample_every_files=10,
        )
        clock.advance(1)
        accumulator.record_file(MIB)
        clock.advance(1)
        accumulator.mark_unavailable()
        clock.advance(1)

        closed = accumulator.close()

        self.assertEqual(1, len(closed.samples))
        self.assertIsNone(closed.samples[0].bytes_per_second)

    def test_gap_restarts_sampling_window_for_exactly_n_following_files(self) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
            sample_every_files=3,
        )
        clock.advance(1)
        accumulator.record_file(MIB)
        clock.advance(1)
        accumulator.mark_unavailable()

        for _ in range(2):
            clock.advance(1)
            accumulator.record_file(MIB)
        self.assertEqual(1, len(accumulator.snapshot().samples))

        clock.advance(1)
        accumulator.record_file(MIB)
        samples = accumulator.snapshot().samples
        self.assertEqual((None, MIB), tuple(item.bytes_per_second for item in samples))

    def test_live_snapshot_uses_one_now_for_effective_rate_and_active_phase(
        self,
    ) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        clock.advance(1)
        accumulator.record_file(MIB)
        accumulator.start_phase(TelemetryPhase.FINALIZATION)
        clock.advance(4)
        calls_before = clock.monotonic_calls

        snapshot = accumulator.snapshot()

        self.assertEqual(calls_before + 1, clock.monotonic_calls)
        self.assertEqual(MIB / 5, snapshot.effective_bytes_per_second)
        self.assertEqual(4.0, snapshot.durations.finalization_seconds)

    def test_all_runtime_phases_are_closed_and_diagnostic_summary_is_complete(
        self,
    ) -> None:
        clock = FakeClock()
        accumulator = TelemetryAccumulator(
            monotonic=clock.monotonic,
            utc_now=clock.utc_now,
        )
        expected = {
            "source_open_seconds",
            "smb_read_seconds",
            "ltfs_write_admission_seconds",
            "copy_seconds",
            "close_seconds",
            "manifest_seconds",
            "snapshot_seconds",
            "finalization_seconds",
            "unmount_seconds",
            "unload_seconds",
            "retry_seconds",
            "operator_wait_seconds",
        }
        for phase in TelemetryPhase:
            accumulator.add_duration(phase, 1)

        durations = accumulator.snapshot().durations

        self.assertEqual(expected, set(durations.to_diagnostic_payload()))
        self.assertEqual(
            {
                "copy_seconds",
                "close_seconds",
                "finalization_seconds",
                "unmount_seconds",
                "unload_seconds",
            },
            set(durations.to_api_payload()),
        )
        with self.assertRaisesRegex(ValueError, "unknown"):
            accumulator.add_duration("serial-SERIAL123", 1)


if __name__ == "__main__":
    unittest.main()
