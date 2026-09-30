from __future__ import annotations

import os
import json
import unittest
from unittest.mock import patch

from ltobackup.broker.service import drain_ltfs_event_stream
from ltobackup.operational_log import (
    OperationalCorrelation,
    OperationalEvent,
    OperationalSeverity,
    OperationalSource,
    emit_operational_phase,
)


class RecordingSink:
    def __init__(self) -> None:
        self.events: list[OperationalEvent] = []

    def emit(self, event: OperationalEvent) -> None:
        self.events.append(event)


class OperationalPhaseTests(unittest.TestCase):
    def test_phase_context_is_closed_and_correlated(self) -> None:
        context = OperationalCorrelation(
            operation_id="operation-1",
            job_id="JOB-1",
            cassette_label="TAPE01",
            cassette_sequence=1,
        )
        sink = RecordingSink()

        emit_operational_phase(sink, context, "mount", "started", read_only=True)
        emit_operational_phase(sink, context, "mount", "succeeded", read_only=True)

        self.assertEqual(
            ["ltfs.phase.started", "ltfs.phase.succeeded"],
            [event.code for event in sink.events],
        )
        self.assertTrue(all(event.operation_id == "operation-1" for event in sink.events))
        self.assertTrue(all(event.phase == "mount_read_only" for event in sink.events))

    def test_phase_sink_baseexception_is_best_effort(self) -> None:
        class Sink:
            def emit(self, _event: OperationalEvent) -> None:
                raise SystemExit(12)

        emit_operational_phase(
            Sink(), OperationalCorrelation(operation_id="operation-1"), "eject", "succeeded"
        )

    def test_phase_helper_redacts_and_bounds_injected_messages(self) -> None:
        sink = RecordingSink()
        emit_operational_phase(
            sink,
            OperationalCorrelation(operation_id="operation-1"),
            "mount",
            "failed",
            message="password=hunter2 " + "x" * 5000,
        )

        self.assertEqual(1, len(sink.events))
        self.assertNotIn("hunter2", sink.events[0].message)
        self.assertLessEqual(len(sink.events[0].message.encode("utf-8")), 4096)
        self.assertTrue(sink.events[0].truncated)

    def test_unknown_phase_and_result_are_rejected_before_sink(self) -> None:
        sink = RecordingSink()
        context = OperationalCorrelation(operation_id="operation-1")
        with self.assertRaises(ValueError):
            emit_operational_phase(sink, context, "erase", "started")
        with self.assertRaises(ValueError):
            emit_operational_phase(sink, context, "mount", "maybe")
        self.assertEqual([], sink.events)


class LtfsBrokerStreamTests(unittest.TestCase):
    stream_operation_id = "a081a350-376c-5f9a-a0a3-7d490a25a053"

    def _driver_event(self) -> dict[str, object]:
        # Complete r16 ltfs_event_emit schema; synthetic values, no device I/O.
        return {
            "schema": 1, "operation_id": self.stream_operation_id,
            "volume_uuid": None, "prior_generation": None, "new_generation": None,
            "seq": 1, "monotonic_ns": 42, "wall_time": "2026-09-04T21:12:53.219Z",
            "phase": "FAILED", "status": "failed", "result": -21700,
            "device_close_result": None, "bytes_done": 0, "bytes_total": None,
            "files_done": 0, "files_total": None, "rate_bytes_per_second": 0,
            "queue_fill_bytes": 0, "buffer_underrun_count": 0, "retry_count": 0,
            "memory_high_water_bytes": 0, "telemetry_overflowed": False,
            "phase_elapsed_ns": 0, "index_done": None, "index_total": None,
            "eta_seconds": None, "device_serial": "private-device-serial",
            "message_code": "process.failed",
        }

    def test_broker_accepts_complete_driver_schema_with_trusted_correlation(self) -> None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, json.dumps(self._driver_event()).encode() + b"\n")
        os.close(write_fd)
        sink = RecordingSink()
        drain_ltfs_event_stream(
            read_fd, sink=sink,
            correlation=OperationalCorrelation(operation_id="operation-1", job_id="JOB-1"),
            expected_stream_operation_id=self.stream_operation_id,
        )
        self.assertEqual(1, len(sink.events))
        event = sink.events[0]
        self.assertEqual(OperationalSource.LTFS, event.source)
        self.assertEqual(OperationalSeverity.ERROR, event.severity)
        self.assertEqual("operation-1", event.operation_id)
        self.assertEqual("JOB-1", event.job_id)
        self.assertEqual(-21700, event.exit_code)
        self.assertEqual("LTFS driver failed: failed (result -21700).", event.message)
        self.assertNotIn("private-device-serial", repr(event))

    def test_broker_rejects_malformed_complete_driver_schema(self) -> None:
        for changes in (
            {"seq": True}, {"seq": 0}, {"bytes_done": -1},
            {"bytes_total": 2**64}, {"result": 2**31},
            {"device_close_result": True}, {"phase": "ERASE"},
            {"status": "unknown"}, {"telemetry_overflowed": "false"},
            {"memory_high_water_bytes": 536870913},
            {"wall_time": "invalid"}, {"message_code": "password=secret"},
            {"operation_id": "wrong-operation"}, {"unknown_field": "extra"},
        ):
            with self.subTest(changes=changes):
                read_fd, write_fd = os.pipe()
                os.write(write_fd, json.dumps({**self._driver_event(), **changes}).encode() + b"\n")
                os.close(write_fd)
                sink = RecordingSink()
                drain_ltfs_event_stream(
                    read_fd, sink=sink,
                    correlation=OperationalCorrelation(operation_id="operation-1"),
                    expected_stream_operation_id=self.stream_operation_id,
                )
                self.assertEqual([], sink.events)

    def test_complete_driver_schema_preserves_known_identity_diagnostic(self) -> None:
        read_fd, write_fd = os.pipe()
        event = {**self._driver_event(), "message_code": "device.identity.mismatch"}
        os.write(write_fd, json.dumps(event).encode() + b"\n")
        os.close(write_fd)
        sink = RecordingSink()
        drain_ltfs_event_stream(
            read_fd, sink=sink,
            correlation=OperationalCorrelation(operation_id="operation-1"),
            expected_stream_operation_id=self.stream_operation_id,
        )
        self.assertEqual(["device.identity.mismatch"], [event.code for event in sink.events])
        self.assertEqual("LTFS device identity mismatch.", sink.events[0].message)

    def test_driver_failure_cannot_be_downgraded_by_a_message_mapping(self) -> None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, json.dumps(self._driver_event()).encode() + b"\n")
        os.close(write_fd)
        sink = RecordingSink()
        with patch.dict("ltobackup.broker.service._LTFS_EVENT_MAP", {
            "process.failed": (OperationalSeverity.INFO, "Mapped lifecycle event.", "mount")
        }):
            drain_ltfs_event_stream(
                read_fd, sink=sink,
                correlation=OperationalCorrelation(operation_id="operation-1"),
                expected_stream_operation_id=self.stream_operation_id,
            )
        self.assertEqual(OperationalSeverity.ERROR, sink.events[0].severity)

    def _identity_mismatch(self) -> bytes:
        return (
            b'{"schema":1,"operation_id":"'
            + self.stream_operation_id.encode("ascii")
            + b'","code":"device.identity.mismatch",'
            b'"detail":"private drive serial"}\n'
        )

    def test_broker_stream_coalesces_consecutive_duplicate_progress(self) -> None:
        read_fd, write_fd = os.pipe()
        sink = RecordingSink()
        line = self._identity_mismatch()
        os.write(write_fd, line + line)
        os.close(write_fd)

        drain_ltfs_event_stream(
            read_fd,
            sink=sink,
            correlation=OperationalCorrelation(operation_id="operation-1"),
            expected_stream_operation_id=self.stream_operation_id,
        )

        self.assertEqual(1, len(sink.events))
        self.assertEqual(2, sink.events[0].repeat_count)

    def test_broker_stream_parses_closed_json_and_never_emits_raw_stdio(self) -> None:
        read_fd, write_fd = os.pipe()
        sink = RecordingSink()
        os.write(
            write_fd,
            self._identity_mismatch()
            + b'not-json with token=swordfish\n'
            + self._identity_mismatch().replace(
                self.stream_operation_id.encode("ascii"),
                b"00000000-0000-4000-8000-000000000001",
            )
            + self._identity_mismatch().replace(
                b"device.identity.mismatch", b"private.secret.event.code"
            ),
        )
        os.close(write_fd)

        drain_ltfs_event_stream(
            read_fd,
            sink=sink,
            correlation=OperationalCorrelation(operation_id="operation-1"),
            expected_stream_operation_id=self.stream_operation_id,
        )

        self.assertEqual(["device.identity.mismatch"], [e.code for e in sink.events])
        self.assertNotIn("private drive serial", repr(sink.events))
        self.assertNotIn("swordfish", repr(sink.events))
        self.assertTrue(all(e.source is OperationalSource.LTFS for e in sink.events))

    def test_broker_stream_rejects_boolean_schema_and_missing_detail(self) -> None:
        read_fd, write_fd = os.pipe()
        prefix = (
            b'{"schema":true,"operation_id":"'
            + self.stream_operation_id.encode("ascii")
            + b'","code":"device.identity.mismatch"'
        )
        os.write(write_fd, prefix + b',"detail":"private"}\n')
        os.write(write_fd, prefix.replace(b"true", b"1") + b"}\n")
        os.close(write_fd)
        sink = RecordingSink()

        drain_ltfs_event_stream(
            read_fd,
            sink=sink,
            correlation=OperationalCorrelation(operation_id="operation-1"),
            expected_stream_operation_id=self.stream_operation_id,
        )

        self.assertEqual([], sink.events)

    def test_broker_stream_emitter_failure_does_not_stop_drain(self) -> None:
        class Sink:
            def __init__(self) -> None:
                self.calls = 0

            def emit(self, _event: OperationalEvent) -> None:
                self.calls += 1
                raise KeyboardInterrupt

        read_fd, write_fd = os.pipe()
        os.write(
            write_fd,
            self._identity_mismatch()
            + b"not-json\n"
            + self._identity_mismatch(),
        )
        os.close(write_fd)
        sink = Sink()

        drain_ltfs_event_stream(
            read_fd,
            sink=sink,
            correlation=OperationalCorrelation(operation_id="operation-1"),
            expected_stream_operation_id=self.stream_operation_id,
        )

        self.assertEqual(2, sink.calls)

    def test_broker_stream_parser_baseexception_does_not_stop_drain(self) -> None:
        read_fd, write_fd = os.pipe()
        os.write(write_fd, b"first\nsecond\n")
        os.close(write_fd)
        sink = RecordingSink()
        recovered = OperationalEvent(
            OperationalSource.LTFS,
            OperationalSeverity.ERROR,
            "device.identity.mismatch",
            "LTFS device identity mismatch.",
            operation_id="operation-1",
            phase="mount",
        )

        with patch(
            "ltobackup.broker.service._parse_ltfs_event",
            side_effect=(KeyboardInterrupt, recovered),
        ):
            drain_ltfs_event_stream(
                read_fd,
                sink=sink,
                correlation=OperationalCorrelation(operation_id="operation-1"),
                expected_stream_operation_id=self.stream_operation_id,
            )

        self.assertEqual([recovered], sink.events)

    def test_broker_stream_discards_oversized_record_until_its_newline(self) -> None:
        sink = RecordingSink()
        valid = self._identity_mismatch()

        with (
            patch(
                "ltobackup.broker.service.os.read",
                side_effect=(b"x" * 4097, valid + valid, b""),
            ),
            patch("ltobackup.broker.service.os.close"),
        ):
            drain_ltfs_event_stream(
                99,
                sink=sink,
                correlation=OperationalCorrelation(operation_id="operation-1"),
                expected_stream_operation_id=self.stream_operation_id,
            )

        self.assertEqual(1, len(sink.events))
        self.assertEqual(1, sink.events[0].repeat_count)


if __name__ == "__main__":
    unittest.main()
