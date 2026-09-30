from __future__ import annotations

import json
import unittest

from ltobackup.log_reader import (
    JournalEntry,
    JournalPage,
    JournalQuery,
    LogDirection,
    LogRange,
    LogSource,
    ProtocolError,
    Severity,
    canonical_json,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)


class JournalReaderProtocolTests(unittest.TestCase):
    def test_request_rejects_arbitrary_unit_path_and_unknown_fields(self) -> None:
        for payload in (
            {
                "version": 1,
                "source": "host",
                "range": "1h",
                "direction": "older",
                "limit": 50,
            },
            {
                "version": 1,
                "source": "daemon",
                "range": "1h",
                "direction": "older",
                "limit": 50,
                "unit": "sshd.service",
            },
            {
                "version": 1,
                "source": "daemon",
                "range": "/tmp/x",
                "direction": "older",
                "limit": 50,
            },
        ):
            with self.subTest(payload=payload), self.assertRaises(ProtocolError):
                decode_request(canonical_json(payload))

    def test_request_round_trip_is_canonical_and_closed(self) -> None:
        query = JournalQuery(
            source=LogSource.DAEMON,
            minimum_severity=Severity.INFO,
            range=LogRange.ONE_HOUR,
            direction=LogDirection.OLDER,
            cursor=None,
            limit=50,
        )
        packet = encode_request(query)
        self.assertEqual(query, decode_request(packet))
        self.assertEqual(packet, canonical_json(json.loads(packet[4:])))

    def test_request_rejects_boolean_limits_and_non_ascii_or_long_cursors(self) -> None:
        base = {
            "version": 1,
            "source": "daemon",
            "minimum_severity": "info",
            "range": "1h",
            "direction": "older",
            "cursor": None,
            "limit": 50,
        }
        for replacement in (
            {"limit": True},
            {"cursor": "é"},
            {"cursor": "x" * 2049},
            {"limit": 201},
        ):
            with (
                self.subTest(replacement=replacement),
                self.assertRaises(ProtocolError),
            ):
                decode_request(canonical_json({**base, **replacement}))

    def test_response_round_trip_rejects_extra_data_and_oversized_frame(self) -> None:
        page = JournalPage(
            entries=(
                JournalEntry(
                    cursor="cursor-1",
                    timestamp="2026-09-04T10:11:12.123456Z",
                    source=LogSource.DAEMON,
                    severity=Severity.INFO,
                    unit="lto-archiverd.service",
                    message="safe",
                ),
            ),
            older_cursor="cursor-1",
            newer_cursor=None,
            cursor_rotated=False,
        )
        self.assertEqual(page, decode_response(encode_response(page)))
        payload = {
            "version": 1,
            "entries": [],
            "older_cursor": None,
            "newer_cursor": None,
            "cursor_rotated": False,
            "extra": "no",
        }
        with self.assertRaises(ProtocolError):
            decode_response(canonical_json(payload))
        with self.assertRaises(ProtocolError):
            decode_request((262_145).to_bytes(4, "big") + b"x")

    def test_response_rejects_invalid_unicode_as_a_closed_protocol_error(self) -> None:
        entry = {
            "cursor": "cursor-1",
            "timestamp": "2026-09-04T10:11:12Z",
            "source": "daemon",
            "severity": "info",
            "unit": "lto-archiverd.service",
            "message": "\ud800",
            "operation_id": None,
            "job_id": None,
            "cassette_label": None,
            "cassette_sequence": None,
            "command_kind": None,
            "phase": None,
            "exit_code": None,
            "elapsed_ms": None,
            "repeat_count": 1,
            "truncated": False,
            "pid": None,
            "boot_id": None,
        }
        with self.assertRaises(ProtocolError):
            decode_response(
                canonical_json(
                    {
                        "version": 1,
                        "entries": [entry],
                        "older_cursor": None,
                        "newer_cursor": None,
                        "cursor_rotated": False,
                    }
                )
            )

    def test_repeat_count_matches_task_one_bound_and_numeric_fields_are_bounded(
        self,
    ) -> None:
        entry = JournalEntry(
            cursor="cursor-1",
            timestamp="2026-09-04T10:11:12Z",
            source=LogSource.DAEMON,
            severity=Severity.INFO,
            unit="lto-archiverd.service",
            message="safe",
            cassette_sequence=2**31 - 1,
            exit_code=-(2**31),
            elapsed_ms=2**63 - 1,
            repeat_count=2**31 - 1,
            pid=2**31 - 1,
        )
        self.assertEqual(
            2**31 - 1,
            decode_response(encode_response(JournalPage((entry,), None, None, False)))
            .entries[0]
            .repeat_count,
        )
        with self.assertRaises(ProtocolError):
            JournalEntry(
                "cursor-2",
                "2026-09-04T10:11:12Z",
                LogSource.DAEMON,
                Severity.INFO,
                "unit",
                "safe",
                repeat_count=2**31,
            )

    def test_page_unavailable_sources_are_concrete_unique_and_canonical(self) -> None:
        page = JournalPage(
            (),
            None,
            None,
            False,
            unavailable_sources=(LogSource.COMMAND_BROKER, LogSource.DAEMON),
        )
        self.assertEqual(
            (LogSource.COMMAND_BROKER, LogSource.DAEMON),
            decode_response(encode_response(page)).unavailable_sources,
        )
        self.assertEqual((), JournalPage((), None, None, False).unavailable_sources)
        with self.assertRaises(ProtocolError):
            JournalPage(
                (),
                None,
                None,
                False,
                unavailable_sources=(LogSource.DAEMON, LogSource.COMMAND_BROKER),
            )
        with self.assertRaises(ProtocolError):
            JournalPage((), None, None, False, unavailable_sources=(LogSource.ALL,))


if __name__ == "__main__":
    unittest.main()
