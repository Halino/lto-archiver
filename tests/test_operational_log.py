from __future__ import annotations

import unittest

from ltobackup.operational_log import (
    JournalOperationalEventSink,
    OperationalEvent,
    OperationalSeverity,
    OperationalSource,
    closed_operational_correlation,
    coalesce_operational_lines,
    redact_operational_message,
)


class OperationalLogTests(unittest.TestCase):
    def test_closed_correlation_drops_unsafe_optional_metadata(self) -> None:
        correlation = closed_operational_correlation(
            operation_id="operation-1",
            job_id="job with spaces",
            cassette_label=r"CURRENT/LABEL\EXACT",
            cassette_sequence=0,
            command_id="bad command",
            daemon_generation=True,
        )

        self.assertEqual("operation-1", correlation.operation_id)
        self.assertIsNone(correlation.job_id)
        self.assertIsNone(correlation.cassette_label)
        self.assertIsNone(correlation.cassette_sequence)
        self.assertIsNone(correlation.command_id)
        self.assertIsNone(correlation.daemon_generation)

    def test_operational_message_redacts_secrets_controls_and_size(self) -> None:
        """Removing any redaction pass must expose operational credentials."""
        text, truncated = redact_operational_message(
            "Authorization: Bearer swordfish\npassword=hunter2\x00" + "x" * 5000
        )

        self.assertNotIn("swordfish", text)
        self.assertNotIn("hunter2", text)
        self.assertNotIn("\x00", text)
        self.assertLessEqual(len(text.encode("utf-8")), 4096)
        self.assertTrue(truncated)

    def test_operational_event_rejects_unknown_source_and_raw_fields(self) -> None:
        """Weakening the closed event model must reject untrusted source values."""
        with self.assertRaises((TypeError, ValueError)):
            OperationalEvent(source="host", severity="info", code="x", message="x")

    def test_journal_sink_sends_only_allowlisted_structured_fields(self) -> None:
        """Adding arbitrary event fields must not expand journald's payload."""
        sent: list[bytes] = []
        sink = JournalOperationalEventSink(send=sent.append)
        sink.emit(
            OperationalEvent(
                source=OperationalSource.LTFS,
                severity=OperationalSeverity.ERROR,
                code="ltfs.command.failed",
                message="mount failed",
                operation_id="operation-1",
                job_id="job-1",
                cassette_label="ABC123",
                cassette_sequence=2,
                command_id="command-123",
                daemon_generation=7,
                command_kind="mount",
                phase="unmount",
                exit_code=5,
                elapsed_ms=1234,
                repeat_count=3,
                truncated=True,
            )
        )

        payload = sent[0]
        field_names = {line.split(b"=", 1)[0] for line in payload.splitlines()}
        self.assertEqual(
            {
                b"MESSAGE",
                b"PRIORITY",
                b"SYSLOG_IDENTIFIER",
                b"LTO_ARCHIVER_SOURCE",
                b"LTO_ARCHIVER_CODE",
                b"LTO_ARCHIVER_OPERATION_ID",
                b"LTO_ARCHIVER_JOB_ID",
                b"LTO_ARCHIVER_CASSETTE_LABEL",
                b"LTO_ARCHIVER_CASSETTE_SEQUENCE",
                b"LTO_ARCHIVER_COMMAND_ID",
                b"LTO_ARCHIVER_DAEMON_GENERATION",
                b"LTO_ARCHIVER_COMMAND_KIND",
                b"LTO_ARCHIVER_PHASE",
                b"LTO_ARCHIVER_EXIT_CODE",
                b"LTO_ARCHIVER_ELAPSED_MS",
                b"LTO_ARCHIVER_REPEAT_COUNT",
                b"LTO_ARCHIVER_TRUNCATED",
            },
            field_names,
        )

    def test_redactor_removes_all_recognized_credential_forms(self) -> None:
        """Skipping a credential pattern must never leave its plaintext in output."""
        secret_argument = type(
            "SecretArgument",
            (str,),
            {"__module__": "ltobackup.tape.command_supervisor"},
        )
        text, truncated = redact_operational_message(
            "token=abc123 cookie=delicious "
            "https://alice:secret@example.test/path "
            "Authorization: Basic YWxpY2U6c2VjcmV0"
        )

        self.assertFalse(truncated)
        for plaintext in ("YWxpY2U6c2VjcmV0", "abc123", "delicious", "alice:secret"):
            self.assertNotIn(plaintext, text)
        self.assertEqual(
            "<redacted>", redact_operational_message(secret_argument("opaque"))[0]
        )

    def test_redactor_removes_json_colon_header_and_cli_secret_forms(self) -> None:
        """A delimiter-specific redactor must not leak common tool diagnostics."""
        text, truncated = redact_operational_message(
            '{"password":"hunter2","api-key":"api-secret"} '
            "secret: colon-secret Cookie: session=cookie-secret "
            "X-CSRF-Token: csrf-secret --token cli-token status=finished"
        )

        self.assertFalse(truncated)
        for plaintext in (
            "hunter2",
            "api-secret",
            "colon-secret",
            "cookie-secret",
            "csrf-secret",
            "cli-token",
        ):
            self.assertNotIn(plaintext, text)
        self.assertIn("status=finished", text)

    def test_redactor_consumes_escaped_quotes_inside_quoted_secret_values(self) -> None:
        """Ending quoted matches at an escaped quote must not expose secret tails."""
        cases = (
            (r'{"password":"hunter\"json-tail"} status=finished', "json-tail"),
            (r"password='hunter\'assignment-tail' status=finished", "assignment-tail"),
            ('{"token":"päss\\"unicode-tail"} status=finished', "unicode-tail"),
            (
                b'{"token":"\xffinvalid\\"byte-tail"} status=finished',
                "byte-tail",
            ),
        )

        for value, secret_tail in cases:
            with self.subTest(value=value):
                text, truncated = redact_operational_message(value)

                self.assertFalse(truncated)
                self.assertNotIn(secret_tail, text)
                self.assertIn("status=finished", text)

    def test_coalescing_preserves_consecutive_repeats_and_uses_utf8_bytes(self) -> None:
        """Counting characters instead of UTF-8 bytes must breach the output cap."""
        coalesced, truncated = coalesce_operational_lines(
            ("éé", "éé", "z"), max_bytes=4
        )

        self.assertEqual((("éé", 2),), coalesced)
        self.assertTrue(truncated)

    def test_journal_failure_is_dropped_with_a_closed_error_code(self) -> None:
        """A journald outage must not raise or disclose the transport exception."""
        errors: list[str] = []

        def unavailable(_: bytes) -> None:
            raise OSError("socket path and token=secret must stay private")

        JournalOperationalEventSink(send=unavailable, on_error=errors.append).emit(
            OperationalEvent(
                source=OperationalSource.DAEMON,
                severity=OperationalSeverity.WARNING,
                code="daemon.journal.retry",
                message="journal unavailable",
            )
        )

        self.assertEqual(["journald_unavailable"], errors)

    def test_journal_sink_uses_only_a_validated_distinct_service_identifier(self) -> None:
        sent: list[bytes] = []
        sink = JournalOperationalEventSink(
            send=sent.append,
            syslog_identifier="lto-archiver-command-broker",
        )
        sink.emit(
            OperationalEvent(
                OperationalSource.COMMAND_BROKER,
                OperationalSeverity.INFO,
                "broker.started",
                "Command broker started.",
            )
        )
        self.assertIn(
            b"SYSLOG_IDENTIFIER=lto-archiver-command-broker\n", sent[0]
        )
        with self.assertRaises(ValueError):
            JournalOperationalEventSink(syslog_identifier="bad identifier")

    def test_event_rejects_numeric_metadata_that_cannot_be_safely_serialized(self) -> None:
        """Removing numeric bounds must not permit unsafe journal serialization."""
        enormous = 10**5000
        for field, value in (
            ("cassette_sequence", enormous),
            ("exit_code", enormous),
            ("elapsed_ms", enormous),
            ("repeat_count", enormous),
        ):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    OperationalEvent(
                        source=OperationalSource.LTFS,
                        severity=OperationalSeverity.INFO,
                        code="ltfs.command.complete",
                        message="complete",
                        **{field: value},
                    )

    def test_journal_sink_drops_corrupt_metadata_before_serialization_raises(self) -> None:
        """Moving serialization out of the best-effort boundary must raise here."""
        errors: list[str] = []
        sent: list[bytes] = []
        event = OperationalEvent(
            source=OperationalSource.LTFS,
            severity=OperationalSeverity.INFO,
            code="ltfs.command.complete",
            message="complete",
        )
        object.__setattr__(event, "repeat_count", 10**5000)

        JournalOperationalEventSink(send=sent.append, on_error=errors.append).emit(event)

        self.assertEqual([], sent)
        self.assertEqual(["journald_unavailable"], errors)
