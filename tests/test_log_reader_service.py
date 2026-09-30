from __future__ import annotations

import gc
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import warnings
from pathlib import Path

from ltobackup.log_reader.protocol import (
    JournalQuery,
    LogDirection,
    LogRange,
    LogSource,
    Severity,
)
from ltobackup.log_reader.service import (
    JournalReaderService,
    JournalReaderUnavailable,
    _default_run_command,
)

_RUNNER_WATCHDOG = r"""
import gc
import json
import os
import subprocess
import sys
import threading
import time
import warnings
from pathlib import Path

from ltobackup.log_reader.service import JournalReaderUnavailable, _default_run_command

started = time.monotonic()
baseline_threads = {thread.ident for thread in threading.enumerate()}
kind = "completed"
stdout = ""
stderr = ""
resource_errors = []
original_unraisablehook = sys.unraisablehook
def capture_unraisable(unraisable):
    if isinstance(unraisable.exc_value, ResourceWarning):
        resource_errors.append(str(unraisable.exc_value))
    else:
        original_unraisablehook(unraisable)
sys.unraisablehook = capture_unraisable
with warnings.catch_warnings():
    warnings.simplefilter("error", ResourceWarning)
    try:
        result = _default_run_command(
            (sys.executable, "-c", sys.argv[1], sys.argv[2]),
            timeout=float(sys.argv[3]),
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            max_output_bytes=int(sys.argv[4]),
        )
        stdout = result.stdout
        stderr = result.stderr
        del result
    except subprocess.TimeoutExpired:
        kind = "timeout"
    except JournalReaderUnavailable:
        kind = "unavailable"
    gc.collect()
sys.unraisablehook = original_unraisablehook

group_record = Path(sys.argv[2]).read_text().split()
group = int(group_record[0])
direct_pid = int(group_record[2])
deadline = time.monotonic() + 0.5
while True:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        group_alive = False
        break
    group_alive = True
    if time.monotonic() >= deadline:
        break
    time.sleep(0.01)

print(json.dumps({
    "elapsed": time.monotonic() - started,
    "direct_pid": direct_pid,
    "group": group,
    "group_alive": group_alive,
    "kind": kind,
    "stderr": stderr,
    "stdout": stdout,
    "threads": [
        thread.name
        for thread in threading.enumerate()
        if thread.ident not in baseline_threads and thread.is_alive()
    ],
    "warnings": resource_errors,
}))
"""


def _watchdog_runner(
    child_source: str,
    *,
    timeout: float,
    max_output_bytes: int,
) -> dict[str, object]:
    with tempfile.TemporaryDirectory() as directory:
        group_file = Path(directory) / "group"
        process = subprocess.Popen(
            (
                sys.executable,
                "-c",
                _RUNNER_WATCHDOG,
                child_source,
                str(group_file),
                str(timeout),
                str(max_output_bytes),
            ),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=3.0)
        except subprocess.TimeoutExpired as exc:
            groups = {process.pid}
            if group_file.exists():
                groups.add(int(group_file.read_text().split()[0]))
            for group in groups:
                try:
                    os.killpg(group, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            process.wait(timeout=1.0)
            assert process.stdout is not None and process.stderr is not None
            process.stdout.close()
            process.stderr.close()
            raise AssertionError("journal runner exceeded its outer watchdog") from exc
        if process.returncode != 0:
            if group_file.exists():
                try:
                    os.killpg(int(group_file.read_text().split()[0]), signal.SIGKILL)
                except ProcessLookupError:
                    pass
            raise AssertionError(
                f"journal runner watchdog failed ({process.returncode}): {stderr}"
            )
        evidence = json.loads(stdout)
        if evidence["group_alive"]:
            try:
                os.killpg(int(evidence["group"]), signal.SIGKILL)
            except ProcessLookupError:
                pass
        return evidence


def completed(
    stdout: str, returncode: int = 0, stderr: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        ("/usr/bin/journalctl",), returncode, stdout, stderr
    )


def daemon_query(**changes: object) -> JournalQuery:
    values: dict[str, object] = {
        "source": LogSource.DAEMON,
        "minimum_severity": Severity.INFO,
        "range": LogRange.ONE_HOUR,
        "direction": LogDirection.OLDER,
        "cursor": None,
        "limit": 50,
    }
    values.update(changes)
    return JournalQuery(**values)  # type: ignore[arg-type]


class JournalReaderServiceTests(unittest.TestCase):
    def test_native_ltfs_records_are_selected_using_trusted_executable_and_unit(self) -> None:
        record = {
            "__CURSOR": "native-ltfs",
            "__REALTIME_TIMESTAMP": "1725444672123456",
            "_SYSTEMD_UNIT": "lto-archiver-command-broker.service",
            "_EXE": "/usr/bin/ltfs",
            "PRIORITY": "3",
            "MESSAGE": "LTFS12030E Cannot get capacity (-21700)",
        }

        def journal_fixture(
            argv: tuple[str, ...], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            # journalctl ORs '+' groups; distinct fields within a group are ANDed.
            groups: list[list[str]] = [[]]
            for argument in argv[1:]:
                if argument == "+":
                    groups.append([])
                elif argument.startswith(("_", "LTO_ARCHIVER_")):
                    groups[-1].append(argument)
            for group in groups:
                matches: dict[str, list[str]] = {}
                for argument in group:
                    key, value = argument.split("=", 1)
                    matches.setdefault(key, []).append(value)
                if all(record.get(key) in values for key, values in matches.items()):
                    return completed(json.dumps(record))
            return completed("")

        service = JournalReaderService(run_command=journal_fixture)
        for source in (LogSource.LTFS, LogSource.ALL):
            with self.subTest(source=source):
                page = service.query(daemon_query(source=source))
                self.assertEqual(["native-ltfs"], [entry.cursor for entry in page.entries])
                self.assertEqual(LogSource.LTFS, page.entries[0].source)
                self.assertEqual(Severity.ERROR, page.entries[0].severity)
        self.assertEqual(
            (), service.query(daemon_query(source=LogSource.COMMAND_BROKER)).entries
        )

    def test_native_ltfs_attribution_rejects_message_and_process_name_spoofing(self) -> None:
        for metadata in (
            {},
            {"SYSLOG_IDENTIFIER": "ltfs", "_COMM": "ltfs"},
            {"_EXE": "/tmp/ltfs"},
            {"_EXE": "/usr/bin/python3"},
            {"_EXE": "/usr/bin/ltfs", "_SYSTEMD_UNIT": "lto-archiver-web.service"},
        ):
            with self.subTest(metadata=metadata):
                record = {
                    "__CURSOR": "spoof",
                    "__REALTIME_TIMESTAMP": "1725444672123456",
                    "_SYSTEMD_UNIT": "lto-archiver-command-broker.service",
                    "PRIORITY": "3",
                    "MESSAGE": "LTFS12030E Cannot get capacity",
                    **metadata,
                }
                service = JournalReaderService(
                    run_command=lambda *_args, **_kwargs: completed(json.dumps(record))
                )
                self.assertEqual(
                    (), service.query(daemon_query(source=LogSource.LTFS)).entries
                )

    def test_malformed_native_ltfs_record_quarantines_ltfs_only(self) -> None:
        records = [
            {
                "__CURSOR": "broker",
                "__REALTIME_TIMESTAMP": "1725444672123456",
                "_SYSTEMD_UNIT": "lto-archiver-command-broker.service",
                "PRIORITY": "6",
                "MESSAGE": "safe",
            },
            {
                "__CURSOR": "native",
                "__REALTIME_TIMESTAMP": "invalid",
                "_SYSTEMD_UNIT": "lto-archiver-command-broker.service",
                "_EXE": "/usr/bin/ltfs",
                "PRIORITY": "3",
                "MESSAGE": "LTFS12030E Cannot get capacity",
            },
        ]
        service = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(
                "\n".join(json.dumps(record) for record in records)
            )
        )
        page = service.query(daemon_query(source=LogSource.ALL))
        self.assertEqual(["broker"], [entry.cursor for entry in page.entries])
        self.assertEqual((LogSource.LTFS,), page.unavailable_sources)

    def test_cursor_rotation_returns_a_valid_rotated_page_without_fallback(
        self,
    ) -> None:
        calls: list[tuple[str, ...]] = []
        service = JournalReaderService(
            run_command=lambda argv, **_kwargs: (
                calls.append(argv)
                or completed("", returncode=1, stderr="Failed to seek to cursor")
            )
        )
        page = service.query(daemon_query(cursor="expired-cursor"))
        self.assertEqual((), page.entries)
        self.assertTrue(page.cursor_rotated)
        self.assertIsNone(page.older_cursor)
        self.assertIsNone(page.newer_cursor)
        self.assertEqual(1, len(calls))

        from ltobackup.log_reader.protocol import decode_response, encode_request

        packet = service.handle_packet(
            encode_request(daemon_query(cursor="expired-cursor")),
            peer_uid=0,
            peer_gid=0,
        )
        self.assertTrue(decode_response(packet).cursor_rotated)

    def test_direction_selects_non_overlapping_continuation_boundaries(self) -> None:
        lines = "\n".join(
            f'{{"__CURSOR":"c{index}","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}}'
            for index in range(1, 4)
        )
        service = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(lines)
        )
        older = service.query(daemon_query(direction=LogDirection.OLDER, limit=3))
        newer = service.query(daemon_query(direction=LogDirection.NEWER, limit=3))
        self.assertEqual(("c3", "c1"), (older.older_cursor, older.newer_cursor))
        self.assertEqual(("c1", "c3"), (newer.older_cursor, newer.newer_cursor))

    def test_adjacent_older_and_newer_pages_have_no_overlap(self) -> None:
        def output(*cursors: str) -> str:
            return "\n".join(
                f'{{"__CURSOR":"{cursor}","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}}'
                for cursor in cursors
            )

        def runner(
            argv: tuple[str, ...], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            if "--reverse" in argv:
                return (
                    completed(output("o3", "o2"))
                    if "--after-cursor=o2" not in argv
                    else completed(output("o1", "o0"))
                )
            return (
                completed(output("n1", "n2"))
                if "--after-cursor=n2" not in argv
                else completed(output("n3", "n4"))
            )

        service = JournalReaderService(run_command=runner)
        older_first = service.query(daemon_query(direction=LogDirection.OLDER, limit=2))
        older_second = service.query(
            daemon_query(
                direction=LogDirection.OLDER, cursor=older_first.older_cursor, limit=2
            )
        )
        newer_first = service.query(daemon_query(direction=LogDirection.NEWER, limit=2))
        newer_second = service.query(
            daemon_query(
                direction=LogDirection.NEWER, cursor=newer_first.newer_cursor, limit=2
            )
        )
        self.assertFalse(
            {entry.cursor for entry in older_first.entries}
            & {entry.cursor for entry in older_second.entries}
        )
        self.assertFalse(
            {entry.cursor for entry in newer_first.entries}
            & {entry.cursor for entry in newer_second.entries}
        )

    def test_filtered_candidate_page_retains_navigation_when_no_rows_match(
        self,
    ) -> None:
        lines = "\n".join(
            f'{{"__CURSOR":"c{index}","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe","LTO_ARCHIVER_SOURCE":"ltfs"}}'
            for index in range(1, 3)
        )
        calls: list[tuple[str, ...]] = []
        service = JournalReaderService(
            run_command=lambda argv, **_kwargs: calls.append(argv) or completed(lines)
        )
        page = service.query(daemon_query(limit=1))
        self.assertEqual((), page.entries)
        self.assertEqual("c2", page.older_cursor)
        self.assertEqual("c1", page.newer_cursor)
        self.assertIn("--lines=200", calls[0])

    def test_all_query_quarantines_one_attributable_source_without_extra_calls(
        self,
    ) -> None:
        lines = (
            '{"__CURSOR":"ltfs-good","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiver-command-broker.service","PRIORITY":"6","MESSAGE":"safe","LTO_ARCHIVER_SOURCE":"ltfs"}'
            '\n{"__CURSOR":"daemon-good","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}'
            '\n{"__CURSOR":"ltfs-bad","__REALTIME_TIMESTAMP":"invalid","_SYSTEMD_UNIT":"lto-archiver-command-broker.service","PRIORITY":"6","MESSAGE":"bad","LTO_ARCHIVER_SOURCE":"ltfs"}'
            '\n{"__CURSOR":"ltfs-after","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiver-command-broker.service","PRIORITY":"6","MESSAGE":"safe","LTO_ARCHIVER_SOURCE":"ltfs"}'
        )
        calls: list[tuple[str, ...]] = []
        page = JournalReaderService(
            run_command=lambda argv, **_kwargs: calls.append(argv) or completed(lines)
        ).query(daemon_query(source=LogSource.ALL, limit=50))
        self.assertEqual(
            ("daemon-good",), tuple(entry.cursor for entry in page.entries)
        )
        self.assertEqual((LogSource.LTFS,), page.unavailable_sources)
        self.assertEqual(
            ("daemon-good", "daemon-good"), (page.older_cursor, page.newer_cursor)
        )
        self.assertEqual(1, len(calls))

    def test_all_query_rejects_raw_records_over_candidate_limit_before_quarantine(
        self,
    ) -> None:
        malformed_records = [
            (
                f'{{"__CURSOR":"ltfs-{index}","__REALTIME_TIMESTAMP":"invalid",'
                '"_SYSTEMD_UNIT":"lto-archiver-command-broker.service",'
                '"PRIORITY":"6","MESSAGE":"bad","LTO_ARCHIVER_SOURCE":"ltfs"}'
            )
            for index in range(201)
        ]
        malformed_records.append(
            '{"__CURSOR":"daemon-good","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}'
        )
        calls: list[tuple[str, ...]] = []
        service = JournalReaderService(
            run_command=lambda argv, **_kwargs: (
                calls.append(argv) or completed("\n".join(malformed_records))
            )
        )
        with self.assertRaises(JournalReaderUnavailable):
            service.query(daemon_query(source=LogSource.ALL, limit=50))
        self.assertEqual(1, len(calls))

    def test_all_query_quarantines_multiple_sources_in_canonical_order(self) -> None:
        lines = (
            '{"__CURSOR":"daemon","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}'
            '\n{"__CURSOR":"web-bad","__REALTIME_TIMESTAMP":"invalid","_SYSTEMD_UNIT":"lto-archiver-web.service","PRIORITY":"6","MESSAGE":"bad"}'
            '\n{"__CURSOR":"share-bad","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiver-share-broker.service","PRIORITY":"invalid","MESSAGE":"bad"}'
        )
        page = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(lines)
        ).query(daemon_query(source=LogSource.ALL, limit=50))
        self.assertEqual(("daemon",), tuple(entry.cursor for entry in page.entries))
        self.assertEqual(
            (LogSource.SHARE_BROKER, LogSource.WEBUI), page.unavailable_sources
        )

    def test_unattributable_or_concrete_source_invalid_data_fails_globally(
        self,
    ) -> None:
        malformed = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed("{not json")
        )
        with self.assertRaises(JournalReaderUnavailable):
            malformed.query(daemon_query(source=LogSource.ALL))
        concrete = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(
                '{"__CURSOR":"bad","__REALTIME_TIMESTAMP":"invalid","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"bad"}'
            )
        )
        with self.assertRaises(JournalReaderUnavailable):
            concrete.query(daemon_query(source=LogSource.DAEMON))

    def test_all_sources_ranges_and_directions_construct_only_fixed_matches(
        self,
    ) -> None:
        calls: list[tuple[str, ...]] = []
        service = JournalReaderService(
            run_command=lambda argv, **_kwargs: calls.append(argv) or completed("")
        )
        for source in LogSource:
            for log_range in LogRange:
                for direction in LogDirection:
                    service.query(
                        daemon_query(
                            source=source, range=log_range, direction=direction
                        )
                    )
        self.assertEqual(len(LogSource) * len(LogRange) * len(LogDirection), len(calls))
        self.assertTrue(all(call[0] == "/usr/bin/journalctl" for call in calls))
        self.assertTrue(all("sshd.service" not in call for call in calls))
        all_call = calls[0]
        self.assertEqual(
            6, sum(argument.startswith("_SYSTEMD_UNIT=") for argument in all_call)
        )

    def test_timeout_and_live_output_overflow_close_the_command_boundary(self) -> None:
        service = JournalReaderService(
            run_command=lambda *_args, **_kwargs: (_ for _ in ()).throw(
                subprocess.TimeoutExpired("journalctl", 5)
            )
        )
        with self.assertRaises(JournalReaderUnavailable):
            service.query(daemon_query())
        started = time.monotonic()
        with self.assertRaises(JournalReaderUnavailable):
            _default_run_command(
                (
                    sys.executable,
                    "-c",
                    "import sys,time; sys.stdout.write('x' * (3 * 1024 * 1024)); sys.stdout.flush(); time.sleep(10)",
                ),
                timeout=5.0,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                max_output_bytes=2 * 1024 * 1024,
            )
        self.assertLess(time.monotonic() - started, 5.0)

    def test_default_runner_replaces_invalid_utf8_after_bounded_capture(self) -> None:
        result = _default_run_command(
            (sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff')"),
            timeout=5.0,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            max_output_bytes=2 * 1024 * 1024,
        )
        self.assertEqual("�", result.stdout)

    def test_default_runner_closes_capture_pipes_without_resource_warnings(
        self,
    ) -> None:
        gc.collect()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            result = _default_run_command(
                (sys.executable, "-c", "print('safe')"),
                timeout=5.0,
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
                max_output_bytes=2 * 1024 * 1024,
            )
            self.assertEqual("safe\n", result.stdout)
            del result
            gc.collect()
        self.assertEqual([], [item for item in caught if isinstance(item.message, ResourceWarning)])

    def test_default_runner_bounds_inherited_pipe_cleanup_for_every_exit(
        self,
    ) -> None:
        child_prefix = (
            "import os,subprocess,sys,time; from pathlib import Path; "
            "descendant=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
            "stdout=sys.stdout,stderr=sys.stderr); "
            "Path(sys.argv[1]).write_text("
            "f'{os.getpgrp()} {descendant.pid} {os.getpid()}'); "
            "print('stdout-sentinel',flush=True); "
            "print('stderr-sentinel',file=sys.stderr,flush=True); "
        )
        cases = (
            ("success", child_prefix, 1.0, 2 * 1024 * 1024, "completed"),
            ("timeout", child_prefix + "time.sleep(30)", 0.2, 2 * 1024 * 1024, "timeout"),
            (
                "overflow",
                child_prefix
                + "import signal; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                + "exec(\"while True:\\n os.write(sys.stdout.fileno(), b'x' * 65536)\")",
                1.0,
                1024,
                "unavailable",
            ),
        )
        for name, source, timeout, max_output_bytes, expected_kind in cases:
            with self.subTest(name=name):
                evidence = _watchdog_runner(
                    source,
                    timeout=timeout,
                    max_output_bytes=max_output_bytes,
                )
                self.assertEqual(expected_kind, evidence["kind"])
                self.assertLess(float(evidence["elapsed"]), 2.5)
                self.assertEqual(evidence["direct_pid"], evidence["group"])
                self.assertFalse(evidence["group_alive"])
                self.assertEqual([], evidence["threads"])
                self.assertEqual([], evidence["warnings"])
                if name == "success":
                    self.assertIn("stdout-sentinel", evidence["stdout"])
                    self.assertIn("stderr-sentinel", evidence["stderr"])

    def test_peer_identity_rejection_happens_before_journal_execution(self) -> None:
        calls: list[tuple[str, ...]] = []
        service = JournalReaderService(
            daemon_uid=123,
            daemon_gid=456,
            run_command=lambda argv, **_kwargs: calls.append(argv) or completed(""),
        )
        from ltobackup.log_reader.protocol import encode_request

        with self.assertRaises(PermissionError):
            service.handle_packet(
                encode_request(daemon_query()), peer_uid=1, peer_gid=2
            )
        self.assertEqual([], calls)

    def test_real_service_connection_rejects_untrusted_peer_before_reading(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)
            service = JournalReaderService(daemon_uid=99_999, daemon_gid=99_999)
            errors: list[BaseException] = []

            def server() -> None:
                with listener.accept()[0] as connection:
                    try:
                        service.handle_connection(connection)
                    except BaseException as exc:  # noqa: BLE001 - assert closed service boundary
                        errors.append(exc)

            thread = threading.Thread(target=server)
            thread.start()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.connect(str(path))
                connection.shutdown(socket.SHUT_WR)
                self.assertEqual(b"", connection.recv(1))
            thread.join()
            listener.close()
            self.assertEqual(1, len(errors))
            self.assertIsInstance(errors[0], PermissionError)

    def test_constructs_fixed_shell_free_journal_query(self) -> None:
        calls: list[tuple[tuple[str, ...], dict[str, object]]] = []

        def runner(
            argv: tuple[str, ...], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            calls.append((argv, kwargs))
            return completed("")

        service = JournalReaderService(run_command=runner)
        self.assertEqual((), service.query(daemon_query()).entries)
        argv, kwargs = calls[0]
        self.assertEqual("/usr/bin/journalctl", argv[0])
        self.assertIn("_SYSTEMD_UNIT=lto-archiverd.service", argv)
        self.assertNotIn("sshd.service", argv)
        self.assertIn("--output=json", argv)
        self.assertIn("--no-pager", argv)
        self.assertIn("--priority=0..6", argv)
        self.assertEqual(5.0, kwargs["timeout"])
        self.assertEqual(2 * 1024 * 1024, kwargs["max_output_bytes"])
        self.assertEqual(
            {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/usr/bin:/bin"},
            kwargs["env"],
        )
        self.assertNotIn("shell", kwargs)

    def test_only_allowlisted_matching_fields_survive_and_messages_are_redacted(
        self,
    ) -> None:
        output = (
            '{"__CURSOR":"cursor-1","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","_PID":"41","_BOOT_ID":"boot-1","PRIORITY":"6","MESSAGE":"Authorization: Bearer swordfish","_CMDLINE":"never"}'
            '\n{"__CURSOR":"cursor-2","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"sshd.service","PRIORITY":"3","MESSAGE":"ignore"}'
        )
        page = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(output)
        ).query(daemon_query())
        self.assertEqual(1, len(page.entries))
        entry = page.entries[0]
        self.assertEqual("daemon", entry.source.value)
        self.assertEqual("info", entry.severity.value)
        self.assertNotIn("swordfish", entry.message)
        self.assertEqual(41, entry.pid)
        self.assertEqual("boot-1", entry.boot_id)
        self.assertFalse(hasattr(entry, "cmdline"))

    def test_malformed_journal_results_close_without_a_fallback_query(self) -> None:
        cases = (
            completed("{not json"),
            completed("", returncode=1, stderr="journal unavailable"),
            completed("x" * (2 * 1024 * 1024 + 1)),
            completed(
                '{"__CURSOR":"cursor","__REALTIME_TIMESTAMP":"invalid","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"bad"}'
            ),
        )
        for result in cases:
            calls: list[tuple[str, ...]] = []

            def runner(
                argv: tuple[str, ...],
                *,
                calls: list[tuple[str, ...]] = calls,
                result: subprocess.CompletedProcess[str] = result,
                **_kwargs: object,
            ) -> subprocess.CompletedProcess[str]:
                calls.append(argv)
                return result

            service = JournalReaderService(run_command=runner)
            with (
                self.subTest(result=result),
                self.assertRaises(JournalReaderUnavailable),
            ):
                service.query(daemon_query(cursor="cursor-0"))
            self.assertEqual(1, len(calls))

    def test_rejects_more_than_two_hundred_journal_entries(self) -> None:
        line = '{"__CURSOR":"cursor-%d","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}'
        output = "\n".join(line % index for index in range(201))
        service = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(output)
        )
        with self.assertRaises(JournalReaderUnavailable):
            service.query(daemon_query(limit=200))

    def test_candidate_window_returns_requested_limit_without_skipping_next_match(
        self,
    ) -> None:
        line = '{"__CURSOR":"cursor-%d","__REALTIME_TIMESTAMP":"1725444672123456","_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"safe"}'
        service = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(
                "\n".join(line % index for index in range(2))
            )
        )
        page = service.query(daemon_query(limit=1))
        self.assertEqual(("cursor-0",), tuple(entry.cursor for entry in page.entries))
        self.assertEqual("cursor-0", page.older_cursor)

    def test_rejects_a_valid_journal_page_that_cannot_fit_the_protocol_cap(
        self,
    ) -> None:
        message = "x" * 4_096
        line = (
            '{"__CURSOR":"cursor-%d","__REALTIME_TIMESTAMP":"1725444672123456",'
            '"_SYSTEMD_UNIT":"lto-archiverd.service","PRIORITY":"6","MESSAGE":"%s"}'
        )
        output = "\n".join(line % (index, message) for index in range(200))
        service = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(output)
        )
        with self.assertRaises(JournalReaderUnavailable):
            service.query(daemon_query(limit=200))

    def test_reads_only_task_one_structured_fields_in_their_journal_encoding(
        self,
    ) -> None:
        output = (
            '{"__CURSOR":"cursor-1","__REALTIME_TIMESTAMP":"1725444672123456",'
            '"_SYSTEMD_UNIT":"lto-archiver-command-broker.service","PRIORITY":"3",'
            '"MESSAGE":"safe","LTO_ARCHIVER_SOURCE":"ltfs",'
            '"LTO_ARCHIVER_OPERATION_ID":"operation-1","LTO_ARCHIVER_CASSETTE_SEQUENCE":"1",'
            '"LTO_ARCHIVER_COMMAND_ID":"command-1","LTO_ARCHIVER_DAEMON_GENERATION":"9",'
            '"LTO_ARCHIVER_EXIT_CODE":"-9","LTO_ARCHIVER_TRUNCATED":"1","LTO_ARCHIVER_CODE":"ignored"}'
        )
        page = JournalReaderService(
            run_command=lambda *_args, **_kwargs: completed(output)
        ).query(daemon_query(source=LogSource.LTFS))
        entry = page.entries[0]
        self.assertEqual("ltfs", entry.source.value)
        self.assertEqual("operation-1", entry.operation_id)
        self.assertEqual(1, entry.cassette_sequence)
        self.assertEqual("command-1", entry.command_id)
        self.assertEqual(9, entry.daemon_generation)
        self.assertEqual(-9, entry.exit_code)
        self.assertTrue(entry.truncated)


if __name__ == "__main__":
    unittest.main()
