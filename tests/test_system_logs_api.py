from __future__ import annotations

import unittest
from dataclasses import replace

from httpx2 import ASGITransport, AsyncClient
from pydantic import ValidationError

from ltobackup.daemon.api import create_app
from ltobackup.daemon.api_models import (
    SystemLogEntryV1,
    SystemLogQuery,
    SystemLogsPageV1,
)
from ltobackup.daemon.service import DaemonService, Principal, RoleDenied
from ltobackup.log_reader.client import JournalReaderUnavailable
from ltobackup.log_reader.protocol import (
    JournalEntry,
    JournalPage,
    LogDirection,
    LogRange,
    LogSource,
    Severity,
)


def entry(
    cursor: str,
    message: str,
    *,
    source: LogSource = LogSource.LTFS,
    operation_id: str | None = None,
    job_id: str | None = None,
) -> JournalEntry:
    return JournalEntry(
        cursor=cursor,
        timestamp="2026-09-04T12:00:00.000000Z",
        severity=Severity.INFO,
        source=source,
        unit="lto-archiverd.service",
        message=message,
        operation_id=operation_id,
        job_id=job_id,
        cassette_label="TAPE05",
        cassette_sequence=5,
        command_id="command-1",
        daemon_generation=9,
        command_kind="mount",
        phase="copy",
        exit_code=0,
        elapsed_ms=125,
        repeat_count=1,
        truncated=False,
        pid=123,
        boot_id="boot-1",
    )


def source_entry(
    cursor: str, source: LogSource, message: str = "match"
) -> JournalEntry:
    units = {
        LogSource.DAEMON: "lto-archiverd.service",
        LogSource.WEBUI: "lto-archiver-web.service",
        LogSource.LTFS: "lto-archiverd.service",
        LogSource.COMMAND_BROKER: "lto-archiver-command-broker.service",
        LogSource.SHARE_BROKER: "lto-archiver-share-broker.service",
        LogSource.QUALIFICATION: "lto-archiver-ltfs-qualification.service",
    }
    return replace(entry(cursor, message, source=source), unit=units[source])


def unavailable(*sources: LogSource) -> tuple[LogSource, ...]:
    return tuple(sorted(sources, key=lambda source: source.value))


def query(**changes: object) -> SystemLogQuery:
    values: dict[str, object] = {
        "source": LogSource.LTFS,
        "severity": Severity.INFO,
        "range": LogRange.ONE_DAY,
        "direction": LogDirection.OLDER,
        "cursor": None,
        "search": None,
        "limit": 50,
    }
    values.update(changes)
    return SystemLogQuery.model_validate(values)


class FakeReader:
    def __init__(self, pages: list[JournalPage | Exception]) -> None:
        self.pages = pages
        self.calls = []

    def query(self, request):
        self.calls.append(request)
        selected = self.pages.pop(0)
        if isinstance(selected, Exception):
            raise selected
        return selected


def service_for(reader: FakeReader) -> DaemonService:
    service = object.__new__(DaemonService)
    service._journal_reader = reader
    return service


class SystemLogModelTests(unittest.TestCase):
    def test_system_log_exposes_closed_durable_command_identity(self) -> None:
        item = SystemLogEntryV1.model_validate(
            {
                "cursor": "cursor-1",
                "occurred_at": "2026-09-04T12:00:00Z",
                "severity": "info",
                "source": "ltfs",
                "unit": "lto-archiverd.service",
                "message": "safe",
                "repeat_count": 1,
                "truncated": False,
                "command_id": "command-1",
                "daemon_generation": 9,
            }
        )

        self.assertEqual("command-1", item.command_id)
        self.assertEqual(9, item.daemon_generation)
        for changes in ({"command_id": "bad command"}, {"daemon_generation": True}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                SystemLogEntryV1.model_validate({**item.model_dump(), **changes})

    def test_system_log_model_rejects_unknown_journal_fields(self) -> None:
        valid = {
            "cursor": "cursor-1",
            "occurred_at": "2026-09-04T12:00:00.000000Z",
            "severity": "info",
            "source": "ltfs",
            "unit": "lto-archiverd.service",
            "message": "safe",
            "repeat_count": 1,
            "truncated": False,
            "pid": 123,
            "boot_id": "boot-1",
        }
        SystemLogEntryV1.model_validate(valid)
        with self.assertRaises(ValidationError):
            SystemLogEntryV1.model_validate({**valid, "_CMDLINE": "secret"})

    def test_query_rejects_non_printable_or_oversized_search_and_bad_cursor(self) -> None:
        for field, value in (
            ("search", "x" * 129),
            ("search", "bad\nquery"),
            ("cursor", "é"),
            ("cursor", "x" * 2049),
        ):
            with self.subTest(field=field), self.assertRaises(ValidationError):
                query(**{field: value})

    def test_entry_enforces_source_unit_pairing_and_boot_id_utf8_bytes(self) -> None:
        valid = {
            "cursor": "cursor-1",
            "occurred_at": "2026-09-04T12:00:00Z",
            "severity": "info",
            "source": "daemon",
            "unit": "lto-archiverd.service",
            "message": "safe",
            "repeat_count": 1,
            "truncated": False,
            "pid": None,
            "boot_id": None,
        }
        for changes in (
            {"unit": "lto-archiver-web.service"},
            {"boot_id": "é" * 129},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                SystemLogEntryV1.model_validate({**valid, **changes})

    def test_page_rejects_partial_unavailable_or_fabricated_rotated_state(self) -> None:
        item = SystemLogEntryV1(
            cursor="cursor-1",
            occurred_at="2026-09-04T12:00:00Z",
            severity="info",
            source="daemon",
            unit="lto-archiverd.service",
            message="safe",
            repeat_count=1,
            truncated=False,
            pid=None,
            boot_id=None,
        )
        base = {
            "source": "daemon",
            "severity": "info",
            "range": "1h",
            "direction": "older",
            "search": None,
            "limit": 50,
            "items": (),
            "older_cursor": None,
            "newer_cursor": None,
            "cursor_rotated": False,
            "live_supported": True,
            "unavailable_sources": (),
        }
        invalid = (
            {"cursor_rotated": True, "items": (item,)},
            {"cursor_rotated": True, "older_cursor": "fabricated"},
            {"unavailable_sources": ("daemon",), "items": (item,)},
            {"unavailable_sources": ("daemon",), "newer_cursor": "fabricated"},
        )
        for changes in invalid:
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                SystemLogsPageV1.model_validate({**base, **changes})

    def test_all_page_allows_only_healthy_items_during_partial_degradation(self) -> None:
        healthy = SystemLogEntryV1(
            cursor="cursor-1",
            occurred_at="2026-09-04T12:00:00Z",
            severity="info",
            source="daemon",
            unit="lto-archiverd.service",
            message="safe",
            repeat_count=1,
            truncated=False,
            pid=None,
            boot_id=None,
        )
        base = {
            "source": "all",
            "severity": "info",
            "range": "1h",
            "direction": "older",
            "search": None,
            "limit": 50,
            "items": (healthy,),
            "older_cursor": "cursor-1",
            "newer_cursor": "cursor-1",
            "cursor_rotated": False,
            "live_supported": True,
            "unavailable_sources": ("ltfs",),
        }

        SystemLogsPageV1.model_validate(base)
        with self.assertRaises(ValidationError):
            SystemLogsPageV1.model_validate(
                {
                    **base,
                    "items": (
                        healthy.model_copy(
                            update={
                                "source": LogSource.LTFS,
                                "unit": "lto-archiverd.service",
                            }
                        ),
                    ),
                }
            )


class SystemLogServiceTests(unittest.TestCase):
    def test_all_query_returns_healthy_entries_with_one_unavailable_source(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("c3", LogSource.DAEMON),
                        source_entry("c2", LogSource.LTFS),
                        source_entry("c1", LogSource.WEBUI),
                    ),
                    None,
                    "c3",
                    False,
                    unavailable(LogSource.LTFS),
                )
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual(["c3", "c1"], [item.cursor for item in result.items])
        self.assertEqual((LogSource.LTFS,), result.unavailable_sources)
        self.assertEqual("c1", result.older_cursor)
        self.assertEqual("c3", result.newer_cursor)

    def test_all_query_aggregates_multiple_unavailable_sources(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (source_entry("c3", LogSource.DAEMON),),
                    "next",
                    "c3",
                    False,
                    unavailable(LogSource.LTFS),
                ),
                JournalPage(
                    (
                        source_entry("c2", LogSource.WEBUI),
                        source_entry("c1", LogSource.SHARE_BROKER),
                    ),
                    None,
                    "c2",
                    False,
                    unavailable(LogSource.LTFS, LogSource.SHARE_BROKER),
                ),
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual(["c3", "c2"], [item.cursor for item in result.items])
        self.assertEqual(
            unavailable(LogSource.LTFS, LogSource.SHARE_BROKER),
            result.unavailable_sources,
        )

    def test_later_unavailability_quarantines_already_collected_entries(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("c4", LogSource.LTFS),
                        source_entry("c3", LogSource.DAEMON),
                    ),
                    "next",
                    "c4",
                    False,
                ),
                JournalPage(
                    (
                        source_entry("c2", LogSource.LTFS),
                        source_entry("c1", LogSource.WEBUI),
                    ),
                    None,
                    "c2",
                    False,
                    unavailable(LogSource.LTFS),
                ),
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual(["c3", "c1"], [item.cursor for item in result.items])
        self.assertEqual((LogSource.LTFS,), result.unavailable_sources)

    def test_all_unavailable_is_empty_without_fabricated_cursors(self) -> None:
        all_sources = unavailable(
            *(source for source in LogSource if source is not LogSource.ALL)
        )
        reader = FakeReader(
            [JournalPage((), "fake-old", "fake-new", False, all_sources)]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual((), result.items)
        self.assertEqual(all_sources, result.unavailable_sources)
        self.assertIsNone(result.older_cursor)
        self.assertIsNone(result.newer_cursor)

    def test_mixed_source_search_limit_order_and_cursors_remain_global(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("c5", LogSource.WEBUI, "not selected"),
                        source_entry("c4", LogSource.DAEMON, "needle daemon"),
                    ),
                    "next",
                    "c5",
                    False,
                    unavailable(LogSource.SHARE_BROKER),
                ),
                JournalPage(
                    (
                        source_entry("c3", LogSource.LTFS, "needle tape"),
                        source_entry("c2", LogSource.QUALIFICATION, "needle later"),
                    ),
                    "c2",
                    "c3",
                    False,
                    unavailable(LogSource.SHARE_BROKER),
                ),
            ]
        )

        result = service_for(reader).system_logs(
            query(source=LogSource.ALL, search="needle", limit=2)
        )

        self.assertEqual(["c4", "c3"], [item.cursor for item in result.items])
        self.assertEqual("c3", result.older_cursor)
        self.assertEqual("c4", result.newer_cursor)
        self.assertEqual((LogSource.SHARE_BROKER,), result.unavailable_sources)
        self.assertEqual(2, len(reader.calls))
        self.assertTrue(all(call.source is LogSource.ALL for call in reader.calls))

    def test_later_rotation_discards_partial_availability_and_positions(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (source_entry("c2", LogSource.DAEMON),),
                    "next",
                    "c2",
                    False,
                    unavailable(LogSource.LTFS),
                ),
                JournalPage((), "fake-old", "fake-new", True),
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertTrue(result.cursor_rotated)
        self.assertEqual((), result.items)
        self.assertEqual((), result.unavailable_sources)
        self.assertIsNone(result.older_cursor)
        self.assertIsNone(result.newer_cursor)

    def test_single_source_protocol_unavailable_preserves_closed_behavior(self) -> None:
        reader = FakeReader(
            [JournalPage((), "fake-old", "fake-new", False, unavailable(LogSource.LTFS))]
        )

        result = service_for(reader).system_logs(query(source=LogSource.LTFS))

        self.assertEqual((), result.items)
        self.assertEqual((LogSource.LTFS,), result.unavailable_sources)
        self.assertIsNone(result.older_cursor)
        self.assertIsNone(result.newer_cursor)

    def test_single_source_rejects_unrelated_availability_as_malformed(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (entry("c1", "unsafe partial"),),
                    "fake-old",
                    "fake-new",
                    False,
                    unavailable(LogSource.WEBUI),
                )
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.LTFS))

        self.assertEqual((), result.items)
        self.assertEqual((LogSource.LTFS,), result.unavailable_sources)
        self.assertIsNone(result.older_cursor)
        self.assertIsNone(result.newer_cursor)

    def test_unavailable_source_entries_still_cross_the_validation_boundary(self) -> None:
        malformed = replace(
            source_entry("c1", LogSource.LTFS),
            unit="lto-archiver-web.service",
        )
        reader = FakeReader(
            [
                JournalPage(
                    (malformed,),
                    None,
                    None,
                    False,
                    unavailable(LogSource.LTFS),
                )
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual((), result.items)
        self.assertEqual(
            tuple(source for source in LogSource if source is not LogSource.ALL),
            result.unavailable_sources,
        )

    def test_match_limit_does_not_skip_later_page_entry_validation(self) -> None:
        malformed = replace(
            source_entry("c1", LogSource.WEBUI, "not selected"),
            unit="lto-archiverd.service",
        )
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("c2", LogSource.DAEMON, "needle"),
                        malformed,
                    ),
                    None,
                    None,
                    False,
                )
            ]
        )

        result = service_for(reader).system_logs(
            query(source=LogSource.ALL, search="needle", limit=1)
        )

        self.assertEqual((), result.items)
        self.assertEqual(
            tuple(source for source in LogSource if source is not LogSource.ALL),
            result.unavailable_sources,
        )

    def test_malformed_duplicate_cursor_fails_closed_before_deduplication(self) -> None:
        malformed_duplicate = replace(
            source_entry("same", LogSource.WEBUI, "unsafe duplicate"),
            unit="lto-archiverd.service",
        )
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("same", LogSource.DAEMON, "valid first"),
                        malformed_duplicate,
                    ),
                    None,
                    None,
                    False,
                )
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual((), result.items)
        self.assertEqual(
            tuple(source for source in LogSource if source is not LogSource.ALL),
            result.unavailable_sources,
        )

    def test_malformed_duplicate_after_match_limit_still_fails_closed(self) -> None:
        malformed_duplicate = replace(
            source_entry("same", LogSource.WEBUI, "not selected"),
            unit="lto-archiverd.service",
        )
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("same", LogSource.DAEMON, "needle"),
                        malformed_duplicate,
                    ),
                    None,
                    None,
                    False,
                )
            ]
        )

        result = service_for(reader).system_logs(
            query(source=LogSource.ALL, search="needle", limit=1)
        )

        self.assertEqual((), result.items)
        self.assertEqual(
            tuple(source for source in LogSource if source is not LogSource.ALL),
            result.unavailable_sources,
        )

    def test_later_unavailable_malformed_duplicate_still_fails_closed(self) -> None:
        malformed_duplicate = replace(
            source_entry("same", LogSource.LTFS, "unsafe duplicate"),
            unit="lto-archiver-web.service",
        )
        reader = FakeReader(
            [
                JournalPage(
                    (
                        source_entry("same", LogSource.LTFS, "valid first"),
                        source_entry("healthy", LogSource.DAEMON, "healthy"),
                    ),
                    "next",
                    "same",
                    False,
                ),
                JournalPage(
                    (malformed_duplicate,),
                    None,
                    None,
                    False,
                    unavailable(LogSource.LTFS),
                ),
            ]
        )

        result = service_for(reader).system_logs(query(source=LogSource.ALL))

        self.assertEqual((), result.items)
        self.assertEqual(
            tuple(source for source in LogSource if source is not LogSource.ALL),
            result.unavailable_sources,
        )

    def test_mismatched_source_or_severity_fails_closed_without_partial_items(self) -> None:
        mismatches = (
            replace(
                entry("wrong-source", "unsafe"),
                source=LogSource.WEBUI,
                unit="lto-archiver-web.service",
            ),
            replace(entry("wrong-severity", "unsafe"), severity=Severity.DEBUG),
            replace(
                entry("wrong-unit", "unsafe", source=LogSource.DAEMON),
                unit="lto-archiver-web.service",
            ),
        )
        for candidate in mismatches:
            with self.subTest(cursor=candidate.cursor):
                source = (
                    LogSource.ALL
                    if candidate.cursor == "wrong-unit"
                    else LogSource.LTFS
                )
                reader = FakeReader(
                    [
                        JournalPage(
                            (entry("valid", "valid"), candidate),
                            None,
                            None,
                            False,
                        )
                    ]
                )

                result = service_for(reader).system_logs(query(source=source))

                self.assertEqual((), result.items)
                self.assertEqual(
                    tuple(
                        concrete
                        for concrete in LogSource
                        if concrete is not LogSource.ALL
                    )
                    if source is LogSource.ALL
                    else (source,),
                    result.unavailable_sources,
                )
                self.assertIsNone(result.older_cursor)
                self.assertIsNone(result.newer_cursor)

    def test_search_can_reach_third_page_and_uses_safe_correlation_fields(self) -> None:
        pages = [
            JournalPage((entry("c1", "first"),), "next-1", "c1", False),
            JournalPage((entry("c2", "second"),), "next-2", "c2", False),
            JournalPage(
                (entry("c3", "third", operation_id="operation-needle"),),
                None,
                "c3",
                False,
            ),
        ]
        reader = FakeReader(pages)

        result = service_for(reader).system_logs(query(search="needle"))

        self.assertEqual(["c3"], [item.cursor for item in result.items])
        self.assertEqual(3, len(reader.calls))
        self.assertEqual("next-1", reader.calls[1].cursor)
        self.assertEqual("next-2", reader.calls[2].cursor)

    def test_search_does_not_match_unit_or_boot_metadata(self) -> None:
        candidate = replace(
            entry("c1", "safe"),
            boot_id="needle",
        )
        reader = FakeReader([JournalPage((candidate,), None, None, False)])

        result = service_for(reader).system_logs(query(search="needle"))

        self.assertEqual((), result.items)
        self.assertEqual((), result.unavailable_sources)

    def test_daemon_redacts_again_before_searching_or_returning_a_message(self) -> None:
        reader = FakeReader(
            [JournalPage((entry("c1", "password=hunter2 mounted"),), None, None, False)]
        )

        hidden = service_for(reader).system_logs(query(search="hunter2"))

        self.assertEqual((), hidden.items)
        reader = FakeReader(
            [JournalPage((entry("c1", "password=hunter2 mounted"),), None, None, False)]
        )
        visible = service_for(reader).system_logs(query(search="mounted"))
        self.assertEqual(1, len(visible.items))
        self.assertNotIn("hunter2", visible.items[0].message)

    def test_search_inspects_at_most_one_thousand_entries_in_five_pages(self) -> None:
        pages = []
        for page_number in range(6):
            items = tuple(
                entry(f"c-{page_number}-{index}", "no match") for index in range(200)
            )
            pages.append(
                JournalPage(items, f"next-{page_number}", items[0].cursor, False)
            )
        reader = FakeReader(pages)

        result = service_for(reader).system_logs(query(search="absent", limit=200))

        self.assertEqual((), result.items)
        self.assertEqual(5, len(reader.calls))

    def test_partial_search_keeps_combined_five_page_inspection_cap(self) -> None:
        pages = []
        for page_number in range(6):
            message = "needle" if page_number == 5 else "no match"
            items = tuple(
                source_entry(
                    f"c-{page_number}-{index}", LogSource.DAEMON, message
                )
                for index in range(200)
            )
            pages.append(
                JournalPage(
                    items,
                    f"next-{page_number}",
                    items[0].cursor,
                    False,
                    unavailable(LogSource.SHARE_BROKER),
                )
            )
        reader = FakeReader(pages)

        result = service_for(reader).system_logs(
            query(source=LogSource.ALL, search="needle", limit=200)
        )

        self.assertEqual((), result.items)
        self.assertEqual((LogSource.SHARE_BROKER,), result.unavailable_sources)
        self.assertEqual(5, len(reader.calls))
        self.assertTrue(all(call.source is LogSource.ALL for call in reader.calls))

    def test_pagination_stops_without_a_next_cursor(self) -> None:
        reader = FakeReader(
            [JournalPage((entry("c1", "no match"),), None, "c1", False)]
        )

        service_for(reader).system_logs(query(search="absent"))

        self.assertEqual(1, len(reader.calls))

    def test_reader_failure_discards_partial_results_and_marks_source_unavailable(self) -> None:
        reader = FakeReader(
            [
                JournalPage((entry("c1", "match"),), "next", "c1", False),
                JournalReaderUnavailable(),
            ]
        )

        result = service_for(reader).system_logs(query(search="match", limit=2))

        self.assertEqual((), result.items)
        self.assertEqual((LogSource.LTFS,), result.unavailable_sources)
        self.assertIsNone(result.older_cursor)
        self.assertIsNone(result.newer_cursor)

    def test_rotation_returns_no_fabricated_position(self) -> None:
        reader = FakeReader([JournalPage((), "fake-old", "fake-new", True)])

        result = service_for(reader).system_logs(query(cursor="expired"))

        self.assertTrue(result.cursor_rotated)
        self.assertEqual((), result.items)
        self.assertIsNone(result.older_cursor)
        self.assertIsNone(result.newer_cursor)

    def test_all_source_failure_reports_each_concrete_source(self) -> None:
        result = service_for(FakeReader([JournalReaderUnavailable()])).system_logs(
            query(source=LogSource.ALL)
        )

        self.assertEqual(
            tuple(source for source in LogSource if source is not LogSource.ALL),
            result.unavailable_sources,
        )

    def test_entries_are_deduplicated_and_keep_reader_order(self) -> None:
        reader = FakeReader(
            [
                JournalPage(
                    (entry("c3", "three"), entry("c2", "two")),
                    "next",
                    "c3",
                    False,
                ),
                JournalPage(
                    (entry("c2", "two"), entry("c1", "one")),
                    None,
                    "c2",
                    False,
                ),
            ]
        )

        result = service_for(reader).system_logs(query(limit=3))

        self.assertEqual(["c3", "c2", "c1"], [item.cursor for item in result.items])


class _Principals:
    @staticmethod
    def _principal() -> Principal:
        return Principal("operator-1", role="operator")

    require_mutation_principal = _principal
    require_operator = _principal
    require_admin = _principal
    require_direct_local_admin = _principal
    require_webui_admin = _principal


class _DenyPrincipals(_Principals):
    @staticmethod
    def require_operator() -> Principal:
        raise RoleDenied("read denied")


class SystemLogApiTests(unittest.IsolatedAsyncioTestCase):
    async def _request(self, path: str, *, denied: bool = False):
        reader = FakeReader([JournalPage((), None, None, False)])
        service = service_for(reader)
        service.principals = _DenyPrincipals() if denied else _Principals()
        app = create_app(service)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://daemon"
        ) as client:
            response = await client.get(path)
        return response, reader

    async def test_api_rejects_unknown_filters_before_reader_call(self) -> None:
        reader = FakeReader([JournalPage((), None, None, False)])
        service = service_for(reader)
        service.principals = _Principals()
        app = create_app(service)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://daemon"
        ) as client:
            response = await client.get("/api/v1/system-logs?unit=sshd.service")

        self.assertEqual(422, response.status_code)
        self.assertEqual([], reader.calls)

    async def test_api_rejects_complete_invalid_query_matrix_before_reader(self) -> None:
        invalid_queries = (
            "source=ltfs&source=daemon",
            "source=host",
            "severity=notice",
            "range=forever",
            "direction=sideways",
            "limit=0",
            "limit=201",
            "limit=true",
            "limit=1.5",
            "search=",
            "search=%20%20",
            f"search={'x' * 129}",
            "search=bad%0Aquery",
            "search=bad%7Fquery",
            "cursor=",
            f"cursor={'x' * 2049}",
            "cursor=%C3%A9",
            "cursor=bad%00cursor",
        )
        for query_string in invalid_queries:
            with self.subTest(query_string=query_string):
                response, reader = await self._request(
                    "/api/v1/system-logs?" + query_string
                )
                self.assertEqual(422, response.status_code, response.text)
                self.assertEqual([], reader.calls)

    async def test_api_requires_an_authorized_read_principal_before_reader(self) -> None:
        response, reader = await self._request(
            "/api/v1/system-logs", denied=True
        )

        self.assertEqual(403, response.status_code)
        self.assertEqual("role_denied", response.json()["error"]["code"])
        self.assertEqual([], reader.calls)

    async def test_api_returns_closed_typed_page(self) -> None:
        reader = FakeReader(
            [JournalPage((entry("cursor-1", "mounted"),), None, "cursor-1", False)]
        )
        service = service_for(reader)
        service.principals = _Principals()
        app = create_app(service)
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://daemon"
        ) as client:
            response = await client.get(
                "/api/v1/system-logs",
                params={"source": "ltfs", "severity": "info", "range": "24h"},
            )

        self.assertEqual(200, response.status_code, response.text)
        parsed = SystemLogsPageV1.model_validate(response.json())
        self.assertEqual("cursor-1", parsed.items[0].cursor)


if __name__ == "__main__":
    unittest.main()
