from __future__ import annotations

import json
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ltobackup import automation
from ltobackup.automation import (
    AutomaticJobRunner,
    CassetteLabel,
    StoreOpenController,
    TapeTelemetrySnapshot,
    TapeTelemetryMonitor,
    TapeWriteProgress,
    classify_tape_activity,
    choose_mount_path,
    normalize_cassette_labels,
    parse_log_sense_parameters,
    parse_read_position_short,
)
from ltobackup.catalog import Catalog
from ltobackup.errors import CatalogError, CapacityError, CopyError, OperationCancelled, ValidationError
from ltobackup.models import VolumeInfo
from ltobackup.settings import AppPaths, Settings
from ltobackup.volume import inspect_volume
from ltobackup.volume_probe import _parse_ltfs_mebibytes


class FakeStoreOpen:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def wait_for_media(self, stop_requested) -> bool:
        self.calls.append(("wait",))
        return not stop_requested()

    def format(self, cassette: CassetteLabel) -> None:
        self.calls.append(("format", cassette.physical_label, cassette.tape_serial))

    def mount(self, _stop_requested) -> Path:
        mount_path = Path("M:\\")
        self.calls.append(("mount", str(mount_path)))
        return mount_path

    def unmount_and_eject(self) -> None:
        self.calls.append(("eject",))


class AutomationTests(unittest.TestCase):
    def test_registered_tape_catalog_is_preserved_when_authorized_format_fails(self) -> None:
        class FailingFormat(FakeStoreOpen):
            def format(self, cassette: CassetteLabel) -> None:
                super().format(cassette)
                raise CopyError("format failed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("OLD-BLOCK", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1", "OLD-BLOCK", "AB1234", "old.bin", "old/files/old.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.create_automatic_job(
                    "REUSE", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
                    allow_registered_reuse=True,
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=FailingFormat(),
                backup=lambda *_args: self.fail("backup must not start"),
            )
            with self.assertRaisesRegex(CopyError, "format failed"):
                runner.run("REUSE", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertIsNotNone(catalog.get_tape("AB1234"))
                self.assertIn("old.bin", catalog.latest_versions("LIB1"))

    def test_registered_tape_catalog_is_purged_after_authorized_format_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("OLD-BLOCK", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1", "OLD-BLOCK", "AB1234", "old.bin", "old/files/old.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.create_automatic_job(
                    "REUSE", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
                    allow_registered_reuse=True,
                )

            def backup(*_args):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    with self.assertRaises(CatalogError):
                        catalog.get_tape("AB1234")
                    self.assertEqual({}, catalog.latest_versions("LIB1"))
                return {
                    "status": "completed", "block_id": "NEW-BLOCK",
                    "copied_files": 1, "copied_bytes": 10,
                }

            runner = AutomaticJobRunner(
                paths, Settings(), storeopen=FakeStoreOpen(), backup=backup
            )
            runner.run("REUSE", stop_requested=lambda: False)

    def test_ltfs_capacity_attribute_is_converted_from_mib_to_bytes(self) -> None:
        self.assertEqual(
            7_000 * 1024**2,
            _parse_ltfs_mebibytes("ltfs.mediaDataPartitionAvailableSpace=7000\r\n"),
        )

    def test_unmount_progress_failure_never_interrupts_the_operation(self) -> None:
        calls: list[str] = []

        def operation() -> None:
            calls.append("unmounted")

        def broken_progress(_event: dict) -> None:
            raise RuntimeError("GUI non disponibile")

        controller = object.__new__(StoreOpenController)
        controller._run_unmount_stage(
            "index_sync", 1, operation, broken_progress
        )

        self.assertEqual(["unmounted"], calls)

    def test_parses_scsi_read_position_short_response(self) -> None:
        payload = bytearray(20)
        payload[0] = 0x80
        payload[1] = 1
        payload[4:8] = (12_345).to_bytes(4, "big")
        payload[8:12] = (12_347).to_bytes(4, "big")
        payload[13:16] = (2).to_bytes(3, "big")
        payload[16:20] = (8_388_608).to_bytes(4, "big")

        position = parse_read_position_short(bytes(payload))

        self.assertTrue(position.beginning_of_partition)
        self.assertEqual(1, position.partition)
        self.assertEqual(12_345, position.first_logical_object)
        self.assertEqual(12_347, position.last_logical_object)
        self.assertEqual(2, position.buffered_objects)
        self.assertEqual(8_388_608, position.buffered_bytes)

    def test_parses_active_tapealert_log_sense_parameters(self) -> None:
        payload = bytes.fromhex(
            "2e00000a"
            "0001000101"
            "0014000101"
        )

        parameters = parse_log_sense_parameters(payload, expected_page=0x2E)

        self.assertEqual({1: b"\x01", 20: b"\x01"}, parameters)

    def test_classifies_buffered_movement_idle_and_unavailable_telemetry(self) -> None:
        previous = TapeTelemetrySnapshot(
            available=True, first_logical_object=100, last_logical_object=100
        )
        buffered = TapeTelemetrySnapshot(
            available=True,
            first_logical_object=100,
            last_logical_object=100,
            buffered_objects=1,
            buffered_bytes=4096,
        )
        moved = TapeTelemetrySnapshot(
            available=True, first_logical_object=101, last_logical_object=101
        )

        self.assertEqual("buffered", classify_tape_activity(buffered, previous))
        self.assertEqual("positioning", classify_tape_activity(moved, previous))
        self.assertEqual("idle", classify_tape_activity(previous, previous))
        self.assertEqual(
            "unavailable",
            classify_tape_activity(TapeTelemetrySnapshot(available=False), previous),
        )

    def test_telemetry_monitor_converts_provider_failure_to_nonfatal_event(self) -> None:
        received: list[dict] = []
        ready = threading.Event()

        def provider() -> TapeTelemetrySnapshot:
            raise CopyError("drive riservato da LTFS")

        def callback(event: dict) -> None:
            received.append(event)
            ready.set()

        monitor = TapeTelemetryMonitor(provider, callback, poll_seconds=60)
        monitor.start()
        self.assertTrue(ready.wait(1))
        monitor.stop()

        self.assertEqual("tape.telemetry", received[0]["event"])
        self.assertEqual("unavailable", received[0]["activity"])
        self.assertIn("riservato", received[0]["detail"])

    def test_tape_write_progress_reports_live_speed_and_cassette_totals(self) -> None:
        times = iter((10.0, 11.0, 13.0))
        events: list[dict] = []
        reporter = TapeWriteProgress(
            job_id="JOB1",
            sequence=2,
            physical_label="LIVE02",
            cassette_planned_bytes=1000,
            job_copied_bytes=500,
            job_planned_bytes=2000,
            callback=events.append,
            clock=lambda: next(times),
        )

        reporter({"event": "file.start", "relative_path": "large.mxf", "size": 400})
        reporter({"event": "file.progress", "relative_path": "large.mxf", "copied_bytes": 100})
        reporter({"event": "file.progress", "relative_path": "large.mxf", "copied_bytes": 300})

        live = events[-1]
        self.assertEqual(300, live["cassette_copied_bytes"])
        self.assertEqual(800, live["job_copied_bytes"])
        self.assertEqual(100.0, live["write_bps"])
        self.assertEqual(100.0, live["average_write_bps"])
        self.assertEqual(40.0, live["job_progress_percent"])

    def test_tape_write_progress_recalculates_effective_average_during_close(self) -> None:
        times = iter((0.0, 10.0, 20.0))
        events: list[dict] = []
        reporter = TapeWriteProgress(
            job_id="JOB1",
            sequence=2,
            physical_label="LIVE02",
            cassette_planned_bytes=2_000,
            job_copied_bytes=500,
            job_planned_bytes=4_000,
            callback=events.append,
            clock=lambda: next(times),
        )

        reporter({"event": "file.start", "relative_path": "large.mxf", "size": 2_000})
        reporter({"event": "file.progress", "relative_path": "large.mxf", "copied_bytes": 1_000})
        reporter({
            "event": "file.activity",
            "phase": "close.pending",
            "relative_path": "large.mxf",
        })

        closing = events[-1]
        self.assertEqual(20.0, closing["cassette_elapsed_seconds"])
        self.assertEqual(50.0, closing["average_write_bps"])
        self.assertEqual(20.0, closing["cassette_eta_seconds"])
        self.assertEqual(50.0, closing["job_eta_seconds"])

    def test_tape_write_progress_has_no_eta_before_the_first_confirmed_byte(self) -> None:
        times = iter((5.0, 15.0))
        events: list[dict] = []
        reporter = TapeWriteProgress(
            job_id="JOB1",
            sequence=1,
            physical_label="LIVE01",
            cassette_planned_bytes=2_000,
            job_copied_bytes=0,
            job_planned_bytes=4_000,
            callback=events.append,
            clock=lambda: next(times),
        )

        reporter({"event": "file.start", "relative_path": "large.mxf", "size": 2_000})
        reporter({
            "event": "file.activity",
            "phase": "close.pending",
            "relative_path": "large.mxf",
        })

        waiting = events[-1]
        self.assertEqual(10.0, waiting["cassette_elapsed_seconds"])
        self.assertEqual(0.0, waiting["average_write_bps"])
        self.assertIsNone(waiting["cassette_eta_seconds"])
        self.assertIsNone(waiting["job_eta_seconds"])

    def test_cassette_eta_uses_the_planned_payload_not_physical_free_space(self) -> None:
        times = iter((0.0, 10.0))
        events: list[dict] = []
        reporter = TapeWriteProgress(
            job_id="JOB1",
            sequence=1,
            physical_label="LIVE01",
            cassette_planned_bytes=2_000,
            job_copied_bytes=0,
            job_planned_bytes=2_000,
            callback=events.append,
            clock=lambda: next(times),
        )

        reporter({
            "event": "tape.capacity",
            "total_bytes": 20_000,
            "free_bytes": 10_000,
            "usable_bytes": 9_000,
        })
        reporter({"event": "file.start", "relative_path": "large.mxf", "size": 2_000})
        reporter({"event": "file.progress", "relative_path": "large.mxf", "copied_bytes": 1_000})

        self.assertEqual(10.0, events[-1]["cassette_eta_seconds"])

    def test_tape_write_progress_reports_current_ltfs_capacity(self) -> None:
        events: list[dict] = []
        reporter = TapeWriteProgress(
            job_id="JOB1",
            sequence=1,
            physical_label="LIVE01",
            cassette_planned_bytes=1000,
            job_copied_bytes=0,
            job_planned_bytes=1000,
            callback=events.append,
            clock=lambda: 10.0,
        )

        reporter({
            "event": "tape.capacity",
            "total_bytes": 2500,
            "free_bytes": 2400,
            "ltfs_data_free_bytes": 2300,
            "usable_bytes": 2200,
            "reserve_bytes": 200,
            "application_limit_bytes": 2300,
            "ltfs_overhead_bytes": 100,
        })
        reporter({"event": "file.start", "relative_path": "large.mxf", "size": 400})
        reporter({"event": "file.progress", "relative_path": "large.mxf", "copied_bytes": 300})

        live = events[-1]
        self.assertEqual(2500, live["tape_total_bytes"])
        self.assertEqual(2300, live["tape_initial_free_bytes"])
        self.assertEqual(2200, live["tape_usable_bytes"])
        self.assertEqual(1800, live["tape_remaining_bytes"])
        self.assertEqual(100, live["tape_ltfs_overhead_bytes"])
        self.assertEqual(200, live["tape_reserve_bytes"])
        self.assertAlmostEqual(400 * 100 / 2200, live["tape_used_percent"])

    def test_cancel_during_write_ejects_and_restarts_entire_cassette(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = FakeStoreOpen()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("LIVE01", "LIVE01", 2, 20)], force_format=True,
                )

            def cancelled_backup(_libraries, label, _mount, callback, _stop_requested):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.register_tape(
                        label, label, label, "LTFS", "M:\\", cassette_number=label
                    )
                    catalog.create_block("BLOCK-LIVE", "LIB1", label, "live", 2, 20)
                    catalog.record_file_version(
                        "LIB1", "BLOCK-LIVE", label, "first.bin", "live/first.bin",
                        8, 1, "a" * 64,
                    )
                if callback:
                    callback({"event": "file.start", "relative_path": "second.bin", "size": 12})
                    callback({"event": "file.progress", "relative_path": "second.bin", "copied_bytes": 4})
                raise OperationCancelled("Interrotta dall'operatore")

            events: list[dict] = []
            runner = AutomaticJobRunner(
                paths, Settings(), storeopen=storeopen, backup=cancelled_backup
            )
            runner.run("JOB1", progress=events.append, stop_requested=lambda: False)

            self.assertEqual(1, sum(call[0] == "eject" for call in storeopen.calls))
            self.assertEqual("automatic.paused", events[-1]["event"])
            self.assertTrue(events[-1]["restart_cassette"])
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])
                cassette = catalog.list_automatic_cassettes("JOB1")[0]
                self.assertEqual("pending", cassette["status"])
                self.assertEqual(0, cassette["copied_files"])
                self.assertEqual([], catalog.list_tapes())
                self.assertEqual([], catalog.list_blocks(include_forgotten=True))

    def test_storeopen_mapping_service_rejects_foreign_mapping_and_owns_lifecycle(self) -> None:
        service_class = getattr(automation, "WindowsStoreOpenMappingService", None)
        self.assertIsNotNone(service_class, "manca il gestore delle mappature StoreOpen")

        class FakePlatform:
            def __init__(self) -> None:
                self.mappings: dict[str, object] = {}
                self.state = "stopped"

            def list_mappings(self):
                return dict(self.mappings)

            def service_state(self):
                return self.state

            def mapping_visible(self, _letter) -> bool:
                return False

            def write_mapping(self, mapping) -> None:
                self.mappings[mapping.letter] = mapping

            def delete_mapping(self, letter) -> None:
                del self.mappings[letter]

            def start_service(self) -> None:
                self.state = "running"

            def stop_service(self) -> None:
                self.state = "stopped"

        platform = FakePlatform()
        service = service_class(platform=platform)
        service.create_mapping(
            "L", "TAPE0", "DRIVE-SERIAL-42",
            '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" L: -o devname=TAPE0 -d',
        )
        service.start()

        mapping = platform.mappings["L"]
        self.assertEqual("DRIVE-SERIAL-42", mapping.serial_number)
        self.assertEqual("running", platform.state)

        service.stop()
        service.remove_mapping("L")
        self.assertEqual({}, platform.mappings)
        self.assertEqual("stopped", platform.state)

        platform.mappings["M"] = automation.StoreOpenMapping(
            "M", "OTHER-TAPE", "OTHER-SERIAL", "external command"
        )
        with self.assertRaisesRegex(ValidationError, "[Ee]siston"):
            service_class(platform=platform).create_mapping(
                "L", "TAPE0", "OTHER",
                '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" L: -o devname=TAPE0 -d',
            )

    def test_storeopen_mapping_service_cleans_its_stale_mapping_before_create(self) -> None:
        class FakePlatform:
            def __init__(self) -> None:
                self.state = "running"
                self.visible = {"L"}
                self.deleted: list[str] = []
                stale = automation.StoreOpenMapping(
                    "L", "TAPE0", "DRIVE-SERIAL-42",
                    '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" L: '
                    "-o devname=TAPE0 -o sync_type=unmount -d",
                )
                object.__setattr__(stale, "managed_by", "LTOArchiver")
                self.mappings = {
                    "L": stale
                }

            def list_mappings(self):
                return dict(self.mappings)

            def service_state(self):
                return self.state

            def mapping_visible(self, letter) -> bool:
                return letter in self.visible

            def write_mapping(self, mapping) -> None:
                self.mappings[mapping.letter] = mapping

            def delete_mapping(self, letter) -> None:
                self.deleted.append(letter)
                del self.mappings[letter]

            def start_service(self) -> None:
                self.state = "running"

            def stop_service(self) -> None:
                self.state = "stopped"
                self.visible.clear()

        platform = FakePlatform()
        service = automation.WindowsStoreOpenMappingService(platform=platform)

        service.create_mapping(
            "M", "TAPE0", "DRIVE-SERIAL-42",
            '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" M: '
            "-o devname=TAPE0 -o sync_type=unmount -d",
        )

        self.assertEqual("stopped", platform.state)
        self.assertEqual(["L"], platform.deleted)
        self.assertEqual({"M"}, set(platform.mappings))
        self.assertEqual("LTOArchiver", platform.mappings["M"].managed_by)

    def test_storeopen_mapping_service_cleans_matching_legacy_mapping(self) -> None:
        class FakePlatform:
            def __init__(self) -> None:
                self.state = "stopped"
                self.deleted: list[str] = []
                self.mappings = {
                    "L": automation.StoreOpenMapping(
                        "L", "TAPE0", "DRIVE-SERIAL-42",
                        '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" L: '
                        "-o devname=TAPE0 -o sync_type=unmount -d",
                    )
                }

            def list_mappings(self):
                return dict(self.mappings)

            def service_state(self):
                return self.state

            def mapping_visible(self, _letter) -> bool:
                return False

            def write_mapping(self, mapping) -> None:
                self.mappings[mapping.letter] = mapping

            def delete_mapping(self, letter) -> None:
                self.deleted.append(letter)
                del self.mappings[letter]

            def start_service(self) -> None:
                self.state = "running"

            def stop_service(self) -> None:
                self.state = "stopped"

        platform = FakePlatform()
        service = automation.WindowsStoreOpenMappingService(platform=platform)

        service.create_mapping(
            "M", "TAPE0", "DRIVE-SERIAL-42",
            '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" M: '
            "-o devname=TAPE0 -o sync_type=unmount -d",
        )

        self.assertEqual(["L"], platform.deleted)
        self.assertEqual({"M"}, set(platform.mappings))

    def test_storeopen_mapping_service_recycles_stopped_service_for_stuck_drive(self) -> None:
        class FakePlatform:
            def __init__(self) -> None:
                self.state = "stopped"
                self.visible = {"L"}
                self.service_calls: list[str] = []
                stale = automation.StoreOpenMapping(
                    "L", "TAPE0", "DRIVE-SERIAL-42",
                    '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" L: '
                    "-o devname=TAPE0 -o sync_type=unmount -d",
                )
                object.__setattr__(stale, "managed_by", "LTOArchiver")
                self.mappings = {"L": stale}

            def list_mappings(self):
                return dict(self.mappings)

            def service_state(self):
                return self.state

            def mapping_visible(self, letter) -> bool:
                visible = letter in self.visible
                self.visible.discard(letter)
                return visible

            def write_mapping(self, mapping) -> None:
                self.mappings[mapping.letter] = mapping

            def delete_mapping(self, letter) -> None:
                del self.mappings[letter]

            def start_service(self) -> None:
                self.service_calls.append("start")
                self.state = "running"

            def stop_service(self) -> None:
                self.service_calls.append("stop")
                self.state = "stopped"
                self.visible.clear()

        platform = FakePlatform()
        service = automation.WindowsStoreOpenMappingService(platform=platform)

        service.create_mapping(
            "M", "TAPE0", "DRIVE-SERIAL-42",
            '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" M: '
            "-o devname=TAPE0 -o sync_type=unmount -d",
        )

        self.assertEqual(["start", "stop"], platform.service_calls)
        self.assertEqual({"M"}, set(platform.mappings))

    def test_storeopen_mapping_service_does_not_clean_foreign_mapping(self) -> None:
        class FakePlatform:
            def __init__(self) -> None:
                self.state = "stopped"
                self.deleted: list[str] = []
                self.mappings = {
                    "L": automation.StoreOpenMapping(
                        "L", "OTHER-TAPE", "OTHER-SERIAL", "external command"
                    )
                }

            def list_mappings(self):
                return dict(self.mappings)

            def service_state(self):
                return self.state

            def mapping_visible(self, _letter) -> bool:
                return False

            def write_mapping(self, mapping) -> None:
                self.mappings[mapping.letter] = mapping

            def delete_mapping(self, letter) -> None:
                self.deleted.append(letter)

            def start_service(self) -> None:
                self.state = "running"

            def stop_service(self) -> None:
                self.state = "stopped"

        platform = FakePlatform()
        service = automation.WindowsStoreOpenMappingService(platform=platform)

        with self.assertRaisesRegex(ValidationError, "[Ee]siston"):
            service.create_mapping(
                "M", "TAPE0", "DRIVE-SERIAL-42",
                '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" M: '
                "-o devname=TAPE0 -o sync_type=unmount -d",
            )

        self.assertEqual([], platform.deleted)
        self.assertEqual({"L"}, set(platform.mappings))

    def test_scsi_vpd_parser_returns_runtime_drive_serial(self) -> None:
        parser = getattr(automation, "parse_unit_serial_vpd", None)
        self.assertIsNotNone(parser, "manca il parser della pagina VPD 0x80")
        payload = bytes([0x01, 0x80, 0x00, 0x0A]) + b"HU14131E8L"

        self.assertEqual("HU14131E8L", parser(payload))

    def test_mount_uses_service_mapping_with_runtime_drive_serial(self) -> None:
        class FakeDevice:
            def read_unit_serial(self) -> str:
                return "DRIVE-SERIAL-42"

        class FakeMappingService:
            def __init__(self) -> None:
                self.calls: list[tuple] = []

            def create_mapping(self, letter, device_name, serial, command) -> None:
                self.calls.append(("create", letter, device_name, serial, command))

            def start(self) -> None:
                self.calls.append(("start",))

        with tempfile.TemporaryDirectory() as temporary:
            install_dir = Path(temporary)
            executable = install_dir / "ltfs.exe"
            executable.write_bytes(b"")
            service = FakeMappingService()
            controller = StoreOpenController(
                "TAPE0", Path("L:\\"), Path(temporary) / "state",
                install_dir=install_dir,
            )
            controller.device = FakeDevice()
            controller.mapping_service = service
            running_process = Mock()
            running_process.poll.return_value = None
            mounted = VolumeInfo(
                root=Path("L:\\"), filesystem="LTFS", label="IR1821",
                serial="12345678", total_bytes=1000, free_bytes=900,
            )

            with (
                patch("ltobackup.automation.subprocess.Popen", return_value=running_process) as popen,
                patch("ltobackup.automation.inspect_volume", return_value=mounted),
            ):
                self.assertEqual(Path("L:\\"), controller.mount(lambda: False))

            popen.assert_not_called()
            self.assertIs(mounted, controller.mounted_volume)
            self.assertEqual(
                [
                    (
                        "create", "L", "TAPE0", "DRIVE-SERIAL-42",
                        f'"{executable}" L: -o devname=TAPE0 '
                        "-o sync_type=unmount -d",
                    ),
                    ("start",),
                ],
                service.calls,
            )

    def test_runner_reuses_volume_already_inspected_during_mount(self) -> None:
        class CachedVolumeStoreOpen(FakeStoreOpen):
            def __init__(self) -> None:
                super().__init__()
                self.mounted_volume = VolumeInfo(
                    root=Path("M:\\"), filesystem="LTFS", label="AB1234",
                    serial="12345678", total_bytes=2500, free_bytes=2400,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = CachedVolumeStoreOpen()
            received: list[object] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=lambda _libraries, _label, mounted, _progress, _stop: received.append(mounted)
                or {
                    "status": "completed", "block_id": "BLOCK1",
                    "copied_files": 1, "copied_bytes": 10, "remaining_files": 0,
                },
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual([storeopen.mounted_volume], received)

    def test_unmount_stops_service_removes_mapping_then_ejects(self) -> None:
        calls: list[tuple] = []

        class FakeDevice:
            def unload(self) -> None:
                calls.append(("unload",))

        class FakeMappingService:
            def stop(self) -> None:
                calls.append(("stop",))

            def remove_mapping(self, letter) -> None:
                calls.append(("remove", letter))

        controller = StoreOpenController("TAPE0", Path("L:\\"), Path("C:\\state"))
        controller.device = FakeDevice()
        controller.mapping_service = FakeMappingService()
        controller.mount_path = Path("L:\\")
        controller.mapping_active = True

        with patch("ltobackup.automation._mount_path_visible", return_value=False):
            controller.unmount_and_eject()

        self.assertEqual([("stop",), ("remove", "L"), ("unload",)], calls)

    def test_unmount_reports_each_real_finalization_stage(self) -> None:
        class FakeDevice:
            def unload(self) -> None:
                pass

        class FakeMappingService:
            def stop(self) -> None:
                pass

            def remove_mapping(self, _letter) -> None:
                pass

        controller = StoreOpenController("TAPE0", Path("L:\\"), Path("C:\\state"))
        controller.device = FakeDevice()
        controller.mapping_service = FakeMappingService()
        controller.mount_path = Path("L:\\")
        controller.mapping_active = True
        events: list[dict] = []

        with patch("ltobackup.automation._mount_path_visible", return_value=False):
            controller.unmount_and_eject(progress=events.append)

        self.assertEqual(
            [
                ("index_sync", "pending"),
                ("index_sync", "complete"),
                ("mapping_release", "pending"),
                ("mapping_release", "complete"),
                ("eject", "pending"),
                ("eject", "complete"),
            ],
            [(event["stage"], event["status"]) for event in events],
        )
        self.assertEqual([1, 1, 2, 2, 3, 3], [event["stage_number"] for event in events])
        self.assertTrue(all(event["stage_total"] == 3 for event in events))

    def test_storeopen_service_stop_has_no_deadline_while_index_is_flushed(self) -> None:
        platform = automation.WindowsStoreOpenPlatform()
        states = iter(["running", *(["stop_pending"] * 181), "stopped"])
        stopped = subprocess.CompletedProcess(["sc.exe", "stop"], 0, "", "")

        with (
            patch.object(platform, "service_state", side_effect=states),
            patch.object(platform, "_run_sc", return_value=stopped),
            patch("ltobackup.automation.time.monotonic", side_effect=AssertionError("deadline")),
            patch("ltobackup.automation.time.sleep"),
        ):
            platform.stop_service()

    def test_unmount_waits_for_drive_letter_removal_without_deadline(self) -> None:
        calls: list[tuple] = []

        class FakeDevice:
            def unload(self) -> None:
                calls.append(("unload",))

        class FakeMappingService:
            def stop(self) -> None:
                calls.append(("stop",))

            def remove_mapping(self, letter) -> None:
                calls.append(("remove", letter))

        controller = StoreOpenController("TAPE0", Path("L:\\"), Path("C:\\state"))
        controller.device = FakeDevice()
        controller.mapping_service = FakeMappingService()
        controller.mount_path = Path("L:\\")
        controller.mapping_active = True

        with (
            patch("ltobackup.automation._mount_path_visible", side_effect=[True, True, False]),
            patch("ltobackup.automation.time.monotonic", side_effect=AssertionError("deadline")),
            patch("ltobackup.automation.time.sleep"),
        ):
            controller.unmount_and_eject()

        self.assertEqual([("stop",), ("remove", "L"), ("unload",)], calls)

    def test_failed_physical_eject_can_be_retried_after_mapping_is_removed(self) -> None:
        calls: list[tuple] = []

        class RetryDevice:
            attempts = 0

            def unload(self) -> None:
                self.attempts += 1
                calls.append(("unload", self.attempts))
                if self.attempts == 1:
                    raise CopyError("espulsione temporaneamente fallita")

        class FakeMappingService:
            def stop(self) -> None:
                calls.append(("stop",))

            def remove_mapping(self, letter) -> None:
                calls.append(("remove", letter))

        controller = StoreOpenController("TAPE0", Path("L:\\"), Path("C:\\state"))
        controller.device = RetryDevice()
        controller.mapping_service = FakeMappingService()
        controller.mount_path = Path("L:\\")
        controller.mapping_active = True

        with patch("ltobackup.automation._mount_path_visible", return_value=False):
            with self.assertRaisesRegex(CopyError, "temporaneamente fallita"):
                controller.unmount_and_eject()
            controller.unmount_and_eject()

        self.assertEqual(
            [("stop",), ("remove", "L"), ("unload", 1), ("unload", 2)],
            calls,
        )

    def test_mount_never_calls_blocking_path_exists_on_ltfs_volume(self) -> None:
        class FakeDevice:
            def read_unit_serial(self) -> str:
                return "DRIVE-SERIAL-42"

        class FakeMappingService:
            def create_mapping(self, *_args) -> None:
                pass

            def start(self) -> None:
                pass

        with tempfile.TemporaryDirectory() as temporary:
            install_dir = Path(temporary)
            (install_dir / "ltfs.exe").write_bytes(b"")
            controller = StoreOpenController(
                "TAPE0", Path("L:\\"), Path(temporary) / "state",
                install_dir=install_dir,
            )
            controller.device = FakeDevice()
            controller.mapping_service = FakeMappingService()
            mounted = VolumeInfo(
                root=Path("L:\\"), filesystem="LTFS", label="IR1821",
                serial="12345678", total_bytes=1000, free_bytes=900,
            )

            with (
                patch("ltobackup.automation.inspect_volume", return_value=mounted),
                patch("pathlib.Path.exists", side_effect=AssertionError("blocking Path.exists")),
            ):
                self.assertEqual(Path("L:\\"), controller.mount(lambda: False))

    def test_unmount_completion_never_calls_blocking_path_exists(self) -> None:
        class FakeDevice:
            def unload(self) -> None:
                pass

        class FakeMappingService:
            def stop(self) -> None:
                pass

            def remove_mapping(self, _letter) -> None:
                pass

        controller = StoreOpenController("TAPE0", Path("L:\\"), Path("C:\\state"))
        controller.device = FakeDevice()
        controller.mapping_service = FakeMappingService()
        controller.mapping_active = True

        with (
            patch("ltobackup.automation._used_drive_letters", return_value={"C"}),
            patch("pathlib.Path.exists", side_effect=AssertionError("blocking Path.exists")),
        ):
            controller.unmount_and_eject()

    def test_windows_volume_probe_reports_timeout_instead_of_blocking(self) -> None:
        class HungProbe:
            pid = 4321
            returncode = None
            tree_alive = True

            def communicate(self, timeout=None):
                if self.tree_alive:
                    raise subprocess.TimeoutExpired(["volume-probe"], timeout)
                self.returncode = 1
                return "", ""

            def kill(self):
                self.tree_alive = False
                self.returncode = 1

        probe = HungProbe()

        def terminate_tree(command, **_kwargs):
            if command == ["taskkill.exe", "/PID", "4321", "/T", "/F"]:
                probe.tree_alive = False
                probe.returncode = 1
                return subprocess.CompletedProcess(command, 0, "", "")
            raise subprocess.TimeoutExpired(command, 30)

        with (
            patch("ltobackup.volume.subprocess.Popen", return_value=probe),
            patch("ltobackup.volume.subprocess.run", side_effect=terminate_tree),
        ):
            with self.assertRaisesRegex(ValidationError, "non risponde entro 30 secondi"):
                inspect_volume(Path("L:\\"))

        self.assertFalse(probe.tree_alive, "il processo figlio del probe e rimasto attivo")

    def test_windows_volume_probe_does_not_depend_on_powershell(self) -> None:
        process = Mock()
        process.returncode = 0
        process.communicate.return_value = (
            '{"filesystem":"LTFS","label":"IR1821","serial":"12345678",'
            '"total_bytes":1000,"free_bytes":900}',
            "",
        )
        with patch("ltobackup.volume.subprocess.Popen", return_value=process) as popen:
            volume = inspect_volume(Path("L:\\"))

        command = popen.call_args.args[0]
        self.assertNotIn("powershell", " ".join(command).casefold())
        self.assertEqual("LTFS", volume.filesystem)
        self.assertEqual(900, volume.free_bytes)

    def test_windows_volume_probe_preserves_native_ltfs_partition_capacity(self) -> None:
        process = Mock()
        process.returncode = 0
        process.communicate.return_value = (
            '{"filesystem":"LTFS","label":"IR1821","serial":"12345678",'
            '"total_bytes":2500000000000,"free_bytes":9000000000,'
            '"ltfs_data_total_bytes":2410000000000,'
            '"ltfs_data_free_bytes":7340032000}',
            "",
        )
        with patch("ltobackup.volume.subprocess.Popen", return_value=process):
            volume = inspect_volume(Path("L:\\"))

        self.assertEqual(2_410_000_000_000, volume.ltfs_data_total_bytes)
        self.assertEqual(7_340_032_000, volume.ltfs_data_free_bytes)

    def test_windows_volume_probe_reports_process_tree_cleanup_failure(self) -> None:
        process = Mock()
        process.pid = 7654
        process.communicate.side_effect = [
            subprocess.TimeoutExpired(["volume-probe"], 30),
            subprocess.TimeoutExpired(["volume-probe"], 10),
        ]
        taskkill = subprocess.CompletedProcess(
            ["taskkill.exe", "/PID", "7654", "/T", "/F"],
            1,
            "",
            "Accesso negato",
        )

        with (
            patch("ltobackup.volume.subprocess.Popen", return_value=process),
            patch("ltobackup.volume.subprocess.run", return_value=taskkill),
        ):
            with self.assertRaisesRegex(
                ValidationError, "arresto dell'albero del probe non riuscito: Accesso negato"
            ):
                inspect_volume(Path("L:\\"))

    def test_mount_service_failure_is_cleaned_up_and_reported(self) -> None:
        calls: list[str] = []

        class FakeDevice:
            def read_unit_serial(self) -> str:
                return "DRIVE-SERIAL-42"

            def unload(self) -> None:
                calls.append("unload")

        class FailingMappingService:
            def create_mapping(self, *_args) -> None:
                calls.append("create")

            def start(self) -> None:
                calls.append("start")
                raise CopyError("avvio servizio HPE fallito")

            def stop(self) -> None:
                calls.append("stop")

            def remove_mapping(self, _letter) -> None:
                calls.append("remove")

        with tempfile.TemporaryDirectory() as temporary:
            install_dir = Path(temporary)
            (install_dir / "ltfs.exe").write_bytes(b"")
            controller = StoreOpenController(
                "TAPE0", Path("L:\\"), Path(temporary) / "state",
                install_dir=install_dir,
            )
            controller.device = FakeDevice()
            controller.mapping_service = FailingMappingService()

            with patch("ltobackup.automation._mount_path_visible", return_value=False):
                with self.assertRaisesRegex(CopyError, "avvio servizio HPE fallito"):
                    controller.mount(lambda: False)

        self.assertEqual(["create", "start", "stop", "remove", "unload"], calls)

    def test_format_timeout_is_reported_as_copy_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            install_dir = Path(temporary)
            (install_dir / "mkltfs.exe").write_bytes(b"")
            controller = StoreOpenController(
                "TAPE0",
                Path("AUTO"),
                Path(temporary) / "state",
                install_dir=install_dir,
                format_timeout_seconds=0.1,
            )

            with patch(
                "ltobackup.automation.subprocess.run",
                side_effect=subprocess.TimeoutExpired(["mkltfs.exe"], 0.1),
            ) as run:
                with self.assertRaisesRegex(CopyError, "tempo massimo"):
                    controller.format(CassetteLabel("AB1234L6", "AB1234"))

            self.assertEqual(0.1, run.call_args.kwargs["timeout"])

    def test_format_releases_stale_owned_storeopen_mapping_before_mkltfs(self) -> None:
        class FakePlatform:
            def __init__(self) -> None:
                self.state = "running"
                self.visible = {"L"}
                self.mappings = {
                    "L": automation.StoreOpenMapping(
                        "L",
                        "TAPE0",
                        "DRIVE-SERIAL-42",
                        '"C:\\Program Files\\HPE\\LTFS\\ltfs.exe" L: '
                        "-o devname=TAPE0 -o sync_type=unmount -d",
                        "LTOArchiver",
                    )
                }

            def list_mappings(self):
                return dict(self.mappings)

            def service_state(self):
                return self.state

            def mapping_visible(self, letter) -> bool:
                return letter in self.visible

            def write_mapping(self, mapping) -> None:
                self.mappings[mapping.letter] = mapping

            def delete_mapping(self, letter) -> None:
                del self.mappings[letter]

            def start_service(self) -> None:
                self.state = "running"

            def stop_service(self) -> None:
                self.state = "stopped"
                self.visible.clear()

        with tempfile.TemporaryDirectory() as temporary:
            install_dir = Path(temporary)
            (install_dir / "mkltfs.exe").write_bytes(b"")
            platform = FakePlatform()
            controller = StoreOpenController(
                "TAPE0",
                Path("AUTO"),
                Path(temporary) / "state",
                install_dir=install_dir,
            )
            controller.mapping_service = automation.WindowsStoreOpenMappingService(
                platform=platform
            )

            def run_formatter(*_args, **_kwargs):
                self.assertEqual("stopped", platform.state)
                self.assertEqual({}, platform.mappings)
                return subprocess.CompletedProcess([], 0, "", "")

            with patch(
                "ltobackup.automation.subprocess.run", side_effect=run_formatter
            ):
                controller.format(CassetteLabel("AB1234L6", "AB1234"))

    def test_storeopen_force_format_requires_explicit_destructive_option(self) -> None:
        safe = StoreOpenController("TAPE0", Path("AUTO"), Path("C:\\state"))
        destructive = StoreOpenController(
            "TAPE0", Path("AUTO"), Path("C:\\state"), force_format=True
        )
        safe_command = safe.format_command(CassetteLabel("AB1234L6", "AB1234"))
        destructive_command = destructive.format_command(CassetteLabel("AB1234L6", "AB1234"))

        self.assertNotIn("--force", safe_command)
        self.assertIn("--force", destructive_command)
        self.assertEqual(["-s", "AB1234", "-n", "AB1234L6"], destructive_command[-4:])

    def test_automatic_mount_chooses_a_free_drive_letter(self) -> None:
        self.assertEqual(Path("M:\\"), choose_mount_path(Path("AUTO"), {"C", "D", "L"}))
        self.assertEqual(Path("R:\\"), choose_mount_path(Path("R:\\"), {"C", "D", "L"}))
        with self.assertRaisesRegex(Exception, "gia in uso"):
            choose_mount_path(Path("R:\\"), {"C", "D", "R"})

    def test_normalizes_six_character_and_lto6_barcode_labels(self) -> None:
        labels = normalize_cassette_labels([" ab1234 ", "CD5678L6"])

        self.assertEqual(
            [CassetteLabel("AB1234", "AB1234"), CassetteLabel("CD5678L6", "CD5678")],
            labels,
        )
        with self.assertRaisesRegex(Exception, "duplicata"):
            normalize_cassette_labels(["AB1234", "AB1234L6"])
        with self.assertRaisesRegex(Exception, "LTO-6"):
            normalize_cassette_labels(["AB1234L5"])

    def test_normalizes_barcode_for_the_selected_media_generation(self) -> None:
        self.assertEqual(
            [CassetteLabel("AB1234L5", "AB1234")],
            normalize_cassette_labels(["AB1234L5"], media_key="LTO-5"),
        )
        self.assertEqual(
            [CassetteLabel("AB1234LA", "AB1234")],
            normalize_cassette_labels(["AB1234LA"], media_key="LTO-10 LA"),
        )
        self.assertEqual(
            [CassetteLabel("AB1234PA", "AB1234")],
            normalize_cassette_labels(["AB1234PA"], media_key="LTO-10 PA"),
        )
        with self.assertRaisesRegex(Exception, "LTO-5"):
            normalize_cassette_labels(["AB1234L6"], media_key="LTO-5")

    def test_runner_processes_each_cassette_in_order_and_ejects_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = FakeStoreOpen()
            backed_up: list[tuple[list[str], str, Path]] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.add_library("LIB2", "Library 2", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 100), ("CD5678L6", "CD5678", 1, 80)],
                    library_ids=["LIB1", "LIB2"],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=lambda libraries, label, mount, _progress, _stop: backed_up.append((libraries, label, mount))
                or {"status": "completed", "block_id": "B-" + label, "copied_files": 1, "copied_bytes": 10},
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual(
                [
                    (["LIB1", "LIB2"], "AB1234", Path("M:\\")),
                    (["LIB1", "LIB2"], "CD5678L6", Path("M:\\")),
                ],
                backed_up,
            )
            self.assertEqual(2, sum(1 for call in storeopen.calls if call[0] == "eject"))
            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                steps = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("completed", job["status"])
                self.assertEqual(["completed", "completed"], [row["status"] for row in steps])

    def test_runner_forwards_unmount_subphases_with_job_context(self) -> None:
        class ProgressStoreOpen(FakeStoreOpen):
            def __init__(inner_self) -> None:
                super().__init__()
                inner_self.unmount_progress = None

            def set_unmount_progress(inner_self, callback) -> None:
                inner_self.unmount_progress = callback

            def unmount_and_eject(inner_self) -> None:
                inner_self.unmount_progress({
                    "event": "unmount.progress",
                    "stage": "index_sync",
                    "status": "pending",
                    "stage_number": 1,
                    "stage_total": 3,
                    "elapsed_seconds": 12.0,
                })
                inner_self.unmount_progress({
                    "event": "unmount.progress",
                    "stage": "index_sync",
                    "status": "complete",
                    "stage_number": 1,
                    "stage_total": 3,
                    "elapsed_seconds": 18.0,
                })
                super().unmount_and_eject()

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = ProgressStoreOpen()
            events: list[dict] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10)],
                )

            def backup(_libraries, _label, _mount, tape_progress, _stop):
                tape_progress({"event": "file.start", "relative_path": "payload.bin"})
                tape_progress({
                    "event": "file.progress",
                    "relative_path": "payload.bin",
                    "copied_bytes": 10,
                })
                return {
                    "status": "completed", "block_id": "BLOCK1",
                    "copied_files": 1, "copied_bytes": 10,
                }

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=backup,
            )
            runner.run("JOB1", progress=events.append, stop_requested=lambda: False)
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                persisted_timings = [
                    json.loads(row["payload_json"])
                    for row in catalog.connection.execute(
                        "SELECT payload_json FROM events "
                        "WHERE action='automatic.unmount.timing' ORDER BY id"
                    )
                ]

        unmount = [event for event in events if event.get("event") == "unmount.progress"]
        self.assertEqual(["pending", "complete"], [event["status"] for event in unmount])
        self.assertTrue(all(event["job_id"] == "JOB1" for event in unmount))
        self.assertTrue(all(event["physical_label"] == "AB1234" for event in unmount))
        self.assertTrue(all("average_write_bps" in event for event in unmount))
        self.assertTrue(all("cassette_elapsed_seconds" in event for event in unmount))
        self.assertEqual(1, len(persisted_timings))
        self.assertEqual("index_sync", persisted_timings[0]["stage"])
        self.assertEqual(18.0, persisted_timings[0]["elapsed_seconds"])

    def test_runner_commits_catalog_blocks_only_after_successful_unmount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()

            class CommitAwareStoreOpen(FakeStoreOpen):
                def unmount_and_eject(inner_self) -> None:
                    with Catalog(paths.catalog_file) as catalog:
                        catalog.initialize()
                        block = catalog.list_blocks(include_forgotten=True)[0]
                        self.assertEqual("copying", block["status"])
                        self.assertEqual({}, catalog.latest_versions("LIB1"))
                    super().unmount_and_eject()

            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )

            def backup(_libraries, label, _mount, _progress, _stop):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.register_tape(
                        label, label, label, "LTFS", "M:\\", cassette_number=label
                    )
                    catalog.create_block("BLOCK1", "LIB1", label, "blocks/BLOCK1", 1, 10)
                    catalog.record_file_version(
                        "LIB1", "BLOCK1", label, "file.bin", "blocks/BLOCK1/file.bin",
                        10, 1, "a" * 64,
                    )
                return {
                    "status": "pending-commit",
                    "commit_required": True,
                    "block_id": "BLOCK1",
                    "block_ids": ["BLOCK1"],
                    "copied_files": 1,
                    "copied_bytes": 10,
                    "remaining_files": 0,
                }

            runner = AutomaticJobRunner(
                paths, Settings(), storeopen=CommitAwareStoreOpen(), backup=backup
            )
            runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual("completed", catalog.list_blocks()[0]["status"])
                self.assertEqual(["file.bin"], list(catalog.latest_versions("LIB1")))

    def test_runner_marks_staged_blocks_failed_when_unmount_fails(self) -> None:
        class FailingUnmount(FakeStoreOpen):
            def unmount_and_eject(self) -> None:
                self.calls.append(("eject",))
                raise CopyError("unmount failed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )

            def backup(_libraries, label, _mount, _progress, _stop):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.register_tape(
                        label, label, label, "LTFS", "M:\\", cassette_number=label
                    )
                    catalog.create_block("BLOCK1", "LIB1", label, "blocks/BLOCK1", 1, 10)
                    catalog.record_file_version(
                        "LIB1", "BLOCK1", label, "file.bin", "blocks/BLOCK1/file.bin",
                        10, 1, "a" * 64,
                    )
                return {
                    "status": "pending-commit",
                    "commit_required": True,
                    "block_id": "BLOCK1",
                    "block_ids": ["BLOCK1"],
                    "copied_files": 1,
                    "copied_bytes": 10,
                }

            runner = AutomaticJobRunner(
                paths, Settings(), storeopen=FailingUnmount(), backup=backup
            )
            with self.assertRaisesRegex(CopyError, "unmount failed"):
                runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                block = catalog.list_blocks(include_forgotten=True)[0]
                self.assertEqual("failed", block["status"])
                self.assertEqual({}, catalog.latest_versions("LIB1"))

    def test_runner_scopes_read_only_telemetry_to_the_write_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = FakeStoreOpen()
            lifecycle: list[str] = []

            class FakeDevice:
                @staticmethod
                def read_telemetry() -> TapeTelemetrySnapshot:
                    return TapeTelemetrySnapshot(available=True)

            class FakeMonitor:
                def __init__(self, _provider, callback):
                    self.callback = callback

                def start(self) -> None:
                    lifecycle.append("telemetry.start")
                    self.callback({
                        "event": "tape.telemetry",
                        "activity": "idle",
                        "available": True,
                    })

                def stop(self) -> None:
                    lifecycle.append("telemetry.stop")

            storeopen.device = FakeDevice()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 100)],
                )

            def backup(_libraries, _label, _mount, _progress, _stop):
                lifecycle.append("backup")
                return {
                    "status": "completed", "block_id": "B1",
                    "copied_files": 1, "copied_bytes": 10,
                }

            events: list[dict] = []
            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=backup,
                telemetry_monitor_factory=FakeMonitor,
            )
            runner.run("JOB1", progress=events.append, stop_requested=lambda: False)

            self.assertEqual(
                ["telemetry.start", "backup", "telemetry.stop"], lifecycle
            )
            telemetry = next(row for row in events if row["event"] == "tape.telemetry")
            self.assertEqual("JOB1", telemetry["job_id"])
            self.assertEqual("AB1234", telemetry["physical_label"])

    def test_runner_keeps_surplus_cassette_unformatted_for_future_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = FakeStoreOpen()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 100), ("CD5678L6", "CD5678", 0, 0)],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=lambda *_args: {
                    "status": "completed",
                    "block_id": "B-AB1234",
                    "copied_files": 1,
                    "copied_bytes": 100,
                    "remaining_files": 0,
                },
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual(
                ["wait", "format", "mount", "eject"],
                [call[0] for call in storeopen.calls],
            )
            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                steps = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("completed", job["status"])
                self.assertEqual(["completed", "pending"], [row["status"] for row in steps])
                self.assertEqual((0, 0), (steps[1]["planned_files"], steps[1]["planned_bytes"]))

    def test_runner_resumes_same_job_from_first_appended_cassette(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = FakeStoreOpen()
            backed_up: list[str] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.append_automatic_cassettes(
                    "JOB1", [("CD5678L6", "CD5678", 1, 20)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=lambda _libraries, label, _mount, _progress, _stop: backed_up.append(label)
                or {
                    "status": "completed",
                    "block_id": "B-" + label,
                    "copied_files": 1,
                    "copied_bytes": 20,
                    "remaining_files": 0,
                },
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual(["CD5678L6"], backed_up)
            self.assertEqual(
                ["wait", "format", "mount", "eject"],
                [call[0] for call in storeopen.calls],
            )
            with Catalog(paths.catalog_file) as catalog:
                self.assertEqual("completed", catalog.get_automatic_job("JOB1")["status"])
                self.assertEqual(
                    ["completed", "completed"],
                    [row["status"] for row in catalog.list_automatic_cassettes("JOB1")],
                )

    def test_runner_mounts_completed_tape_for_append_without_formatting_it(self) -> None:
        class AppendStoreOpen(FakeStoreOpen):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("M:\\")
                self.calls.append(("mount", str(mount_path)))
                self.mounted_volume = VolumeInfo(
                    mount_path, "LTFS", "AB1234", "AB1234", 10_000, 5_000
                )
                return mount_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            storeopen = AppendStoreOpen()
            events: list[dict] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "M:\\",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette(
                    "JOB1", 1, "completed", tape_id="AB1234", copied_files=1, copied_bytes=10
                )
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 20)

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=storeopen,
                backup=lambda *_args: {
                    "status": "completed", "block_id": "B-NEW",
                    "copied_files": 1, "copied_bytes": 20, "remaining_files": 0,
                },
            )
            runner.run("JOB1", progress=events.append, stop_requested=lambda: False)

            self.assertEqual(
                ["wait", "mount", "eject"], [call[0] for call in storeopen.calls]
            )
            self.assertNotIn("automatic.formatting", [event["event"] for event in events])
            with Catalog(paths.catalog_file) as catalog:
                cassette = catalog.list_automatic_cassettes("JOB1")[0]
                self.assertEqual("completed", cassette["status"])
                self.assertEqual("append", cassette["operation"])

    def test_runner_rejects_wrong_tape_identity_before_append_write(self) -> None:
        class WrongTapeStoreOpen(FakeStoreOpen):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("M:\\")
                self.calls.append(("mount", str(mount_path)))
                self.mounted_volume = VolumeInfo(
                    mount_path, "LTFS", "WRONG", "WRONG", 10_000, 5_000
                )
                return mount_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "M:\\",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed", tape_id="AB1234")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 20)

            backup = Mock()
            storeopen = WrongTapeStoreOpen()
            runner = AutomaticJobRunner(
                paths, Settings(), storeopen=storeopen, backup=backup
            )
            with self.assertRaisesRegex(ValidationError, "Nastro errato"):
                runner.run("JOB1", stop_requested=lambda: False)

            backup.assert_not_called()
            self.assertNotIn("format", [call[0] for call in storeopen.calls])

    def test_cancelled_append_preserves_old_tape_and_remains_retryable(self) -> None:
        class AppendStoreOpen(FakeStoreOpen):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("M:\\")
                self.calls.append(("mount", str(mount_path)))
                self.mounted_volume = VolumeInfo(
                    mount_path, "LTFS", "AB1234", "AB1234", 10_000, 5_000
                )
                return mount_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "M:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1", "BLOCK-OLD", "AB1234", "old.bin", "old/old.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    "JOB1", 1, "completed", tape_id="AB1234",
                    block_id="BLOCK-OLD", copied_files=1, copied_bytes=10,
                )
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 20)

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=AppendStoreOpen(),
                backup=lambda *_args: (_ for _ in ()).throw(
                    OperationCancelled("stop append")
                ),
            )
            runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                self.assertEqual(["AB1234"], [row["id"] for row in catalog.list_tapes()])
                self.assertEqual(["BLOCK-OLD"], [row["id"] for row in catalog.list_blocks()])
                self.assertIn("old.bin", catalog.latest_versions("LIB1"))
                cassette = catalog.list_automatic_cassettes("JOB1")[0]
                self.assertEqual(("pending", "append"), (
                    cassette["status"], cassette["operation"]
                ))

    def test_full_append_tape_continues_with_next_new_cassette(self) -> None:
        class MountedStoreOpen(FakeStoreOpen):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("M:\\")
                self.calls.append(("mount", str(mount_path)))
                self.mounted_volume = VolumeInfo(
                    mount_path, "LTFS", "AB1234", "AB1234", 10_000, 0
                )
                return mount_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\",
                    [("AB1234", "AB1234", 1, 10), ("CD5678", "CD5678", 1, 10)],
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "M:\\",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed", tape_id="AB1234")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 10)

            labels: list[str] = []

            def backup(_libraries, label, _mount, _progress, _stop):
                labels.append(label)
                if label == "AB1234":
                    raise CapacityError("nessun file entra nello spazio reale")
                return {
                    "status": "completed", "block_id": "B-NEW",
                    "copied_files": 1, "copied_bytes": 10, "remaining_files": 0,
                }

            storeopen = MountedStoreOpen()
            runner = AutomaticJobRunner(
                paths, Settings(), storeopen=storeopen, backup=backup
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual(["AB1234", "CD5678"], labels)
            self.assertEqual(1, sum(call[0] == "format" for call in storeopen.calls))
            with Catalog(paths.catalog_file) as catalog:
                rows = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual(["completed", "completed"], [row["status"] for row in rows])

    def test_full_append_tape_without_next_cassette_requests_another_label(self) -> None:
        class MountedStoreOpen(FakeStoreOpen):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("M:\\")
                self.calls.append(("mount", str(mount_path)))
                self.mounted_volume = VolumeInfo(
                    mount_path, "LTFS", "AB1234", "AB1234", 10_000, 0
                )
                return mount_path

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "M:\\",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed", tape_id="AB1234")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 10)

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=MountedStoreOpen(),
                backup=lambda *_args: (_ for _ in ()).throw(
                    CapacityError("spazio reale esaurito")
                ),
            )
            runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                self.assertEqual("failed", job["status"])
                self.assertIn("Aggiungere cassette", job["last_error"])

    def test_runner_wait_has_no_retry_limit_and_pause_is_persisted(self) -> None:
        class StopWhileWaiting(FakeStoreOpen):
            def wait_for_media(self, stop_requested) -> bool:
                self.calls.append(("wait",))
                return False

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 100)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=StopWhileWaiting(),
                backup=lambda *_args: self.fail("backup must not start"),
            )
            runner.run("JOB1", stop_requested=lambda: True)

            with Catalog(paths.catalog_file) as catalog:
                self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])

    def test_runner_records_cleanup_failure_with_original_error(self) -> None:
        class FailingCleanup(FakeStoreOpen):
            def unmount_and_eject(self) -> None:
                self.calls.append(("eject",))
                raise CopyError("eject failed")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "L:\\", [("AB1234", "AB1234", 1, 10)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                storeopen=FailingCleanup(),
                backup=lambda *_args: (_ for _ in ()).throw(CopyError("copy failed")),
            )
            with self.assertRaisesRegex(CopyError, "copy failed"):
                runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                cassette = catalog.list_automatic_cassettes("JOB1")[0]
                self.assertIn("copy failed", job["last_error"])
                self.assertIn("eject failed", job["last_error"])
                self.assertEqual(job["last_error"], cassette["error"])


if __name__ == "__main__":
    unittest.main()
