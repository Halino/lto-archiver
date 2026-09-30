from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from ltobackup.automation import (
    AutomaticJobRunner,
    CassetteLabel,
    TapeWriteProgress,
    normalize_cassette_labels,
)
from ltobackup.catalog import Catalog
from ltobackup.errors import CatalogError, CapacityError, CopyError, OperationCancelled, ValidationError
from ltobackup.models import VolumeInfo
from ltobackup.settings import AppPaths, Settings


class FakeTapeController:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def wait_for_media(self, stop_requested) -> bool:
        self.calls.append(("wait",))
        return not stop_requested()

    def format(self, cassette: CassetteLabel) -> None:
        self.calls.append(("format", cassette.physical_label, cassette.tape_serial))

    def mount(self, _stop_requested) -> Path:
        mount_path = Path("/mnt/lto-auto")
        self.calls.append(("mount", str(mount_path)))
        return mount_path

    def unmount_and_eject(self) -> None:
        self.calls.append(("eject",))


class AutomationTests(unittest.TestCase):
    def test_registered_tape_catalog_is_preserved_when_authorized_format_fails(self) -> None:
        class FailingFormat(FakeTapeController):
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
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto",
                    cassette_number="AB1234",
                )
                catalog.create_block("OLD-BLOCK", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1", "OLD-BLOCK", "AB1234", "old.bin", "old/files/old.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.create_automatic_job(
                    "REUSE", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 10)], force_format=True,
                    allow_registered_reuse=True,
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=FailingFormat(),
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
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto",
                    cassette_number="AB1234",
                )
                catalog.create_block("OLD-BLOCK", "LIB1", "AB1234", "old", 1, 10)
                catalog.record_file_version(
                    "LIB1", "OLD-BLOCK", "AB1234", "old.bin", "old/files/old.bin",
                    10, 1, "a" * 64,
                )
                catalog.complete_block("OLD-BLOCK")
                catalog.create_automatic_job(
                    "REUSE", "LIB1", "TAPE0", "/mnt/lto",
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
                paths, Settings(), controller=FakeTapeController(), backup=backup
            )
            runner.run("REUSE", stop_requested=lambda: False)

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
            controller = FakeTapeController()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("LIVE01", "LIVE01", 2, 20)], force_format=True,
                )

            def cancelled_backup(_libraries, label, _mount, callback, _stop_requested):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.register_tape(
                        label, label, label, "LTFS", "/mnt/lto-auto", cassette_number=label
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
                paths, Settings(), controller=controller, backup=cancelled_backup
            )
            runner.run("JOB1", progress=events.append, stop_requested=lambda: False)

            self.assertEqual(1, sum(call[0] == "eject" for call in controller.calls))
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

    def test_runner_reuses_volume_already_inspected_during_mount(self) -> None:
        class CachedVolumeTapeController(FakeTapeController):
            def __init__(self) -> None:
                super().__init__()
                self.mounted_volume = VolumeInfo(
                    root=Path("/mnt/lto-auto"), filesystem="LTFS", label="AB1234",
                    serial="12345678", total_bytes=2500, free_bytes=2400,
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            controller = CachedVolumeTapeController()
            received: list[object] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
                backup=lambda _libraries, _label, mounted, _progress, _stop: received.append(mounted)
                or {
                    "status": "completed", "block_id": "BLOCK1",
                    "copied_files": 1, "copied_bytes": 10, "remaining_files": 0,
                },
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual([controller.mounted_volume], received)

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
            controller = FakeTapeController()
            backed_up: list[tuple[list[str], str, Path]] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.add_library("LIB2", "Library 2", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678L6", "CD5678", 1, 80)],
                    library_ids=["LIB1", "LIB2"],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
                backup=lambda libraries, label, mount, _progress, _stop: backed_up.append((libraries, label, mount))
                or {"status": "completed", "block_id": "B-" + label, "copied_files": 1, "copied_bytes": 10},
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual(
                [
                    (["LIB1", "LIB2"], "AB1234", Path("/mnt/lto-auto")),
                    (["LIB1", "LIB2"], "CD5678L6", Path("/mnt/lto-auto")),
                ],
                backed_up,
            )
            self.assertEqual(2, sum(1 for call in controller.calls if call[0] == "eject"))
            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                steps = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual("completed", job["status"])
                self.assertEqual(["completed", "completed"], [row["status"] for row in steps])

    def test_stop_after_cassette_leaves_next_media_waiting_without_user_pause(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            events: list[dict] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678", "CD5678", 1, 80)],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=FakeTapeController(),
                backup=lambda *_args: {
                    "status": "completed", "block_id": "B-AB1234",
                    "copied_files": 1, "copied_bytes": 100,
                },
            )
            runner.run(
                "JOB1",
                progress=events.append,
                stop_requested=lambda: False,
                stop_after_cassette=True,
            )

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                first, second = catalog.list_automatic_cassettes("JOB1")
            self.assertEqual("completed", first["status"])
            self.assertEqual("waiting_media", second["status"])
            self.assertEqual("waiting_media", job["status"])
            self.assertNotIn("automatic.paused", [event["event"] for event in events])

    def test_stop_after_final_data_cassette_completes_job_and_leaves_reserve_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            controller = FakeTapeController()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678", "CD5678", 0, 0)],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
                backup=lambda *_args: {
                    "status": "completed", "block_id": "B-AB1234",
                    "copied_files": 1, "copied_bytes": 100,
                },
            )
            runner.run("JOB1", stop_requested=lambda: False, stop_after_cassette=True)

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                first, reserve = catalog.list_automatic_cassettes("JOB1")
                sequence = catalog.automatic_sequence_state("JOB1")
            self.assertEqual("completed", job["status"])
            self.assertEqual("completed", sequence["state"])
            self.assertEqual("completed", first["status"])
            self.assertEqual((0, 0, "pending"), (
                reserve["planned_files"], reserve["planned_bytes"], reserve["status"]
            ))
            self.assertNotIn("CD5678", [call[1] for call in controller.calls if call[0] == "format"])

    def test_stop_after_cassette_exposes_a_promoted_reserve_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            controller = FakeTapeController()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678", "CD5678", 0, 0)],
                )
                catalog.activate_automatic_reserves(
                    "JOB1", [(1, 80)], current_sequence=1
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
                backup=lambda _libraries, label, *_args: {
                    "status": "completed", "block_id": "B-" + label,
                    "copied_files": 1, "copied_bytes": 80,
                },
            )
            runner.run("JOB1", stop_requested=lambda: False, stop_after_cassette=True)
            with Catalog(paths.catalog_file) as catalog:
                first, reserve = catalog.list_automatic_cassettes("JOB1")
            self.assertEqual("completed", first["status"])
            self.assertEqual(("waiting_media", "format", 1, 80), (
                reserve["status"], reserve["operation"],
                reserve["planned_files"], reserve["planned_bytes"],
            ))

            runner.run("JOB1", stop_requested=lambda: False, stop_after_cassette=True)
            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                _, reserve = catalog.list_automatic_cassettes("JOB1")
            self.assertEqual("completed", job["status"])
            self.assertEqual("completed", reserve["status"])
            self.assertIn("CD5678", [call[1] for call in controller.calls if call[0] == "format"])

    def test_advance_after_eject_rejects_stale_double_and_out_of_order_sequences(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                source = root / "source"
                source.mkdir()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678", "CD5678", 1, 80)],
                )
                catalog.update_automatic_job("JOB1", "waiting_media", current_sequence=1)
                catalog.update_automatic_cassette("JOB1", 2, "completed")
                with self.assertRaises(CatalogError):
                    catalog.advance_automatic_job_after_eject("JOB1", 2)
                catalog.update_automatic_cassette("JOB1", 2, "pending")
                catalog.update_automatic_cassette("JOB1", 1, "completed")
                self.assertEqual(2, catalog.advance_automatic_job_after_eject("JOB1", 1))
                with self.assertRaises(CatalogError):
                    catalog.advance_automatic_job_after_eject("JOB1", 1)

    def test_advance_after_eject_rejects_final_cassette_replay(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = AppPaths(root / "state")
            paths.create()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                source = root / "source"
                source.mkdir()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 100)]
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed")
                catalog.update_automatic_job("JOB1", "failed", current_sequence=1)
                with self.assertRaises(CatalogError):
                    catalog.advance_automatic_job_after_eject("JOB1", 1)
                catalog.update_automatic_job("JOB1", "waiting_media", current_sequence=1)

                self.assertIsNone(catalog.advance_automatic_job_after_eject("JOB1", 1))
                with self.assertRaises(CatalogError):
                    catalog.advance_automatic_job_after_eject("JOB1", 1)
                self.assertEqual("completed", catalog.get_automatic_job("JOB1")["status"])

    def test_failed_eject_does_not_advance_the_next_cassette(self) -> None:
        class FailingEject(FakeTapeController):
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678", "CD5678", 1, 80)],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=FailingEject(),
                backup=lambda *_args: {
                    "status": "completed", "block_id": "B-AB1234",
                    "copied_files": 1, "copied_bytes": 100,
                },
            )
            with self.assertRaisesRegex(CopyError, "eject failed"):
                runner.run("JOB1", stop_requested=lambda: False, stop_after_cassette=True)

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                first, second = catalog.list_automatic_cassettes("JOB1")
            self.assertEqual("failed", first["status"])
            self.assertEqual("pending", second["status"])
            self.assertEqual(1, job["current_sequence"])

    def test_stop_after_append_full_eject_leaves_next_cassette_waiting(self) -> None:
        class MountedTapeController(FakeTapeController):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("/mnt/lto-auto")
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 10), ("CD5678", "CD5678", 1, 10)],
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto-auto",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed", tape_id="AB1234")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 10)
                self.assertEqual(
                    "append", catalog.list_automatic_cassettes("JOB1")[0]["operation"]
                )

            controller = MountedTapeController()
            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
                backup=lambda *_args: (_ for _ in ()).throw(
                    CapacityError("append tape full")
                ),
            )
            runner.run("JOB1", stop_requested=lambda: False, stop_after_cassette=True)

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                first, second = catalog.list_automatic_cassettes("JOB1")
            self.assertEqual("completed", first["status"])
            self.assertEqual("waiting_media", second["status"])
            self.assertEqual(("waiting_media", 2), (job["status"], job["current_sequence"]))
            self.assertEqual(["wait", "mount", "eject"], [call[0] for call in controller.calls])

    def test_stop_requested_after_eject_pauses_before_advancing(self) -> None:
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678", "CD5678", 1, 80)],
                )

            stopped = iter((False, False, True))
            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=FakeTapeController(),
                backup=lambda *_args: {
                    "status": "completed", "block_id": "B-AB1234",
                    "copied_files": 1, "copied_bytes": 100,
                },
            )
            runner.run("JOB1", stop_requested=lambda: next(stopped))

            with Catalog(paths.catalog_file) as catalog:
                job = catalog.get_automatic_job("JOB1")
                first, second = catalog.list_automatic_cassettes("JOB1")
            self.assertEqual("completed", first["status"])
            self.assertEqual("pending", second["status"])
            self.assertEqual(("paused", 1), (job["status"], job["current_sequence"]))

    def test_runner_forwards_unmount_subphases_with_job_context(self) -> None:
        class ProgressTapeController(FakeTapeController):
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
            controller = ProgressTapeController()
            events: list[dict] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
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
                controller=controller,
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

            class CommitAwareTapeController(FakeTapeController):
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )

            def backup(_libraries, label, _mount, _progress, _stop):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.register_tape(
                        label, label, label, "LTFS", "/mnt/lto-auto", cassette_number=label
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
                paths, Settings(), controller=CommitAwareTapeController(), backup=backup
            )
            runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual("completed", catalog.list_blocks()[0]["status"])
                self.assertEqual(["file.bin"], list(catalog.latest_versions("LIB1")))

    def test_runner_marks_staged_blocks_failed_when_unmount_fails(self) -> None:
        class FailingUnmount(FakeTapeController):
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )

            def backup(_libraries, label, _mount, _progress, _stop):
                with Catalog(paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.register_tape(
                        label, label, label, "LTFS", "/mnt/lto-auto", cassette_number=label
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
                paths, Settings(), controller=FailingUnmount(), backup=backup
            )
            with self.assertRaisesRegex(CopyError, "unmount failed"):
                runner.run("JOB1", stop_requested=lambda: False)

            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                block = catalog.list_blocks(include_forgotten=True)[0]
                self.assertEqual("failed", block["status"])
                self.assertEqual({}, catalog.latest_versions("LIB1"))

    def test_runner_keeps_surplus_cassette_unformatted_for_future_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            paths = AppPaths(root / "state")
            paths.create()
            controller = FakeTapeController()
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 100), ("CD5678L6", "CD5678", 0, 0)],
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
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
                [call[0] for call in controller.calls],
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
            controller = FakeTapeController()
            backed_up: list[str] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.append_automatic_cassettes(
                    "JOB1", [("CD5678L6", "CD5678", 1, 20)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=controller,
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
                [call[0] for call in controller.calls],
            )
            with Catalog(paths.catalog_file) as catalog:
                self.assertEqual("completed", catalog.get_automatic_job("JOB1")["status"])
                self.assertEqual(
                    ["completed", "completed"],
                    [row["status"] for row in catalog.list_automatic_cassettes("JOB1")],
                )

    def test_runner_mounts_completed_tape_for_append_without_formatting_it(self) -> None:
        class AppendTapeController(FakeTapeController):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("/mnt/lto-auto")
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
            controller = AppendTapeController()
            events: list[dict] = []
            with Catalog(paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.add_library("LIB1", "Library", str(source))
                catalog.create_automatic_job(
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto-auto",
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
                controller=controller,
                backup=lambda *_args: {
                    "status": "completed", "block_id": "B-NEW",
                    "copied_files": 1, "copied_bytes": 20, "remaining_files": 0,
                },
            )
            runner.run("JOB1", progress=events.append, stop_requested=lambda: False)

            self.assertEqual(
                ["wait", "mount", "eject"], [call[0] for call in controller.calls]
            )
            self.assertNotIn("automatic.formatting", [event["event"] for event in events])
            with Catalog(paths.catalog_file) as catalog:
                cassette = catalog.list_automatic_cassettes("JOB1")[0]
                self.assertEqual("completed", cassette["status"])
                self.assertEqual("append", cassette["operation"])

    def test_runner_rejects_wrong_tape_identity_before_append_write(self) -> None:
        class WrongTapeController(FakeTapeController):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("/mnt/lto-auto")
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto-auto",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed", tape_id="AB1234")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 20)

            backup = Mock()
            controller = WrongTapeController()
            runner = AutomaticJobRunner(
                paths, Settings(), controller=controller, backup=backup
            )
            with self.assertRaisesRegex(ValidationError, "Nastro errato"):
                runner.run("JOB1", stop_requested=lambda: False)

            backup.assert_not_called()
            self.assertNotIn("format", [call[0] for call in controller.calls])

    def test_cancelled_append_preserves_old_tape_and_remains_retryable(self) -> None:
        class AppendTapeController(FakeTapeController):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("/mnt/lto-auto")
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto-auto",
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
                controller=AppendTapeController(),
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
        class MountedTapeController(FakeTapeController):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("/mnt/lto-auto")
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto",
                    [("AB1234", "AB1234", 1, 10), ("CD5678", "CD5678", 1, 10)],
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto-auto",
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

            controller = MountedTapeController()
            runner = AutomaticJobRunner(
                paths, Settings(), controller=controller, backup=backup
            )
            runner.run("JOB1", stop_requested=lambda: False)

            self.assertEqual(["AB1234", "CD5678"], labels)
            self.assertEqual(1, sum(call[0] == "format" for call in controller.calls))
            with Catalog(paths.catalog_file) as catalog:
                rows = catalog.list_automatic_cassettes("JOB1")
                self.assertEqual(["completed", "completed"], [row["status"] for row in rows])

    def test_full_append_tape_without_next_cassette_requests_another_label(self) -> None:
        class MountedTapeController(FakeTapeController):
            def mount(self, _stop_requested) -> Path:
                mount_path = Path("/mnt/lto-auto")
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/mnt/lto-auto",
                    cassette_number="AB1234",
                )
                catalog.update_automatic_cassette("JOB1", 1, "completed", tape_id="AB1234")
                catalog.update_automatic_job("JOB1", "completed", current_sequence=1)
                catalog.activate_automatic_append("JOB1", 1, 1, 10)

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=MountedTapeController(),
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
        class StopWhileWaiting(FakeTapeController):
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 100)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=StopWhileWaiting(),
                backup=lambda *_args: self.fail("backup must not start"),
            )
            runner.run("JOB1", stop_requested=lambda: True)

            with Catalog(paths.catalog_file) as catalog:
                self.assertEqual("paused", catalog.get_automatic_job("JOB1")["status"])

    def test_runner_records_cleanup_failure_with_original_error(self) -> None:
        class FailingCleanup(FakeTapeController):
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
                    "JOB1", "LIB1", "TAPE0", "/mnt/lto", [("AB1234", "AB1234", 1, 10)]
                )

            runner = AutomaticJobRunner(
                paths,
                Settings(),
                controller=FailingCleanup(),
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
