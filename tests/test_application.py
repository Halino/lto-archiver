from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ltobackup.application import LtoApplication
from ltobackup.catalog import Catalog
from ltobackup.errors import CatalogError, ValidationError
from ltobackup.media import lto_media_profiles
from ltobackup.models import VolumeInfo
from ltobackup.settings import DEFAULT_RESERVE_BYTES, LTO6_LTFS_DATA_BYTES, Settings, save_settings


class ApplicationTests(unittest.TestCase):
    def test_failed_job_still_reserves_its_libraries_until_reset_or_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            failed = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.update_automatic_cassette(
                    failed["id"], 1, "failed", error="copy failed"
                )
                catalog.update_automatic_job(
                    failed["id"], "failed", current_sequence=1, error="copy failed"
                )

            context = application.automatic_job_creation_context("LIB1", "TAPE0")

            self.assertEqual(
                [failed["id"]],
                [row["id"] for row in context["conflicting_jobs"]],
            )
            with self.assertRaisesRegex(ValidationError, failed["id"]):
                application.create_automatic_job(
                    "LIB1", ["CD5678"], destructive_confirmed=True
                )

    def test_job_creation_context_distinguishes_conflicts_from_independent_saved_jobs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            for library_id in ("LIB1", "LIB2"):
                source = root / library_id
                source.mkdir()
                (source / "payload.bin").write_bytes(library_id.encode("ascii"))
                application.add_library(library_id, library_id, str(source))
            first = application.create_automatic_job(
                "LIB1", ["AB1234"], device_name="TAPE0", destructive_confirmed=True
            )

            conflict = application.automatic_job_creation_context(["lib1"], "tape0")
            independent = application.automatic_job_creation_context(["LIB2"], "TAPE0")

            self.assertEqual([first["id"]], [row["id"] for row in conflict["conflicting_jobs"]])
            self.assertEqual(["LIB1"], conflict["conflicting_jobs"][0]["overlapping_libraries"])
            self.assertEqual([], conflict["saved_on_device"])
            self.assertEqual([], independent["conflicting_jobs"])
            self.assertEqual([first["id"]], [row["id"] for row in independent["saved_on_device"]])

    def test_job_start_context_identifies_next_cassette_and_other_saved_jobs_on_drive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            jobs = []
            for library_id, label in (("LIB1", "AB1234"), ("LIB2", "CD5678")):
                source = root / library_id
                source.mkdir()
                (source / "payload.bin").write_bytes(library_id.encode("ascii"))
                application.add_library(library_id, library_id, str(source))
                jobs.append(
                    application.create_automatic_job(
                        library_id,
                        [label],
                        device_name="TAPE0",
                        destructive_confirmed=True,
                    )
                )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.update_automatic_job(
                    jobs[0]["id"], "failed", current_sequence=1, error="copy failed"
                )

            context = application.automatic_job_start_context(jobs[1]["id"])

            self.assertEqual(jobs[1]["id"], context["job"]["id"])
            self.assertEqual("CD5678", context["next_cassette"]["physical_label"])
            self.assertEqual([jobs[0]["id"]], [row["id"] for row in context["other_jobs_on_device"]])

    def test_automatic_job_can_explicitly_queue_a_registered_tape_for_reformat(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "new.bin").write_bytes(b"new")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )

            with self.assertRaisesRegex(CatalogError, "gia registrata"):
                application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )

            job = application.create_automatic_job(
                "LIB1",
                ["AB1234"],
                destructive_confirmed=True,
                allow_registered_reuse=True,
            )

            self.assertEqual(1, job["cassettes"][0]["reuse_registered"])

    def test_doctor_rejects_an_empty_mount_converted_to_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            application = LtoApplication(Path(temporary) / "state")
            with self.assertRaisesRegex(ValidationError, "mount LTFS"):
                application.doctor("TAPE1", Path(""))

    def test_first_start_initializes_state_and_exposes_dashboard_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            source = root / "source"
            source.mkdir()

            application = LtoApplication(state)
            application.ensure_initialized()
            application.add_library("MEDIA_01", "Media 01", str(source))

            snapshot = application.snapshot()

            self.assertTrue((state / "config.json").is_file())
            self.assertTrue((state / "catalog.db").is_file())
            self.assertEqual(DEFAULT_RESERVE_BYTES, snapshot["settings"]["reserve_bytes"])
            self.assertEqual(LTO6_LTFS_DATA_BYTES, snapshot["settings"]["tape_capacity_bytes"])
            self.assertEqual("MEDIA_01", snapshot["libraries"][0]["id"])
            self.assertEqual([], snapshot["tapes"])
            self.assertEqual([], snapshot["blocks"])

    def test_startup_migrates_only_the_legacy_capacity_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            (state / "config.json").write_text(
                json.dumps(
                    {
                        "reserve_bytes": 200 * 1024**3,
                        "tape_capacity_bytes": 2_500_000_000_000,
                        "buffer_bytes": 8 * 1024**2,
                        "min_age_seconds": 123,
                        "tape_root_directory": ".lto-backup",
                    }
                ),
                encoding="utf-8",
            )

            application = LtoApplication(state)
            application.ensure_initialized()
            settings = application.snapshot()["settings"]

            self.assertEqual(DEFAULT_RESERVE_BYTES, settings["reserve_bytes"])
            self.assertEqual(LTO6_LTFS_DATA_BYTES, settings["tape_capacity_bytes"])
            self.assertEqual(8 * 1024**2, settings["buffer_bytes"])
            self.assertEqual(123, settings["min_age_seconds"])

    def test_startup_preserves_a_custom_extra_margin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            custom_reserve = 64 * 1024**3
            (state / "config.json").write_text(
                json.dumps(
                    {
                        "reserve_bytes": custom_reserve,
                        "tape_capacity_bytes": 2_500_000_000_000,
                        "buffer_bytes": 16 * 1024**2,
                        "min_age_seconds": 900,
                        "tape_root_directory": ".lto-backup",
                    }
                ),
                encoding="utf-8",
            )

            application = LtoApplication(state)
            application.ensure_initialized()
            settings = application.snapshot()["settings"]

            self.assertEqual(custom_reserve, settings["reserve_bytes"])
            self.assertEqual(LTO6_LTFS_DATA_BYTES, settings["tape_capacity_bytes"])

    def test_startup_removes_the_previous_200_gib_default_from_current_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            (state / "config.json").write_text(
                json.dumps(
                    {
                        "reserve_bytes": 200 * 1024**3,
                        "tape_capacity_bytes": LTO6_LTFS_DATA_BYTES,
                        "buffer_bytes": 16 * 1024**2,
                        "min_age_seconds": 900,
                        "tape_root_directory": ".lto-backup",
                    }
                ),
                encoding="utf-8",
            )

            application = LtoApplication(state)
            application.ensure_initialized()

            self.assertEqual(0, application.snapshot()["settings"]["reserve_bytes"])

    def test_scan_result_is_ready_for_graphical_display(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            source = root / "source"
            source.mkdir()
            (source / "video.mxf").write_bytes(b"x" * 4096)

            application = LtoApplication(state)
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("MEDIA_01", "Media 01", str(source))

            result = application.scan("MEDIA_01")

            self.assertEqual("MEDIA_01", result["library_id"])
            self.assertEqual(1, result["files"])
            self.assertEqual(4096, result["bytes"])
            self.assertIn("human", result)

    def test_scan_persists_total_library_size_for_the_libraries_screen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            archived = source / "archived.bin"
            archived.write_bytes(b"a" * 10)
            (source / "new.bin").write_bytes(b"b" * 20)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            archived_stat = archived.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\")
                catalog.create_block("BLOCK1", "LIB1", "TAPE1", "blocks/BLOCK1", 1, 10)
                catalog.record_file_version(
                    "LIB1", "BLOCK1", "TAPE1", "archived.bin",
                    "blocks/BLOCK1/files/archived.bin", 10,
                    archived_stat.st_mtime_ns, "archived-hash",
                )
                catalog.complete_block("BLOCK1")

            result = application.scan("LIB1")
            library = application.snapshot()["libraries"][0]

            self.assertEqual(1, result["files"])
            self.assertEqual(20, result["bytes"])
            self.assertEqual(2, result["source_files"])
            self.assertEqual(30, result["source_bytes"])
            self.assertEqual(2, library["last_scan_files"])
            self.assertEqual(30, library["last_scan_bytes"])
            self.assertIsNotNone(library["last_scanned_at"])

    def test_scan_all_libraries_reports_aggregate_progress_and_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            for library_id, size in (("LIB_A", 10), ("LIB_B", 20)):
                source = root / library_id
                source.mkdir()
                (source / "file.bin").write_bytes(b"x" * size)
                application.add_library(library_id, library_id, str(source))
            events: list[dict] = []

            result = application.scan_all_libraries(progress=events.append)

            self.assertEqual(2, result["total_libraries"])
            self.assertEqual(2, result["completed_libraries"])
            self.assertEqual(2, result["total_files"])
            self.assertEqual(30, result["total_bytes"])
            self.assertEqual(
                [
                    ("library.scan.start", "LIB_A", 1, 2),
                    ("library.scan.complete", "LIB_A", 1, 2),
                    ("library.scan.start", "LIB_B", 2, 2),
                    ("library.scan.complete", "LIB_B", 2, 2),
                ],
                [
                    (event["event"], event["library_id"], event["index"], event["total"])
                    for event in events
                ],
            )

    def test_search_result_exposes_physical_cassette_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100")
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 123)
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "film/master.mxf",
                    ".lto-backup/block1/files/film/master.mxf",
                    123,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("block1")

            rows = application.search_files("master.mxf")

            self.assertEqual(1, len(rows))
            self.assertEqual("CASS-0100", rows[0]["cassette_number"])
            self.assertEqual(".lto-backup/block1/files/film/master.mxf", rows[0]["tape_relative_path"])

    def test_offline_browser_is_available_without_source_or_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100")
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 123)
                catalog.record_file_version(
                    "LIB1", "block1", "TAPE1", "film/master.mxf",
                    ".lto-backup/block1/files/film/master.mxf", 123, 1, "a" * 64,
                )
                catalog.complete_block("block1")
            source.rmdir()

            root_children = application.browse_backup_children("LIB1", "")
            film_children = application.browse_backup_children("LIB1", "film")

            self.assertEqual(["film"], [row["name"] for row in root_children])
            self.assertEqual(["master.mxf"], [row["name"] for row in film_children])

    def test_library_analysis_lists_files_and_plans_tape_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            archived = source / "archived.mxf"
            archived.write_bytes(b"a" * 120)
            (source / "new.mov").write_bytes(b"b" * 80)
            archived_stat = archived.stat()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100")
                catalog.create_block("block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 120)
                catalog.record_file_version(
                    "LIB1", "block1", "TAPE1", "archived.mxf",
                    ".lto-backup/block1/files/archived.mxf", 120,
                    archived_stat.st_mtime_ns, "a" * 64,
                )
                catalog.complete_block("block1")

            result = application.analyze_library("LIB1")

            self.assertEqual(2, result["total_files"])
            self.assertEqual(1, result["archived_files"])
            self.assertEqual(1, result["pending_files"])
            self.assertEqual(1, result["estimated_tapes"])
            self.assertEqual("CASS-0100", result["tape_distribution"][0]["cassette_number"])
            locations = {row["relative_path"]: row for row in result["listing"]}
            self.assertEqual("archived", locations["archived.mxf"]["status"])
            self.assertEqual("CASS-0100", locations["archived.mxf"]["cassette_number"])
            self.assertEqual("pending", locations["new.mov"]["status"])

    def test_automatic_job_plans_multiple_libraries_as_one_cumulative_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            for library_id, size in (("LIB_A", 10), ("LIB_B", 20)):
                source = root / library_id
                source.mkdir()
                (source / "file.bin").write_bytes(b"x" * size)
                application.add_library(library_id, library_id, str(source))

            job = application.create_automatic_job(
                ["LIB_A", "LIB_B"],
                ["AB1234"],
                destructive_confirmed=True,
            )

            self.assertEqual(["LIB_A", "LIB_B"], job["library_ids"])
            self.assertEqual("AUTO", job["mount_path"])
            self.assertEqual(1, job["force_format"])
            self.assertEqual(1, len(job["cassettes"]))
            self.assertEqual(2, job["cassettes"][0]["planned_files"])
            self.assertEqual(30, job["cassettes"][0]["planned_bytes"])

    def test_automatic_job_persists_selected_media_type_and_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            plan = application.plan_automatic_job("LIB1", media_key="LTO-5")
            job = application.create_automatic_job(
                "LIB1", ["AB1234L5"], media_key="LTO-5", destructive_confirmed=True
            )

            self.assertEqual("LTO-5", plan["media_key"])
            self.assertEqual(
                1_430_000_000_000 - DEFAULT_RESERVE_BYTES,
                plan["usable_tape_bytes"],
            )
            self.assertEqual("LTO-5", job["media_key"])

    def test_automatic_planner_uses_profile_ltfs_capacity_for_every_supported_media(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=2_000_000_000_000,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))

            for profile in lto_media_profiles():
                with self.subTest(media_key=profile.key):
                    plan = application.plan_automatic_job("LIB1", media_key=profile.key)
                    self.assertEqual(profile.ltfs_usable_bytes, plan["nominal_tape_bytes"])
                    self.assertEqual(profile.ltfs_usable_bytes, plan["usable_tape_bytes"])
                    self.assertEqual(0, plan["reserve_bytes"])
                    cassette = plan["cassettes"][0]
                    self.assertGreater(cassette["capacity_used_bytes"], cassette["total_bytes"])
                    self.assertEqual(
                        cassette["capacity_used_bytes"] - cassette["total_bytes"],
                        cassette["ltfs_overhead_bytes"],
                    )

    def test_lto4_is_outside_the_supported_job_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            with self.assertRaisesRegex(ValidationError, "non supportato.*LTO-4"):
                application.plan_automatic_job("LIB1", media_key="LTO-4")

    def test_automatic_job_keeps_surplus_labels_as_future_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            job = application.create_automatic_job(
                "LIB1",
                ["AB1234", "CD5678L6", "EF9012"],
                destructive_confirmed=True,
            )

            self.assertEqual(3, job["total_cassettes"])
            self.assertEqual(
                [(1, 1, 7), (2, 0, 0), (3, 0, 0)],
                [
                    (row["sequence"], row["planned_files"], row["planned_bytes"])
                    for row in job["cassettes"]
                ],
            )

    def test_automatic_job_name_can_be_changed_and_survives_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )

            renamed = application.rename_automatic_job(job["id"], "Archivio marketing")
            refreshed = next(
                row for row in application.snapshot()["automatic_jobs"]
                if row["id"] == job["id"]
            )

            self.assertEqual(job["id"], renamed["id"])
            self.assertEqual("Archivio marketing", renamed["display_name"])
            self.assertEqual("Archivio marketing", refreshed["display_name"])

    def test_automatic_job_can_be_deleted_without_deleting_its_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )

            deleted = application.delete_automatic_job(job["id"])

            self.assertEqual(job["id"], deleted["id"])
            snapshot = application.snapshot()
            self.assertEqual([], snapshot["automatic_jobs"])
            self.assertEqual("LIB1", snapshot["libraries"][0]["id"])

    def test_completed_job_activates_a_reserved_cassette_for_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=5):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678L6"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\", cassette_number="AB1234"
                )
                catalog.create_block("BLOCK-1", "LIB1", "AB1234", "blocks/BLOCK-1", 1, 3)
                catalog.record_file_version(
                    "LIB1", "BLOCK-1", "AB1234", "old.bin", "blocks/BLOCK-1/files/old.bin",
                    3, old_stat.st_mtime_ns, "old-hash",
                )
                catalog.complete_block("BLOCK-1")
                catalog.update_automatic_cassette(job["id"], 1, "completed")
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "new.bin").write_bytes(b"new payload")
            prepared = application.prepare_automatic_job_run(job["id"])

            self.assertEqual("planned", prepared["status"])
            self.assertEqual(1, prepared["cassettes"][1]["planned_files"])
            self.assertEqual(len(b"new payload"), prepared["cassettes"][1]["planned_bytes"])

    def test_completed_job_appends_new_files_to_last_tape_without_formatting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 3)
                catalog.record_file_version(
                    "LIB1", "BLOCK-OLD", "AB1234", "old.bin", "old/files/old.bin",
                    3, old_stat.st_mtime_ns, "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"], 1, "completed", tape_id="AB1234",
                    block_id="BLOCK-OLD", copied_files=1, copied_bytes=3,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "new.bin").write_bytes(b"new!")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                prepared = application.prepare_automatic_job_run(job["id"])

            self.assertEqual("planned", prepared["status"])
            self.assertEqual(1, len(prepared["cassettes"]))
            cassette = prepared["cassettes"][0]
            self.assertEqual("append", cassette["operation"])
            self.assertEqual("pending", cassette["status"])
            self.assertEqual((1, 4), (cassette["planned_files"], cassette["planned_bytes"]))
            self.assertEqual("AB1234", cassette["tape_id"])

    def test_append_capacity_includes_existing_ltfs_objects_and_block_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234", "CD5678L6"], destructive_confirmed=True
            )
            capacity = 2_410_000_000_000
            recorded_size = capacity - 7 * 1024**2

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block(
                    "BLOCK-OLD", "LIB1", "AB1234", "old", 1, recorded_size
                )
                catalog.record_file_version(
                    "LIB1", "BLOCK-OLD", "AB1234", "old.bin", "old/files/old.bin",
                    recorded_size, old_file.stat().st_mtime_ns, "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"], 1, "completed", tape_id="AB1234",
                    block_id="BLOCK-OLD", copied_files=1, copied_bytes=recorded_size,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            old_file.unlink()
            (source / "new.bin").write_bytes(b"new")
            prepared = application.prepare_automatic_job_run(job["id"])

            self.assertEqual("completed", prepared["cassettes"][0]["status"])
            self.assertEqual("format", prepared["cassettes"][1]["operation"])
            self.assertEqual(1, prepared["cassettes"][1]["planned_files"])

    def test_append_fills_last_tape_then_uses_reserved_new_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"12345678")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 8)
                catalog.record_file_version(
                    "LIB1", "BLOCK-OLD", "AB1234", "old.bin", "old/files/old.bin",
                    8, old_stat.st_mtime_ns, "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"], 1, "completed", tape_id="AB1234",
                    block_id="BLOCK-OLD", copied_files=1, copied_bytes=8,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "small.bin").write_bytes(b"12")
            (source / "large.bin").write_bytes(b"3456")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                prepared = application.prepare_automatic_job_run(job["id"])

            first, second = prepared["cassettes"]
            self.assertEqual(
                ("append", "pending", 1, 2),
                (first["operation"], first["status"], first["planned_files"], first["planned_bytes"]),
            )
            self.assertEqual(
                ("format", "pending", 1, 4),
                (second["operation"], second["status"], second["planned_files"], second["planned_bytes"]),
            )

    def test_reset_failed_cassette_preserves_completed_tapes_and_makes_it_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["DONE01", "FAIL02"], destructive_confirmed=True
            )

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                for tape_id in ("DONE01", "FAIL02"):
                    catalog.register_tape(
                        tape_id, tape_id, tape_id, "LTFS", "L:\\",
                        cassette_number=tape_id,
                    )
                catalog.create_block("BLOCK-DONE", "LIB1", "DONE01", "done", 1, 7)
                catalog.record_file_version(
                    "LIB1", "BLOCK-DONE", "DONE01", "done.bin", "done/done.bin",
                    7, 1, "a" * 64,
                )
                catalog.complete_block("BLOCK-DONE")
                catalog.update_automatic_cassette(
                    job["id"], 1, "completed", tape_id="DONE01", block_id="BLOCK-DONE",
                    copied_files=1, copied_bytes=7,
                )
                catalog.create_block("BLOCK-FAIL", "LIB1", "FAIL02", "failed", 1, 7)
                catalog.record_file_version(
                    "LIB1", "BLOCK-FAIL", "FAIL02", "partial.bin", "failed/partial.bin",
                    4, 2, "b" * 64,
                )
                catalog.update_automatic_cassette(
                    job["id"], 2, "failed", tape_id="FAIL02", block_id="BLOCK-FAIL",
                    copied_files=1, copied_bytes=4, error="StoreOpen non disponibile",
                )
                catalog.update_automatic_job(
                    job["id"], "failed", current_sequence=2,
                    error="StoreOpen non disponibile",
                )

            reset_method = getattr(application, "reset_failed_automatic_cassette", None)
            self.assertIsNotNone(reset_method, "manca il reset applicativo della cassetta")
            reset = reset_method(job["id"], 2)

            self.assertEqual("paused", reset["status"])
            self.assertEqual("pending", reset["cassettes"][1]["status"])
            self.assertEqual(0, reset["cassettes"][1]["copied_bytes"])
            self.assertEqual({"blocks": 1, "files": 1, "tapes": 1}, reset["discarded"])
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual(["BLOCK-DONE"], [row["id"] for row in catalog.list_blocks()])
                self.assertEqual(["DONE01"], [row["id"] for row in catalog.list_tapes()])

    def test_job_extension_uses_existing_reserve_before_new_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=5,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234", "CD5678L6"], destructive_confirmed=True
            )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\", cassette_number="AB1234"
                )
                catalog.create_block("BLOCK-1", "LIB1", "AB1234", "blocks/BLOCK-1", 1, 3)
                catalog.record_file_version(
                    "LIB1", "BLOCK-1", "AB1234", "old.bin", "blocks/BLOCK-1/files/old.bin",
                    3, old_stat.st_mtime_ns, "old-hash",
                )
                catalog.complete_block("BLOCK-1")
                catalog.update_automatic_cassette(job["id"], 1, "completed")
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "new-1.bin").write_bytes(b"1111")
            (source / "new-2.bin").write_bytes(b"2222")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=5):
                extended = application.extend_automatic_job(
                    job["id"], ["EF9012"], destructive_confirmed=True
                )

            self.assertEqual(3, extended["total_cassettes"])
            self.assertEqual(
                [(1, 4), (1, 4)],
                [
                    (row["planned_files"], row["planned_bytes"])
                    for row in extended["cassettes"][1:]
                ],
            )

    def test_job_extension_appends_to_last_tape_before_new_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"12345678")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 8)
                catalog.record_file_version(
                    "LIB1", "BLOCK-OLD", "AB1234", "old.bin", "old/files/old.bin",
                    8, old_stat.st_mtime_ns, "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"], 1, "completed", tape_id="AB1234",
                    block_id="BLOCK-OLD", copied_files=1, copied_bytes=8,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "small.bin").write_bytes(b"12")
            (source / "large.bin").write_bytes(b"3456")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                extended = application.extend_automatic_job(
                    job["id"], ["CD5678"], destructive_confirmed=True
                )

            first, second = extended["cassettes"]
            self.assertEqual(("append", 1, 2), (
                first["operation"], first["planned_files"], first["planned_bytes"]
            ))
            self.assertEqual(("format", 1, 4), (
                second["operation"], second["planned_files"], second["planned_bytes"]
            ))

    def test_job_planner_distributes_multiple_libraries_across_shared_cassettes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=100 * 1024**3,
                    tape_capacity_bytes=100 * 1024**3 + 100,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            payloads = {
                "LIB_A": (70, 10),
                "LIB_B": (60, 20),
            }
            for library_id, sizes in payloads.items():
                source = root / library_id
                source.mkdir()
                for index, size in enumerate(sizes, 1):
                    (source / f"file-{index}.bin").write_bytes(b"x" * size)
                application.add_library(library_id, library_id, str(source))

            events: list[dict] = []
            simulated_capacity = 100 * 1024**3 + 100
            with patch.object(
                LtoApplication, "_media_tape_capacity", return_value=simulated_capacity
            ):
                plan = application.plan_automatic_job(
                    ["LIB_A", "LIB_B"], progress=events.append
                )

            self.assertEqual(["LIB_A", "LIB_B"], plan["library_ids"])
            self.assertEqual(4, plan["pending_files"])
            self.assertEqual(160, plan["pending_bytes"])
            self.assertEqual(2, plan["estimated_tapes"])
            self.assertEqual(
                [
                    ("library.scan.start", "LIB_A", 1, 2),
                    ("library.scan.complete", "LIB_A", 1, 2),
                    ("library.scan.start", "LIB_B", 2, 2),
                    ("library.scan.complete", "LIB_B", 2, 2),
                ],
                [
                    (event["event"], event["library_id"], event["index"], event["total"])
                    for event in events
                ],
            )
            self.assertEqual(
                [
                    (1, 3, 100, [("LIB_A", 2, 80), ("LIB_B", 1, 20)]),
                    (2, 1, 60, [("LIB_B", 1, 60)]),
                ],
                [
                    (
                        cassette["sequence"],
                        cassette["file_count"],
                        cassette["total_bytes"],
                        [
                            (row["library_id"], row["file_count"], row["total_bytes"])
                            for row in cassette["libraries"]
                        ],
                    )
                    for cassette in plan["cassettes"]
                ],
            )

    def test_completed_automatic_job_plans_new_files_on_appended_cassettes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            original = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "L:\\", cassette_number="AB1234"
                )
                catalog.create_block("BLOCK-1", "LIB1", "AB1234", "blocks/BLOCK-1", 1, 3)
                catalog.record_file_version(
                    "LIB1", "BLOCK-1", "AB1234", "old.bin", "blocks/BLOCK-1/files/old.bin",
                    3, old_stat.st_mtime_ns, "old-hash",
                )
                catalog.complete_block("BLOCK-1")
                catalog.update_automatic_cassette(original["id"], 1, "completed")
                catalog.update_automatic_job(original["id"], "completed", current_sequence=1)

            (source / "new.bin").write_bytes(b"new payload")
            extended = application.extend_automatic_job(
                original["id"], ["CD5678L6", "EF9012"], destructive_confirmed=True
            )

            self.assertEqual(original["id"], extended["id"])
            self.assertEqual("planned", extended["status"])
            self.assertEqual(3, extended["total_cassettes"])
            self.assertEqual([1, 2, 3], [row["sequence"] for row in extended["cassettes"]])
            self.assertEqual(
                ["AB1234", "CD5678L6", "EF9012"],
                [row["physical_label"] for row in extended["cassettes"]],
            )
            self.assertEqual(1, extended["cassettes"][1]["planned_files"])
            self.assertEqual(len(b"new payload"), extended["cassettes"][1]["planned_bytes"])
            self.assertEqual(0, extended["cassettes"][2]["planned_files"])
            self.assertEqual(0, extended["cassettes"][2]["planned_bytes"])


    def test_resume_keeps_existing_assignments_and_adds_new_files_to_residual_space(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "largest.mxf").write_bytes(b"a" * 7)
            (source / "small.mxf").write_bytes(b"b" * 3)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678"], destructive_confirmed=True
                )

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                before = [
                    [row["relative_path"] for row in catalog.list_automatic_cassette_manifest(job["id"], sequence)]
                    for sequence in (1, 2)
                ]

            (source / "added-later.mxf").write_bytes(b"c" * 4)
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                application.prepare_automatic_job_run(job["id"])

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                after = [
                    [row["relative_path"] for row in catalog.list_automatic_cassette_manifest(job["id"], sequence)]
                    for sequence in (1, 2)
                ]

            self.assertEqual([["largest.mxf"], ["small.mxf"]], before)
            self.assertEqual([["largest.mxf"], ["small.mxf", "added-later.mxf"]], after)

    def test_paused_job_can_append_a_label_for_new_files_without_moving_the_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "first.mxf").write_bytes(b"a" * 7)
            (source / "second.mxf").write_bytes(b"b" * 7)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678"], destructive_confirmed=True
                )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                before = [
                    [
                        row["relative_path"]
                        for row in catalog.list_automatic_cassette_manifest(
                            job["id"], sequence
                        )
                    ]
                    for sequence in (1, 2)
                ]
                catalog.update_automatic_job(job["id"], "paused", current_sequence=1)

            (source / "new.mxf").write_bytes(b"n" * 6)
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                extended = application.extend_automatic_job(
                    job["id"], ["EF9012"], destructive_confirmed=True
                )

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                after = [
                    [
                        row["relative_path"]
                        for row in catalog.list_automatic_cassette_manifest(
                            job["id"], sequence
                        )
                    ]
                    for sequence in (1, 2, 3)
                ]
            self.assertEqual(before, after[:2])
            self.assertEqual(["new.mxf"], after[2])
            self.assertEqual(3, extended["total_cassettes"])

    def test_automatic_batch_never_marks_a_missing_manifest_file_as_completed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            mount = root / "tape"
            source.mkdir()
            mount.mkdir()
            planned = source / "planned.mxf"
            planned.write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=100,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=100):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )
            volume = VolumeInfo(mount, "LTFS", "AB1234", "AB1234", 100, 100)
            application.register_tape("AB1234", "AB1234", mount, known_volume=volume)
            planned.unlink()

            with self.assertRaisesRegex(ValidationError, "mancanti"):
                application.backup_automatic_batch(
                    ["LIB1"],
                    "AB1234",
                    mount,
                    known_volume=volume,
                    tape_capacity_bytes=100,
                    automatic_job_id=job["id"],
                )

    def test_legacy_job_freezes_all_remaining_paths_before_next_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "largest.mxf").write_bytes(b"a" * 7)
            (source / "small.mxf").write_bytes(b"b" * 3)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=7,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.create_automatic_job(
                    "LEGACY", "LIB1", "TAPE0", "AUTO",
                    [("AB1234", "AB1234", 1, 7), ("CD5678", "CD5678", 1, 3)],
                    force_format=True,
                )

            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                application.prepare_automatic_job_run("LEGACY")

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual(
                    [["largest.mxf"], ["small.mxf"]],
                    [
                        [
                            row["relative_path"]
                            for row in catalog.list_automatic_cassette_manifest(
                                "LEGACY", sequence
                            )
                        ]
                        for sequence in (1, 2)
                    ],
                )


if __name__ == "__main__":
    unittest.main()
