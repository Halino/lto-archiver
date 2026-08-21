from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.engine import BackupEngine
from ltobackup.errors import CapacityError, CopyError, OperationCancelled, ValidationError
from ltobackup.models import VolumeInfo
from ltobackup.settings import AppPaths, Settings
from ltobackup.util import copy_and_hash as real_copy_and_hash
from ltobackup.volume import assert_registered_tape


GIB = 1024**3


class FakeVolumes:
    def __init__(self):
        self._volumes: dict[str, VolumeInfo] = {}

    def add(
        self,
        root: Path,
        serial: str,
        free_bytes: int = 500 * GIB,
        total_bytes: int | None = None,
    ) -> None:
        self._volumes[str(root.resolve()).casefold()] = VolumeInfo(
            root=root.resolve(),
            filesystem="LTFS",
            label="TEST-" + serial,
            serial=serial,
            total_bytes=free_bytes if total_bytes is None else total_bytes,
            free_bytes=free_bytes,
        )

    def __call__(self, path: Path) -> VolumeInfo:
        return self._volumes[str(path.resolve()).casefold()]


class EngineTests(unittest.TestCase):
    def test_ltfs_identity_uses_volume_label_when_storeopen_serial_is_shared(self) -> None:
        registered = {
            "volume_serial": "00007AF3",
            "volume_label": "IR1821",
            "filesystem": "LTFS",
        }
        matching = VolumeInfo(
            root=Path("L:\\"), filesystem="LTFS", label="ir1821",
            serial="00007AF3", total_bytes=1, free_bytes=1,
        )
        wrong_cartridge = replace(matching, label="IR1822")

        assert_registered_tape(registered, matching)
        with self.assertRaisesRegex(ValidationError, "Nastro errato.*IR1821.*IR1822"):
            assert_registered_tape(registered, wrong_cartridge)

    def test_backup_persists_copyfileex_phase_timings_for_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "video.mxf").write_bytes(b"payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)

            def timed_copy(src, destination, _buffer_bytes, progress=None, **kwargs):
                if kwargs.get("activity") is None:
                    return real_copy_and_hash(
                        src, destination, _buffer_bytes, progress=progress
                    )
                destination.write_bytes(src.read_bytes())
                if progress:
                    progress(src.stat().st_size)
                kwargs["activity"]({
                    "phase": "timing.complete",
                    "io_mode": "windows_copyfileex_parallel_hash",
                    "data_complete_seconds": 10.0,
                    "copy_return_seconds": 15.0,
                    "close_elapsed_seconds": 5.0,
                    "hash_complete_seconds": 18.0,
                })
                return "a" * 64

            try:
                engine.register_tape("TAPE1", tape)
                with patch("ltobackup.engine.copy_and_hash", side_effect=timed_copy):
                    engine.backup("LIB1", "TAPE1", tape)

                rows = catalog.connection.execute(
                    "SELECT payload_json FROM events "
                    "WHERE action='file.copy.timing' ORDER BY id"
                ).fetchall()
                self.assertEqual(1, len(rows))
                timing = json.loads(rows[0]["payload_json"])
                self.assertEqual("video.mxf", timing["relative_path"])
                self.assertEqual(10.0, timing["data_complete_seconds"])
                self.assertEqual(15.0, timing["copy_return_seconds"])
                self.assertEqual(5.0, timing["close_elapsed_seconds"])
                self.assertEqual(18.0, timing["hash_complete_seconds"])
                self.assertFalse(timing["slow_close"])
            finally:
                catalog.close()

    def test_operator_stop_removes_partial_and_leaves_no_catalogued_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "large.bin").write_bytes(b"x" * (3 * 1024**2))
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            stop = False

            def progress(event: dict) -> None:
                nonlocal stop
                if event["event"] == "file.progress":
                    stop = True

            try:
                engine.register_tape("TAPE1", tape)
                with self.assertRaises(OperationCancelled):
                    engine.backup(
                        "LIB1", "TAPE1", tape,
                        progress=progress,
                        stop_requested=lambda: stop,
                    )

                self.assertEqual([], list(tape.rglob("*.partial-*")))
                self.assertEqual({}, catalog.latest_versions("LIB1"))
                self.assertEqual("failed", catalog.list_blocks(include_forgotten=True)[0]["status"])
            finally:
                catalog.close()

    def make_engine(self, root: Path, source: Path, volumes: FakeVolumes) -> tuple[Catalog, BackupEngine]:
        paths = AppPaths(root / "state")
        paths.create()
        settings = Settings(reserve_bytes=200 * GIB, buffer_bytes=1024**2, min_age_seconds=0)
        catalog = Catalog(paths.catalog_file)
        catalog.initialize()
        catalog.add_library("LIB1", "Library 1", str(source))
        engine = BackupEngine(catalog, settings, paths, volume_provider=volumes, enforce_ltfs=True)
        return catalog, engine

    def test_backup_copies_direct_files_and_skips_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "folder").mkdir()
            payload = b"large-file-content" * 1000
            (source / "folder" / "video.bin").write_bytes(payload)
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape)
                result = engine.backup("LIB1", "TAPE1", tape)
                self.assertIsNotNone(result)
                assert result is not None
                copied = tape.joinpath(*Path(result.tape_relative_root).parts) / "files" / "folder" / "video.bin"
                self.assertEqual(payload, copied.read_bytes())
                self.assertTrue((copied.parents[2] / "manifest.jsonl").is_file())
                self.assertTrue((copied.parents[2] / "block.json").is_file())
                snapshots = list((tape / ".lto-backup" / "catalog-snapshots").glob("*.json"))
                self.assertEqual(1, len(snapshots))
                snapshot = json.loads(snapshots[0].read_text(encoding="utf-8"))
                self.assertNotIn("events", snapshot)
                backup = engine.paths.catalog_backup_file()
                self.assertTrue(backup.is_file())
                with Catalog(backup) as copied_catalog:
                    copied_catalog.initialize()
                    self.assertEqual("completed", copied_catalog.list_blocks()[0]["status"])
                self.assertFalse(any(path.suffix.lower() == ".tar" for path in tape.rglob("*")))
                self.assertIsNone(engine.backup("LIB1", "TAPE1", tape))
                latest = catalog.latest_versions("LIB1")["folder/video.bin"]
                self.assertEqual(len(payload), latest["size"])
                self.assertEqual("TAPE1", latest["tape_id"])
                self.assertNotEqual("legacy", latest["metadata_state"])
                self.assertIsNotNone(latest["created_ns"])
                self.assertIsNotNone(latest["accessed_ns"])
            finally:
                catalog.close()

    def test_deferred_backup_is_invisible_until_ltfs_commit_is_confirmed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "video.bin").write_bytes(b"video-payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape)
                result = engine.backup(
                    "LIB1", "TAPE1", tape, defer_completion=True
                )
                assert result is not None

                block = catalog.list_blocks(include_forgotten=True)[0]
                self.assertEqual("copying", block["status"])
                self.assertEqual({}, catalog.latest_versions("LIB1"))
                self.assertEqual([], catalog.restore_plan("LIB1"))

                catalog.complete_blocks([result.block_id])

                self.assertEqual(
                    "completed",
                    catalog.list_blocks(include_forgotten=True)[0]["status"],
                )
                self.assertEqual(["video.bin"], list(catalog.latest_versions("LIB1")))
            finally:
                catalog.close()

    def test_optional_sha_verification_detects_same_size_same_timestamp_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            source_file = source / "video.bin"
            source_file.write_bytes(b"AAAA")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape)
                engine.backup("LIB1", "TAPE1", tape)
                archived = catalog.latest_versions("LIB1")["video.bin"]
                original_mtime = int(archived["mtime_ns"])

                source_file.write_bytes(b"BBBB")
                os.utime(source_file, ns=(original_mtime, original_mtime))

                self.assertEqual(0, len(engine.scan("LIB1").items))
                engine.settings = replace(
                    engine.settings, verify_unchanged_content=True
                )
                verified = engine.scan("LIB1")
                self.assertEqual(["video.bin"], [item.relative_path for item in verified.items])
            finally:
                catalog.close()

    def test_tape_data_is_written_to_final_name_without_partial_rename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "video.bin").write_bytes(b"video-payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            destinations: list[Path] = []
            streaming_modes: list[bool] = []

            def record_destination(source_path, destination, buffer_bytes, *args, **kwargs):
                destinations.append(destination)
                streaming_modes.append(bool(kwargs.get("streaming_destination")))
                return real_copy_and_hash(
                    source_path, destination, buffer_bytes, *args, **kwargs
                )

            try:
                engine.register_tape("TAPE1", tape)
                with patch("ltobackup.engine.copy_and_hash", side_effect=record_destination):
                    engine.backup("LIB1", "TAPE1", tape)

                data_destinations = [path for path in destinations if "files" in path.parts]
                self.assertEqual(["video.bin"], [path.name for path in data_destinations])
                self.assertFalse(any("partial" in path.name for path in data_destinations))
                self.assertTrue(streaming_modes[destinations.index(data_destinations[0])])
            finally:
                catalog.close()

    def test_backup_probes_ltfs_once_and_reports_capacity_before_copy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "a.bin").write_bytes(b"a" * 10)
            (source / "b.bin").write_bytes(b"b" * 20)
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1", free_bytes=500 * GIB, total_bytes=500 * GIB)
            catalog, engine = self.make_engine(root, source, volumes)
            events: list[dict] = []
            calls = 0

            def counted_volume(path: Path) -> VolumeInfo:
                nonlocal calls
                calls += 1
                return volumes(path)

            engine.volume_provider = counted_volume
            try:
                engine.register_tape("TAPE1", tape)
                calls = 0
                engine.backup("LIB1", "TAPE1", tape, progress=events.append)

                self.assertEqual(1, calls)
                capacity = next(event for event in events if event["event"] == "tape.capacity")
                self.assertEqual(500 * GIB, capacity["total_bytes"])
                self.assertEqual(500 * GIB, capacity["free_bytes"])
                self.assertEqual(300 * GIB, capacity["usable_bytes"])
                self.assertEqual(200 * GIB, capacity["reserve_bytes"])
                activity = next(
                    event
                    for event in events
                    if event["event"] == "file.activity"
                    and event["phase"] == "write.pending"
                )
                self.assertEqual("a.bin", activity["relative_path"])
                self.assertEqual(10, activity["pending_bytes"])
                self.assertFalse(
                    any(
                        event["event"] == "file.activity"
                        and str(event.get("phase", "")).startswith("verify.")
                        for event in events
                    )
                )
            finally:
                catalog.close()

    def test_native_ltfs_free_space_is_stricter_than_windows_free_space(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "archive.bin").write_bytes(b"x" * 1024)
            volumes = FakeVolumes()
            catalog, engine = self.make_engine(root, source, volumes)
            engine.settings = replace(
                engine.settings, reserve_bytes=0, tape_capacity_bytes=500 * GIB
            )
            volume = VolumeInfo(
                root=tape.resolve(), filesystem="LTFS", label="TEST-SERIAL1",
                serial="SERIAL1", total_bytes=600 * GIB, free_bytes=20 * GIB,
                ltfs_data_total_bytes=500 * GIB, ltfs_data_free_bytes=7 * GIB,
            )
            try:
                self.assertEqual(7 * GIB, engine._application_free_bytes(volume))
            finally:
                catalog.close()

    def test_known_mounted_volume_skips_all_additional_ltfs_probes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "archive.bin").write_bytes(b"payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            mounted = volumes(tape)
            try:
                engine.register_tape("TAPE1", tape, known_volume=mounted)
                engine.volume_provider = lambda _path: self.fail("unexpected LTFS probe")

                result = engine.backup(
                    "LIB1", "TAPE1", tape, known_volume=mounted
                )

                self.assertIsNotNone(result)
            finally:
                catalog.close()

    def test_backup_does_not_reopen_tape_file_after_completed_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "archive.bin").write_bytes(b"payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            real_stat = Path.stat
            tape_file_stats = 0

            def tracked_stat(path: Path, *args, **kwargs):
                nonlocal tape_file_stats
                if tape in path.parents and "files" in path.parts and path.name == "archive.bin":
                    tape_file_stats += 1
                return real_stat(path, *args, **kwargs)

            try:
                engine.register_tape("TAPE1", tape)
                with patch.object(Path, "stat", tracked_stat):
                    result = engine.backup("LIB1", "TAPE1", tape)

                self.assertIsNotNone(result)
                self.assertEqual(0, tape_file_stats)
            finally:
                catalog.close()

    @unittest.skipUnless(__import__("os").name == "nt", "Windows streaming I/O")
    def test_backup_closes_each_data_file_before_starting_the_next(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "first.bin").write_bytes(b"A" * 131_071)
            (source / "second.bin").write_bytes(b"B" * 196_613)
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            events: list[dict] = []
            try:
                engine.register_tape("TAPE1", tape)
                engine.backup("LIB1", "TAPE1", tape, progress=events.append)

                self.assertFalse(
                    any(str(event.get("event", "")).startswith("batch.finalize") for event in events)
                )
                first_close = next(
                    index
                    for index, event in enumerate(events)
                    if event.get("event") == "file.activity"
                    and event.get("phase") == "close.complete"
                    and event.get("index") == 1
                )
                second_start = next(
                    index
                    for index, event in enumerate(events)
                    if event.get("event") == "file.start" and event.get("index") == 2
                )
                self.assertLess(first_close, second_start)
            finally:
                catalog.close()

    def test_precomputed_scan_plan_is_reused_before_first_tape_write(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "archive.bin").write_bytes(b"payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape)
                plan = engine.scan("LIB1", min_age_seconds=0)
                engine.scan = lambda *_args, **_kwargs: self.fail("unexpected SMB rescan")

                result = engine.backup(
                    "LIB1", "TAPE1", tape, min_age_seconds=0, known_plan=plan
                )

                self.assertIsNotNone(result)
            finally:
                catalog.close()

    def test_blank_tape_never_exceeds_configured_application_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "a.bin").write_bytes(b"a" * 1500)
            (source / "b.bin").write_bytes(b"b" * 700)
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1", free_bytes=2500, total_bytes=2500)
            paths = AppPaths(root / "state")
            paths.create()
            catalog = Catalog(paths.catalog_file)
            catalog.initialize()
            catalog.add_library("LIB1", "Library 1", str(source))
            engine = BackupEngine(
                catalog,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=2000,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
                paths,
                volume_provider=volumes,
                enforce_ltfs=True,
            )
            try:
                engine.register_tape("TAPE1", tape)

                result = engine.backup("LIB1", "TAPE1", tape)

                assert result is not None
                self.assertEqual(1500, result.copied_bytes)
                self.assertEqual(1, result.remaining_files)
                self.assertEqual(700, result.remaining_bytes)
            finally:
                catalog.close()

    def test_backup_can_write_only_the_paths_selected_by_a_cumulative_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "a.bin").write_bytes(b"a" * 10)
            (source / "b.bin").write_bytes(b"b" * 20)
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape)

                result = engine.backup(
                    "LIB1", "TAPE1", tape, only_relative_paths={"b.bin"}
                )

                assert result is not None
                self.assertEqual(1, result.copied_files)
                self.assertEqual(20, result.copied_bytes)
                self.assertEqual({"b.bin"}, set(catalog.latest_versions("LIB1")))
                self.assertEqual(["a.bin"], [item.relative_path for item in engine.scan("LIB1").items])
            finally:
                catalog.close()

    def test_capacity_reserve_refuses_before_creating_a_block(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "data.bin").write_bytes(b"x")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1", free_bytes=200 * GIB)
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape)
                with self.assertRaises(CapacityError):
                    engine.backup("LIB1", "TAPE1", tape)
                self.assertEqual([], catalog.list_blocks(include_forgotten=True))
                self.assertEqual([], list(tape.rglob("block.json")))
            finally:
                catalog.close()

    def test_failed_copy_removes_partial_file_from_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape = root / "tape"
            source.mkdir()
            tape.mkdir()
            (source / "data.bin").write_bytes(b"payload")
            volumes = FakeVolumes()
            volumes.add(tape, "SERIAL1")
            catalog, engine = self.make_engine(root, source, volumes)

            def fail_after_creating_partial(
                _source, destination, _buffer, progress=None, **_kwargs
            ):
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"partial")
                raise CopyError("simulated copy failure")

            try:
                engine.register_tape("TAPE1", tape)
                with patch("ltobackup.engine.copy_and_hash", side_effect=fail_after_creating_partial):
                    with self.assertRaisesRegex(CopyError, "simulated copy failure"):
                        engine.backup("LIB1", "TAPE1", tape)

                self.assertEqual([], list(tape.rglob("*.partial-*")))
            finally:
                catalog.close()

    def test_restore_plan_uses_latest_versions_across_tapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape1 = root / "tape1"
            tape2 = root / "tape2"
            destination = root / "restore"
            source.mkdir()
            tape1.mkdir()
            tape2.mkdir()
            (source / "a.bin").write_bytes(b"version-one")
            (source / "b.bin").write_bytes(b"only-on-tape-one")
            volumes = FakeVolumes()
            volumes.add(tape1, "SERIAL1")
            volumes.add(tape2, "SERIAL2")
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape1)
                engine.register_tape("TAPE2", tape2)
                engine.backup("LIB1", "TAPE1", tape1)

                (source / "a.bin").write_bytes(b"version-two-is-newer")
                modified = time.time_ns() - 1_000_000_000
                os.utime(source / "a.bin", ns=(modified, modified))
                engine.backup("LIB1", "TAPE2", tape2)

                plan = {row["tape_id"]: row for row in catalog.restore_plan("LIB1")}
                self.assertEqual(1, plan["TAPE1"]["file_count"])
                self.assertEqual(1, plan["TAPE2"]["file_count"])

                engine.restore("LIB1", "TAPE1", tape1, destination)
                engine.restore("LIB1", "TAPE2", tape2, destination)
                self.assertEqual(b"version-two-is-newer", (destination / "a.bin").read_bytes())
                self.assertEqual(b"only-on-tape-one", (destination / "b.bin").read_bytes())

                (destination / "a.bin").write_bytes(b"preserve-on-replace-failure")
                with patch("ltobackup.engine.os.replace", side_effect=OSError("replace failed")):
                    with self.assertRaisesRegex(OSError, "replace failed"):
                        engine.restore("LIB1", "TAPE2", tape2, destination, overwrite=True)
                self.assertEqual(
                    b"preserve-on-replace-failure",
                    (destination / "a.bin").read_bytes(),
                )
            finally:
                catalog.close()

    def test_backup_writes_only_first_planned_batch_and_reports_remaining_tapes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            tape1 = root / "tape1"
            tape2 = root / "tape2"
            source.mkdir()
            tape1.mkdir()
            tape2.mkdir()
            mib = 1024**2
            (source / "a.bin").write_bytes(b"a" * (5 * mib))
            (source / "b.bin").write_bytes(b"b" * (3 * mib))
            (source / "c.bin").write_bytes(b"c" * (2 * mib))
            volumes = FakeVolumes()
            volumes.add(tape1, "SERIAL1", free_bytes=200 * GIB + 11 * mib)
            volumes.add(tape2, "SERIAL2", free_bytes=200 * GIB + 11 * mib)
            catalog, engine = self.make_engine(root, source, volumes)
            try:
                engine.register_tape("TAPE1", tape1)
                engine.register_tape("TAPE2", tape2)

                first = engine.backup("LIB1", "TAPE1", tape1)
                assert first is not None
                self.assertEqual(1, first.copied_files)
                self.assertEqual(5 * mib, first.copied_bytes)
                self.assertEqual(2, first.remaining_files)
                self.assertEqual(5 * mib, first.remaining_bytes)
                self.assertEqual(1, first.estimated_remaining_tapes)

                second = engine.backup("LIB1", "TAPE2", tape2)
                assert second is not None
                self.assertEqual(2, second.copied_files)
                self.assertEqual(5 * mib, second.copied_bytes)
                self.assertEqual(0, second.remaining_files)
                self.assertEqual(0, second.estimated_remaining_tapes)
            finally:
                catalog.close()


if __name__ == "__main__":
    unittest.main()
