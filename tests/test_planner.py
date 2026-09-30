from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ltobackup.application import LtoApplication, _plan_ltfs_batches
from ltobackup.errors import CapacityError
from ltobackup.media import get_lto_media_profile, lto_media_profiles
from ltobackup.models import LibraryAnalysis, ScanItem
from ltobackup.planner import (
    LTFS_ALLOCATION_UNIT_BYTES,
    LtfsCapacityModel,
    plan_tape_batches,
    select_tape_batch,
)
from ltobackup.settings import Settings, save_settings


class TapePlannerTests(unittest.TestCase):
    @staticmethod
    def item(name: str, size: int) -> ScanItem:
        return ScanItem(Path(name), name, size, 1)

    def test_first_fit_decreasing_produces_deterministic_tape_batches(self) -> None:
        items = (
            self.item("d.bin", 20),
            self.item("b.bin", 40),
            self.item("a.bin", 60),
            self.item("c.bin", 40),
        )

        batches = plan_tape_batches(items, usable_bytes=100)

        self.assertEqual(2, len(batches))
        self.assertEqual(["a.bin", "b.bin"], [item.relative_path for item in batches[0].items])
        self.assertEqual(100, batches[0].total_bytes)
        self.assertEqual(["c.bin", "d.bin"], [item.relative_path for item in batches[1].items])
        self.assertEqual(60, batches[1].total_bytes)

    def test_file_larger_than_usable_tape_capacity_is_rejected(self) -> None:
        with self.assertRaises(CapacityError):
            plan_tape_batches((self.item("huge.bin", 101),), usable_bytes=100)

    def test_current_partial_tape_skips_files_that_need_a_fresher_tape(self) -> None:
        batch = select_tape_batch(
            (self.item("large.bin", 1000), self.item("small.bin", 400)),
            usable_bytes=500,
        )

        self.assertEqual(["small.bin"], [item.relative_path for item in batch.items])

    def test_ltfs_plan_never_fills_any_supported_media_profile_with_payload_only(self) -> None:
        for profile in lto_media_profiles():
            with self.subTest(media=profile.key):
                assert profile.ltfs_usable_bytes is not None
                capacity = profile.ltfs_usable_bytes
                item = ScanItem(
                    Path("library.bin"), "library.bin", capacity - 1, 1, library_id="LIB1"
                )

                with self.assertRaises(CapacityError):
                    plan_tape_batches(
                        (item,),
                        usable_bytes=capacity,
                        capacity_model=LtfsCapacityModel(),
                    )

    def test_ltfs_plan_accounts_for_file_allocation_and_one_block_per_library(self) -> None:
        unit = LTFS_ALLOCATION_UNIT_BYTES
        items = (
            ScanItem(Path("a.bin"), "a.bin", unit + 1, 1, library_id="LIB1"),
            ScanItem(Path("b.bin"), "b.bin", unit, 1, library_id="LIB2"),
        )

        batches = plan_tape_batches(
            items,
            usable_bytes=13 * unit,
            capacity_model=LtfsCapacityModel(),
        )

        self.assertEqual(1, len(batches))
        self.assertEqual(2 * unit + 1, batches[0].total_bytes)
        self.assertEqual(13 * unit, batches[0].capacity_used_bytes)
        self.assertEqual(0, batches[0].remaining_bytes)

    def test_media_reserve_uses_literal_ltfs_capacity_for_every_profile(self) -> None:
        expected_effective_bytes = {
            "LTO-5": 1_215_251_635_200,
            "LTO-6": 2_195_251_635_200,
            "LTO-7": 5_515_251_635_200,
            "LTO-8": 11_495_251_635_200,
            "LTO-9": 17_335_251_635_200,
            "LTO-10 LA": 27_615_251_635_200,
            "LTO-10 PA": 36_815_251_635_200,
        }
        settings = Settings(reserve_bytes=214_748_364_800)

        self.assertEqual(
            expected_effective_bytes,
            {
                key: LtoApplication._media_usable_tape_bytes(
                    settings, get_lto_media_profile(key)
                )
                for key in expected_effective_bytes
            },
        )

    def test_lto5_plan_matches_hand_calculated_rounding_block_overhead_and_remaining(self) -> None:
        items = (
            ScanItem(Path("Caffè/A.bin"), "Caffè/A.bin", 600_000_000_001, 1, library_id="ALPHA"),
            ScanItem(Path("I Flintstones /B.bin"), "I Flintstones /B.bin", 600_000_000_000, 1, library_id="ALPHA"),
            ScanItem(Path("CON.txt"), "CON.txt", 100_000_000_001, 1, library_id="BETA"),
        )

        batches = plan_tape_batches(
            items,
            1_215_251_635_200,
            capacity_model=LtfsCapacityModel(),
        )

        self.assertEqual(2, len(batches))
        self.assertEqual(
            ["Caffè/A.bin", "I Flintstones /B.bin"],
            [item.relative_path for item in batches[0].items],
        )
        self.assertEqual(1_200_007_151_616, batches[0].capacity_used_bytes)
        self.assertEqual(15_244_483_584, batches[0].remaining_bytes)
        self.assertEqual(["CON.txt"], [item.relative_path for item in batches[1].items])
        self.assertEqual(100_005_838_848, batches[1].capacity_used_bytes)
        self.assertEqual(1_115_245_796_352, batches[1].remaining_bytes)
        self.assertEqual(1_300_000_000_002, sum(batch.total_bytes for batch in batches))
        self.assertEqual(1_300_012_990_464, sum(batch.capacity_used_bytes for batch in batches))
        self.assertEqual(
            12_990_462,
            sum(batch.capacity_used_bytes - batch.total_bytes for batch in batches),
        )
        capacity_model = LtfsCapacityModel()
        self.assertEqual(
            (1_478_655, 1_478_656, 1_644_543),
            tuple(capacity_model.item_bytes(item) - item.size for item in items),
        )
        self.assertEqual(
            4_601_854,
            sum(capacity_model.item_bytes(item) - item.size for item in items),
        )
        self.assertEqual(
            8_388_608,
            sum(
                len({item.library_id for item in batch.items})
                * capacity_model.block_bytes
                for batch in batches
            ),
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(reserve_bytes=214_748_364_800, min_age_seconds=0),
            )
            (root / "alpha").mkdir()
            (root / "beta").mkdir()
            application.add_library("ALPHA", "Alpha", str(root / "alpha"))
            application.add_library("BETA", "Beta", str(root / "beta"))
            analyses = {
                "ALPHA": LibraryAnalysis(
                    library_id="ALPHA",
                    source_root=root / "alpha",
                    entries=(),
                    pending_items=items[:2],
                    total_files=2,
                    total_bytes=1_200_000_000_001,
                    archived_files=0,
                    archived_bytes=0,
                    too_recent_files=0,
                    too_recent_bytes=0,
                    extension_counts=(),
                ),
                "BETA": LibraryAnalysis(
                    library_id="BETA",
                    source_root=root / "beta",
                    entries=(),
                    pending_items=items[2:],
                    total_files=1,
                    total_bytes=100_000_000_001,
                    archived_files=0,
                    archived_bytes=0,
                    too_recent_files=0,
                    too_recent_bytes=0,
                    extension_counts=(),
                ),
            }

            with (
                patch(
                    "ltobackup.application._source_identity",
                    side_effect=lambda value: (str(value), "1" * 64),
                ),
                patch(
                    "ltobackup.application.analyze_library",
                    side_effect=lambda _catalog, library_id, *_args, **_kwargs: analyses[
                        library_id
                    ],
                ),
            ):
                projection = application.plan_automatic_job(
                    ["ALPHA", "BETA"], media_key="LTO-5"
                )

        self.assertEqual(1_430_000_000_000, projection["nominal_tape_bytes"])
        self.assertEqual(214_748_364_800, projection["reserve_bytes"])
        self.assertEqual(1_215_251_635_200, projection["usable_tape_bytes"])
        self.assertEqual(2, projection["estimated_tapes"])
        self.assertEqual(
            (
                (1_200_007_151_616, 7_151_615, 15_244_483_584),
                (100_005_838_848, 5_838_847, 1_115_245_796_352),
            ),
            tuple(
                (
                    cassette["capacity_used_bytes"],
                    cassette["ltfs_overhead_bytes"],
                    cassette["remaining_bytes"],
                )
                for cassette in projection["cassettes"]
            ),
        )

    def test_high_reserve_keeps_nominal_media_capacity_for_overhead_model_selection(self) -> None:
        sentinel = object()
        item = ScanItem(Path("tiny.bin"), "tiny.bin", 1, 1, library_id="ALPHA")

        with (
            patch("ltobackup.application.capacity_model_for_media", return_value=sentinel) as choose,
            patch("ltobackup.application.plan_tape_batches", return_value=()) as planner,
        ):
            _plan_ltfs_batches(
                (item,),
                500_000_000_000,
                nominal_capacity_bytes=1_430_000_000_000,
            )

        choose.assert_called_once_with(1_430_000_000_000)
        planner.assert_called_once_with(
            (item,), 500_000_000_000, capacity_model=sentinel
        )


if __name__ == "__main__":
    unittest.main()
