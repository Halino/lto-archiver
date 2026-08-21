from __future__ import annotations

import unittest
from pathlib import Path

from ltobackup.errors import CapacityError
from ltobackup.media import lto_media_profiles
from ltobackup.models import ScanItem
from ltobackup.planner import (
    LTFS_ALLOCATION_UNIT_BYTES,
    LtfsCapacityModel,
    plan_tape_batches,
    select_tape_batch,
)


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


if __name__ == "__main__":
    unittest.main()
