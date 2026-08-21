from __future__ import annotations

import unittest

from ltobackup.errors import ValidationError
from ltobackup.media import get_lto_media_profile, lto_media_profiles


class LtoMediaProfileTests(unittest.TestCase):
    def test_profiles_start_at_lto5_and_cover_both_lto10_media_types(self) -> None:
        profiles = lto_media_profiles()

        self.assertEqual(
            ["LTO-5", "LTO-6", "LTO-7", "LTO-8", "LTO-9", "LTO-10 LA", "LTO-10 PA"],
            [profile.key for profile in profiles],
        )
        self.assertEqual(
            [1_500, 2_500, 6_000, 12_000, 18_000, 30_000, 40_000],
            [profile.native_capacity_bytes // 1_000_000_000 for profile in profiles],
        )

    def test_profiles_use_documented_ltfs_data_partition_capacities(self) -> None:
        expected_tb = {
            "LTO-5": 1.43,
            "LTO-6": 2.41,
            "LTO-7": 5.73,
            "LTO-8": 11.71,
            "LTO-9": 17.55,
            "LTO-10 LA": 27.83,
            "LTO-10 PA": 37.03,
        }

        for key, usable_tb in expected_tb.items():
            with self.subTest(key=key):
                self.assertEqual(
                    int(usable_tb * 1_000_000_000_000),
                    get_lto_media_profile(key).ltfs_usable_bytes,
                )

        with self.assertRaisesRegex(ValidationError, "non supportato"):
            get_lto_media_profile("LTO-4")

    def test_unknown_media_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "(?i)tipo di cassetta"):
            get_lto_media_profile("LTO-11")
