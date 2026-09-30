from __future__ import annotations

import unittest

from ltobackup.errors import ValidationError
from ltobackup.media import get_lto_media_profile, lto_media_profiles

LITERAL_LTO_PROFILE_FIXTURE = (
    ("LTO-5", 5, 1_500_000_000_000, 3_000_000_000_000, 1_430_000_000_000, "L5", ""),
    ("LTO-6", 6, 2_500_000_000_000, 6_250_000_000_000, 2_410_000_000_000, "L6", ""),
    ("LTO-7", 7, 6_000_000_000_000, 15_000_000_000_000, 5_730_000_000_000, "L7", ""),
    ("LTO-8", 8, 12_000_000_000_000, 30_000_000_000_000, 11_710_000_000_000, "L8", ""),
    ("LTO-9", 9, 18_000_000_000_000, 45_000_000_000_000, 17_550_000_000_000, "L9", ""),
    ("LTO-10 LA", 10, 30_000_000_000_000, 75_000_000_000_000, 27_830_000_000_000, "LA", "standard"),
    ("LTO-10 PA", 10, 40_000_000_000_000, 100_000_000_000_000, 37_030_000_000_000, "PA", "premium"),
)


class LtoMediaProfileTests(unittest.TestCase):
    def test_profiles_match_independent_literal_byte_fixture(self) -> None:
        profiles = lto_media_profiles()

        self.assertEqual(
            LITERAL_LTO_PROFILE_FIXTURE,
            tuple(
                (
                    profile.key,
                    profile.generation,
                    profile.native_capacity_bytes,
                    profile.compressed_capacity_bytes,
                    profile.ltfs_usable_bytes,
                    profile.barcode_suffix,
                    profile.variant,
                )
                for profile in profiles
            ),
        )
        self.assertEqual((True,) * 7, tuple(profile.ltfs_supported for profile in profiles))

    def test_lto10_canonical_aliases_select_standard_la_without_hiding_pa(self) -> None:
        standard = LITERAL_LTO_PROFILE_FIXTURE[-2]
        premium = LITERAL_LTO_PROFILE_FIXTURE[-1]

        for alias in (10, "10", "LTO-10", "LTO10"):
            with self.subTest(alias=alias):
                profile = get_lto_media_profile(alias)
                self.assertEqual(
                    standard,
                    (
                        profile.key,
                        profile.generation,
                        profile.native_capacity_bytes,
                        profile.compressed_capacity_bytes,
                        profile.ltfs_usable_bytes,
                        profile.barcode_suffix,
                        profile.variant,
                    ),
                )

        for alias in ("LTO-10 PA", "LTO10 PA"):
            with self.subTest(alias=alias):
                profile = get_lto_media_profile(alias)
                self.assertEqual(
                    premium,
                    (
                        profile.key,
                        profile.generation,
                        profile.native_capacity_bytes,
                        profile.compressed_capacity_bytes,
                        profile.ltfs_usable_bytes,
                        profile.barcode_suffix,
                        profile.variant,
                    ),
                )

        for generation in range(5, 10):
            with self.subTest(generation=generation):
                self.assertEqual(f"LTO-{generation}", get_lto_media_profile(generation).key)

        with self.assertRaisesRegex(ValidationError, "non supportato"):
            get_lto_media_profile("LTO-4")

    def test_unknown_media_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValidationError, "(?i)tipo di cassetta"):
            get_lto_media_profile("LTO-11")
