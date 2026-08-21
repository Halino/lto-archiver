from __future__ import annotations

from dataclasses import dataclass

from .errors import ValidationError


TB = 1_000_000_000_000
GB = 1_000_000_000


@dataclass(frozen=True)
class LtoMediaProfile:
    key: str
    generation: int
    native_capacity_bytes: int
    compressed_capacity_bytes: int
    ltfs_usable_bytes: int | None
    barcode_suffix: str
    variant: str = ""

    @property
    def ltfs_supported(self) -> bool:
        return self.ltfs_usable_bytes is not None

    @property
    def native_capacity_tb(self) -> float:
        return self.native_capacity_bytes / TB

    @property
    def compressed_capacity_tb(self) -> float:
        return self.compressed_capacity_bytes / TB

    @property
    def ltfs_usable_tb(self) -> float | None:
        if self.ltfs_usable_bytes is None:
            return None
        return self.ltfs_usable_bytes / TB


# Capacita native/compressed: specifiche LTO/HPE. Capacita LTFS: dimensione
# utilizzabile della data partition documentata da IBM Storage Archive.
_PROFILES = (
    LtoMediaProfile("LTO-5", 5, 1_500 * GB, 3 * TB, 1_430_000_000_000, "L5"),
    LtoMediaProfile("LTO-6", 6, 2_500 * GB, 6_250 * GB, 2_410_000_000_000, "L6"),
    LtoMediaProfile("LTO-7", 7, 6 * TB, 15 * TB, 5_730_000_000_000, "L7"),
    LtoMediaProfile("LTO-8", 8, 12 * TB, 30 * TB, 11_710_000_000_000, "L8"),
    LtoMediaProfile("LTO-9", 9, 18 * TB, 45 * TB, 17_550_000_000_000, "L9"),
    LtoMediaProfile(
        "LTO-10 LA", 10, 30 * TB, 75 * TB, 27_830_000_000_000, "LA", "standard"
    ),
    LtoMediaProfile(
        "LTO-10 PA", 10, 40 * TB, 100 * TB, 37_030_000_000_000, "PA", "premium"
    ),
)
_BY_KEY = {profile.key: profile for profile in _PROFILES}


def lto_media_profiles() -> tuple[LtoMediaProfile, ...]:
    return _PROFILES


def get_lto_media_profile(value: str | int | None = None) -> LtoMediaProfile:
    if value is None:
        return _BY_KEY["LTO-6"]
    if isinstance(value, int):
        value = f"LTO-{value}"
    normalized = str(value).strip().upper().replace("_", " ")
    aliases = {
        "5": "LTO-5", "6": "LTO-6", "7": "LTO-7",
        "8": "LTO-8", "9": "LTO-9", "10": "LTO-10 LA", "LTO-10": "LTO-10 LA",
        "LTO10": "LTO-10 LA", "LTO10 LA": "LTO-10 LA", "LTO10 PA": "LTO-10 PA",
    }
    key = aliases.get(normalized, normalized)
    try:
        return _BY_KEY[key]
    except KeyError as exc:
        raise ValidationError(f"Tipo di cassetta LTO non supportato: {value}") from exc


def require_ltfs_profile(value: str | int | None = None) -> LtoMediaProfile:
    return get_lto_media_profile(value)
