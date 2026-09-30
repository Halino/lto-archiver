from __future__ import annotations

from dataclasses import dataclass

from .errors import CapacityError, ValidationError
from .models import ScanItem, TapeBatch
from .util import human_bytes


LTFS_ALLOCATION_UNIT_BYTES = 1024**2
LTFS_BLOCK_COMPLETION_UNITS = 4


@dataclass(frozen=True)
class LtfsCapacityModel:
    """Conservative LTFS allocation estimate expressed in MiB units.

    Each data object is rounded to the unit used by the LTFS capacity
    attributes and receives one unit for its index/manifest metadata. Every
    library written to a cassette creates an independent block and therefore
    reserves four units for its directories, manifest and block descriptor.
    """

    allocation_unit_bytes: int = LTFS_ALLOCATION_UNIT_BYTES
    block_completion_units: int = LTFS_BLOCK_COMPLETION_UNITS

    def __post_init__(self) -> None:
        if self.allocation_unit_bytes <= 0 or self.block_completion_units < 0:
            raise ValueError("Il modello di capacita LTFS deve usare valori positivi")

    def file_bytes(self, size: int) -> int:
        units = (size + self.allocation_unit_bytes - 1) // self.allocation_unit_bytes
        return (units + 1) * self.allocation_unit_bytes

    def item_bytes(self, item: ScanItem) -> int:
        return self.file_bytes(item.size)

    @property
    def block_bytes(self) -> int:
        return self.block_completion_units * self.allocation_unit_bytes

    def batch_bytes(self, items: tuple[ScanItem, ...] | list[ScanItem]) -> int:
        libraries = {item.library_id or "" for item in items}
        return sum(self.item_bytes(item) for item in items) + len(libraries) * self.block_bytes


LTFS_CAPACITY_MODEL = LtfsCapacityModel()
MINIMUM_SUPPORTED_LTFS_MEDIA_BYTES = 1_000_000_000_000


def capacity_model_for_media(nominal_capacity_bytes: int) -> LtfsCapacityModel | None:
    """Return LTFS accounting for real media, while allowing byte-scale simulations."""
    if nominal_capacity_bytes < MINIMUM_SUPPORTED_LTFS_MEDIA_BYTES:
        return None
    return LTFS_CAPACITY_MODEL


def plan_tape_batches(
    items: tuple[ScanItem, ...] | list[ScanItem],
    usable_bytes: int,
    *,
    capacity_model: LtfsCapacityModel | None = None,
) -> tuple[TapeBatch, ...]:
    """Distribute indivisible files deterministically with first-fit decreasing."""
    if usable_bytes <= 0:
        raise ValidationError("La capacita utilizzabile per nastro deve essere maggiore di zero")

    ordered = sorted(
        items,
        key=lambda item: (
            -item.size, (item.library_id or "").casefold(),
            item.relative_path.casefold(), item.relative_path,
        ),
    )
    bins: list[list[ScanItem]] = []
    used: list[int] = []
    libraries: list[set[str]] = []
    for item in ordered:
        item_bytes = capacity_model.item_bytes(item) if capacity_model else item.size
        library = item.library_id or ""
        empty_batch_bytes = item_bytes + (
            capacity_model.block_bytes if capacity_model else 0
        )
        if empty_batch_bytes > usable_bytes:
            raise CapacityError(
                f"Il file {item.relative_path} ({human_bytes(item.size)}) supera la capacita "
                f"utilizzabile di una singola cassetta ({human_bytes(usable_bytes)})."
            )
        for index, occupied in enumerate(used):
            block_bytes = (
                capacity_model.block_bytes
                if capacity_model and library not in libraries[index]
                else 0
            )
            candidate_bytes = occupied + item_bytes + block_bytes
            if candidate_bytes <= usable_bytes:
                bins[index].append(item)
                used[index] = candidate_bytes
                libraries[index].add(library)
                break
        else:
            bins.append([item])
            used.append(empty_batch_bytes)
            libraries.append({library})

    return tuple(
        TapeBatch(
            slot=index,
            items=tuple(sorted(
                batch,
                key=lambda item: (
                    (item.library_id or "").casefold(), item.relative_path.casefold(), item.relative_path,
                ),
            )),
            usable_bytes=usable_bytes,
            capacity_used_bytes=used[index - 1],
        )
        for index, batch in enumerate(bins, start=1)
    )


def select_tape_batch(
    items: tuple[ScanItem, ...] | list[ScanItem],
    usable_bytes: int,
    *,
    capacity_model: LtfsCapacityModel | None = None,
) -> TapeBatch:
    """Choose a deterministic subset that fits the currently mounted cartridge."""
    if usable_bytes <= 0:
        raise CapacityError("Il nastro montato non ha spazio utilizzabile per un nuovo file.")
    selected: list[ScanItem] = []
    occupied = 0
    libraries: set[str] = set()
    for item in sorted(
        items,
        key=lambda value: (
            -value.size, (value.library_id or "").casefold(),
            value.relative_path.casefold(), value.relative_path,
        ),
    ):
        library = item.library_id or ""
        item_bytes = capacity_model.item_bytes(item) if capacity_model else item.size
        block_bytes = (
            capacity_model.block_bytes
            if capacity_model and library not in libraries
            else 0
        )
        if item_bytes + block_bytes <= usable_bytes - occupied:
            selected.append(item)
            occupied += item_bytes + block_bytes
            libraries.add(library)
    if not selected:
        smallest = min(items, key=lambda item: item.size)
        raise CapacityError(
            f"Nessun file pendente entra nel nastro montato: il piu piccolo e "
            f"{smallest.relative_path} ({human_bytes(smallest.size)}), ma sono utilizzabili "
            f"{human_bytes(usable_bytes)}. Montare una cassetta con piu spazio."
        )
    return TapeBatch(
        slot=1,
        items=tuple(sorted(
            selected,
            key=lambda item: (
                (item.library_id or "").casefold(), item.relative_path.casefold(), item.relative_path,
            ),
        )),
        usable_bytes=usable_bytes,
        capacity_used_bytes=occupied,
    )
