"""Value objects for offline migration acceptance."""

from __future__ import annotations

from dataclasses import dataclass

from ltobackup.errors import LtoBackupError


class MigrationRejected(LtoBackupError):
    """The source catalog does not meet the frozen-job migration contract."""


@dataclass(frozen=True)
class AcceptanceReport:
    job_id: str
    accepted: bool
    next_sequence: int | None
    total_cassettes: int
    completed_sequences: tuple[int, ...]
    assignment_sha256: str
    error_codes: tuple[str, ...]
    media_accesses: tuple[str, ...] = ()

    def require_valid(self) -> None:
        if not self.accepted:
            raise MigrationRejected(",".join(self.error_codes))
