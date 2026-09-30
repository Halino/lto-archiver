from __future__ import annotations

import uuid
from dataclasses import dataclass
from pathlib import Path

from ltobackup.tape.command_supervisor import (
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
)


@dataclass(frozen=True)
class ExpectedMedia:
    operation_kind: str
    job_id: str
    cassette_sequence: int
    volume_label: str
    volume_serial: str | None
    volume_uuid: str | None = None

    def __post_init__(self) -> None:
        if not _exact_media_text(self.volume_label, maximum=255):
            raise ValueError("expected LTFS label is invalid")
        if self.volume_serial is not None and not _exact_media_text(
            self.volume_serial, maximum=32
        ):
            raise ValueError("expected tape serial is invalid")
        if self.volume_uuid is not None:
            try:
                if str(uuid.UUID(self.volume_uuid)) != self.volume_uuid:
                    raise ValueError
            except (AttributeError, TypeError, ValueError):
                raise ValueError("expected LTFS UUID is invalid") from None

    def target_scope(self) -> tuple[str, ...]:
        return (
            self.operation_kind,
            self.job_id,
            str(self.cassette_sequence),
            self.volume_label,
            self.volume_serial or "",
            self.volume_uuid or "",
        )


def expected_media_from_catalog(
    operation_kind: str,
    job_id: str,
    cassette_sequence: int,
    volume_label: str,
    volume_serial: str | None,
    volume_uuid: str | None,
) -> ExpectedMedia:
    """Build strict expected media, including the legacy UUID-in-serial layout."""
    if volume_uuid is None and type(volume_serial) is str:
        try:
            canonical_uuid = str(uuid.UUID(volume_serial))
        except (AttributeError, TypeError, ValueError):
            pass
        else:
            if canonical_uuid == volume_serial:
                volume_serial = None
                volume_uuid = canonical_uuid
    return ExpectedMedia(
        operation_kind,
        job_id,
        cassette_sequence,
        volume_label,
        volume_serial,
        volume_uuid,
    )


def _exact_media_text(value: object, *, maximum: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= maximum
        and value == value.strip(" ")
        and value.isascii()
        and value.isprintable()
    )


@dataclass(frozen=True)
class MediaIdentity:
    drive_serial: str
    mam_barcode: str | None = None
    mam_volume_serial: str | None = None
    ltfs_volume_label: str | None = None
    ltfs_volume_uuid: str | None = None

    @property
    def volume_label(self) -> str | None:
        return self.ltfs_volume_label

    @property
    def volume_serial(self) -> str | None:
        return self.mam_volume_serial

    def canonical_fields(self) -> tuple[object | None, ...]:
        return (
            self.drive_serial,
            self.mam_barcode,
            self.mam_volume_serial,
            self.ltfs_volume_label,
            self.ltfs_volume_uuid,
        )


@dataclass(frozen=True)
class MediaIdentityFields:
    mam_barcode: str | None = None
    mam_volume_serial: str | None = None
    ltfs_volume_label: str | None = None
    ltfs_volume_uuid: str | None = None
    index_generation: int | None = None


@dataclass(frozen=True)
class MountedTape:
    path: Path
    read_only: bool
    session_receipt: LtfsSessionReceipt


@dataclass(frozen=True)
class UnmountResult:
    finalization_seconds: float
    mount_release_seconds: float
    finalization_receipt: LtfsFinalizationReceipt

    @property
    def observed_volume_label(self) -> str:
        return self.finalization_receipt.session_receipt.observed_volume_label

    @property
    def observed_media_identity_sha256(self) -> str:
        return self.finalization_receipt.session_receipt.observed_media_identity_sha256


@dataclass(frozen=True)
class TapeTelemetry:
    available: bool
    remaining_bytes: int | None = None
    position_bytes: int | None = None


@dataclass(frozen=True)
class BackendHealth:
    available: bool
    required_tools: tuple[str, ...]
    detail_code: str | None = None
