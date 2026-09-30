from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..errors import ValidationError as DomainValidationError
from ..log_reader.protocol import LogDirection, LogRange, LogSource, Severity
from ..managed_sources import normalize_managed_source_subpath
from ..media import require_ltfs_profile
from ..shares import ShareConfig


class ClosedV1Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


_SAFE_JOB_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_PHYSICAL_LABEL = re.compile(r"^[A-Z0-9]{6}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_LIBRARY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_SAFE_SHARE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")


def _normalized_physical_label(value: str) -> str:
    normalized = value.strip().upper()
    if not _PHYSICAL_LABEL.fullmatch(normalized):
        raise ValueError("physical label is invalid")
    return normalized


def _require_canonical_restore_path(value: str) -> None:
    path = PurePosixPath(value)
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\x00" in value
        or any(part in {".", ".."} for part in path.parts)
        or path.as_posix() != value
    ):
        raise ValueError("restore destination path is invalid")


class CreateNativeJobRequestV1(ClosedV1Model):
    """Create a label-authoritative native backup after an exact logical reset."""

    display_name: str = Field(min_length=1, max_length=120)
    labels: tuple[str, ...] = Field(min_length=1, max_length=64)
    expected_job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    typed_job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)

    @model_validator(mode="after")
    def normalize_and_confirm(self) -> Self:
        display_name = self.display_name.strip()
        labels = tuple(_normalized_physical_label(label) for label in self.labels)
        if (
            not display_name
            or any(ord(character) < 32 for character in display_name)
            or len(set(labels)) != len(labels)
            or not secrets.compare_digest(self.expected_job_id, self.typed_job_id)
        ):
            raise ValueError("native job reset confirmation is invalid")
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "labels", labels)
        return self


class OperationRequest(ClosedV1Model):
    """Additive V1 operation request; only an imported job identifier is accepted."""

    kind: Literal["diagnostic", "archive.resume", "archive.native"]
    job_id: str | None = None

    @model_validator(mode="after")
    def require_job_for_archive_resume(self) -> Self:
        if self.kind == "diagnostic" and self.job_id is not None:
            raise ValueError("diagnostic operations do not accept a job identifier")
        if self.kind in {"archive.resume", "archive.native"} and (
            self.job_id is None or not _SAFE_JOB_ID.fullmatch(self.job_id)
        ):
            raise ValueError("archive operation requires a safe job identifier")
        return self


class ResumeArchiveRequestV1(ClosedV1Model):
    """Operator evidence accepted when resuming one frozen archive job."""

    cutover_credential: str | None = None
    format_confirmation_label: str | None = None


class SignedAcceptanceReportV1(ClosedV1Model):
    """Hash-bound offline acceptance evidence for cassette four."""

    job_id: str
    next_sequence: Literal[4]
    bundle_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    assignment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_label: str = Field(min_length=1, max_length=255)
    host_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    drive_serial_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expires_at: str

    @model_validator(mode="after")
    def require_safe_current_report(self) -> Self:
        if not _SAFE_JOB_ID.fullmatch(self.job_id):
            raise ValueError("cutover report has an invalid job identifier")
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError as exc:
            raise ValueError(
                "cutover report expiry must be an absolute timestamp"
            ) from exc
        if expiry.utcoffset() != timedelta(0):
            raise ValueError("cutover report expiry must be UTC")
        return self


class CutoverAuthorizationRequestV1(ClosedV1Model):
    acceptance_report: SignedAcceptanceReportV1
    credential_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class OperationResponseV1(ClosedV1Model):
    id: str
    kind: str
    state: str
    phase: str | None
    idempotency_key: str
    principal: str
    job_id: str | None
    cassette_sequence: int | None
    started_at: str
    finished_at: str | None
    error_class: str | None
    error_code: str | None
    error_message: str | None


class BoundaryRefreshAcceptedV1(ClosedV1Model):
    kind: Literal["boundary.refresh"]
    state: Literal["accepted"]
    job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    request_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)


class CriticalRecoveryTargetV1(ClosedV1Model):
    mount_path_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    tape_device_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scsi_device_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_media_scope_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class PreMediaResetProofV1(ClosedV1Model):
    operation_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    cassette_sequence: int = Field(ge=1)
    daemon_generation: int = Field(ge=1)
    command_ledger_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target: CriticalRecoveryTargetV1


class ResetPreMediaAttemptRequestV1(PreMediaResetProofV1):
    pass


class CriticalRecoveryProofV1(ClosedV1Model):
    operation_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    cassette_sequence: int = Field(ge=1)
    expected_label: str
    target: CriticalRecoveryTargetV1
    daemon_generation: int = Field(ge=1)
    attempt_number: int = Field(ge=1)
    last_safe_checkpoint: str | None = Field(default=None, max_length=64)
    evidence_category: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_media_identity_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    commands_quiescent: bool
    mount_quiescent: bool
    processes_quiescent: bool
    observed_at: str
    safe_explanation: str = Field(min_length=1, max_length=500)
    safe_next_action: str = Field(min_length=1, max_length=500)

    @field_validator("expected_label")
    @classmethod
    def normalize_expected_label(cls, value: str) -> str:
        return _normalized_physical_label(value)


class _CriticalRecoveryRequestV1(ClosedV1Model):
    operation_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    cassette_sequence: int = Field(ge=1)
    expected_label: str
    target: CriticalRecoveryTargetV1
    daemon_generation: int = Field(ge=1)
    attempt_number: int = Field(ge=1)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    observed_media_identity_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )

    @field_validator("expected_label")
    @classmethod
    def normalize_expected_label(cls, value: str) -> str:
        return _normalized_physical_label(value)


class ReconcileCriticalRecoveryRequestV1(_CriticalRecoveryRequestV1):
    pass


class AbandonCriticalAttemptRequestV1(_CriticalRecoveryRequestV1):
    pass


class AuthorizeReplacementAttemptRequestV1(_CriticalRecoveryRequestV1):
    typed_label_confirmation: str

    @model_validator(mode="after")
    def require_exact_label_confirmation(self) -> Self:
        confirmation = _normalized_physical_label(self.typed_label_confirmation)
        if not secrets.compare_digest(self.expected_label, confirmation):
            raise ValueError("critical replacement label confirmation is invalid")
        object.__setattr__(self, "typed_label_confirmation", confirmation)
        return self


class HealthV1(ClosedV1Model):
    status: Literal["ok"]
    api_version: Literal[1] = 1


class SafeErrorV1(ClosedV1Model):
    code: str
    message: str


class PublicErrorV1(ClosedV1Model):
    error: SafeErrorV1


class CreateShareRequestV1(ClosedV1Model):
    share_id: str = Field(pattern=_SAFE_SHARE_ID.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    config: ShareConfig
    auto_connect: bool = False

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("share display name is invalid")
        return normalized


class UpdateShareRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=1)
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    config: ShareConfig | None = None
    auto_connect: bool | None = None
    lifecycle: Literal["active", "disabled"] | None = None

    @model_validator(mode="after")
    def require_change(self) -> Self:
        if all(
            value is None
            for value in (
                self.display_name,
                self.config,
                self.auto_connect,
                self.lifecycle,
            )
        ):
            raise ValueError("share update is empty")
        if self.display_name is not None:
            normalized = CreateShareRequestV1.normalize_display_name(self.display_name)
            object.__setattr__(self, "display_name", normalized)
        return self


class ShareOperationRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=1)


class ShareCredentialRequestV1(ShareOperationRequestV1):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=4096)
    domain: str | None = Field(default=None, max_length=256)

    @field_validator("username", "password", "domain")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is not None and any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("credential value is invalid")
        return value


class _ConfirmedShareRequestV1(ShareOperationRequestV1):
    typed_share_id: str = Field(pattern=_SAFE_SHARE_ID.pattern)

    def confirm(self, share_id: str) -> Self:
        if not secrets.compare_digest(self.typed_share_id, share_id):
            raise ValueError("share confirmation does not match")
        return self


class ShareConfirmedOperationRequestV1(_ConfirmedShareRequestV1):
    pass


class ShareRetireRequestV1(_ConfirmedShareRequestV1):
    pass


class ShareRemoveRequestV1(_ConfirmedShareRequestV1):
    pass


class ShareCredentialClearRequestV1(_ConfirmedShareRequestV1):
    pass


class ShareOperationV1(ClosedV1Model):
    operation_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    share_id: str = Field(pattern=_SAFE_SHARE_ID.pattern)
    action: Literal[
        "connect",
        "disconnect",
        "test",
        "reconcile",
        "credential.install",
        "credential.clear",
    ]
    state: Literal["queued", "running", "recovering", "succeeded", "failed"]
    safe_error_code: str | None
    queued_at: str
    started_at: str | None
    finished_at: str | None


class ShareSummaryV1(ClosedV1Model):
    share_id: str = Field(pattern=_SAFE_SHARE_ID.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    protocol: Literal["nfs", "smb"]
    lifecycle: Literal["active", "disabled", "retired"]
    desired_state: Literal["connected", "disconnected"]
    observed_state: Literal[
        "disconnected", "connecting", "connected", "disconnecting", "error"
    ]
    safe_error_code: str | None
    last_checked_at: str | None
    revision: int = Field(ge=1)
    current_operation: ShareOperationV1 | None = None
    latest_operation: ShareOperationV1 | None = None


class ShareV1(ShareSummaryV1):
    config: ShareConfig
    config_revision: int = Field(ge=1)
    credential_generation: int = Field(ge=0)
    credential_configured: bool
    auto_connect: bool
    mount_identity_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    mounted_config_revision: int | None = Field(default=None, ge=1)
    mounted_credential_generation: int | None = Field(default=None, ge=0)
    created_at: str
    updated_at: str


class NetworkShareOptionsV1(ClosedV1Model):
    nfs_versions: tuple[Literal["3", "4", "4.1", "4.2"], ...] = Field(
        min_length=1, max_length=4
    )
    nfs_timeout_seconds: tuple[Literal[5, 15, 30, 60, 120, 300, 600], ...] = Field(
        min_length=1, max_length=7
    )
    nfs_retransmissions: tuple[Literal[1, 2, 3, 5, 10], ...] = Field(
        min_length=1, max_length=5
    )
    smb_dialects: tuple[Literal["3.0", "3.1.1"], ...] = Field(
        min_length=1, max_length=2
    )
    lifecycles: tuple[Literal["active", "disabled"], ...] = Field(
        min_length=1, max_length=2
    )


class OperationConflictV1(ClosedV1Model):
    error: SafeErrorV1
    active_operation: OperationResponseV1


class TelemetrySampleV1(ClosedV1Model):
    event_id: int
    occurred_at: str
    mib_per_second: float | None


class DriveStatusV1(ClosedV1Model):
    state: Literal["unavailable", "empty", "loaded", "busy", "attention"]
    loaded: bool | None
    display_label: str
    cleaning_required: bool | None
    tape_alert_codes: tuple[str, ...] | None


class ExpectedMediaV1(ClosedV1Model):
    sequence: int
    label: str
    format_required: bool


class JobSummaryV1(ClosedV1Model):
    id: str
    display_name: str
    state: str
    current_sequence: int
    total_cassettes: int
    labels: tuple[str, ...] = ()


class ProgressV1(ClosedV1Model):
    files_completed: int
    files_total: int
    bytes_completed: int
    bytes_total: int


class PhaseDurationsV1(ClosedV1Model):
    copy_seconds: float
    close_seconds: float
    finalization_seconds: float
    unmount_seconds: float
    unload_seconds: float


class TelemetryV1(ClosedV1Model):
    current_mib_per_second: float | None
    effective_mib_per_second: float | None
    current_sample_age_seconds: float | None = Field(default=None, ge=0)
    current_sample_stale: bool = False
    samples: tuple[TelemetrySampleV1, ...]
    durations: PhaseDurationsV1


class DiagnosticHealthV1(ClosedV1Model):
    status: Literal["ok", "degraded", "attention", "unavailable"]
    cleaning_required: bool | None
    tape_alert_codes: tuple[int, ...] = Field(max_length=64)


class DiagnosticPhaseDurationsV1(ClosedV1Model):
    source_open_seconds: float = Field(ge=0)
    smb_read_seconds: float = Field(ge=0)
    ltfs_write_admission_seconds: float = Field(ge=0)
    copy_seconds: float = Field(ge=0)
    close_seconds: float = Field(ge=0)
    manifest_seconds: float = Field(ge=0)
    snapshot_seconds: float = Field(ge=0)
    finalization_seconds: float = Field(ge=0)
    unmount_seconds: float = Field(ge=0)
    unload_seconds: float = Field(ge=0)
    retry_seconds: float = Field(ge=0)
    operator_wait_seconds: float = Field(ge=0)


class DiagnosticTelemetryV1(ClosedV1Model):
    files_completed: int = Field(ge=0)
    bytes_completed: int = Field(ge=0)
    current_mib_per_second: float | None = Field(default=None, ge=0)
    effective_mib_per_second: float | None = Field(default=None, ge=0)
    samples: tuple[TelemetrySampleV1, ...] = Field(max_length=300)
    phase_durations: DiagnosticPhaseDurationsV1
    current_phase: (
        Literal[
            "source_open",
            "smb_read",
            "ltfs_write_admission",
            "copy",
            "close",
            "manifest",
            "snapshot",
            "finalization",
            "unmount",
            "unload",
            "retry",
            "operator_wait",
        ]
        | None
    )
    closed: bool


class DiagnosticSummaryV1(ClosedV1Model):
    """New additive diagnostic contract; DaemonStatusV1 remains unchanged."""

    api_version: Literal[1] = 1
    health: DiagnosticHealthV1
    telemetry: DiagnosticTelemetryV1


class StorageFilesystemV1(ClosedV1Model):
    roles: tuple[Literal["state", "backups", "scratch"], ...] = Field(min_length=1, max_length=3)
    total_bytes: int | None = Field(default=None, ge=0)
    available_bytes: int | None = Field(default=None, ge=0)


class StorageSummaryV1(ClosedV1Model):
    """Bounded metadata observations; no catalog or rollback verification claim."""

    api_version: Literal[1] = 1
    measured_at: str = Field(min_length=1, max_length=64)
    cache_seconds: Literal[15] = 15
    filesystems: tuple[StorageFilesystemV1, ...] = Field(max_length=3)
    catalog_bytes: int | None = Field(default=None, ge=0)
    wal_bytes: int | None = Field(default=None, ge=0)
    rollback_status: Literal["unknown"] = "unknown"


class SettingsSummaryV1(ClosedV1Model):
    source_root_count: int
    restore_root_count: int
    buffer_bytes: int
    socket_group: str
    stable_tape_id_configured: bool
    stable_scsi_id_configured: bool


class ConfiguredPathLibrarySourceV1(ClosedV1Model):
    kind: Literal["configured_path"]
    source_root: str = Field(min_length=1, max_length=4096)


class ManagedShareLibrarySourceV1(ClosedV1Model):
    kind: Literal["managed_share"]
    share_id: str = Field(pattern=_SAFE_SHARE_ID.pattern)
    relative_subpath: str = Field(max_length=4096)

    @field_validator("relative_subpath")
    @classmethod
    def normalize_relative_subpath(cls, value: str) -> str:
        try:
            return normalize_managed_source_subpath(value)
        except DomainValidationError as exc:
            raise ValueError(str(exc)) from None


LibrarySourceV1 = Annotated[
    ConfiguredPathLibrarySourceV1 | ManagedShareLibrarySourceV1,
    Field(discriminator="kind"),
]


class CreateLibraryRequestV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    source_root: str | None = Field(default=None, min_length=1, max_length=4096)
    source: LibrarySourceV1 | None = None

    @model_validator(mode="after")
    def normalize_display_name(self) -> Self:
        normalized = self.display_name.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("library display name is invalid")
        object.__setattr__(self, "display_name", normalized)
        if (self.source_root is None) == (self.source is None):
            raise ValueError("exactly one library source is required")
        return self


class UpdateLibraryRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    source_root: str | None = Field(default=None, min_length=1, max_length=4096)
    source: LibrarySourceV1 | None = None
    state: Literal["active", "disabled"] | None = None

    @model_validator(mode="after")
    def require_update(self) -> Self:
        if (
            self.display_name is None
            and self.source_root is None
            and self.source is None
            and self.state is None
        ):
            raise ValueError("library update must change at least one field")
        if self.display_name is not None:
            normalized = self.display_name.strip()
            if not normalized or any(ord(character) < 32 for character in normalized):
                raise ValueError("library display name is invalid")
            object.__setattr__(self, "display_name", normalized)
        if self.source_root is not None and self.source is not None:
            raise ValueError("library source is ambiguous")
        return self


class RetireLibraryRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    typed_library_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)


class LibrarySummaryV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    source_root: str | None = Field(default=None, min_length=1, max_length=4096)
    source: LibrarySourceV1 | None = None
    state: Literal["active", "disabled", "retired"]
    scan_state: Literal["never", "running", "ready", "failed"]
    last_successful_scan_at: str | None
    file_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    revision: int = Field(ge=0)


class PlannedCassetteV1(ClosedV1Model):
    sequence: int = Field(ge=1)
    physical_label: str | None = None
    bytes: int = Field(ge=0)
    objects: int = Field(ge=0)
    allocation_bytes: int = Field(ge=0)
    capacity_utilization: float = Field(ge=0, le=1)
    format_required: bool
    operation: Literal["format", "append", "reserve"] | None = None
    state: Literal[
        "pending",
        "waiting_media",
        "identifying_media",
        "formatting",
        "formatting_media",
        "mounting",
        "writing",
        "writing_manifest",
        "finalizing_index",
        "unmounting",
        "committing",
        "unloading",
        "paused",
        "completed",
        "failed",
    ] | None = None
    error: str | None = Field(default=None, max_length=4000)

    @field_validator("physical_label")
    @classmethod
    def normalize_physical_label(cls, value: str | None) -> str | None:
        return None if value is None else _normalized_physical_label(value)


class CompletedJobAssignmentV1(ClosedV1Model):
    sequence: int = Field(ge=1)
    physical_label: str
    tape_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    objects: int = Field(ge=0)
    bytes: int = Field(ge=0)

    @field_validator("physical_label")
    @classmethod
    def normalize_assignment_label(cls, value: str) -> str:
        return _normalized_physical_label(value)


class JobPlanV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    state: Literal["building", "ready", "failed", "expired", "consumed"]
    kind: Literal["create", "extend"]
    requires_automatic_format_authorization: bool
    creator: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    created_at: str
    expires_at: str
    library_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    media_profile: str = Field(min_length=1, max_length=16)
    capacity_reserve_bytes: int = Field(default=0, ge=0)
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cassettes: tuple[PlannedCassetteV1, ...]
    base_job_id: str | None = Field(default=None, pattern=_SAFE_JOB_ID.pattern)
    base_job_revision: int | None = Field(default=None, ge=0)
    base_job_fingerprint_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    residual_append_capacity_bytes: int = Field(default=0, ge=0)
    existing_reserve_labels: tuple[str, ...] = ()
    completed_assignments: tuple[CompletedJobAssignmentV1, ...] = Field(
        default=()
    )

    @field_validator("library_ids")
    @classmethod
    def require_safe_library_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_IDENTIFIER.fullmatch(item) for item in value):
            raise ValueError("library identifiers must be safe")
        return value

    @field_validator("media_profile")
    @classmethod
    def normalize_media_profile(cls, value: str) -> str:
        try:
            return require_ltfs_profile(value).key
        except DomainValidationError as exc:
            raise ValueError("unsupported LTFS media profile") from exc

    @field_validator("existing_reserve_labels")
    @classmethod
    def normalize_existing_reserves(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        labels = tuple(_normalized_physical_label(label) for label in value)
        if len(set(labels)) != len(labels):
            raise ValueError("existing reserve labels must be unique")
        return labels

    @model_validator(mode="after")
    def require_extension_evidence(self) -> Self:
        if self.kind == "extend" and (
            self.base_job_id is None
            or self.base_job_revision is None
            or self.base_job_fingerprint_sha256 is None
        ):
            raise ValueError("extension plans require frozen base job evidence")
        if self.kind == "create" and any(
            value is not None
            for value in (
                self.base_job_id,
                self.base_job_revision,
                self.base_job_fingerprint_sha256,
            )
        ):
            raise ValueError("create plans cannot contain base job evidence")
        return self


class CreateJobPlanRequestV1(ClosedV1Model):
    kind: Literal["create", "extend"]
    library_ids: tuple[str, ...] | None = Field(
        default=None, min_length=1, max_length=64
    )
    media_profile: str | None = Field(default=None, min_length=1, max_length=16)
    base_job_id: str | None = Field(default=None, pattern=_SAFE_JOB_ID.pattern)

    @model_validator(mode="after")
    def require_kind_specific_fields(self) -> Self:
        if self.kind == "create":
            if (
                self.library_ids is None
                or self.media_profile is None
                or self.base_job_id is not None
            ):
                raise ValueError("initial plans require libraries and media profile")
            folded = tuple(item.casefold() for item in self.library_ids)
            if any(
                not _SAFE_LIBRARY_ID.fullmatch(item) for item in self.library_ids
            ) or len(set(folded)) != len(folded):
                raise ValueError("initial plan libraries are invalid")
            try:
                profile = require_ltfs_profile(self.media_profile).key
            except DomainValidationError as exc:
                raise ValueError("unsupported LTFS media profile") from exc
            object.__setattr__(self, "media_profile", profile)
        elif (
            self.base_job_id is None
            or self.library_ids is not None
            or self.media_profile is not None
        ):
            raise ValueError("extension plans accept only a base job")
        return self


class JobCassetteProgressV1(ClosedV1Model):
    completed: int = Field(ge=0)
    total: int = Field(ge=0)


class JobManifestTotalsV1(ClosedV1Model):
    objects: int = Field(ge=0)
    bytes: int = Field(ge=0)


class JobProgressV1(ClosedV1Model):
    objects_completed: int = Field(ge=0)
    objects_total: int = Field(ge=0)
    bytes_completed: int = Field(ge=0)
    bytes_total: int = Field(ge=0)


class JobCapabilitiesV1(ClosedV1Model):
    start: bool = False
    resume: bool = False
    pause: bool = False
    rename: bool = False
    extend: bool = False
    reserve_label: bool = False
    retire: bool = False
    scan_now: bool = False
    reset_failed_cassette: bool = False


class JobSequenceStatusV1(ClosedV1Model):
    """The current, fingerprint-bound authority needed to run a native job."""

    authorization_state: Literal["not_required", "pending", "authorized"]
    layout_fingerprint_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    next_expected_sequence: int | None = Field(default=None, ge=1)
    next_expected_label: str | None = Field(default=None, min_length=1, max_length=32)
    waiting_for_media: bool = False


IncrementalCadenceV1 = Literal["off", "every_6_hours", "every_12_hours", "daily", "weekly"]
IncrementalRunStateV1 = Literal[
    "claimed",
    "scanning",
    "no_changes",
    "extension_ready",
    "extension_queued",
    "waiting_labels",
    "deferred_busy",
    "plan_stale",
    "source_unavailable",
    "failed_safe",
]
IncrementalTerminalOutcomeV1 = Literal[
    "no_changes",
    "extension_queued",
    "waiting_labels",
    "deferred_busy",
    "plan_stale",
    "source_unavailable",
    "failed_safe",
]


class IncrementalRunSummaryV1(ClosedV1Model):
    state: IncrementalRunStateV1
    recorded_at: str
    discovered_files: int = Field(default=0, ge=0)
    discovered_bytes: int = Field(default=0, ge=0)
    required_additional_labels: int = Field(default=0, ge=0)
    plan_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    plan_digest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,64}$")


class PendingIncrementalExtensionV1(ClosedV1Model):
    plan_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    plan_digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    discovered_files: int = Field(ge=0)
    discovered_bytes: int = Field(ge=0)
    required_additional_labels: int = Field(ge=0)


class IncrementalPolicyV1(ClosedV1Model):
    job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    cadence: IncrementalCadenceV1
    next_eligible_at: str | None = None
    last_attempt_at: str | None = None
    last_success_at: str | None = None
    last_outcome: IncrementalTerminalOutcomeV1 | None = None
    revision: int = Field(ge=1)
    latest_event: IncrementalRunSummaryV1 | None = None
    pending_extension: PendingIncrementalExtensionV1 | None = None


class UpdateIncrementalPolicyRequestV1(ClosedV1Model):
    cadence: IncrementalCadenceV1
    expected_revision: int = Field(ge=1)


class IncrementalScanResultV1(ClosedV1Model):
    run_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    state: IncrementalRunStateV1
    recorded_at: str
    discovered_files: int = Field(default=0, ge=0)
    discovered_bytes: int = Field(default=0, ge=0)
    required_additional_labels: int = Field(default=0, ge=0)
    plan_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    plan_digest_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_code: str | None = Field(default=None, pattern=r"^[a-z0-9_]{1,64}$")
    next_eligible_at: str | None = None


class SourceCheckIssueV1(ClosedV1Model):
    library_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    relative_path: str | None = Field(default=None, max_length=4096)
    code: Literal["source_missing", "source_changed", "source_unavailable"]


class SourceCheckV1(ClosedV1Model):
    cassette_sequence: int = Field(ge=1)
    state: Literal["ready", "blocked", "source_unavailable"]
    checked_files: int = Field(ge=0)
    missing_files: int = Field(ge=0)
    changed_files: int = Field(ge=0)
    unavailable_libraries: int = Field(ge=0)
    checked_at: str
    issues: tuple[SourceCheckIssueV1, ...] = Field(max_length=100)


class PreservedTapeV1(ClosedV1Model):
    tape_id: str
    reason: Literal[
        "retained_history_reference", "ambiguous_tape_identity", "shared_tape",
        "operation_active", "ownership_unproven", "inconsistent_file_ownership",
    ]


class JobCatalogCleanupV1(ClosedV1Model):
    deleted_tape_count: int = Field(ge=0)
    preserved_tape_count: int = Field(ge=0)
    deleted_tapes: tuple[str, ...] = Field(max_length=100)
    preserved_tapes: tuple[PreservedTapeV1, ...] = Field(max_length=100)
    deleted_blocks: int = Field(ge=0)
    deleted_files: int = Field(ge=0)
    tape_data_deleted: Literal[False]


class BoundaryRefreshStatusV1(ClosedV1Model):
    state: Literal[
        "queued",
        "scanning",
        "waiting_labels",
        "blocked",
        "stale",
        "applied",
        "paused",
    ]
    completed_sequence: int | None = Field(default=None, ge=1)
    required_additional_labels: int | None = Field(default=None, ge=0)
    candidate_files: int | None = Field(default=None, ge=0)
    candidate_bytes: int | None = Field(default=None, ge=0)
    error_code: str | None = Field(
        default=None, pattern=r"^[a-z][a-z0-9_]{0,63}$"
    )
    occurred_at: str


class JobDetailV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    state: Literal[
        "planned",
        "pending",
        "waiting_media",
        "identifying_media",
        "formatting_media",
        "mounting",
        "writing",
        "writing_manifest",
        "finalizing_index",
        "unmounting",
        "committing",
        "unloading",
        "paused",
        "completed",
        "failed",
        "retired",
    ]
    library_ids: tuple[str, ...] = Field(min_length=1, max_length=64)
    media_profile: str = Field(min_length=1, max_length=16)
    cassettes: tuple[PlannedCassetteV1, ...]
    requires_format_confirmation: bool
    resumable: bool
    revision: int = Field(default=0, ge=0)
    cassette_progress: JobCassetteProgressV1 = Field(
        default_factory=lambda: JobCassetteProgressV1(completed=0, total=0)
    )
    manifest_totals: JobManifestTotalsV1 = Field(
        default_factory=lambda: JobManifestTotalsV1(objects=0, bytes=0)
    )
    progress: JobProgressV1 = Field(
        default_factory=lambda: JobProgressV1(
            objects_completed=0,
            objects_total=0,
            bytes_completed=0,
            bytes_total=0,
        )
    )
    created_at: str = ""
    last_activity_at: str = ""
    current_checkpoint: str = Field(default="saved", min_length=1, max_length=64)
    last_error: str | None = None
    imported: bool = False
    pause_requested: bool = False
    pause_acknowledged: bool = False
    capabilities: JobCapabilitiesV1 = Field(default_factory=JobCapabilitiesV1)
    incremental: IncrementalPolicyV1 | None = None
    source_check: SourceCheckV1 | None = None
    catalog_cleanup: JobCatalogCleanupV1 | None = None
    boundary_refresh: BoundaryRefreshStatusV1 | None = None

    @field_validator("library_ids")
    @classmethod
    def require_safe_library_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _SAFE_IDENTIFIER.fullmatch(item) for item in value):
            raise ValueError("library identifiers must be safe")
        return value

    @field_validator("media_profile")
    @classmethod
    def normalize_media_profile(cls, value: str) -> str:
        try:
            return require_ltfs_profile(value).key
        except DomainValidationError as exc:
            raise ValueError("unsupported LTFS media profile") from exc


class MediaProfileV1(ClosedV1Model):
    key: str = Field(min_length=1, max_length=16)
    generation: int = Field(ge=5, le=10)
    native_capacity_bytes: int = Field(gt=0)
    ltfs_usable_bytes: int = Field(gt=0)

    @field_validator("key")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        try:
            return require_ltfs_profile(value).key
        except DomainValidationError as exc:
            raise ValueError("unsupported LTFS media profile") from exc


class MediaProfilesV1(ClosedV1Model):
    default_media_profile: str = Field(min_length=1, max_length=16)
    items: tuple[MediaProfileV1, ...] = Field(min_length=1, max_length=16)

    @field_validator("default_media_profile")
    @classmethod
    def normalize_default(cls, value: str) -> str:
        try:
            return require_ltfs_profile(value).key
        except DomainValidationError as exc:
            raise ValueError("unsupported LTFS media profile") from exc

    @model_validator(mode="after")
    def require_default_item(self) -> Self:
        if self.default_media_profile not in {item.key for item in self.items}:
            raise ValueError("default LTFS media profile is not advertised")
        return self


class JobListPageV1(ClosedV1Model):
    items: tuple[JobDetailV1, ...] = Field(max_length=200)
    next_cursor: str | None
    current_job_id: str | None = Field(default=None, pattern=_SAFE_JOB_ID.pattern)


class JobCassettePageV1(ClosedV1Model):
    items: tuple[PlannedCassetteV1, ...] = Field(max_length=200)
    next_cursor: str | None


class JobManifestItemV1(ClosedV1Model):
    cassette_sequence: int = Field(ge=1)
    item_sequence: int = Field(ge=1)
    library_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    relative_path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)
    mtime_ns: int = Field(ge=0)


class JobManifestPageV1(ClosedV1Model):
    items: tuple[JobManifestItemV1, ...] = Field(max_length=200)
    next_cursor: str | None


class JobHistoryItemV1(ClosedV1Model):
    id: int = Field(ge=1)
    occurred_at: str
    action: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    actor: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    checkpoint: str = Field(pattern=_SAFE_IDENTIFIER.pattern)


class JobHistoryPageV1(ClosedV1Model):
    items: tuple[JobHistoryItemV1, ...] = Field(max_length=200)
    next_cursor: str | None


class CatalogAlternateStreamV1(ClosedV1Model):
    name: str = Field(min_length=1, max_length=255)
    size: int = Field(ge=0)


class CatalogFileVersionV1(ClosedV1Model):
    id: int = Field(ge=1)
    library_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    library_name: str = Field(min_length=1, max_length=120)
    job_id: str | None = Field(default=None, pattern=_SAFE_JOB_ID.pattern)
    job_display_name: str | None = Field(default=None, min_length=1, max_length=120)
    block_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    block_status: Literal["completed"]
    tape_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    cassette_number: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    physical_label: str | None = Field(default=None, min_length=1, max_length=32)
    volume_label: str = Field(max_length=255)
    volume_serial: str = Field(max_length=255)
    relative_path: str = Field(min_length=1, max_length=4096)
    parent_path: str = Field(max_length=4096)
    file_name: str = Field(min_length=1, max_length=255)
    tape_relative_path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)
    mtime_ns: int = Field(ge=0)
    created_ns: int | None = Field(default=None, ge=0)
    accessed_ns: int | None = Field(default=None, ge=0)
    source_mode: int | None = Field(default=None, ge=0, le=2**32 - 1)
    windows_attributes: int | None = Field(default=None, ge=0, le=2**32 - 1)
    owner_name: str | None = Field(default=None, max_length=1024)
    owner_sid: str | None = Field(default=None, max_length=1024)
    security_descriptor: str | None = Field(default=None, max_length=65536)
    alternate_streams: tuple[CatalogAlternateStreamV1, ...] = Field(
        default=(), max_length=128
    )
    metadata_state: Literal["legacy", "complete", "partial"]
    metadata_error: str | None = Field(default=None, max_length=4096)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    copied_at: str = Field(min_length=1, max_length=64)
    is_current: bool


class CatalogSearchPageV1(ClosedV1Model):
    items: tuple[CatalogFileVersionV1, ...] = Field(max_length=200)
    next_cursor: str | None = Field(default=None, max_length=512)


class CatalogBrowseEntryV1(ClosedV1Model):
    kind: Literal["directory", "file"]
    name: str = Field(min_length=1, max_length=255)
    library_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    relative_path: str = Field(min_length=1, max_length=4096)
    id: int | None = Field(default=None, ge=1)
    library_name: str | None = Field(default=None, min_length=1, max_length=120)
    job_id: str | None = Field(default=None, pattern=_SAFE_JOB_ID.pattern)
    job_display_name: str | None = Field(default=None, min_length=1, max_length=120)
    block_id: str | None = Field(default=None, pattern=_SAFE_LIBRARY_ID.pattern)
    block_status: Literal["completed"] | None = None
    tape_id: str | None = Field(default=None, pattern=_SAFE_LIBRARY_ID.pattern)
    cassette_number: str | None = Field(default=None, pattern=_SAFE_LIBRARY_ID.pattern)
    physical_label: str | None = Field(default=None, min_length=1, max_length=32)
    volume_label: str | None = Field(default=None, max_length=255)
    volume_serial: str | None = Field(default=None, max_length=255)
    parent_path: str | None = Field(default=None, max_length=4096)
    file_name: str | None = Field(default=None, min_length=1, max_length=255)
    tape_relative_path: str | None = Field(default=None, min_length=1, max_length=4096)
    size: int | None = Field(default=None, ge=0)
    mtime_ns: int | None = Field(default=None, ge=0)
    created_ns: int | None = Field(default=None, ge=0)
    accessed_ns: int | None = Field(default=None, ge=0)
    source_mode: int | None = Field(default=None, ge=0, le=2**32 - 1)
    windows_attributes: int | None = Field(default=None, ge=0, le=2**32 - 1)
    owner_name: str | None = Field(default=None, max_length=1024)
    owner_sid: str | None = Field(default=None, max_length=1024)
    security_descriptor: str | None = Field(default=None, max_length=65536)
    alternate_streams: tuple[CatalogAlternateStreamV1, ...] | None = Field(
        default=None, max_length=128
    )
    sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    copied_at: str | None = Field(default=None, min_length=1, max_length=64)
    metadata_state: Literal["legacy", "complete", "partial"] | None = None
    metadata_error: str | None = Field(default=None, max_length=4096)
    is_current: bool | None = None

    @model_validator(mode="after")
    def require_entry_shape(self) -> Self:
        file_fields = (
            "id",
            "library_name",
            "job_id",
            "job_display_name",
            "block_id",
            "block_status",
            "tape_id",
            "cassette_number",
            "physical_label",
            "volume_label",
            "volume_serial",
            "parent_path",
            "file_name",
            "tape_relative_path",
            "size",
            "mtime_ns",
            "created_ns",
            "accessed_ns",
            "source_mode",
            "windows_attributes",
            "owner_name",
            "owner_sid",
            "security_descriptor",
            "alternate_streams",
            "sha256",
            "copied_at",
            "metadata_state",
            "metadata_error",
            "is_current",
        )
        required_file_fields = (
            "id",
            "library_name",
            "block_id",
            "block_status",
            "tape_id",
            "cassette_number",
            "volume_label",
            "volume_serial",
            "parent_path",
            "file_name",
            "tape_relative_path",
            "size",
            "mtime_ns",
            "alternate_streams",
            "sha256",
            "copied_at",
            "metadata_state",
            "is_current",
        )
        if self.kind == "directory":
            if any(getattr(self, field) is not None for field in file_fields):
                raise ValueError("directory entries cannot contain file fields")
        elif any(getattr(self, field) is None for field in required_file_fields):
            raise ValueError("file entries require complete catalog identity")
        return self


class CatalogBrowsePageV1(ClosedV1Model):
    items: tuple[CatalogBrowseEntryV1, ...] = Field(max_length=200)
    next_cursor: str | None = Field(default=None, max_length=512)


class CatalogRestoreOptionsV1(ClosedV1Model):
    restore_roots: tuple[str, ...] = Field(max_length=64)

    @field_validator("restore_roots")
    @classmethod
    def require_absolute_unique_roots(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(
            not root.startswith("/") or "\x00" in root or len(root) > 4096
            for root in value
        ):
            raise ValueError("restore roots are invalid")
        return value


class CreateCatalogRestorePlanRequestV1(ClosedV1Model):
    file_version_ids: tuple[
        Annotated[int, Field(strict=True, ge=1, le=2**63 - 1)], ...
    ] = Field(min_length=1, max_length=200)
    destination_root: str = Field(min_length=1, max_length=4096)
    destination_subdirectory: str = Field(default="", max_length=2048)

    @model_validator(mode="after")
    def require_unique_versions_and_absolute_root(self) -> Self:
        if (
            len(set(self.file_version_ids)) != len(self.file_version_ids)
            or any(
                type(version_id) is not int or version_id < 1
                or version_id > 2**63 - 1
                for version_id in self.file_version_ids
            )
            or not self.destination_root.startswith("/")
            or "\x00" in self.destination_root
        ):
            raise ValueError("restore plan selection is invalid")
        subdirectory = self.destination_subdirectory
        normalized = PurePosixPath(subdirectory)
        if subdirectory and (
            subdirectory == "."
            or subdirectory.startswith("/")
            or "\\" in subdirectory
            or "\x00" in subdirectory
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in subdirectory
            )
            or any(part in {".", ".."} for part in normalized.parts)
            or normalized.as_posix() != subdirectory
        ):
            raise ValueError("restore destination subdirectory is invalid")
        return self


class CatalogRestorePlanItemV1(ClosedV1Model):
    sequence: int = Field(ge=1, le=200)
    file_version_id: int = Field(ge=1, le=2**63 - 1)
    library_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    relative_path: str = Field(min_length=1, max_length=4096)
    tape_relative_path: str = Field(min_length=1, max_length=4096)
    tape_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    cassette_number: str = Field(min_length=1, max_length=255)
    physical_label: str | None = Field(default=None, min_length=1, max_length=32)
    volume_label: str | None = Field(default=None, max_length=255)
    block_id: str | None = Field(default=None, pattern=_SAFE_LIBRARY_ID.pattern)
    size: int = Field(ge=0, le=2**63 - 1)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    copied_at: str = Field(min_length=1, max_length=64)
    is_current: bool | None = None


class CatalogRestorePlanCassetteV1(ClosedV1Model):
    sequence: int = Field(ge=1, le=200)
    tape_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    cassette_number: str = Field(min_length=1, max_length=255)
    physical_label: str | None = Field(default=None, min_length=1, max_length=32)
    volume_serial: str | None = Field(default=None, min_length=1, max_length=255)
    volume_uuid: str | None = Field(
        default=None,
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    )
    item_count: int = Field(ge=1, le=200)
    total_bytes: int = Field(ge=0, le=2**63 - 1)


class CatalogRestoreDestinationV1(ClosedV1Model):
    kind: Literal["local"]
    root: str = Field(min_length=1, max_length=4096)
    anchor: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def require_canonical_local_root_within_anchor(self) -> Self:
        root = PurePosixPath(self.root)
        anchor = PurePosixPath(self.anchor)
        if (
            self.root.startswith("//")
            or self.anchor.startswith("//")
            or not root.is_absolute()
            or not anchor.is_absolute()
            or any(part in {".", ".."} for part in (*root.parts, *anchor.parts))
            or root.as_posix() != self.root
            or anchor.as_posix() != self.anchor
            or root.parts[: len(anchor.parts)] != anchor.parts
        ):
            raise ValueError("restore destination snapshot is invalid")
        return self


class CatalogRestorePlanV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    state: Literal["planned"]
    identity_state: Literal["exact", "legacy_invalid"] = "exact"
    invalidation_reason: Literal["legacy_physical_identity_ambiguous"] | None = None
    destination_root: str = Field(min_length=1, max_length=4096)
    destination: CatalogRestoreDestinationV1 | None = None
    destination_state: Literal["exact", "legacy_invalid"] = "exact"
    destination_invalidation_reason: Literal[
        "legacy_destination_snapshot_missing"
    ] | None = None
    created_by: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    created_at: str = Field(min_length=1, max_length=64)
    total_files: int = Field(ge=1, le=200)
    total_bytes: int = Field(ge=0, le=2**63 - 1)
    cassettes: tuple[CatalogRestorePlanCassetteV1, ...] = Field(
        min_length=1, max_length=200
    )
    items: tuple[CatalogRestorePlanItemV1, ...] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def require_closed_identity_state(self) -> Self:
        if (self.identity_state, self.invalidation_reason) not in {
            ("exact", None),
            ("legacy_invalid", "legacy_physical_identity_ambiguous"),
        }:
            raise ValueError("restore plan identity state is invalid")
        if (self.destination_state, self.destination_invalidation_reason) not in {
            ("exact", None),
            ("legacy_invalid", "legacy_destination_snapshot_missing"),
        } or (self.destination_state == "exact") != (self.destination is not None):
            raise ValueError("restore plan destination state is invalid")
        return self


class StartCatalogRestoreRunRequestV1(ClosedV1Model):
    """Start exactly the server-selected immutable restore plan."""


class RestoreRunControlRequestV1(ClosedV1Model):
    """Closed empty control body; the idempotency key is a header."""


class AuthorizeCatalogRestoreItemReplacementRequestV1(ClosedV1Model):
    """Fresh administrator proof; conflict evidence is loaded server-side."""

    capability: str = Field(min_length=32, max_length=1024)


class IssueCatalogRestoreReplacementCapabilityRequestV1(ClosedV1Model):
    """The trusted WebUI attestation is carried only in authenticated context."""


class CatalogRestoreReplacementCapabilityV1(ClosedV1Model):
    capability: str = Field(min_length=32, max_length=1024)
    expires_at: str = Field(min_length=1, max_length=64)


class CatalogRestoreItemConflictV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    run_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    item_sequence: int = Field(ge=1, le=200)
    conflict_sequence: int = Field(ge=1, le=2**63 - 1)
    file_version_id: int = Field(ge=1, le=2**63 - 1)
    canonical_destination: str = Field(min_length=1, max_length=4096)
    observed_size: int = Field(ge=0, le=2**63 - 1)
    observed_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: Literal["recorded", "authorized", "consumed"]
    authorization_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    recorded_at: str = Field(min_length=1, max_length=64)
    authorized_at: str | None = Field(default=None, max_length=64)
    consumed_at: str | None = Field(default=None, max_length=64)

    @field_validator("canonical_destination")
    @classmethod
    def require_canonical_destination(cls, value: str) -> str:
        _require_canonical_restore_path(value)
        return value


class CatalogRestoreReplacementAuthorizationV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    conflict_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    run_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    item_sequence: int = Field(ge=1, le=200)
    file_version_id: int = Field(ge=1, le=2**63 - 1)
    canonical_destination: str = Field(min_length=1, max_length=4096)
    observed_size: int = Field(ge=0, le=2**63 - 1)
    observed_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    administrator: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    state: Literal["authorized", "consumed"]
    authorized_at: str = Field(min_length=1, max_length=64)
    consumed_at: str | None = Field(default=None, max_length=64)
    consumed_by_operation_id: str | None = Field(
        default=None, pattern=_SAFE_IDENTIFIER.pattern
    )

    @field_validator("canonical_destination")
    @classmethod
    def require_canonical_destination(cls, value: str) -> str:
        _require_canonical_restore_path(value)
        return value


class CatalogRestoreRunCassetteV1(ClosedV1Model):
    sequence: int = Field(ge=1, le=200)
    plan_cassette_sequence: int = Field(ge=1, le=200)
    tape_id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    cassette_number: str = Field(min_length=1, max_length=255)
    physical_label: str = Field(pattern=_PHYSICAL_LABEL.pattern)
    volume_label: str = Field(min_length=1, max_length=255)
    volume_serial: str = Field(min_length=1, max_length=255)
    volume_uuid: str | None = Field(default=None, max_length=64)
    state: Literal[
        "pending", "waiting_media", "restoring", "recovery_required", "completed", "failed"
    ]
    item_count: int = Field(ge=1, le=200)
    total_bytes: int = Field(ge=0, le=2**63 - 1)
    restored_files: int = Field(ge=0, le=200)
    skipped_files: int = Field(ge=0, le=200)
    failed_files: int = Field(ge=0, le=200)
    copied_bytes: int = Field(ge=0, le=2**63 - 1)
    operation_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    started_at: str | None = Field(default=None, max_length=64)
    completed_at: str | None = Field(default=None, max_length=64)
    last_error_code: str | None = Field(
        default=None, max_length=64, pattern=_SAFE_IDENTIFIER.pattern
    )


class CatalogRestoreRunItemV1(ClosedV1Model):
    sequence: int = Field(ge=1, le=200)
    cassette_sequence: int = Field(ge=1, le=200)
    destination_relative_path: str = Field(min_length=1, max_length=4096)
    canonical_destination: str = Field(min_length=1, max_length=4096)
    state: Literal[
        "pending", "restoring", "restored", "skipped_verified", "failed", "recovery_required"
    ]
    bytes_copied: int = Field(ge=0, le=2**63 - 1)
    observed_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    error_code: str | None = Field(
        default=None, max_length=64, pattern=_SAFE_IDENTIFIER.pattern
    )
    started_at: str | None = Field(default=None, max_length=64)
    completed_at: str | None = Field(default=None, max_length=64)
    conflict: CatalogRestoreItemConflictV1 | None = None
    plan_item: CatalogRestorePlanItemV1

    @field_validator("canonical_destination")
    @classmethod
    def require_canonical_destination(cls, value: str) -> str:
        _require_canonical_restore_path(value)
        return value


class CatalogRestoreRunV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    plan_id: str = Field(pattern=_SAFE_JOB_ID.pattern)
    actor: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    state: Literal[
        "planned", "waiting_media", "restoring", "paused", "recovery_required", "completed", "cancelled", "failed"
    ]
    current_cassette_sequence: int | None = Field(default=None, ge=1, le=200)
    plan_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    total_files: int = Field(ge=1, le=200)
    total_bytes: int = Field(ge=0, le=2**63 - 1)
    restored_files: int = Field(ge=0, le=200)
    skipped_files: int = Field(ge=0, le=200)
    failed_files: int = Field(ge=0, le=200)
    copied_bytes: int = Field(ge=0, le=2**63 - 1)
    created_at: str = Field(min_length=1, max_length=64)
    started_at: str | None = Field(default=None, max_length=64)
    completed_at: str | None = Field(default=None, max_length=64)
    last_error_code: str | None = Field(
        default=None, max_length=64, pattern=_SAFE_IDENTIFIER.pattern
    )
    cassettes: tuple[CatalogRestoreRunCassetteV1, ...] = Field(
        min_length=1, max_length=200
    )
    items: tuple[CatalogRestoreRunItemV1, ...] = Field(min_length=1, max_length=200)


class CreateJobFromPlanRequestV1(ClosedV1Model):
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    display_name: str = Field(min_length=1, max_length=120)
    labels: tuple[str, ...] = Field(min_length=1, max_length=64)
    allow_registered_reuse: bool = False
    authorize_automatic_formatting: bool = False

    @model_validator(mode="after")
    def normalize_job_creation(self) -> Self:
        display_name = self.display_name.strip()
        labels = tuple(_normalized_physical_label(label) for label in self.labels)
        if (
            not display_name
            or any(ord(character) < 32 for character in display_name)
            or len(set(labels)) != len(labels)
        ):
            raise ValueError("job creation request is invalid")
        object.__setattr__(self, "display_name", display_name)
        object.__setattr__(self, "labels", labels)
        return self


class AuthorizeAutomaticSequenceRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    layout_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authorize_automatic_formatting: Literal[True]


class JobCommandRequestV1(ClosedV1Model):
    format_confirmation_label: str | None = None

    @field_validator("format_confirmation_label")
    @classmethod
    def normalize_optional_label(cls, value: str | None) -> str | None:
        return None if value is None else _normalized_physical_label(value)


class ResetFailedCassetteRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    cassette_sequence: int = Field(ge=1)
    typed_physical_label: str

    @field_validator("typed_physical_label")
    @classmethod
    def normalize_confirmation_label(cls, value: str) -> str:
        return _normalized_physical_label(value)


class UpdateJobRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    display_name: str = Field(min_length=1, max_length=120)

    @field_validator("display_name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(ord(character) < 32 for character in normalized):
            raise ValueError("job display name is invalid")
        return normalized


class ReserveJobLabelsRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    labels: tuple[str, ...] = Field(min_length=1, max_length=64)
    authorize_automatic_formatting: Literal[True]

    @field_validator("labels")
    @classmethod
    def normalize_labels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        labels = tuple(_normalized_physical_label(label) for label in value)
        if len(set(labels)) != len(labels):
            raise ValueError("physical labels must be unique")
        return labels


class RetireJobRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    typed_job_id: str = Field(pattern=_SAFE_JOB_ID.pattern)


class ExtendJobRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=0)
    plan_id: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    digest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    labels: tuple[str, ...] = Field(max_length=64)
    authorize_automatic_formatting: bool = False

    @field_validator("labels")
    @classmethod
    def normalize_extension_labels(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        labels = tuple(_normalized_physical_label(label) for label in value)
        if len(set(labels)) != len(labels):
            raise ValueError("physical labels must be unique")
        return labels


class ApplicationSettingsV1(ClosedV1Model):
    revision: int = Field(ge=1)
    capacity_reserve_bytes: int = Field(ge=0)
    minimum_source_file_age_seconds: int = Field(ge=0, le=31 * 24 * 60 * 60)
    copy_buffer_bytes: int = Field(ge=1024**2, le=64 * 1024**2)
    content_verification_policy: Literal["none", "manifest", "full"]
    source_change_detection_policy: Literal["size_mtime", "size_mtime_change"]
    default_media_profile: str = Field(min_length=1, max_length=16)
    tape_root_directory: str = Field(min_length=1, max_length=128)
    legacy_tape_capacity_bytes: int = Field(ge=0)

    @field_validator("default_media_profile")
    @classmethod
    def normalize_default_media(cls, value: str) -> str:
        try:
            return require_ltfs_profile(value).key
        except DomainValidationError as exc:
            raise ValueError("unsupported LTFS media profile") from exc

    @field_validator("tape_root_directory")
    @classmethod
    def validate_tape_root(cls, value: str) -> str:
        if (
            value in {".", ".."}
            or "/" in value
            or "\\" in value
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("tape root directory must be one safe segment")
        return value


class UpdateApplicationSettingsRequestV1(ClosedV1Model):
    expected_revision: int = Field(ge=1)
    capacity_reserve_bytes: int = Field(ge=0)
    minimum_source_file_age_seconds: int = Field(ge=0, le=31 * 24 * 60 * 60)
    copy_buffer_bytes: int = Field(ge=1024**2, le=64 * 1024**2)
    content_verification_policy: Literal["none", "manifest", "full"]
    source_change_detection_policy: Literal["size_mtime", "size_mtime_change"] | None = None
    default_media_profile: str = Field(min_length=1, max_length=16)
    tape_root_directory: str = Field(min_length=1, max_length=128)

    @field_validator("default_media_profile")
    @classmethod
    def normalize_default_media(cls, value: str) -> str:
        try:
            return require_ltfs_profile(value).key
        except DomainValidationError as exc:
            raise ValueError("unsupported LTFS media profile") from exc

    @field_validator("tape_root_directory")
    @classmethod
    def validate_tape_root(cls, value: str) -> str:
        return ApplicationSettingsV1.validate_tape_root(value)

    @model_validator(mode="after")
    def require_reserve_below_selected_media(self) -> Self:
        usable = require_ltfs_profile(self.default_media_profile).ltfs_usable_bytes
        if usable is None or self.capacity_reserve_bytes >= usable:
            raise ValueError("capacity reserve must be below selected LTFS capacity")
        return self


class HostSettingsV1(ClosedV1Model):
    daemon_socket_path: str = Field(min_length=1, max_length=4096)
    service_group: str = Field(pattern=_SAFE_IDENTIFIER.pattern)
    state_directory: str = Field(min_length=1, max_length=4096)
    tape_device_path: str = Field(min_length=1, max_length=4096)
    scsi_device_path: str = Field(min_length=1, max_length=4096)
    mount_path: str = Field(min_length=1, max_length=4096)
    managed_source_mount_root: str = Field(min_length=1, max_length=4096)
    source_allowlist: tuple[str, ...] = Field(max_length=64)
    restore_roots: tuple[str, ...] = Field(max_length=64)
    required_restart: bool


class DaemonStatusV1(ClosedV1Model):
    api_version: Literal[1] = 1
    accepting_mutations: bool
    admission_blocker: OperationResponseV1 | None
    drive: DriveStatusV1
    expected_media: ExpectedMediaV1 | None
    job: JobSummaryV1 | None
    operation: OperationResponseV1 | None
    critical_recovery: CriticalRecoveryProofV1 | None = None
    progress: ProgressV1
    telemetry: TelemetryV1


class LogEntryV1(ClosedV1Model):
    id: int
    occurred_at: str
    level: Literal["debug", "info", "warning", "error"]
    code: str
    message: str
    request_id: str | None
    operation_id: str | None


class LogsPageV1(ClosedV1Model):
    items: tuple[LogEntryV1, ...]
    next_after_id: int | None


SYSTEM_LOG_SOURCE_UNITS = MappingProxyType({
    LogSource.DAEMON: frozenset({"lto-archiverd.service"}),
    LogSource.WEBUI: frozenset({"lto-archiver-web.service"}),
    LogSource.LTFS: frozenset(
        {
            "lto-archiverd.service",
            "lto-archiver-command-broker.service",
            "lto-archiver-ltfs-qualification.service",
            "lto-archiver-archive-runner-qualification.service",
        }
    ),
    LogSource.COMMAND_BROKER: frozenset(
        {"lto-archiver-command-broker.service"}
    ),
    LogSource.SHARE_BROKER: frozenset({"lto-archiver-share-broker.service"}),
    LogSource.QUALIFICATION: frozenset(
        {
            "lto-archiver-ltfs-qualification.service",
            "lto-archiver-archive-runner-qualification.service",
        }
    ),
})

SYSTEM_LOG_SEVERITY_RANK = MappingProxyType({
    Severity.DEBUG: 0,
    Severity.INFO: 1,
    Severity.WARNING: 2,
    Severity.ERROR: 3,
})


class SystemLogEntryV1(ClosedV1Model):
    cursor: str = Field(min_length=1, max_length=2_048)
    occurred_at: str = Field(min_length=1, max_length=64)
    severity: Severity
    source: LogSource
    unit: str = Field(min_length=1, max_length=256)
    message: str = Field(min_length=1)
    repeat_count: int = Field(strict=True, ge=1, le=2**31 - 1)
    truncated: bool = Field(strict=True)
    pid: int | None = Field(default=None, strict=True, ge=1, le=2**31 - 1)
    boot_id: str | None = Field(default=None, min_length=1, max_length=256)
    operation_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    job_id: str | None = Field(default=None, pattern=_SAFE_JOB_ID.pattern)
    cassette_label: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    cassette_sequence: int | None = Field(
        default=None, strict=True, ge=1, le=2**31 - 1
    )
    command_id: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    daemon_generation: int | None = Field(
        default=None, strict=True, ge=0, le=2**63 - 1
    )
    command_kind: str | None = Field(
        default=None, pattern=_SAFE_IDENTIFIER.pattern
    )
    phase: str | None = Field(default=None, pattern=_SAFE_IDENTIFIER.pattern)
    exit_code: int | None = Field(
        default=None, strict=True, ge=-(2**31), le=2**31 - 1
    )
    elapsed_ms: int | None = Field(default=None, strict=True, ge=0, le=2**63 - 1)

    @model_validator(mode="after")
    def require_closed_safe_entry(self) -> Self:
        if (
            not self.cursor.isascii()
            or "\x00" in self.cursor
            or self.source is LogSource.ALL
            or self.unit not in SYSTEM_LOG_SOURCE_UNITS[self.source]
            or len(self.message.encode("utf-8")) > 4_096
            or (
                self.boot_id is not None
                and len(self.boot_id.encode("utf-8")) > 256
            )
        ):
            raise ValueError("system log entry is outside the public contract")
        try:
            occurred_at = datetime.fromisoformat(
                self.occurred_at.removesuffix("Z") + (
                    "+00:00" if self.occurred_at.endswith("Z") else ""
                )
            )
        except ValueError as exc:
            raise ValueError("system log timestamp is invalid") from exc
        if occurred_at.utcoffset() != timedelta(0):
            raise ValueError("system log timestamp must be UTC")
        return self


class SystemLogQuery(ClosedV1Model):
    source: LogSource = LogSource.ALL
    severity: Severity = Severity.INFO
    range: LogRange = LogRange.ONE_HOUR
    direction: LogDirection = LogDirection.OLDER
    cursor: str | None = Field(default=None, min_length=1, max_length=2_048)
    search: str | None = Field(default=None, min_length=1, max_length=128)
    limit: int = Field(default=100, strict=True, ge=1, le=200)

    @model_validator(mode="after")
    def require_closed_safe_query(self) -> Self:
        if self.cursor is not None and (
            not self.cursor.isascii() or "\x00" in self.cursor
        ):
            raise ValueError("system log cursor is invalid")
        if self.search is not None:
            normalized = self.search.strip()
            if not normalized or any(not character.isprintable() for character in normalized):
                raise ValueError("system log search is invalid")
            object.__setattr__(self, "search", normalized)
        return self


class SystemLogsPageV1(ClosedV1Model):
    source: LogSource
    severity: Severity
    range: LogRange
    direction: LogDirection
    search: str | None = Field(default=None, min_length=1, max_length=128)
    limit: int = Field(strict=True, ge=1, le=200)
    items: tuple[SystemLogEntryV1, ...] = Field(max_length=200)
    older_cursor: str | None = Field(default=None, min_length=1, max_length=2_048)
    newer_cursor: str | None = Field(default=None, min_length=1, max_length=2_048)
    cursor_rotated: bool = Field(strict=True)
    live_supported: bool = Field(strict=True)
    unavailable_sources: tuple[LogSource, ...] = Field(max_length=6)

    @model_validator(mode="after")
    def require_closed_safe_page(self) -> Self:
        concrete_sources = frozenset(SYSTEM_LOG_SOURCE_UNITS)
        unavailable_sources = frozenset(self.unavailable_sources)
        source_unavailable = (
            self.source is not LogSource.ALL
            and self.source in unavailable_sources
        )
        all_sources_unavailable = unavailable_sources == concrete_sources
        for cursor in (self.older_cursor, self.newer_cursor):
            if cursor is not None and (not cursor.isascii() or "\x00" in cursor):
                raise ValueError("system log page cursor is invalid")
        if self.search is not None and any(
            not character.isprintable() for character in self.search
        ):
            raise ValueError("system log page search is invalid")
        if (
            len(self.items) > self.limit
            or any(
                (self.source is not LogSource.ALL and item.source is not self.source)
                or SYSTEM_LOG_SEVERITY_RANK[item.severity]
                < SYSTEM_LOG_SEVERITY_RANK[self.severity]
                for item in self.items
            )
            or LogSource.ALL in self.unavailable_sources
            or len(set(self.unavailable_sources)) != len(self.unavailable_sources)
            or (
                self.source is not LogSource.ALL
                and any(source is not self.source for source in self.unavailable_sources)
            )
            or (
                any(item.source in unavailable_sources for item in self.items)
            )
            or (
                (self.cursor_rotated or source_unavailable or all_sources_unavailable)
                and bool(self.items)
            )
            or (
                (self.cursor_rotated or source_unavailable or all_sources_unavailable)
                and (self.older_cursor is not None or self.newer_cursor is not None)
            )
            or (self.cursor_rotated and bool(self.unavailable_sources))
        ):
            raise ValueError("system log unavailable sources are invalid")
        return self


class StatusPatchV1(ClosedV1Model):
    drive: DriveStatusV1 | None = None
    expected_media: ExpectedMediaV1 | None = None
    job: JobSummaryV1 | None = None
    operation: OperationResponseV1 | None = None
    critical_recovery: CriticalRecoveryProofV1 | None = None
    progress: ProgressV1 | None = None
    telemetry: TelemetryV1 | None = None


class LibraryEventSummaryV1(ClosedV1Model):
    id: str = Field(pattern=_SAFE_LIBRARY_ID.pattern)
    state: Literal["active", "disabled", "retired"]
    scan_state: Literal["never", "running", "ready", "failed"]
    last_successful_scan_at: str | None
    file_count: int = Field(ge=0)
    byte_count: int = Field(ge=0)
    revision: int = Field(ge=0)


class LibraryChangedV1(ClosedV1Model):
    library: LibraryEventSummaryV1


class ShareEventSummaryV1(ClosedV1Model):
    share_id: str = Field(pattern=_SAFE_SHARE_ID.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    protocol: Literal["nfs", "smb"]
    lifecycle: Literal["active", "disabled", "retired"]
    desired_state: Literal["connected", "disconnected"]
    observed_state: Literal[
        "disconnected", "connecting", "connected", "disconnecting", "error"
    ]
    safe_error_code: str | None
    revision: int = Field(ge=1)
    last_checked_at: str | None


class ShareChangedV1(ClosedV1Model):
    share: ShareEventSummaryV1
    operation: ShareOperationV1 | None = None


class EventEnvelopeV1(ClosedV1Model):
    api_version: Literal[1] = 1
    id: int
    event: Literal["state.replace", "state.patch", "library.changed", "share.changed"]
    data: DaemonStatusV1 | StatusPatchV1 | LibraryChangedV1 | ShareChangedV1

    @model_validator(mode="after")
    def require_payload_matching_event_type(self) -> Self:
        if self.event == "state.replace" and not isinstance(self.data, DaemonStatusV1):
            raise ValueError("state.replace requires a complete daemon status")
        if self.event == "state.patch" and not isinstance(self.data, StatusPatchV1):
            raise ValueError("state.patch requires a status patch")
        if self.event == "library.changed" and not isinstance(
            self.data, LibraryChangedV1
        ):
            raise ValueError("library.changed requires a library summary")
        if self.event == "share.changed" and not isinstance(self.data, ShareChangedV1):
            raise ValueError("share.changed requires a share summary")
        return self
