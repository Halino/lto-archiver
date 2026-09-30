from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import secrets
from collections.abc import Iterator
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from math import isfinite
from pathlib import Path
from typing import Final, Literal
from urllib.parse import parse_qsl, urlencode
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import ValidationError

from ltobackup.client import (
    ApiCompatibilityError,
    DaemonClient,
    DaemonConflict,
    DaemonProtocolError,
    DaemonRequestError,
    DaemonUnavailable,
    WebReauthenticationContext,
)
from ltobackup.daemon.api_models import (
    AbandonCriticalAttemptRequestV1,
    ApplicationSettingsV1,
    AuthorizeAutomaticSequenceRequestV1,
    AuthorizeCatalogRestoreItemReplacementRequestV1,
    AuthorizeReplacementAttemptRequestV1,
    CatalogBrowseEntryV1,
    CatalogFileVersionV1,
    CreateCatalogRestorePlanRequestV1,
    CreateJobFromPlanRequestV1,
    CreateJobPlanRequestV1,
    CreateLibraryRequestV1,
    CreateShareRequestV1,
    CriticalRecoveryTargetV1,
    DaemonStatusV1,
    DiagnosticSummaryV1,
    EventEnvelopeV1,
    ExtendJobRequestV1,
    HealthV1,
    HostSettingsV1,
    JobCommandRequestV1,
    JobDetailV1,
    JobPlanV1,
    JobSequenceStatusV1,
    LibrarySummaryV1,
    PlannedCassetteV1,
    ReconcileCriticalRecoveryRequestV1,
    ReserveJobLabelsRequestV1,
    ResetFailedCassetteRequestV1,
    ResetPreMediaAttemptRequestV1,
    RetireJobRequestV1,
    RetireLibraryRequestV1,
    ShareConfirmedOperationRequestV1,
    ShareCredentialClearRequestV1,
    ShareCredentialRequestV1,
    ShareOperationRequestV1,
    ShareOperationV1,
    ShareRemoveRequestV1,
    ShareRetireRequestV1,
    ShareSummaryV1,
    ShareV1,
    StorageSummaryV1,
    SystemLogQuery,
    SystemLogsPageV1,
    TelemetrySampleV1,
    TelemetryV1,
    UpdateApplicationSettingsRequestV1,
    UpdateIncrementalPolicyRequestV1,
    UpdateJobRequestV1,
    UpdateLibraryRequestV1,
    UpdateShareRequestV1,
)
from ltobackup.errors import ValidationError as DomainValidationError
from ltobackup.log_reader.protocol import LogDirection, LogRange, LogSource, Severity
from ltobackup.media import require_ltfs_profile

from .auth_store import AuditContext, AuthStore, SessionManager, User
from .security import LoginRateLimiter, constant_time_matches

_PACKAGE_DIR: Final = Path(__file__).resolve().parent
_TEMPLATE_DIR: Final = _PACKAGE_DIR / "templates"
_STATIC_DIR: Final = _PACKAGE_DIR / "static"
_MAX_FORM_BYTES: Final = 16 * 1024
_SAFE_IDENTIFIER: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_SHARE_ID: Final = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_SAFE_CATALOG_LIBRARY_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SAFE_CATALOG_JOB_ID: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_MAX_SYSTEM_LOG_LIMIT: Final = 200
_LOG_SOURCE_LABELS: Final = {
    LogSource.ALL: "All sources",
    LogSource.DAEMON: "Daemon",
    LogSource.WEBUI: "WebUI",
    LogSource.LTFS: "LTFS / Tape",
    LogSource.COMMAND_BROKER: "Command broker",
    LogSource.SHARE_BROKER: "Share broker",
    LogSource.QUALIFICATION: "Qualification",
}
_LOG_SEVERITY_LABELS: Final = {
    Severity.DEBUG: "Debug",
    Severity.INFO: "Info",
    Severity.WARNING: "Warning",
    Severity.ERROR: "Error",
}
_LOG_RANGE_LABELS: Final = {
    LogRange.ONE_HOUR: "Last hour",
    LogRange.SIX_HOURS: "Last 6 hours",
    LogRange.ONE_DAY: "Last 24 hours",
    LogRange.SEVEN_DAYS: "Last 7 days",
    LogRange.THIRTY_DAYS: "Last 30 days",
    LogRange.RETAINED: "All retained events",
}
_LOG_DIRECTION_LABELS: Final = {
    LogDirection.OLDER: "Newest first",
    LogDirection.NEWER: "Oldest first",
}
_CSP: Final = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'self'"
)


def _parse_multiline_labels(value: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in value.splitlines() if line.strip())


@dataclass(frozen=True)
class WebSettings:
    """Security settings for the browser-facing, catalog-free process."""

    secure_cookies: bool = True
    session_cookie_name: str = "lto_archiver_session"
    csrf_cookie_name: str = "lto_archiver_csrf"
    session_max_age_seconds: int = 43_200

    def __post_init__(self) -> None:
        cookie_name = re.compile(r"[A-Za-z0-9_]{1,64}\Z")
        if not cookie_name.fullmatch(self.session_cookie_name):
            raise ValueError("invalid WebUI session cookie name")
        if not cookie_name.fullmatch(self.csrf_cookie_name):
            raise ValueError("invalid WebUI CSRF cookie name")
        if self.session_cookie_name == self.csrf_cookie_name:
            raise ValueError("WebUI cookie names must be distinct")
        if self.session_max_age_seconds <= 0:
            raise ValueError("WebUI session maximum age must be positive")


class FormFieldValueError(ValueError):
    """A scalar form value could not be parsed for a named field."""

    def __init__(self, field: str) -> None:
        super().__init__(field)
        self.field = field


def _form_integer(values: dict[str, str], field: str) -> int:
    try:
        return int(values.get(field, ""))
    except (TypeError, ValueError) as exc:
        raise FormFieldValueError(field) from exc


def _share_safe_form_values(values: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in values.items() if key != "csrf"}


def _pydantic_field_errors(
    exc: ValidationError,
    *,
    aliases: dict[str, str] | None = None,
    fallback: str,
) -> dict[str, str]:
    mapped: dict[str, str] = {}
    names = {} if aliases is None else aliases
    for error in exc.errors():
        location = error.get("loc", ())
        raw_field = next(
            (str(item) for item in reversed(location) if isinstance(item, str)),
            fallback,
        )
        field = names.get(raw_field, raw_field)
        mapped[field] = "Invalid value."
    if not mapped:
        mapped[fallback] = "Invalid value."
    return mapped


def _domain_field_error(
    exc: DomainValidationError,
    *,
    fallback: str,
    recent_reauthentication_field: str = "sessions",
) -> dict[str, str]:
    message = str(exc)
    exact_fields = {
        "Username is required": "username",
        "Username is too long": "username",
        "Username already exists": "username",
        "Invalid WebUI role": "role",
        "Account role is unchanged": "role",
        "Cannot remove the last administrator": "role",
        "WebUI administrator required": "role",
        "Invalid WebUI account state": "state",
        "WebUI user not found": "state",
        "Action on your own account is not allowed": "state",
        "Account state transition is not allowed": "state",
        "Invalid current password": "current_password",
        "Invalid idempotency key": "idempotency_key",
        "Idempotency key conflict": "idempotency_key",
        "Inconsistent idempotency receipt": "idempotency_key",
        "Administrator reauthentication required": recent_reauthentication_field,
    }
    field = exact_fields.get(message, fallback)
    return {field: "Invalid value or action."}


@dataclass(frozen=True)
class LibraryView:
    id: str
    display_name: str
    source_root: str | None
    source_kind: str
    share_id: str | None
    relative_subpath: str | None
    state: str
    scan_state: str
    last_successful_scan_at: str | None
    file_count: int
    byte_count: int
    revision: int

    @classmethod
    def from_model(cls, item: LibrarySummaryV1) -> LibraryView:
        source = item.source
        return cls(
            id=item.id,
            display_name=item.display_name,
            source_root=item.source_root,
            source_kind=("configured_path" if source is None else source.kind),
            share_id=(
                source.share_id
                if source is not None and source.kind == "managed_share"
                else None
            ),
            relative_subpath=(
                source.relative_subpath
                if source is not None and source.kind == "managed_share"
                else None
            ),
            state=item.state,
            scan_state=item.scan_state,
            last_successful_scan_at=item.last_successful_scan_at,
            file_count=item.file_count,
            byte_count=item.byte_count,
            revision=item.revision,
        )


@dataclass(frozen=True)
class CatalogFileVersionView:
    id: int
    library_id: str
    library_name: str
    job_id: str | None
    job_display_name: str | None
    block_id: str
    tape_id: str
    physical_label: str | None
    volume_label: str
    cassette_number: str
    tape_relative_path: str
    relative_path: str
    parent_path: str
    file_name: str
    size: str
    size_bytes: int
    copied_at: str
    sha256: str
    metadata_state: str
    metadata_error: str | None
    is_current: bool
    created_ns: int | None
    accessed_ns: int | None
    mtime_ns: int
    source_mode: int | None
    windows_attributes: int | None
    owner_name: str | None
    owner_sid: str | None
    security_descriptor: str | None
    alternate_streams: tuple[object, ...]

    @classmethod
    def from_model(cls, item: CatalogFileVersionV1) -> CatalogFileVersionView:
        return cls(
            id=item.id,
            library_id=item.library_id,
            library_name=item.library_name,
            job_id=item.job_id,
            job_display_name=item.job_display_name,
            block_id=item.block_id,
            tape_id=item.tape_id,
            physical_label=item.physical_label,
            volume_label=item.volume_label,
            cassette_number=item.cassette_number,
            tape_relative_path=item.tape_relative_path,
            relative_path=item.relative_path,
            parent_path=item.parent_path,
            file_name=item.file_name,
            size=_format_runtime_bytes(item.size),
            size_bytes=item.size,
            copied_at=item.copied_at,
            sha256=item.sha256,
            metadata_state=item.metadata_state,
            metadata_error=item.metadata_error,
            is_current=item.is_current,
            created_ns=item.created_ns,
            accessed_ns=item.accessed_ns,
            mtime_ns=item.mtime_ns,
            source_mode=item.source_mode,
            windows_attributes=item.windows_attributes,
            owner_name=item.owner_name,
            owner_sid=item.owner_sid,
            security_descriptor=item.security_descriptor,
            alternate_streams=tuple(item.alternate_streams),
        )


@dataclass(frozen=True)
class CatalogBrowseEntryView:
    kind: str
    name: str
    relative_path: str
    file: CatalogFileVersionView | None

    @classmethod
    def from_model(cls, item: CatalogBrowseEntryV1) -> CatalogBrowseEntryView:
        if item.kind == "directory":
            return cls(
                kind=item.kind,
                name=item.name,
                relative_path=item.relative_path,
                file=None,
            )
        return cls(
            kind=item.kind,
            name=item.name,
            relative_path=item.relative_path,
            file=CatalogFileVersionView.from_model(
                CatalogFileVersionV1.model_validate(
                    item.model_dump(exclude={"kind", "name"})
                )
            ),
        )


@dataclass(frozen=True)
class ShareErrorView:
    code: str
    title: str
    explanation: str
    recommendation: str
    operation: str
    occurred_at: str | None


_SHARE_ERROR_PRESENTATIONS: Final[dict[str, tuple[str, str, str]]] = {
    "idempotency_conflict": (
        "Request already used",
        "The request does not match the previously recorded operation.",
        "Refresh the page before repeating the operation.",
    ),
    "share_authentication_failed": (
        "Authentication failed",
        "The server rejected the share credentials.",
        "Update the credentials on this page and repeat the test.",
    ),
    "share_broker_unavailable": (
        "Share service unavailable",
        "The daemon cannot communicate with the protected mount service.",
        "Check the share broker service, then repeat the operation.",
    ),
    "share_busy": (
        "Operation already in progress",
        "The share is already running another operation.",
        "Wait for completion and refresh the status.",
    ),
    "share_connected": (
        "Share still connected",
        "The requested change requires a disconnected share.",
        "Disconnect the share and repeat the change.",
    ),
    "share_credentials_required": (
        "SMB credentials required",
        "The SMB share does not have usable credentials.",
        "Install SMB credentials and repeat the test.",
    ),
    "share_endpoint_invalid": (
        "Invalid endpoint",
        "The server or remote resource does not match the required format.",
        "Correct the server and export or share name, then save again.",
    ),
    "share_endpoint_not_allowed": (
        "Unauthorized endpoint",
        "The resolved address is not in a network allowed by the system.",
        "Check DNS and the local-network allowlist before retrying.",
    ),
    "share_has_libraries": (
        "Share used by libraries",
        "One or more libraries still depend on this share.",
        "Remove the dependencies shown on this page first.",
    ),
    "share_identity_changed": (
        "Mount identity changed",
        "The observed mount no longer matches the recorded configuration.",
        "Check the server and use Reconcile only after confirming the identity.",
    ),
    "share_in_use": (
        "Share in use",
        "A library or active job is using this source.",
        "End dependent use before disconnecting or removing the share.",
    ),
    "share_mount_authorization_failed": (
        "Connection blocked by the system",
        "The protected service did not receive authorization to create the network mount.",
        "Check the installed SELinux/systemd policy, then repeat the test.",
    ),
    "share_mount_failed": (
        "Connection failed",
        "The share mount did not complete.",
        "Check the protocol, version, and export or share name, then repeat the test.",
    ),
    "share_not_found": (
        "Share unavailable",
        "The requested share is no longer in the catalog.",
        "Return to the list and select an existing share.",
    ),
    "share_operation_timeout": (
        "Operation timed out",
        "The service did not complete the operation within the expected time.",
        "Check the current status before repeating the operation once.",
    ),
    "share_options_invalid": (
        "Invalid connection options",
        "The configuration contains options incompatible with the selected protocol.",
        "Correct the values in the share settings and repeat the test.",
    ),
    "share_recovery_required": (
        "Manual verification required",
        "The system cannot safely confirm whether the mount is still present.",
        "Check the mount status on the server before using Reconcile.",
    ),
    "share_revision_conflict": (
        "Configuration changed",
        "The page uses an earlier revision of the share.",
        "Refresh the page and repeat the change using current values.",
    ),
    "share_state_conflict": (
        "Incompatible state",
        "The requested operation is not valid in the current state.",
        "Refresh the status and choose an available action.",
    ),
    "share_unreachable": (
        "Server unreachable",
        "The share server does not respond from the system network.",
        "Check the network, DNS, and server export, then repeat the test.",
    ),
}

_SHARE_OPERATION_LABELS: Final[dict[str, str]] = {
    "connect": "Connection",
    "disconnect": "Disconnection",
    "test": "Test share",
    "reconcile": "Reconciliation",
    "credential.install": "Install credentials",
    "credential.clear": "Remove credentials",
}


@dataclass(frozen=True)
class ShareSummaryView:
    share_id: str
    display_name: str
    protocol: str
    lifecycle: str
    desired_state: str
    observed_state: str
    safe_error_code: str | None
    last_checked_at: str | None
    revision: int
    current_operation: ShareOperationV1 | None
    latest_operation: ShareOperationV1 | None

    @property
    def error_detail(self) -> ShareErrorView | None:
        if self.safe_error_code is None:
            return None
        title, explanation, recommendation = _SHARE_ERROR_PRESENTATIONS.get(
            self.safe_error_code,
            (
                "Operation failed",
                "The share reported a safe error.",
                "Refresh the status and check the configuration before retrying.",
            ),
        )
        operation = next(
            (
                candidate
                for candidate in (self.current_operation, self.latest_operation)
                if candidate is not None
                and candidate.safe_error_code == self.safe_error_code
            ),
            None,
        )
        return ShareErrorView(
            code=self.safe_error_code,
            title=title,
            explanation=explanation,
            recommendation=recommendation,
            operation=(
                "Share status"
                if operation is None
                else _SHARE_OPERATION_LABELS[operation.action]
            ),
            occurred_at=(
                self.last_checked_at
                if operation is None
                else operation.finished_at
                or operation.started_at
                or operation.queued_at
            ),
        )

    @classmethod
    def from_model(cls, item: ShareSummaryV1) -> ShareSummaryView:
        return cls(
            share_id=item.share_id,
            display_name=item.display_name,
            protocol=item.protocol,
            lifecycle=item.lifecycle,
            desired_state=item.desired_state,
            observed_state=item.observed_state,
            safe_error_code=item.safe_error_code,
            last_checked_at=item.last_checked_at,
            revision=item.revision,
            current_operation=item.current_operation,
            latest_operation=item.latest_operation,
        )


@dataclass(frozen=True)
class ShareAdminView(ShareSummaryView):
    server: str
    remote_resource: str
    nfs_version: str | None
    timeout_seconds: int | None
    retransmissions: int | None
    smb_dialect: str | None
    auto_connect: bool
    credential_configured: bool
    config_revision: int

    @classmethod
    def from_model(cls, item: ShareV1) -> ShareAdminView:
        config = item.config
        is_nfs = config.kind == "nfs"
        return cls(
            **ShareSummaryView.from_model(item).__dict__,
            server=config.server,
            remote_resource=config.export if is_nfs else config.share,
            nfs_version=config.version if is_nfs else None,
            timeout_seconds=config.timeout_seconds if is_nfs else None,
            retransmissions=config.retransmissions if is_nfs else None,
            smb_dialect=None if is_nfs else config.dialect,
            auto_connect=item.auto_connect,
            credential_configured=item.credential_configured,
            config_revision=item.config_revision,
        )


@dataclass(frozen=True)
class JobView:
    id: str
    display_name: str
    state: str
    library_ids: tuple[str, ...]
    media_profile: str
    cassettes: tuple[object, ...]
    requires_format_confirmation: bool
    resumable: bool
    revision: int
    capabilities: object
    sequence_status: JobSequenceStatusV1 | None
    sequence_status_error: str | None
    cassette_progress: object
    manifest_totals: object
    progress: object
    created_at: str
    last_activity_at: str
    current_checkpoint: str
    last_error: str | None
    imported: bool
    pause_requested: bool
    pause_acknowledged: bool
    incremental: object | None
    source_check: object | None
    catalog_cleanup: object | None
    boundary_refresh: object | None = None

    @classmethod
    def from_model(
        cls,
        item: JobDetailV1,
        *,
        cassettes: tuple[object, ...] | None = None,
        sequence_status: JobSequenceStatusV1 | None = None,
        sequence_status_error: str | None = None,
    ) -> JobView:
        return cls(
            id=item.id,
            display_name=item.display_name,
            state=item.state,
            library_ids=item.library_ids,
            media_profile=item.media_profile,
            cassettes=item.cassettes if cassettes is None else cassettes,
            requires_format_confirmation=item.requires_format_confirmation,
            resumable=item.resumable,
            revision=item.revision,
            capabilities=item.capabilities,
            sequence_status=sequence_status,
            sequence_status_error=sequence_status_error,
            cassette_progress=item.cassette_progress,
            manifest_totals=item.manifest_totals,
            progress=item.progress,
            created_at=item.created_at,
            last_activity_at=item.last_activity_at,
            current_checkpoint=item.current_checkpoint,
            last_error=item.last_error,
            imported=item.imported,
            pause_requested=item.pause_requested,
            pause_acknowledged=item.pause_acknowledged,
            incremental=item.incremental,
            source_check=item.source_check,
            catalog_cleanup=item.catalog_cleanup,
            boundary_refresh=item.boundary_refresh,
        )


@dataclass(frozen=True)
class PlannedCassetteView:
    sequence: int
    physical_label: str | None
    bytes: int
    objects: int
    allocation_bytes: int
    capacity_utilization_percent: str
    format_required: bool
    operation: str | None
    capacity_base_bytes: int
    overhead_bytes: int
    available_bytes: int

    @classmethod
    def from_model(
        cls,
        item: PlannedCassetteV1,
        *,
        effective_capacity_bytes: int,
        residual_append_capacity_bytes: int,
    ) -> PlannedCassetteView:
        capacity_base_bytes = (
            residual_append_capacity_bytes
            if item.operation == "append"
            else effective_capacity_bytes
        )
        utilization = item.capacity_utilization
        if item.operation == "append" and capacity_base_bytes > 0:
            utilization = item.allocation_bytes / capacity_base_bytes
        return cls(
            sequence=item.sequence,
            physical_label=item.physical_label,
            bytes=item.bytes,
            objects=item.objects,
            allocation_bytes=item.allocation_bytes,
            capacity_utilization_percent=f"{utilization * 100:.1f}",
            format_required=item.format_required,
            operation=item.operation,
            capacity_base_bytes=capacity_base_bytes,
            overhead_bytes=max(0, item.allocation_bytes - item.bytes),
            available_bytes=max(0, capacity_base_bytes - item.allocation_bytes),
        )


@dataclass(frozen=True)
class PlanView:
    id: str
    state: str
    kind: str
    requires_automatic_format_authorization: bool
    library_ids: tuple[str, ...]
    media_profile: str
    digest_sha256: str
    cassettes: tuple[PlannedCassetteView, ...]
    base_job_id: str | None
    base_job_revision: int | None
    native_capacity_bytes: int
    ltfs_usable_bytes: int
    capacity_reserve_bytes: int
    effective_capacity_bytes: int
    total_payload_bytes: int
    total_allocation_bytes: int
    total_overhead_bytes: int
    total_effective_capacity_bytes: int
    total_available_bytes: int

    @classmethod
    def from_model(cls, item: JobPlanV1) -> PlanView:
        profile = require_ltfs_profile(item.media_profile)
        if profile.ltfs_usable_bytes is None:
            raise ValueError("job plan media profile is not LTFS compatible")
        effective_capacity_bytes = max(
            0, profile.ltfs_usable_bytes - item.capacity_reserve_bytes
        )
        cassettes = tuple(
            PlannedCassetteView.from_model(
                cassette,
                effective_capacity_bytes=effective_capacity_bytes,
                residual_append_capacity_bytes=item.residual_append_capacity_bytes,
            )
            for cassette in item.cassettes
        )
        return cls(
            id=item.id,
            state=item.state,
            kind=item.kind,
            requires_automatic_format_authorization=(
                item.requires_automatic_format_authorization
            ),
            library_ids=item.library_ids,
            media_profile=item.media_profile,
            digest_sha256=item.digest_sha256,
            cassettes=cassettes,
            base_job_id=item.base_job_id,
            base_job_revision=item.base_job_revision,
            native_capacity_bytes=profile.native_capacity_bytes,
            ltfs_usable_bytes=profile.ltfs_usable_bytes,
            capacity_reserve_bytes=item.capacity_reserve_bytes,
            effective_capacity_bytes=effective_capacity_bytes,
            total_payload_bytes=sum(cassette.bytes for cassette in cassettes),
            total_allocation_bytes=sum(
                cassette.allocation_bytes for cassette in cassettes
            ),
            total_overhead_bytes=sum(
                cassette.overhead_bytes for cassette in cassettes
            ),
            total_effective_capacity_bytes=sum(
                cassette.capacity_base_bytes for cassette in cassettes
            ),
            total_available_bytes=sum(
                cassette.available_bytes for cassette in cassettes
            ),
        )


@dataclass(frozen=True)
class ApplicationSettingsView:
    revision: int
    capacity_reserve_bytes: int
    minimum_source_file_age_seconds: int
    copy_buffer_bytes: int
    content_verification_policy: str
    source_change_detection_policy: str
    default_media_profile: str
    tape_root_directory: str

    @classmethod
    def from_model(cls, item: ApplicationSettingsV1) -> ApplicationSettingsView:
        return cls(
            revision=item.revision,
            capacity_reserve_bytes=item.capacity_reserve_bytes,
            minimum_source_file_age_seconds=item.minimum_source_file_age_seconds,
            copy_buffer_bytes=item.copy_buffer_bytes,
            content_verification_policy=item.content_verification_policy,
            source_change_detection_policy=item.source_change_detection_policy,
            default_media_profile=item.default_media_profile,
            tape_root_directory=item.tape_root_directory,
        )


@dataclass(frozen=True)
class HostSettingsView:
    daemon_socket_path: str
    service_group: str
    state_directory: str
    tape_device_path: str
    scsi_device_path: str
    mount_path: str
    managed_source_mount_root: str
    source_allowlist: tuple[str, ...]
    restore_roots: tuple[str, ...]
    required_restart: bool

    @classmethod
    def from_model(cls, item: HostSettingsV1) -> HostSettingsView:
        return cls(**item.model_dump())


def _sample_freshness(telemetry: TelemetryV1 | None) -> str:
    if telemetry is None or telemetry.current_sample_age_seconds is None:
        return "Sample age unavailable"
    age = f"{telemetry.current_sample_age_seconds:.1f} s"
    if telemetry.current_sample_stale:
        return f"Stale — last sample {age} ago"
    return f"Last sample {age} ago"


@dataclass(frozen=True)
class DashboardView:
    drive_label: str
    expected_media_label: str
    job_display_name: str
    job_id: str | None
    operation_phase: str
    operation_title: str
    operation_phase_label: str
    files_progress: str
    bytes_progress: str
    current_rate: str
    effective_rate: str
    sample_freshness: str
    copy_time: str
    close_time: str
    finalization_time: str
    unmount_time: str
    unload_time: str
    explanation: str
    can_resume: bool
    finalization_active: bool
    finalization_label: str
    daemon_available: bool
    refresh_mode: str
    recovery_operation_id: str | None = None

    @classmethod
    def unavailable(cls) -> DashboardView:
        missing = "Not available"
        return cls(
            drive_label=missing,
            expected_media_label=missing,
            job_display_name=missing,
            job_id=None,
            operation_phase="unavailable",
            operation_title="Daemon unavailable",
            operation_phase_label=missing,
            files_progress=missing,
            bytes_progress=missing,
            current_rate=missing,
            effective_rate=missing,
            sample_freshness="Sample age unavailable",
            copy_time=missing,
            close_time=missing,
            finalization_time=missing,
            unmount_time=missing,
            unload_time=missing,
            explanation=(
                "Status is unreachable. The job remains owned by the daemon; "
                "refreshing the page does not start or interrupt operations."
            ),
            can_resume=False,
            finalization_active=False,
            finalization_label="LTFS cassette finalization: status unavailable",
            daemon_available=False,
            refresh_mode="idle",
        )

    @classmethod
    def from_status(cls, status: DaemonStatusV1) -> DashboardView:
        missing = "Not available"
        drive_label = status.drive.display_label.strip()
        if status.drive.state == "unavailable" or not drive_label:
            drive_label = missing

        expected = status.expected_media
        expected_media_label = (
            missing if expected is None else f"{expected.sequence} — {expected.label}"
        )
        job = status.job
        job_display_name = (
            missing if job is None else job.display_name.strip() or missing
        )
        job_id = None if job is None else job.id

        operation = status.operation
        blocker = status.admission_blocker or (
            operation
            if operation is not None and operation.state == "recovery_required"
            else None
        )
        phase = (
            "inactive"
            if operation is None or operation.phase is None
            else operation.phase
        )
        phase_labels = {
            "identifying_media": "Cassette identification",
            "formatting_media": "Cassette formatting",
            "mounting": "LTFS mount",
            "writing": "Writing files to LTFS",
            "writing_manifest": "Writing manifest",
            "finalizing_index": "LTFS index finalization",
            "unmounting": "LTFS unmount",
            "committing": "Catalog consolidation",
            "unloading": "Cassette unload",
            "inactive": missing,
        }
        phase_label = phase_labels.get(phase, "Unrecognized daemon phase")
        title = phase_label if operation is not None else "No active operation"
        if blocker is not None:
            phase = "recovery_required"
            phase_label = "Blocked — recovery required"
            title = "Operation blocked — recovery required"

        has_progress_context = job is not None or operation is not None
        files_progress = (
            f"{_format_integer(status.progress.files_completed)} / "
            f"{_format_integer(status.progress.files_total)} files"
            if has_progress_context
            else missing
        )
        bytes_progress = (
            f"{_format_runtime_bytes(status.progress.bytes_completed)} / "
            f"{_format_runtime_bytes(status.progress.bytes_total)}"
            if has_progress_context
            else missing
        )

        telemetry = status.telemetry
        current_rate = _format_rate(telemetry.current_mib_per_second)
        effective_rate = _format_rate(telemetry.effective_mib_per_second)
        sample_freshness = _sample_freshness(telemetry)
        has_operation = operation is not None

        def duration(value: float | None) -> str:
            return _format_duration(value) if has_operation else missing

        explanation = "Operation status received from the daemon."
        if blocker is not None:
            explanation = (
                f"Operation {blocker.id} is blocked. Automatic continuation is blocked. "
                "Safe reconciliation is required before another operation. "
                f"Reason code: {blocker.error_code or blocker.state}. "
                "An administrator must review recovery before this job can continue."
            )
            current_rate = missing
        elif job is None:
            explanation = "No active job in the daemon."
        elif job.state == "waiting_media" and expected is not None:
            explanation = (
                f"Insert the expected cassette {expected.sequence} — {expected.label}. "
                "The job will resume only after daemon verification."
            )
        elif job.state == "paused":
            explanation = "Job paused. Use Resume job; a deliberate pause requires your password there."

        finalization_active = phase in {"finalizing_index", "unmounting"}
        if blocker is not None:
            finalization_label = "LTFS cassette finalization: recovery review required"
        elif phase == "finalizing_index":
            finalization_label = (
                "LTFS cassette finalization: index consolidation in progress"
            )
        elif phase == "unmounting":
            finalization_label = (
                "LTFS cassette finalization: unmount and release in progress"
            )
        else:
            finalization_label = "LTFS cassette finalization: inactive"

        return cls(
            drive_label=drive_label,
            expected_media_label=expected_media_label,
            job_display_name=job_display_name,
            job_id=job_id,
            operation_phase=phase,
            operation_title=title,
            operation_phase_label=phase_label,
            files_progress=files_progress,
            bytes_progress=bytes_progress,
            current_rate=current_rate,
            effective_rate=effective_rate,
            sample_freshness=sample_freshness,
            copy_time=duration(telemetry.durations.copy_seconds),
            close_time=duration(telemetry.durations.close_seconds),
            finalization_time=duration(telemetry.durations.finalization_seconds),
            unmount_time=duration(telemetry.durations.unmount_seconds),
            unload_time=duration(telemetry.durations.unload_seconds),
            explanation=explanation,
            can_resume=(
                status.accepting_mutations
                and blocker is None
                and operation is None
                and job is not None
                and job.state == "paused"
            ),
            finalization_active=finalization_active,
            finalization_label=finalization_label,
            daemon_available=True,
            refresh_mode=(
                "waiting"
                if blocker is not None or (job is not None and job.state == "waiting_media")
                else "active"
                if operation is not None
                else "idle"
            ),
            recovery_operation_id=None if blocker is None else blocker.id,
        )


@dataclass(frozen=True)
class DiagnosticSummaryView:
    health_status: str
    cleaning_required: str
    tape_alerts: str
    files_completed: str
    bytes_completed: str
    current_rate: str
    effective_rate: str
    current_phase: str
    acquisition_state: str
    last_sample_at: str
    phase_durations: tuple[tuple[str, str], ...]
    refresh_mode: str

    @classmethod
    def from_summary(cls, summary: DiagnosticSummaryV1) -> DiagnosticSummaryView:
        health_labels = {
            "ok": "Normal",
            "degraded": "Degraded",
            "attention": "Needs attention",
            "unavailable": "Not available",
        }
        phase_labels = {
            "source_open": "Opening source",
            "smb_read": "SMB read",
            "ltfs_write_admission": "LTFS write admission",
            "copy": "Copy",
            "close": "File close",
            "manifest": "Manifest",
            "snapshot": "Snapshot",
            "finalization": "LTFS index finalization",
            "unmount": "LTFS unmount",
            "unload": "Unload",
            "retry": "Retry",
            "operator_wait": "Waiting for operator",
        }
        telemetry = summary.telemetry
        durations = telemetry.phase_durations
        sample_instants = tuple(
            _parse_diagnostic_timestamp(sample.occurred_at)
            for sample in telemetry.samples
        )
        latest_sample = (
            "No runtime samples available"
            if not sample_instants
            else max(sample_instants).strftime("%Y-%m-%d %H:%M:%S UTC")
        )
        cleaning_required = (
            "Not available"
            if summary.health.cleaning_required is None
            else "Required"
            if summary.health.cleaning_required
            else "Not required"
        )
        tape_alerts = (
            "No TapeAlert"
            if not summary.health.tape_alert_codes
            else "TapeAlert codes: "
            + ", ".join(str(code) for code in summary.health.tape_alert_codes)
        )
        phase_durations = (
            ("Opening source", _format_duration(durations.source_open_seconds)),
            ("SMB read", _format_duration(durations.smb_read_seconds)),
            (
                "LTFS write admission",
                _format_duration(durations.ltfs_write_admission_seconds),
            ),
            ("Copy", _format_duration(durations.copy_seconds)),
            ("File close", _format_duration(durations.close_seconds)),
            ("Manifest", _format_duration(durations.manifest_seconds)),
            ("Snapshot", _format_duration(durations.snapshot_seconds)),
            (
                "LTFS index finalization",
                _format_duration(durations.finalization_seconds),
            ),
            ("LTFS unmount", _format_duration(durations.unmount_seconds)),
            ("Unload", _format_duration(durations.unload_seconds)),
            ("Retry", _format_duration(durations.retry_seconds)),
            ("Waiting for operator", _format_duration(durations.operator_wait_seconds)),
        )
        return cls(
            health_status=health_labels[summary.health.status],
            cleaning_required=cleaning_required,
            tape_alerts=tape_alerts,
            files_completed=f"{_format_integer(telemetry.files_completed)} files",
            bytes_completed=_format_runtime_bytes(telemetry.bytes_completed),
            current_rate=_format_rate(telemetry.current_mib_per_second),
            effective_rate=_format_rate(telemetry.effective_mib_per_second),
            current_phase=(
                "No active runtime phase"
                if telemetry.current_phase is None
                else phase_labels[telemetry.current_phase]
            ),
            acquisition_state=(
                "Acquisition complete" if telemetry.closed else "Acquiring"
            ),
            last_sample_at=latest_sample,
            phase_durations=phase_durations,
            refresh_mode=(
                "idle"
                if telemetry.closed
                else "waiting"
                if telemetry.current_phase == "operator_wait"
                else "active"
            ),
        )


@dataclass(frozen=True)
class ChartPoint:
    event_id: int
    x: float
    y: float
    presentation_y: float
    time_offset_seconds: float
    rate: float
    presentation_rate: float


@dataclass(frozen=True)
class ChartGap:
    x: float
    time_offset_seconds: float


@dataclass(frozen=True)
class TelemetryChartView:
    available: bool
    maximum_rate: float
    middle_rate: float
    elapsed_seconds: float
    segments: tuple[tuple[ChartPoint, ...], ...]
    effective_rate: float | None
    effective_y: float | None
    gaps: tuple[ChartGap, ...]


def render_telemetry(
    samples: tuple[TelemetrySampleV1, ...], *, effective_rate: float | None = None
) -> str:
    """Render authoritative samples and effective rate without bridging gaps."""

    templates = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(("html", "xml"), default_for_string=True),
        auto_reload=False,
    )
    return templates.get_template("partials/telemetry.html").render(
        chart=_telemetry_chart(samples, effective_rate=effective_rate),
        format_axis_rate=_format_axis_rate,
        format_elapsed=_format_elapsed,
    )


def _telemetry_chart(
    samples: tuple[TelemetrySampleV1, ...], *, effective_rate: float | None = None
) -> TelemetryChartView:
    parsed: list[tuple[TelemetrySampleV1, datetime | None, float | None]] = []
    for sample in samples:
        instant = _parse_timestamp(sample.occurred_at)
        rate = sample.mib_per_second
        valid_rate = (
            float(rate)
            if rate is not None
            and not isinstance(rate, bool)
            and isfinite(rate)
            and rate >= 0
            else None
        )
        parsed.append((sample, instant, valid_rate))

    valid_instants = [instant for _, instant, _ in parsed if instant is not None]
    valid_rates = [
        rate for _, instant, rate in parsed if instant is not None and rate is not None
    ]
    if not valid_instants:
        return TelemetryChartView(False, 0, 0, 0, (), None, None, ())

    start = min(valid_instants)
    end = max(valid_instants)
    elapsed = max(0.0, (end - start).total_seconds())
    normalized_effective = (
        float(effective_rate)
        if effective_rate is not None
        and not isinstance(effective_rate, bool)
        and isfinite(effective_rate)
        and effective_rate >= 0
        else None
    )
    maximum = max(
        (*valid_rates, *(() if normalized_effective is None else (normalized_effective,))),
        default=0.0,
    )
    available = bool(valid_rates)
    denominator = maximum if maximum > 0 else 1.0
    time_denominator = elapsed if elapsed > 0 else 1.0
    segments: list[list[ChartPoint]] = []
    current_segment: list[ChartPoint] = []
    gaps: list[ChartGap] = []
    previous_instant: datetime | None = None
    previous_presentation_rate: float | None = None

    for sample, instant, rate in parsed:
        if instant is None:
            if current_segment:
                segments.append(current_segment)
                current_segment = []
            previous_presentation_rate = None
            continue
        offset = max(0.0, (instant - start).total_seconds())
        x = 150.0 + (offset / time_denominator) * 700.0
        if rate is None or (
            previous_instant is not None and instant <= previous_instant
        ):
            if current_segment:
                segments.append(current_segment)
                current_segment = []
            previous_presentation_rate = None
            gaps.append(ChartGap(x=x, time_offset_seconds=offset))
            previous_instant = instant
            continue
        y = 250.0 - (rate / denominator) * 220.0
        presentation_rate = (
            rate
            if previous_presentation_rate is None
            else previous_presentation_rate + 0.35 * (rate - previous_presentation_rate)
        )
        presentation_y = 250.0 - (presentation_rate / denominator) * 220.0
        current_segment.append(
            ChartPoint(
                event_id=sample.event_id,
                x=x,
                y=y,
                presentation_y=presentation_y,
                time_offset_seconds=offset,
                rate=rate,
                presentation_rate=presentation_rate,
            )
        )
        previous_presentation_rate = presentation_rate
        previous_instant = instant

    if current_segment:
        segments.append(current_segment)
    effective_y = (
        None
        if normalized_effective is None
        else 250.0 - (normalized_effective / denominator) * 220.0
    )
    return TelemetryChartView(
        available=available,
        maximum_rate=maximum,
        middle_rate=maximum / 2,
        elapsed_seconds=elapsed,
        segments=tuple(tuple(segment) for segment in segments),
        effective_rate=normalized_effective,
        effective_y=effective_y,
        gaps=tuple(gaps),
    )


def create_web_app(
    settings: WebSettings,
    auth_store: AuthStore,
    daemon_client: DaemonClient,
) -> FastAPI:
    """Create the unprivileged WebUI; all operational state comes from the daemon."""

    session_manager = SessionManager(
        auth_store,
        absolute_lifetime_seconds=settings.session_max_age_seconds,
    )
    rate_limiter = LoginRateLimiter()
    templates = Environment(
        loader=FileSystemLoader(_TEMPLATE_DIR),
        autoescape=select_autoescape(("html", "xml"), default_for_string=True),
        auto_reload=False,
    )
    templates.globals["format_integer"] = _format_integer
    templates.globals["format_storage_size"] = _format_storage_size
    # The HTML and its code/styles must advance together after deployment,
    # even when a browser retains an older same-path static response.
    templates.globals["asset_revision"] = hashlib.sha256(
        (_STATIC_DIR / "app.css").read_bytes()
        + (_STATIC_DIR / "live.js").read_bytes()
        + (_STATIC_DIR / "resume.js").read_bytes()
        + (_STATIC_DIR / "protected-action.js").read_bytes()
    ).hexdigest()[:16]
    app = FastAPI(
        title="LTO Archiver WebUI",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.session_manager = session_manager
    app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = _CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        if request.url.scheme.casefold() == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        if not request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/v1/health", response_model=HealthV1)
    def health() -> HealthV1 | JSONResponse:
        try:
            return daemon_client.get(
                "/api/v1/health",
                response_model=HealthV1,
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ):
            return JSONResponse(
                {"status": "unavailable"},
                status_code=503,
            )

    def render(name: str, **context: object) -> HTMLResponse:
        return HTMLResponse(templates.get_template(name).render(**context))

    def safe_login_destination(value: str) -> str:
        # Only read-only review pages. Never replay a command after signing in.
        if re.fullmatch(r"/(?:critical-recovery|jobs|restore-runs)/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value):
            return value
        if re.fullmatch(r"/operations/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}/recovery", value):
            return value
        return "/"

    def login_form_response(
        *,
        error: str | None,
        status_code: int = 200,
        csrf_token: str | None = None,
        next_destination: str = "/",
    ) -> HTMLResponse:
        pre_auth_csrf = csrf_token or secrets.token_urlsafe(32)
        response = HTMLResponse(
            templates.get_template("login.html").render(
                error=error,
                login_csrf=pre_auth_csrf,
                next_destination=safe_login_destination(next_destination),
            ),
            status_code=status_code,
        )
        _set_session_cookie(
            response,
            settings.csrf_cookie_name,
            pre_auth_csrf,
            settings,
        )
        return response

    def resolved_user(request: Request) -> tuple[User, str, str] | None:
        session_cookie = request.cookies.get(settings.session_cookie_name)
        csrf_cookie = request.cookies.get(settings.csrf_cookie_name)
        if not session_cookie or not csrf_cookie:
            return None
        user = session_manager.resolve(session_cookie)
        if user is None or not session_manager.verify_csrf(session_cookie, csrf_cookie):
            return None
        return user, session_cookie, csrf_cookie

    def load_status() -> tuple[DaemonStatusV1 | None, DashboardView]:
        try:
            status = daemon_client.get(
                "/api/v1/status",
                response_model=DaemonStatusV1,
            )
            return status, DashboardView.from_status(status)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
        ):
            return None, DashboardView.unavailable()

    def daemon_principal(user: User) -> str:
        return f"web-user-{user.id}"

    def daemon_role(user: User) -> Literal["admin", "operator"]:
        """Forward only the role resolved from the server-side WebUI session."""

        if user.role not in {"admin", "operator"}:
            raise DaemonProtocolError("invalid server session role")
        return user.role

    def load_storage_summary(user: User) -> StorageSummaryV1 | None:
        try:
            return daemon_client.get_storage_summary(
                principal=daemon_principal(user), role=daemon_role(user),
            )
        except (
            AttributeError,
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValueError,
        ):
            return None

    def load_diagnostic_summary(user: User) -> DiagnosticSummaryView | None:
        try:
            summary = daemon_client.get(
                "/api/v1/diagnostics/summary",
                response_model=DiagnosticSummaryV1,
                principal=daemon_principal(user),
                role=daemon_role(user),
            )
            return DiagnosticSummaryView.from_summary(summary)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValueError,
        ):
            return None

    def load_job_sequence_status(
        user: User, job_id: str
    ) -> tuple[JobSequenceStatusV1 | None, str | None]:
        """Load versioned sequence authority without confusing outages for upgrades."""

        try:
            return daemon_client.get_job_sequence_status(job_id, **daemon_kwargs(user)), None
        except (AttributeError, ApiCompatibilityError, DaemonProtocolError, ValidationError):
            return None, None
        except DaemonRequestError as exc:
            if exc.status_code in {404, 405, 501}:
                return None, None
            return (
                None,
                "The daemon could not provide cassette-sequence status. Refresh the job and review daemon health.",
            )
        except DaemonUnavailable:
            return (
                None,
                "The daemon is unavailable, so cassette-sequence controls remain safely disabled. Refresh the job after it recovers.",
            )

    def preparation_context(job, status: DaemonStatusV1 | None) -> dict | None:
        if status is None or status.job is None or status.admission_blocker or status.critical_recovery:
            return None
        operation = status.operation
        if operation is not None:
            if (operation.job_id == status.job.id and operation.kind == "archive.native"
                    and operation.state == "running" and operation.phase is None):
                return {
                    "label": "Preparing cassette",
                    "detail": "Catalog backup and preflight checks, or waiting for inserted media and identifying it. The daemon has not reported a finer step yet. No tape data is being copied; this stage can take several minutes.",
                    "since": operation.started_at,
                }
            return None
        if job is None or job.id != status.job.id or job.pause_requested or job.state == "paused":
            return None
        refresh = job.boundary_refresh
        if refresh is None or refresh.state not in {"queued", "scanning"}:
            return None
        return {
            "label": "Scanning source libraries" if refresh.state == "scanning" else "Source scan queued",
            "detail": "Checking for added, changed and removed files before the next cassette. The daemon has not reported a scan percentage; tape-copy counters do not measure this scan.",
            "since": refresh.occurred_at,
        }

    def status_template_context(
        user: User,
        csrf_token: str,
        status: DaemonStatusV1 | None,
        view: DashboardView,
    ) -> dict[str, object]:
        samples = () if status is None else status.telemetry.samples
        active_job = None
        preparation_unavailable = False
        if (status is not None and status.job is not None and status.operation is None
                and status.job.state == "waiting_media" and not status.admission_blocker
                and not status.critical_recovery):
            try:
                active_job = daemon_client.get_job(status.job.id, **daemon_kwargs(user))
            except (ApiCompatibilityError, DaemonProtocolError, DaemonRequestError,
                    DaemonUnavailable, ValidationError):
                preparation_unavailable = True
        preparation = preparation_context(active_job, status)
        if preparation is not None:
            view = replace(view, operation_title=preparation["label"],
                           operation_phase_label=preparation["label"],
                           explanation=preparation["detail"], can_resume=False,
                           refresh_mode="active")
        return {
            "user": user,
            "view": view,
            "preparation": preparation,
            "preparation_unavailable": preparation_unavailable,
            "storage": load_storage_summary(user),
            "csrf": csrf_token,
            "idempotency_key": str(uuid4()),
            "current_rate_value": (
                None if status is None else status.telemetry.current_mib_per_second
            ),
            "effective_rate_value": (
                None if status is None else status.telemetry.effective_mib_per_second
            ),
            "critical_recovery": (
                status.critical_recovery
                if status is not None and user.role == "admin"
                else None
            ),
            "telemetry_html": render_telemetry(
                samples,
                effective_rate=(
                    None if status is None else status.telemetry.effective_mib_per_second
                ),
            ),
        }

    def job_runtime_context(
        job: JobView, status: DaemonStatusV1 | None
    ) -> dict[str, object]:
        """Expose daemon samples only to the job that currently owns them."""

        live = status is not None and status.job is not None and status.job.id == job.id
        progress = status.progress if live and status is not None else job.progress
        operation = status.operation if live and status is not None else None
        current_sequence = (
            status.job.current_sequence if live and status is not None and status.job else None
        )
        total_cassettes = (
            status.job.total_cassettes if live and status is not None and status.job else None
        )
        telemetry = status.telemetry if live and status is not None else None
        status_view = None if status is None else DashboardView.from_status(status)
        blocked = status_view is not None and status_view.recovery_operation_id is not None
        boundary_refresh_state = getattr(job.boundary_refresh, "state", None)
        preparation = preparation_context(job, status) if live else None
        return {
            "live": live,
            "preparation": preparation,
            "blocked": blocked,
            "blocked_explanation": status_view.explanation if blocked else None,
            "recovery_operation_id": status_view.recovery_operation_id if blocked else None,
            "critical_recovery_operation_id": (
                status.critical_recovery.operation_id
                if blocked and status is not None and status.critical_recovery is not None
                and status.critical_recovery.operation_id == status_view.recovery_operation_id
                else None
            ),
            "files_progress": (
                f"{_format_integer(progress.files_completed)} / "
                f"{_format_integer(progress.files_total)} files"
                if live
                else f"{_format_integer(job.progress.objects_completed)} / "
                f"{_format_integer(job.progress.objects_total)} files"
            ),
            "bytes_progress": (
                f"{_format_runtime_bytes(progress.bytes_completed)} / "
                f"{_format_runtime_bytes(progress.bytes_total)}"
                if live
                else f"{_format_runtime_bytes(job.progress.bytes_completed)} / "
                f"{_format_runtime_bytes(job.progress.bytes_total)}"
            ),
            "cassette_progress": (
                f"{_format_integer(current_sequence)} / "
                f"{_format_integer(total_cassettes)}"
                if current_sequence is not None and total_cassettes is not None
                else f"{_format_integer(job.cassette_progress.completed)} / "
                f"{_format_integer(job.cassette_progress.total)}"
            ),
            "current_rate": _format_rate(
                None if telemetry is None or blocked else telemetry.current_mib_per_second
            ),
            "current_rate_value": (
                None if telemetry is None or blocked else telemetry.current_mib_per_second
            ),
            "sample_freshness": _sample_freshness(telemetry),
            "effective_rate": _format_rate(
                None if telemetry is None else telemetry.effective_mib_per_second
            ),
            "effective_rate_value": (
                None if telemetry is None else telemetry.effective_mib_per_second
            ),
            "phase": (
                "Blocked — recovery required"
                if blocked
                else preparation["label"]
                if preparation is not None
                else "Not available"
                if operation is None or operation.phase is None
                else operation.phase.replace("_", " ").capitalize()
            ),
            "eta": "Not available",
            "telemetry_html": render_telemetry(
                () if telemetry is None else telemetry.samples,
                effective_rate=(
                    None if telemetry is None else telemetry.effective_mib_per_second
                ),
            ),
            "refresh_mode": (
                "active"
                if preparation is not None
                else
                "waiting"
                if blocked
                or boundary_refresh_state == "waiting_labels"
                or (
                    live and status is not None and status.job.state == "waiting_media"
                    and boundary_refresh_state not in {"queued", "scanning"}
                )
                else "active"
                if boundary_refresh_state in {"queued", "scanning"}
                or (
                    live
                    and status is not None
                    and status.job.state
                    not in {
                        "planned",
                        "pending",
                        "paused",
                        "completed",
                        "failed",
                        "retired",
                    }
                )
                else "idle"
            ),
            "boundary_refresh": job.boundary_refresh,
        }

    def job_has_active_operation(
        job_id: str, status: DaemonStatusV1 | None
    ) -> bool:
        operation = None if status is None else status.operation
        return bool(
            operation is not None
            and operation.job_id == job_id
            and operation.state in {"running", "recovery_required"}
        )

    def restore_run_template_context(
        user: User,
        session_cookie: str,
        csrf_token: str,
        run: object,
    ) -> dict[str, object]:
        status, _view = load_status()
        operation = None if status is None else status.operation
        owns_live_telemetry = (
            operation is not None and operation.job_id == getattr(run, "id", None)
        )
        telemetry = status.telemetry if owns_live_telemetry and status is not None else None
        cassettes = tuple(getattr(run, "cassettes", ()))
        current_sequence = getattr(run, "current_cassette_sequence", None)
        current_cassette = next(
            (
                cassette
                for cassette in cassettes
                if cassette.sequence == current_sequence
            ),
            None,
        )
        state = str(getattr(run, "state", "failed"))
        recent_admin = (
            user.role == "admin"
            and session_manager.reauthentication_evidence(session_cookie) is not None
        )
        return {
            "user": user,
            "csrf": csrf_token,
            "idempotency_key": str(uuid4()),
            "new_idempotency_key": uuid4,
            "run": run,
            "current_cassette": current_cassette,
            "current_rate": _format_rate(
                None if telemetry is None else telemetry.current_mib_per_second
            ),
            "current_rate_value": (
                None if telemetry is None else telemetry.current_mib_per_second
            ),
            "effective_rate": _format_rate(
                None if telemetry is None else telemetry.effective_mib_per_second
            ),
            "effective_rate_value": (
                None if telemetry is None else telemetry.effective_mib_per_second
            ),
            "phase": (
                state.replace("_", " ").capitalize()
                if operation is None or operation.phase is None
                else operation.phase.replace("_", " ").capitalize()
            ),
            "bytes_progress": (
                f"{_format_runtime_bytes(getattr(run, 'copied_bytes', 0))} / "
                f"{_format_runtime_bytes(getattr(run, 'total_bytes', 0))}"
            ),
            "recent_admin": recent_admin,
            "telemetry_html": render_telemetry(
                () if telemetry is None else telemetry.samples,
                effective_rate=(
                    None if telemetry is None else telemetry.effective_mib_per_second
                ),
            ),
            "refresh_mode": (
                "waiting"
                if state in {"planned", "waiting_media", "paused", "recovery_required"}
                else "active"
                if state == "restoring"
                else "idle"
            ),
        }

    async def mutation_form(
        request: Request,
        allowed_fields: set[str],
    ) -> tuple[User, dict[str, str]] | JSONResponse:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, session_cookie, _csrf_cookie = resolved
        try:
            form = await _read_form(request, allowed_fields)
        except FormRejected as exc:
            return JSONResponse(
                {"error": {"code": exc.code, "message": exc.public_message}},
                status_code=422,
            )
        if not session_manager.verify_csrf(session_cookie, form.get("csrf", "")):
            return JSONResponse({"error": {"code": "csrf_invalid"}}, status_code=403)
        idempotency_key = form.get("idempotency_key", "")
        if not _SAFE_IDENTIFIER.fullmatch(idempotency_key):
            return JSONResponse(
                {"error": {"code": "idempotency_key_invalid"}}, status_code=422
            )
        return user, form

    async def management_form(
        request: Request,
        scalar_fields: set[str],
        list_fields: set[str] | None = None,
        *,
        admin: bool = False,
    ) -> tuple[User, str, dict[str, str], dict[str, tuple[str, ...]]] | Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, session_cookie, _csrf_cookie = resolved
        if admin and user.role != "admin":
            return management_error_response(
                user,
                "Operation allowed only for administrators.",
                status_code=403,
            )
        try:
            scalars, lists = await _read_typed_form(
                request,
                scalar_fields,
                list_fields or set(),
            )
        except FormRejected as exc:
            return management_error_response(user, exc.public_message, status_code=422)
        if not session_manager.verify_csrf(session_cookie, scalars.get("csrf", "")):
            return management_error_response(
                user, "Form session expired.", status_code=403
            )
        if not _SAFE_IDENTIFIER.fullmatch(scalars.get("idempotency_key", "")):
            return management_error_response(
                user, "Invalid request identifier.", status_code=422
            )
        return user, session_cookie, scalars, lists

    async def share_preview_form(
        request: Request,
        scalar_fields: set[str],
    ) -> tuple[User, dict[str, str]] | Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, session_cookie, _csrf_cookie = resolved
        if user.role != "admin":
            return management_error_response(
                user,
                "Operation allowed only for administrators.",
                status_code=403,
            )
        try:
            scalars, _lists = await _read_typed_form(
                request,
                scalar_fields,
                set(),
            )
        except FormRejected as exc:
            return management_error_response(user, exc.public_message, status_code=422)
        if not session_manager.verify_csrf(session_cookie, scalars.get("csrf", "")):
            return management_error_response(
                user, "Form session expired.", status_code=403
            )
        return user, scalars

    def management_error_response(
        user: User,
        message: str,
        *,
        status_code: int,
        template_name: str = "management_error.html",
        **context: object,
    ) -> HTMLResponse:
        return HTMLResponse(
            templates.get_template(template_name).render(
                user=user,
                error=message,
                csrf=context.pop("csrf", ""),
                idempotency_key=context.pop("idempotency_key", str(uuid4())),
                **context,
            ),
            status_code=status_code,
        )

    def daemon_error_response(
        user: User,
        exc: Exception,
        *,
        template_name: str = "management_error.html",
        **context: object,
    ) -> HTMLResponse:
        messages = {
            "settings_revision_conflict": "Revision conflict: refresh the settings.",
            "idempotency_conflict": "Conflict with a previous request.",
            "library_not_found": "Library unavailable.",
            "library_revision_conflict": "The library changed: refresh the page.",
            "library_source_changed": "The source changed: run a new scan.",
            "plan_stale": "The plan is no longer current: create a new estimate.",
            "plan_digest_mismatch": "The plan changed: refresh the estimate.",
            "plan_expired": "The plan expired: create a new estimate.",
            "plan_consumed": "The plan has already been saved.",
            "job_not_found": "Job unavailable.",
            "job_revision_conflict": "The job changed: refresh the page.",
            "role_denied": "Operation not allowed for this role.",
            "share_not_found": "Share unavailable.",
            "share_revision_conflict": "The share changed: refresh the page.",
            "share_in_use": "The share is used by a library or job.",
            "share_connected": "Disconnect the share before changing it.",
            "share_credentials_required": "SMB credentials required.",
            "share_unreachable": "Share unreachable.",
            "share_authentication_failed": "Share authentication failed.",
            "share_mount_failed": "Share connection failed.",
            "share_identity_changed": "Share identity changed: reconcile it.",
            "share_busy": "Share busy with an operation.",
            "share_operation_timeout": "Share operation timed out.",
            "share_endpoint_not_allowed": "Share endpoint is unauthorized.",
            "catalog_file_version_not_found": "The requested catalog version is unavailable.",
            "catalog_library_not_found": "The requested catalog library is unavailable.",
            "restore_plan_not_found": "The requested restore plan is unavailable.",
            "restore_plan_invalid": "The restore selection or destination is invalid.",
            "critical_recovery_rejected": "Recovery was not authorized: the recorded evidence changed or a safety prerequisite is still missing. No replacement has been authorized by this response.",
            "critical_recovery_not_found": "This protected attempt is no longer available. Check the job's current state.",
        }
        titles = {
            "settings_revision_conflict": "Configuration changed",
            "catalog_file_version_not_found": "Catalog version not found",
            "catalog_library_not_found": "Catalog offline or unavailable",
            "restore_plan_not_found": "Restore plan not found",
            "restore_plan_invalid": "Invalid restore plan",
            "daemon_unavailable": "Daemon unavailable",
            "critical_recovery_rejected": "Recovery is still blocked",
            "critical_recovery_not_found": "Recovery state changed",
        }
        next_actions = {
            "settings_revision_conflict": "Refresh the settings and repeat the change using current values.",
            "catalog_file_version_not_found": "Return to the catalog and choose a version that is still visible.",
            "catalog_library_not_found": "Return to the catalog and check the selected library.",
            "restore_plan_not_found": "Return to the catalog and create a new plan from available metadata.",
            "restore_plan_invalid": "Correct the selection or choose an authorized destination.",
            "daemon_unavailable": "Refresh this page; do not repeat an ambiguous mutation with a new key.",
            "critical_recovery_rejected": "Use Continue to return to this recovery, re-evaluate its current status, and review the explanation before choosing another action.",
            "critical_recovery_not_found": "Return to this job to see its latest state before sending another command.",
        }
        if isinstance(exc, DaemonRequestError):
            raw_code = exc.error_code
            code = (
                raw_code
                if isinstance(raw_code, str)
                and _SAFE_IDENTIFIER.fullmatch(raw_code)
                and raw_code in messages
                else "daemon_rejected"
            )
            message = messages.get(code, "Request rejected by the daemon.")
            status_code = exc.status_code if 400 <= exc.status_code < 500 else 503
        else:
            code = "daemon_unavailable"
            message = "Daemon unavailable. Retry without repeating any other actions."
            status_code = 503
        next_url = str(
            context.pop(
                "next_url",
                (
                    "/settings"
                    if code == "settings_revision_conflict"
                    else "/catalog"
                    if code.startswith(("catalog_", "restore_"))
                    else "/"
                ),
            )
        )
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name=template_name,
            error_code=code,
            error_title=titles.get(code, "Operation unavailable"),
            error_explanation=message,
            error_next_action=next_actions.get(
                code,
                "Return to the previous page, check the status, and retry only the available action.",
            ),
            error_field=context.pop("error_field", None),
            error_action=context.pop("error_action_name", None),
            next_url=next_url,
            **context,
        )

    def daemon_kwargs(user: User) -> dict[str, str]:
        return {"principal": daemon_principal(user), "role": daemon_role(user)}

    def selectable_share_views(user: User) -> tuple[ShareSummaryView, ...]:
        list_shares = getattr(daemon_client, "list_network_shares", None)
        if list_shares is None:
            return ()
        return tuple(
            ShareSummaryView.from_model(item)
            for item in list_shares(**daemon_kwargs(user))
            if item.lifecycle == "active" and item.observed_state == "connected"
        )

    def all_share_views(user: User) -> tuple[ShareSummaryView, ...]:
        list_shares = getattr(daemon_client, "list_network_shares", None)
        if list_shares is None:
            return ()
        return tuple(
            ShareSummaryView.from_model(item)
            for item in list_shares(**daemon_kwargs(user))
        )

    def library_detail_form_error(
        user: User,
        library_id: str,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        form_values: dict[str, object],
        field_errors: dict[str, str],
        error_action: str,
    ) -> HTMLResponse:
        try:
            fresh = daemon_client.get_library(library_id, **daemon_kwargs(user))
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ):
            return management_error_response(user, message, status_code=status_code)
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="library_detail.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            library=LibraryView.from_model(fresh),
            form_values=form_values,
            field_errors=field_errors,
            error_action=error_action,
        )

    def libraries_form_error(
        user: User,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        form_values: dict[str, str],
        field_errors: dict[str, str],
    ) -> HTMLResponse:
        try:
            libraries = tuple(
                LibraryView.from_model(item)
                for item in daemon_client.list_libraries(**daemon_kwargs(user))
            )
            share_options = selectable_share_views(user)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ):
            return management_error_response(user, message, status_code=status_code)
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="libraries.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            libraries=libraries,
            share_options=share_options,
            form_values=form_values,
            field_errors=field_errors,
        )

    def settings_form_error(
        user: User,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        form_values: dict[str, str],
        field_errors: dict[str, str],
    ) -> HTMLResponse:
        try:
            application = daemon_client.get_application_settings(**daemon_kwargs(user))
            host = daemon_client.get_host_settings(**daemon_kwargs(user))
            profiles = daemon_client.get_media_profiles(**daemon_kwargs(user))
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ):
            return management_error_response(user, message, status_code=status_code)
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="settings.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            application=ApplicationSettingsView.from_model(application),
            host=HostSettingsView.from_model(host),
            profiles=profiles,
            form_values=form_values,
            field_errors=field_errors,
        )

    def job_detail_form_error(
        user: User,
        job_id: str,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        form_values: dict[str, object],
        field_errors: dict[str, str],
        error_action: str,
    ) -> HTMLResponse:
        try:
            job = daemon_client.get_job(job_id, **daemon_kwargs(user))
            cassettes = daemon_client.get_job_cassettes(
                job_id, limit=64, cursor=None, **daemon_kwargs(user)
            )
            manifest = daemon_client.get_job_manifest(
                job_id, limit=100, cursor=None, **daemon_kwargs(user)
            )
            history = daemon_client.get_job_history(
                job_id, limit=100, cursor=None, **daemon_kwargs(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ):
            return management_error_response(user, message, status_code=status_code)
        sequence_status, sequence_status_error = load_job_sequence_status(user, job_id)
        status = load_status()[0]
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="job_detail.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            job=JobView.from_model(
                job,
                cassettes=cassettes.items,
                sequence_status=sequence_status,
                sequence_status_error=sequence_status_error,
            ),
            cassettes=cassettes,
            manifest=manifest,
            history=history,
            manifest_cursor=None,
            history_cursor=None,
            cassette_cursor=None,
            form_values=form_values,
            field_errors=field_errors,
            error_action=error_action,
            operation_active=job_has_active_operation(job_id, status),
            runtime=job_runtime_context(
                JobView.from_model(job, cassettes=cassettes.items), status
            ),
        )

    def users_form_error(
        user: User,
        session_cookie: str,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        form_values: dict[str, str] | None = None,
        field_errors: dict[str, str] | None = None,
        error_action: str = "",
    ) -> HTMLResponse:
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="users.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            new_idempotency_key=uuid4,
            users=auth_store.list_users(),
            format_timestamp=_format_user_timestamp,
            recently_reauthenticated=session_manager.recently_reauthenticated(
                session_cookie
            ),
            form_values={} if form_values is None else form_values,
            field_errors={} if field_errors is None else field_errors,
            error_action=error_action,
        )

    def account_form_error(
        user: User,
        session_cookie: str,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        field_errors: dict[str, str],
        error_action: str,
    ) -> HTMLResponse:
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="account.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            recently_reauthenticated=session_manager.recently_reauthenticated(
                session_cookie
            ),
            field_errors=field_errors,
            error_action=error_action,
        )

    def load_plan_view(user: User, plan_id: str) -> PlanView:
        plan = daemon_client.get_job_plan(plan_id, **daemon_kwargs(user))
        return PlanView.from_model(plan)

    def plan_form_error(
        user: User,
        plan_id: str,
        *,
        csrf: str,
        idempotency_key: str,
        message: str,
        status_code: int,
        labels: tuple[str, ...],
        field_errors: dict[str, str],
        authorize_automatic_formatting: bool = False,
    ) -> HTMLResponse:
        try:
            plan = load_plan_view(user, plan_id)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ):
            return management_error_response(user, message, status_code=status_code)
        return management_error_response(
            user,
            message,
            status_code=status_code,
            template_name="job_plan.html",
            csrf=csrf,
            idempotency_key=idempotency_key,
            plan=plan,
            form_values={
                "display_name": "",
                "labels": labels,
                "authorize_automatic_formatting": authorize_automatic_formatting,
            },
            field_errors=field_errors,
        )

    def audit_context(request: Request) -> AuditContext:
        return AuditContext(
            request_id=str(uuid4()),
            remote_address=_request_origin(request)[1],
        )

    def forward_mutation(
        *,
        user: User,
        csrf_token: str,
        path: str,
        payload: dict[str, object],
        idempotency_key: str,
    ) -> Response:
        try:
            operation = daemon_client.post(
                path,
                payload,
                idempotency_key,
                principal=daemon_principal(user),
                role=daemon_role(user),
            )
        except DaemonConflict as exc:
            return HTMLResponse(
                templates.get_template("operation_conflict.html").render(
                    user=user,
                    csrf=csrf_token,
                    active_operation=exc.active_operation,
                ),
                status_code=409,
            )
        except ApiCompatibilityError:
            return JSONResponse(
                {"error": {"code": "daemon_api_incompatible"}}, status_code=409
            )
        except (DaemonProtocolError, DaemonRequestError, DaemonUnavailable):
            return JSONResponse(
                {"error": {"code": "daemon_unavailable"}}, status_code=503
            )
        return JSONResponse(operation, status_code=202)

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        destination = safe_login_destination(request.query_params.get("next", "/"))
        if resolved_user(request) is not None:
            return RedirectResponse(destination, status_code=303)
        return login_form_response(error=None, next_destination=destination)

    @app.post("/login")
    async def login(request: Request) -> Response:
        try:
            form = await _read_form(
                request,
                {"username", "password", "login_csrf", "next"},
            )
        except FormRejected as exc:
            return login_form_response(
                error=exc.public_message,
                status_code=422,
            )
        destination = safe_login_destination(form.get("next", "/"))
        csrf_cookie = request.cookies.get(settings.csrf_cookie_name, "")
        supplied_login_csrf = form.get("login_csrf", "")
        if (
            not csrf_cookie
            or not supplied_login_csrf
            or not constant_time_matches(
                csrf_cookie,
                supplied_login_csrf,
            )
        ):
            return login_form_response(
                error="Sign-in session expired. Try again.",
                status_code=403,
                next_destination=destination,
            )
        username = form.get("username", "")
        password = form.get("password", "")
        origin_key, audit_origin = _request_origin(request)
        if not rate_limiter.allowed(username, origin_key):
            return login_form_response(
                error="Too many attempts. Try again in a few minutes.",
                status_code=429,
                csrf_token=csrf_cookie,
                next_destination=destination,
            )
        audit_context = AuditContext(
            request_id=str(uuid4()),
            remote_address=audit_origin,
        )
        user = auth_store.authenticate(
            username,
            password,
            audit_context=audit_context,
        )
        if user is None:
            rate_limiter.record_failure(username, origin_key)
            return login_form_response(
                error="Invalid username or password.",
                status_code=401,
                csrf_token=csrf_cookie,
                next_destination=destination,
            )
        rate_limiter.record_success(username, origin_key)
        session = session_manager.create(user, audit_context=audit_context)
        response = RedirectResponse(destination, status_code=303)
        _set_session_cookie(
            response,
            settings.session_cookie_name,
            session.cookie,
            settings,
        )
        _set_session_cookie(
            response,
            settings.csrf_cookie_name,
            session.csrf_token,
            settings,
        )
        return response

    # These reads use a synchronous daemon client. Let FastAPI run them in its
    # worker pool so a daemon waiting on a source scan cannot stall the WebUI.
    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        status, view = load_status()
        return render(
            "dashboard.html", **status_template_context(user, csrf_token, status, view)
        )

    @app.get("/status-fragment", response_class=HTMLResponse)
    def status_fragment(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, csrf_token = resolved
        status, view = load_status()
        return render(
            "partials/status.html",
            **status_template_context(user, csrf_token, status, view),
        )

    @app.get("/events")
    async def events(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        _user, session_cookie, csrf_cookie = resolved
        try:
            after_id, last_event_id = _web_event_cursors(request)
        except ValueError:
            return JSONResponse(
                {"error": {"code": "invalid_event_cursor"}}, status_code=400
            )

        def serialized_events() -> Iterator[str]:
            try:
                if not session_manager.verify_csrf(session_cookie, csrf_cookie):
                    return
                for candidate in daemon_client.events(
                    after_id=after_id,
                    last_event_id=last_event_id,
                ):
                    envelope = EventEnvelopeV1.model_validate(candidate)
                    data = envelope.data.model_dump(
                        mode="json",
                        exclude_unset=envelope.event == "state.patch",
                    )
                    if not session_manager.verify_csrf(session_cookie, csrf_cookie):
                        return
                    yield (
                        f"id: {envelope.id}\n"
                        f"event: {envelope.event}\n"
                        f"data: {json.dumps(data, separators=(',', ':'))}\n\n"
                    )
                if not session_manager.verify_csrf(session_cookie, csrf_cookie):
                    return
                yield "event: stream.ready\ndata: {}\n\n"
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                TypeError,
                ValueError,
                ValidationError,
            ):
                return

        return StreamingResponse(
            serialized_events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    def share_detail_response(
        user: User,
        csrf_token: str,
        share_id: str,
        *,
        error: str | None = None,
        status_code: int = 200,
        form_values: dict[str, str] | None = None,
        field_errors: dict[str, str] | None = None,
        error_action: str = "",
        idempotency_key: str | None = None,
        preview_ready: bool = False,
    ) -> HTMLResponse:
        try:
            if user.role == "admin":
                share_options = daemon_client.get_network_share_options(
                    **daemon_kwargs(user)
                )
                share: ShareSummaryView | ShareAdminView = ShareAdminView.from_model(
                    daemon_client.get_network_share(share_id, **daemon_kwargs(user))
                )
            else:
                share_options = None
                summary = next(
                    item
                    for item in daemon_client.list_network_shares(**daemon_kwargs(user))
                    if item.share_id == share_id
                )
                share = ShareSummaryView.from_model(summary)
            dependent_libraries = tuple(
                LibraryView.from_model(item)
                for item in daemon_client.list_libraries(**daemon_kwargs(user))
                if item.source is not None
                and item.source.kind == "managed_share"
                and item.source.share_id == share_id
            )
        except StopIteration:
            return management_error_response(
                user, "Share unavailable.", status_code=404
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/shares")
        return HTMLResponse(
            templates.get_template("share_detail.html").render(
                user=user,
                csrf=csrf_token,
                idempotency_key=idempotency_key or str(uuid4()),
                share=share,
                error=error,
                form_values=form_values or {},
                field_errors=field_errors or {},
                error_action=error_action,
                dependent_libraries=dependent_libraries,
                preview_ready=preview_ready,
                share_options=share_options,
            ),
            status_code=status_code,
        )

    def share_ambiguous_retry_response(
        user: User,
        *,
        csrf_token: str,
        share_id: str,
        action_url: str,
        idempotency_key: str,
        retry_fields: dict[str, str],
        credential_retry: bool = False,
        offer_retry: bool = True,
    ) -> HTMLResponse:
        return HTMLResponse(
            templates.get_template("share_retry.html").render(
                user=user,
                csrf=csrf_token,
                share_id=share_id,
                action_url=action_url,
                idempotency_key=idempotency_key,
                retry_fields=retry_fields,
                credential_retry=credential_retry,
                offer_retry=offer_retry,
            ),
            status_code=503,
        )

    @app.get("/shares", response_class=HTMLResponse)
    async def shares_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        try:
            shares = tuple(
                ShareSummaryView.from_model(item)
                for item in daemon_client.list_network_shares(**daemon_kwargs(user))
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/shares")
        return render("shares.html", user=user, csrf=csrf_token, shares=shares)

    @app.get("/shares/new", response_class=HTMLResponse)
    async def new_share_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if user.role != "admin":
            return management_error_response(
                user, "Operation allowed only for administrators.", status_code=403
            )
        create_protocol = request.query_params.get("protocol", "nfs")
        if create_protocol not in {"nfs", "smb"}:
            create_protocol = "nfs"
        try:
            share_options = daemon_client.get_network_share_options(
                **daemon_kwargs(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/shares")
        return render(
            "share_detail.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            share=None,
            form_values={},
            field_errors={},
            error_action="create",
            create_protocol=create_protocol,
            share_options=share_options,
        )

    @app.post("/shares")
    async def create_share(request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "share_id",
                "display_name",
                "protocol",
                "server",
                "remote_resource",
                "nfs_version",
                "timeout_seconds",
                "retransmissions",
                "dialect",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        safe_values = _share_safe_form_values(form)
        try:
            share_options = daemon_client.get_network_share_options(
                **daemon_kwargs(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/shares")
        try:
            protocol = form.get("protocol", "")
            if protocol == "nfs":
                config = {
                    "kind": "nfs",
                    "server": form.get("server", ""),
                    "export": form.get("remote_resource", ""),
                    "version": form.get("nfs_version", "4.2"),
                    "timeout_seconds": _form_integer(form, "timeout_seconds"),
                    "retransmissions": _form_integer(form, "retransmissions"),
                }
            elif protocol == "smb":
                config = {
                    "kind": "smb",
                    "server": form.get("server", ""),
                    "share": form.get("remote_resource", ""),
                    "dialect": form.get("dialect", "3.1.1"),
                }
            else:
                raise ValueError("protocol")
            candidate = CreateShareRequestV1(
                share_id=form.get("share_id", ""),
                display_name=form.get("display_name", ""),
                config=config,
                auto_connect=True,
            )
            created = daemon_client.create_network_share(
                candidate, form["idempotency_key"], **daemon_kwargs(user)
            )
        except FormFieldValueError as exc:
            return management_error_response(
                user,
                "Invalid share configuration.",
                status_code=422,
                template_name="share_detail.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                share=None,
                form_values=safe_values,
                field_errors={exc.field: "Invalid value."},
                error_action="create",
                create_protocol=form.get("protocol", "nfs"),
                share_options=share_options,
            )
        except (ValidationError, ValueError) as exc:
            field_errors = (
                _pydantic_field_errors(
                    exc,
                    aliases={
                        "export": "remote_resource",
                        "share": "remote_resource",
                        "version": "nfs_version",
                    },
                    fallback="protocol",
                )
                if isinstance(exc, ValidationError)
                else {"protocol": "Invalid value."}
            )
            return management_error_response(
                user,
                "Invalid share configuration.",
                status_code=422,
                template_name="share_detail.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                share=None,
                form_values=safe_values,
                field_errors=field_errors,
                error_action="create",
                create_protocol=form.get("protocol", "nfs"),
                share_options=share_options,
            )
        except DaemonRequestError as exc:
            fields = {
                "share_already_exists": "share_id",
                "share_endpoint_not_allowed": "server",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return management_error_response(
                    user,
                    "Share creation rejected.",
                    status_code=(
                        exc.status_code if 400 <= exc.status_code < 500 else 503
                    ),
                    template_name="share_detail.html",
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    share=None,
                    form_values=safe_values,
                    field_errors={fields[exc.error_code]: "Invalid value."},
                    error_action="create",
                    create_protocol=form.get("protocol", "nfs"),
                    share_options=share_options,
                )
            return daemon_error_response(user, exc)
        except (ApiCompatibilityError, DaemonProtocolError) as exc:
            return daemon_error_response(user, exc)
        except DaemonUnavailable:
            return management_error_response(
                user,
                "Daemon unavailable. Retry the same request once.",
                status_code=503,
                template_name="share_detail.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form["idempotency_key"],
                share=None,
                form_values=safe_values,
                field_errors={"request": "Outcome unavailable."},
                error_action="create",
                create_protocol=form.get("protocol", "nfs"),
                share_options=share_options,
            )
        return RedirectResponse(f"/shares/{created.share_id}", status_code=303)

    @app.get("/shares/{share_id}/status-fragment", response_class=HTMLResponse)
    async def share_status_fragment(share_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, _csrf = resolved
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        try:
            summary = next(
                item
                for item in daemon_client.list_network_shares(**daemon_kwargs(user))
                if item.share_id == share_id
            )
        except StopIteration:
            return management_error_response(
                user, "Share unavailable.", status_code=404
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "partials/share_status.html",
            share=ShareSummaryView.from_model(summary),
            compact=request.query_params.get("view") == "list",
        )

    @app.get("/shares/{share_id}", response_class=HTMLResponse)
    async def share_detail(share_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        return share_detail_response(user, csrf_token, share_id)

    @app.post("/shares/{share_id}/update-preview")
    async def preview_share_update(share_id: str, request: Request) -> Response:
        parsed = await share_preview_form(
            request,
            {
                "csrf",
                "expected_revision",
                "display_name",
                "protocol",
                "server",
                "remote_resource",
                "nfs_version",
                "timeout_seconds",
                "retransmissions",
                "dialect",
                "lifecycle",
            },
        )
        if isinstance(parsed, Response):
            return parsed
        user, form = parsed
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        form_values = _share_safe_form_values(form)
        try:
            current = daemon_client.get_network_share(share_id, **daemon_kwargs(user))
            expected_revision = _form_integer(form, "expected_revision")
            if expected_revision != current.revision:
                raise FormFieldValueError("expected_revision")
            if current.observed_state != "disconnected":
                raise FormFieldValueError("protocol")
            protocol = form.get("protocol", "")
            if protocol not in {"nfs", "smb"}:
                raise FormFieldValueError("protocol")
        except FormFieldValueError as exc:
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Invalid change preview.",
                status_code=422,
                form_values=form_values,
                field_errors={exc.field: "Invalid value."},
                error_action="update",
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        if protocol != current.protocol:
            form_values["remote_resource"] = ""
            for field in (
                "nfs_version",
                "timeout_seconds",
                "retransmissions",
                "dialect",
            ):
                form_values.pop(field, None)
        form_values["protocol"] = protocol
        return share_detail_response(
            user,
            form.get("csrf", ""),
            share_id,
            form_values=form_values,
            preview_ready=True,
        )

    @app.post("/shares/{share_id}/update")
    async def update_share(share_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "display_name",
                "protocol",
                "server",
                "remote_resource",
                "nfs_version",
                "timeout_seconds",
                "retransmissions",
                "dialect",
                "lifecycle",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        preview_ready = False
        try:
            current = daemon_client.get_network_share(share_id, **daemon_kwargs(user))
            preview_ready = current.observed_state == "disconnected"
            protocol = form.get("protocol", current.protocol)
            if (
                current.observed_state != "disconnected"
                and protocol != current.protocol
            ):
                raise FormFieldValueError("protocol")
            if protocol == "nfs":
                config = {
                    "kind": "nfs",
                    "server": form.get("server", ""),
                    "export": form.get("remote_resource", ""),
                    "version": form.get("nfs_version", "4.2"),
                    "timeout_seconds": _form_integer(form, "timeout_seconds"),
                    "retransmissions": _form_integer(form, "retransmissions"),
                }
            elif protocol == "smb":
                config = {
                    "kind": "smb",
                    "server": form.get("server", ""),
                    "share": form.get("remote_resource", ""),
                    "dialect": form.get("dialect", "3.1.1"),
                }
            else:
                raise FormFieldValueError("protocol")
            normalized_config = CreateShareRequestV1(
                share_id=current.share_id,
                display_name=current.display_name,
                config=config,
            ).config
            requested_name = form.get("display_name", "").strip()
            requested_lifecycle = form.get("lifecycle", "active")
            candidate = UpdateShareRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                display_name=(
                    requested_name if requested_name != current.display_name else None
                ),
                config=(
                    normalized_config if normalized_config != current.config else None
                ),
                auto_connect=None,
                lifecycle=(
                    requested_lifecycle
                    if requested_lifecycle != current.lifecycle
                    else None
                ),
            )
            daemon_client.update_network_share(
                share_id, candidate, form["idempotency_key"], **daemon_kwargs(user)
            )
        except FormFieldValueError as exc:
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Invalid share change.",
                status_code=422,
                form_values=_share_safe_form_values(form),
                field_errors={exc.field: "Invalid value."},
                error_action="update",
                idempotency_key=form.get("idempotency_key"),
                preview_ready=preview_ready,
            )
        except (ValidationError, ValueError) as exc:
            field_errors = (
                _pydantic_field_errors(
                    exc,
                    aliases={
                        "export": "remote_resource",
                        "share": "remote_resource",
                        "version": "nfs_version",
                    },
                    fallback="protocol",
                )
                if isinstance(exc, ValidationError)
                else {"protocol": "Invalid value."}
            )
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Invalid share change.",
                status_code=422,
                form_values=_share_safe_form_values(form),
                field_errors=field_errors,
                error_action="update",
                idempotency_key=form.get("idempotency_key"),
                preview_ready=preview_ready,
            )
        except DaemonUnavailable:
            return share_ambiguous_retry_response(
                user,
                csrf_token=form.get("csrf", ""),
                share_id=share_id,
                action_url=f"/shares/{share_id}/update",
                idempotency_key=form["idempotency_key"],
                retry_fields={
                    key: value
                    for key, value in form.items()
                    if key not in {"csrf", "idempotency_key"}
                },
            )
        except DaemonRequestError as exc:
            fields = {
                "share_endpoint_not_allowed": "server",
                "share_revision_conflict": "expected_revision",
                "share_connected": "protocol",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return share_detail_response(
                    user,
                    form.get("csrf", ""),
                    share_id,
                    error="Share change rejected.",
                    status_code=(
                        exc.status_code if 400 <= exc.status_code < 500 else 503
                    ),
                    form_values=_share_safe_form_values(form),
                    field_errors={fields[exc.error_code]: "Invalid value."},
                    error_action="update",
                    idempotency_key=str(uuid4()),
                    preview_ready=preview_ready,
                )
            return daemon_error_response(user, exc)
        except (ApiCompatibilityError, DaemonProtocolError) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/shares/{share_id}", status_code=303)

    @app.post("/shares/{share_id}/credential")
    async def install_share_credential(share_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "username",
                "domain",
                "password",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        safe_values: dict[str, str] = {}
        try:
            candidate = ShareCredentialRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                username=form.get("username", ""),
                domain=form.get("domain") or None,
                password=form.get("password", ""),
            )
            daemon_client.install_network_share_credential(
                share_id, candidate, form["idempotency_key"], **daemon_kwargs(user)
            )
        except FormFieldValueError as exc:
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Invalid credentials.",
                status_code=422,
                form_values=safe_values,
                field_errors={exc.field: "Invalid value."},
                error_action="credential",
                idempotency_key=form.get("idempotency_key"),
            )
        except ValidationError as exc:
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Invalid credentials.",
                status_code=422,
                form_values=safe_values,
                field_errors=_pydantic_field_errors(exc, fallback="password"),
                error_action="credential",
                idempotency_key=form.get("idempotency_key"),
            )
        except DaemonRequestError as exc:
            field = {
                "share_authentication_failed": "password",
                "share_revision_conflict": "expected_revision",
                "idempotency_conflict": "idempotency_key",
            }.get(exc.error_code, "credential")
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error={
                    "share_authentication_failed": "Share authentication failed.",
                    "share_revision_conflict": "The share changed: refresh the page.",
                }.get(exc.error_code, "Credential request rejected."),
                status_code=exc.status_code if 400 <= exc.status_code < 500 else 503,
                form_values=safe_values,
                field_errors={field: "Credentials not accepted."},
                error_action="credential",
                idempotency_key=str(uuid4()),
            )
        except DaemonUnavailable:
            return share_ambiguous_retry_response(
                user,
                csrf_token=form.get("csrf", ""),
                share_id=share_id,
                action_url=f"/shares/{share_id}/credential",
                idempotency_key=form["idempotency_key"],
                retry_fields={"expected_revision": form.get("expected_revision", "")},
                credential_retry=True,
            )
        except (ApiCompatibilityError, DaemonProtocolError) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/shares/{share_id}", status_code=303)

    async def confirmed_share_action(
        share_id: str, request: Request, action: str
    ) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "expected_revision", "typed_share_id"},
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        try:
            model_type = {
                "disconnect": ShareConfirmedOperationRequestV1,
                "credential-clear": ShareCredentialClearRequestV1,
                "retire": ShareRetireRequestV1,
                "delete": ShareRemoveRequestV1,
            }[action]
            candidate = model_type(
                expected_revision=_form_integer(form, "expected_revision"),
                typed_share_id=form.get("typed_share_id", ""),
            ).confirm(share_id)
            method = {
                "disconnect": daemon_client.disconnect_network_share,
                "credential-clear": daemon_client.clear_network_share_credential,
                "retire": daemon_client.retire_network_share,
                "delete": daemon_client.remove_network_share,
            }[action]
            method(share_id, candidate, form["idempotency_key"], **daemon_kwargs(user))
        except (ValidationError, ValueError, FormFieldValueError):
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Exact share confirmation required.",
                status_code=422,
                field_errors={"typed_share_id": "Confirmation does not match."},
                error_action=action,
                idempotency_key=form.get("idempotency_key"),
            )
        except DaemonUnavailable:
            return share_ambiguous_retry_response(
                user,
                csrf_token=form.get("csrf", ""),
                share_id=share_id,
                action_url=f"/shares/{share_id}/{action.replace('-', '/')}",
                idempotency_key=form["idempotency_key"],
                retry_fields={
                    "expected_revision": form.get("expected_revision", ""),
                    "typed_share_id": form.get("typed_share_id", ""),
                },
                offer_retry=action != "disconnect",
            )
        except (ApiCompatibilityError, DaemonProtocolError, DaemonRequestError) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(
            "/shares" if action == "delete" else f"/shares/{share_id}", status_code=303
        )

    @app.post("/shares/{share_id}/credential/clear")
    async def clear_share_credential(share_id: str, request: Request) -> Response:
        return await confirmed_share_action(share_id, request, "credential-clear")

    @app.post("/shares/{share_id}/disconnect")
    async def disconnect_share(share_id: str, request: Request) -> Response:
        return await confirmed_share_action(share_id, request, "disconnect")

    @app.post("/shares/{share_id}/retire")
    async def retire_share(share_id: str, request: Request) -> Response:
        return await confirmed_share_action(share_id, request, "retire")

    @app.post("/shares/{share_id}/delete")
    async def delete_share(share_id: str, request: Request) -> Response:
        return await confirmed_share_action(share_id, request, "delete")

    async def simple_share_action(
        share_id: str, request: Request, action: str
    ) -> Response:
        parsed = await management_form(
            request, {"csrf", "idempotency_key", "expected_revision"}, admin=True
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        if not _SAFE_SHARE_ID.fullmatch(share_id):
            return management_error_response(
                user, "Invalid share identifier.", status_code=422
            )
        try:
            candidate = ShareOperationRequestV1(
                expected_revision=_form_integer(form, "expected_revision")
            )
            method = {
                "test": daemon_client.test_network_share,
                "connect": daemon_client.connect_network_share,
                "reconcile": daemon_client.reconcile_network_share,
            }[action]
            method(share_id, candidate, form["idempotency_key"], **daemon_kwargs(user))
        except (ValidationError, FormFieldValueError):
            return share_detail_response(
                user,
                form.get("csrf", ""),
                share_id,
                error="Invalid share operation.",
                status_code=422,
                field_errors={"expected_revision": "Invalid revision."},
                error_action=action,
                idempotency_key=form.get("idempotency_key"),
            )
        except DaemonUnavailable:
            return share_ambiguous_retry_response(
                user,
                csrf_token=form.get("csrf", ""),
                share_id=share_id,
                action_url=f"/shares/{share_id}/{action}",
                idempotency_key=form["idempotency_key"],
                retry_fields={"expected_revision": form.get("expected_revision", "")},
                offer_retry=action != "connect",
            )
        except (ApiCompatibilityError, DaemonProtocolError, DaemonRequestError) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/shares/{share_id}", status_code=303)

    @app.post("/shares/{share_id}/test")
    async def test_share(share_id: str, request: Request) -> Response:
        return await simple_share_action(share_id, request, "test")

    @app.post("/shares/{share_id}/connect")
    async def connect_share(share_id: str, request: Request) -> Response:
        return await simple_share_action(share_id, request, "connect")

    @app.post("/shares/{share_id}/reconcile")
    async def reconcile_share(share_id: str, request: Request) -> Response:
        return await simple_share_action(share_id, request, "reconcile")

    @app.get("/libraries", response_class=HTMLResponse)
    def libraries_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        try:
            items = tuple(
                LibraryView.from_model(item)
                for item in daemon_client.list_libraries(**daemon_kwargs(user))
            )
            share_options = selectable_share_views(user)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "libraries.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            libraries=items,
            share_options=share_options,
            form_values={},
        )

    @app.get("/libraries/status-fragment", response_class=HTMLResponse)
    def libraries_status_fragment(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, _csrf_token = resolved
        try:
            items = tuple(
                LibraryView.from_model(item)
                for item in daemon_client.list_libraries(**daemon_kwargs(user))
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render("partials/libraries_status.html", libraries=items)

    @app.post("/libraries")
    async def create_library(request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "library_id",
                "display_name",
                "source_root",
                "source_kind",
                "share_id",
                "relative_subpath",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            source_kind = form.get("source_kind", "configured_path")
            source = (
                {
                    "kind": "managed_share",
                    "share_id": form.get("share_id", ""),
                    "relative_subpath": form.get("relative_subpath", ""),
                }
                if source_kind == "managed_share"
                else None
            )
            candidate = CreateLibraryRequestV1(
                id=form.get("library_id", ""),
                display_name=form.get("display_name", ""),
                source_root=(
                    form.get("source_root", "")
                    if source_kind == "configured_path"
                    else None
                ),
                source=source,
            )
            daemon_client.create_library(
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except ValidationError as exc:
            return libraries_form_error(
                user,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Check the library identifier, name, and path.",
                status_code=422,
                form_values={
                    "library_id": form.get("library_id", ""),
                    "display_name": form.get("display_name", ""),
                    "source_root": form.get("source_root", ""),
                    "source_kind": form.get("source_kind", "configured_path"),
                    "share_id": form.get("share_id", ""),
                    "relative_subpath": form.get("relative_subpath", ""),
                },
                field_errors=_pydantic_field_errors(
                    exc,
                    aliases={"id": "library_id"},
                    fallback="display_name",
                ),
            )
        except DaemonRequestError as exc:
            fields = {
                "library_path_invalid": "source_root",
                "library_already_exists": "library_id",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return libraries_form_error(
                    user,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Library creation rejected.",
                    status_code=exc.status_code,
                    form_values={
                        "library_id": form.get("library_id", ""),
                        "display_name": form.get("display_name", ""),
                        "source_root": form.get("source_root", ""),
                        "source_kind": form.get("source_kind", "configured_path"),
                        "share_id": form.get("share_id", ""),
                        "relative_subpath": form.get("relative_subpath", ""),
                    },
                    field_errors={fields[exc.error_code]: "Invalid value."},
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/libraries/{candidate.id}", status_code=303)

    @app.get("/libraries/{library_id}", response_class=HTMLResponse)
    async def library_detail(library_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if not _SAFE_IDENTIFIER.fullmatch(library_id):
            return management_error_response(
                user, "Invalid library identifier.", status_code=422
            )
        try:
            item = daemon_client.get_library(library_id, **daemon_kwargs(user))
            shares = all_share_views(user)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "library_detail.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            library=LibraryView.from_model(item),
            share_options=tuple(
                share
                for share in shares
                if share.lifecycle == "active" and share.observed_state == "connected"
            ),
            source_share=next(
                (
                    share
                    for share in shares
                    if item.source is not None
                    and item.source.kind == "managed_share"
                    and share.share_id == item.source.share_id
                ),
                None,
            ),
            form_values={},
        )

    @app.post("/libraries/{library_id}/update")
    async def update_library(library_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "display_name",
                "source_root",
                "state",
                "source_kind",
                "share_id",
                "relative_subpath",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        if not _SAFE_IDENTIFIER.fullmatch(library_id):
            return management_error_response(
                user, "Invalid library identifier.", status_code=422
            )
        try:
            current = daemon_client.get_library(library_id, **daemon_kwargs(user))
            display_name = form.get("display_name", "").strip()
            source_root = form.get("source_root", "").strip()
            requested_state = form.get("state", "")
            source_kind = form.get(
                "source_kind",
                current.source.kind if current.source else "configured_path",
            )
            requested_source = (
                {
                    "kind": "managed_share",
                    "share_id": form.get("share_id", ""),
                    "relative_subpath": form.get("relative_subpath", ""),
                }
                if source_kind == "managed_share"
                else None
            )
            current_source_payload = (
                None if current.source is None else current.source.model_dump()
            )
            candidate = UpdateLibraryRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                display_name=(
                    display_name if display_name != current.display_name else None
                ),
                source_root=(
                    source_root
                    if source_kind == "configured_path"
                    and source_root != current.source_root
                    else None
                ),
                source=(
                    requested_source
                    if requested_source != current_source_payload
                    else None
                ),
                state=(requested_state if requested_state != current.state else None),
            )
            daemon_client.update_library(
                library_id,
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return library_detail_form_error(
                user,
                library_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid library revision.",
                status_code=422,
                form_values={
                    "display_name": form.get("display_name", ""),
                    "source_root": form.get("source_root", ""),
                    "state": form.get("state", ""),
                    "source_kind": form.get("source_kind", ""),
                    "share_id": form.get("share_id", ""),
                    "relative_subpath": form.get("relative_subpath", ""),
                },
                field_errors={exc.field: "Invalid revision."},
                error_action="update",
            )
        except ValidationError as exc:
            return library_detail_form_error(
                user,
                library_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid library change.",
                status_code=422,
                form_values={
                    "display_name": form.get("display_name", ""),
                    "source_root": form.get("source_root", ""),
                    "state": form.get("state", ""),
                },
                field_errors=_pydantic_field_errors(exc, fallback="display_name"),
                error_action="update",
            )
        except DaemonRequestError as exc:
            if exc.error_code == "library_revision_conflict":
                return library_detail_form_error(
                    user,
                    library_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The library changed: review and retry.",
                    status_code=409,
                    form_values={
                        "display_name": form.get("display_name", ""),
                        "source_root": form.get("source_root", ""),
                        "state": form.get("state", ""),
                    },
                    field_errors={"expected_revision": "Revision is no longer current."},
                    error_action="update",
                )
            fields = {
                "library_path_invalid": "source_root",
                "library_state_conflict": "state",
                "library_source_changed": "source_root",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return library_detail_form_error(
                    user,
                    library_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Library change rejected.",
                    status_code=exc.status_code,
                    form_values={
                        "display_name": form.get("display_name", ""),
                        "source_root": form.get("source_root", ""),
                        "state": form.get("state", ""),
                    },
                    field_errors={fields[exc.error_code]: "Invalid value."},
                    error_action="update",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/libraries/{library_id}", status_code=303)

    @app.post("/libraries/{library_id}/scan")
    async def scan_library(library_id: str, request: Request) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        if not _SAFE_IDENTIFIER.fullmatch(library_id):
            return management_error_response(
                user, "Invalid library identifier.", status_code=422
            )
        try:
            daemon_client.scan_library(
                library_id, form["idempotency_key"], **daemon_kwargs(user)
            )
        except DaemonRequestError as exc:
            if exc.error_code in {
                "library_state_conflict",
                "library_source_changed",
            }:
                return library_detail_form_error(
                    user,
                    library_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Library scan rejected.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={"state": "State is incompatible with scanning."},
                    error_action="scan",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/libraries/{library_id}", status_code=303)

    @app.post("/libraries/{library_id}/retire")
    async def retire_library(library_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "expected_revision", "typed_library_id"},
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            candidate = RetireLibraryRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                typed_library_id=form.get("typed_library_id", ""),
            )
            if not constant_time_matches(library_id, candidate.typed_library_id):
                raise ValueError("confirmation mismatch")
            daemon_client.retire_library(
                library_id,
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return library_detail_form_error(
                user,
                library_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid library revision.",
                status_code=422,
                form_values={},
                field_errors={exc.field: "Invalid revision."},
                error_action="retire",
            )
        except ValidationError as exc:
            return library_detail_form_error(
                user,
                library_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Exact library confirmation required.",
                status_code=422,
                form_values={},
                field_errors=_pydantic_field_errors(exc, fallback="typed_library_id"),
                error_action="retire",
            )
        except ValueError:
            return library_detail_form_error(
                user,
                library_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Exact library confirmation required.",
                status_code=422,
                form_values={},
                field_errors={"typed_library_id": "Confirmation does not match."},
                error_action="retire",
            )
        except DaemonRequestError as exc:
            if exc.error_code == "library_revision_conflict":
                return library_detail_form_error(
                    user,
                    library_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The library changed: review and retry.",
                    status_code=409,
                    form_values={},
                    field_errors={"expected_revision": "Revision is no longer current."},
                    error_action="retire",
                )
            fields = {
                "library_confirmation_mismatch": "typed_library_id",
                "library_state_conflict": "state",
                "library_in_use": "state",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return library_detail_form_error(
                    user,
                    library_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Library retirement rejected.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={fields[exc.error_code]: "Invalid action."},
                    error_action="retire",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse("/libraries", status_code=303)

    @app.get("/jobs", response_class=HTMLResponse)
    def jobs_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        try:
            query = _single_query_values(request, {"cursor", "show_retired"})
            cursor = query.get("cursor")
            show_retired_value = query.get("show_retired")
            if show_retired_value not in (None, "1"):
                raise ValueError("invalid retired job filter")
            show_retired = show_retired_value == "1"
            page = daemon_client.list_jobs(
                limit=50,
                cursor=cursor or None,
                include_retired=show_retired,
                **daemon_kwargs(user),
            )
            jobs = tuple(JobView.from_model(item) for item in page.items)
        except ValueError:
            return management_error_response(
                user, "Invalid job cursor.", status_code=422
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "jobs.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            jobs=jobs,
            next_cursor=page.next_cursor,
            current_job_id=page.current_job_id,
            show_retired=show_retired,
            cursor=cursor,
        )

    @app.get("/jobs/status-fragment", response_class=HTMLResponse)
    def jobs_status_fragment(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, _csrf_token = resolved
        try:
            query = _single_query_values(request, {"cursor", "show_retired"})
            cursor = query.get("cursor")
            show_retired_value = query.get("show_retired")
            if show_retired_value not in (None, "1"):
                raise ValueError("invalid retired job filter")
            show_retired = show_retired_value == "1"
            page = daemon_client.list_jobs(
                limit=50,
                cursor=cursor or None,
                include_retired=show_retired,
                **daemon_kwargs(user),
            )
            jobs = tuple(JobView.from_model(item) for item in page.items)
        except ValueError:
            return management_error_response(
                user, "Invalid job cursor.", status_code=422
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "partials/jobs_status.html",
            jobs=jobs,
            next_cursor=page.next_cursor,
            current_job_id=page.current_job_id,
            show_retired=show_retired,
            cursor=cursor,
        )

    @app.get("/jobs/new", response_class=HTMLResponse)
    async def new_job_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        try:
            libraries = tuple(
                LibraryView.from_model(item)
                for item in daemon_client.list_libraries(**daemon_kwargs(user))
                if item.state == "active"
            )
            profiles = daemon_client.get_media_profiles(**daemon_kwargs(user))
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "job_new.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            libraries=libraries,
            profiles=profiles,
            selected_libraries=(),
        )

    @app.post("/jobs/plans")
    async def create_job_plan(request: Request) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "media_profile"},
            {"library_ids"},
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, lists = parsed
        try:
            candidate = CreateJobPlanRequestV1(
                kind="create",
                library_ids=lists.get("library_ids", ()),
                media_profile=form.get("media_profile", ""),
            )
            plan = daemon_client.create_job_plan(
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except ValidationError as exc:
            try:
                libraries = tuple(
                    LibraryView.from_model(item)
                    for item in daemon_client.list_libraries(**daemon_kwargs(user))
                    if item.state == "active"
                )
                profiles = daemon_client.get_media_profiles(**daemon_kwargs(user))
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                ValidationError,
            ) as exc:
                return daemon_error_response(user, exc)
            return management_error_response(
                user,
                "Select at least one active library and a supported profile.",
                status_code=422,
                template_name="job_new.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                libraries=libraries,
                profiles=profiles,
                selected_libraries=lists.get("library_ids", ()),
                selected_media_profile=form.get("media_profile", ""),
                field_errors=_pydantic_field_errors(
                    exc,
                    fallback=(
                        "library_ids"
                        if not lists.get("library_ids", ())
                        else "media_profile"
                    ),
                ),
            )
        except DaemonRequestError as exc:
            fields = {
                "library_source_changed": "library_ids",
                "library_state_conflict": "library_ids",
                "idempotency_conflict": "idempotency_key",
                "validation_error": "media_profile",
            }
            if exc.error_code in fields:
                try:
                    libraries = tuple(
                        LibraryView.from_model(item)
                        for item in daemon_client.list_libraries(**daemon_kwargs(user))
                        if item.state == "active"
                    )
                    profiles = daemon_client.get_media_profiles(**daemon_kwargs(user))
                except (
                    ApiCompatibilityError,
                    DaemonProtocolError,
                    DaemonRequestError,
                    DaemonUnavailable,
                    ValidationError,
                ):
                    return daemon_error_response(user, exc)
                return management_error_response(
                    user,
                    "Estimate creation rejected: check the selection.",
                    status_code=exc.status_code,
                    template_name="job_new.html",
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    libraries=libraries,
                    profiles=profiles,
                    selected_libraries=lists.get("library_ids", ()),
                    selected_media_profile=form.get("media_profile", ""),
                    field_errors={fields[exc.error_code]: "Invalid value."},
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/plans/{plan.id}", status_code=303)

    @app.get("/jobs/plans/{plan_id}", response_class=HTMLResponse)
    async def job_plan_page(plan_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if not _SAFE_IDENTIFIER.fullmatch(plan_id):
            return management_error_response(
                user, "Invalid plan identifier.", status_code=422
            )
        try:
            plan = load_plan_view(user, plan_id)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "job_plan.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            plan=plan,
            form_values={
                "display_name": "",
                "labels": "",
                "allow_registered_reuse": False,
                "authorize_automatic_formatting": False,
            },
        )

    @app.post("/jobs/plans/{plan_id}/jobs")
    async def save_job_plan(plan_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "digest_sha256",
                "display_name",
                "labels",
                "allow_registered_reuse",
                "authorize_automatic_formatting",
            },
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, lists = parsed
        if not _SAFE_IDENTIFIER.fullmatch(plan_id):
            return management_error_response(
                user, "Invalid plan identifier.", status_code=422
            )
        allow_registered_reuse = form.get("allow_registered_reuse") == "on"
        authorize_automatic_formatting = (
            form.get("authorize_automatic_formatting") == "on"
        )
        invalid_checkbox = next(
            (
                field
                for field in (
                    "allow_registered_reuse",
                    "authorize_automatic_formatting",
                )
                if form.get(field) not in (None, "on")
            ),
            None,
        )
        if invalid_checkbox is not None:
            try:
                plan = load_plan_view(user, plan_id)
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                ValidationError,
            ) as exc:
                return daemon_error_response(user, exc)
            return management_error_response(
                user,
                "Invalid destructive authorization selection.",
                status_code=422,
                template_name="job_plan.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                plan=plan,
                form_values={
                    "display_name": form.get("display_name", ""),
                    "labels": form.get("labels", ""),
                    "allow_registered_reuse": allow_registered_reuse,
                    "authorize_automatic_formatting": authorize_automatic_formatting,
                },
                field_errors={invalid_checkbox: "Select this option only by checking it."},
            )
        if authorize_automatic_formatting and user.role != "admin":
            try:
                plan = load_plan_view(user, plan_id)
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                ValidationError,
            ) as exc:
                return daemon_error_response(user, exc)
            return management_error_response(
                user,
                "Automatic formatting authorization requires an administrator.",
                status_code=403,
                template_name="job_plan.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                plan=plan,
                form_values={
                    "display_name": form.get("display_name", ""),
                    "labels": form.get("labels", ""),
                    "allow_registered_reuse": allow_registered_reuse,
                    "authorize_automatic_formatting": True,
                },
                field_errors={
                    "authorize_automatic_formatting": "Administrator approval is required."
                },
            )
        if not authorize_automatic_formatting:
            try:
                plan = load_plan_view(user, plan_id)
                submitted_labels = tuple(
                    line.strip()
                    for line in form.get("labels", "").splitlines()
                    if line.strip()
                )
                requires_format_authority = (
                    len(submitted_labels) > len(plan.cassettes)
                    or any(cassette.operation != "append" for cassette in plan.cassettes)
                )
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                ValidationError,
            ) as exc:
                return daemon_error_response(user, exc)
            if requires_format_authority:
                return management_error_response(
                    user,
                    "Explicit administrator authorization is required before saving format rows.",
                    status_code=422,
                    template_name="job_plan.html",
                    csrf=form.get("csrf", ""),
                    idempotency_key=form.get("idempotency_key", str(uuid4())),
                    plan=plan,
                    form_values={
                        "display_name": form.get("display_name", ""),
                        "labels": form.get("labels", ""),
                        "allow_registered_reuse": allow_registered_reuse,
                        "authorize_automatic_formatting": False,
                    },
                    field_errors={
                        "authorize_automatic_formatting": (
                            "Check this authorization as an administrator to save the job."
                        )
                    },
                )
        try:
            candidate = CreateJobFromPlanRequestV1(
                digest_sha256=form.get("digest_sha256", ""),
                display_name=form.get("display_name", ""),
                labels=_parse_multiline_labels(form.get("labels", "")),
                allow_registered_reuse=allow_registered_reuse,
                authorize_automatic_formatting=authorize_automatic_formatting,
            )
            job = daemon_client.create_job_from_plan(
                plan_id,
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except ValidationError as exc:
            try:
                plan = load_plan_view(user, plan_id)
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                ValidationError,
            ) as exc:
                return daemon_error_response(user, exc)
            return management_error_response(
                user,
                "Invalid name or physical labels.",
                status_code=422,
                template_name="job_plan.html",
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                plan=plan,
                form_values={
                    "display_name": form.get("display_name", ""),
                    "labels": form.get("labels", ""),
                    "allow_registered_reuse": allow_registered_reuse,
                    "authorize_automatic_formatting": authorize_automatic_formatting,
                },
                field_errors=_pydantic_field_errors(exc, fallback="display_name"),
            )
        except DaemonRequestError as exc:
            fields = {
                "plan_digest_mismatch": "digest_sha256",
                "plan_stale": "digest_sha256",
                "plan_expired": "digest_sha256",
                "plan_consumed": "digest_sha256",
                "plan_labels_inexact": "labels",
                "plan_label_unavailable": "labels",
                "plan_label_registered": "allow_registered_reuse",
                "plan_label_identity_ambiguous": "labels",
                "plan_library_conflict": "state",
                "managed_source_evidence_changed": "state",
                "share_identity_changed": "state",
                "plan_consumption_conflict": "state",
                "automatic_format_authorization_required": "authorize_automatic_formatting",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                try:
                    fresh_plan = load_plan_view(user, plan_id)
                except (
                    ApiCompatibilityError,
                    DaemonProtocolError,
                    DaemonRequestError,
                    DaemonUnavailable,
                    ValidationError,
                ):
                    return daemon_error_response(user, exc)
                field_message = {
                    "plan_label_registered": (
                        "This label is already catalogued. Select registered-label "
                        "reuse to continue."
                    ),
                    "plan_label_identity_ambiguous": (
                        "This physical label matches multiple catalogued tapes. "
                        "Resolve duplicate catalogue identities before saving."
                    ),
                    "automatic_format_authorization_required": (
                        "Check this authorization as an administrator to save format rows."
                    ),
                }.get(exc.error_code, "Value is no longer current.")
                return management_error_response(
                    user,
                    "Plan save rejected: check the estimate.",
                    status_code=exc.status_code,
                    template_name="job_plan.html",
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    plan=fresh_plan,
                    form_values={
                        "display_name": form.get("display_name", ""),
                        "labels": form.get("labels", ""),
                        "allow_registered_reuse": allow_registered_reuse,
                        "authorize_automatic_formatting": authorize_automatic_formatting,
                    },
                    field_errors={fields[exc.error_code]: field_message},
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job.id}", status_code=303)

    @app.get("/jobs/{job_id}", response_class=HTMLResponse)
    def job_detail_page(job_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if not _SAFE_IDENTIFIER.fullmatch(job_id):
            return management_error_response(
                user, "Invalid job identifier.", status_code=422
            )
        try:
            query = _single_query_values(
                request,
                {"cassette_cursor", "manifest_cursor", "history_cursor"},
            )
            job = daemon_client.get_job(job_id, **daemon_kwargs(user))
            cassettes = daemon_client.get_job_cassettes(
                job_id,
                limit=64,
                cursor=query.get("cassette_cursor") or None,
                **daemon_kwargs(user),
            )
            manifest = daemon_client.get_job_manifest(
                job_id,
                limit=100,
                cursor=query.get("manifest_cursor") or None,
                **daemon_kwargs(user),
            )
            history = daemon_client.get_job_history(
                job_id,
                limit=100,
                cursor=query.get("history_cursor") or None,
                **daemon_kwargs(user),
            )
        except ValueError:
            return management_error_response(
                user, "Invalid job cursor.", status_code=422
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        sequence_status, sequence_status_error = load_job_sequence_status(user, job_id)
        status = load_status()[0]
        return render(
            "job_detail.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            job=JobView.from_model(
                job,
                cassettes=cassettes.items,
                sequence_status=sequence_status,
                sequence_status_error=sequence_status_error,
            ),
            cassettes=cassettes,
            manifest=manifest,
            history=history,
            manifest_cursor=query.get("manifest_cursor"),
            history_cursor=query.get("history_cursor"),
            cassette_cursor=query.get("cassette_cursor"),
            form_values={},
            operation_active=job_has_active_operation(job_id, status),
            runtime=job_runtime_context(
                JobView.from_model(job, cassettes=cassettes.items), status
            ),
        )

    @app.get("/partials/jobs/{job_id}/runtime", response_class=HTMLResponse)
    def job_runtime_fragment(job_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, csrf_token = resolved
        if not _SAFE_IDENTIFIER.fullmatch(job_id):
            return management_error_response(
                user, "Invalid job identifier.", status_code=422
            )
        try:
            query = _single_query_values(request, {"cassette_cursor", "manifest_cursor", "history_cursor"})
            job = daemon_client.get_job(job_id, **daemon_kwargs(user))
            cassettes = daemon_client.get_job_cassettes(
                job_id, limit=64, cursor=query.get("cassette_cursor") or None,
                **daemon_kwargs(user),
            )
        except ValueError:
            return management_error_response(user, "Invalid job cursor.", status_code=422)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        sequence_status, sequence_status_error = load_job_sequence_status(user, job_id)
        status = load_status()[0]
        view = JobView.from_model(
            job, cassettes=cassettes.items, sequence_status=sequence_status,
            sequence_status_error=sequence_status_error,
        )
        return render(
            "partials/job_live.html", user=user, csrf=csrf_token,
            idempotency_key=str(uuid4()), job=view, cassettes=cassettes,
            cassette_cursor=query.get("cassette_cursor"), form_values={},
            manifest_cursor=query.get("manifest_cursor"),
            history_cursor=query.get("history_cursor"),
            operation_active=job_has_active_operation(job_id, status),
            runtime=job_runtime_context(view, status),
        )

    @app.post("/jobs/{job_id}/automatic-sequence/authorize")
    async def authorize_job_sequence(job_id: str, request: Request) -> Response:
        if not _SAFE_IDENTIFIER.fullmatch(job_id):
            return JSONResponse({"error": {"code": "job_id_invalid"}}, status_code=422)
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "layout_fingerprint_sha256",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            candidate = AuthorizeAutomaticSequenceRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                layout_fingerprint_sha256=form.get("layout_fingerprint_sha256", ""),
                authorize_automatic_formatting=True,
            )
            daemon_client.authorize_automatic_sequence(
                job_id,
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except (FormFieldValueError, ValidationError):
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Sequence authorization is no longer current.",
                status_code=422,
                form_values={},
                field_errors={"state": "Refresh the job and review the current cassette sequence."},
                error_action="authorize_sequence",
            )
        except DaemonRequestError as exc:
            if exc.error_code == "idempotency_conflict":
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message=(
                        "This request key was already used for a different "
                        "authorization. Submit the authorization again with "
                        "the fresh request key shown on this page."
                    ),
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={
                        "idempotency_key": (
                            "This request key was already used; submit the "
                            "authorization again."
                        )
                    },
                    error_action="authorize_sequence",
                )
            if exc.error_code in {
                "automatic_sequence_revision_conflict",
                "automatic_sequence_layout_conflict",
                "automatic_sequence_authorization_native_only",
                "automatic_sequence_job_retired",
                "job_state_conflict",
            }:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Sequence authorization rejected; review the current job.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={"state": "Sequence authority is no longer current."},
                    error_action="authorize_sequence",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.get("/media", response_class=HTMLResponse)
    async def media_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        status, view = load_status()
        return render(
            "media.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            status=status,
            view=view,
        )

    @app.get("/catalog", response_class=HTMLResponse)
    async def catalog_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        try:
            query = _catalog_query(request)
        except ValueError:
            return management_error_response(
                user, "Invalid catalog parameters.", status_code=422
            )

        browsing = query["mode"] == "browse"
        try:
            restore_options = daemon_client.get_catalog_restore_options(
                **daemon_kwargs(user)
            )
            if browsing:
                page = daemon_client.browse_catalog(
                    library_id=query["library_id"],
                    parent_path=query["parent_path"],
                    limit=query["limit"],
                    cursor=query["browse_cursor"] or None,
                    **daemon_kwargs(user),
                )
                entries = tuple(
                    CatalogBrowseEntryView.from_model(item) for item in page.items
                )
                results = ()
                next_url = _catalog_browse_url(
                    library_id=query["library_id"],
                    parent_path=query["parent_path"],
                    limit=query["limit"],
                    cursor=page.next_cursor,
                )
                breadcrumbs = _catalog_breadcrumbs(
                    query["library_id"], query["parent_path"], query["limit"]
                )
            else:
                page = daemon_client.search_catalog(
                    q=query["q"],
                    library_id=query["library_id"] or None,
                    job_id=query["job_id"] or None,
                    cassette=query["cassette"] or None,
                    sha256=query["sha256"] or None,
                    min_size=query["min_size"],
                    max_size=query["max_size"],
                    copied_after=query["copied_after"] or None,
                    copied_before=query["copied_before"] or None,
                    include_history=query["include_history"],
                    limit=query["limit"],
                    cursor=query["cursor"] or None,
                    **daemon_kwargs(user),
                )
                entries = ()
                results = tuple(
                    CatalogFileVersionView.from_model(item) for item in page.items
                )
                next_url = _catalog_search_url(query, page.next_cursor)
                breadcrumbs = ()
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/catalog")
        return render(
            "catalog.html",
            user=user,
            csrf=csrf_token,
            catalog_mode="browse" if browsing else "search",
            query=query,
            results=results,
            entries=entries,
            breadcrumbs=breadcrumbs,
            next_url=next_url,
            browse_root_url=(
                _catalog_browse_url(
                    library_id=query["library_id"],
                    parent_path="",
                    limit=query["limit"],
                    cursor=None,
                )
                if query["library_id"]
                else None
            ),
            restore_options=restore_options,
            idempotency_key=str(uuid4()),
        )

    @app.get("/catalog/file-versions/{version_id}", response_class=HTMLResponse)
    async def catalog_file_version_page(version_id: int, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if not 1 <= version_id <= 2**63 - 1:
            return management_error_response(
                user, "Invalid version identifier.", status_code=422
            )
        try:
            restore_options = daemon_client.get_catalog_restore_options(
                **daemon_kwargs(user)
            )
            version = daemon_client.get_catalog_file_version(
                version_id, **daemon_kwargs(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/catalog")
        return render(
            "catalog.html",
            user=user,
            csrf=csrf_token,
            catalog_mode="detail",
            version=CatalogFileVersionView.from_model(version),
            restore_options=restore_options,
            idempotency_key=str(uuid4()),
        )

    @app.post("/catalog/restore-plans")
    async def create_catalog_restore_plan(request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "destination_root",
                "destination_subdirectory",
            },
            {"file_version_ids"},
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, lists = parsed
        try:
            version_ids = tuple(int(value) for value in lists["file_version_ids"])
            candidate = CreateCatalogRestorePlanRequestV1(
                file_version_ids=version_ids,
                destination_root=form.get("destination_root", ""),
                destination_subdirectory=form.get("destination_subdirectory", ""),
            )
            plan = daemon_client.create_catalog_restore_plan(
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except (KeyError, TypeError, ValueError, ValidationError):
            return management_error_response(
                user,
                "Invalid restore selection.",
                status_code=422,
                error_code="restore_plan_invalid",
                error_title="Invalid restore plan",
                error_explanation="The file selection or destination is invalid.",
                error_next_action="Return to the catalog and choose at least one version and an authorized destination.",
                error_field="file_version_ids",
                error_action="restore.plan.create",
                next_url="/catalog",
            )
        except (DaemonProtocolError, DaemonUnavailable):
            return HTMLResponse(
                templates.get_template("restore_retry.html").render(
                    user=user,
                    csrf=form["csrf"],
                    idempotency_key=form["idempotency_key"],
                    destination_root=candidate.destination_root,
                    destination_subdirectory=candidate.destination_subdirectory,
                    file_version_ids=candidate.file_version_ids,
                ),
                status_code=503,
            )
        except DaemonRequestError as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name="restore.plan.create",
                error_field=(
                    "idempotency_key"
                    if exc.error_code == "idempotency_conflict"
                    else None
                ),
                next_url="/catalog",
            )
        except ApiCompatibilityError as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name="restore.plan.create",
                next_url="/catalog",
            )
        return RedirectResponse(f"/restore-plans/{plan.id}", status_code=303)

    @app.get("/restore-plans/{plan_id}", response_class=HTMLResponse)
    async def catalog_restore_plan_page(plan_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if not _SAFE_CATALOG_JOB_ID.fullmatch(plan_id):
            return management_error_response(
                user, "Invalid plan identifier.", status_code=422
            )
        try:
            plan = daemon_client.get_catalog_restore_plan(
                plan_id, **daemon_kwargs(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/catalog")
        return render(
            "restore_plan.html",
            user=user,
            csrf=csrf_token,
            plan=plan,
            idempotency_key=str(uuid4()),
            start_error=None,
        )

    @app.post("/restore-plans/{plan_id}/runs")
    async def start_catalog_restore_run(plan_id: str, request: Request) -> Response:
        if not _SAFE_CATALOG_JOB_ID.fullmatch(plan_id):
            return JSONResponse(
                {"error": {"code": "restore_plan_id_invalid"}}, status_code=422
            )
        parsed = await management_form(request, {"csrf", "idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            run = daemon_client.start_catalog_restore_run(
                plan_id, form["idempotency_key"], **daemon_kwargs(user)
            )
        except (DaemonProtocolError, DaemonUnavailable):
            try:
                plan = daemon_client.get_catalog_restore_plan(
                    plan_id, **daemon_kwargs(user)
                )
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                ValidationError,
                ValueError,
            ) as exc:
                return daemon_error_response(user, exc, next_url="/catalog")
            return HTMLResponse(
                templates.get_template("restore_plan.html").render(
                    user=user,
                    csrf=form["csrf"],
                    plan=plan,
                    idempotency_key=form["idempotency_key"],
                    start_error="The daemon did not confirm the outcome. Replay this unchanged request to retrieve the same run.",
                ),
                status_code=503,
            )
        except DaemonRequestError as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name="restore.run.start",
                error_field=(
                    "idempotency_key"
                    if exc.error_code == "idempotency_conflict"
                    else "state"
                ),
                next_url=f"/restore-plans/{plan_id}",
            )
        except (ApiCompatibilityError, ValidationError, ValueError) as exc:
            return daemon_error_response(
                user, exc, error_action_name="restore.run.start", next_url=f"/restore-plans/{plan_id}"
            )
        return RedirectResponse(f"/restore-runs/{run.id}", status_code=303)

    def load_restore_run(user: User, run_id: str):
        if not _SAFE_CATALOG_JOB_ID.fullmatch(run_id):
            raise ValueError("invalid restore run identifier")
        return daemon_client.get_catalog_restore_run(run_id, **daemon_kwargs(user))

    @app.get("/restore-runs/{run_id}", response_class=HTMLResponse)
    async def catalog_restore_run_page(run_id: str, request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, session_cookie, csrf_token = resolved
        try:
            run = load_restore_run(user, run_id)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/catalog")
        return render(
            "restore_run.html",
            **restore_run_template_context(user, session_cookie, csrf_token, run),
        )

    @app.get("/restore-runs/{run_id}/status-fragment", response_class=HTMLResponse)
    async def catalog_restore_run_status_fragment(
        run_id: str, request: Request
    ) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, session_cookie, csrf_token = resolved
        try:
            run = load_restore_run(user, run_id)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(user, exc, next_url="/catalog")
        return render(
            "partials/restore_status.html",
            **restore_run_template_context(user, session_cookie, csrf_token, run),
        )

    async def control_catalog_restore_run(
        run_id: str,
        action: Literal["pause", "resume", "cancel"],
        request: Request,
    ) -> Response:
        if not _SAFE_CATALOG_JOB_ID.fullmatch(run_id):
            return JSONResponse(
                {"error": {"code": "restore_run_id_invalid"}}, status_code=422
            )
        parsed = await management_form(request, {"csrf", "idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        method = getattr(daemon_client, f"{action}_catalog_restore_run")
        try:
            method(run_id, form["idempotency_key"], **daemon_kwargs(user))
        except DaemonRequestError as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name=f"restore.run.{action}",
                error_field=(
                    "idempotency_key"
                    if exc.error_code == "idempotency_conflict"
                    else "state"
                ),
                next_url=f"/restore-runs/{run_id}",
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name=f"restore.run.{action}",
                next_url=f"/restore-runs/{run_id}",
            )
        return RedirectResponse(f"/restore-runs/{run_id}", status_code=303)

    @app.post("/restore-runs/{run_id}/pause")
    async def pause_catalog_restore_run(run_id: str, request: Request) -> Response:
        return await control_catalog_restore_run(run_id, "pause", request)

    @app.post("/restore-runs/{run_id}/resume")
    async def resume_catalog_restore_run(run_id: str, request: Request) -> Response:
        return await control_catalog_restore_run(run_id, "resume", request)

    @app.post("/restore-runs/{run_id}/cancel")
    async def cancel_catalog_restore_run(run_id: str, request: Request) -> Response:
        return await control_catalog_restore_run(run_id, "cancel", request)

    @app.post(
        "/restore-runs/{run_id}/items/{item_sequence}/replacement-authorizations"
    )
    async def authorize_catalog_restore_item_replacement(
        run_id: str, item_sequence: int, request: Request
    ) -> Response:
        if not _SAFE_CATALOG_JOB_ID.fullmatch(run_id) or not 1 <= item_sequence <= 200:
            return JSONResponse(
                {"error": {"code": "restore_item_invalid"}}, status_code=422
            )
        parsed = await management_form(
            request, {"csrf", "idempotency_key"}, admin=True
        )
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        evidence = session_manager.reauthentication_evidence(session_cookie)
        if evidence is None:
            return management_error_response(
                user,
                "Recent administrator reauthentication is required.",
                status_code=403,
            )
        context = WebReauthenticationContext(
            session_binding_sha256=evidence.session_binding_sha256,
            reauthenticated_at=evidence.reauthenticated_at,
        )
        try:
            receipt = auth_store.restore_replacement_authorization_receipt(
                actor_user_id=user.id,
                session_binding_sha256=evidence.session_binding_sha256,
                run_id=run_id,
                item_sequence=item_sequence,
                idempotency_key=form["idempotency_key"],
            )
            if receipt is not None and receipt.state == "complete":
                return RedirectResponse(f"/restore-runs/{run_id}", status_code=303)
            if receipt is not None and receipt.state != "pending":
                raise DomainValidationError(
                    "Restore replacement authorization requires a new request"
                )
            if receipt is None:
                issued = daemon_client.issue_catalog_restore_replacement_capability(
                    str(uuid4()),
                    **daemon_kwargs(user),
                    reauthentication_context=context,
                )
                expiry = datetime.fromisoformat(issued.expires_at.replace("Z", "+00:00"))
                if expiry.utcoffset() != UTC.utcoffset(expiry):
                    raise ValueError("replacement capability expiry must be UTC")
                receipt = auth_store.reserve_restore_replacement_authorization(
                    actor_user_id=user.id,
                    session_binding_sha256=evidence.session_binding_sha256,
                    run_id=run_id,
                    item_sequence=item_sequence,
                    idempotency_key=form["idempotency_key"],
                    capability=issued.capability,
                    expires_at=expiry.timestamp(),
                )
                if receipt.state == "complete":
                    return RedirectResponse(f"/restore-runs/{run_id}", status_code=303)
            if receipt.capability is None:
                raise DomainValidationError("Restore replacement receipt is invalid")
            authorization = daemon_client.authorize_catalog_restore_item_replacement(
                run_id,
                item_sequence,
                AuthorizeCatalogRestoreItemReplacementRequestV1(
                    capability=receipt.capability
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
                reauthentication_context=context,
            )
            auth_store.complete_restore_replacement_authorization(
                actor_user_id=user.id,
                session_binding_sha256=evidence.session_binding_sha256,
                run_id=run_id,
                item_sequence=item_sequence,
                idempotency_key=form["idempotency_key"],
                authorization_id=authorization.id,
            )
        except DaemonRequestError as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name="restore.item.replacement.authorize",
                error_field=(
                    "idempotency_key"
                    if exc.error_code == "idempotency_conflict"
                    else "state"
                ),
                next_url=f"/restore-runs/{run_id}",
            )
        except DomainValidationError as exc:
            return management_error_response(
                user,
                (
                    "Conflict with a previous request. Use the original action and target."
                    if "Idempotency key conflict" in str(exc)
                    else "The replacement authorization is no longer available; start a new request."
                ),
                status_code=409,
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
            ValidationError,
            ValueError,
        ) as exc:
            return daemon_error_response(
                user,
                exc,
                error_action_name="restore.item.replacement.authorize",
                next_url=f"/restore-runs/{run_id}",
            )
        return RedirectResponse(f"/restore-runs/{run_id}", status_code=303)

    @app.get("/diagnostics", response_class=HTMLResponse)
    async def diagnostics_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        summary = load_diagnostic_summary(user)
        if summary is None:
            return JSONResponse(
                {"error": {"code": "daemon_unavailable"}}, status_code=503
            )
        return render(
            "diagnostics.html",
            user=user,
            csrf=csrf_token,
            diagnostic=summary,
        )

    @app.get("/diagnostics/summary-fragment", response_class=HTMLResponse)
    async def diagnostics_summary_fragment(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, _csrf_token = resolved
        summary = load_diagnostic_summary(user)
        if summary is None:
            return JSONResponse(
                {"error": {"code": "daemon_unavailable"}}, status_code=503
            )
        return render("partials/diagnostics_summary.html", diagnostic=summary)

    @app.get("/settings", response_class=HTMLResponse)
    async def settings_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if user.role != "admin":
            return management_error_response(
                user,
                "Settings are available only to administrators.",
                status_code=403,
            )
        try:
            application = daemon_client.get_application_settings(**daemon_kwargs(user))
            host = daemon_client.get_host_settings(**daemon_kwargs(user))
            profiles = daemon_client.get_media_profiles(**daemon_kwargs(user))
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        return render(
            "settings.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            application=ApplicationSettingsView.from_model(application),
            host=HostSettingsView.from_model(host),
            profiles=profiles,
            form_values={},
        )

    @app.post("/settings/application")
    async def update_application_settings(request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "capacity_reserve_bytes",
                "minimum_source_file_age_seconds",
                "copy_buffer_bytes",
                "content_verification_policy",
                "source_change_detection_policy",
                "default_media_profile",
                "tape_root_directory",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            candidate = UpdateApplicationSettingsRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                capacity_reserve_bytes=_form_integer(form, "capacity_reserve_bytes"),
                minimum_source_file_age_seconds=_form_integer(
                    form, "minimum_source_file_age_seconds"
                ),
                copy_buffer_bytes=_form_integer(form, "copy_buffer_bytes"),
                content_verification_policy=form.get("content_verification_policy", ""),
                source_change_detection_policy=form.get(
                    "source_change_detection_policy"
                ),
                default_media_profile=form.get("default_media_profile", ""),
                tape_root_directory=form.get("tape_root_directory", ""),
            )
            daemon_client.update_application_settings(
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return settings_form_error(
                user,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid application settings.",
                status_code=422,
                form_values={
                    key: value
                    for key, value in form.items()
                    if key not in {"csrf", "idempotency_key", "expected_revision"}
                },
                field_errors={exc.field: "Invalid integer."},
            )
        except ValidationError as exc:
            return settings_form_error(
                user,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid application settings.",
                status_code=422,
                form_values={
                    key: value
                    for key, value in form.items()
                    if key not in {"csrf", "idempotency_key", "expected_revision"}
                },
                field_errors=_pydantic_field_errors(
                    exc, fallback="capacity_reserve_bytes"
                ),
            )
        except DaemonRequestError as exc:
            if exc.error_code == "settings_revision_conflict":
                return settings_form_error(
                    user,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The settings changed: review and retry.",
                    status_code=409,
                    form_values={
                        key: value
                        for key, value in form.items()
                        if key not in {"csrf", "idempotency_key", "expected_revision"}
                    },
                    field_errors={"expected_revision": "Revision is no longer current."},
                )
            fields = {
                "application_settings_error": "capacity_reserve_bytes",
                "validation_error": "capacity_reserve_bytes",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return settings_form_error(
                    user,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Application settings rejected.",
                    status_code=exc.status_code,
                    form_values={
                        key: value
                        for key, value in form.items()
                        if key not in {"csrf", "idempotency_key", "expected_revision"}
                    },
                    field_errors={fields[exc.error_code]: "Invalid value."},
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse("/settings", status_code=303)

    def system_logs_context(
        user: User,
        csrf_token: str,
        query: SystemLogQuery,
        page: SystemLogsPageV1 | None,
        *,
        unavailable_state: str | None = None,
    ) -> dict[str, object]:
        severity_counts = {severity.value: 0 for severity in Severity}
        source_counts = {
            source.value: 0 for source in LogSource if source is not LogSource.ALL
        }
        if page is not None:
            for entry in page.items:
                severity_counts[entry.severity.value] += entry.repeat_count
                source_counts[entry.source.value] += entry.repeat_count
        navigation = {
            "older": (
                _system_logs_url(
                    query,
                    cursor=page.older_cursor,
                    direction=LogDirection.OLDER,
                )
                if page is not None and page.older_cursor is not None
                else None
            ),
            "newer": (
                _system_logs_url(
                    query,
                    cursor=page.newer_cursor,
                    direction=LogDirection.NEWER,
                )
                if page is not None and page.newer_cursor is not None
                else None
            ),
            "newest": _system_logs_url(
                query, cursor=None, direction=LogDirection.OLDER
            ),
        }
        follow_available = bool(
            page is not None
            and page.live_supported
            and query.direction is LogDirection.OLDER
            and query.cursor is None
            and not page.cursor_rotated
        )
        return {
            "user": user,
            "csrf": csrf_token,
            "query": query,
            "page": page,
            "source_labels": _LOG_SOURCE_LABELS,
            "severity_labels": _LOG_SEVERITY_LABELS,
            "range_labels": _LOG_RANGE_LABELS,
            "direction_labels": _LOG_DIRECTION_LABELS,
            "severity_counts": severity_counts,
            "source_counts": source_counts,
            "navigation": navigation,
            "follow_available": follow_available,
            "status_fragment_url": _system_logs_status_url(query),
            "unavailable_state": unavailable_state,
        }

    def load_system_logs(
        user: User, query: SystemLogQuery
    ) -> tuple[SystemLogsPageV1 | None, str | None]:
        try:
            page = daemon_client.get_system_logs(
                source=query.source.value,
                severity=query.severity.value,
                range=query.range.value,
                direction=query.direction.value,
                cursor=query.cursor,
                search=query.search,
                limit=query.limit,
                **daemon_kwargs(user),
            )
        except ApiCompatibilityError:
            return None, "upgrade_required"
        except DaemonRequestError as exc:
            if exc.status_code == 404 and exc.error_code == "not_found":
                return None, "upgrade_required"
            return None, "unavailable"
        except (
            DaemonProtocolError,
            DaemonUnavailable,
            ValidationError,
        ):
            return None, "unavailable"
        return page, None

    @app.get("/logs", response_class=HTMLResponse)
    async def logs_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, _session_cookie, csrf_token = resolved
        try:
            query = _system_logs_query(request)
        except (ValueError, ValidationError):
            return JSONResponse(
                {"error": {"code": "logs_query_invalid"}}, status_code=422
            )
        page, unavailable_state = load_system_logs(user, query)
        response = render(
            "logs.html",
            **system_logs_context(
                user,
                csrf_token,
                query,
                page,
                unavailable_state=unavailable_state,
            ),
        )
        response.status_code = 503 if unavailable_state is not None else 200
        return response

    @app.get("/logs/status-fragment", response_class=HTMLResponse)
    async def logs_status_fragment(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, csrf_token = resolved
        try:
            query = _system_logs_query(request)
        except (ValueError, ValidationError):
            return JSONResponse(
                {"error": {"code": "logs_query_invalid"}}, status_code=422
            )
        page, unavailable_state = load_system_logs(user, query)
        response = render(
            "partials/logs_status.html",
            **system_logs_context(
                user,
                csrf_token,
                query,
                page,
                unavailable_state=unavailable_state,
            ),
        )
        response.status_code = 503 if unavailable_state is not None else 200
        return response

    @app.get("/logs/events")
    async def logs_events(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        try:
            after_id, last_event_id = _web_event_cursors(request)
        except ValueError:
            return JSONResponse(
                {"error": {"code": "invalid_log_event_query"}}, status_code=400
            )
        _user, session_cookie, csrf_cookie = resolved

        def serialized_log_events() -> Iterator[str]:
            try:
                if not session_manager.verify_csrf(session_cookie, csrf_cookie):
                    return
                for candidate in daemon_client.events(
                    after_id=after_id,
                    last_event_id=last_event_id,
                ):
                    envelope = EventEnvelopeV1.model_validate(candidate)
                    if not session_manager.verify_csrf(session_cookie, csrf_cookie):
                        return
                    yield (
                        f"id: {envelope.id}\n"
                        "event: logs.changed\n"
                        "data: {}\n\n"
                    )
                if session_manager.verify_csrf(session_cookie, csrf_cookie):
                    yield "event: stream.ready\ndata: {}\n\n"
            except (
                ApiCompatibilityError,
                DaemonProtocolError,
                DaemonRequestError,
                DaemonUnavailable,
                TypeError,
                ValueError,
                ValidationError,
            ):
                return

        return StreamingResponse(
            serialized_log_events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/users", response_class=HTMLResponse)
    async def users_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, session_cookie, csrf_token = resolved
        if user.role != "admin":
            return management_error_response(
                user,
                "User management is available only to administrators.",
                status_code=403,
            )
        return render(
            "users.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            new_idempotency_key=uuid4,
            users=auth_store.list_users(),
            format_timestamp=_format_user_timestamp,
            recently_reauthenticated=session_manager.recently_reauthenticated(
                session_cookie
            ),
            form_values={},
        )

    @app.get("/account", response_class=HTMLResponse)
    async def account_page(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse("/login", status_code=303)
        user, session_cookie, csrf_token = resolved
        return render(
            "account.html",
            user=user,
            csrf=csrf_token,
            idempotency_key=str(uuid4()),
            recently_reauthenticated=session_manager.recently_reauthenticated(
                session_cookie
            ),
        )

    @app.post("/users")
    async def create_local_user(request: Request) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "username", "role", "password"},
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        safe_values = {
            "username": form.get("username", ""),
            "role": form.get("role", "operator"),
        }
        try:
            auth_store.create_user(
                form.get("username", ""),
                form.get("password", ""),
                role=form.get("role", ""),
                actor_user_id=user.id,
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return users_form_error(
                user,
                session_cookie,
                message="Invalid user data or account already exists.",
                status_code=422,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                form_values=safe_values,
                field_errors=_domain_field_error(exc, fallback="password"),
                error_action="/users",
            )
        return RedirectResponse("/users", status_code=303)

    async def local_user_lifecycle(
        target_user_id: int,
        action: Literal["enable", "disable", "retire"],
        request: Request,
    ) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"}, admin=True)
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        kwargs = {
            "actor_user_id": user.id,
            "target_user_id": target_user_id,
            "idempotency_key": form["idempotency_key"],
            "audit_context": audit_context(request),
        }
        try:
            if action == "enable":
                auth_store.enable_user(**kwargs)
            elif action == "disable":
                auth_store.disable_user(**kwargs)
            else:
                auth_store.retire_user(**kwargs, reauthenticated_session=session_cookie)
        except DomainValidationError as exc:
            return users_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Account change rejected; check the role and reauthentication.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="state"),
                error_action=f"/users/{target_user_id}/{action}",
            )
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/{target_user_id}/enable")
    async def enable_local_user(target_user_id: int, request: Request) -> Response:
        return await local_user_lifecycle(target_user_id, "enable", request)

    @app.post("/users/{target_user_id}/disable")
    async def disable_local_user(target_user_id: int, request: Request) -> Response:
        return await local_user_lifecycle(target_user_id, "disable", request)

    @app.post("/users/{target_user_id}/retire")
    async def retire_local_user(target_user_id: int, request: Request) -> Response:
        return await local_user_lifecycle(target_user_id, "retire", request)

    @app.post("/users/{target_user_id}/role")
    async def set_local_user_role(target_user_id: int, request: Request) -> Response:
        parsed = await management_form(
            request, {"csrf", "idempotency_key", "role"}, admin=True
        )
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            auth_store.set_role(
                actor_user_id=user.id,
                target_user_id=target_user_id,
                role=form.get("role", ""),
                reauthenticated_session=session_cookie,
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return users_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Role change rejected; reauthenticate and protect the last administrator.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="role"),
                error_action=f"/users/{target_user_id}/role",
            )
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/{target_user_id}/password-reset")
    async def reset_local_password(target_user_id: int, request: Request) -> Response:
        parsed = await management_form(
            request, {"csrf", "idempotency_key", "new_password"}, admin=True
        )
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            auth_store.reset_password(
                actor_user_id=user.id,
                target_user_id=target_user_id,
                new_password=form.get("new_password", ""),
                reauthenticated_session=session_cookie,
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return users_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Credential reset rejected.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="new_password"),
                error_action=f"/users/{target_user_id}/password-reset",
            )
        return RedirectResponse("/users", status_code=303)

    @app.post("/users/{target_user_id}/sessions/revoke")
    async def revoke_local_user_sessions(
        target_user_id: int, request: Request
    ) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"}, admin=True)
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            auth_store.revoke_user_sessions(
                actor_user_id=user.id,
                target_user_id=target_user_id,
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return users_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Session revocation rejected.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="sessions"),
                error_action=f"/users/{target_user_id}/sessions/revoke",
            )
        response = RedirectResponse("/users", status_code=303)
        if target_user_id == user.id:
            _delete_web_cookies(response, settings)
        return response

    @app.post("/account/reauthenticate")
    async def reauthenticate_account(request: Request) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key", "password"})
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            accepted = session_manager.reauthenticate(
                session_cookie,
                form.get("password", ""),
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            field_errors = _domain_field_error(exc, fallback="password")
            if user.role == "admin":
                return users_form_error(
                    user,
                    session_cookie,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Reauthentication rejected.",
                    status_code=422,
                    field_errors=field_errors,
                    error_action="/account/reauthenticate",
                )
            return account_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=str(uuid4()),
                message="Reauthentication rejected.",
                status_code=422,
                field_errors=field_errors,
                error_action="/account/reauthenticate",
            )
        if not accepted:
            if user.role == "admin":
                return users_form_error(
                    user,
                    session_cookie,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Reauthentication failed.",
                    status_code=401,
                    field_errors={"password": "Invalid credential."},
                    error_action="/account/reauthenticate",
                )
            return account_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=str(uuid4()),
                message="Reauthentication failed.",
                status_code=401,
                field_errors={"password": "Invalid credential."},
                error_action="/account/reauthenticate",
            )
        target = "/users" if user.role == "admin" else "/account"
        return RedirectResponse(target, status_code=303)

    @app.post("/account/sessions/revoke")
    async def revoke_own_sessions(request: Request) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            auth_store.revoke_user_sessions(
                actor_user_id=user.id,
                target_user_id=user.id,
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return account_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Session revocation rejected.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="sessions"),
                error_action="/account/sessions/revoke",
            )
        response = RedirectResponse("/login", status_code=303)
        _delete_web_cookies(response, settings)
        return response

    @app.post("/account/password-change")
    async def change_local_password(request: Request) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "current_password", "new_password"},
        )
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            auth_store.change_password(
                user_id=user.id,
                current_password=form.get("current_password", ""),
                new_password=form.get("new_password", ""),
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return account_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Credential change rejected.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="new_password"),
                error_action="/account/password-change",
            )
        response = RedirectResponse("/login", status_code=303)
        _delete_web_cookies(response, settings)
        return response

    @app.post("/sessions/revoke-all")
    async def revoke_all_local_sessions(request: Request) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"}, admin=True)
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        try:
            auth_store.revoke_all_sessions(
                actor_user_id=user.id,
                reauthenticated_session=session_cookie,
                idempotency_key=form["idempotency_key"],
                audit_context=audit_context(request),
            )
        except DomainValidationError as exc:
            return users_form_error(
                user,
                session_cookie,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Global revocation rejected; reauthenticate.",
                status_code=422,
                field_errors=_domain_field_error(exc, fallback="sessions"),
                error_action="/sessions/revoke-all",
            )
        response = RedirectResponse("/login", status_code=303)
        _delete_web_cookies(response, settings)
        return response

    @app.post("/jobs/{job_id}/resume")
    async def resume_job(job_id: str, request: Request) -> Response:
        if not _SAFE_IDENTIFIER.fullmatch(job_id):
            return JSONResponse(
                {"error": {"code": "job_id_invalid"}},
                status_code=422,
            )
        parsed = await management_form(
            request, {"csrf", "idempotency_key", "format_confirmation_label", "password"}
        )
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        wants_json = request.headers.get("accept") == "application/json"

        def password_error(code: str, message: str) -> Response:
            if wants_json:
                return JSONResponse({"error": {"code": code, "message": message}}, status_code=401)
            return job_detail_form_error(
                user, job_id, csrf=form.get("csrf", ""),
                idempotency_key=form["idempotency_key"], message=message,
                status_code=401, form_values={}, field_errors={"password": message},
                error_action="resume",
            )

        try:
            if form.get("format_confirmation_label"):
                JobCommandRequestV1(
                    format_confirmation_label=form["format_confirmation_label"]
                )
            job = daemon_client.get_job(job_id, **daemon_kwargs(user))
            # Read the authoritative pause markers, never a submitted state.
            # Waiting for the next cassette alone is not a deliberate pause.
            if job.pause_requested or job.pause_acknowledged:
                password = form.pop("password", "")
                if not password:
                    return password_error("resume_password_required", "Enter your password to resume this deliberately paused job.")
                try:
                    accepted = session_manager.reauthenticate(
                        session_cookie, password, audit_context=audit_context(request),
                    )
                finally:
                    password = ""
                if not accepted:
                    return password_error("resume_password_invalid", "Password not accepted. Check it or wait before trying again.")
            daemon_client.resume_job(
                job_id,
                JobCommandRequestV1(
                    format_confirmation_label=(
                        form.get("format_confirmation_label") or None
                        if job.imported
                        else None
                    )
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except ValidationError:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid label confirmation.",
                status_code=422,
                form_values={
                    "format_confirmation_label": form.get(
                        "format_confirmation_label", ""
                    )
                },
                field_errors={"format_confirmation_label": "Invalid label."},
                error_action="resume",
            )
        except DaemonRequestError as exc:
            if wants_json:
                return JSONResponse({"error": {
                    "code": "resume_rejected",
                    "message": "Resume was rejected by the daemon. Check the job status and recovery warnings.",
                }}, status_code=exc.status_code)
            if exc.error_code in {
                "format_confirmation_required",
                "format_confirmation_mismatch",
            }:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Label confirmation rejected.",
                    status_code=exc.status_code,
                    form_values={
                        "format_confirmation_label": form.get(
                            "format_confirmation_label", ""
                        )
                    },
                    field_errors={"format_confirmation_label": "Invalid label."},
                    error_action="resume",
                )
            if exc.error_code in {"job_state_conflict", "job_imported_frozen"}:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Start or resume is not allowed in the current state.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={"state": "Job state is incompatible."},
                    error_action="resume",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            if wants_json:
                return JSONResponse({"error": {
                    "code": "resume_unconfirmed",
                    "message": "Resume could not be confirmed. Check the job status before retrying.",
                }}, status_code=503)
            return daemon_error_response(user, exc)
        if wants_json:
            return JSONResponse({"redirect": f"/jobs/{job_id}"})
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/failed-cassette/reset")
    async def reset_failed_cassette(job_id: str, request: Request) -> Response:
        if not _SAFE_IDENTIFIER.fullmatch(job_id):
            return JSONResponse(
                {"error": {"code": "job_id_invalid"}}, status_code=422
            )
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "cassette_sequence",
                "typed_physical_label",
            },
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            candidate = ResetFailedCassetteRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                cassette_sequence=_form_integer(form, "cassette_sequence"),
                typed_physical_label=form.get("typed_physical_label", ""),
            )
            daemon_client.reset_failed_cassette(
                job_id,
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except (FormFieldValueError, ValidationError):
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Cassette reset confirmation is invalid.",
                status_code=422,
                form_values={},
                field_errors={"typed_physical_label": "Enter the exact physical label."},
                error_action="reset_failed_cassette",
            )
        except DaemonRequestError as exc:
            field = (
                "typed_physical_label"
                if exc.error_code == "job_confirmation_mismatch"
                else "state"
            )
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=str(uuid4()),
                message="Cassette reset was rejected.",
                status_code=exc.status_code,
                form_values={},
                field_errors={field: "Refresh the job and confirm the failed cassette."},
                error_action="reset_failed_cassette",
            )
        except (ApiCompatibilityError, DaemonProtocolError, DaemonUnavailable) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/start")
    async def start_saved_job(job_id: str, request: Request) -> Response:
        parsed = await management_form(
            request, {"csrf", "idempotency_key", "format_confirmation_label"}
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            if form.get("format_confirmation_label"):
                JobCommandRequestV1(
                    format_confirmation_label=form["format_confirmation_label"]
                )
            job = daemon_client.get_job(job_id, **daemon_kwargs(user))
            daemon_client.start_job(
                job_id,
                JobCommandRequestV1(
                    format_confirmation_label=(
                        form.get("format_confirmation_label") or None
                        if job.imported
                        else None
                    )
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except ValidationError:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid label confirmation.",
                status_code=422,
                form_values={
                    "format_confirmation_label": form.get(
                        "format_confirmation_label", ""
                    )
                },
                field_errors={"format_confirmation_label": "Invalid label."},
                error_action="start",
            )
        except DaemonRequestError as exc:
            if exc.error_code in {
                "format_confirmation_required",
                "format_confirmation_mismatch",
            }:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Label confirmation rejected.",
                    status_code=exc.status_code,
                    form_values={
                        "format_confirmation_label": form.get(
                            "format_confirmation_label", ""
                        )
                    },
                    field_errors={"format_confirmation_label": "Invalid label."},
                    error_action="start",
                )
            if exc.error_code in {"job_state_conflict", "job_imported_frozen"}:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Start is not allowed in the current state.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={"state": "Job state is incompatible."},
                    error_action="start",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/pause")
    async def pause_saved_job(job_id: str, request: Request) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            daemon_client.pause_job(
                job_id, form["idempotency_key"], **daemon_kwargs(user)
            )
        except DaemonRequestError as exc:
            if exc.error_code in {"job_state_conflict", "job_imported_frozen"}:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Pause is not allowed in the current state.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={"state": "Job state is incompatible."},
                    error_action="pause",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/update")
    async def update_saved_job(job_id: str, request: Request) -> Response:
        parsed = await management_form(
            request, {"csrf", "idempotency_key", "expected_revision", "display_name"}
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            daemon_client.update_job(
                job_id,
                UpdateJobRequestV1(
                    expected_revision=_form_integer(form, "expected_revision"),
                    display_name=form.get("display_name", ""),
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid job revision.",
                status_code=422,
                form_values={"display_name": form.get("display_name", "")},
                field_errors={exc.field: "Invalid revision."},
                error_action="update",
            )
        except ValidationError as exc:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid job name.",
                status_code=422,
                form_values={"display_name": form.get("display_name", "")},
                field_errors=_pydantic_field_errors(exc, fallback="display_name"),
                error_action="update",
            )
        except DaemonRequestError as exc:
            if exc.error_code == "job_revision_conflict":
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The job changed: review and retry.",
                    status_code=409,
                    form_values={"display_name": form.get("display_name", "")},
                    field_errors={"expected_revision": "Revision is no longer current."},
                    error_action="update",
                )
            fields = {
                "job_state_conflict": "state",
                "job_imported_frozen": "state",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Job rename rejected.",
                    status_code=exc.status_code,
                    form_values={"display_name": form.get("display_name", "")},
                    field_errors={fields[exc.error_code]: "Invalid action."},
                    error_action="update",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/incremental-policy")
    async def update_job_incremental_policy(job_id: str, request: Request) -> Response:
        parsed = await management_form(
            request, {"csrf","idempotency_key","expected_revision","cadence"}
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            daemon_client.update_incremental_policy(
                job_id,
                UpdateIncrementalPolicyRequestV1(
                    cadence=form.get("cadence", ""),
                    expected_revision=_form_integer(form, "expected_revision"),
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except (ValidationError, FormFieldValueError) as exc:
            field = exc.field if isinstance(exc, FormFieldValueError) else "cadence"
            return job_detail_form_error(
                user,job_id,csrf=form.get("csrf", ""),idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Incremental policy is invalid.",status_code=422,
                form_values={"cadence": form.get("cadence", "")},
                field_errors={field: "Select one supported cadence."},
                error_action="incremental-policy")
        except DaemonRequestError as exc:
            if exc.error_code in {"job_revision_conflict","job_state_conflict","job_imported_frozen","idempotency_conflict"}:
                return job_detail_form_error(
                    user,job_id,csrf=form.get("csrf", ""),idempotency_key=str(uuid4()),
                    message="Incremental policy update was rejected.",status_code=exc.status_code,
                    form_values={"cadence": form.get("cadence", "")},
                    field_errors={"expected_revision": "The job changed; review and retry."},
                    error_action="incremental-policy")
            return daemon_error_response(user, exc)
        except (ApiCompatibilityError,DaemonProtocolError,DaemonUnavailable) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/incremental-scan")
    async def scan_job_incrementally(job_id: str, request: Request) -> Response:
        parsed = await management_form(request, {"csrf","idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            daemon_client.scan_job_now(
                job_id, form["idempotency_key"], **daemon_kwargs(user)
            )
        except DaemonRequestError as exc:
            if exc.error_code in {"job_state_conflict","job_imported_frozen","incremental_scan_busy"}:
                return job_detail_form_error(
                    user,job_id,csrf=form.get("csrf", ""),idempotency_key=str(uuid4()),
                    message="Incremental scan is not available now.",status_code=exc.status_code,
                    form_values={},field_errors={"state": "Complete or recover the current epoch first."},
                    error_action="incremental-scan")
            return daemon_error_response(user, exc)
        except (ApiCompatibilityError,DaemonProtocolError,DaemonUnavailable) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/reserve-labels")
    async def reserve_saved_job_labels(job_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "expected_revision", "labels", "authorize_automatic_formatting"},
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        attempted_labels = form.get("labels", "")
        if form.get("authorize_automatic_formatting") != "on" or user.role != "admin":
            return job_detail_form_error(
                user, job_id, csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Adding format reserves requires explicit administrator authorization.",
                status_code=403 if user.role != "admin" else 422,
                form_values={"labels": attempted_labels, "authorize_automatic_formatting": False},
                field_errors={"authorize_automatic_formatting": "Check this authorization as an administrator."},
                error_action="reserve-labels",
            )
        try:
            daemon_client.reserve_job_labels(
                job_id,
                ReserveJobLabelsRequestV1(
                    expected_revision=_form_integer(form, "expected_revision"),
                    labels=_parse_multiline_labels(attempted_labels),
                    authorize_automatic_formatting=True,
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid job revision.",
                status_code=422,
                form_values={"labels": attempted_labels},
                field_errors={exc.field: "Invalid revision."},
                error_action="reserve-labels",
            )
        except ValidationError as exc:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid reserve labels.",
                status_code=422,
                form_values={"labels": attempted_labels},
                field_errors=_pydantic_field_errors(exc, fallback="labels"),
                error_action="reserve-labels",
            )
        except DaemonRequestError as exc:
            if exc.error_code == "job_revision_conflict":
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The job changed: review and retry.",
                    status_code=409,
                    form_values={"labels": attempted_labels},
                    field_errors={"expected_revision": "Revision is no longer current."},
                    error_action="reserve-labels",
                )
            fields = {
                "job_state_conflict": "state",
                "job_imported_frozen": "state",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Label reservation rejected.",
                    status_code=exc.status_code,
                    form_values={"labels": attempted_labels},
                    field_errors={fields[exc.error_code]: "Invalid action."},
                    error_action="reserve-labels",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/extension-plan")
    async def create_extension_plan(job_id: str, request: Request) -> Response:
        parsed = await management_form(request, {"csrf", "idempotency_key"})
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            plan = daemon_client.create_job_plan(
                CreateJobPlanRequestV1(kind="extend", base_job_id=job_id),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except DaemonRequestError as exc:
            if exc.error_code in {"job_state_conflict", "job_imported_frozen"}:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Extension is not allowed in the current state.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={"state": "Job state is incompatible."},
                    error_action="extension-plan",
                )
            return daemon_error_response(user, exc)
        except ValidationError:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=str(uuid4()),
                message="Invalid job identifier.",
                status_code=422,
                form_values={},
                field_errors={"job_id": "Invalid identifier."},
                error_action="extension-plan",
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/plans/{plan.id}", status_code=303)

    @app.post("/jobs/{job_id}/extend")
    async def extend_saved_job(job_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "expected_revision",
                "plan_id",
                "digest_sha256",
                "authorize_automatic_formatting",
            },
            {"labels"},
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, lists = parsed
        raw_extension_authority = form.get("authorize_automatic_formatting")
        if raw_extension_authority not in (None, "on"):
            return plan_form_error(
                user, form.get("plan_id", ""), csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid destructive authorization selection.", status_code=422,
                labels=lists.get("labels", ()),
                field_errors={"authorize_automatic_formatting": "Select this option only by checking it."},
            )
        extension_authority = raw_extension_authority == "on"
        try:
            plan = load_plan_view(user, form.get("plan_id", ""))
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
            ValidationError,
        ) as exc:
            return daemon_error_response(user, exc)
        if plan.requires_automatic_format_authorization and user.role != "admin":
            return plan_form_error(
                user, form.get("plan_id", ""), csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Automatic formatting authorization requires an administrator.", status_code=403,
                labels=lists.get("labels", ()),
                field_errors={"authorize_automatic_formatting": "Administrator approval is required."},
                authorize_automatic_formatting=extension_authority,
            )
        if plan.requires_automatic_format_authorization and not extension_authority:
            return plan_form_error(
                user, form.get("plan_id", ""), csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Automatic formatting authorization is required.", status_code=422,
                labels=lists.get("labels", ()),
                field_errors={"authorize_automatic_formatting": "Administrator authorization is required."},
            )
        if extension_authority and user.role != "admin":
            return plan_form_error(
                user, form.get("plan_id", ""), csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Automatic formatting authorization requires an administrator.", status_code=403,
                labels=lists.get("labels", ()),
                field_errors={"authorize_automatic_formatting": "Administrator approval is required."},
                authorize_automatic_formatting=True,
            )
        try:
            daemon_client.extend_job(
                job_id,
                ExtendJobRequestV1(
                    expected_revision=_form_integer(form, "expected_revision"),
                    plan_id=form.get("plan_id", ""),
                    digest_sha256=form.get("digest_sha256", ""),
                    labels=lists.get("labels", ()),
                    authorize_automatic_formatting=extension_authority,
                ),
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return plan_form_error(
                user,
                form.get("plan_id", ""),
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid job revision.",
                status_code=422,
                labels=lists.get("labels", ()),
                field_errors={exc.field: "Invalid revision."},
                authorize_automatic_formatting=extension_authority,
            )
        except ValidationError as exc:
            return plan_form_error(
                user,
                form.get("plan_id", ""),
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid extension plan.",
                status_code=422,
                labels=lists.get("labels", ()),
                field_errors=_pydantic_field_errors(exc, fallback="labels"),
                authorize_automatic_formatting=extension_authority,
            )
        except DaemonRequestError as exc:
            if exc.error_code in {
                "job_revision_conflict",
                "plan_stale",
                "plan_digest_mismatch",
                "plan_expired",
                "plan_consumed",
                "automatic_format_authorization_required",
            }:
                field = (
                    "expected_revision"
                    if exc.error_code == "job_revision_conflict"
                    else "authorize_automatic_formatting"
                    if exc.error_code == "automatic_format_authorization_required"
                    else "digest_sha256"
                )
                return plan_form_error(
                    user,
                    form.get("plan_id", ""),
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The job or plan changed: review and retry.",
                    status_code=409,
                    labels=lists.get("labels", ()),
                    field_errors={field: "Value is no longer current."},
                    authorize_automatic_formatting=extension_authority,
                )
            if exc.error_code in {"job_state_conflict", "job_imported_frozen"}:
                return plan_form_error(
                    user,
                    form.get("plan_id", ""),
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Extension is not allowed in the current state.",
                    status_code=exc.status_code,
                    labels=lists.get("labels", ()),
                    field_errors={"state": "Job state is incompatible."},
                    authorize_automatic_formatting=extension_authority,
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/{job_id}/retire")
    async def retire_saved_job(job_id: str, request: Request) -> Response:
        parsed = await management_form(
            request,
            {"csrf", "idempotency_key", "expected_revision", "typed_job_id"},
            admin=True,
        )
        if isinstance(parsed, Response):
            return parsed
        user, _session_cookie, form, _lists = parsed
        try:
            candidate = RetireJobRequestV1(
                expected_revision=_form_integer(form, "expected_revision"),
                typed_job_id=form.get("typed_job_id", ""),
            )
            if not constant_time_matches(job_id, candidate.typed_job_id):
                raise ValueError("confirmation mismatch")
            daemon_client.retire_job(
                job_id,
                candidate,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except FormFieldValueError as exc:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Invalid job revision.",
                status_code=422,
                form_values={},
                field_errors={exc.field: "Invalid revision."},
                error_action="retire",
            )
        except ValidationError as exc:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Exact job confirmation required.",
                status_code=422,
                form_values={},
                field_errors=_pydantic_field_errors(exc, fallback="typed_job_id"),
                error_action="retire",
            )
        except ValueError:
            return job_detail_form_error(
                user,
                job_id,
                csrf=form.get("csrf", ""),
                idempotency_key=form.get("idempotency_key", str(uuid4())),
                message="Exact job confirmation required.",
                status_code=422,
                form_values={},
                field_errors={"typed_job_id": "Confirmation does not match."},
                error_action="retire",
            )
        except DaemonRequestError as exc:
            if exc.error_code == "job_revision_conflict":
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="The job changed: review and retry.",
                    status_code=409,
                    form_values={},
                    field_errors={"expected_revision": "Revision is no longer current."},
                    error_action="retire",
                )
            fields = {
                "job_confirmation_mismatch": "typed_job_id",
                "job_state_conflict": "state",
                "job_imported_frozen": "state",
                "idempotency_conflict": "idempotency_key",
            }
            if exc.error_code in fields:
                return job_detail_form_error(
                    user,
                    job_id,
                    csrf=form.get("csrf", ""),
                    idempotency_key=str(uuid4()),
                    message="Job retirement rejected.",
                    status_code=exc.status_code,
                    form_values={},
                    field_errors={fields[exc.error_code]: "Invalid action."},
                    error_action="retire",
                )
            return daemon_error_response(user, exc)
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return RedirectResponse(f"/jobs/{job_id}", status_code=303)

    @app.post("/jobs/native")
    async def create_native_job(request: Request) -> Response:
        parsed = await mutation_form(
            request,
            {
                "csrf",
                "idempotency_key",
                "display_name",
                "labels",
                "expected_job_id",
                "typed_job_id",
            },
        )
        if isinstance(parsed, JSONResponse):
            return parsed
        user, form = parsed
        display_name = form.get("display_name", "").strip()
        expected_job_id = form.get("expected_job_id", "")
        typed_job_id = form.get("typed_job_id", "")
        labels = [
            line.strip().upper()
            for line in form.get("labels", "").splitlines()
            if line.strip()
        ]
        if (
            not display_name
            or len(display_name) > 120
            or any(ord(character) < 32 for character in display_name)
            or not _SAFE_IDENTIFIER.fullmatch(expected_job_id)
            or not _SAFE_IDENTIFIER.fullmatch(typed_job_id)
            or not constant_time_matches(expected_job_id, typed_job_id)
            or not 1 <= len(labels) <= 64
            or len(set(labels)) != len(labels)
            or any(not re.fullmatch(r"[A-Z0-9]{6}", label) for label in labels)
        ):
            return JSONResponse(
                {"error": {"code": "native_job_reset_invalid"}}, status_code=422
            )
        return forward_mutation(
            user=user,
            csrf_token=form["csrf"],
            path="/api/v1/jobs/native",
            payload={
                "display_name": display_name,
                "labels": labels,
                "expected_job_id": expected_job_id,
                "typed_job_id": typed_job_id,
            },
            idempotency_key=form["idempotency_key"],
        )

    @app.get("/operations/{operation_id}/recovery", response_class=HTMLResponse)
    async def pre_media_recovery_page(operation_id: str, request: Request) -> Response:
        if not _SAFE_IDENTIFIER.fullmatch(operation_id):
            return management_error_response(
                None, "Invalid operation identifier.", status_code=422
            )
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse(f"/login?next=/operations/{operation_id}/recovery", status_code=303)
        user, _session_cookie, csrf_token = resolved
        if user.role != "admin":
            return management_error_response(
                user, "Operation allowed only for administrators.", status_code=403
            )
        # Old Dashboard/bookmark links must follow the current recovery mode,
        # never call the pre-media reset endpoint for a critical quarantine.
        status, _view = load_status()
        if (
            status is not None and status.critical_recovery is not None
            and status.critical_recovery.operation_id == operation_id
        ):
            return RedirectResponse(f"/critical-recovery/{operation_id}", status_code=303)
        try:
            proof = daemon_client.get_pre_media_reset(operation_id, **daemon_kwargs(user))
        except (
            ApiCompatibilityError, DaemonProtocolError, DaemonRequestError,
            DaemonUnavailable, ValidationError,
        ) as exc:
            return management_error_response(
                user,
                "Reset is unavailable for this operation. Review its current recovery status.",
                status_code=exc.status_code if isinstance(exc, DaemonRequestError) else 503,
                error_next_action="Return to the dashboard and review the blocker before taking another action.",
            )
        return render(
            "pre_media_reset.html", user=user, csrf=csrf_token, proof=proof,
            idempotency_key=str(uuid4()), reset_complete=False,
        )

    @app.post("/operations/{operation_id}/recovery", response_class=HTMLResponse)
    async def reset_pre_media_attempt_web(operation_id: str, request: Request) -> Response:
        fields = {
            "csrf", "idempotency_key", "password", "operation_id", "job_id",
            "cassette_sequence", "daemon_generation", "command_ledger_sha256",
            "mount_path_sha256", "tape_device_identity_sha256",
            "scsi_device_identity_sha256", "expected_media_scope_sha256",
        }
        parsed = await management_form(request, fields, admin=True)
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        if (
            not _SAFE_IDENTIFIER.fullmatch(operation_id)
            or not constant_time_matches(form.get("operation_id", ""), operation_id)
        ):
            return management_error_response(
                user, "Operation proof does not match.", status_code=422
            )
        try:
            reset_request = ResetPreMediaAttemptRequestV1.model_validate({
                "operation_id": operation_id,
                "job_id": form.get("job_id", ""),
                "cassette_sequence": form.get("cassette_sequence", ""),
                "daemon_generation": form.get("daemon_generation", ""),
                "command_ledger_sha256": form.get("command_ledger_sha256", ""),
                "target": {
                    field: form.get(field, "")
                    for field in (
                        "mount_path_sha256", "tape_device_identity_sha256",
                        "scsi_device_identity_sha256", "expected_media_scope_sha256",
                    )
                },
            })
        except ValidationError:
            return management_error_response(
                user, "Invalid reset proof. Refresh the recovery page.", status_code=422
            )

        def password_error(message: str) -> Response:
            return management_error_response(
                user, message, status_code=401, template_name="pre_media_reset.html",
                csrf=form["csrf"], idempotency_key=form["idempotency_key"],
                proof=reset_request, reset_complete=False,
            )

        password = form.pop("password", "")
        if not password:
            return password_error("Enter your password to confirm this reset.")
        try:
            accepted = session_manager.reauthenticate(
                session_cookie, password, audit_context=audit_context(request),
            )
        finally:
            password = ""
        if not accepted:
            return password_error("Password not accepted. Check it or wait before trying again.")
        evidence = session_manager.reauthentication_evidence(session_cookie)
        if evidence is None:
            return password_error("Your confirmation expired. Enter your password again.")
        context = WebReauthenticationContext(
            session_binding_sha256=evidence.session_binding_sha256,
            reauthenticated_at=evidence.reauthenticated_at,
        )
        try:
            # Keep the reviewed snapshot: the daemon rejects stale or changed proof.
            result = daemon_client.reset_pre_media_attempt(
                operation_id, reset_request, form["idempotency_key"],
                **daemon_kwargs(user), reauthentication_context=context,
            )
            if result.id != operation_id or result.state != "failed":
                raise DaemonProtocolError("Reset outcome was not confirmed")
        except (
            ApiCompatibilityError, DaemonProtocolError, DaemonRequestError,
            DaemonUnavailable, ValidationError,
        ) as exc:
            return management_error_response(
                user,
                "Reset was not confirmed. Review the current operation and job status before retrying.",
                status_code=exc.status_code if isinstance(exc, DaemonRequestError) else 503,
                error_next_action="Open recovery again to review fresh proof. Do not assume the job can resume.",
                next_url=f"/operations/{operation_id}/recovery",
            )
        return render(
            "pre_media_reset.html", user=user, csrf=form["csrf"],
            proof=reset_request, reset_complete=True,
        )

    critical_identity_fields = {
        "csrf",
        "idempotency_key",
        "operation_id",
        "job_id",
        "cassette_sequence",
        "expected_label",
        "daemon_generation",
        "attempt_number",
        "evidence_sha256",
        "observed_media_identity_sha256",
        "mount_path_sha256",
        "tape_device_identity_sha256",
        "scsi_device_identity_sha256",
        "expected_media_scope_sha256",
    }

    def critical_access_rejection(
        request: Request,
        user: User,
        result: str,
        message: str,
    ) -> HTMLResponse:
        auth_store.record_critical_recovery_rejection(
            actor_user_id=user.id,
            result=result,
            audit_context=audit_context(request),
        )
        return management_error_response(user, message, status_code=403)

    def critical_request_from_form(
        model_type,
        form: dict[str, str],
    ):
        payload: dict[str, object] = {
            "operation_id": form.get("operation_id", ""),
            "job_id": form.get("job_id", ""),
            "cassette_sequence": _form_integer(form, "cassette_sequence"),
            "expected_label": form.get("expected_label", ""),
            "target": CriticalRecoveryTargetV1(
                mount_path_sha256=form.get("mount_path_sha256", ""),
                tape_device_identity_sha256=form.get(
                    "tape_device_identity_sha256", ""
                ),
                scsi_device_identity_sha256=form.get(
                    "scsi_device_identity_sha256", ""
                ),
                expected_media_scope_sha256=form.get(
                    "expected_media_scope_sha256", ""
                ),
            ),
            "daemon_generation": _form_integer(form, "daemon_generation"),
            "attempt_number": _form_integer(form, "attempt_number"),
            "evidence_sha256": form.get("evidence_sha256", ""),
            "observed_media_identity_sha256": (
                form.get("observed_media_identity_sha256") or None
            ),
        }
        if model_type is AuthorizeReplacementAttemptRequestV1:
            payload["typed_label_confirmation"] = form.get(
                "typed_label_confirmation", ""
            )
        return model_type.model_validate(payload)

    def critical_page_response(
        request: Request, user: User, proof, *, status_code: int = 200,
        error: str | None = None, notice: str | None = None,
        form: dict[str, str] | None = None,
    ) -> HTMLResponse:
        keys = {name: str(uuid4()) for name in (
            "reconcile_key", "abandon_key", "replacement_key"
        )}
        action_key = {
            "reconcile": "reconcile_key", "abandon": "abandon_key",
            "authorize-replacement": "replacement_key",
        }.get(request.url.path.rsplit("/", 1)[-1])
        if form and action_key:
            keys[action_key] = form["idempotency_key"]
        response = render(
            "critical_recovery.html", user=user,
            csrf=request.cookies.get(settings.csrf_cookie_name, ""),
            proof=proof, critical_recovery=proof, **keys,
            password_required=not session_manager.recently_reauthenticated(
                request.cookies.get(settings.session_cookie_name, "")
            ),
            error=error, notice=notice,
            typed_label_confirmation=(form or {}).get("typed_label_confirmation", ""),
        )
        response.status_code = status_code
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/critical-recovery/{operation_id}", response_class=HTMLResponse)
    async def critical_recovery_page(operation_id: str, request: Request) -> Response:
        if not _SAFE_IDENTIFIER.fullmatch(operation_id):
            return management_error_response(
                None, "Invalid operation identifier.", status_code=422
            )
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse(f"/login?next=/critical-recovery/{operation_id}", status_code=303)
        user, session_cookie, csrf_token = resolved
        if user.role != "admin":
            return critical_access_rejection(
                request,
                user,
                "role_denied",
                "Operation allowed only for administrators.",
            )
        try:
            proof = daemon_client.get_critical_recovery(
                operation_id, **daemon_kwargs(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc)
        return critical_page_response(
            request, user, proof,
            notice=(
                "Review the current result below. Read-only reassessment does not resume the backup."
                if request.query_params.get("review") == "reassessed" else None
            ),
        )

    async def critical_action_form(
        operation_id: str,
        request: Request,
        *,
        replacement: bool = False,
    ):
        if not _SAFE_IDENTIFIER.fullmatch(operation_id):
            return management_error_response(
                None, "Invalid operation identifier.", status_code=422
            )
        resolved = resolved_user(request)
        if resolved is None:
            return RedirectResponse(f"/login?next=/critical-recovery/{operation_id}", status_code=303)
        preliminary_user, preliminary_cookie, _csrf = resolved
        if preliminary_user.role != "admin":
            return critical_access_rejection(
                request,
                preliminary_user,
                "role_denied",
                "Operation allowed only for administrators.",
            )
        fields = set(critical_identity_fields)
        fields.add("password")
        if replacement:
            fields.add("typed_label_confirmation")
        parsed = await management_form(request, fields, admin=True)
        if isinstance(parsed, Response):
            return parsed
        user, session_cookie, form, _lists = parsed
        if not constant_time_matches(form.get("operation_id", ""), operation_id):
            return management_error_response(
                user, "Operation proof does not match.", status_code=422
            )
        return user, form

    async def execute_critical_action(
        operation_id: str,
        request: Request,
        model_type,
        client_method,
        *,
        replacement: bool = False,
    ) -> Response:
        parsed = await critical_action_form(
            operation_id, request, replacement=replacement
        )
        if isinstance(parsed, Response):
            return parsed
        user, form = parsed
        try:
            critical_request = critical_request_from_form(model_type, form)
        except (FormFieldValueError, ValidationError, ValueError):
            return management_error_response(
                user, "Invalid critical-recovery proof.", status_code=422,
                next_url=f"/critical-recovery/{operation_id}",
            )
        password = form.pop("password", "")
        session_cookie = request.cookies.get(settings.session_cookie_name, "")
        if not session_manager.recently_reauthenticated(session_cookie):
            authenticated = bool(password) and session_manager.reauthenticate(
                session_cookie, password, audit_context=audit_context(request)
            )
            password = ""
            if not authenticated:
                try:
                    proof = daemon_client.get_critical_recovery(operation_id, **daemon_kwargs(user))
                except (ApiCompatibilityError, DaemonProtocolError, DaemonRequestError, DaemonUnavailable) as exc:
                    return daemon_error_response(user, exc, next_url=f"/critical-recovery/{operation_id}")
                return critical_page_response(
                    request, user, proof, status_code=401, form=form,
                    error="Password not accepted or too many attempts. Check your current password and try again here; if attempts are limited, wait a few minutes. No command was sent.",
                )
        try:
            client_method(
                operation_id,
                critical_request,
                form["idempotency_key"],
                **daemon_kwargs(user),
            )
        except (FormFieldValueError, ValidationError, ValueError):
            return management_error_response(
                user, "Invalid critical-recovery proof.", status_code=422
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
        ) as exc:
            return daemon_error_response(user, exc, next_url=f"/critical-recovery/{operation_id}")
        if model_type is ReconcileCriticalRecoveryRequestV1:
            # Refresh or bookmarking must never resubmit a consumed one-shot action.
            return RedirectResponse(
                f"/critical-recovery/{operation_id}?review=reassessed", status_code=303
            )
        return RedirectResponse(f"/jobs/{critical_request.job_id}", status_code=303)

    @app.post("/critical-recovery/{operation_id}/reconcile")
    async def reconcile_critical_recovery_web(
        operation_id: str, request: Request
    ) -> Response:
        return await execute_critical_action(
            operation_id,
            request,
            ReconcileCriticalRecoveryRequestV1,
            daemon_client.reconcile_critical_recovery,
        )

    @app.post("/critical-recovery/{operation_id}/abandon")
    async def abandon_critical_recovery_web(
        operation_id: str, request: Request
    ) -> Response:
        return await execute_critical_action(
            operation_id,
            request,
            AbandonCriticalAttemptRequestV1,
            daemon_client.abandon_critical_recovery,
        )

    @app.post("/critical-recovery/{operation_id}/authorize-replacement")
    async def authorize_critical_replacement_web(
        operation_id: str, request: Request
    ) -> Response:
        return await execute_critical_action(
            operation_id,
            request,
            AuthorizeReplacementAttemptRequestV1,
            daemon_client.authorize_critical_replacement,
            replacement=True,
        )

    @app.post("/media/{sequence}/format")
    async def format_media(sequence: int, request: Request) -> Response:
        if "x-cutover-credential" in request.headers:
            return JSONResponse(
                {"error": {"code": "cutover_authorization_invalid"}},
                status_code=422,
            )
        if sequence <= 0:
            return JSONResponse(
                {"error": {"code": "media_sequence_invalid"}}, status_code=422
            )
        parsed = await mutation_form(
            request,
            {"csrf", "idempotency_key", "typed_label", "cutover_credential"},
        )
        if isinstance(parsed, JSONResponse):
            return parsed
        user, form = parsed
        if user.role != "admin":
            return JSONResponse({"error": {"code": "role_denied"}}, status_code=403)
        if "cutover_credential" in form:
            return JSONResponse(
                {"error": {"code": "cutover_authorization_invalid"}},
                status_code=422,
            )
        status, _view = load_status()
        expected = None if status is None else status.expected_media
        if (
            expected is None
            or expected.sequence != sequence
            or form.get("typed_label", "") != expected.label
        ):
            return JSONResponse(
                {"error": {"code": "format_label_mismatch"}}, status_code=422
            )
        return forward_mutation(
            user=user,
            csrf_token=form["csrf"],
            path=f"/api/v1/media/{sequence}/format",
            payload={"format_confirmation_label": expected.label},
            idempotency_key=form["idempotency_key"],
        )

    @app.get("/diagnostics/export")
    async def diagnostic_export(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        user, _session_cookie, _csrf_token = resolved
        try:
            bundle = daemon_client.download_diagnostics(
                principal=daemon_principal(user), role=daemon_role(user)
            )
        except (
            ApiCompatibilityError,
            DaemonProtocolError,
            DaemonRequestError,
            DaemonUnavailable,
        ):
            return JSONResponse(
                {"error": {"code": "daemon_unavailable"}}, status_code=503
            )
        return Response(
            content=bundle,
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="lto-diagnostics.zip"',
                "Content-Length": str(len(bundle)),
            },
        )

    @app.post("/logout")
    async def logout(request: Request) -> Response:
        resolved = resolved_user(request)
        if resolved is None:
            return JSONResponse({"error": {"code": "unauthorized"}}, status_code=401)
        _user, session_cookie, _csrf_cookie = resolved
        try:
            form = await _read_form(request, {"csrf"})
        except FormRejected:
            return JSONResponse({"error": {"code": "csrf_invalid"}}, status_code=403)
        if not session_manager.verify_csrf(session_cookie, form.get("csrf", "")):
            return JSONResponse({"error": {"code": "csrf_invalid"}}, status_code=403)
        session_manager.revoke(
            session_cookie,
            audit_context=AuditContext(
                request_id=str(uuid4()),
                remote_address=_request_origin(request)[1],
            ),
        )
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(
            settings.session_cookie_name,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
            samesite="strict",
        )
        response.delete_cookie(
            settings.csrf_cookie_name,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
            samesite="strict",
        )
        return response

    return app


class FormRejected(ValueError):
    def __init__(self, code: str, public_message: str) -> None:
        super().__init__(public_message)
        self.code = code
        self.public_message = public_message


async def _read_bounded_form_body(request: Request) -> bytes:
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > _MAX_FORM_BYTES:
            raise FormRejected("form_too_large", "Form is too large.")
        body.extend(chunk)
    return bytes(body)


async def _read_form(request: Request, allowed_fields: set[str]) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").partition(";")[0]
    if content_type.casefold().strip() != "application/x-www-form-urlencoded":
        raise FormRejected("form_content_type_invalid", "Invalid form.")
    body = await _read_bounded_form_body(request)
    try:
        decoded = body.decode("utf-8", errors="strict")
        pairs = parse_qsl(decoded, keep_blank_values=True, strict_parsing=True)
    except (UnicodeDecodeError, ValueError):
        raise FormRejected("form_invalid", "Invalid form.") from None
    values: dict[str, str] = {}
    for key, value in pairs:
        if key not in allowed_fields or key in values:
            raise FormRejected("form_invalid", "Invalid form.")
        values[key] = value
    return values


async def _read_typed_form(
    request: Request,
    scalar_fields: set[str],
    list_fields: set[str],
) -> tuple[dict[str, str], dict[str, tuple[str, ...]]]:
    if scalar_fields & list_fields:
        raise ValueError("form field multiplicity must be unambiguous")
    content_type = request.headers.get("content-type", "").partition(";")[0]
    if content_type.casefold().strip() != "application/x-www-form-urlencoded":
        raise FormRejected("form_content_type_invalid", "Invalid form.")
    body = await _read_bounded_form_body(request)
    try:
        decoded = body.decode("utf-8", errors="strict")
        pairs = parse_qsl(decoded, keep_blank_values=True, strict_parsing=True)
    except (UnicodeDecodeError, ValueError):
        raise FormRejected("form_invalid", "Invalid form.") from None
    scalars: dict[str, str] = {}
    collected: dict[str, list[str]] = {field: [] for field in list_fields}
    for key, value in pairs:
        if key in scalar_fields:
            if key in scalars:
                raise FormRejected("form_invalid", "Invalid form.")
            scalars[key] = value
        elif key in list_fields:
            collected[key].append(value)
        else:
            raise FormRejected("form_invalid", "Invalid form.")
    return scalars, {key: tuple(values) for key, values in collected.items()}


def _set_session_cookie(
    response: Response,
    name: str,
    value: str,
    settings: WebSettings,
) -> None:
    response.set_cookie(
        name,
        value,
        max_age=settings.session_max_age_seconds,
        path="/",
        secure=settings.secure_cookies,
        httponly=True,
        samesite="strict",
    )


def _delete_web_cookies(response: Response, settings: WebSettings) -> None:
    for name in (settings.session_cookie_name, settings.csrf_cookie_name):
        response.delete_cookie(
            name,
            path="/",
            secure=settings.secure_cookies,
            httponly=True,
            samesite="strict",
        )


def _request_origin(request: Request) -> tuple[str, str | None]:
    if request.client is None:
        return "unknown", None
    try:
        address = str(ipaddress.ip_address(request.client.host))
    except ValueError:
        # Keep one conservative rate-limit bucket and omit the audit address.
        # A browser-controlled forwarding header is never accepted as identity.
        return "unknown", None
    return address, address


def _web_event_cursors(request: Request) -> tuple[int | None, int | None]:
    values = _single_query_values(request, {"after_id"})
    after_id = _parse_nonnegative_integer(values.get("after_id"), "after_id")
    raw_header = request.headers.get("last-event-id")
    last_event_id = _parse_nonnegative_integer(raw_header, "Last-Event-ID")
    if after_id is not None and last_event_id is not None and after_id != last_event_id:
        raise ValueError("event cursors must agree")
    return after_id, last_event_id


def _system_logs_query(request: Request) -> SystemLogQuery:
    values = _single_query_values(
        request,
        {"source", "severity", "range", "direction", "cursor", "q", "limit"},
    )
    raw_cursor = values.get("cursor")
    if raw_cursor is not None and (
        not 1 <= len(raw_cursor) <= 2_048
        or not raw_cursor.isascii()
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in raw_cursor)
    ):
        raise ValueError("system log cursor is invalid")
    raw_search = values.get("q")
    if raw_search is not None:
        raw_search = raw_search.strip()
        if not raw_search:
            raw_search = None
        elif len(raw_search) > 128 or any(
            not character.isprintable() for character in raw_search
        ):
            raise ValueError("system log search is invalid")
    raw_limit = values.get("limit")
    try:
        limit = 100 if raw_limit is None else int(raw_limit)
    except (TypeError, ValueError) as exc:
        raise ValueError("system log limit is invalid") from exc
    if str(limit) != (raw_limit if raw_limit is not None else str(limit)):
        raise ValueError("system log limit is invalid")
    if not 1 <= limit <= _MAX_SYSTEM_LOG_LIMIT:
        raise ValueError("system log limit is outside the WebUI bound")
    try:
        return SystemLogQuery(
            source=values.get("source", LogSource.ALL.value),
            severity=values.get("severity", Severity.INFO.value),
            range=values.get("range", LogRange.ONE_HOUR.value),
            direction=values.get("direction", LogDirection.OLDER.value),
            cursor=raw_cursor,
            search=raw_search,
            limit=limit,
        )
    except ValidationError as exc:
        raise ValueError("system log query is invalid") from exc


def _system_logs_parameters(
    query: SystemLogQuery,
    *,
    cursor: str | None,
    direction: LogDirection,
) -> list[tuple[str, str | int]]:
    parameters: list[tuple[str, str | int]] = [
        ("source", query.source.value),
        ("severity", query.severity.value),
        ("range", query.range.value),
        ("direction", direction.value),
        ("limit", query.limit),
    ]
    if query.search is not None:
        parameters.append(("q", query.search))
    if cursor is not None:
        parameters.append(("cursor", cursor))
    return parameters


def _system_logs_url(
    query: SystemLogQuery,
    *,
    cursor: str | None,
    direction: LogDirection,
) -> str:
    return "/logs?" + urlencode(
        _system_logs_parameters(query, cursor=cursor, direction=direction)
    )


def _system_logs_status_url(query: SystemLogQuery) -> str:
    return "/logs/status-fragment?" + urlencode(
        _system_logs_parameters(
            query,
            cursor=query.cursor,
            direction=query.direction,
        )
    )


def _catalog_query(request: Request) -> dict[str, object]:
    values = _single_query_values(
        request,
        {
            "mode",
            "q",
            "library_id",
            "job_id",
            "cassette",
            "sha256",
            "min_size",
            "max_size",
            "copied_after",
            "copied_before",
            "include_history",
            "limit",
            "cursor",
            "parent_path",
            "browse_cursor",
        },
    )
    mode = values.get("mode", "search")
    if mode not in {"search", "browse"}:
        raise ValueError("catalog mode is invalid")
    q = _bounded_catalog_text(values.get("q", ""), maximum=256)
    library_id = values.get("library_id", "")
    job_id = values.get("job_id", "")
    if library_id and not _SAFE_CATALOG_LIBRARY_ID.fullmatch(library_id):
        raise ValueError("catalog library identifier is invalid")
    if job_id and not _SAFE_CATALOG_JOB_ID.fullmatch(job_id):
        raise ValueError("catalog job identifier is invalid")
    cassette = _bounded_catalog_text(values.get("cassette", ""), maximum=128)
    sha256 = values.get("sha256", "")
    if sha256 and not re.fullmatch(r"[0-9A-Fa-f]{64}", sha256):
        raise ValueError("catalog hash is invalid")
    sha256 = sha256.lower()
    min_size = _catalog_size(values.get("min_size"), "minimum")
    max_size = _catalog_size(values.get("max_size"), "maximum")
    if min_size is not None and max_size is not None and min_size > max_size:
        raise ValueError("catalog size range is invalid")
    copied_after = _bounded_catalog_text(values.get("copied_after", ""), maximum=64)
    copied_before = _bounded_catalog_text(values.get("copied_before", ""), maximum=64)
    cursor = _bounded_catalog_optional(values.get("cursor"), maximum=512)
    browse_cursor = _bounded_catalog_optional(values.get("browse_cursor"), maximum=512)
    parent_path = _catalog_path(values.get("parent_path", ""))
    raw_history = values.get("include_history", "")
    if raw_history not in {"", "0", "1", "false", "true", "off", "on"}:
        raise ValueError("catalog history flag is invalid")
    raw_limit = values.get("limit")
    limit = 50 if raw_limit is None else _catalog_size(raw_limit, "limit")
    if limit is None or not 1 <= limit <= 200:
        raise ValueError("catalog limit is outside the WebUI bound")
    if mode == "search" and (parent_path or browse_cursor):
        raise ValueError("catalog search cannot include browse state")
    if mode == "browse":
        if not library_id:
            raise ValueError("catalog browse requires a library")
        if any(
            name in values
            for name in (
                "q",
                "job_id",
                "cassette",
                "sha256",
                "min_size",
                "max_size",
                "copied_after",
                "copied_before",
                "include_history",
                "cursor",
            )
        ):
            raise ValueError("catalog browse cannot include search state")
    return {
        "mode": mode,
        "q": q,
        "library_id": library_id,
        "job_id": job_id,
        "cassette": cassette,
        "sha256": sha256,
        "min_size": min_size,
        "max_size": max_size,
        "copied_after": copied_after,
        "copied_before": copied_before,
        "include_history": raw_history in {"1", "true", "on"},
        "limit": limit,
        "cursor": cursor,
        "parent_path": parent_path,
        "browse_cursor": browse_cursor,
    }


def _bounded_catalog_text(value: str, *, maximum: int) -> str:
    if "\x00" in value or len(value) > maximum:
        raise ValueError("catalog text is invalid")
    return value


def _bounded_catalog_optional(value: str | None, *, maximum: int) -> str:
    if value is None:
        return ""
    if not value:
        raise ValueError("catalog cursor is invalid")
    return _bounded_catalog_text(value, maximum=maximum)


def _catalog_size(value: str | None, name: str) -> int | None:
    parsed = _parse_nonnegative_integer(value, name)
    if parsed is not None and parsed > 2**63 - 1:
        raise ValueError("catalog size is outside the supported range")
    return parsed


def _catalog_path(value: str) -> str:
    _bounded_catalog_text(value, maximum=4096)
    if not value:
        return ""
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise ValueError("catalog path is invalid")
    return "/".join(components)


def _catalog_search_url(query: dict[str, object], cursor: str | None) -> str | None:
    if cursor is None:
        return None
    parameters = {
        key: value
        for key, value in query.items()
        if key not in {"parent_path", "browse_cursor", "cursor", "mode"}
        and value not in {"", None, False}
    }
    parameters["mode"] = "search"
    if query["include_history"]:
        parameters["include_history"] = "true"
    parameters["cursor"] = cursor
    return "/catalog?" + urlencode(parameters)


def _catalog_browse_url(
    *, library_id: object, parent_path: object, limit: object, cursor: str | None
) -> str | None:
    if not library_id:
        return None
    parameters: dict[str, object] = {
        "mode": "browse",
        "library_id": library_id,
        "parent_path": parent_path,
        "limit": limit,
    }
    if cursor is not None:
        parameters["browse_cursor"] = cursor
    return "/catalog?" + urlencode(parameters)


def _catalog_breadcrumbs(
    library_id: object, parent_path: object, limit: object
) -> tuple[tuple[str, str], ...]:
    library = str(library_id)
    path = str(parent_path)
    crumbs: list[tuple[str, str]] = [
        (
            library,
            _catalog_browse_url(
                library_id=library, parent_path="", limit=limit, cursor=None
            )
            or "/catalog",
        )
    ]
    accumulated: list[str] = []
    for component in path.split("/") if path else ():
        accumulated.append(component)
        crumbs.append(
            (
                component,
                _catalog_browse_url(
                    library_id=library,
                    parent_path="/".join(accumulated),
                    limit=limit,
                    cursor=None,
                )
                or "/catalog",
            )
        )
    return tuple(crumbs)


def _single_query_values(request: Request, allowed: set[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key not in allowed or key in values:
            raise ValueError("invalid query")
        values[key] = value
    return values


def _parse_nonnegative_integer(value: str | None, name: str) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdecimal():
        raise ValueError(f"{name} must be a non-negative integer")
    return int(value)


def _format_integer(value: int) -> str:
    return f"{value:,}"


def _format_decimal(value: float) -> str:
    return f"{value:,.2f}"


def _format_rate(value: float | None) -> str:
    return "Not available" if value is None else f"{_format_decimal(value)} MiB/s"


def _format_bytes(value: int) -> str:
    gib = value / (1024**3)
    return f"{_format_decimal(gib)} GiB"


def _format_mib(value: int) -> str:
    return f"{_format_decimal(value / (1024**2))} MiB"


def _format_runtime_bytes(value: int) -> str:
    if value < 1024**2:
        return f"{_format_integer(value)} B"
    if value < 1024**3:
        return _format_mib(value)
    return _format_bytes(value)


def _format_storage_size(value: int) -> str:
    units = ("B", "KiB", "MiB", "GiB", "TiB", "PiB")
    amount = float(value)
    unit = units[0]
    for candidate in units:
        unit = candidate
        if amount < 1024 or candidate == units[-1]:
            break
        amount /= 1024
    if unit == "B":
        return f"{value:,} B"
    return f"{amount:,.2f} {unit}"


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{_format_decimal(seconds)} s"
    minutes = int(seconds // 60)
    remainder = int(seconds % 60)
    if minutes < 60:
        return f"{minutes} min {remainder:02d} s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes:02d} min"


def _parse_timestamp(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _parse_diagnostic_timestamp(value: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError("diagnostic timestamp must be RFC3339 UTC")
    parsed = _parse_timestamp(value)
    if parsed is None:
        raise ValueError("diagnostic timestamp must be RFC3339 UTC")
    return parsed


def _format_axis_rate(value: float) -> str:
    rounded = round(value, 2)
    if rounded.is_integer():
        return f"{int(rounded)} MiB/s"
    return f"{_format_decimal(rounded)} MiB/s"


def _format_elapsed(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.0f} s"
    minutes = int(seconds // 60)
    remainder = int(seconds % 60)
    return f"{minutes}:{remainder:02d} min"


def _format_user_timestamp(value: float | None) -> str:
    if value is None:
        return "Never"
    return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d %H:%M UTC")
