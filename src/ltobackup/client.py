from __future__ import annotations

import json
import re
from collections.abc import Iterator
from math import isfinite
from pathlib import Path
from threading import TIMEOUT_MAX
from typing import Literal, Protocol, Self, TypeVar
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .daemon.api_models import (
    AbandonCriticalAttemptRequestV1,
    ApplicationSettingsV1,
    AuthorizeAutomaticSequenceRequestV1,
    AuthorizeCatalogRestoreItemReplacementRequestV1,
    AuthorizeReplacementAttemptRequestV1,
    BoundaryRefreshAcceptedV1,
    CatalogBrowsePageV1,
    CatalogFileVersionV1,
    CatalogRestoreOptionsV1,
    CatalogRestorePlanV1,
    CatalogRestoreReplacementAuthorizationV1,
    CatalogRestoreReplacementCapabilityV1,
    CatalogRestoreRunCassetteV1,
    CatalogRestoreRunItemV1,
    CatalogRestoreRunV1,
    CatalogSearchPageV1,
    CreateCatalogRestorePlanRequestV1,
    CreateJobFromPlanRequestV1,
    CreateJobPlanRequestV1,
    CreateLibraryRequestV1,
    CreateShareRequestV1,
    CriticalRecoveryProofV1,
    DaemonStatusV1,
    EventEnvelopeV1,
    ExtendJobRequestV1,
    HostSettingsV1,
    IncrementalPolicyV1,
    IncrementalScanResultV1,
    IssueCatalogRestoreReplacementCapabilityRequestV1,
    JobCassettePageV1,
    JobCommandRequestV1,
    JobDetailV1,
    JobHistoryPageV1,
    JobListPageV1,
    JobManifestPageV1,
    JobPlanV1,
    JobSequenceStatusV1,
    LibraryChangedV1,
    LibrarySummaryV1,
    MediaProfilesV1,
    NetworkShareOptionsV1,
    OperationConflictV1,
    OperationResponseV1,
    PreMediaResetProofV1,
    ResetPreMediaAttemptRequestV1,
    PublicErrorV1,
    ReconcileCriticalRecoveryRequestV1,
    ReserveJobLabelsRequestV1,
    ResetFailedCassetteRequestV1,
    RestoreRunControlRequestV1,
    RetireJobRequestV1,
    RetireLibraryRequestV1,
    ShareChangedV1,
    ShareConfirmedOperationRequestV1,
    ShareCredentialClearRequestV1,
    ShareCredentialRequestV1,
    ShareOperationRequestV1,
    ShareOperationV1,
    ShareRemoveRequestV1,
    ShareRetireRequestV1,
    ShareSummaryV1,
    ShareV1,
    StartCatalogRestoreRunRequestV1,
    StatusPatchV1,
    StorageSummaryV1,
    SystemLogQuery,
    SystemLogsPageV1,
    UpdateApplicationSettingsRequestV1,
    UpdateIncrementalPolicyRequestV1,
    UpdateJobRequestV1,
    UpdateLibraryRequestV1,
    UpdateShareRequestV1,
)

SUPPORTED_DAEMON_API_VERSION = 1
_MAX_PUBLIC_ERROR_BODY_BYTES = 64 * 1024
_MAX_DIAGNOSTIC_DOWNLOAD_BYTES = 512 * 1024
_DIAGNOSTIC_DOWNLOAD_PATH = "/api/v1/diagnostics/export"
_DIAGNOSTIC_DOWNLOAD_DISPOSITION = 'attachment; filename="lto-diagnostics.zip"'
_SAFE_WIRE_PRINCIPAL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_SAFE_WIRE_IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SAFE_LIBRARY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_SAFE_SHARE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_SAFE_JOB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_AUTHENTICATED_ROLES = frozenset({"admin", "operator"})

ResponseModelT = TypeVar("ResponseModelT", bound=BaseModel)
ResumeResponseV1 = OperationResponseV1 | BoundaryRefreshAcceptedV1
_RESUME_RESPONSE_ADAPTER = TypeAdapter(ResumeResponseV1)


class WebReauthenticationContext(BaseModel):
    """Trusted WebUI session attestation; never a generic caller header bag."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    session_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    reauthenticated_at: float = Field(ge=0, le=2**63 - 1)


class DaemonClient(Protocol):
    def get_storage_summary(
        self, *, principal: str, role: Literal["admin", "operator"] = "admin",
    ) -> StorageSummaryV1: ...

    def get(
        self,
        path: str,
        *,
        response_model: type[ResponseModelT],
        principal: str | None = None,
        role: Literal["admin", "operator"] | None = None,
        params: dict[str, object] | None = None,
    ) -> ResponseModelT: ...

    def post(
        self,
        path: str,
        payload: dict,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"] = "admin",
    ) -> dict[str, object]: ...

    def events(
        self,
        after_id: int | None = None,
        *,
        last_event_id: int | None = None,
    ) -> Iterator[dict[str, object]]: ...

    def download_diagnostics(
        self,
        *,
        principal: str,
        role: Literal["admin", "operator"] = "admin",
    ) -> bytes: ...

    def get_system_logs(
        self,
        *,
        source: str,
        severity: str,
        range: str,
        direction: str,
        cursor: str | None,
        search: str | None,
        limit: int,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> SystemLogsPageV1: ...

    def list_network_shares(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> tuple[ShareSummaryV1, ...]: ...

    def get_network_share_options(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> NetworkShareOptionsV1: ...

    def create_network_share(
        self,
        request: CreateShareRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1: ...

    def get_network_share(
        self, share_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> ShareV1: ...

    def update_network_share(
        self,
        share_id: str,
        request: UpdateShareRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1: ...

    def install_network_share_credential(
        self,
        share_id: str,
        request: ShareCredentialRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1: ...

    def clear_network_share_credential(
        self,
        share_id: str,
        request: ShareCredentialClearRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1: ...

    def test_network_share(
        self,
        share_id: str,
        request: ShareOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1: ...

    def connect_network_share(
        self,
        share_id: str,
        request: ShareOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1: ...

    def disconnect_network_share(
        self,
        share_id: str,
        request: ShareConfirmedOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1: ...

    def reconcile_network_share(
        self,
        share_id: str,
        request: ShareOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1: ...

    def retire_network_share(
        self,
        share_id: str,
        request: ShareRetireRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1: ...

    def remove_network_share(
        self,
        share_id: str,
        request: ShareRemoveRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1: ...

    def get_network_share_operation(
        self, operation_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> ShareOperationV1: ...

    def list_libraries(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> tuple[LibrarySummaryV1, ...]: ...

    def create_library(
        self,
        request: CreateLibraryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1: ...

    def get_library(
        self, library_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> LibrarySummaryV1: ...

    def update_library(
        self,
        library_id: str,
        request: UpdateLibraryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1: ...

    def scan_library(
        self,
        library_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1: ...

    def retire_library(
        self,
        library_id: str,
        request: RetireLibraryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1: ...

    def get_media_profiles(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> MediaProfilesV1: ...

    def create_job_plan(
        self,
        request: CreateJobPlanRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobPlanV1: ...

    def get_job_plan(
        self, plan_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> JobPlanV1: ...

    def create_job_from_plan(
        self,
        plan_id: str,
        request: CreateJobFromPlanRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def authorize_automatic_sequence(
        self,
        job_id: str,
        request: AuthorizeAutomaticSequenceRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def list_jobs(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        include_retired: bool = False,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobListPageV1: ...

    def get_job(
        self, job_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> JobDetailV1: ...

    def get_job_sequence_status(
        self, job_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> JobSequenceStatusV1: ...

    def get_job_cassettes(
        self, job_id: str, *, limit: int = 100, cursor: str | None = None,
        principal: str, role: Literal["admin", "operator"],
    ) -> JobCassettePageV1: ...

    def get_incremental_policy(self, job_id: str, *, principal: str, role: Literal["admin", "operator"]) -> IncrementalPolicyV1: ...
    def update_incremental_policy(self, job_id: str, request: UpdateIncrementalPolicyRequestV1, idempotency_key: str, *, principal: str, role: Literal["admin", "operator"]) -> IncrementalPolicyV1: ...
    def scan_job_now(self, job_id: str, idempotency_key: str, *, principal: str, role: Literal["admin", "operator"]) -> IncrementalScanResultV1: ...

    def get_job_manifest(
        self,
        job_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobManifestPageV1: ...

    def get_job_history(
        self,
        job_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobHistoryPageV1: ...

    def search_catalog(
        self,
        *,
        q: str = "",
        library_id: str | None = None,
        job_id: str | None = None,
        cassette: str | None = None,
        sha256: str | None = None,
        min_size: int | None = None,
        max_size: int | None = None,
        copied_after: str | None = None,
        copied_before: str | None = None,
        include_history: bool = False,
        limit: int = 50,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogSearchPageV1: ...

    def browse_catalog(
        self,
        *,
        library_id: str,
        parent_path: str = "",
        limit: int = 50,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogBrowsePageV1: ...

    def get_catalog_file_version(
        self,
        version_id: int,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogFileVersionV1: ...

    def get_catalog_restore_options(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> CatalogRestoreOptionsV1: ...

    def create_catalog_restore_plan(
        self,
        request: CreateCatalogRestorePlanRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestorePlanV1: ...

    def get_catalog_restore_plan(
        self,
        plan_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestorePlanV1: ...

    def start_catalog_restore_run(
        self,
        plan_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1: ...

    def get_catalog_restore_run(
        self, run_id: str, *, principal: str, role: Literal["admin", "operator"]
    ) -> CatalogRestoreRunV1: ...

    def get_catalog_restore_run_cassette_result(self, run_id: str, cassette_sequence: int, *, principal: str, role: Literal["admin", "operator"]) -> CatalogRestoreRunCassetteV1: ...

    def get_catalog_restore_run_item_result(self, run_id: str, item_sequence: int, *, principal: str, role: Literal["admin", "operator"]) -> CatalogRestoreRunItemV1: ...

    def pause_catalog_restore_run(
        self, run_id: str, idempotency_key: str, *, principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1: ...

    def resume_catalog_restore_run(
        self, run_id: str, idempotency_key: str, *, principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1: ...

    def cancel_catalog_restore_run(
        self, run_id: str, idempotency_key: str, *, principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1: ...

    def authorize_catalog_restore_item_replacement(
        self,
        run_id: str,
        item_sequence: int,
        request: AuthorizeCatalogRestoreItemReplacementRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
        reauthentication_context: WebReauthenticationContext,
    ) -> CatalogRestoreReplacementAuthorizationV1: ...

    def issue_catalog_restore_replacement_capability(self, idempotency_key: str, *, principal: str, role: Literal["admin", "operator"], reauthentication_context: WebReauthenticationContext) -> CatalogRestoreReplacementCapabilityV1: ...

    def start_job(
        self,
        job_id: str,
        request: JobCommandRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1: ...

    def resume_job(
        self,
        job_id: str,
        request: JobCommandRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ResumeResponseV1: ...

    def reset_failed_cassette(
        self,
        job_id: str,
        request: ResetFailedCassetteRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def pause_job(
        self,
        job_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def update_job(
        self,
        job_id: str,
        request: UpdateJobRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def reserve_job_labels(
        self,
        job_id: str,
        request: ReserveJobLabelsRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def extend_job(
        self,
        job_id: str,
        request: ExtendJobRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def retire_job(
        self,
        job_id: str,
        request: RetireJobRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1: ...

    def get_application_settings(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> ApplicationSettingsV1: ...

    def update_application_settings(
        self,
        request: UpdateApplicationSettingsRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ApplicationSettingsV1: ...

    def get_host_settings(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> HostSettingsV1: ...

    def get_pre_media_reset(
        self, operation_id: str, *, principal: str, role: Literal["admin", "operator"],
    ) -> PreMediaResetProofV1: ...

    def reset_pre_media_attempt(
        self, operation_id: str, request: ResetPreMediaAttemptRequestV1, idempotency_key: str,
        *, principal: str, role: Literal["admin", "operator"],
        reauthentication_context: WebReauthenticationContext,
    ) -> OperationResponseV1: ...

    def get_critical_recovery(
        self,
        operation_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CriticalRecoveryProofV1: ...

    def reconcile_critical_recovery(
        self,
        operation_id: str,
        request: ReconcileCriticalRecoveryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CriticalRecoveryProofV1: ...

    def abandon_critical_recovery(
        self,
        operation_id: str,
        request: AbandonCriticalAttemptRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1: ...

    def authorize_critical_replacement(
        self,
        operation_id: str,
        request: AuthorizeReplacementAttemptRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1: ...


class DaemonProtocolError(RuntimeError):
    """The daemon returned data outside the public versioned contract."""


class DaemonUnavailable(RuntimeError):
    def __init__(self) -> None:
        super().__init__("daemon is unavailable")


class DaemonRequestError(RuntimeError):
    def __init__(self, status_code: int, error_code: str | None) -> None:
        super().__init__("daemon request failed")
        self.status_code = status_code
        self.error_code = error_code


class ApiCompatibilityError(RuntimeError):
    def __init__(self, actual_version: int, supported_version: int) -> None:
        super().__init__("daemon API version is incompatible with mutations")
        self.actual_version = actual_version
        self.supported_version = supported_version


class DaemonConflict(RuntimeError):
    def __init__(
        self,
        error_code: Literal["active_operation"],
        active_operation: dict[str, object],
    ) -> None:
        super().__init__("another daemon operation is active")
        self.error_code = error_code
        self.active_operation = active_operation


class _HealthCompatibilityResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    status: Literal["ok"]
    api_version: int = Field(strict=True, ge=1)


def _validated_timeout(value: object) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not isfinite(value)
        or value <= 0
        or value > TIMEOUT_MAX
    ):
        raise ValueError(
            "daemon timeout must be positive, finite, and no greater than "
            "threading.TIMEOUT_MAX seconds"
        )
    return float(value)


def _validated_cursor(value: object, name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


class UnixDaemonClient:
    def __init__(
        self,
        socket_path: str | Path,
        timeout_seconds: float,
        *,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        selected_socket = Path(socket_path)
        if not selected_socket.is_absolute():
            raise ValueError("daemon Unix socket path must be absolute")
        timeout = _validated_timeout(timeout_seconds)
        selected_transport = (
            httpx.HTTPTransport(uds=str(selected_socket))
            if transport is None
            else transport
        )

        self.socket_path = selected_socket
        self.timeout_seconds = timeout
        self._client = httpx.Client(
            transport=selected_transport,
            base_url="http://daemon",
            timeout=timeout,
        )

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get_storage_summary(
        self, *, principal: str, role: Literal["admin", "operator"] = "admin",
    ) -> StorageSummaryV1:
        return self.get(
            "/api/v1/storage", response_model=StorageSummaryV1,
            principal=principal, role=role,
        )

    def get(
        self,
        path: str,
        *,
        response_model: type[ResponseModelT],
        principal: str | None = None,
        role: Literal["admin", "operator"] | None = None,
        params: dict[str, object] | None = None,
    ) -> ResponseModelT:
        headers = None
        if principal is not None:
            headers = {
                "X-Authenticated-Principal": self._validated_wire_header(
                    principal,
                    _SAFE_WIRE_PRINCIPAL,
                ),
                "X-Authenticated-Role": self._validated_role(role or "admin"),
            }
        response = self._send("GET", path, headers=headers, params=params)
        try:
            self._require_success(response)
            return self._parse_model(response, response_model)
        finally:
            response.close()

    def post(
        self,
        path: str,
        payload: dict,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"] = "admin",
    ) -> dict[str, object]:
        operation = self._mutate(
            "POST",
            path,
            payload,
            idempotency_key,
            response_model=OperationResponseV1,
            principal=principal,
            role=role,
        )
        return operation.model_dump(mode="json")

    def _mutate(
        self,
        method: Literal["POST", "PATCH", "PUT", "DELETE"],
        path: str,
        payload: dict[str, object],
        idempotency_key: str,
        *,
        response_model: type[ResponseModelT] | TypeAdapter[ResponseModelT],
        principal: str,
        role: Literal["admin", "operator"],
        reauthentication_context: WebReauthenticationContext | None = None,
    ) -> ResponseModelT:
        headers = {
            "Idempotency-Key": self._validated_wire_header(
                idempotency_key, _SAFE_WIRE_IDEMPOTENCY_KEY
            ),
            "X-Authenticated-Principal": self._validated_wire_header(
                principal, _SAFE_WIRE_PRINCIPAL
            ),
            "X-Authenticated-Role": self._validated_role(role),
        }
        if reauthentication_context is not None:
            headers.update(
                {
                    "X-Authenticated-Session-Binding": reauthentication_context.session_binding_sha256,
                    "X-Authenticated-Reauthenticated-At": str(reauthentication_context.reauthenticated_at),
                }
            )
        request = self._build_request(
            method,
            path,
            json=payload,
            headers=headers,
        )
        self._require_mutation_compatibility()
        response = self._send_request(request)
        try:
            if response.status_code == 409:
                try:
                    raw_conflict = response.json()
                except (TypeError, ValueError, json.JSONDecodeError):
                    raw_conflict = None
                if (
                    isinstance(raw_conflict, dict)
                    and isinstance(raw_conflict.get("error"), dict)
                    and raw_conflict["error"].get("code") == "active_operation"
                ):
                    conflict = self._parse_model(response, OperationConflictV1)
                    if conflict.error.code != "active_operation":
                        raise DaemonProtocolError("invalid daemon conflict response")
                    raise DaemonConflict(
                        "active_operation",
                        conflict.active_operation.model_dump(mode="json"),
                    )
            self._require_success(response)
            return self._parse_model(response, response_model)
        finally:
            response.close()

    def events(
        self,
        after_id: int | None = None,
        *,
        last_event_id: int | None = None,
    ) -> Iterator[dict[str, object]]:
        query_cursor = _validated_cursor(after_id, "after_id")
        header_cursor = _validated_cursor(last_event_id, "last_event_id")
        if (
            query_cursor is not None
            and header_cursor is not None
            and query_cursor != header_cursor
        ):
            raise ValueError("event cursors must agree")

        params = {"after_id": query_cursor} if query_cursor is not None else None
        headers = (
            {"Last-Event-ID": str(header_cursor)} if header_cursor is not None else None
        )
        resume_cursor = header_cursor if header_cursor is not None else query_cursor

        response = self._send(
            "GET",
            "/api/v1/events",
            params=params,
            headers=headers,
            stream=True,
        )
        transport_failed = False
        try:
            self._require_success(response)
            media_type = response.headers.get("content-type", "").partition(";")[0]
            if media_type.strip().casefold() != "text/event-stream":
                raise DaemonProtocolError("invalid daemon event stream")
            yield from self._validated_events(response.iter_lines(), resume_cursor)
        except httpx.TransportError:
            transport_failed = True
        finally:
            response.close()
        if transport_failed:
            raise DaemonUnavailable()

    def download_diagnostics(
        self,
        *,
        principal: str,
        role: Literal["admin", "operator"] = "admin",
    ) -> bytes:
        safe_principal = self._validated_wire_header(
            principal,
            _SAFE_WIRE_PRINCIPAL,
        )
        response = self._send(
            "GET",
            _DIAGNOSTIC_DOWNLOAD_PATH,
            stream=True,
            headers={
                "X-Authenticated-Principal": safe_principal,
                "X-Authenticated-Role": self._validated_role(role),
            },
        )
        try:
            self._require_success(response)
            content_type = response.headers.get("content-type", "").partition(";")[0]
            disposition = response.headers.get("content-disposition")
            if (
                content_type.strip().casefold() != "application/zip"
                or disposition != _DIAGNOSTIC_DOWNLOAD_DISPOSITION
            ):
                raise DaemonProtocolError("invalid diagnostic download")
            return self._bounded_diagnostic_bytes(response)
        except httpx.TransportError:
            raise DaemonUnavailable() from None
        finally:
            response.close()

    def _require_mutation_compatibility(self) -> None:
        response = self._send("GET", "/api/v1/health")
        try:
            self._require_success(response)
            health = self._parse_model(response, _HealthCompatibilityResponse)
        finally:
            response.close()
        if health.api_version != SUPPORTED_DAEMON_API_VERSION:
            raise ApiCompatibilityError(
                health.api_version,
                SUPPORTED_DAEMON_API_VERSION,
            )

    @staticmethod
    def _model_payload(model: BaseModel) -> dict[str, object]:
        return model.model_dump(mode="json", exclude_none=True)

    def list_libraries(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> tuple[LibrarySummaryV1, ...]:
        response = self._send(
            "GET",
            "/api/v1/libraries",
            headers={
                "X-Authenticated-Principal": self._validated_wire_header(
                    principal, _SAFE_WIRE_PRINCIPAL
                ),
                "X-Authenticated-Role": self._validated_role(role),
            },
        )
        try:
            self._require_success(response)
            return TypeAdapter(tuple[LibrarySummaryV1, ...]).validate_python(
                response.json()
            )
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
            raise DaemonProtocolError("invalid daemon response") from None
        finally:
            response.close()

    def list_network_shares(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> tuple[ShareSummaryV1, ...]:
        response = self._send(
            "GET",
            "/api/v1/network-shares",
            headers={
                "X-Authenticated-Principal": self._validated_wire_header(
                    principal, _SAFE_WIRE_PRINCIPAL
                ),
                "X-Authenticated-Role": self._validated_role(role),
            },
        )
        try:
            self._require_success(response)
            return TypeAdapter(tuple[ShareSummaryV1, ...]).validate_python(
                response.json()
            )
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
            raise DaemonProtocolError("invalid daemon response") from None
        finally:
            response.close()

    def get_network_share_options(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> NetworkShareOptionsV1:
        return self.get(
            "/api/v1/network-share-options",
            response_model=NetworkShareOptionsV1,
            principal=principal,
            role=role,
        )

    @staticmethod
    def _share_path(share_id: str) -> str:
        return (
            "/api/v1/network-shares/"
            + UnixDaemonClient._validated_domain_identifier(share_id, _SAFE_SHARE_ID)
        )

    def create_network_share(
        self,
        request: CreateShareRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1:
        return self._mutate(
            "POST",
            "/api/v1/network-shares",
            self._model_payload(request),
            idempotency_key,
            response_model=ShareV1,
            principal=principal,
            role=role,
        )

    def get_network_share(
        self,
        share_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1:
        return self.get(
            self._share_path(share_id),
            response_model=ShareV1,
            principal=principal,
            role=role,
        )

    def update_network_share(
        self,
        share_id: str,
        request: UpdateShareRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1:
        return self._mutate(
            "PATCH",
            self._share_path(share_id),
            self._model_payload(request),
            idempotency_key,
            response_model=ShareV1,
            principal=principal,
            role=role,
        )

    def install_network_share_credential(
        self,
        share_id: str,
        request: ShareCredentialRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._share_operation_mutation(
            "PUT", share_id, "credential", request, idempotency_key, principal, role
        )

    def clear_network_share_credential(
        self,
        share_id: str,
        request: ShareCredentialClearRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._share_operation_mutation(
            "DELETE", share_id, "credential", request, idempotency_key, principal, role
        )

    def test_network_share(
        self,
        share_id: str,
        request: ShareOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._share_operation_mutation(
            "POST", share_id, "test", request, idempotency_key, principal, role
        )

    def connect_network_share(
        self,
        share_id: str,
        request: ShareOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._share_operation_mutation(
            "POST", share_id, "connect", request, idempotency_key, principal, role
        )

    def disconnect_network_share(
        self,
        share_id: str,
        request: ShareConfirmedOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._share_operation_mutation(
            "POST", share_id, "disconnect", request, idempotency_key, principal, role
        )

    def reconcile_network_share(
        self,
        share_id: str,
        request: ShareOperationRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._share_operation_mutation(
            "POST", share_id, "reconcile", request, idempotency_key, principal, role
        )

    def _share_operation_mutation(
        self,
        method: Literal["POST", "PUT", "DELETE"],
        share_id: str,
        action: str,
        request: BaseModel,
        idempotency_key: str,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        return self._mutate(
            method,
            f"{self._share_path(share_id)}/{action}",
            self._model_payload(request),
            idempotency_key,
            response_model=ShareOperationV1,
            principal=principal,
            role=role,
        )

    def retire_network_share(
        self,
        share_id: str,
        request: ShareRetireRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1:
        return self._mutate(
            "POST",
            f"{self._share_path(share_id)}/retire",
            self._model_payload(request),
            idempotency_key,
            response_model=ShareV1,
            principal=principal,
            role=role,
        )

    def remove_network_share(
        self,
        share_id: str,
        request: ShareRemoveRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareV1:
        return self._mutate(
            "DELETE",
            self._share_path(share_id),
            self._model_payload(request),
            idempotency_key,
            response_model=ShareV1,
            principal=principal,
            role=role,
        )

    def get_network_share_operation(
        self,
        operation_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ShareOperationV1:
        operation = self._validated_domain_identifier(
            operation_id, _SAFE_WIRE_PRINCIPAL
        )
        return self.get(
            f"/api/v1/network-share-operations/{operation}",
            response_model=ShareOperationV1,
            principal=principal,
            role=role,
        )

    def create_library(
        self,
        request: CreateLibraryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1:
        return self._mutate(
            "POST",
            "/api/v1/libraries",
            self._model_payload(request),
            idempotency_key,
            response_model=LibrarySummaryV1,
            principal=principal,
            role=role,
        )

    def get_library(
        self,
        library_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1:
        return self.get(
            f"/api/v1/libraries/{self._validated_domain_identifier(library_id, _SAFE_LIBRARY_ID)}",
            response_model=LibrarySummaryV1,
            principal=principal,
            role=role,
        )

    def update_library(
        self,
        library_id: str,
        request: UpdateLibraryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1:
        return self._mutate(
            "PATCH",
            f"/api/v1/libraries/{self._validated_domain_identifier(library_id, _SAFE_LIBRARY_ID)}",
            self._model_payload(request),
            idempotency_key,
            response_model=LibrarySummaryV1,
            principal=principal,
            role=role,
        )

    def scan_library(
        self,
        library_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1:
        return self._mutate(
            "POST",
            f"/api/v1/libraries/{self._validated_domain_identifier(library_id, _SAFE_LIBRARY_ID)}/scan",
            {},
            idempotency_key,
            response_model=LibrarySummaryV1,
            principal=principal,
            role=role,
        )

    def retire_library(
        self,
        library_id: str,
        request: RetireLibraryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> LibrarySummaryV1:
        return self._mutate(
            "POST",
            f"/api/v1/libraries/{self._validated_domain_identifier(library_id, _SAFE_LIBRARY_ID)}/retire",
            self._model_payload(request),
            idempotency_key,
            response_model=LibrarySummaryV1,
            principal=principal,
            role=role,
        )

    def get_media_profiles(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> MediaProfilesV1:
        return self.get(
            "/api/v1/media-profiles",
            response_model=MediaProfilesV1,
            principal=principal,
            role=role,
        )

    def create_job_plan(
        self,
        request: CreateJobPlanRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobPlanV1:
        return self._mutate(
            "POST",
            "/api/v1/job-plans",
            self._model_payload(request),
            idempotency_key,
            response_model=JobPlanV1,
            principal=principal,
            role=role,
        )

    def get_job_plan(
        self,
        plan_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobPlanV1:
        return self.get(
            f"/api/v1/job-plans/{self._validated_domain_identifier(plan_id, _SAFE_JOB_ID)}",
            response_model=JobPlanV1,
            principal=principal,
            role=role,
        )

    def create_job_from_plan(
        self,
        plan_id: str,
        request: CreateJobFromPlanRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._mutate(
            "POST",
            f"/api/v1/job-plans/{self._validated_domain_identifier(plan_id, _SAFE_JOB_ID)}/jobs",
            self._model_payload(request),
            idempotency_key,
            response_model=JobDetailV1,
            principal=principal,
            role=role,
        )

    def authorize_automatic_sequence(
        self,
        job_id: str,
        request: AuthorizeAutomaticSequenceRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._mutate(
            "POST",
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}/automatic-sequence/authorize",
            self._model_payload(request),
            idempotency_key,
            response_model=JobDetailV1,
            principal=principal,
            role=role,
        )

    def search_catalog(
        self,
        *,
        q: str = "",
        library_id: str | None = None,
        job_id: str | None = None,
        cassette: str | None = None,
        sha256: str | None = None,
        min_size: int | None = None,
        max_size: int | None = None,
        copied_after: str | None = None,
        copied_before: str | None = None,
        include_history: bool = False,
        limit: int = 50,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogSearchPageV1:
        params: dict[str, object] = {
            "q": self._validated_catalog_text(q, "catalog query", max_length=256),
            "include_history": self._validated_catalog_bool(
                include_history, "catalog history flag"
            ),
            "limit": self._validated_catalog_limit(limit),
        }
        if library_id is not None:
            params["library_id"] = self._validated_catalog_identifier(
                library_id, _SAFE_LIBRARY_ID, "catalog library id"
            )
        if job_id is not None:
            params["job_id"] = self._validated_catalog_identifier(
                job_id, _SAFE_JOB_ID, "catalog job id"
            )
        if cassette is not None:
            params["cassette"] = self._validated_catalog_text(
                cassette, "catalog cassette", min_length=1, max_length=128
            )
        if sha256 is not None:
            params["sha256"] = self._validated_catalog_sha256(sha256)
        if min_size is not None:
            params["min_size"] = self._validated_catalog_size(min_size, "minimum")
        if max_size is not None:
            params["max_size"] = self._validated_catalog_size(max_size, "maximum")
        if copied_after is not None:
            params["copied_after"] = self._validated_catalog_text(
                copied_after, "catalog copied-after", max_length=64
            )
        if copied_before is not None:
            params["copied_before"] = self._validated_catalog_text(
                copied_before, "catalog copied-before", max_length=64
            )
        if cursor is not None:
            params["cursor"] = self._validated_catalog_text(
                cursor, "catalog cursor", min_length=1, max_length=512
            )
        return self.get(
            "/api/v1/catalog/search",
            response_model=CatalogSearchPageV1,
            principal=principal,
            role=role,
            params=params,
        )

    def browse_catalog(
        self,
        *,
        library_id: str,
        parent_path: str = "",
        limit: int = 50,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogBrowsePageV1:
        params: dict[str, object] = {
            "library_id": self._validated_catalog_identifier(
                library_id, _SAFE_LIBRARY_ID, "catalog library id"
            ),
            "parent_path": self._validated_catalog_text(
                parent_path, "catalog parent path", max_length=4096
            ),
            "limit": self._validated_catalog_limit(limit),
        }
        if cursor is not None:
            params["cursor"] = self._validated_catalog_text(
                cursor, "catalog cursor", min_length=1, max_length=512
            )
        return self.get(
            "/api/v1/catalog/browse",
            response_model=CatalogBrowsePageV1,
            principal=principal,
            role=role,
            params=params,
        )

    def get_catalog_file_version(
        self,
        version_id: int,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogFileVersionV1:
        if (
            isinstance(version_id, bool)
            or not isinstance(version_id, int)
            or not 1 <= version_id <= 2**63 - 1
        ):
            raise ValueError("catalog file version id is invalid")
        return self.get(
            f"/api/v1/catalog/file-versions/{version_id}",
            response_model=CatalogFileVersionV1,
            principal=principal,
            role=role,
        )

    def get_catalog_restore_options(
        self, *, principal: str, role: Literal["admin", "operator"]
    ) -> CatalogRestoreOptionsV1:
        return self.get(
            "/api/v1/catalog/restore-options",
            response_model=CatalogRestoreOptionsV1,
            principal=principal,
            role=role,
        )

    def create_catalog_restore_plan(
        self,
        request: CreateCatalogRestorePlanRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestorePlanV1:
        return self._mutate(
            "POST",
            "/api/v1/catalog/restore-plans",
            self._model_payload(request),
            idempotency_key,
            response_model=CatalogRestorePlanV1,
            principal=principal,
            role=role,
        )

    def get_catalog_restore_plan(
        self,
        plan_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestorePlanV1:
        safe_id = self._validated_domain_identifier(plan_id, _SAFE_JOB_ID)
        return self.get(
            f"/api/v1/catalog/restore-plans/{safe_id}",
            response_model=CatalogRestorePlanV1,
            principal=principal,
            role=role,
        )

    def start_catalog_restore_run(
        self,
        plan_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1:
        safe_id = self._validated_domain_identifier(plan_id, _SAFE_JOB_ID)
        return self._mutate(
            "POST",
            f"/api/v1/catalog/restore-plans/{safe_id}/runs",
            self._model_payload(StartCatalogRestoreRunRequestV1()),
            idempotency_key,
            response_model=CatalogRestoreRunV1,
            principal=principal,
            role=role,
        )

    def get_catalog_restore_run(
        self,
        run_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1:
        safe_id = self._validated_domain_identifier(run_id, _SAFE_JOB_ID)
        return self.get(
            f"/api/v1/catalog/restore-runs/{safe_id}",
            response_model=CatalogRestoreRunV1,
            principal=principal,
            role=role,
        )

    def get_catalog_restore_run_cassette_result(
        self, run_id: str, cassette_sequence: int, *, principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunCassetteV1:
        safe_id = self._validated_domain_identifier(run_id, _SAFE_JOB_ID)
        if type(cassette_sequence) is not int or not 1 <= cassette_sequence <= 200:
            raise ValueError("restore cassette sequence is invalid")
        return self.get(
            f"/api/v1/catalog/restore-runs/{safe_id}/cassettes/{cassette_sequence}/result",
            response_model=CatalogRestoreRunCassetteV1, principal=principal, role=role,
        )

    def get_catalog_restore_run_item_result(
        self, run_id: str, item_sequence: int, *, principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunItemV1:
        safe_id = self._validated_domain_identifier(run_id, _SAFE_JOB_ID)
        if type(item_sequence) is not int or not 1 <= item_sequence <= 200:
            raise ValueError("restore item sequence is invalid")
        return self.get(
            f"/api/v1/catalog/restore-runs/{safe_id}/items/{item_sequence}/result",
            response_model=CatalogRestoreRunItemV1, principal=principal, role=role,
        )

    def pause_catalog_restore_run(
        self,
        run_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1:
        return self._restore_run_control(
            run_id, "pause", idempotency_key, principal=principal, role=role
        )

    def resume_catalog_restore_run(
        self,
        run_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1:
        return self._restore_run_control(
            run_id, "resume", idempotency_key, principal=principal, role=role
        )

    def cancel_catalog_restore_run(
        self,
        run_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1:
        return self._restore_run_control(
            run_id, "cancel", idempotency_key, principal=principal, role=role
        )

    def _restore_run_control(
        self,
        run_id: str,
        action: Literal["pause", "resume", "cancel"],
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CatalogRestoreRunV1:
        safe_id = self._validated_domain_identifier(run_id, _SAFE_JOB_ID)
        return self._mutate(
            "POST",
            f"/api/v1/catalog/restore-runs/{safe_id}/{action}",
            self._model_payload(RestoreRunControlRequestV1()),
            idempotency_key,
            response_model=CatalogRestoreRunV1,
            principal=principal,
            role=role,
        )

    def authorize_catalog_restore_item_replacement(
        self,
        run_id: str,
        item_sequence: int,
        request: AuthorizeCatalogRestoreItemReplacementRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
        reauthentication_context: WebReauthenticationContext,
    ) -> CatalogRestoreReplacementAuthorizationV1:
        safe_id = self._validated_domain_identifier(run_id, _SAFE_JOB_ID)
        if type(item_sequence) is not int or not 1 <= item_sequence <= 200:
            raise ValueError("restore item sequence is invalid")
        return self._mutate(
            "POST",
            f"/api/v1/catalog/restore-runs/{safe_id}/items/{item_sequence}/replacement-authorizations",
            self._model_payload(request),
            idempotency_key,
            response_model=CatalogRestoreReplacementAuthorizationV1,
            principal=principal,
            role=role,
            reauthentication_context=reauthentication_context,
        )

    def issue_catalog_restore_replacement_capability(
        self, idempotency_key: str, *, principal: str,
        role: Literal["admin", "operator"],
        reauthentication_context: WebReauthenticationContext,
    ) -> CatalogRestoreReplacementCapabilityV1:
        return self._mutate(
            "POST", "/api/v1/catalog/restore-replacement-capabilities",
            self._model_payload(IssueCatalogRestoreReplacementCapabilityRequestV1()),
            idempotency_key, response_model=CatalogRestoreReplacementCapabilityV1,
            principal=principal, role=role,
            reauthentication_context=reauthentication_context,
        )

    def list_jobs(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        include_retired: bool = False,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobListPageV1:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("job page limit is invalid")
        if cursor is not None and (
            not isinstance(cursor, str)
            or not cursor.isascii()
            or not cursor.isdecimal()
            or len(cursor) > 32
        ):
            raise ValueError("job page cursor is invalid")
        if not isinstance(include_retired, bool):
            raise ValueError("include_retired is invalid")
        params: dict[str, object] = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        if include_retired:
            params["include_retired"] = True
        return self.get(
            "/api/v1/jobs",
            response_model=JobListPageV1,
            principal=principal,
            role=role,
            params=params,
        )

    def get_job(
        self,
        job_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self.get(
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}",
            response_model=JobDetailV1,
            principal=principal,
            role=role,
        )

    def get_job_sequence_status(
        self,
        job_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobSequenceStatusV1:
        return self.get(
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}/sequence-status",
            response_model=JobSequenceStatusV1,
            principal=principal,
            role=role,
        )

    def get_job_cassettes(
        self,
        job_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobCassettePageV1:
        return self._get_job_page(
            job_id,
            "cassettes",
            JobCassettePageV1,
            limit=limit,
            cursor=cursor,
            principal=principal,
            role=role,
        )

    def get_incremental_policy(self, job_id: str, *, principal: str, role: Literal["admin", "operator"]) -> IncrementalPolicyV1:
        identifier = self._validated_domain_identifier(job_id, _SAFE_JOB_ID)
        return self.get(f"/api/v1/jobs/{identifier}/incremental-policy",response_model=IncrementalPolicyV1,principal=principal,role=role)

    def update_incremental_policy(self, job_id: str, request: UpdateIncrementalPolicyRequestV1, idempotency_key: str, *, principal: str, role: Literal["admin", "operator"]) -> IncrementalPolicyV1:
        identifier = self._validated_domain_identifier(job_id, _SAFE_JOB_ID)
        return self._mutate("PATCH",f"/api/v1/jobs/{identifier}/incremental-policy",request.model_dump(mode="json"),idempotency_key,response_model=IncrementalPolicyV1,principal=principal,role=role)

    def scan_job_now(self, job_id: str, idempotency_key: str, *, principal: str, role: Literal["admin", "operator"]) -> IncrementalScanResultV1:
        identifier = self._validated_domain_identifier(job_id, _SAFE_JOB_ID)
        return self._mutate("POST",f"/api/v1/jobs/{identifier}/incremental-scan",{},idempotency_key,response_model=IncrementalScanResultV1,principal=principal,role=role)

    def get_job_manifest(
        self,
        job_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobManifestPageV1:
        return self._get_job_page(
            job_id,
            "manifests",
            JobManifestPageV1,
            limit=limit,
            cursor=cursor,
            principal=principal,
            role=role,
        )

    def get_job_history(
        self,
        job_id: str,
        *,
        limit: int = 100,
        cursor: str | None = None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobHistoryPageV1:
        return self._get_job_page(
            job_id,
            "history",
            JobHistoryPageV1,
            limit=limit,
            cursor=cursor,
            principal=principal,
            role=role,
        )

    def _get_job_page(
        self,
        job_id: str,
        suffix: Literal["cassettes", "manifests", "history"],
        response_model: type[ResponseModelT],
        *,
        limit: int,
        cursor: str | None,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ResponseModelT:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("job page limit is invalid")
        if cursor is not None and (
            not isinstance(cursor, str)
            or not cursor.isascii()
            or not cursor.isdecimal()
            or len(cursor) > 32
        ):
            raise ValueError("job page cursor is invalid")
        params: dict[str, object] = {"limit": limit}
        if cursor is not None:
            params["cursor"] = cursor
        return self.get(
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}/{suffix}",
            response_model=response_model,
            principal=principal,
            role=role,
            params=params,
        )

    def start_job(
        self,
        job_id: str,
        request: JobCommandRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1:
        return self._job_operation(
            job_id,
            "start",
            request,
            idempotency_key,
            principal=principal,
            role=role,
        )

    def resume_job(
        self,
        job_id: str,
        request: JobCommandRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ResumeResponseV1:
        return self._mutate(
            "POST",
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}/resume",
            self._model_payload(request),
            idempotency_key,
            response_model=_RESUME_RESPONSE_ADAPTER,
            principal=principal,
            role=role,
        )

    def reset_failed_cassette(
        self,
        job_id: str,
        request: ResetFailedCassetteRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._mutate(
            "POST",
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}/failed-cassette/reset",
            self._model_payload(request),
            idempotency_key,
            response_model=JobDetailV1,
            principal=principal,
            role=role,
        )

    def _job_operation(
        self,
        job_id: str,
        action: Literal["start"],
        request: JobCommandRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1:
        return self._mutate(
            "POST",
            f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}/{action}",
            self._model_payload(request),
            idempotency_key,
            response_model=OperationResponseV1,
            principal=principal,
            role=role,
        )

    def _critical_recovery_path(self, operation_id: str) -> str:
        return (
            "/api/v1/critical-recovery/"
            + self._validated_domain_identifier(operation_id, _SAFE_JOB_ID)
        )

    def get_pre_media_reset(
        self, operation_id: str, *, principal: str, role: Literal["admin", "operator"],
    ) -> PreMediaResetProofV1:
        operation_id = self._validated_domain_identifier(operation_id, _SAFE_JOB_ID)
        return self.get(
            f"/api/v1/operations/{operation_id}/pre-media-reset",
            response_model=PreMediaResetProofV1, principal=principal, role=role,
        )

    def reset_pre_media_attempt(
        self, operation_id: str, request: ResetPreMediaAttemptRequestV1, idempotency_key: str,
        *, principal: str, role: Literal["admin", "operator"],
        reauthentication_context: WebReauthenticationContext,
    ) -> OperationResponseV1:
        operation_id = self._validated_domain_identifier(operation_id, _SAFE_JOB_ID)
        if request.operation_id != operation_id:
            raise DaemonProtocolError("pre-media reset request does not match the operation")
        return self._mutate(
            "POST", f"/api/v1/operations/{operation_id}/pre-media-reset",
            self._model_payload(request), idempotency_key, response_model=OperationResponseV1,
            principal=principal, role=role, reauthentication_context=reauthentication_context,
        )

    def get_critical_recovery(
        self,
        operation_id: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CriticalRecoveryProofV1:
        return self.get(
            self._critical_recovery_path(operation_id),
            response_model=CriticalRecoveryProofV1,
            principal=principal,
            role=role,
        )

    def reconcile_critical_recovery(
        self,
        operation_id: str,
        request: ReconcileCriticalRecoveryRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> CriticalRecoveryProofV1:
        return self._mutate(
            "POST",
            self._critical_recovery_path(operation_id) + "/reconcile",
            self._model_payload(request),
            idempotency_key,
            response_model=CriticalRecoveryProofV1,
            principal=principal,
            role=role,
        )

    def abandon_critical_recovery(
        self,
        operation_id: str,
        request: AbandonCriticalAttemptRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1:
        return self._mutate(
            "POST",
            self._critical_recovery_path(operation_id) + "/abandon",
            self._model_payload(request),
            idempotency_key,
            response_model=OperationResponseV1,
            principal=principal,
            role=role,
        )

    def authorize_critical_replacement(
        self,
        operation_id: str,
        request: AuthorizeReplacementAttemptRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> OperationResponseV1:
        return self._mutate(
            "POST",
            self._critical_recovery_path(operation_id) + "/authorize-replacement",
            self._model_payload(request),
            idempotency_key,
            response_model=OperationResponseV1,
            principal=principal,
            role=role,
        )

    def pause_job(
        self,
        job_id: str,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._job_detail_mutation(
            "POST", job_id, "pause", {}, idempotency_key, principal, role
        )

    def update_job(
        self,
        job_id: str,
        request: UpdateJobRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._job_detail_mutation(
            "PATCH",
            job_id,
            None,
            self._model_payload(request),
            idempotency_key,
            principal,
            role,
        )

    def reserve_job_labels(
        self,
        job_id: str,
        request: ReserveJobLabelsRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._job_detail_mutation(
            "POST",
            job_id,
            "reserve-labels",
            self._model_payload(request),
            idempotency_key,
            principal,
            role,
        )

    def extend_job(
        self,
        job_id: str,
        request: ExtendJobRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._job_detail_mutation(
            "POST",
            job_id,
            "extensions",
            self._model_payload(request),
            idempotency_key,
            principal,
            role,
        )

    def retire_job(
        self,
        job_id: str,
        request: RetireJobRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        return self._job_detail_mutation(
            "POST",
            job_id,
            "retire",
            self._model_payload(request),
            idempotency_key,
            principal,
            role,
        )

    def _job_detail_mutation(
        self,
        method: Literal["POST", "PATCH"],
        job_id: str,
        suffix: str | None,
        payload: dict[str, object],
        idempotency_key: str,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> JobDetailV1:
        path = f"/api/v1/jobs/{self._validated_domain_identifier(job_id, _SAFE_JOB_ID)}"
        if suffix is not None:
            path += f"/{suffix}"
        return self._mutate(
            method,
            path,
            payload,
            idempotency_key,
            response_model=JobDetailV1,
            principal=principal,
            role=role,
        )

    def get_application_settings(
        self,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ApplicationSettingsV1:
        return self.get(
            "/api/v1/settings/application",
            response_model=ApplicationSettingsV1,
            principal=principal,
            role=role,
        )

    def update_application_settings(
        self,
        request: UpdateApplicationSettingsRequestV1,
        idempotency_key: str,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> ApplicationSettingsV1:
        return self._mutate(
            "PUT",
            "/api/v1/settings/application",
            self._model_payload(request),
            idempotency_key,
            response_model=ApplicationSettingsV1,
            principal=principal,
            role=role,
        )

    def get_host_settings(
        self,
        *,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> HostSettingsV1:
        return self.get(
            "/api/v1/settings/host",
            response_model=HostSettingsV1,
            principal=principal,
            role=role,
        )

    def get_system_logs(
        self,
        *,
        source: str,
        severity: str,
        range: str,
        direction: str,
        cursor: str | None,
        search: str | None,
        limit: int,
        principal: str,
        role: Literal["admin", "operator"],
    ) -> SystemLogsPageV1:
        query = SystemLogQuery(
            source=source,
            severity=severity,
            range=range,
            direction=direction,
            cursor=cursor,
            search=search,
            limit=limit,
        )
        parameters: list[tuple[str, str | int]] = [
            ("source", query.source.value),
            ("severity", query.severity.value),
            ("range", query.range.value),
            ("direction", query.direction.value),
            ("limit", query.limit),
        ]
        if query.cursor is not None:
            parameters.append(("cursor", query.cursor))
        if query.search is not None:
            parameters.append(("search", query.search))
        return self.get(
            f"/api/v1/system-logs?{urlencode(parameters)}",
            response_model=SystemLogsPageV1,
            principal=principal,
            role=role,
        )

    def _send(
        self,
        method: str,
        path: str,
        *,
        stream: bool = False,
        **kwargs: object,
    ) -> httpx.Response:
        request = self._build_request(method, path, **kwargs)
        return self._send_request(request, stream=stream)

    def _build_request(
        self,
        method: str,
        path: str,
        **kwargs: object,
    ) -> httpx.Request:
        request: httpx.Request | None = None
        request_invalid = False
        try:
            request = self._client.build_request(method, path, **kwargs)
        except (httpx.InvalidURL, UnicodeError, ValueError, TypeError):
            request_invalid = True
        if request_invalid:
            raise DaemonProtocolError("invalid daemon request") from None
        assert request is not None
        return request

    def _send_request(
        self,
        request: httpx.Request,
        *,
        stream: bool = False,
    ) -> httpx.Response:
        response: httpx.Response | None = None
        request_invalid = False
        try:
            response = self._client.send(request, stream=stream)
        except httpx.LocalProtocolError:
            request_invalid = True
        except httpx.TransportError:
            pass
        if request_invalid:
            raise DaemonProtocolError("invalid daemon request") from None
        if response is None:
            raise DaemonUnavailable()
        return response

    @staticmethod
    def _validated_wire_header(value: object, pattern: re.Pattern[str]) -> str:
        if (
            not isinstance(value, str)
            or not value.isascii()
            or pattern.fullmatch(value) is None
        ):
            raise DaemonProtocolError("invalid daemon request") from None
        return value

    @staticmethod
    def _validated_role(value: object) -> Literal["admin", "operator"]:
        if value not in _AUTHENTICATED_ROLES:
            raise DaemonProtocolError("invalid daemon request") from None
        return value

    @staticmethod
    def _validated_management_identifier(value: object) -> str:
        return UnixDaemonClient._validated_wire_header(value, _SAFE_WIRE_PRINCIPAL)

    @staticmethod
    def _validated_domain_identifier(value: object, pattern: re.Pattern[str]) -> str:
        return UnixDaemonClient._validated_wire_header(value, pattern)

    @staticmethod
    def _validated_catalog_text(
        value: object,
        name: str,
        *,
        min_length: int = 0,
        max_length: int,
    ) -> str:
        if not isinstance(value, str) or not min_length <= len(value) <= max_length:
            raise ValueError(f"{name} is invalid")
        return value

    @staticmethod
    def _validated_catalog_identifier(
        value: object,
        pattern: re.Pattern[str],
        name: str,
    ) -> str:
        if not isinstance(value, str) or pattern.fullmatch(value) is None:
            raise ValueError(f"{name} is invalid")
        return value

    @staticmethod
    def _validated_catalog_sha256(value: object) -> str:
        if (
            not isinstance(value, str)
            or re.fullmatch(r"[0-9A-Fa-f]{64}", value) is None
        ):
            raise ValueError("catalog sha256 is invalid")
        return value

    @staticmethod
    def _validated_catalog_size(value: object, name: str) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 2**63 - 1
        ):
            raise ValueError(f"catalog {name} size is invalid")
        return value

    @staticmethod
    def _validated_catalog_bool(value: object, name: str) -> bool:
        if not isinstance(value, bool):
            raise TypeError(f"{name} is invalid")
        return value

    @staticmethod
    def _validated_catalog_limit(value: object) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1 <= value <= 200
        ):
            raise ValueError("catalog page limit is invalid")
        return value

    @staticmethod
    def _require_success(response: httpx.Response) -> None:
        if response.is_success:
            return
        error_code: str | None = None
        payload = bytearray()
        for chunk in response.iter_bytes():
            remaining = _MAX_PUBLIC_ERROR_BODY_BYTES + 1 - len(payload)
            payload.extend(chunk[:remaining])
            if len(payload) > _MAX_PUBLIC_ERROR_BODY_BYTES:
                payload.clear()
                break
        public_error: PublicErrorV1 | None = None
        if payload:
            try:
                public_error = PublicErrorV1.model_validate_json(payload)
            except (TypeError, ValueError, ValidationError):
                pass
        if public_error is not None and re.fullmatch(
            r"[a-z][a-z0-9_]{0,63}", public_error.error.code
        ):
            error_code = public_error.error.code
        raise DaemonRequestError(response.status_code, error_code)

    @staticmethod
    def _parse_model(
        response: httpx.Response,
        response_model: type[ResponseModelT] | TypeAdapter[ResponseModelT],
    ) -> ResponseModelT:
        try:
            if isinstance(response_model, TypeAdapter):
                return response_model.validate_python(response.json())
            return response_model.model_validate(response.json())
        except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
            raise DaemonProtocolError("invalid daemon response") from None

    @staticmethod
    def _bounded_diagnostic_bytes(response: httpx.Response) -> bytes:
        payload = bytearray()
        try:
            for chunk in response.iter_bytes():
                remaining = _MAX_DIAGNOSTIC_DOWNLOAD_BYTES + 1 - len(payload)
                payload.extend(chunk[:remaining])
                if len(payload) > _MAX_DIAGNOSTIC_DOWNLOAD_BYTES:
                    raise DaemonProtocolError("invalid diagnostic download")
        except httpx.TransportError:
            raise
        except DaemonProtocolError:
            raise
        except (RuntimeError, ValueError):
            raise DaemonProtocolError("invalid diagnostic download") from None
        return bytes(payload)

    @staticmethod
    def _validated_events(
        lines: Iterator[str],
        resume_cursor: int | None,
    ) -> Iterator[dict[str, object]]:
        fields: dict[str, list[str]] = {}
        previous_id = 0 if resume_cursor is None else resume_cursor
        received_event = False

        def parse_pending() -> dict[str, object] | None:
            nonlocal previous_id, received_event
            if not fields:
                return None
            if set(fields) != {"id", "event", "data"}:
                raise DaemonProtocolError("invalid daemon event stream")
            if len(fields["id"]) != 1 or len(fields["event"]) != 1:
                raise DaemonProtocolError("invalid daemon event stream")

            raw_id = fields["id"][0]
            if not raw_id.isascii() or not raw_id.isdecimal():
                raise DaemonProtocolError("invalid daemon event stream")
            event_id = int(raw_id)
            event_type = fields["event"][0]
            if event_id <= 0:
                raise DaemonProtocolError("invalid daemon event stream")
            if event_type not in {
                "state.replace",
                "state.patch",
                "library.changed",
                "share.changed",
            }:
                raise DaemonProtocolError("invalid daemon event stream")
            if event_type != "state.replace" and not received_event:
                if resume_cursor is None:
                    raise DaemonProtocolError(
                        "fresh daemon event stream must replace state"
                    )
                if event_id != previous_id + 1:
                    raise DaemonProtocolError("daemon event IDs are not contiguous")
            elif event_type != "state.replace" and event_id != previous_id + 1:
                raise DaemonProtocolError("daemon event IDs are not contiguous")
            elif received_event and event_id <= previous_id:
                raise DaemonProtocolError("daemon event IDs are not increasing")

            try:
                data = json.loads("\n".join(fields["data"]))
                if event_type == "state.replace":
                    state = DaemonStatusV1.model_validate(data)
                    serialized_data = state.model_dump(mode="json")
                elif event_type == "state.patch":
                    state = StatusPatchV1.model_validate(data)
                    serialized_data = state.model_dump(
                        mode="json",
                        exclude_unset=True,
                    )
                elif event_type == "library.changed":
                    state = LibraryChangedV1.model_validate(data)
                    serialized_data = state.model_dump(mode="json")
                else:
                    state = ShareChangedV1.model_validate(data)
                    serialized_data = state.model_dump(mode="json")
                envelope = EventEnvelopeV1.model_validate(
                    {
                        "api_version": SUPPORTED_DAEMON_API_VERSION,
                        "id": event_id,
                        "event": event_type,
                        "data": serialized_data,
                    }
                )
            except DaemonProtocolError:
                raise
            except (TypeError, ValueError, ValidationError, json.JSONDecodeError):
                raise DaemonProtocolError("invalid daemon event stream") from None

            previous_id = event_id
            received_event = True
            return {
                "api_version": envelope.api_version,
                "id": envelope.id,
                "event": envelope.event,
                "data": serialized_data,
            }

        for line in lines:
            if line == "":
                parsed = parse_pending()
                fields = {}
                if parsed is not None:
                    yield parsed
                continue
            if line.startswith(":"):
                continue
            field, separator, raw_value = line.partition(":")
            if not separator or field not in {"id", "event", "data"}:
                raise DaemonProtocolError("invalid daemon event stream")
            value = raw_value.removeprefix(" ")
            fields.setdefault(field, []).append(value)

        parsed = parse_pending()
        if parsed is not None:
            yield parsed
