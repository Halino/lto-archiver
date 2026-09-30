from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager
from dataclasses import asdict
from typing import Annotated

from fastapi import Depends, FastAPI, Header, Path, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from ..errors import CutoverAuthorizationInvalid
from .api_models import (
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
    CreateNativeJobRequestV1,
    CreateShareRequestV1,
    CriticalRecoveryProofV1,
    CutoverAuthorizationRequestV1,
    DaemonStatusV1,
    DiagnosticSummaryV1,
    EventEnvelopeV1,
    ExtendJobRequestV1,
    HealthV1,
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
    LibrarySummaryV1,
    LogsPageV1,
    MediaProfilesV1,
    NetworkShareOptionsV1,
    OperationConflictV1,
    OperationRequest,
    OperationResponseV1,
    PreMediaResetProofV1,
    ResetPreMediaAttemptRequestV1,
    PublicErrorV1,
    ReconcileCriticalRecoveryRequestV1,
    ReserveJobLabelsRequestV1,
    ResetFailedCassetteRequestV1,
    RestoreRunControlRequestV1,
    ResumeArchiveRequestV1,
    RetireJobRequestV1,
    RetireLibraryRequestV1,
    SafeErrorV1,
    SettingsSummaryV1,
    ShareConfirmedOperationRequestV1,
    ShareCredentialClearRequestV1,
    ShareCredentialRequestV1,
    ShareOperationRequestV1,
    ShareOperationV1,
    ShareRemoveRequestV1,
    ShareRetireRequestV1,
    ShareSummaryV1,
    ShareV1,
    SignedAcceptanceReportV1,
    StartCatalogRestoreRunRequestV1,
    StorageSummaryV1,
    SystemLogQuery,
    SystemLogsPageV1,
    UpdateApplicationSettingsRequestV1,
    UpdateIncrementalPolicyRequestV1,
    UpdateJobRequestV1,
    UpdateLibraryRequestV1,
    UpdateShareRequestV1,
)
from .incremental import IncrementalScheduler
from .management import (
    ApplicationSettingsIdempotencyConflict,
    ApplicationSettingsManagementError,
    ApplicationSettingsRevisionConflict,
    IdempotencyConflict,
    JobConfirmationMismatch,
    JobImportedFrozen,
    JobManagementError,
    JobNotFound,
    JobPlanError,
    JobRevisionConflict,
    JobStateConflict,
    LibraryAlreadyExists,
    LibraryConfirmationMismatch,
    LibraryInUse,
    LibraryManagementError,
    LibraryNotFound,
    LibraryPathInvalid,
    LibrarySourceChanged,
    LibraryStateConflict,
    ShareBusy,
    ShareConfirmationMismatch,
    ShareManagementError,
    ShareNotFound,
    ShareRevisionConflict,
)
from .models import MutationAdmissionClosed, OperationConflict
from .service import (
    PEER_CREDENTIAL_SCOPE_KEY,
    CatalogFileVersionNotFound,
    CatalogLibraryNotFound,
    CatalogQueryInvalid,
    CatalogRestorePlanConflict,
    CatalogRestorePlanInvalid,
    CatalogRestorePlanNotFound,
    CatalogRestoreRunConflict,
    CatalogRestoreRunInvalid,
    CatalogRestoreRunNotFound,
    CriticalRecoveryNotFound,
    CriticalRecoveryRejected,
    DaemonService,
    FormatConfirmationMismatch,
    FormatConfirmationRequired,
    FormatRequiresAdmin,
    OperationReplayConflict,
    PreMediaResetNotFound,
    PreMediaResetRejected,
    Principal,
    RestoreCoordinatorUnavailable,
    RoleDenied,
    UntrustedPeer,
)

__all__ = ["PEER_CREDENTIAL_SCOPE_KEY", "create_app", "resolve_sse_cursor"]


class InvalidEventCursor(ValueError):
    pass


IdempotencyHeader = Annotated[
    str,
    Header(
        alias="Idempotency-Key",
        min_length=1,
        max_length=128,
        pattern=r".*\S.*",
    ),
]
SafeJobIdPath = Annotated[
    str,
    Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
]
SafeLibraryIdPath = Annotated[
    str,
    Path(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"),
]
SafeShareIdPath = Annotated[
    str,
    Path(min_length=1, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{0,62}$"),
]
SafeShareOperationIdPath = Annotated[
    str,
    Path(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$"),
]
CatalogFileVersionIdPath = Annotated[
    int,
    Path(ge=1, le=9_223_372_036_854_775_807),
]


def resolve_sse_cursor(header: str | None, query: int | None) -> int | None:
    header_cursor: int | None = None
    if header is not None:
        try:
            header_cursor = int(header)
        except ValueError as exc:
            raise InvalidEventCursor(
                "event cursor must be a non-negative integer"
            ) from exc
        if header_cursor < 0:
            raise InvalidEventCursor("event cursor must be a non-negative integer")
    if header_cursor is not None and query is not None and header_cursor != query:
        raise InvalidEventCursor("header and query event cursors do not match")
    return header_cursor if header_cursor is not None else query


def _safe_error(code: str, message: str) -> dict:
    return PublicErrorV1(error=SafeErrorV1(code=code, message=message)).model_dump(
        mode="json"
    )


def create_app(service: DaemonService) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        service.startup()
        scheduler = IncrementalScheduler(service.incremental_coordinator())
        task = asyncio.create_task(scheduler.run(), name="lto-incremental-scheduler")
        try:
            yield
        finally:
            scheduler.stop()
            await task
            service.shutdown()

    app = FastAPI(
        title="LTO Archiver Daemon API",
        version="1",
        lifespan=lifespan,
    )
    principal_dependency = Depends(service.principals.require_mutation_principal)
    operator_dependency = Depends(service.principals.require_operator)
    admin_dependency = Depends(service.principals.require_admin)
    direct_admin_dependency = Depends(service.principals.require_direct_local_admin)

    def settings_principal(
        request: Request,
        principal: Principal = principal_dependency,
    ) -> Principal:
        request.state.settings_principal = principal
        return principal

    settings_principal_dependency = Depends(settings_principal)

    def share_mutation_name(request: Request) -> str:
        path = request.url.path
        suffix = path.rsplit("/", 1)[-1]
        if request.method == "POST" and path == "/api/v1/network-shares":
            return "create"
        if request.method == "PATCH":
            return "update"
        if suffix == "credential":
            return (
                "credential.install" if request.method == "PUT" else "credential.clear"
            )
        if suffix in {"connect", "disconnect", "reconcile", "retire", "test"}:
            return suffix
        return "remove"

    def share_principal(
        request: Request,
        principal: Principal = principal_dependency,
    ) -> Principal:
        request.state.share_principal = principal
        try:
            service.authorize_command(principal, capability="library.manage")
        except Exception as exc:
            service.record_share_mutation_rejection(
                principal,
                share_mutation_name(request),
                exc,
                request.path_params.get("share_id"),
                request.headers.get("Idempotency-Key"),
                None,
            )
            raise
        return principal

    share_principal_dependency = Depends(share_principal)

    @app.exception_handler(OperationConflict)
    async def operation_conflict(_request: Request, exc: OperationConflict):
        body = OperationConflictV1(
            error=SafeErrorV1(
                code="active_operation",
                message="another mutating operation is active",
            ),
            active_operation=OperationResponseV1.model_validate(asdict(exc.active)),
        )
        return JSONResponse(status_code=409, content=body.model_dump(mode="json"))

    @app.exception_handler(MutationAdmissionClosed)
    async def mutation_closed(_request: Request, _exc: MutationAdmissionClosed):
        return JSONResponse(
            status_code=503,
            content=_safe_error(
                "startup_reconciliation",
                "mutation admission is closed during startup reconciliation",
            ),
        )

    @app.exception_handler(UntrustedPeer)
    async def untrusted_peer(request: Request, _exc: UntrustedPeer):
        if (
            request.method == "PUT"
            and request.url.path == "/api/v1/settings/application"
        ):
            service.record_application_settings_rejection("unknown", "untrusted_peer")
        return JSONResponse(
            status_code=403,
            content=_safe_error(
                "untrusted_peer",
                "trusted Unix peer credentials are required",
            ),
        )

    @app.exception_handler(FormatRequiresAdmin)
    async def format_requires_admin(_request: Request, _exc: FormatRequiresAdmin):
        return JSONResponse(
            status_code=403,
            content=_safe_error(
                "format_requires_admin",
                "formatting media requires an admin role",
            ),
        )

    @app.exception_handler(RoleDenied)
    async def role_denied(_request: Request, _exc: RoleDenied):
        return JSONResponse(
            status_code=403,
            content=_safe_error(
                "role_denied", "the authenticated role is not permitted"
            ),
        )

    @app.exception_handler(CatalogQueryInvalid)
    async def catalog_query_invalid(_request: Request, _exc: CatalogQueryInvalid):
        return JSONResponse(
            status_code=422,
            content=_safe_error("validation_error", "the request is invalid"),
        )

    @app.exception_handler(CatalogFileVersionNotFound)
    async def catalog_file_version_not_found(
        _request: Request, _exc: CatalogFileVersionNotFound
    ):
        return JSONResponse(
            status_code=404,
            content=_safe_error(
                "catalog_file_version_not_found",
                "the requested catalog file version was not found",
            ),
        )

    @app.exception_handler(CatalogLibraryNotFound)
    async def catalog_library_not_found(
        _request: Request, _exc: CatalogLibraryNotFound
    ):
        return JSONResponse(
            status_code=404,
            content=_safe_error(
                "catalog_library_not_found",
                "the requested catalog library was not found",
            ),
        )

    @app.exception_handler(CatalogRestorePlanNotFound)
    async def catalog_restore_plan_not_found(
        _request: Request, _exc: CatalogRestorePlanNotFound
    ):
        return JSONResponse(
            status_code=404,
            content=_safe_error(
                "restore_plan_not_found",
                "the requested restore plan was not found",
            ),
        )

    @app.exception_handler(CatalogRestorePlanInvalid)
    async def catalog_restore_plan_invalid(
        _request: Request, _exc: CatalogRestorePlanInvalid
    ):
        return JSONResponse(
            status_code=422,
            content=_safe_error(
                "restore_plan_invalid",
                "the restore plan selection or destination is invalid",
            ),
        )

    @app.exception_handler(CatalogRestorePlanConflict)
    async def catalog_restore_plan_conflict(
        _request: Request, _exc: CatalogRestorePlanConflict
    ):
        return JSONResponse(
            status_code=409,
            content=_safe_error(
                "idempotency_conflict",
                "the restore plan request conflicts with a previous request",
            ),
        )

    @app.exception_handler(CatalogRestoreRunNotFound)
    async def catalog_restore_run_not_found(
        _request: Request, _exc: CatalogRestoreRunNotFound
    ):
        return JSONResponse(
            status_code=404,
            content=_safe_error("restore_run_not_found", "the restore run was not found"),
        )

    @app.exception_handler(CatalogRestoreRunInvalid)
    async def catalog_restore_run_invalid(
        _request: Request, _exc: CatalogRestoreRunInvalid
    ):
        return JSONResponse(
            status_code=409,
            content=_safe_error(
                "restore_run_state_conflict",
                "the restore run is not in a safe state for this action",
            ),
        )

    @app.exception_handler(CatalogRestoreRunConflict)
    async def catalog_restore_run_conflict(
        _request: Request, _exc: CatalogRestoreRunConflict
    ):
        return JSONResponse(
            status_code=409,
            content=_safe_error(
                "idempotency_conflict",
                "the restore run request conflicts with a previous request",
            ),
        )

    @app.exception_handler(RestoreCoordinatorUnavailable)
    async def restore_coordinator_unavailable(
        _request: Request, _exc: RestoreCoordinatorUnavailable
    ):
        return JSONResponse(
            status_code=503,
            content=_safe_error(
                "restore_coordinator_unavailable",
                "restore control is temporarily unavailable",
            ),
        )

    @app.exception_handler(OperationReplayConflict)
    async def operation_replay_conflict(
        _request: Request, _exc: OperationReplayConflict
    ):
        return JSONResponse(
            status_code=409,
            content=_safe_error(
                "idempotency_conflict",
                "the operation key conflicts with a previous request",
            ),
        )

    @app.exception_handler(PreMediaResetNotFound)
    async def pre_media_reset_not_found(_request: Request, _exc: PreMediaResetNotFound):
        return JSONResponse(status_code=404, content=_safe_error(
            "pre_media_reset_not_found", "the requested operation is unavailable",
        ))

    @app.exception_handler(PreMediaResetRejected)
    async def pre_media_reset_rejected(_request: Request, _exc: PreMediaResetRejected):
        return JSONResponse(status_code=409, content=_safe_error(
            "pre_media_reset_rejected", "the attempt cannot be safely reset with the current evidence",
        ))

    @app.exception_handler(CriticalRecoveryNotFound)
    async def critical_recovery_not_found(
        _request: Request, _exc: CriticalRecoveryNotFound
    ):
        return JSONResponse(
            status_code=404,
            content=_safe_error(
                "critical_recovery_not_found",
                "critical recovery evidence is not available",
            ),
        )

    @app.exception_handler(CriticalRecoveryRejected)
    async def critical_recovery_rejected(
        _request: Request, _exc: CriticalRecoveryRejected
    ):
        return JSONResponse(
            status_code=409,
            content=_safe_error(
                "critical_recovery_rejected",
                "the protected critical recovery action was rejected",
            ),
        )

    @app.exception_handler(LibraryManagementError)
    async def library_error(_request: Request, exc: LibraryManagementError):
        if isinstance(exc, LibraryNotFound):
            status_code = 404
            message = "the requested library was not found"
        elif isinstance(
            exc,
            (
                IdempotencyConflict,
                LibraryAlreadyExists,
                LibraryInUse,
                LibrarySourceChanged,
                LibraryStateConflict,
            ),
        ):
            status_code = 409
            message = "the library operation conflicts with current state"
        elif isinstance(exc, LibraryConfirmationMismatch):
            status_code = 422
            message = "the library retirement confirmation does not match"
        elif isinstance(exc, LibraryPathInvalid):
            status_code = 422
            message = "the library source root is invalid or unavailable"
        else:
            status_code = 422
            message = "the library operation could not be completed"
        return JSONResponse(
            status_code=status_code,
            content=_safe_error(exc.code, message),
        )

    @app.exception_handler(JobManagementError)
    async def job_error(_request: Request, exc: JobManagementError):
        if isinstance(exc, JobNotFound):
            status_code = 404
            message = "the requested job was not found"
        elif isinstance(exc, JobConfirmationMismatch):
            status_code = 422
            message = "the job confirmation does not match"
        elif isinstance(
            exc, (JobStateConflict, JobImportedFrozen, JobRevisionConflict, IdempotencyConflict)
        ):
            status_code = 409
            message = "the job operation conflicts with current state"
        else:
            status_code = 422
            message = "the job operation could not be completed"
        return JSONResponse(
            status_code=status_code,
            content=_safe_error(exc.code, message),
        )

    @app.exception_handler(JobPlanError)
    async def job_plan_error(_request: Request, exc: JobPlanError):
        return JSONResponse(
            status_code=409,
            content=_safe_error(
                exc.code,
                "the job plan conflicts with current catalog or source state",
            ),
        )

    @app.exception_handler(ApplicationSettingsManagementError)
    async def application_settings_error(
        _request: Request, exc: ApplicationSettingsManagementError
    ):
        status_code = (
            409
            if isinstance(
                exc,
                (
                    ApplicationSettingsRevisionConflict,
                    ApplicationSettingsIdempotencyConflict,
                ),
            )
            else 422
        )
        return JSONResponse(
            status_code=status_code,
            content=_safe_error(
                exc.code,
                "the application settings operation conflicts with current state"
                if status_code == 409
                else "the application settings candidate is invalid",
            ),
        )

    @app.exception_handler(ShareManagementError)
    async def managed_share_error(_request: Request, exc: ShareManagementError):
        if isinstance(exc, ShareNotFound):
            status_code = 404
            message = "the requested network share was not found"
        elif isinstance(exc, ShareConfirmationMismatch):
            status_code = 422
            message = "the network share confirmation does not match"
        elif isinstance(exc, (ShareBusy, ShareRevisionConflict)) or exc.code in {
            "idempotency_conflict",
            "share_busy",
            "share_connected",
            "share_in_use",
            "share_state_conflict",
        }:
            status_code = 409
            message = "the network share operation conflicts with current state"
        else:
            status_code = 422
            message = "the network share operation could not be completed"
        return JSONResponse(
            status_code=status_code,
            content=_safe_error(exc.code, message),
        )

    @app.exception_handler(InvalidEventCursor)
    async def invalid_event_cursor(_request: Request, _exc: InvalidEventCursor):
        return JSONResponse(
            status_code=400,
            content=_safe_error(
                "invalid_event_cursor",
                "event cursors must be non-negative and agree",
            ),
        )

    @app.exception_handler(FormatConfirmationRequired)
    async def format_confirmation_required(
        _request: Request, _exc: FormatConfirmationRequired
    ):
        return JSONResponse(
            status_code=422,
            content=_safe_error(
                "format_confirmation_required",
                "the expected tape label must be confirmed before formatting",
            ),
        )

    @app.exception_handler(FormatConfirmationMismatch)
    async def format_confirmation_mismatch(
        _request: Request, _exc: FormatConfirmationMismatch
    ):
        return JSONResponse(
            status_code=422,
            content=_safe_error(
                "format_confirmation_mismatch",
                "the format confirmation does not match the expected tape label",
            ),
        )

    @app.exception_handler(CutoverAuthorizationInvalid)
    async def cutover_authorization_invalid(
        _request: Request, _exc: CutoverAuthorizationInvalid
    ):
        return JSONResponse(
            status_code=422,
            content=_safe_error(
                "cutover_authorization_invalid",
                "the cassette-four authorization is invalid",
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def request_validation(request: Request, _exc: RequestValidationError):
        if (
            request.method == "PUT"
            and request.url.path == "/api/v1/settings/application"
        ):
            principal = getattr(request.state, "settings_principal", None)
            service.record_application_settings_rejection(
                principal.name if isinstance(principal, Principal) else "unknown",
                "validation_error",
            )
        elif request.method in {"DELETE", "PATCH", "POST", "PUT"} and (
            request.url.path.startswith("/api/v1/network-shares")
        ):
            principal = getattr(request.state, "share_principal", None)
            service.record_share_mutation_rejection(
                principal if isinstance(principal, Principal) else "unknown",
                share_mutation_name(request),
                "validation_error",
                request.path_params.get("share_id"),
                request.headers.get("Idempotency-Key"),
                None,
            )
        return JSONResponse(
            status_code=422,
            content=_safe_error("validation_error", "the request is invalid"),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_request: Request, exc: StarletteHTTPException):
        code = "not_found" if exc.status_code == 404 else "http_error"
        message = (
            "the requested resource was not found"
            if exc.status_code == 404
            else "the request could not be completed"
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=_safe_error(code, message),
        )

    @app.exception_handler(Exception)
    async def internal_error(_request: Request, _exc: Exception):
        return JSONResponse(
            status_code=500,
            content=_safe_error("internal_error", "the request could not be completed"),
        )

    @app.get("/api/v1/health", response_model=HealthV1)
    def health() -> HealthV1:
        return HealthV1(status="ok")

    @app.get("/api/v1/status", response_model=DaemonStatusV1)
    def status() -> DaemonStatusV1:
        return service.status()

    @app.get("/api/v1/diagnostics/summary", response_model=DiagnosticSummaryV1)
    def diagnostics_summary(
        _principal: Principal = principal_dependency,
    ) -> DiagnosticSummaryV1:
        return service.diagnostics_summary()

    @app.get("/api/v1/storage", response_model=StorageSummaryV1)
    def storage_summary(
        _principal: Principal = principal_dependency,
    ) -> StorageSummaryV1:
        return service.storage_summary()

    @app.get("/api/v1/diagnostics/export")
    def diagnostics_export(
        _principal: Principal = principal_dependency,
    ) -> Response:
        return Response(
            content=service.diagnostics_export(),
            media_type="application/zip",
            headers={
                "Content-Disposition": 'attachment; filename="lto-diagnostics.zip"',
            },
        )

    @app.get("/api/v1/settings", response_model=SettingsSummaryV1)
    def settings() -> SettingsSummaryV1:
        return service.settings_summary()

    @app.get("/api/v1/settings/application", response_model=ApplicationSettingsV1)
    def application_settings(
        principal: Principal = admin_dependency,
    ) -> ApplicationSettingsV1:
        return service.application_settings(principal)

    @app.put("/api/v1/settings/application", response_model=ApplicationSettingsV1)
    async def update_application_settings(
        settings_request: UpdateApplicationSettingsRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = settings_principal_dependency,
    ) -> ApplicationSettingsV1:
        return await service.update_application_settings(
            settings_request, idempotency_key.strip(), principal
        )

    @app.get("/api/v1/settings/host", response_model=HostSettingsV1)
    def host_settings(
        principal: Principal = admin_dependency,
    ) -> HostSettingsV1:
        return service.host_settings(principal)

    @app.get("/api/v1/network-shares", response_model=list[ShareSummaryV1])
    def network_shares(
        principal: Principal = principal_dependency,
    ) -> tuple[ShareSummaryV1, ...]:
        return service.list_network_shares(principal)

    @app.get("/api/v1/network-share-options", response_model=NetworkShareOptionsV1)
    def network_share_options(
        principal: Principal = principal_dependency,
    ) -> NetworkShareOptionsV1:
        return service.network_share_options(principal)

    @app.post("/api/v1/network-shares", status_code=201, response_model=ShareV1)
    def create_network_share(
        share_request: CreateShareRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareV1:
        return service.create_network_share(
            share_request, idempotency_key.strip(), principal
        )

    @app.get("/api/v1/network-shares/{share_id}", response_model=ShareV1)
    def network_share_detail(
        share_id: SafeShareIdPath,
        principal: Principal = admin_dependency,
    ) -> ShareV1:
        return service.get_network_share(share_id, principal)

    @app.patch("/api/v1/network-shares/{share_id}", response_model=ShareV1)
    def update_network_share(
        share_id: SafeShareIdPath,
        share_request: UpdateShareRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareV1:
        return service.update_network_share(
            share_id, share_request, idempotency_key.strip(), principal
        )

    @app.put(
        "/api/v1/network-shares/{share_id}/credential",
        status_code=202,
        response_model=ShareOperationV1,
    )
    def install_network_share_credential(
        share_id: SafeShareIdPath,
        credential_request: ShareCredentialRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareOperationV1:
        return service.mutate_network_share_credential(
            share_id,
            credential_request,
            idempotency_key.strip(),
            principal,
        )

    @app.delete(
        "/api/v1/network-shares/{share_id}/credential",
        status_code=202,
        response_model=ShareOperationV1,
    )
    def clear_network_share_credential(
        share_id: SafeShareIdPath,
        credential_request: ShareCredentialClearRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareOperationV1:
        return service.mutate_network_share_credential(
            share_id,
            credential_request,
            idempotency_key.strip(),
            principal,
        )

    def start_share_action(
        share_id: str,
        action: str,
        share_request: ShareOperationRequestV1 | ShareConfirmedOperationRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareOperationV1:
        return service.start_network_share_operation(
            share_id,
            action,
            share_request,
            idempotency_key.strip(),
            principal,
        )

    @app.post(
        "/api/v1/network-shares/{share_id}/test",
        status_code=202,
        response_model=ShareOperationV1,
    )
    def test_network_share(
        share_id: SafeShareIdPath,
        share_request: ShareOperationRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareOperationV1:
        return start_share_action(
            share_id, "test", share_request, idempotency_key, principal
        )

    @app.post(
        "/api/v1/network-shares/{share_id}/connect",
        status_code=202,
        response_model=ShareOperationV1,
    )
    def connect_network_share(
        share_id: SafeShareIdPath,
        share_request: ShareOperationRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareOperationV1:
        return start_share_action(
            share_id, "connect", share_request, idempotency_key, principal
        )

    @app.post(
        "/api/v1/network-shares/{share_id}/disconnect",
        status_code=202,
        response_model=ShareOperationV1,
    )
    def disconnect_network_share(
        share_id: SafeShareIdPath,
        share_request: ShareConfirmedOperationRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareOperationV1:
        return start_share_action(
            share_id, "disconnect", share_request, idempotency_key, principal
        )

    @app.post(
        "/api/v1/network-shares/{share_id}/reconcile",
        status_code=202,
        response_model=ShareOperationV1,
    )
    def reconcile_network_share(
        share_id: SafeShareIdPath,
        share_request: ShareOperationRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareOperationV1:
        return start_share_action(
            share_id, "reconcile", share_request, idempotency_key, principal
        )

    @app.post("/api/v1/network-shares/{share_id}/retire", response_model=ShareV1)
    def retire_network_share(
        share_id: SafeShareIdPath,
        share_request: ShareRetireRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareV1:
        return service.retire_network_share(
            share_id, share_request, idempotency_key.strip(), principal
        )

    @app.delete("/api/v1/network-shares/{share_id}", response_model=ShareV1)
    def remove_network_share(
        share_id: SafeShareIdPath,
        share_request: ShareRemoveRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = share_principal_dependency,
    ) -> ShareV1:
        return service.remove_network_share(
            share_id, share_request, idempotency_key.strip(), principal
        )

    @app.get(
        "/api/v1/network-share-operations/{operation_id}",
        response_model=ShareOperationV1,
    )
    def network_share_operation(
        operation_id: SafeShareOperationIdPath,
        principal: Principal = principal_dependency,
    ) -> ShareOperationV1:
        return service.get_network_share_operation(operation_id, principal)

    @app.get("/api/v1/libraries", response_model=list[LibrarySummaryV1])
    async def libraries(
        principal: Principal = principal_dependency,
    ) -> tuple[LibrarySummaryV1, ...]:
        return await service.list_libraries(principal)

    @app.get("/api/v1/catalog/search", response_model=CatalogSearchPageV1)
    def catalog_search(
        q: str = Query("", max_length=256),
        library_id: str | None = Query(
            None,
            min_length=1,
            max_length=64,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$",
        ),
        job_id: str | None = Query(
            None,
            min_length=1,
            max_length=128,
            pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
        ),
        cassette: str | None = Query(None, min_length=1, max_length=128),
        sha256: str | None = Query(None, pattern=r"^[0-9A-Fa-f]{64}$"),
        min_size: int | None = Query(None, ge=0, le=2**63 - 1),
        max_size: int | None = Query(None, ge=0, le=2**63 - 1),
        copied_after: str | None = Query(None, max_length=64),
        copied_before: str | None = Query(None, max_length=64),
        include_history: bool = False,
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = Query(None, min_length=1, max_length=512),
        principal: Principal = principal_dependency,
    ) -> CatalogSearchPageV1:
        return service.search_catalog_file_versions(
            principal,
            query=q,
            library_id=library_id,
            job_id=job_id,
            cassette=cassette,
            sha256=sha256,
            min_size=min_size,
            max_size=max_size,
            copied_after=copied_after,
            copied_before=copied_before,
            include_history=include_history,
            limit=limit,
            cursor=cursor,
        )

    @app.get(
        "/api/v1/catalog/restore-options", response_model=CatalogRestoreOptionsV1
    )
    def catalog_restore_options(
        principal: Principal = principal_dependency,
    ) -> CatalogRestoreOptionsV1:
        return service.catalog_restore_options(principal)

    @app.post(
        "/api/v1/catalog/restore-plans",
        status_code=201,
        response_model=CatalogRestorePlanV1,
    )
    async def create_catalog_restore_plan(
        restore_request: CreateCatalogRestorePlanRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> CatalogRestorePlanV1:
        return await service.create_catalog_restore_plan(
            restore_request, idempotency_key.strip(), principal
        )

    @app.get(
        "/api/v1/catalog/restore-plans/{plan_id}",
        response_model=CatalogRestorePlanV1,
    )
    def catalog_restore_plan(
        plan_id: SafeJobIdPath,
        principal: Principal = principal_dependency,
    ) -> CatalogRestorePlanV1:
        return service.get_catalog_restore_plan(plan_id, principal)

    @app.post(
        "/api/v1/catalog/restore-plans/{plan_id}/runs",
        status_code=201,
        response_model=CatalogRestoreRunV1,
    )
    async def start_catalog_restore_run(
        plan_id: SafeJobIdPath,
        _request: StartCatalogRestoreRunRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> CatalogRestoreRunV1:
        return service.start_catalog_restore_run(
            plan_id, idempotency_key.strip(), principal
        )

    @app.get(
        "/api/v1/catalog/restore-runs/{run_id}", response_model=CatalogRestoreRunV1
    )
    def get_catalog_restore_run(
        run_id: SafeJobIdPath,
        principal: Principal = principal_dependency,
    ) -> CatalogRestoreRunV1:
        return service.get_catalog_restore_run(run_id, principal)

    @app.get(
        "/api/v1/catalog/restore-runs/{run_id}/cassettes/{cassette_sequence}/result",
        response_model=CatalogRestoreRunCassetteV1,
    )
    def get_catalog_restore_run_cassette_result(
        run_id: SafeJobIdPath,
        cassette_sequence: int = Path(ge=1, le=200),
        principal: Principal = principal_dependency,
    ) -> CatalogRestoreRunCassetteV1:
        return service.get_catalog_restore_run_cassette_result(
            run_id, cassette_sequence, principal
        )

    @app.get(
        "/api/v1/catalog/restore-runs/{run_id}/items/{item_sequence}/result",
        response_model=CatalogRestoreRunItemV1,
    )
    def get_catalog_restore_run_item_result(
        run_id: SafeJobIdPath,
        item_sequence: int = Path(ge=1, le=200),
        principal: Principal = principal_dependency,
    ) -> CatalogRestoreRunItemV1:
        return service.get_catalog_restore_run_item_result(
            run_id, item_sequence, principal
        )

    @app.post(
        "/api/v1/catalog/restore-runs/{run_id}/pause",
        response_model=CatalogRestoreRunV1,
    )
    def pause_catalog_restore_run(
        run_id: SafeJobIdPath,
        _request: RestoreRunControlRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> CatalogRestoreRunV1:
        return service.pause_catalog_restore_run(
            run_id, idempotency_key.strip(), principal
        )

    @app.post(
        "/api/v1/catalog/restore-runs/{run_id}/resume",
        response_model=CatalogRestoreRunV1,
    )
    def resume_catalog_restore_run(
        run_id: SafeJobIdPath,
        _request: RestoreRunControlRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> CatalogRestoreRunV1:
        return service.resume_catalog_restore_run(
            run_id, idempotency_key.strip(), principal
        )

    @app.post(
        "/api/v1/catalog/restore-runs/{run_id}/cancel",
        response_model=CatalogRestoreRunV1,
    )
    def cancel_catalog_restore_run(
        run_id: SafeJobIdPath,
        _request: RestoreRunControlRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> CatalogRestoreRunV1:
        return service.cancel_catalog_restore_run(
            run_id, idempotency_key.strip(), principal
        )

    @app.post(
        "/api/v1/catalog/restore-replacement-capabilities",
        response_model=CatalogRestoreReplacementCapabilityV1,
    )
    def issue_catalog_restore_replacement_capability(
        _request: IssueCatalogRestoreReplacementCapabilityRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> CatalogRestoreReplacementCapabilityV1:
        del idempotency_key
        return service.issue_catalog_restore_replacement_capability(principal)

    @app.post(
        "/api/v1/catalog/restore-runs/{run_id}/items/{item_sequence}/replacement-authorizations",
        status_code=201,
        response_model=CatalogRestoreReplacementAuthorizationV1,
    )
    def authorize_catalog_restore_item_replacement(
        run_id: SafeJobIdPath,
        item_sequence: int = Path(ge=1, le=200),
        authorization_request: AuthorizeCatalogRestoreItemReplacementRequestV1 = ...,
        idempotency_key: IdempotencyHeader = ...,
        principal: Principal = admin_dependency,
    ) -> CatalogRestoreReplacementAuthorizationV1:
        return service.authorize_catalog_restore_item_replacement(
            run_id,
            item_sequence,
            fresh_reauthentication=authorization_request.capability,
            idempotency_key=idempotency_key.strip(),
            principal=principal,
        )

    @app.get("/api/v1/catalog/browse", response_model=CatalogBrowsePageV1)
    def catalog_browse(
        library_id: str = Query(
            min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
        ),
        parent_path: str = Query("", max_length=4096),
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = Query(None, min_length=1, max_length=512),
        principal: Principal = principal_dependency,
    ) -> CatalogBrowsePageV1:
        return service.browse_catalog_backup_children(
            library_id, parent_path, principal, limit=limit, cursor=cursor
        )

    @app.get(
        "/api/v1/catalog/file-versions/{version_id}",
        response_model=CatalogFileVersionV1,
    )
    def catalog_file_version(
        version_id: CatalogFileVersionIdPath,
        principal: Principal = principal_dependency,
    ) -> CatalogFileVersionV1:
        return service.get_catalog_file_version(version_id, principal)

    @app.post(
        "/api/v1/libraries",
        status_code=201,
        response_model=LibrarySummaryV1,
    )
    async def create_library(
        library_request: CreateLibraryRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> LibrarySummaryV1:
        return await service.create_library(
            library_request, idempotency_key.strip(), principal
        )

    @app.get(
        "/api/v1/libraries/{library_id}",
        response_model=LibrarySummaryV1,
    )
    async def library_detail(
        library_id: SafeLibraryIdPath,
        principal: Principal = principal_dependency,
    ) -> LibrarySummaryV1:
        return await service.get_library(library_id, principal)

    @app.patch(
        "/api/v1/libraries/{library_id}",
        response_model=LibrarySummaryV1,
    )
    async def update_library(
        library_id: SafeLibraryIdPath,
        library_request: UpdateLibraryRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> LibrarySummaryV1:
        return await service.update_library(
            library_id,
            library_request,
            idempotency_key.strip(),
            principal,
        )

    @app.post(
        "/api/v1/libraries/{library_id}/scan",
        status_code=202,
        response_model=LibrarySummaryV1,
    )
    async def scan_library(
        library_id: SafeLibraryIdPath,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> LibrarySummaryV1:
        return service.start_library_scan(
            library_id, idempotency_key.strip(), principal
        )

    @app.post(
        "/api/v1/libraries/{library_id}/retire",
        response_model=LibrarySummaryV1,
    )
    async def retire_library(
        library_id: SafeLibraryIdPath,
        retire_request: RetireLibraryRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> LibrarySummaryV1:
        return await service.retire_library(
            library_id,
            retire_request,
            idempotency_key.strip(),
            principal,
        )

    @app.get("/api/v1/jobs", response_model=JobListPageV1)
    async def jobs(
        limit: int = Query(50, ge=1, le=200),
        cursor: str | None = Query(None, min_length=1, max_length=32),
        include_retired: bool = Query(False),
        principal: Principal = principal_dependency,
    ) -> JobListPageV1:
        return await service.list_jobs(
            principal,
            limit=limit,
            cursor=cursor,
            include_retired=include_retired,
        )

    @app.get("/api/v1/jobs/{job_id}", response_model=JobDetailV1)
    async def job_detail(
        job_id: SafeJobIdPath,
        principal: Principal = principal_dependency,
    ) -> JobDetailV1:
        return await service.get_job(job_id, principal)

    @app.get(
        "/api/v1/jobs/{job_id}/sequence-status",
        response_model=JobSequenceStatusV1,
    )
    async def job_sequence_status(
        job_id: SafeJobIdPath,
        principal: Principal = principal_dependency,
    ) -> JobSequenceStatusV1:
        return await service.get_job_sequence_status(job_id, principal)

    @app.get("/api/v1/jobs/{job_id}/incremental-policy", response_model=IncrementalPolicyV1)
    async def incremental_policy(job_id: SafeJobIdPath, principal: Principal = principal_dependency) -> IncrementalPolicyV1:
        return await service.incremental_policy(job_id, principal)

    @app.patch("/api/v1/jobs/{job_id}/incremental-policy", response_model=IncrementalPolicyV1)
    async def update_incremental_policy(
        job_id: SafeJobIdPath, policy_request: UpdateIncrementalPolicyRequestV1,
        idempotency_key: IdempotencyHeader, principal: Principal = operator_dependency,
    ) -> IncrementalPolicyV1:
        return await service.update_incremental_policy(job_id,policy_request,idempotency_key.strip(),principal)

    @app.post("/api/v1/jobs/{job_id}/incremental-scan", response_model=IncrementalScanResultV1)
    async def scan_job_now(
        job_id: SafeJobIdPath,idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> IncrementalScanResultV1:
        return await service.scan_job_now(job_id,idempotency_key.strip(),principal)

    @app.get(
        "/api/v1/jobs/{job_id}/cassettes", response_model=JobCassettePageV1
    )
    async def job_cassettes(
        job_id: SafeJobIdPath,
        limit: int = Query(100, ge=1, le=200),
        cursor: str | None = Query(None, min_length=1, max_length=32),
        principal: Principal = principal_dependency,
    ) -> JobCassettePageV1:
        return await service.job_cassettes(
            job_id, principal, limit=limit, cursor=cursor
        )

    @app.get("/api/v1/jobs/{job_id}/manifests", response_model=JobManifestPageV1)
    async def job_manifest(
        job_id: SafeJobIdPath,
        limit: int = Query(100, ge=1, le=200),
        cursor: str | None = Query(None, min_length=1, max_length=32),
        principal: Principal = principal_dependency,
    ) -> JobManifestPageV1:
        return await service.job_manifest(job_id, principal, limit=limit, cursor=cursor)

    @app.get("/api/v1/jobs/{job_id}/history", response_model=JobHistoryPageV1)
    async def job_history(
        job_id: SafeJobIdPath,
        limit: int = Query(100, ge=1, le=200),
        cursor: str | None = Query(None, min_length=1, max_length=32),
        principal: Principal = principal_dependency,
    ) -> JobHistoryPageV1:
        return await service.job_history(job_id, principal, limit=limit, cursor=cursor)

    @app.post(
        "/api/v1/job-plans",
        status_code=201,
        response_model=JobPlanV1,
    )
    async def create_job_plan(
        plan_request: CreateJobPlanRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> JobPlanV1:
        return await service.create_job_plan(
            plan_request, idempotency_key.strip(), principal
        )

    @app.get("/api/v1/media-profiles", response_model=MediaProfilesV1)
    def media_profiles(
        principal: Principal = principal_dependency,
    ) -> MediaProfilesV1:
        return service.media_profiles(principal)

    @app.get("/api/v1/job-plans/{plan_id}", response_model=JobPlanV1)
    async def job_plan_detail(
        plan_id: SafeJobIdPath,
        principal: Principal = principal_dependency,
    ) -> JobPlanV1:
        return await service.get_job_plan(plan_id, principal)

    @app.post(
        "/api/v1/job-plans/{plan_id}/jobs",
        status_code=201,
        response_model=JobDetailV1,
    )
    async def create_job_from_plan(
        plan_id: SafeJobIdPath,
        job_request: CreateJobFromPlanRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> JobDetailV1:
        return await service.create_job_from_plan(
            plan_id,
            job_request,
            idempotency_key.strip(),
            principal,
        )

    @app.post(
        "/api/v1/jobs/{job_id}/automatic-sequence/authorize",
        response_model=JobDetailV1,
    )
    async def authorize_automatic_sequence(
        job_id: SafeJobIdPath,
        sequence_request: AuthorizeAutomaticSequenceRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> JobDetailV1:
        return await service.authorize_automatic_sequence(
            job_id,
            sequence_request,
            idempotency_key.strip(),
            principal,
        )

    @app.post(
        "/api/v1/jobs/{job_id}/start",
        status_code=202,
        response_model=OperationResponseV1,
    )
    def start_saved_job(
        job_id: SafeJobIdPath,
        job_request: JobCommandRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> OperationResponseV1:
        record = service.start_archive(
            job_id,
            idempotency_key.strip(),
            principal,
            format_confirmation_label=job_request.format_confirmation_label,
            start_only=True,
        )
        return OperationResponseV1.model_validate(asdict(record))

    @app.post("/api/v1/jobs/{job_id}/pause", response_model=JobDetailV1)
    async def pause_job(
        job_id: SafeJobIdPath,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> JobDetailV1:
        return await service.pause_job(job_id, idempotency_key.strip(), principal)

    @app.patch("/api/v1/jobs/{job_id}", response_model=JobDetailV1)
    async def rename_job(
        job_id: SafeJobIdPath,
        job_request: UpdateJobRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> JobDetailV1:
        return await service.rename_job(
            job_id, job_request, idempotency_key.strip(), principal
        )

    @app.post("/api/v1/jobs/{job_id}/reserve-labels", response_model=JobDetailV1)
    async def reserve_job_labels(
        job_id: SafeJobIdPath,
        job_request: ReserveJobLabelsRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> JobDetailV1:
        return await service.reserve_job_labels(
            job_id, job_request, idempotency_key.strip(), principal
        )

    @app.post("/api/v1/jobs/{job_id}/extensions", response_model=JobDetailV1)
    async def extend_job(
        job_id: SafeJobIdPath,
        job_request: ExtendJobRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> JobDetailV1:
        return await service.extend_job(
            job_id, job_request, idempotency_key.strip(), principal
        )

    @app.post("/api/v1/jobs/{job_id}/retire", response_model=JobDetailV1)
    async def retire_job(
        job_id: SafeJobIdPath,
        job_request: RetireJobRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> JobDetailV1:
        return await service.retire_job(
            job_id, job_request, idempotency_key.strip(), principal
        )

    @app.get("/api/v1/logs", response_model=LogsPageV1)
    def logs(
        after_id: int | None = Query(None, ge=0),
        limit: int = Query(100, ge=1, le=200),
    ) -> LogsPageV1:
        return service.logs(after_id, limit)

    @app.get("/api/v1/system-logs", response_model=SystemLogsPageV1)
    def system_logs(
        request: Request,
        source: str = Query("all"),
        severity: str = Query("info"),
        time_range: str = Query("1h", alias="range"),
        direction: str = Query("older"),
        cursor: str | None = Query(None, min_length=1, max_length=2_048),
        search: str | None = Query(None, min_length=1, max_length=128),
        limit: int = Query(100, ge=1, le=200),
        _principal: Principal = operator_dependency,
    ) -> SystemLogsPageV1:
        allowed = {
            "source",
            "severity",
            "range",
            "direction",
            "cursor",
            "search",
            "limit",
        }
        keys = [key for key, _value in request.query_params.multi_items()]
        if any(key not in allowed for key in keys) or len(keys) != len(set(keys)):
            raise CatalogQueryInvalid("system log query is invalid")
        try:
            query = SystemLogQuery(
                source=source,
                severity=severity,
                range=time_range,
                direction=direction,
                cursor=cursor,
                search=search,
                limit=limit,
            )
        except (TypeError, ValueError):
            raise CatalogQueryInvalid("system log query is invalid") from None
        return service.system_logs(query)

    @app.post(
        "/api/v1/operations",
        status_code=202,
        response_model=OperationResponseV1,
    )
    def start(
        operation_request: OperationRequest,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> OperationResponseV1:
        record = service.start_operation(
            operation_request,
            idempotency_key.strip(),
            principal,
        )
        return OperationResponseV1.model_validate(asdict(record))

    @app.get("/api/v1/operations/{operation_id}/pre-media-reset", response_model=PreMediaResetProofV1)
    def pre_media_reset_detail(
        operation_id: SafeJobIdPath,
        principal: Principal = Depends(service.principals.require_webui_admin),
    ) -> PreMediaResetProofV1:
        return service.get_pre_media_reset(operation_id, principal)

    @app.post("/api/v1/operations/{operation_id}/pre-media-reset", response_model=OperationResponseV1)
    def reset_pre_media_attempt(
        operation_id: SafeJobIdPath, reset_request: ResetPreMediaAttemptRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = Depends(service.principals.require_webui_admin),
    ) -> OperationResponseV1:
        return OperationResponseV1.model_validate(asdict(service.reset_pre_media_attempt(
            operation_id, reset_request, idempotency_key.strip(), principal,
        )))

    @app.get(
        "/api/v1/critical-recovery/{operation_id}",
        response_model=CriticalRecoveryProofV1,
    )
    def critical_recovery_detail(
        operation_id: SafeJobIdPath,
        principal: Principal = Depends(service.principals.require_webui_admin),
    ) -> CriticalRecoveryProofV1:
        return service.critical_recovery_proof(operation_id, principal)

    @app.post(
        "/api/v1/critical-recovery/{operation_id}/reconcile",
        response_model=CriticalRecoveryProofV1,
    )
    def reconcile_critical_recovery(
        operation_id: SafeJobIdPath,
        critical_request: ReconcileCriticalRecoveryRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = Depends(service.principals.require_webui_admin),
    ) -> CriticalRecoveryProofV1:
        return service.reconcile_critical_recovery(
            operation_id, critical_request, idempotency_key.strip(), principal
        )

    @app.post(
        "/api/v1/critical-recovery/{operation_id}/abandon",
        response_model=OperationResponseV1,
    )
    def abandon_critical_recovery(
        operation_id: SafeJobIdPath,
        critical_request: AbandonCriticalAttemptRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = Depends(service.principals.require_webui_admin),
    ) -> OperationResponseV1:
        return OperationResponseV1.model_validate(
            asdict(
                service.abandon_critical_recovery(
                    operation_id,
                    critical_request,
                    idempotency_key.strip(),
                    principal,
                )
            )
        )

    @app.post(
        "/api/v1/critical-recovery/{operation_id}/authorize-replacement",
        status_code=202,
        response_model=OperationResponseV1,
    )
    def authorize_critical_replacement(
        operation_id: SafeJobIdPath,
        critical_request: AuthorizeReplacementAttemptRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = Depends(service.principals.require_webui_admin),
    ) -> OperationResponseV1:
        return OperationResponseV1.model_validate(
            asdict(
                service.authorize_critical_replacement(
                    operation_id,
                    critical_request,
                    idempotency_key.strip(),
                    principal,
                )
            )
        )

    @app.post(
        "/api/v1/jobs/{job_id}/resume",
        status_code=202,
        response_model=OperationResponseV1 | BoundaryRefreshAcceptedV1,
    )
    def resume_archive(
        job_id: SafeJobIdPath,
        archive_request: ResumeArchiveRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = operator_dependency,
    ) -> OperationResponseV1 | BoundaryRefreshAcceptedV1:
        result = service.start_archive(
            job_id,
            idempotency_key.strip(),
            principal,
            cutover_credential=archive_request.cutover_credential,
            format_confirmation_label=archive_request.format_confirmation_label,
        )
        if isinstance(result, BoundaryRefreshAcceptedV1):
            return result
        return OperationResponseV1.model_validate(asdict(result))

    @app.post(
        "/api/v1/jobs/{job_id}/failed-cassette/reset",
        response_model=JobDetailV1,
    )
    async def reset_failed_cassette(
        job_id: SafeJobIdPath,
        reset_request: ResetFailedCassetteRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> JobDetailV1:
        return await service.reset_failed_cassette(
            job_id,
            reset_request,
            idempotency_key.strip(),
            principal,
        )

    @app.post(
        "/api/v1/jobs/native",
        status_code=202,
        response_model=OperationResponseV1,
        include_in_schema=False,
    )
    def create_native_job(
        native_request: CreateNativeJobRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> OperationResponseV1:
        record = service.start_native_job(
            native_request,
            idempotency_key.strip(),
            principal,
        )
        return OperationResponseV1.model_validate(asdict(record))

    @app.post(
        "/api/v1/media/{sequence}/format",
        status_code=202,
        response_model=OperationResponseV1,
    )
    def format_expected_media(
        sequence: Annotated[int, Path(ge=1)],
        archive_request: ResumeArchiveRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = admin_dependency,
    ) -> OperationResponseV1:
        status = service.status()
        if (
            status.job is None
            or status.expected_media is None
            or status.expected_media.sequence != sequence
            or not status.expected_media.format_required
        ):
            raise FormatConfirmationMismatch()
        record = service.start_archive(
            status.job.id,
            idempotency_key.strip(),
            principal,
            format_confirmation_label=archive_request.format_confirmation_label,
        )
        return OperationResponseV1.model_validate(asdict(record))

    @app.post(
        "/api/v1/cutover/cassette-4/authorizations",
        status_code=202,
        response_model=OperationResponseV1,
    )
    def register_cutover_authorization(
        authorization_request: CutoverAuthorizationRequestV1,
        idempotency_key: IdempotencyHeader,
        principal: Principal = direct_admin_dependency,
    ) -> OperationResponseV1:
        record = service.start_cutover_authorization(
            authorization_request,
            idempotency_key.strip(),
            principal,
        )
        return OperationResponseV1.model_validate(asdict(record))

    @app.get(
        "/api/v1/jobs/{job_id}/cutover/cassette-4/report",
        response_model=SignedAcceptanceReportV1,
    )
    def prepare_cutover_report(
        job_id: SafeJobIdPath,
        principal: Principal = direct_admin_dependency,
    ) -> SignedAcceptanceReportV1:
        return service.prepare_cutover_report(job_id, principal)

    @app.get("/api/v1/events")
    def events(
        request: Request,
        after_id: int | None = Query(None, ge=0),
    ) -> StreamingResponse:
        cursor = resolve_sse_cursor(request.headers.get("Last-Event-ID"), after_id)

        def serialized_events():
            for candidate in service.events(cursor):
                envelope = EventEnvelopeV1.model_validate(candidate)
                yield (
                    f"id: {envelope.id}\n"
                    f"event: {envelope.event}\n"
                    "data: "
                    f"{json.dumps(envelope.data.model_dump(mode='json', exclude_unset=envelope.event == 'state.patch'), separators=(',', ':'))}"
                    "\n\n"
                )

        return StreamingResponse(
            serialized_events(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache"},
        )

    return app
