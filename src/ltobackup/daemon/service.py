from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import shutil
import socket
import tempfile
import time
import uuid
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, RLock, local
from typing import Any, Literal, Protocol

try:
    import pwd
except ImportError:  # pragma: no cover - pwd is present on supported Linux hosts.
    pwd = None  # type: ignore[assignment]

from fastapi import Request

from ..application import LtoApplication
from ..catalog import Catalog
from ..errors import CatalogError, CutoverAuthorizationInvalid
from ..errors import ValidationError as DomainValidationError
from ..linux_settings import LinuxPaths, LinuxSettings
from ..log_reader.client import JournalReaderUnavailable, UnixJournalReaderClient
from ..log_reader.protocol import (
    JournalEntry,
    JournalPage,
    JournalQuery,
    LogDirection,
    LogSource,
)
from ..media import lto_media_profiles
from ..operational_log import (
    NullOperationalEventSink,
    OperationalEvent,
    OperationalEventSink,
    OperationalSeverity,
    OperationalSource,
    redact_operational_message,
)
from ..settings import AppPaths, save_settings
from ..shares import (
    NFS_RETRANSMISSION_CHOICES,
    NFS_TIMEOUT_SECONDS_CHOICES,
    NFS_VERSION_CHOICES,
    SMB_DIALECT_CHOICES,
    EndpointPolicy,
)
from ..util import utc_now
from .api_models import (
    SYSTEM_LOG_SEVERITY_RANK,
    SYSTEM_LOG_SOURCE_UNITS,
    AbandonCriticalAttemptRequestV1,
    ApplicationSettingsV1,
    AuthorizeAutomaticSequenceRequestV1,
    AuthorizeReplacementAttemptRequestV1,
    BoundaryRefreshAcceptedV1,
    CatalogBrowseEntryV1,
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
    CriticalRecoveryTargetV1,
    CutoverAuthorizationRequestV1,
    DaemonStatusV1,
    DiagnosticHealthV1,
    DiagnosticPhaseDurationsV1,
    DiagnosticSummaryV1,
    DiagnosticTelemetryV1,
    DriveStatusV1,
    EventEnvelopeV1,
    ExpectedMediaV1,
    ExtendJobRequestV1,
    HostSettingsV1,
    IncrementalPolicyV1,
    IncrementalScanResultV1,
    JobCassettePageV1,
    JobDetailV1,
    JobHistoryPageV1,
    JobListPageV1,
    JobManifestPageV1,
    JobPlanV1,
    JobSequenceStatusV1,
    JobSummaryV1,
    LibrarySummaryV1,
    LogEntryV1,
    LogsPageV1,
    MediaProfilesV1,
    NetworkShareOptionsV1,
    OperationRequest,
    OperationResponseV1,
    PreMediaResetProofV1,
    ResetPreMediaAttemptRequestV1,
    ProgressV1,
    ReconcileCriticalRecoveryRequestV1,
    ReserveJobLabelsRequestV1,
    ResetFailedCassetteRequestV1,
    RetireJobRequestV1,
    RetireLibraryRequestV1,
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
    StorageSummaryV1,
    SystemLogEntryV1,
    SystemLogQuery,
    SystemLogsPageV1,
    TelemetryV1,
    UpdateApplicationSettingsRequestV1,
    UpdateIncrementalPolicyRequestV1,
    UpdateJobRequestV1,
    UpdateLibraryRequestV1,
    UpdateShareRequestV1,
)
from .archive_runtime import ArchiveResumeAdmission
from .backups import BackupManager
from .diagnostics import RuntimeDiagnostics
from .events import EventBus
from .frozen_job import FrozenJobPlan
from .incremental import IncrementalScanCoordinator
from .management import JobStateConflict, ManagementService, ShareConfirmationMismatch
from .models import (
    CommandQuiescenceReceipt,
    CriticalRecoveryObservation,
    DaemonFence,
    HardwareTargetBinding,
    MutationAdmissionClosed,
    OperationRecord,
    RecoveryAdmissionBlocked,
    RecoveryCommandFence,
    SafeRecoveryResolution,
    StaleDaemonFence,
    cutover_catalog_binding_sha256,
)
from .operations import OperationCallback, OperationManager, new_operation
from .sequence_coordinator import SequenceCandidate
from .storage import StorageMonitor
from .telemetry import TelemetryPhase, TelemetrySnapshot
from .timeouts import validate_shutdown_timeout

PEER_CREDENTIAL_SCOPE_KEY = "lto.peer_credentials"
_SAFE_PRINCIPAL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_AUTHENTICATED_ROLES = frozenset({"admin", "operator"})
_SAFE_LOG_MESSAGES = {
    "diagnostic": "Diagnostic event recorded.",
    "operation.accepted": "Operation accepted.",
    "operation.conflict": "Operation rejected because another operation is active.",
    "operation.rejected": "Operation request rejected.",
    "sequence.coordinator.error": "Cassette sequence admission will be retried safely.",
    "startup.complete": "Startup reconciliation completed.",
    "shutdown.complete": "Daemon shutdown completed.",
}


@dataclass(frozen=True)
class Principal:
    name: str
    role: Literal["admin", "operator"] = "admin"
    direct_local_admin: bool = False
    session_binding_sha256: str | None = None
    reauthenticated_at: float | None = None

    def __post_init__(self) -> None:
        if not _SAFE_PRINCIPAL.fullmatch(self.name):
            raise ValueError("principal name must be safe")
        if self.role not in _AUTHENTICATED_ROLES:
            raise ValueError("principal role must be admin or operator")
        if self.direct_local_admin and self.role != "admin":
            raise ValueError("direct local administrators have the admin role")
        if self.session_binding_sha256 is not None and not re.fullmatch(
            r"[0-9a-f]{64}", self.session_binding_sha256
        ):
            raise ValueError("session binding must be a sha256 digest")

    def allows(self, capability: str, *, formatting_required: bool = False) -> bool:
        """Return whether this authenticated principal has one management capability."""

        if capability == "cutover.authorize":
            return self.direct_local_admin
        if capability in {"user.manage", "account.self"}:
            if self.direct_local_admin:
                return False
            return self.role == "admin" if capability == "user.manage" else True
        if self.direct_local_admin:
            return capability in {
                "read",
                "library.manage",
                "library.scan",
                "job.create",
                "job.manage",
                "job.retire",
                "job.resume",
                "media.format",
                "application.settings",
            }
        if capability in {
            "read",
            "library.scan",
            "job.create",
            "job.manage",
            "job.resume",
        }:
            return self.role in _AUTHENTICATED_ROLES and not (
                capability == "job.resume"
                and formatting_required
                and self.role != "admin"
            )
        return self.role == "admin" and capability in {
            "library.manage",
            "job.retire",
            "media.format",
            "application.settings",
            "restore.replacement",
        }


class UntrustedPeer(RuntimeError):
    pass


class RoleDenied(RuntimeError):
    """The trusted principal lacks the requested management capability."""


class FormatRequiresAdmin(RoleDenied):
    """Formatting media must be a separately authorized admin action."""


class CatalogQueryInvalid(ValueError):
    """A bounded catalog request cannot be fulfilled safely."""


class CatalogFileVersionNotFound(LookupError):
    """The requested visible catalog file version does not exist."""


class CatalogLibraryNotFound(LookupError):
    """The requested catalog library does not exist."""


class CatalogRestorePlanNotFound(LookupError):
    """The requested metadata-only restore plan does not exist."""


class CatalogRestorePlanInvalid(ValueError):
    """The restore selection or destination is outside the closed contract."""


class CatalogRestorePlanConflict(RuntimeError):
    """A restore request reused an incompatible idempotency key."""


class CatalogRestoreRunNotFound(LookupError):
    """The requested durable restore run was not found."""


class CatalogRestoreRunInvalid(ValueError):
    """The requested restore-run transition is not safe or current."""


class CatalogRestoreRunConflict(RuntimeError):
    """A restore-run command reused an incompatible idempotency key."""


class RestoreCoordinatorUnavailable(RuntimeError):
    """Restore control is unavailable until its durable coordinator is live."""


class OperationReplayConflict(RuntimeError):
    """An operation key belongs to a different persisted request identity."""


class CriticalRecoveryNotFound(LookupError):
    """No exact typed critical recovery proof is currently available."""


class CriticalRecoveryRejected(RuntimeError):
    """A protected recovery action failed closed."""


class PreMediaResetNotFound(LookupError):
    """The requested pre-media operation is unavailable."""


class PreMediaResetRejected(RuntimeError):
    """The pre-media reset could not establish its exact safety conditions."""


class TrustedPrincipalResolver:
    """Resolve principals exclusively from kernel-attached Unix peer credentials."""

    def __init__(
        self,
        *,
        administrator_uids: Mapping[int, str] | None = None,
        webui_uid: int | None = None,
        webui_user: str | None = None,
    ) -> None:
        administrators = dict(
            {0: "root"} if administrator_uids is None else administrator_uids
        )
        for uid, name in administrators.items():
            if (
                isinstance(uid, bool)
                or not isinstance(uid, int)
                or uid < 0
                or not isinstance(name, str)
                or not _SAFE_PRINCIPAL.fullmatch(name)
            ):
                raise ValueError("administrator identities must be safe UID/name pairs")
        if webui_uid is not None and (
            isinstance(webui_uid, bool)
            or not isinstance(webui_uid, int)
            or webui_uid < 0
        ):
            raise ValueError("webui_uid must be a non-negative integer")
        if webui_uid is not None and webui_user is not None:
            raise ValueError("configure either webui_uid or webui_user, not both")
        if webui_user is not None and (
            not isinstance(webui_user, str) or not _SAFE_PRINCIPAL.fullmatch(webui_user)
        ):
            raise ValueError("webui_user must be a safe local username")
        if webui_uid in administrators:
            raise ValueError("the WebUI and administrator identities must be distinct")
        self._administrators = administrators
        self._webui_uid = webui_uid
        self._webui_user = webui_user

    def resolve_webui_uid(self) -> int | None:
        """Resolve the configured WebUI account once during daemon startup."""

        if self._webui_user is None:
            return self._webui_uid
        if pwd is None:
            raise ValueError("WebUI username lookup is unavailable on this platform")
        try:
            resolved_uid = pwd.getpwnam(self._webui_user).pw_uid
        except KeyError as exc:
            raise ValueError(
                f"configured WebUI user does not exist: {self._webui_user}"
            ) from exc
        if (
            isinstance(resolved_uid, bool)
            or not isinstance(resolved_uid, int)
            or resolved_uid < 0
        ):
            raise ValueError("configured WebUI user has an invalid UID")
        if resolved_uid in self._administrators:
            raise ValueError("the WebUI and administrator identities must be distinct")
        self._webui_uid = resolved_uid
        self._webui_user = None
        return resolved_uid

    def require_mutation_principal(self, request: Request) -> Principal:
        peer = request.scope.get(PEER_CREDENTIAL_SCOPE_KEY)
        if (
            not isinstance(peer, tuple)
            or len(peer) != 3
            or any(
                isinstance(value, bool) or not isinstance(value, int) for value in peer
            )
        ):
            raise UntrustedPeer("trusted Unix peer credentials are required")
        pid, uid, gid = peer
        if pid <= 0 or uid < 0 or gid < 0:
            raise UntrustedPeer("trusted Unix peer credentials are required")

        administrator = self._administrators.get(uid)
        if administrator is not None:
            return Principal(administrator, role="admin", direct_local_admin=True)
        if self._webui_uid is not None and uid == self._webui_uid:
            forwarded = request.headers.get("X-Authenticated-Principal", "").strip()
            if not _SAFE_PRINCIPAL.fullmatch(forwarded):
                raise UntrustedPeer(
                    "the verified WebUI peer did not provide a safe principal"
                )
            role = request.headers.get("X-Authenticated-Role", "").strip()
            if role not in _AUTHENTICATED_ROLES:
                raise UntrustedPeer(
                    "the verified WebUI peer did not provide a valid role"
                )
            session_binding = request.headers.get("X-Authenticated-Session-Binding", "")
            reauthenticated_at = request.headers.get("X-Authenticated-Reauthenticated-At", "")
            if not session_binding and not reauthenticated_at:
                return Principal(forwarded, role=role)
            if not session_binding or not reauthenticated_at or not re.fullmatch(r"[0-9a-f]{64}", session_binding):
                raise UntrustedPeer("the verified WebUI session attestation is invalid")
            try:
                observed_reauthentication = float(reauthenticated_at)
            except ValueError as exc:
                raise UntrustedPeer("the verified WebUI peer did not provide reauthentication") from exc
            now = time.time()
            if not (now - 600.0 <= observed_reauthentication <= now + 30.0):
                raise UntrustedPeer("the verified WebUI reauthentication is not fresh")
            return Principal(
                forwarded, role=role, session_binding_sha256=session_binding,
                reauthenticated_at=observed_reauthentication,
            )
        raise UntrustedPeer("the Unix peer is not authorized for mutations")

    def require_operator(self, request: Request) -> Principal:
        principal = self.require_mutation_principal(request)
        if not principal.allows("job.resume"):
            raise RoleDenied("operator or admin role is required")
        return principal

    def require_admin(self, request: Request) -> Principal:
        principal = self.require_mutation_principal(request)
        if not principal.allows("library.manage"):
            raise RoleDenied("admin role is required")
        return principal

    def require_webui_admin(self, request: Request) -> Principal:
        """Accept only a server-derived admin forwarded by the configured WebUI."""

        principal = self.require_mutation_principal(request)
        if principal.direct_local_admin or principal.role != "admin":
            raise RoleDenied("recently reauthenticated WebUI admin is required")
        return principal

    def require_direct_local_admin(self, request: Request) -> Principal:
        """Accept only an administrator UID observed directly on the Unix socket."""

        peer = request.scope.get(PEER_CREDENTIAL_SCOPE_KEY)
        if (
            not isinstance(peer, tuple)
            or len(peer) != 3
            or any(
                isinstance(value, bool) or not isinstance(value, int) for value in peer
            )
        ):
            raise UntrustedPeer("direct local administrator credentials are required")
        pid, uid, gid = peer
        administrator = self._administrators.get(uid)
        if pid <= 0 or uid < 0 or gid < 0 or administrator is None:
            raise UntrustedPeer("direct local administrator credentials are required")
        return Principal(administrator, role="admin", direct_local_admin=True)


@dataclass(frozen=True)
class StartupReconciliationResult:
    recovered_operations: tuple[OperationRecord, ...]
    admission_blockers: tuple[OperationRecord, ...]

    @property
    def safe_for_admission(self) -> bool:
        return not self.admission_blockers

    @property
    def admission_blocker_ids(self) -> tuple[str, ...]:
        return tuple(record.id for record in self.admission_blockers)


def _noop_operation(_context: Any) -> None:
    return None


ArchiveResumeAdmissionFactory = Callable[[str], ArchiveResumeAdmission]
CutoverEnvironmentFactory = Callable[[str], tuple[str, str]]


class RecoveryCoordinatorLifecycle(Protocol):
    def set_transition_callback(self, callback: Callable[[object], None]) -> None: ...

    def reconcile_startup(
        self, blockers: tuple[OperationRecord, ...]
    ) -> object: ...

    def reassess_critical(self, operation_id: str) -> object: ...

    def start(self) -> None: ...

    def shutdown(self) -> None: ...


RecoveryCoordinatorFactory = Callable[
    [OperationManager], RecoveryCoordinatorLifecycle
]


class SequenceCoordinatorLifecycle(Protocol):
    def start(self) -> None: ...

    def wake(self) -> None: ...

    def shutdown(self) -> None: ...


class RestoreCoordinatorLifecycle(Protocol):
    def wake(self) -> None: ...

    def request_pause(
        self, run_id: str, actor: str, idempotency_key: str
    ) -> dict[str, object]: ...

    def request_cancel(
        self, run_id: str, actor: str, idempotency_key: str
    ) -> dict[str, object]: ...

    def resume(
        self, run_id: str, actor: str, idempotency_key: str
    ) -> dict[str, object]: ...


SequenceCoordinatorFactory = Callable[[OperationManager], SequenceCoordinatorLifecycle]


class FormatConfirmationRequired(ValueError):
    """The frozen next cassette requires an exact label confirmation."""


class FormatConfirmationMismatch(ValueError):
    """The supplied label does not match the frozen next cassette."""


class DaemonService:
    def __init__(
        self,
        paths: LinuxPaths,
        settings: LinuxSettings,
        backup_manager: BackupManager,
        operation_manager: OperationManager | None,
        event_bus: EventBus,
        *,
        principals: TrustedPrincipalResolver | None = None,
        operation_callbacks: Mapping[str, OperationCallback] | None = None,
        archive_resume_admission: ArchiveResumeAdmissionFactory | None = None,
        native_archive_admission: ArchiveResumeAdmissionFactory | None = None,
        critical_replacement_callback: OperationCallback | None = None,
        cutover_environment: CutoverEnvironmentFactory | None = None,
        startup_reconciler: Callable[[OperationManager], None] | None = None,
        recovery_coordinator_factory: RecoveryCoordinatorFactory | None = None,
        sequence_coordinator_factory: SequenceCoordinatorFactory | None = None,
        shutdown_timeout_seconds: float = 30.0,
        share_broker: object | None = None,
        share_resolver: Callable[[str], tuple[object, ...]] | None = None,
        share_probe: Callable[[Path], object] | None = None,
        share_executor: object | None = None,
        share_timeout_seconds: float = 30.0,
        share_credential_request_key: bytes | None = None,
        critical_recovery_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        restore_reauthentication_key: bytes | None = None,
        journal_reader: UnixJournalReaderClient | None = None,
        operational_event_sink: OperationalEventSink | None = None,
        pre_media_reset_reconciler: Callable[[OperationRecord, DaemonFence], CommandQuiescenceReceipt] | None = None,
    ) -> None:
        validated_shutdown_timeout = validate_shutdown_timeout(shutdown_timeout_seconds)
        self.paths = paths
        self.settings = settings
        self.backups = backup_manager
        self._storage_monitor = StorageMonitor(
            catalog_path=paths.catalog_file,
            storage_paths={
                "state": paths.state_dir,
                "backups": backup_manager.backup_directory,
                "scratch": Path(tempfile.gettempdir()),
            },
        )
        self._operations = operation_manager
        self._events = event_bus
        self._journal_reader = journal_reader
        self._operational_event_sink = (
            operational_event_sink or NullOperationalEventSink()
        )
        self._operational_event_guard = local()
        self.principals = principals or TrustedPrincipalResolver()
        self._callbacks = {"diagnostic": _noop_operation}
        if operation_callbacks is not None:
            self._callbacks.update(operation_callbacks)
        self._archive_resume_admission = archive_resume_admission
        self._native_archive_admission = native_archive_admission
        self._critical_replacement_callback = critical_replacement_callback
        self._cutover_environment = cutover_environment
        self._startup_reconciler = startup_reconciler
        self._recovery_coordinator_factory = recovery_coordinator_factory
        self._recovery_coordinator: RecoveryCoordinatorLifecycle | None = None
        self._sequence_coordinator_factory = sequence_coordinator_factory
        self._sequence_coordinator: SequenceCoordinatorLifecycle | None = None
        self._sequence_coordinator_started = False
        self._shutdown_timeout_seconds = validated_shutdown_timeout
        self._lifecycle_lock = RLock()
        self._critical_action_lock = RLock()
        self._pre_media_reset_reconciler = pre_media_reset_reconciler
        self._critical_recovery_clock = critical_recovery_clock
        self._restore_reauthentication_key = (
            secrets.token_bytes(32) if restore_reauthentication_key is None else restore_reauthentication_key
        )
        if not isinstance(self._restore_reauthentication_key, bytes) or len(self._restore_reauthentication_key) < 32:
            raise ValueError("restore reauthentication key is invalid")
        self._shutdown_requested = Event()
        self._lifecycle_state = "new"
        self._accepting_mutations = False
        self._current_operation_id: str | None = None
        self._current_progress_baseline: tuple[str, int, int, int] | None = None
        self._admission_blocker_id: str | None = None
        self._quarantined_operation_ids: set[str] = set()
        self._logs: deque[LogEntryV1] = deque(maxlen=2_000)
        self._logs_lock = RLock()
        self._next_log_id = 1
        self._diagnostics = RuntimeDiagnostics(
            version="0.11.28",
            monotonic=time.monotonic,
            utc_now=lambda: datetime.now(UTC),
            on_snapshot=self._publish_telemetry_snapshot,
        )
        self._management = ManagementService(
            LtoApplication(self.paths.state_dir),
            source_roots=self.settings.source_roots,
            buffer_bytes=self.settings.buffer_bytes,
            on_library_change=self._publish_library_change,
            share_broker=share_broker,
            share_endpoint_policy=EndpointPolicy(
                tuple(self.settings.share_endpoint_cidrs),
                tuple(self.settings.share_endpoint_dns_suffixes),
            ),
            share_resolver=share_resolver or self._resolve_share_endpoint,
            share_probe=share_probe,
            share_executor=share_executor,
            managed_source_mount_root=self.settings.managed_source_mount_root,
            share_timeout_seconds=share_timeout_seconds,
            on_share_change=self._publish_share_change,
            share_credential_request_key=share_credential_request_key,
        )
        if self._operations is not None:
            self._operations.stop_accepting()

    def admit_job_managed_sources(
        self, job_id: str, operation_id: str, daemon_generation: int
    ) -> tuple[str, ...]:
        return self._management.admit_job_managed_sources(
            job_id, operation_id, daemon_generation
        )

    def release_job_managed_sources(
        self, lease_ids: tuple[str, ...], daemon_generation: int
    ) -> None:
        self._management.release_job_managed_sources(lease_ids, daemon_generation)

    @staticmethod
    def _resolve_share_endpoint(server: str) -> tuple[object, ...]:
        return tuple(
            sorted(
                {
                    ipaddress.ip_address(result[4][0])
                    for result in socket.getaddrinfo(
                        server,
                        None,
                        type=socket.SOCK_STREAM,
                    )
                },
                key=str,
            )
        )

    def startup(self) -> StartupReconciliationResult:
        with self._lifecycle_lock:
            if self._lifecycle_state != "new":
                if self._shutdown_requested.is_set():
                    raise RuntimeError("a shut down daemon service cannot restart")
                raise RuntimeError("daemon service startup may only run once")
            self._lifecycle_state = "starting"
            self._accepting_mutations = False
            if self._operations is not None:
                self._operations.stop_accepting()
        self.backups.prepare_and_initialize()
        self._management.initialize_application_settings()
        self._management.recover_interrupted_library_scans()
        self._management.recover_network_shares()
        if self._operations is None:
            with Catalog(self.paths.catalog_file) as catalog:
                fence = catalog.claim_daemon_owner(f"daemon-{uuid.uuid4().hex}")
            operations = OperationManager(
                lambda: Catalog(self.paths.catalog_file),
                fence,
                accepting=False,
            )
            with self._lifecycle_lock:
                self._operations = operations
        operations = self._require_operations()
        recovered = operations.recover_interrupted()
        if self._startup_reconciler is not None:
            self._startup_reconciler(operations)
        blockers = operations.reconcile_admission_blockers()
        coordinator = None
        sequence_coordinator = None
        if self._recovery_coordinator_factory is not None:
            coordinator = self._recovery_coordinator_factory(operations)
            coordinator.set_transition_callback(self._handle_recovery_transition)
            # An ambiguous pre-media release needs explicit, no-signal reset.
            # Automatic assessment may itself issue media identification, so
            # leave these blockers outside the coordinator's tracked set.
            # Keep the complete blockers below: this does not open admission.
            transition = coordinator.reconcile_startup(
                self._automatic_startup_recovery_candidates(blockers)
            )
            self._remember_recovery_quarantines(transition)
            blockers = operations.reconcile_admission_blockers()
            with self._lifecycle_lock:
                self._recovery_coordinator = coordinator
            if not self._shutdown_requested.is_set():
                coordinator.start()
        if self._sequence_coordinator_factory is not None:
            sequence_coordinator = self._sequence_coordinator_factory(operations)
            with self._lifecycle_lock:
                self._sequence_coordinator = sequence_coordinator
        with self._lifecycle_lock:
            self._set_admission_blockers_locked(
                self._nonquarantined_blockers(blockers)
            )
            shutdown_requested = self._shutdown_requested.is_set()
            if not shutdown_requested:
                self.record_log("info", "startup.complete")
            start_sequence = not shutdown_requested and not self._admission_blocker_id
        if start_sequence and sequence_coordinator is not None:
            self._activate_sequence_coordinator()
        if shutdown_requested:
            if sequence_coordinator is not None:
                sequence_coordinator.shutdown()
            if coordinator is not None:
                coordinator.shutdown()
            operations.shutdown(0.0)
        return StartupReconciliationResult(recovered, blockers)

    def _automatic_startup_recovery_candidates(
        self, blockers: tuple[OperationRecord, ...],
    ) -> tuple[OperationRecord, ...]:
        candidates = []
        with Catalog(self.paths.catalog_file) as catalog:
            for blocker in blockers:
                if blocker.kind == "archive.native" and blocker.phase is None:
                    commands = catalog.hardware_commands_for_operation(blocker.id)
                    if any(
                        command.kind in {"identify", "probe_media"}
                        and command.release_status == "ambiguous"
                        for command in commands
                    ):
                        continue
                candidates.append(blocker)
        return tuple(candidates)

    @staticmethod
    def authorize_command(
        principal: Principal,
        *,
        capability: str,
        formatting_required: bool = False,
    ) -> None:
        """Enforce the shared role matrix at daemon command boundaries."""

        if principal.allows(
            capability,
            formatting_required=formatting_required,
        ):
            return
        if capability == "job.resume" and formatting_required:
            raise FormatRequiresAdmin("formatting requires an admin role")
        raise RoleDenied("the authenticated role is not permitted")

    @property
    def daemon_fence(self) -> DaemonFence:
        return self._require_operations().daemon_fence

    @property
    def archive_telemetry_sink(self) -> RuntimeDiagnostics:
        """Inject this sink when constructing an ArchiveRunner for this daemon."""

        return self._diagnostics

    @property
    def shutdown_requested(self) -> bool:
        """Cancellation boundary passed to the production archive runner."""

        return self._shutdown_requested.is_set()

    def prepare_replacement_admission(
        self,
    ) -> Callable[[OperationRecord], None]:
        """Capture a progress boundary before a recovery replacement is admitted."""

        files, byte_count, generation = self._diagnostics.committed_checkpoint()

        def remember(admitted: OperationRecord) -> None:
            self._current_progress_baseline = (
                admitted.id,
                files,
                byte_count,
                generation,
            )
            self._current_operation_id = admitted.id

        return remember

    def prepare_restore_replacement_admission(
        self, run_id: str, cassette_sequence: int
    ) -> Callable[[OperationRecord], None]:
        """Capture telemetry before publishing one exact restore replacement."""

        if (
            not isinstance(run_id, str)
            or not run_id
            or type(cassette_sequence) is not int
            or cassette_sequence <= 0
        ):
            raise ValueError("restore replacement binding is invalid")
        files, byte_count, generation = self._diagnostics.committed_checkpoint()

        def remember(admitted: OperationRecord) -> None:
            if (
                admitted.kind != "restore.cassette"
                or admitted.job_id != run_id
                or admitted.cassette_sequence != cassette_sequence
            ):
                raise RuntimeError("restore replacement binding is mismatched")
            # This assignment must remain first: status readers cannot observe
            # the replacement ID without its inherited progress boundary.
            self._current_progress_baseline = (
                admitted.id,
                files,
                byte_count,
                generation,
            )
            self._current_operation_id = admitted.id

        return remember

    def status(self) -> DaemonStatusV1:
        with self._lifecycle_lock:
            current_operation_id = self._current_operation_id
            admission_blocker_id = self._admission_blocker_id
            quarantined_operation_ids = tuple(
                sorted(self._quarantined_operation_ids)
            )
            accepting_mutations = self._accepting_mutations
        current = self._lookup_operation(current_operation_id)
        if current is not None and current.state not in {
            "running",
            "recovery_required",
        }:
            current = None
        blocker = None
        blocker_ids = (
            *((admission_blocker_id,) if admission_blocker_id is not None else ()),
            *quarantined_operation_ids,
        )
        for blocker_id in dict.fromkeys(blocker_ids):
            candidate = self._lookup_operation(blocker_id)
            if candidate is not None and candidate.state == "recovery_required":
                blocker = candidate
                break
        # Critical quarantine deliberately leaves the internal lifecycle open for
        # its protected administrator endpoints.  The public status must still
        # fail closed so maintenance/deployment clients cannot mistake it for a
        # quiescent daemon.
        accepting_mutations = accepting_mutations and blocker is None
        snapshot = self._diagnostics.snapshot()
        job_summary = None
        expected_media = None
        files_total = snapshot.files_completed
        bytes_total = snapshot.bytes_completed
        drive = DriveStatusV1(
            state="unavailable", loaded=None, display_label="",
            cleaning_required=None, tape_alert_codes=None,
        )
        with Catalog(self.paths.catalog_file) as catalog:
            # The durable writing phase follows media validation and mounting.
            # Project only this operation's cached proof; status must never probe
            # a drive concurrently with the operation that owns it.
            if current is not None and current.state == "running" and current.phase in {
                "writing", "writing_manifest", "finalizing_index", "unmounting",
                "restoring", "verifying",
            }:
                binding = catalog.media_identity_binding_evidence(current.id)
                if binding is not None:
                    command = catalog.command(str(binding["bound_by_command_id"]))
                    target = catalog.hardware_target_binding(current.id)
                    if (
                        command is not None
                        and command.operation_id == current.id
                        and command.issued_generation == self._operations.daemon_fence.generation
                        and command.kind == "probe_media"
                        and command.state == "quiesced"
                        and command.exit_outcome == "completed"
                        and command.target == target
                    ):
                        drive = DriveStatusV1(
                            state="busy", loaded=True,
                            display_label=catalog.operation_cassette_label(current.id) or "",
                            cleaning_required=None, tape_alert_codes=None,
                        )
            job = catalog.connection.execute(
                "SELECT * FROM automatic_jobs "
                "WHERE status NOT IN ('completed','failed') "
                "ORDER BY created_at DESC,id DESC LIMIT 1"
            ).fetchone()
            cassette = None
            if job is not None:
                job_labels = tuple(
                    str(row["physical_label"])
                    for row in catalog.connection.execute(
                        "SELECT physical_label FROM automatic_cassettes "
                        "WHERE job_id=? ORDER BY sequence",
                        (job["id"],),
                    ).fetchall()
                )
                cassette = catalog.connection.execute(
                    "SELECT * FROM automatic_cassettes WHERE job_id=? "
                    "AND status NOT IN ('completed','failed') ORDER BY sequence LIMIT 1",
                    (job["id"],),
                ).fetchone()
                sequence = (
                    int(cassette["sequence"])
                    if cassette is not None
                    else max(1, int(job["current_sequence"]))
                )
                job_summary = JobSummaryV1(
                    id=job["id"],
                    display_name=job["display_name"],
                    state=job["status"],
                    current_sequence=sequence,
                    total_cassettes=int(job["total_cassettes"]),
                    labels=job_labels,
                )
            if cassette is not None:
                expected_media = ExpectedMediaV1(
                    sequence=int(cassette["sequence"]),
                    label=cassette["physical_label"],
                    format_required=cassette["operation"] == "format",
                )
                files_total = int(cassette["planned_files"])
                bytes_total = int(cassette["planned_bytes"])
        operation_window_pending = False
        if current is None and job_summary is None:
            completed_files = snapshot.files_completed
            completed_bytes = snapshot.bytes_completed
        elif current is None:
            completed_files = 0
            completed_bytes = 0
        else:
            with self._lifecycle_lock:
                baseline = self._current_progress_baseline
            if baseline is not None and baseline[0] == current.id:
                operation_window_pending = snapshot.window_generation <= baseline[3]
                if operation_window_pending:
                    completed_files = 0
                    completed_bytes = 0
                else:
                    completed_files = max(0, snapshot.files_completed - baseline[1])
                    completed_bytes = max(0, snapshot.bytes_completed - baseline[2])
            else:
                completed_files = snapshot.files_completed
                completed_bytes = snapshot.bytes_completed
        critical_recovery = (
            None
            if blocker is None
            else self._critical_recovery_projection(blocker.id)
        )
        telemetry_payload = snapshot.to_api_telemetry()
        if operation_window_pending:
            telemetry_payload = {
                "current_mib_per_second": None,
                "effective_mib_per_second": None,
                "samples": (),
                "durations": {
                    "copy_seconds": 0.0,
                    "close_seconds": 0.0,
                    "finalization_seconds": 0.0,
                    "unmount_seconds": 0.0,
                    "unload_seconds": 0.0,
                },
            }
        return DaemonStatusV1(
            accepting_mutations=accepting_mutations,
            admission_blocker=_operation_response(blocker),
            drive=drive,
            expected_media=expected_media,
            job=job_summary,
            operation=_operation_response(current),
            critical_recovery=critical_recovery,
            progress=ProgressV1(
                files_completed=completed_files,
                files_total=max(files_total, completed_files),
                bytes_completed=completed_bytes,
                bytes_total=max(bytes_total, completed_bytes),
            ),
            telemetry=TelemetryV1.model_validate(telemetry_payload),
        )

    def get_pre_media_reset(self, operation_id: str, principal: Principal) -> PreMediaResetProofV1:
        if principal.role != "admin" or principal.direct_local_admin:
            raise RoleDenied("WebUI administrator is required")
        with Catalog(self.paths.catalog_file) as catalog:
            if catalog.get_operation(operation_id) is None:
                raise PreMediaResetNotFound(operation_id)
            try:
                return PreMediaResetProofV1.model_validate(catalog.pre_media_reset_proof(operation_id, self.daemon_fence))
            except (CatalogError, StaleDaemonFence) as exc:
                raise PreMediaResetRejected(str(exc)) from exc

    def reset_pre_media_attempt(
        self, operation_id: str, request: ResetPreMediaAttemptRequestV1,
        idempotency_key: str, principal: Principal,
    ) -> OperationRecord:
        now = time.time()
        if (principal.role != "admin" or principal.direct_local_admin
            or principal.session_binding_sha256 is None or principal.reauthenticated_at is None
            or not now - 600 <= principal.reauthenticated_at <= now + 30):
            raise RoleDenied("recent WebUI administrator reauthentication is required")
        if request.operation_id != operation_id or not idempotency_key.strip() or len(idempotency_key) > 128:
            raise PreMediaResetRejected("pre-media reset request does not match the operation")
        payload = request.model_dump(mode="json")
        operations = self._require_operations()
        try:
            with self._critical_action_lock, operations.stopped_pre_media_reset(operation_id):
                if self._shutdown_requested.is_set():
                    raise PreMediaResetRejected("daemon is shutting down")
                with Catalog(self.paths.catalog_file) as catalog:
                    replay = catalog.pre_media_reset_replay(
                        payload, self.daemon_fence, principal=principal.name,
                        session_binding_sha256=principal.session_binding_sha256, idempotency_key=idempotency_key,
                    )
                    if replay is None:
                        current = catalog.pre_media_reset_proof(operation_id, self.daemon_fence)
                        if current != payload:
                            raise PreMediaResetRejected("pre-media reset proof changed")
                        commands = catalog.hardware_commands_for_operation(operation_id)
                        operation = operations.operation(operation_id)
                if replay is not None:
                    result = replay
                else:
                    if self._pre_media_reset_reconciler is None or operation is None:
                        raise PreMediaResetRejected("pre-media scope reconciliation is unavailable")
                    receipt = self._pre_media_reset_reconciler(operation, self.daemon_fence)
                    if not isinstance(receipt, CommandQuiescenceReceipt):
                        raise PreMediaResetRejected("pre-media scope receipt is unavailable")
                    with Catalog(self.paths.catalog_file) as catalog:
                        result = catalog.finalize_pre_media_reset(
                            payload, self.daemon_fence, commands, receipt.id,
                            principal=principal.name, session_binding_sha256=principal.session_binding_sha256,
                            idempotency_key=idempotency_key,
                        )
            # Admission/shutdown acquire lifecycle before the operation lock.
            # Release both action locks first, including on durable replay; a
            # prior postcommit refresh failure must be repairable by retry.
            with self._lifecycle_lock:
                blockers = operations.reconcile_admission_blockers()
                self._set_admission_blockers_locked(self._nonquarantined_blockers(blockers))
            # No sequence wake: only an explicit resume can continue this paused job.
            return result
        except PreMediaResetRejected:
            raise
        except Exception as exc:
            raise PreMediaResetRejected("pre-media safety reconciliation was rejected") from exc

    def critical_recovery_proof(
        self, operation_id: str, principal: Principal
    ) -> CriticalRecoveryProofV1:
        if principal.direct_local_admin or principal.role != "admin":
            raise RoleDenied("recently reauthenticated WebUI admin is required")
        proof = self._critical_recovery_projection(operation_id)
        if proof is None:
            raise CriticalRecoveryNotFound("critical recovery proof is unavailable")
        return proof

    def _critical_recovery_projection(
        self, operation_id: str
    ) -> CriticalRecoveryProofV1 | None:
        with Catalog(self.paths.catalog_file) as catalog:
            operation = catalog.get_operation(operation_id)
            attempts = catalog.list_recovery_attempts(operation_id)
            critical = next(
                (
                    item
                    for item in reversed(attempts)
                    if item.state == "critical_quarantine"
                ),
                None,
            )
            if (
                operation is None
                or operation["state"] != "recovery_required"
                or critical is None
                or not isinstance(operation["job_id"], str)
                or type(operation["cassette_sequence"]) is not int
            ):
                return None
            try:
                cassette_label = catalog.operation_cassette_label(operation_id)
            except CatalogError:
                cassette_label = None
            target = catalog.hardware_target_binding(operation_id)
            media = catalog.media_identity_binding_evidence(operation_id)
            commands = catalog.hardware_commands_for_operation(operation_id)
            physical = catalog.latest_physical_reconciliation_receipt(operation_id)
            reassessment = catalog.latest_critical_reassessment(
                operation_id,
                attempt_number=critical.attempt_number,
                daemon_generation=critical.daemon_generation,
            )
            if cassette_label is None or target is None:
                return None
            evidence_category = str(critical.decision)
            evidence_sha256 = critical.evidence_sha256
            observed_media_identity_sha256 = (
                None
                if media is None
                else str(media["observed_media_identity_sha256"])
            )
            commands_quiescent = bool(commands) and all(
                item.state == "quiesced" for item in commands
            )
            mount_quiescent = physical is not None and not physical.mounted
            processes_quiescent = (
                physical is not None and not physical.related_processes
            )
            observed_at = critical.outcome_at or critical.started_at
            if (
                reassessment is not None
                and reassessment.daemon_generation == critical.daemon_generation
            ):
                evidence_category = reassessment.evidence_category
                evidence_sha256 = reassessment.evidence_sha256
                observed_media_identity_sha256 = (
                    reassessment.observed_media_identity_sha256
                    or reassessment.bound_media_identity_sha256
                )
                commands_quiescent = reassessment.commands_quiescent
                mount_quiescent = not reassessment.mounted
                processes_quiescent = reassessment.related_process_count == 0
                observed_at = reassessment.observed_at
            return CriticalRecoveryProofV1(
                operation_id=operation_id,
                job_id=str(operation["job_id"]),
                cassette_sequence=int(operation["cassette_sequence"]),
                expected_label=cassette_label,
                target=CriticalRecoveryTargetV1(
                    mount_path_sha256=target.mount_path_sha256,
                    tape_device_identity_sha256=target.tape_device_identity_sha256,
                    scsi_device_identity_sha256=target.scsi_device_identity_sha256,
                    expected_media_scope_sha256=target.expected_media_scope_sha256,
                ),
                daemon_generation=critical.daemon_generation,
                attempt_number=critical.attempt_number,
                last_safe_checkpoint=(
                    None if operation["phase"] is None else str(operation["phase"])
                ),
                evidence_category=evidence_category,
                evidence_sha256=evidence_sha256,
                observed_media_identity_sha256=observed_media_identity_sha256,
                commands_quiescent=commands_quiescent,
                mount_quiescent=mount_quiescent,
                processes_quiescent=processes_quiescent,
                observed_at=observed_at,
                safe_explanation=(
                    "Contradictory recovery evidence prevents an automatic transition."
                ),
                safe_next_action=(
                    "Re-run safe reconciliation or use one bounded administrator action."
                ),
            )

    @staticmethod
    def _critical_request_matches_proof(
        request: ReconcileCriticalRecoveryRequestV1
        | AbandonCriticalAttemptRequestV1
        | AuthorizeReplacementAttemptRequestV1,
        proof: CriticalRecoveryProofV1,
    ) -> bool:
        return bool(
            request.operation_id == proof.operation_id
            and request.job_id == proof.job_id
            and request.cassette_sequence == proof.cassette_sequence
            and request.expected_label == proof.expected_label
            and request.target == proof.target
            and request.daemon_generation == proof.daemon_generation
            and request.attempt_number == proof.attempt_number
            and request.evidence_sha256 == proof.evidence_sha256
            and request.observed_media_identity_sha256
            == proof.observed_media_identity_sha256
        )

    def reconcile_critical_recovery(
        self,
        operation_id: str,
        request: ReconcileCriticalRecoveryRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> CriticalRecoveryProofV1:
        with self._critical_action_lock:
            try:
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.assert_critical_one_shot_available(
                        operation_id,
                        self.daemon_fence,
                        principal=principal.name,
                        idempotency_key=idempotency_key,
                        action="reconcile",
                    )
            except CatalogError as exc:
                raise CriticalRecoveryRejected(str(exc)) from exc
            except StaleDaemonFence:
                self._reject_critical_daemon_turnover(
                    operation_id, principal, idempotency_key, "reconcile"
                )
            current = self.critical_recovery_proof(operation_id, principal)
            if not self._critical_request_matches_proof(request, current):
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "reconcile",
                    "proof_mismatch",
                )
                raise CriticalRecoveryRejected(
                    "critical recovery proof is stale or mismatched"
                )
            observation_started_at = self._critical_action_now()
            observation = self._observe_critical_action(operation_id)
            if observation is None:
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "reconcile",
                    "observation_incomplete",
                )
                raise CriticalRecoveryRejected(
                    "critical reassessment proof is stale or incomplete"
                )
            consumed_at = self._critical_action_now()
            try:
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.record_critical_reassessment(
                        operation_id,
                        self.daemon_fence,
                        principal=principal.name,
                        idempotency_key=idempotency_key,
                        job_id=request.job_id,
                        cassette_sequence=request.cassette_sequence,
                        expected_label=request.expected_label,
                        expected_daemon_generation=request.daemon_generation,
                        attempt_number=request.attempt_number,
                        evidence_sha256=request.evidence_sha256,
                        target=HardwareTargetBinding(
                            request.target.mount_path_sha256,
                            request.target.tape_device_identity_sha256,
                            request.target.scsi_device_identity_sha256,
                            request.target.expected_media_scope_sha256,
                        ),
                        observed_media_identity_sha256=(
                            request.observed_media_identity_sha256
                        ),
                        observation=observation,
                        consumed_at=consumed_at,
                        observation_started_at=observation_started_at,
                    )
            except CatalogError as exc:
                raise CriticalRecoveryRejected(str(exc)) from exc
            except StaleDaemonFence:
                self._reject_critical_daemon_turnover(
                    operation_id, principal, idempotency_key, "reconcile"
                )
            persisted = self._critical_recovery_projection(operation_id)
            if persisted is None:
                raise CatalogError("critical reassessment projection is unavailable")
            return persisted

    def _critical_action_now(self) -> str:
        value = self._critical_recovery_clock()
        if (
            not isinstance(value, datetime)
            or value.tzinfo is None
            or value.utcoffset() != timedelta(0)
        ):
            raise CatalogError("critical recovery clock is invalid")
        return value.isoformat(timespec="microseconds")

    def _observe_critical_action(
        self, operation_id: str
    ) -> CriticalRecoveryObservation | None:
        coordinator = self._recovery_coordinator
        if coordinator is None:
            return None
        try:
            assessment = coordinator.reassess_critical(operation_id)
        except Exception:  # noqa: BLE001 - observation failure is a closed rejection.
            return None
        observation = getattr(assessment, "observation", None)
        evidence_sha256 = getattr(assessment, "evidence_sha256", None)
        decision = getattr(assessment, "decision", None)
        reason = getattr(decision, "reason", None)
        evidence_category = getattr(reason, "value", None)
        if (
            not isinstance(observation, CriticalRecoveryObservation)
            or observation.operation_id != operation_id
            or observation.evidence_sha256 != evidence_sha256
            or observation.evidence_category != evidence_category
        ):
            return None
        return observation

    def _reject_critical_action(
        self,
        operation_id: str,
        principal: Principal,
        idempotency_key: str,
        action: str,
        reason: str,
    ) -> None:
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.reject_critical_action_once(
                    operation_id,
                    self.daemon_fence,
                    principal=principal.name,
                    idempotency_key=idempotency_key,
                    action=action,
                    reason=reason,
                )
        except CatalogError as exc:
            raise CriticalRecoveryRejected(str(exc)) from exc
        except StaleDaemonFence:
            self._reject_critical_daemon_turnover(
                operation_id, principal, idempotency_key, action
            )

    def _reject_critical_daemon_turnover(
        self,
        operation_id: str,
        principal: Principal,
        idempotency_key: str,
        action: str,
    ) -> None:
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                catalog.reject_critical_action_for_daemon_turnover(
                    operation_id,
                    self.daemon_fence,
                    principal=principal.name,
                    idempotency_key=idempotency_key,
                    action=action,
                )
        except CatalogError as exc:
            raise CriticalRecoveryRejected(str(exc)) from exc
        raise CriticalRecoveryRejected("critical recovery daemon generation changed")

    def abandon_critical_recovery(
        self,
        operation_id: str,
        request: AbandonCriticalAttemptRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> OperationRecord:
        with self._critical_action_lock:
            try:
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.assert_critical_one_shot_available(
                        operation_id,
                        self.daemon_fence,
                        principal=principal.name,
                        idempotency_key=idempotency_key,
                        action="abandon",
                    )
            except CatalogError as exc:
                raise CriticalRecoveryRejected(str(exc)) from exc
            except StaleDaemonFence:
                self._reject_critical_daemon_turnover(
                    operation_id, principal, idempotency_key, "abandon"
                )
            current = self.critical_recovery_proof(operation_id, principal)
            if not self._critical_request_matches_proof(request, current):
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "abandon",
                    "proof_mismatch",
                )
                raise CriticalRecoveryRejected(
                    "critical recovery proof is stale or mismatched"
                )
            observation = self._observe_critical_action(operation_id)
            if observation is None:
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "abandon",
                    "observation_incomplete",
                )
                raise CriticalRecoveryRejected(
                    "critical action observation is unavailable"
                )
            target = HardwareTargetBinding(
                request.target.mount_path_sha256,
                request.target.tape_device_identity_sha256,
                request.target.scsi_device_identity_sha256,
                request.target.expected_media_scope_sha256,
            )
            try:
                with Catalog(self.paths.catalog_file) as catalog:
                    result = catalog.abandon_critical_attempt(
                        operation_id,
                        self.daemon_fence,
                        principal=principal.name,
                        idempotency_key=idempotency_key,
                        job_id=request.job_id,
                        cassette_sequence=request.cassette_sequence,
                        expected_label=request.expected_label,
                        expected_daemon_generation=request.daemon_generation,
                        attempt_number=request.attempt_number,
                        evidence_sha256=request.evidence_sha256,
                        target=target,
                        observed_media_identity_sha256=(
                            request.observed_media_identity_sha256
                        ),
                        observation=observation,
                        consumed_at=self._critical_action_now(),
                    )
            except CatalogError as exc:
                raise CriticalRecoveryRejected(str(exc)) from exc
            except StaleDaemonFence:
                self._reject_critical_daemon_turnover(
                    operation_id, principal, idempotency_key, "abandon"
                )
        with self._lifecycle_lock:
            remaining = self._require_operations().reconcile_admission_blockers()
            self._set_admission_blockers_locked(remaining)
        return result

    def authorize_critical_replacement(
        self,
        operation_id: str,
        request: AuthorizeReplacementAttemptRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> OperationRecord:
        with self._critical_action_lock:
            try:
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.assert_critical_one_shot_available(
                        operation_id,
                        self.daemon_fence,
                        principal=principal.name,
                        idempotency_key=idempotency_key,
                        action="authorize_replacement",
                    )
            except CatalogError as exc:
                raise CriticalRecoveryRejected(str(exc)) from exc
            except StaleDaemonFence:
                self._reject_critical_daemon_turnover(
                    operation_id,
                    principal,
                    idempotency_key,
                    "authorize_replacement",
                )
            current = self.critical_recovery_proof(operation_id, principal)
            if not self._critical_request_matches_proof(request, current):
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "authorize_replacement",
                    "proof_mismatch",
                )
                raise CriticalRecoveryRejected(
                    "critical recovery proof is stale or mismatched"
                )
            if request.observed_media_identity_sha256 is None:
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "authorize_replacement",
                    "media_identity_required",
                )
                raise CriticalRecoveryRejected(
                    "critical replacement requires an exact loaded media identity"
                )
            callback = self._critical_replacement_callback
            if callback is None:
                raise MutationAdmissionClosed("critical replacement is unavailable")
            operations = self._require_operations()
            blocker = operations.operation(operation_id)
            if blocker is None:
                raise CriticalRecoveryRejected(
                    "critical recovery proof is stale or mismatched"
                )
            observation = self._observe_critical_action(operation_id)
            if observation is None:
                self._reject_critical_action(
                    operation_id,
                    principal,
                    idempotency_key,
                    "authorize_replacement",
                    "observation_incomplete",
                )
                raise CriticalRecoveryRejected(
                    "critical action observation is unavailable"
                )
            target = HardwareTargetBinding(
                request.target.mount_path_sha256,
                request.target.tape_device_identity_sha256,
                request.target.scsi_device_identity_sha256,
                request.target.expected_media_scope_sha256,
            )
            try:
                remember_replacement = self.prepare_replacement_admission()
                replacement = operations.authorize_critical_replacement(
                blocker,
                RecoveryCommandFence(operation_id, request.daemon_generation),
                callback,
                principal=principal.name,
                idempotency_key=idempotency_key,
                job_id=request.job_id,
                cassette_sequence=request.cassette_sequence,
                expected_label=request.expected_label,
                attempt_number=request.attempt_number,
                evidence_sha256=request.evidence_sha256,
                target=target,
                observed_media_identity_sha256=(
                    request.observed_media_identity_sha256
                ),
                    observation=observation,
                    consumed_at=self._critical_action_now(),
                    on_admitted=remember_replacement,
                )
            except CatalogError as exc:
                raise CriticalRecoveryRejected(str(exc)) from exc
            except StaleDaemonFence:
                self._reject_critical_daemon_turnover(
                    operation_id,
                    principal,
                    idempotency_key,
                    "authorize_replacement",
                )
        with self._lifecycle_lock:
            remaining = operations.reconcile_admission_blockers()
            self._set_admission_blockers_locked(remaining)
        # Startup may have constructed but not started this coordinator while
        # the critical blocker existed. Start observing even while replacement
        # is busy: the coordinator's durable busy/pause/authority checks prevent
        # admission until it finishes, without relying on another GUI command.
        self._activate_sequence_coordinator()
        return replacement

    def storage_summary(self) -> StorageSummaryV1:
        return self._storage_monitor.snapshot()

    def diagnostics_summary(self) -> DiagnosticSummaryV1:
        """Return a closed, redacted diagnostic projection with all phases."""

        summary = self._diagnostics.summary()
        snapshot = summary.telemetry
        telemetry = snapshot.to_api_telemetry()
        return DiagnosticSummaryV1(
            health=DiagnosticHealthV1(
                status=summary.health.status.value,
                cleaning_required=summary.health.cleaning_required,
                tape_alert_codes=tuple(
                    int(code) for code in summary.health.tape_alert_codes
                ),
            ),
            telemetry=DiagnosticTelemetryV1(
                files_completed=snapshot.files_completed,
                bytes_completed=snapshot.bytes_completed,
                current_mib_per_second=telemetry["current_mib_per_second"],
                effective_mib_per_second=telemetry["effective_mib_per_second"],
                samples=telemetry["samples"],
                phase_durations=DiagnosticPhaseDurationsV1.model_validate(
                    snapshot.durations.to_diagnostic_payload()
                ),
                current_phase=(
                    snapshot.current_phase.value
                    if snapshot.current_phase is not None
                    else None
                ),
                closed=snapshot.closed,
            ),
        )

    def diagnostics_export(self) -> bytes:
        """Create one bounded redacted bundle without exposing a destination."""

        return self._diagnostics.export_bytes()

    def record_telemetry_file(self, byte_count: int) -> TelemetrySnapshot:
        return self._diagnostics.record_file(byte_count)

    def mark_telemetry_unavailable(self) -> TelemetrySnapshot:
        return self._diagnostics.mark_unavailable()

    def add_telemetry_duration(
        self, phase: TelemetryPhase | str, seconds: float
    ) -> TelemetrySnapshot:
        return self._diagnostics.add_duration(phase, seconds)

    def start_telemetry_phase(self, phase: TelemetryPhase | str) -> TelemetrySnapshot:
        return self._diagnostics.start_phase(phase)

    def finish_telemetry_phase(self, phase: TelemetryPhase | str) -> TelemetrySnapshot:
        return self._diagnostics.finish_phase(phase)

    def settings_summary(self) -> SettingsSummaryV1:
        return SettingsSummaryV1.model_validate(self.settings.safe_summary())

    def application_settings(self, principal: Principal) -> ApplicationSettingsV1:
        self.authorize_command(principal, capability="application.settings")
        payload = dict(self._management.application_settings())
        payload.pop("legacy_source_sha256", None)
        return ApplicationSettingsV1.model_validate(payload)

    async def update_application_settings(
        self,
        request: UpdateApplicationSettingsRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ApplicationSettingsV1:
        try:
            self.authorize_command(principal, capability="application.settings")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            candidate = request.model_dump(mode="python", exclude={"expected_revision"})
            payload = await self._management.update_application_settings(
                candidate,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:
            self.record_application_settings_rejection(
                principal.name,
                self._application_settings_rejection_code(exc),
                expected_revision=request.expected_revision,
            )
            raise
        payload.pop("legacy_source_sha256", None)
        return ApplicationSettingsV1.model_validate(payload)

    @staticmethod
    def _application_settings_rejection_code(exc: Exception) -> str:
        if isinstance(exc, RoleDenied):
            return "role_denied"
        if isinstance(exc, MutationAdmissionClosed):
            return "mutation_admission_closed"
        code = getattr(exc, "code", None)
        if code in {
            "application_settings_error",
            "settings_revision_conflict",
            "idempotency_conflict",
        }:
            return str(code)
        return "internal_error"

    def record_application_settings_rejection(
        self,
        principal: str,
        error_code: str,
        *,
        expected_revision: int | None = None,
    ) -> None:
        allowed = {
            "application_settings_error",
            "idempotency_conflict",
            "internal_error",
            "mutation_admission_closed",
            "role_denied",
            "settings_revision_conflict",
            "untrusted_peer",
            "validation_error",
        }
        safe_code = error_code if error_code in allowed else "internal_error"
        payload: dict[str, object] = {"error_code": safe_code}
        if type(expected_revision) is int and expected_revision >= 1:
            payload["expected_revision"] = expected_revision
        self._record_audit(
            principal,
            "application.settings.update",
            "rejected",
            payload,
        )

    def host_settings(self, principal: Principal) -> HostSettingsV1:
        self.authorize_command(principal, capability="application.settings")
        return HostSettingsV1(
            daemon_socket_path=str(self.settings.socket_path),
            service_group=self.settings.socket_group,
            state_directory=str(self.settings.state_dir),
            tape_device_path=str(self.settings.tape_device_path),
            scsi_device_path=str(self.settings.scsi_device_path),
            mount_path=str(self.settings.mount_path),
            managed_source_mount_root=str(self.settings.managed_source_mount_root),
            source_allowlist=tuple(str(path) for path in self.settings.source_roots),
            restore_roots=tuple(str(path) for path in self.settings.restore_roots),
            required_restart=False,
        )

    @staticmethod
    def _library_response(summary: Mapping[str, object]) -> LibrarySummaryV1:
        return LibrarySummaryV1.model_validate(
            {
                key: summary[key]
                for key in (
                    "id",
                    "display_name",
                    "source_root",
                    "source",
                    "state",
                    "scan_state",
                    "last_successful_scan_at",
                    "file_count",
                    "byte_count",
                    "revision",
                )
            }
        )

    async def list_libraries(
        self, principal: Principal
    ) -> tuple[LibrarySummaryV1, ...]:
        self.authorize_command(principal, capability="read")
        rows = await self._management.list_libraries()
        return tuple(self._library_response(row) for row in rows)

    async def get_library(
        self, library_id: str, principal: Principal
    ) -> LibrarySummaryV1:
        self.authorize_command(principal, capability="read")
        return self._library_response(await self._management.get_library(library_id))

    @staticmethod
    def _catalog_file_version_response(
        item: Mapping[str, object],
    ) -> CatalogFileVersionV1:
        return CatalogFileVersionV1.model_validate(
            {
                key: item[key]
                for key in (
                    "id",
                    "library_id",
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
                    "relative_path",
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
                    "metadata_state",
                    "metadata_error",
                    "sha256",
                    "copied_at",
                    "is_current",
                )
            }
        )

    def search_catalog_file_versions(
        self,
        principal: Principal,
        *,
        query: str = "",
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
    ) -> CatalogSearchPageV1:
        self.authorize_command(principal, capability="read")
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                page = catalog.search_file_versions(
                    query=query,
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
        except DomainValidationError as exc:
            raise CatalogQueryInvalid("invalid catalog query") from exc
        return CatalogSearchPageV1(
            items=tuple(
                self._catalog_file_version_response(item) for item in page["items"]
            ),
            next_cursor=page["next_cursor"],
        )

    def browse_catalog_backup_children(
        self,
        library_id: str,
        parent_path: str,
        principal: Principal,
        *,
        limit: int = 50,
        cursor: str | None = None,
    ) -> CatalogBrowsePageV1:
        self.authorize_command(principal, capability="read")
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                page = catalog.browse_backup_children_page(
                    library_id, parent_path, limit=limit, cursor=cursor
                )
                items = tuple(
                    self._catalog_browse_entry_response(
                        entry,
                        catalog.get_file_version(int(entry["id"]))
                        if entry["kind"] == "file"
                        else None,
                    )
                    for entry in page["items"]
                )
        except DomainValidationError as exc:
            raise CatalogQueryInvalid("invalid catalog path") from exc
        except CatalogError as exc:
            raise CatalogLibraryNotFound("catalog library not found") from exc
        return CatalogBrowsePageV1(items=items, next_cursor=page["next_cursor"])

    def get_catalog_file_version(
        self, version_id: int, principal: Principal
    ) -> CatalogFileVersionV1:
        self.authorize_command(principal, capability="read")
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                item = catalog.get_file_version(version_id)
        except DomainValidationError as exc:
            raise CatalogQueryInvalid("invalid catalog file version") from exc
        except CatalogError as exc:
            raise CatalogFileVersionNotFound("catalog file version not found") from exc
        return self._catalog_file_version_response(item)

    def catalog_restore_options(self, principal: Principal) -> CatalogRestoreOptionsV1:
        self.authorize_command(principal, capability="read")
        return CatalogRestoreOptionsV1(
            restore_roots=tuple(str(path) for path in self.settings.restore_roots)
        )

    async def create_catalog_restore_plan(
        self,
        request: CreateCatalogRestorePlanRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> CatalogRestorePlanV1:
        self.authorize_command(principal, capability="job.manage")
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
        try:
            plan = await self._management.create_restore_plan(
                request.file_version_ids,
                destination_root=request.destination_root,
                destination_subdirectory=request.destination_subdirectory,
                allowed_restore_roots=self.settings.restore_roots,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except DomainValidationError as exc:
            raise CatalogRestorePlanInvalid("invalid restore plan") from exc
        except CatalogError as exc:
            if "catalog_file_version_not_found" in str(exc):
                raise CatalogFileVersionNotFound(
                    "catalog file version not found"
                ) from exc
            if str(exc).partition(":")[0] == "idempotency_conflict":
                raise CatalogRestorePlanConflict(
                    "restore plan request conflicts"
                ) from exc
            raise
        return CatalogRestorePlanV1.model_validate(plan)

    def get_catalog_restore_plan(
        self, plan_id: str, principal: Principal
    ) -> CatalogRestorePlanV1:
        self.authorize_command(principal, capability="read")
        try:
            plan = self._management.get_restore_plan(plan_id)
        except (CatalogError, DomainValidationError) as exc:
            raise CatalogRestorePlanNotFound("restore plan not found") from exc
        return CatalogRestorePlanV1.model_validate(plan)

    def start_catalog_restore_run(
        self, plan_id: str, idempotency_key: str, principal: Principal
    ) -> CatalogRestoreRunV1:
        """Create or replay one immutable plan run, then wake its coordinator."""

        self.authorize_command(principal, capability="job.manage")
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
            coordinator = self._require_restore_coordinator_locked()
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                run = catalog.create_restore_run(
                    plan_id,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                    request_sha256=hashlib.sha256(b"{}").hexdigest(),
                )
        except DomainValidationError as exc:
            raise CatalogRestoreRunInvalid("invalid restore run request") from exc
        except CatalogError as exc:
            code = str(exc).partition(":")[0]
            if code == "restore_plan_not_found":
                raise CatalogRestorePlanNotFound("restore plan not found") from exc
            if code == "idempotency_conflict":
                raise CatalogRestoreRunConflict("restore run request conflicts") from exc
            if code == "restore_run_active":
                raise CatalogRestoreRunInvalid("restore plan already has an active run") from exc
            raise CatalogRestoreRunInvalid("restore run request was rejected") from exc
        coordinator.wake()
        return CatalogRestoreRunV1.model_validate(run)

    def get_catalog_restore_run(
        self, run_id: str, principal: Principal
    ) -> CatalogRestoreRunV1:
        self.authorize_command(principal, capability="read")
        try:
            with Catalog(self.paths.catalog_file) as catalog:
                run = catalog.restore_run(run_id)
        except (CatalogError, DomainValidationError) as exc:
            raise CatalogRestoreRunNotFound("restore run not found") from exc
        return CatalogRestoreRunV1.model_validate(run)

    def get_catalog_restore_run_cassette_result(
        self, run_id: str, cassette_sequence: int, principal: Principal
    ) -> CatalogRestoreRunCassetteV1:
        run = self.get_catalog_restore_run(run_id, principal)
        try:
            return next(
                cassette for cassette in run.cassettes
                if cassette.sequence == cassette_sequence
            )
        except StopIteration as exc:
            raise CatalogRestoreRunNotFound("restore cassette result not found") from exc

    def get_catalog_restore_run_item_result(
        self, run_id: str, item_sequence: int, principal: Principal
    ) -> CatalogRestoreRunItemV1:
        run = self.get_catalog_restore_run(run_id, principal)
        try:
            return next(item for item in run.items if item.sequence == item_sequence)
        except StopIteration as exc:
            raise CatalogRestoreRunNotFound("restore item result not found") from exc

    def pause_catalog_restore_run(
        self, run_id: str, idempotency_key: str, principal: Principal
    ) -> CatalogRestoreRunV1:
        return self._control_catalog_restore_run(
            "request_pause", run_id, idempotency_key, principal
        )

    def resume_catalog_restore_run(
        self, run_id: str, idempotency_key: str, principal: Principal
    ) -> CatalogRestoreRunV1:
        return self._control_catalog_restore_run("resume", run_id, idempotency_key, principal)

    def cancel_catalog_restore_run(
        self, run_id: str, idempotency_key: str, principal: Principal
    ) -> CatalogRestoreRunV1:
        return self._control_catalog_restore_run(
            "request_cancel", run_id, idempotency_key, principal
        )

    def _control_catalog_restore_run(
        self,
        command: Literal["request_pause", "resume", "request_cancel"],
        run_id: str,
        idempotency_key: str,
        principal: Principal,
    ) -> CatalogRestoreRunV1:
        self.authorize_command(principal, capability="job.manage")
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
            coordinator = self._require_restore_coordinator_locked()
        try:
            run = getattr(coordinator, command)(
                run_id, principal.name, idempotency_key
            )
        except DomainValidationError as exc:
            raise CatalogRestoreRunInvalid("invalid restore run control") from exc
        except CatalogError as exc:
            error_code = str(exc).partition(":")[0]
            if error_code == "restore_run_not_found":
                raise CatalogRestoreRunNotFound("restore run not found") from exc
            if error_code == "idempotency_conflict":
                raise CatalogRestoreRunConflict("restore run command conflicts") from exc
            raise CatalogRestoreRunInvalid("restore run control was rejected") from exc
        return CatalogRestoreRunV1.model_validate(run)

    def _require_restore_coordinator_locked(self) -> RestoreCoordinatorLifecycle:
        """Resolve the Task 5 restore coordinator without bypassing its wake gate."""

        coordinator = self._sequence_coordinator
        nested = getattr(coordinator, "_coordinators", ())
        candidates = (coordinator, *(nested if isinstance(nested, tuple) else ()))
        for candidate in candidates:
            if candidate is not None and all(
                callable(getattr(candidate, name, None))
                for name in ("wake", "request_pause", "request_cancel", "resume")
            ):
                return candidate  # type: ignore[return-value]
        raise RestoreCoordinatorUnavailable("restore coordinator is unavailable")

    def authorize_catalog_restore_item_replacement(
        self,
        run_id: str,
        item_sequence: int,
        *,
        fresh_reauthentication: str,
        idempotency_key: str,
        principal: Principal,
    ) -> CatalogRestoreReplacementAuthorizationV1:
        """Authorize one exact conflict through an administrator-only seam."""

        self.authorize_command(principal, capability="restore.replacement")
        replay_digest = hashlib.sha256(fresh_reauthentication.encode()).hexdigest()
        with Catalog(self.paths.catalog_file) as catalog:
            replay = catalog.restore_replacement_authorization_replay(
                run_id, item_sequence, administrator=principal.name,
                fresh_reauthentication=replay_digest, idempotency_key=idempotency_key,
            )
        if replay is not None:
            return CatalogRestoreReplacementAuthorizationV1.model_validate(replay)
        fresh_reauthentication = self._verify_restore_replacement_capability(
            fresh_reauthentication, principal
        )
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
        try:
            authorization = self._management.authorize_restore_item_replacement(
                run_id,
                item_sequence,
                administrator=principal.name,
                fresh_reauthentication=fresh_reauthentication,
                idempotency_key=idempotency_key,
            )
        except (CatalogError, DomainValidationError) as exc:
            code = str(exc).partition(":")[0]
            if code in {"restore conflict not found", "restore_item_not_found"}:
                raise CatalogRestoreRunNotFound("restore conflict not found") from exc
            if code == "idempotency_conflict":
                raise CatalogRestoreRunConflict(
                    "restore replacement request conflicts"
                ) from exc
            raise CatalogRestoreRunInvalid(
                "invalid restore replacement authorization"
            ) from exc
        return CatalogRestoreReplacementAuthorizationV1.model_validate(authorization)

    def issue_catalog_restore_replacement_capability(
        self, principal: Principal
    ) -> CatalogRestoreReplacementCapabilityV1:
        self.authorize_command(principal, capability="restore.replacement")
        if principal.direct_local_admin or principal.session_binding_sha256 is None:
            raise RoleDenied("a trusted WebUI administrator session is required")
        now = int(time.time())
        payload = {
            "purpose": "restore.replacement", "administrator": principal.name,
            "session": principal.session_binding_sha256, "issued_at": now,
            "expires_at": now + 300, "nonce": secrets.token_hex(32),
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        ).rstrip(b"=")
        signature = hmac.new(self._restore_reauthentication_key, encoded, hashlib.sha256).hexdigest()
        return CatalogRestoreReplacementCapabilityV1(
            capability=f"{encoded.decode()}.{signature}",
            expires_at=datetime.fromtimestamp(payload["expires_at"], UTC).isoformat(),
        )

    def _verify_restore_replacement_capability(
        self, capability: str, principal: Principal
    ) -> str:
        if principal.direct_local_admin or principal.session_binding_sha256 is None:
            raise RoleDenied("a trusted WebUI administrator session is required")
        encoded, separator, supplied = capability.partition(".")
        if not separator or not encoded or not re.fullmatch(r"[0-9a-f]{64}", supplied):
            raise CatalogRestoreRunInvalid("replacement capability is invalid")
        expected = hmac.new(self._restore_reauthentication_key, encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, supplied):
            raise CatalogRestoreRunInvalid("replacement capability is invalid")
        try:
            padded = encoded + "=" * (-len(encoded) % 4)
            payload = json.loads(base64.urlsafe_b64decode(padded))
            expiry = int(payload["expires_at"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise CatalogRestoreRunInvalid("replacement capability is invalid") from exc
        if (
            payload.get("purpose") != "restore.replacement"
            or payload.get("administrator") != principal.name
            or payload.get("session") != principal.session_binding_sha256
            or not isinstance(payload.get("nonce"), str)
            or expiry < time.time()
            or expiry > time.time() + 301
        ):
            raise CatalogRestoreRunInvalid("replacement capability is invalid")
        return hashlib.sha256(capability.encode()).hexdigest()

    @classmethod
    def _catalog_browse_entry_response(
        cls,
        entry: Mapping[str, object],
        file_detail: Mapping[str, object] | None = None,
    ) -> CatalogBrowseEntryV1:
        if entry["kind"] == "directory":
            return CatalogBrowseEntryV1(
                kind="directory",
                name=str(entry["name"]),
                library_id=str(entry["library_id"]),
                relative_path=str(entry["relative_path"]),
            )
        if file_detail is None:
            raise ValueError("catalog browse file detail is required")
        file_version = cls._catalog_file_version_response(file_detail)
        return CatalogBrowseEntryV1.model_validate(
            {
                "kind": "file",
                "name": file_version.file_name,
                **file_version.model_dump(),
            }
        )

    @staticmethod
    def _share_operation_response(row: Mapping[str, object]) -> ShareOperationV1:
        return ShareOperationV1.model_validate(
            {
                key: row[key]
                for key in (
                    "operation_id",
                    "share_id",
                    "action",
                    "state",
                    "safe_error_code",
                    "queued_at",
                    "started_at",
                    "finished_at",
                )
            }
        )

    @classmethod
    def _share_summary_response(cls, row: Mapping[str, object]) -> ShareSummaryV1:
        payload = {
            key: row[key]
            for key in (
                "share_id",
                "display_name",
                "protocol",
                "lifecycle",
                "desired_state",
                "observed_state",
                "safe_error_code",
                "last_checked_at",
                "revision",
            )
        }
        for key in ("current_operation", "latest_operation"):
            operation = row.get(key)
            payload[key] = (
                None if operation is None else cls._share_operation_response(operation)  # type: ignore[arg-type]
            )
        return ShareSummaryV1.model_validate(payload)

    @classmethod
    def _share_detail_response(cls, row: Mapping[str, object]) -> ShareV1:
        payload = cls._share_summary_response(row).model_dump(mode="json")
        payload.update(
            {
                "config": json.loads(str(row["config_json"])),
                "config_revision": row["config_revision"],
                "credential_generation": row["credential_generation"],
                "credential_configured": row["credential_configured"],
                "auto_connect": row["auto_connect"],
                "mount_identity_sha256": row["mount_identity_sha256"],
                "mounted_config_revision": row["mounted_config_revision"],
                "mounted_credential_generation": row["mounted_credential_generation"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            }
        )
        return ShareV1.model_validate(payload)

    def list_network_shares(self, principal: Principal) -> tuple[ShareSummaryV1, ...]:
        self.authorize_command(principal, capability="read")
        return tuple(
            self._share_summary_response(row)
            for row in self._management.list_network_shares()
        )

    def network_share_options(self, principal: Principal) -> NetworkShareOptionsV1:
        self.authorize_command(principal, capability="read")
        return NetworkShareOptionsV1(
            nfs_versions=NFS_VERSION_CHOICES,
            nfs_timeout_seconds=NFS_TIMEOUT_SECONDS_CHOICES,
            nfs_retransmissions=NFS_RETRANSMISSION_CHOICES,
            smb_dialects=SMB_DIALECT_CHOICES,
            lifecycles=("active", "disabled"),
        )

    def get_network_share(self, share_id: str, principal: Principal) -> ShareV1:
        self.authorize_command(principal, capability="library.manage")
        return self._share_detail_response(self._management.get_network_share(share_id))

    def create_network_share(
        self,
        request: CreateShareRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareV1:
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            row = self._management.create_network_share(
                request.share_id,
                request.display_name,
                request.config.model_dump(mode="json"),
                auto_connect=request.auto_connect,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:
            self.record_share_mutation_rejection(
                principal, "create", exc, request.share_id, idempotency_key, None
            )
            raise
        return self._share_detail_response(row)

    def update_network_share(
        self,
        share_id: str,
        request: UpdateShareRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareV1:
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            row = self._management.update_network_share(
                share_id,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
                display_name=request.display_name,
                config_payload=(
                    None
                    if request.config is None
                    else request.config.model_dump(mode="json")
                ),
                auto_connect=request.auto_connect,
                lifecycle=request.lifecycle,
            )
        except Exception as exc:
            self.record_share_mutation_rejection(
                principal,
                "update",
                exc,
                share_id,
                idempotency_key,
                request.expected_revision,
            )
            raise
        return self._share_detail_response(row)

    def mutate_network_share_credential(
        self,
        share_id: str,
        request: ShareCredentialRequestV1 | ShareCredentialClearRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareOperationV1:
        mutation = (
            "credential.clear"
            if isinstance(request, ShareCredentialClearRequestV1)
            else "credential.install"
        )
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            if isinstance(request, ShareCredentialClearRequestV1):
                try:
                    request.confirm(share_id)
                except ValueError:
                    raise ShareConfirmationMismatch(
                        "share confirmation does not match"
                    ) from None
                row = self._management.clear_network_share_credential(
                    share_id,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                )
            else:
                row = self._management.start_network_share_credential(
                    share_id,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                    username=request.username,
                    password=request.password,
                    domain=request.domain,
                )
        except Exception as exc:
            self.record_share_mutation_rejection(
                principal,
                mutation,
                exc,
                share_id,
                idempotency_key,
                request.expected_revision,
            )
            raise
        return self._share_operation_response(row)

    def start_network_share_operation(
        self,
        share_id: str,
        action: str,
        request: ShareOperationRequestV1 | ShareConfirmedOperationRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareOperationV1:
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            if isinstance(request, ShareConfirmedOperationRequestV1):
                try:
                    request.confirm(share_id)
                except ValueError:
                    raise ShareConfirmationMismatch(
                        "share confirmation does not match"
                    ) from None
            row = self._management.start_network_share_operation(
                share_id,
                action,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:
            self.record_share_mutation_rejection(
                principal,
                action,
                exc,
                share_id,
                idempotency_key,
                request.expected_revision,
            )
            raise
        return self._share_operation_response(row)

    def retire_network_share(
        self,
        share_id: str,
        request: ShareRetireRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareV1:
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            try:
                request.confirm(share_id)
            except ValueError:
                raise ShareConfirmationMismatch(
                    "share confirmation does not match"
                ) from None
            row = self._management.retire_network_share(
                share_id,
                typed_share_id=request.typed_share_id,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:
            self.record_share_mutation_rejection(
                principal,
                "retire",
                exc,
                share_id,
                idempotency_key,
                request.expected_revision,
            )
            raise
        return self._share_detail_response(row)

    def remove_network_share(
        self,
        share_id: str,
        request: ShareRemoveRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> ShareV1:
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            try:
                request.confirm(share_id)
            except ValueError:
                raise ShareConfirmationMismatch(
                    "share confirmation does not match"
                ) from None
            row = self._management.remove_network_share(
                share_id,
                typed_share_id=request.typed_share_id,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception as exc:
            self.record_share_mutation_rejection(
                principal,
                "remove",
                exc,
                share_id,
                idempotency_key,
                request.expected_revision,
            )
            raise
        return self._share_detail_response(row)

    def record_share_mutation_rejection(
        self,
        principal: Principal | str,
        mutation: str,
        exc: Exception | str,
        share_id: str | None,
        idempotency_key: str | None,
        expected_revision: int | None,
    ) -> None:
        allowed_mutations = {
            "connect",
            "create",
            "credential.clear",
            "credential.install",
            "disconnect",
            "reconcile",
            "remove",
            "retire",
            "test",
            "update",
        }
        safe_mutation = mutation if mutation in allowed_mutations else "update"
        if isinstance(principal, Principal):
            principal_name = principal.name
            role = principal.role
        else:
            principal_name = (
                principal if _SAFE_PRINCIPAL.fullmatch(principal) else "unknown"
            )
            role = "unknown"
        if isinstance(exc, str):
            code = exc
        elif isinstance(exc, RoleDenied):
            code = "role_denied"
        elif isinstance(exc, MutationAdmissionClosed):
            code = "mutation_admission_closed"
        else:
            candidate = getattr(exc, "code", None)
            code = candidate if isinstance(candidate, str) else "validation_error"
        allowed_codes = {
            "idempotency_conflict",
            "mutation_admission_closed",
            "role_denied",
            "share_authentication_failed",
            "share_broker_unavailable",
            "share_busy",
            "share_connected",
            "share_credentials_required",
            "share_endpoint_invalid",
            "share_endpoint_not_allowed",
            "share_has_libraries",
            "share_identity_changed",
            "share_in_use",
            "share_mount_failed",
            "share_not_found",
            "share_operation_timeout",
            "share_options_invalid",
            "share_recovery_required",
            "share_revision_conflict",
            "share_state_conflict",
            "share_unreachable",
            "validation_error",
        }
        payload: dict[str, object] = {
            "error_code": code if code in allowed_codes else "validation_error",
            "mutation": safe_mutation,
            "role": role if role in {"admin", "operator", "unknown"} else "unknown",
        }
        if isinstance(share_id, str) and re.fullmatch(
            r"[a-z0-9][a-z0-9-]{0,62}", share_id
        ):
            payload["share_id"] = share_id
        if type(expected_revision) is int and expected_revision >= 1:
            payload["expected_revision"] = expected_revision
        payload["idempotency_sha256"] = (
            hashlib.sha256(
                idempotency_key.encode("utf-8", errors="replace")
            ).hexdigest()
            if isinstance(idempotency_key, str)
            else None
        )
        self._record_audit(principal_name, "share.mutation", "rejected", payload)

    def get_network_share_operation(
        self, operation_id: str, principal: Principal
    ) -> ShareOperationV1:
        self.authorize_command(principal, capability="read")
        return self._share_operation_response(
            self._management.get_network_share_operation(operation_id)
        )

    async def list_jobs(
        self,
        principal: Principal,
        *,
        limit: int = 50,
        cursor: str | None = None,
        include_retired: bool = False,
    ) -> JobListPageV1:
        self.authorize_command(principal, capability="read")
        return JobListPageV1.model_validate(
            await self._management.list_jobs(
                limit=limit, cursor=cursor, include_retired=include_retired
            )
        )

    async def get_job(self, job_id: str, principal: Principal) -> JobDetailV1:
        self.authorize_command(principal, capability="read")
        return JobDetailV1.model_validate(await self._management.get_job(job_id))

    async def get_job_sequence_status(
        self, job_id: str, principal: Principal
    ) -> JobSequenceStatusV1:
        self.authorize_command(principal, capability="read")
        return JobSequenceStatusV1.model_validate(
            await self._management.get_job_sequence_status(job_id)
        )

    async def job_cassettes(
        self,
        job_id: str,
        principal: Principal,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JobCassettePageV1:
        self.authorize_command(principal, capability="read")
        return JobCassettePageV1.model_validate(
            await self._management.list_job_cassettes(
                job_id, limit=limit, cursor=cursor
            )
        )

    def _incremental_generation(self) -> int:
        with Catalog(self.paths.catalog_file) as catalog:
            row = catalog.connection.execute("SELECT generation FROM daemon_ownership WHERE singleton=1").fetchone()
        if row is None:
            raise MutationAdmissionClosed("daemon ownership is unavailable")
        return int(row["generation"])

    def incremental_coordinator(self) -> IncrementalScanCoordinator:
        return IncrementalScanCoordinator(
            self.paths.catalog_file,self._management,
            daemon_generation=self._incremental_generation)

    async def incremental_policy(self, job_id: str, principal: Principal) -> IncrementalPolicyV1:
        self.authorize_command(principal, capability="read")
        return IncrementalPolicyV1.model_validate(await self._management.incremental_policy(job_id))

    async def update_incremental_policy(
        self, job_id: str, request: UpdateIncrementalPolicyRequestV1,
        idempotency_key: str, principal: Principal,
    ) -> IncrementalPolicyV1:
        self.authorize_command(principal, capability="job.manage")
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
        result = await self._management.update_incremental_policy(
            job_id,request.cadence,expected_revision=request.expected_revision,
            actor=principal.name,idempotency_key=idempotency_key)
        return IncrementalPolicyV1.model_validate(result)

    async def scan_job_now(
        self, job_id: str, idempotency_key: str, principal: Principal,
    ) -> IncrementalScanResultV1:
        self.authorize_command(principal, capability="job.manage")
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
        result = await self.incremental_coordinator().run_job(
            job_id,"manual",actor=principal.name,idempotency_key=idempotency_key)
        return IncrementalScanResultV1.model_validate(
            {key: result.get(key) for key in (
                "run_id","state","recorded_at","discovered_files","discovered_bytes",
                "required_additional_labels","plan_id","plan_digest_sha256","error_code",
                "next_eligible_at") if key in result})

    @staticmethod
    def _job_plan_response(plan: Mapping[str, Any]) -> JobPlanV1:
        completed = tuple(plan.get("completed_assignments", ()))
        append_label = str(completed[-1]["physical_label"]) if completed else None
        reserve_labels = iter(plan.get("existing_reserve_labels", ()))
        cassettes = []
        for row in plan.get("cassettes", ()):
            operation = str(row["operation"])
            physical_label = None
            if operation == "append":
                physical_label = append_label
            elif operation == "reserve":
                physical_label = str(next(reserve_labels))
            cassettes.append(
                {
                    "sequence": int(row["sequence"]),
                    "physical_label": physical_label,
                    "bytes": int(row["payload_bytes"]),
                    "objects": int(row["objects"]),
                    "allocation_bytes": int(row["allocation_bytes"]),
                    "capacity_utilization": float(row["capacity_utilization"]),
                    "format_required": operation in {"format", "reserve"},
                    "operation": operation,
                }
            )
        return JobPlanV1.model_validate(
            {
                "id": plan["id"],
                "state": plan["state"],
                "kind": plan["kind"],
                "requires_automatic_format_authorization": plan[
                    "requires_automatic_format_authorization"
                ],
                "creator": plan["creator"],
                "created_at": plan["created_at"],
                "expires_at": plan["expires_at"],
                "library_ids": tuple(plan["library_ids"]),
                "media_profile": plan["media_key"],
                "capacity_reserve_bytes": int(
                    plan.get("capacity_reserve_bytes", 0)
                ),
                "digest_sha256": plan["digest_sha256"],
                "cassettes": tuple(cassettes),
                "base_job_id": plan.get("base_job_id"),
                "base_job_revision": plan.get("base_job_revision"),
                "base_job_fingerprint_sha256": plan.get("base_job_fingerprint_sha256"),
                "residual_append_capacity_bytes": int(
                    plan.get("residual_append_capacity_bytes", 0)
                ),
                "existing_reserve_labels": tuple(
                    plan.get("existing_reserve_labels", ())
                ),
                "completed_assignments": tuple(
                    {
                        "sequence": int(row["sequence"]),
                        "physical_label": str(row["physical_label"]),
                        "tape_id": row.get("tape_id"),
                        "objects": int(row["copied_files"]),
                        "bytes": int(row["copied_bytes"]),
                    }
                    for row in completed
                ),
            }
        )

    async def create_job_plan(
        self,
        request: CreateJobPlanRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobPlanV1:
        try:
            self.authorize_command(principal, capability="job.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            self._management.application.ensure_initialized(
                buffer_mib=max(1, self.settings.buffer_bytes // (1024 * 1024))
            )
            if request.kind == "create":
                assert request.library_ids is not None
                assert request.media_profile is not None
                plan = await self._management.create_initial_plan(
                    request.library_ids,
                    media_key=request.media_profile,
                    creator=principal.name,
                    idempotency_key=idempotency_key,
                )
            else:
                assert request.base_job_id is not None
                plan = await self._management.create_extension_plan(
                    request.base_job_id,
                    creator=principal.name,
                    idempotency_key=idempotency_key,
                )
        except Exception as exc:
            code = getattr(exc, "code", "internal_error")
            if not isinstance(code, str) or not re.fullmatch(
                r"[a-z][a-z0-9_]{0,63}", code
            ):
                code = "internal_error"
            self._record_audit(
                principal.name,
                "job-plan.create",
                "rejected",
                {"error_code": code, "kind": request.kind},
            )
            raise
        return self._job_plan_response(plan)

    def media_profiles(self, principal: Principal) -> MediaProfilesV1:
        self.authorize_command(principal, capability="read")
        authority = self._management.initialize_application_settings()
        return MediaProfilesV1.model_validate(
            {
                "default_media_profile": authority["default_media_profile"],
                "items": tuple(
                    {
                        "key": profile.key,
                        "generation": profile.generation,
                        "native_capacity_bytes": profile.native_capacity_bytes,
                        "ltfs_usable_bytes": profile.ltfs_usable_bytes,
                    }
                    for profile in lto_media_profiles()
                    if profile.ltfs_usable_bytes is not None
                ),
            }
        )

    async def get_job_plan(self, plan_id: str, principal: Principal) -> JobPlanV1:
        self.authorize_command(principal, capability="read")
        return self._job_plan_response(await self._management.get_plan(plan_id))

    async def job_manifest(
        self,
        job_id: str,
        principal: Principal,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JobManifestPageV1:
        self.authorize_command(principal, capability="read")
        return JobManifestPageV1.model_validate(
            await self._management.list_job_manifest(job_id, limit=limit, cursor=cursor)
        )

    async def job_history(
        self,
        job_id: str,
        principal: Principal,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> JobHistoryPageV1:
        self.authorize_command(principal, capability="read")
        return JobHistoryPageV1.model_validate(
            await self._management.list_job_history(job_id, limit=limit, cursor=cursor)
        )

    async def create_job_from_plan(
        self,
        plan_id: str,
        request: CreateJobFromPlanRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        action = "job.create"
        try:
            self.authorize_command(principal, capability="job.create")
            if request.authorize_automatic_formatting and not principal.allows(
                "media.format"
            ):
                raise FormatRequiresAdmin("formatting requires an admin role")
            if request.allow_registered_reuse or request.authorize_automatic_formatting:
                self.authorize_command(principal, capability="media.format")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            result = await self._management.create_job_from_plan(
                plan_id,
                request.digest_sha256,
                request.labels,
                idempotency_key=idempotency_key,
                display_name=request.display_name,
                actor=principal.name,
                allow_registered_reuse=request.allow_registered_reuse,
                authorize_automatic_formatting=request.authorize_automatic_formatting,
            )
        except Exception:
            self._record_audit(principal.name, action, "rejected", {"plan_id": plan_id})
            raise
        return JobDetailV1.model_validate(
            await self._management.get_job(str(result["id"]))
        )

    async def authorize_automatic_sequence(
        self,
        job_id: str,
        request: AuthorizeAutomaticSequenceRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        action = "job.automatic_sequence.authorize"
        try:
            self.authorize_command(principal, capability="media.format")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            result = await self._management.authorize_automatic_sequence(
                job_id,
                expected_revision=request.expected_revision,
                layout_fingerprint_sha256=request.layout_fingerprint_sha256,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._record_audit(
                principal.name,
                action,
                "rejected",
                {"job_id": job_id, "expected_revision": request.expected_revision},
            )
            raise
        return JobDetailV1.model_validate(result)

    async def rename_job(
        self,
        job_id: str,
        request: UpdateJobRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        return JobDetailV1.model_validate(
            await self._job_management_command(
                job_id,
                "job.rename",
                principal,
                "job.manage",
                lambda: self._management.rename_job(
                    job_id,
                    request.display_name,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                ),
            )
        )

    async def pause_job(
        self,
        job_id: str,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        return JobDetailV1.model_validate(
            await self._job_management_command(
                job_id,
                "job.pause",
                principal,
                "job.manage",
                lambda: self._management.request_job_pause(
                    job_id,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                ),
            )
        )

    async def reset_failed_cassette(
        self,
        job_id: str,
        request: ResetFailedCassetteRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        if not principal.allows("media.format"):
            raise FormatRequiresAdmin("cassette reset requires an admin role")
        result = JobDetailV1.model_validate(
            await self._job_management_command(
                job_id,
                "job.failed_cassette.reset",
                principal,
                "job.manage",
                lambda: self._management.reset_failed_cassette(
                    job_id,
                    request.cassette_sequence,
                    request.typed_physical_label,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                ),
            )
        )
        retry_idempotency_key = "failed-cassette-reset-" + hashlib.sha256(
            idempotency_key.encode("utf-8")
        ).hexdigest()[:32]
        self.start_archive(
            job_id,
            retry_idempotency_key,
            principal,
        )
        return result

    async def reserve_job_labels(
        self,
        job_id: str,
        request: ReserveJobLabelsRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        if not principal.allows("media.format"):
            raise FormatRequiresAdmin("formatting requires an admin role")
        result = await self._job_management_command(
                job_id,
                "job.reserve_labels",
                principal,
                "job.manage",
                lambda: self._management.reserve_job_labels(
                    job_id,
                    request.labels,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                    authorize_automatic_formatting=request.authorize_automatic_formatting,
                ),
            )
        with Catalog(self.paths.catalog_file) as catalog:
            pending = catalog.pending_incremental_extension(job_id)
        if pending is not None:
            await self.incremental_coordinator().run_job(
                job_id,"labels_added",actor=principal.name,
                idempotency_key="labels-added-" + hashlib.sha256(idempotency_key.encode()).hexdigest()[:32],
                authorize_automatic_formatting=request.authorize_automatic_formatting,
            )
            result = await self._management.get_job(job_id)
        return JobDetailV1.model_validate(result)

    async def extend_job(
        self,
        job_id: str,
        request: ExtendJobRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        if request.authorize_automatic_formatting and not principal.allows(
            "media.format"
        ):
            raise FormatRequiresAdmin("formatting requires an admin role")
        return JobDetailV1.model_validate(
            await self._job_management_command(
                job_id,
                "job.extend",
                principal,
                "job.manage",
                lambda: self._management.extend_job(
                    job_id,
                    request.plan_id,
                    request.digest_sha256,
                    request.labels,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                    authorize_automatic_formatting=request.authorize_automatic_formatting,
                ),
            )
        )

    async def retire_job(
        self,
        job_id: str,
        request: RetireJobRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> JobDetailV1:
        return JobDetailV1.model_validate(
            await self._job_management_command(
                job_id,
                "job.retire",
                principal,
                "job.retire",
                lambda: self._management.retire_job(
                    job_id,
                    typed_job_id=request.typed_job_id,
                    expected_revision=request.expected_revision,
                    actor=principal.name,
                    idempotency_key=idempotency_key,
                ),
            )
        )

    async def _job_management_command(
        self,
        job_id: str,
        action: str,
        principal: Principal,
        capability: str,
        command: Callable[[], Any],
    ) -> dict[str, Any]:
        try:
            self.authorize_command(principal, capability=capability)
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            return await command()
        except Exception:
            self._record_audit(principal.name, action, "rejected", {"job_id": job_id})
            raise

    async def create_library(
        self,
        request: CreateLibraryRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> LibrarySummaryV1:
        action = "library.create"
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            result, replayed = await self._management.create_library_with_replay(
                request.id,
                request.display_name,
                request.source_root,
                source=(
                    None
                    if request.source is None
                    else request.source.model_dump(mode="json")
                ),
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._record_audit(
                principal.name, action, "rejected", {"library_id": request.id}
            )
            raise
        if not replayed:
            self._publish_library_change(result)
        return self._library_response(result)

    async def update_library(
        self,
        library_id: str,
        request: UpdateLibraryRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> LibrarySummaryV1:
        action = "library.update"
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            result, replayed = await self._management.update_library_with_replay(
                library_id,
                display_name=request.display_name,
                source_root=request.source_root,
                source=(
                    None
                    if request.source is None
                    else request.source.model_dump(mode="json")
                ),
                state=request.state,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._record_audit(
                principal.name, action, "rejected", {"library_id": library_id}
            )
            raise
        if not replayed:
            self._publish_library_change(result)
        return self._library_response(result)

    async def retire_library(
        self,
        library_id: str,
        request: RetireLibraryRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> LibrarySummaryV1:
        action = "library.retire"
        try:
            self.authorize_command(principal, capability="library.manage")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            result, replayed = await self._management.retire_library_with_replay(
                library_id,
                typed_library_id=request.typed_library_id,
                expected_revision=request.expected_revision,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._record_audit(
                principal.name, action, "rejected", {"library_id": library_id}
            )
            raise
        if not replayed:
            self._publish_library_change(result)
        return self._library_response(result)

    def start_library_scan(
        self,
        library_id: str,
        idempotency_key: str,
        principal: Principal,
    ) -> LibrarySummaryV1:
        action = "library.scan"
        try:
            self.authorize_command(principal, capability="library.scan")
            with self._lifecycle_lock:
                self._require_mutating_lifecycle()
            result = self._management.start_library_scan(
                library_id,
                actor=principal.name,
                idempotency_key=idempotency_key,
            )
        except Exception:
            self._record_audit(
                principal.name, action, "rejected", {"library_id": library_id}
            )
            raise
        return self._library_response(result)

    def logs(self, after_id: int | None, limit: int) -> LogsPageV1:
        with self._logs_lock:
            eligible = tuple(
                item for item in self._logs if after_id is None or item.id > after_id
            )
        items = eligible[:limit]
        return LogsPageV1(
            items=items,
            next_after_id=items[-1].id if items else after_id,
        )

    def system_logs(self, query: SystemLogQuery) -> SystemLogsPageV1:
        """Return one bounded, redacted page from the constrained journal reader."""

        if type(query) is not SystemLogQuery:
            raise ValueError("a closed system log query is required")
        unavailable = _requested_log_sources(query.source)
        if self._journal_reader is None:
            return _system_logs_page(query, unavailable_sources=unavailable)

        inspected = 0
        seen_entry_cursors: set[str] = set()
        seen_page_cursors: set[str] = {query.cursor} if query.cursor is not None else set()
        selected: list[SystemLogEntryV1] = []
        unavailable_sources: set[LogSource] = set()
        reader_cursor = query.cursor
        older_cursor: str | None = None
        newer_cursor: str | None = None

        for page_number in range(5):
            request = JournalQuery(
                source=query.source,
                minimum_severity=query.severity,
                range=query.range,
                direction=query.direction,
                cursor=reader_cursor,
                limit=200 if query.search is not None else query.limit,
            )
            try:
                page = self._journal_reader.query(request)
                if type(page) is not JournalPage:
                    raise JournalReaderUnavailable
            except JournalReaderUnavailable:
                return _system_logs_page(query, unavailable_sources=unavailable)

            if page.cursor_rotated:
                return _system_logs_page(query, cursor_rotated=True)

            try:
                page_unavailable = _validated_page_unavailable_sources(page, query)
            except ValueError:
                return _system_logs_page(query, unavailable_sources=unavailable)
            unavailable_sources.update(page_unavailable)
            if unavailable_sources:
                selected = [
                    item
                    for item in selected
                    if item.source not in unavailable_sources
                ]

            if page_number == 0:
                older_cursor = page.older_cursor
                newer_cursor = page.newer_cursor
            elif query.direction is LogDirection.OLDER:
                older_cursor = page.older_cursor
            else:
                newer_cursor = page.newer_cursor

            try:
                for candidate in page.entries:
                    if inspected >= 1_000:
                        break
                    inspected += 1
                    _validate_system_log_candidate(candidate, query)
                    if candidate.source in unavailable_sources:
                        continue
                    if candidate.cursor in seen_entry_cursors:
                        continue
                    seen_entry_cursors.add(candidate.cursor)
                    item = _system_log_entry(candidate)
                    if (
                        len(selected) < query.limit
                        and _system_log_matches(item, query.search)
                    ):
                        selected.append(item)
            except (TypeError, ValueError):
                return _system_logs_page(query, unavailable_sources=unavailable)

            if query.source is not LogSource.ALL and unavailable_sources:
                return _system_logs_page(
                    query,
                    unavailable_sources=(query.source,),
                )
            if unavailable_sources == set(_CONCRETE_LOG_SOURCES):
                return _system_logs_page(
                    query,
                    unavailable_sources=tuple(
                        sorted(unavailable_sources, key=lambda source: source.value)
                    ),
                )
            if len(selected) == query.limit:
                selected_older, selected_newer = _selected_log_cursors(
                    tuple(selected), query.direction
                )
                return _system_logs_page(
                    query,
                    items=tuple(selected),
                    older_cursor=selected_older,
                    newer_cursor=selected_newer,
                    unavailable_sources=tuple(
                        sorted(
                            unavailable_sources,
                            key=lambda source: source.value,
                        )
                    ),
                )

            if inspected >= 1_000:
                break
            reader_cursor = (
                page.older_cursor
                if query.direction is LogDirection.OLDER
                else page.newer_cursor
            )
            if reader_cursor is None or reader_cursor in seen_page_cursors:
                break
            seen_page_cursors.add(reader_cursor)

        if selected:
            older_cursor, newer_cursor = _selected_log_cursors(
                tuple(selected), query.direction
            )
        return _system_logs_page(
            query,
            items=tuple(selected),
            older_cursor=older_cursor,
            newer_cursor=newer_cursor,
            unavailable_sources=tuple(
                sorted(unavailable_sources, key=lambda source: source.value)
            ),
        )

    def record_log(
        self,
        level: str,
        code: str,
        *,
        message: str | None = None,
        fields: Mapping[str, object] | None = None,
        request_id: str | None = None,
        operation_id: str | None = None,
    ) -> LogEntryV1:
        del message, fields
        safe_level = (
            level if level in {"debug", "info", "warning", "error"} else "error"
        )
        safe_code = code if _SAFE_PRINCIPAL.fullmatch(code) else "daemon.event"
        safe_message = _SAFE_LOG_MESSAGES.get(safe_code, "Daemon event recorded.")
        with self._logs_lock:
            entry = LogEntryV1(
                id=self._next_log_id,
                occurred_at=utc_now(),
                level=safe_level,
                code=safe_code,
                message=safe_message,
                request_id=request_id
                if _safe_optional_identifier(request_id)
                else None,
                operation_id=(
                    operation_id if _safe_optional_identifier(operation_id) else None
                ),
            )
            self._next_log_id += 1
            self._logs.append(entry)
        if not getattr(self._operational_event_guard, "active", False):
            self._operational_event_guard.active = True
            try:
                self._operational_event_sink.emit(
                    OperationalEvent(
                        source=OperationalSource.DAEMON,
                        severity=OperationalSeverity(safe_level),
                        code=safe_code,
                        message=safe_message,
                        operation_id=entry.operation_id,
                    )
                )
            except BaseException:  # noqa: BLE001, S110 - journal diagnostics are best-effort
                pass
            finally:
                self._operational_event_guard.active = False
        return entry

    def operation(self, operation_id: str) -> OperationRecord | None:
        return self._require_operations().operation(operation_id)

    def replay(self, idempotency_key: str) -> OperationRecord | None:
        return self._require_operations().replay(idempotency_key)

    def load_frozen_job_plan(self, job_id: str) -> FrozenJobPlan:
        """Load the imported allocation through a strictly read-only catalog."""

        from ..migration.validator import ReadOnlyCatalog

        with ReadOnlyCatalog(self.paths.catalog_file) as catalog:
            return FrozenJobPlan.load(catalog, job_id)

    def events(self, after_id: int | None) -> Iterator[EventEnvelopeV1]:
        server_events = self._events.replay(
            after_id,
            lambda: self.status().model_dump(mode="json"),
        )
        for event in server_events:
            yield EventEnvelopeV1(
                id=event.id,
                event=event.event_type,
                data=event.payload,
            )

    def resolve_recovery(
        self,
        operation_id: str,
        resolution: SafeRecoveryResolution,
    ) -> OperationRecord:
        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
            operations = self._require_operations()
            resolved = operations.resolve_recovery(operation_id, resolution)
            remaining = operations.reconcile_admission_blockers()
            self._set_admission_blockers_locked(remaining)
            wake_sequence = self._accepting_mutations
        if wake_sequence:
            self._activate_sequence_coordinator()
        return resolved

    def start_operation(
        self,
        request: OperationRequest,
        idempotency_key: str,
        principal: Principal,
        *,
        cutover_credential: str | None = None,
        format_confirmation_label: str | None = None,
        enable_native_sequence: bool = False,
    ) -> OperationRecord:
        with self._lifecycle_lock:
            self.authorize_command(
                principal,
                capability=(
                    "job.resume"
                    if request.kind in {"archive.resume", "archive.native"}
                    else "read"
                ),
            )
            self._require_mutating_lifecycle(allow_starting=True)
            if self._operations is None:
                raise MutationAdmissionClosed("catalog mutation admission is closed")
            operations = self._operations
            if self._lifecycle_state == "starting":
                replay = operations.replay(idempotency_key)
                if replay is None:
                    raise MutationAdmissionClosed(
                        "catalog mutation admission is closed"
                    )
            elif self._admission_blocker_id is not None:
                replay = operations.replay(idempotency_key)
                if replay is None:
                    blocker = operations.operation(self._admission_blocker_id)
                    if blocker is not None and blocker.state == "recovery_required":
                        raise RecoveryAdmissionBlocked(blocker)
            replay = operations.replay(idempotency_key)
            if request.kind == "archive.resume" and replay is not None:
                if (
                    replay.kind != request.kind
                    or replay.job_id != request.job_id
                    or replay.principal != principal.name
                ):
                    raise OperationReplayConflict()
                with Catalog(self.paths.catalog_file) as catalog:
                    persisted_cutover = catalog.connection.execute(
                        "SELECT 1 FROM cutover_authorizations "
                        "WHERE consumed_by_operation_id=?",
                        (replay.id,),
                    ).fetchone()
                    persisted_confirmation = catalog.connection.execute(
                        "SELECT 1 FROM format_confirmations WHERE operation_id=?",
                        (replay.id,),
                    ).fetchone()
                if persisted_cutover is not None and not principal.direct_local_admin:
                    raise UntrustedPeer(
                        "direct local administrator credentials are required"
                    )
                if persisted_confirmation is not None:
                    self.authorize_command(
                        principal,
                        capability="job.resume",
                        formatting_required=True,
                    )
                self.record_log("info", "operation.accepted", operation_id=replay.id)
                return replay
            callback = self._callbacks.get(request.kind)
            if callback is None:
                raise MutationAdmissionClosed("operation kind is not configured")
            job_id: str | None = None
            cassette_sequence: int | None = None
            hardware_target = None
            caller_peer_kind: str | None = None
            current_host_id: str | None = None
            sequence_authorization_id: str | None = None
            if request.kind in {"archive.resume", "archive.native"}:
                if request.job_id is None:
                    raise MutationAdmissionClosed("archive resume is not configured")
                requires_cutover_authorization = False
                if request.kind == "archive.resume":
                    if self._archive_resume_admission is None:
                        raise MutationAdmissionClosed(
                            "archive resume is not configured"
                        )
                    plan = self.load_frozen_job_plan(request.job_id)
                    cassette = plan.next_cassette()
                    expected_sequence = cassette.sequence
                    expected_operation = cassette.operation
                    expected_label = cassette.physical_label
                    requires_cutover_authorization = (
                        plan.authority_state == "pre_cutover" and cassette.sequence == 4
                    )
                    if (
                        requires_cutover_authorization
                        and not principal.direct_local_admin
                    ):
                        raise UntrustedPeer(
                            "direct local administrator credentials are required"
                        )
                    admission_factory = self._archive_resume_admission
                else:
                    if self._native_archive_admission is None:
                        raise MutationAdmissionClosed(
                            "native archive is not configured"
                        )
                    with Catalog(self.paths.catalog_file) as catalog:
                        if catalog.get_import_policy(request.job_id) is not None:
                            raise MutationAdmissionClosed(
                                "native archive job is invalid"
                            )
                        job = catalog.get_automatic_job(request.job_id)
                        cassette = catalog.next_automatic_cassette(request.job_id)
                        authority = (
                            None
                            if cassette is None or cassette["operation"] != "format"
                            else catalog.format_sequence_authorization(
                                request.job_id, int(cassette["sequence"])
                            )
                        )
                    if job["status"] == "completed" or cassette is None:
                        raise MutationAdmissionClosed(
                            "native archive job is not resumable"
                        )
                    expected_sequence = int(cassette["sequence"])
                    expected_operation = str(cassette["operation"])
                    expected_label = str(cassette["physical_label"])
                    if expected_operation == "format":
                        sequence_authorization_id = (
                            None
                            if authority is None
                            else str(authority["authorization_id"])
                        )
                    admission_factory = self._native_archive_admission
                admission = admission_factory(request.job_id)
                if admission.job_id != request.job_id:
                    raise RuntimeError("archive admission returned a mismatched job")
                if expected_sequence != admission.cassette_sequence:
                    raise RuntimeError(
                        "archive admission returned a mismatched cassette"
                    )
                job_id = admission.job_id
                cassette_sequence = admission.cassette_sequence
                hardware_target = admission.hardware_target
                if requires_cutover_authorization:
                    if self._cutover_environment is None:
                        raise MutationAdmissionClosed(
                            "cutover authorization is not configured"
                        )
                    current_host_id, current_drive_serial_sha256 = (
                        self._cutover_environment(request.job_id)
                    )
                    if (
                        current_drive_serial_sha256
                        != hardware_target.tape_device_identity_sha256
                    ):
                        raise CutoverAuthorizationInvalid()
                    caller_peer_kind = "local_admin"
                if expected_operation == "format":
                    if sequence_authorization_id is None:
                        self.authorize_command(
                            principal,
                            capability="job.resume",
                            formatting_required=True,
                        )
                        if format_confirmation_label is None:
                            raise FormatConfirmationRequired()
                        if format_confirmation_label != expected_label:
                            raise FormatConfirmationMismatch()
            try:
                telemetry_before = self._diagnostics.committed_checkpoint()

                def remember_admission(admitted: OperationRecord) -> None:
                    self._current_progress_baseline = (
                        admitted.id,
                        telemetry_before[0],
                        telemetry_before[1],
                        telemetry_before[2],
                    )
                    self._current_operation_id = admitted.id

                record = operations.start(
                    request.kind,
                    idempotency_key,
                    principal.name,
                    callback,
                    job_id=job_id,
                    cassette_sequence=cassette_sequence,
                    hardware_target=hardware_target,
                    cutover_credential=cutover_credential,
                    format_confirmation_label=format_confirmation_label,
                    sequence_authorization_id=sequence_authorization_id,
                    enable_native_sequence=enable_native_sequence,
                    caller_peer_kind=caller_peer_kind,
                    current_host_id=current_host_id,
                    on_admitted=remember_admission,
                    on_complete=(
                        self._wake_sequence_coordinator
                        if request.kind == "archive.native"
                        else None
                    ),
                )
            except Exception:
                self.record_log("warning", "operation.rejected")
                raise
            self.record_log("info", "operation.accepted", operation_id=record.id)
            return record

    def start_archive(
        self,
        job_id: str,
        idempotency_key: str,
        principal: Principal,
        *,
        cutover_credential: str | None = None,
        format_confirmation_label: str | None = None,
        start_only: bool = False,
    ) -> OperationRecord | BoundaryRefreshAcceptedV1:
        with Catalog(self.paths.catalog_file) as catalog:
            imported = catalog.get_import_policy(job_id) is not None
            job = catalog.get_automatic_job(job_id)
            state = catalog.job_management_state(job_id)
        if state["retired_at"] is not None:
            raise JobStateConflict("retired jobs cannot be started")
        if start_only and (imported or job["status"] != "planned"):
            raise JobStateConflict("only saved native jobs can be started")
        if not start_only and not imported and job["status"] == "planned":
            raise JobStateConflict("saved native jobs must use start")
        try:
            if (
                not start_only and not imported
                and cutover_credential is None
            ):
                from .boundary_store import BoundaryStore

                accepted = None
                with self._lifecycle_lock:
                    self.authorize_command(principal, capability="job.resume")
                    self._require_mutating_lifecycle(allow_starting=True)
                    operations = self._require_operations()
                    # Existing operation retries must retain the original
                    # operation identity and its normal replay validation.
                    if operations.replay(idempotency_key) is None:
                        self._require_mutating_lifecycle()
                        if (
                            self._native_archive_admission is None
                            or "archive.native" not in self._callbacks
                        ):
                            raise MutationAdmissionClosed("native archive is not configured")
                        accepted = BoundaryStore(
                            lambda: Catalog(self.paths.catalog_file),
                            operations.daemon_fence.generation,
                        ).request_resume(
                            job_id, actor=principal.name, idempotency_key=idempotency_key,
                            confirmation_label=format_confirmation_label,
                        )
                if accepted is not None:
                    self._wake_sequence_coordinator()
                    return BoundaryRefreshAcceptedV1.model_validate(accepted)
            return self.start_operation(
                OperationRequest(
                    kind="archive.resume" if imported else "archive.native",
                    job_id=job_id,
                ),
                idempotency_key,
                principal,
                cutover_credential=cutover_credential,
                format_confirmation_label=format_confirmation_label,
                enable_native_sequence=not imported,
            )
        except CatalogError as exc:
            if str(exc) == "boundary_confirmation_mismatch":
                raise FormatConfirmationMismatch() from exc
            if str(exc) == "idempotency_conflict":
                raise OperationReplayConflict() from exc
            if str(exc).startswith("boundary_"):
                raise JobStateConflict(
                    "Source refresh cannot proceed in the current job state."
                ) from exc
            if str(exc) in {
                "automatic_sequence_pause_pending", "automatic_sequence_state_conflict",
                "automatic_sequence_layout_conflict",
            }:
                raise JobStateConflict(
                    "Resume cannot proceed until a safe pause checkpoint is verified."
                ) from exc
            raise

    def verify_cassette_source_library(
        self, candidate: SequenceCandidate, library: dict
    ) -> tuple[str, str]:
        return self._management.verify_cassette_source_library(candidate, library)

    def boundary_dispatcher(self, daemon_generation: int):
        """Build the owner-fenced boundary stage for the native coordinator."""
        return self._management.boundary_dispatcher(daemon_generation)

    def _admit_sequence_candidate(
        self, candidate: SequenceCandidate
    ) -> OperationRecord:
        """Admit one already-selected durable candidate through OperationManager."""

        with self._lifecycle_lock:
            self._require_mutating_lifecycle()
            operations = self._require_operations()
            with Catalog(self.paths.catalog_file) as catalog:
                current = catalog.next_automatic_sequence_candidate()
            if (
                current is None
                or str(current["job_id"]) != candidate.job_id
                or int(current["cassette_sequence"]) != candidate.cassette_sequence
                or str(current["layout_fingerprint_sha256"])
                != candidate.layout_fingerprint_sha256
                or (
                    None if current["authorization_id"] is None else str(current["authorization_id"])
                ) != candidate.authorization_id
            ):
                raise MutationAdmissionClosed("sequence candidate is no longer current")
            callback = self._callbacks.get("archive.native")
            if callback is None or self._native_archive_admission is None:
                raise MutationAdmissionClosed("native archive is not configured")
            admission = self._native_archive_admission(candidate.job_id)
            if (
                admission.job_id != candidate.job_id
                or admission.cassette_sequence != candidate.cassette_sequence
            ):
                raise MutationAdmissionClosed("sequence admission is no longer exact")
            telemetry_before = self._diagnostics.committed_checkpoint()

            def remember_admission(admitted: OperationRecord) -> None:
                self._current_progress_baseline = (
                    admitted.id,
                    telemetry_before[0],
                    telemetry_before[1],
                    telemetry_before[2],
                )
                self._current_operation_id = admitted.id

            record = operations.start(
                "archive.native",
                candidate.idempotency_key,
                "sequence-coordinator",
                callback,
                job_id=candidate.job_id,
                cassette_sequence=candidate.cassette_sequence,
                hardware_target=admission.hardware_target,
                sequence_authorization_id=candidate.authorization_id,
                sequence_layout_fingerprint_sha256=candidate.layout_fingerprint_sha256,
                on_admitted=remember_admission,
                on_complete=self._wake_sequence_coordinator,
            )
            self.record_log("info", "operation.accepted", operation_id=record.id)
            return record

    def start_native_job(
        self,
        request: CreateNativeJobRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> OperationRecord:
        """Create a fresh native namespace without dispatching tape hardware."""

        with self._lifecycle_lock:
            self.authorize_command(principal, capability="library.manage")
            self._require_mutating_lifecycle()
            operations = self._require_operations()
            if self._admission_blocker_id is not None:
                blocker = operations.operation(self._admission_blocker_id)
                if blocker is not None and blocker.state == "recovery_required":
                    raise RecoveryAdmissionBlocked(blocker)
            job_id = (
                "NATIVE-"
                + datetime.now(UTC).strftime("%Y%m%d-%H%M%S-")
                + uuid.uuid4().hex[:8]
            )

            def reset_and_create(context) -> None:
                authority = self._management.application_settings()
                legacy_settings = self._management._legacy_settings_from_authority(
                    authority
                )
                protected_snapshot = self.backups.create_for_operation(
                    context.fence,
                    f"before-native-reset-{request.expected_job_id}",
                    protected=True,
                )
                scratch_parent = self.paths.state_dir / "temp"
                scratch_parent.mkdir(parents=True, exist_ok=True)
                with tempfile.TemporaryDirectory(
                    prefix="native-plan-", dir=scratch_parent
                ) as temporary:
                    scratch_paths = AppPaths(Path(temporary))
                    scratch_paths.create()
                    shutil.copy2(protected_snapshot, scratch_paths.catalog_file)
                    save_settings(scratch_paths, legacy_settings)
                    with Catalog(scratch_paths.catalog_file) as scratch_catalog:
                        scratch_catalog.reset_and_create_native_job(
                            context.fence,
                            expected_job_id=request.expected_job_id,
                            job_id=job_id,
                            display_name=request.display_name,
                            source_roots=self.settings.source_roots,
                            device_name=str(self.settings.tape_device_path),
                            mount_path=str(self.settings.mount_path),
                            labels=request.labels,
                            application_settings=authority,
                        )
                    LtoApplication(scratch_paths.state_dir).prepare_automatic_job_run(
                        job_id
                    )
                    with Catalog(scratch_paths.catalog_file) as scratch_catalog:
                        planned_cassettes = tuple(
                            (
                                int(cassette["sequence"]),
                                int(cassette["planned_files"]),
                                int(cassette["planned_bytes"]),
                                tuple(
                                    (
                                        str(item["library_id"]),
                                        str(item["relative_path"]),
                                        int(item["size"]),
                                        int(item["mtime_ns"]),
                                    )
                                    for item in scratch_catalog.list_automatic_cassette_manifest(
                                        job_id, int(cassette["sequence"])
                                    )
                                ),
                            )
                            for cassette in scratch_catalog.list_automatic_cassettes(
                                job_id
                            )
                        )
                with Catalog(self.paths.catalog_file) as catalog:
                    catalog.reset_and_create_native_job(
                        context.fence,
                        expected_job_id=request.expected_job_id,
                        job_id=job_id,
                        display_name=request.display_name,
                        source_roots=self.settings.source_roots,
                        device_name=str(self.settings.tape_device_path),
                        mount_path=str(self.settings.mount_path),
                        labels=request.labels,
                        application_settings=authority,
                        planned_cassettes=planned_cassettes,
                    )

            try:
                telemetry_before = self._diagnostics.committed_checkpoint()

                def remember_admission(admitted: OperationRecord) -> None:
                    self._current_progress_baseline = (
                        admitted.id,
                        telemetry_before[0],
                        telemetry_before[1],
                        telemetry_before[2],
                    )
                    self._current_operation_id = admitted.id

                admission = operations.start_with_admission(
                    "catalog.reset_create",
                    idempotency_key,
                    principal.name,
                    reset_and_create,
                    job_id=job_id,
                    on_admitted=remember_admission,
                )
            except Exception:
                self.record_log("warning", "operation.rejected")
                raise
            record = admission.record
            if admission.replayed:
                return record
            self._record_audit(
                principal.name,
                "job.native_reset_create",
                "accepted",
                {"job_id": record.job_id, "operation_id": record.id},
            )
            self.record_log("info", "operation.accepted", operation_id=record.id)
            return record

    def start_cutover_authorization(
        self,
        request: CutoverAuthorizationRequestV1,
        idempotency_key: str,
        principal: Principal,
    ) -> OperationRecord:
        with self._lifecycle_lock:
            if not principal.direct_local_admin:
                raise UntrustedPeer(
                    "direct local administrator credentials are required"
                )
            self._require_mutating_lifecycle()
            operations = self._require_operations()
            replay = operations.replay(idempotency_key)
            if replay is not None:
                if (
                    replay.kind != "cutover.authorize"
                    or replay.job_id != request.acceptance_report.job_id
                    or replay.principal != principal.name
                ):
                    raise CutoverAuthorizationInvalid()
                self._record_audit(
                    principal.name,
                    "cutover.authorization.register",
                    "replayed",
                    {
                        "job_id": replay.job_id,
                        "operation_id": replay.id,
                    },
                )
                self.record_log("info", "operation.accepted", operation_id=replay.id)
                return replay
            if self._admission_blocker_id is not None:
                blocker = operations.operation(self._admission_blocker_id)
                if blocker is not None and blocker.state == "recovery_required":
                    raise RecoveryAdmissionBlocked(blocker)
            if self._cutover_environment is None:
                raise MutationAdmissionClosed("cutover authorization is not configured")
            report = request.acceptance_report
            host_id, drive_serial_sha256 = self._cutover_environment(report.job_id)
            if (
                host_id != report.host_id
                or drive_serial_sha256 != report.drive_serial_sha256
            ):
                raise CutoverAuthorizationInvalid()
            candidate = new_operation(
                "cutover.authorize",
                idempotency_key,
                principal.name,
                report.job_id,
                4,
            )
            with Catalog(self.paths.catalog_file) as catalog:
                admission = catalog.register_cutover_authorization(
                    candidate,
                    operations.daemon_fence,
                    admission_open=True,
                    credential_sha256=request.credential_sha256,
                    bundle_sha256=report.bundle_sha256,
                    catalog_binding_sha256=report.catalog_binding_sha256,
                    assignment_sha256=report.assignment_sha256,
                    expected_label=report.expected_label,
                    host_id=report.host_id,
                    drive_serial_sha256=report.drive_serial_sha256,
                    expires_at=report.expires_at,
                )
            self._record_audit(
                principal.name,
                "cutover.authorization.register",
                "replayed" if admission.replayed else "accepted",
                {
                    "job_id": admission.record.job_id,
                    "operation_id": admission.record.id,
                },
            )
            self.record_log(
                "info", "operation.accepted", operation_id=admission.record.id
            )
            return admission.record

    def prepare_cutover_report(
        self,
        job_id: str,
        principal: Principal,
    ) -> SignedAcceptanceReportV1:
        """Derive short-lived, non-secret cassette-four acceptance evidence."""

        with self._lifecycle_lock:
            if not principal.direct_local_admin:
                raise UntrustedPeer(
                    "direct local administrator credentials are required"
                )
            self._require_mutating_lifecycle()
            if self._cutover_environment is None:
                raise MutationAdmissionClosed("cutover authorization is not configured")
            try:
                plan = self.load_frozen_job_plan(job_id)
                cassette = plan.next_cassette()
            except Exception as exc:
                raise CutoverAuthorizationInvalid() from exc
            if (
                plan.authority_state != "pre_cutover"
                or cassette.sequence != 4
                or cassette.operation != "format"
            ):
                raise CutoverAuthorizationInvalid()
            host_id, drive_serial_sha256 = self._cutover_environment(job_id)
            return SignedAcceptanceReportV1(
                job_id=plan.job_id,
                next_sequence=4,
                bundle_sha256=plan.bundle_sha256,
                catalog_binding_sha256=cutover_catalog_binding_sha256(
                    plan.job_id,
                    plan.bundle_sha256,
                    plan.assignment_sha256,
                    plan.cassette_plan_sha256,
                    plan.completed_evidence_sha256,
                    cassette.physical_label,
                ),
                assignment_sha256=plan.assignment_sha256,
                expected_label=cassette.physical_label,
                host_id=host_id,
                drive_serial_sha256=drive_serial_sha256,
                expires_at=(datetime.now(UTC) + timedelta(minutes=15)).isoformat(),
            )

    def shutdown(self, timeout_seconds: float | None = None) -> None:
        selected_timeout = (
            self._shutdown_timeout_seconds
            if timeout_seconds is None
            else timeout_seconds
        )
        selected_timeout = validate_shutdown_timeout(selected_timeout)
        self._shutdown_requested.set()
        with self._lifecycle_lock:
            if self._lifecycle_state in {"shutting_down", "stopped"}:
                raise RuntimeError("daemon service shutdown may only run once")
            self._lifecycle_state = "shutting_down"
            self._accepting_mutations = False
            operations = self._operations
            recovery_coordinator = self._recovery_coordinator
            sequence_coordinator = self._sequence_coordinator
            if operations is not None:
                operations.stop_accepting()
        if sequence_coordinator is not None:
            try:
                sequence_coordinator.shutdown()
            except Exception:
                # Keep every downstream dependency intact and admissions closed:
                # a live coordinator must never run against torn-down services.
                raise
        try:
            if recovery_coordinator is not None:
                recovery_coordinator.shutdown()
            if operations is not None:
                operations.shutdown(selected_timeout)
            self._management.wait_for_library_scans(selected_timeout)
        finally:
            self._events.close()
            with self._lifecycle_lock:
                self._accepting_mutations = False
                self._lifecycle_state = "stopped"
            self.record_log("info", "shutdown.complete")

    def _lookup_operation(self, operation_id: str | None) -> OperationRecord | None:
        if operation_id is None or self._operations is None:
            return None
        return self._operations.operation(operation_id)

    def _publish_telemetry_snapshot(self, _snapshot: TelemetrySnapshot) -> None:
        status = self.status()
        self._events.publish(
            "state.patch",
            {
                "progress": status.progress.model_dump(mode="json"),
                "telemetry": status.telemetry.model_dump(mode="json"),
            },
        )

    def _publish_library_change(self, summary: Mapping[str, object]) -> None:
        """Publish only path-free library state on the standard event stream."""

        self._events.publish(
            "library.changed",
            {
                "library": {
                    key: summary[key]
                    for key in (
                        "id",
                        "state",
                        "scan_state",
                        "last_successful_scan_at",
                        "file_count",
                        "byte_count",
                        "revision",
                    )
                }
            },
        )

    def _publish_share_change(self, payload: Mapping[str, object]) -> None:
        """Publish the already-redacted durable share projection."""

        self._events.publish("share.changed", dict(payload))

    def _require_operations(self) -> OperationManager:
        if self._operations is None:
            raise RuntimeError("operation admission is not initialized")
        return self._operations

    def _set_admission_blockers_locked(
        self, blockers: tuple[OperationRecord, ...]
    ) -> None:
        self._admission_blocker_id = blockers[0].id if blockers else None
        operations = self._require_operations()
        if blockers or self._shutdown_requested.is_set():
            operations.stop_accepting()
            self._accepting_mutations = False
            if blockers and self._lifecycle_state == "starting":
                self._lifecycle_state = "blocked"
        else:
            operations.start_accepting()
            self._accepting_mutations = True
            self._lifecycle_state = "running"

    def _handle_recovery_transition(self, transition: object) -> None:
        """Recompute durable admission after each autonomous watcher transition."""

        operations = self._require_operations()
        blockers = operations.reconcile_admission_blockers()
        with self._lifecycle_lock:
            if self._shutdown_requested.is_set() or self._lifecycle_state in {
                "shutting_down",
                "stopped",
            }:
                return
            self._remember_recovery_quarantines(transition)
            self._set_admission_blockers_locked(
                self._nonquarantined_blockers(blockers)
            )
            wake_sequence = self._accepting_mutations
        if wake_sequence:
            self._activate_sequence_coordinator()

    def _activate_sequence_coordinator(self) -> None:
        with self._lifecycle_lock:
            coordinator = self._sequence_coordinator
            if coordinator is None or self._shutdown_requested.is_set():
                return
            start = not self._sequence_coordinator_started
            self._sequence_coordinator_started = True
        try:
            if start:
                coordinator.start()
            coordinator.wake()
        except Exception:
            if start:
                with self._lifecycle_lock:
                    self._sequence_coordinator_started = False
            raise

    def _wake_sequence_coordinator(self, _record: OperationRecord | None = None) -> None:
        coordinator = self._sequence_coordinator
        if coordinator is not None and not self._shutdown_requested.is_set():
            coordinator.wake()

    def _remember_recovery_quarantines(self, transition: object) -> None:
        operation_ids = getattr(transition, "quarantined_operation_ids", ())
        if not isinstance(operation_ids, tuple) or any(
            type(operation_id) is not str or not operation_id
            for operation_id in operation_ids
        ):
            raise TypeError("recovery transition quarantine scope is invalid")
        self._quarantined_operation_ids.update(operation_ids)

    def _nonquarantined_blockers(
        self, blockers: tuple[OperationRecord, ...]
    ) -> tuple[OperationRecord, ...]:
        return tuple(
            blocker
            for blocker in blockers
            if blocker.id not in self._quarantined_operation_ids
        )

    def _require_mutating_lifecycle(self, *, allow_starting: bool = False) -> None:
        allowed = {"running", "blocked"}
        if allow_starting:
            allowed.add("starting")
        if self._shutdown_requested.is_set() or self._lifecycle_state not in allowed:
            raise MutationAdmissionClosed("catalog mutation admission is closed")

    def _record_audit(
        self,
        principal: str,
        action: str,
        result: str,
        payload: dict[str, object],
    ) -> None:
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.record_audit(
                principal,
                action,
                result,
                f"request-{uuid.uuid4().hex}",
                None,
                payload,
            )


def _operation_response(record: OperationRecord | None) -> OperationResponseV1 | None:
    if record is None:
        return None
    return OperationResponseV1.model_validate(asdict(record))


def _safe_optional_identifier(value: str | None) -> bool:
    return value is not None and _SAFE_PRINCIPAL.fullmatch(value) is not None


_CONCRETE_LOG_SOURCES = tuple(
    source for source in LogSource if source is not LogSource.ALL
)


def _requested_log_sources(source: LogSource) -> tuple[LogSource, ...]:
    return _CONCRETE_LOG_SOURCES if source is LogSource.ALL else (source,)


def _validated_page_unavailable_sources(
    page: JournalPage, query: SystemLogQuery
) -> tuple[LogSource, ...]:
    unavailable = page.unavailable_sources
    if query.source is not LogSource.ALL and any(
        source is not query.source for source in unavailable
    ):
        raise ValueError("journal page availability is inconsistent with the query")
    return unavailable


def _system_log_entry(entry: JournalEntry) -> SystemLogEntryV1:
    if type(entry) is not JournalEntry:
        raise TypeError("journal entry is outside the closed reader contract")
    message, truncated = redact_operational_message(entry.message)
    return SystemLogEntryV1(
        cursor=entry.cursor,
        occurred_at=entry.timestamp,
        severity=entry.severity,
        source=entry.source,
        unit=entry.unit,
        message=message,
        repeat_count=entry.repeat_count,
        truncated=entry.truncated or truncated,
        pid=entry.pid,
        boot_id=entry.boot_id,
        operation_id=entry.operation_id,
        job_id=entry.job_id,
        cassette_label=entry.cassette_label,
        cassette_sequence=entry.cassette_sequence,
        command_id=entry.command_id,
        daemon_generation=entry.daemon_generation,
        command_kind=entry.command_kind,
        phase=entry.phase,
        exit_code=entry.exit_code,
        elapsed_ms=entry.elapsed_ms,
    )


def _validate_system_log_candidate(
    entry: JournalEntry, query: SystemLogQuery
) -> None:
    if (
        type(entry) is not JournalEntry
        or entry.source is LogSource.ALL
        or entry.unit not in SYSTEM_LOG_SOURCE_UNITS[entry.source]
        or (query.source is not LogSource.ALL and entry.source is not query.source)
        or SYSTEM_LOG_SEVERITY_RANK[entry.severity]
        < SYSTEM_LOG_SEVERITY_RANK[query.severity]
    ):
        raise ValueError("journal entry is inconsistent with the requested log page")


def _system_log_matches(entry: SystemLogEntryV1, search: str | None) -> bool:
    if search is None:
        return True
    needle = search.casefold()
    fields = (
        entry.message,
        entry.operation_id,
        entry.job_id,
        entry.cassette_label,
        str(entry.cassette_sequence) if entry.cassette_sequence is not None else None,
        entry.command_id,
        str(entry.daemon_generation) if entry.daemon_generation is not None else None,
        entry.command_kind,
        entry.phase,
        str(entry.exit_code) if entry.exit_code is not None else None,
        str(entry.elapsed_ms) if entry.elapsed_ms is not None else None,
    )
    return any(value is not None and needle in value.casefold() for value in fields)


def _selected_log_cursors(
    items: tuple[SystemLogEntryV1, ...], direction: LogDirection
) -> tuple[str, str]:
    if direction is LogDirection.OLDER:
        return items[-1].cursor, items[0].cursor
    return items[0].cursor, items[-1].cursor


def _system_logs_page(
    query: SystemLogQuery,
    *,
    items: tuple[SystemLogEntryV1, ...] = (),
    older_cursor: str | None = None,
    newer_cursor: str | None = None,
    cursor_rotated: bool = False,
    unavailable_sources: tuple[LogSource, ...] = (),
) -> SystemLogsPageV1:
    return SystemLogsPageV1(
        source=query.source,
        severity=query.severity,
        range=query.range,
        direction=query.direction,
        search=query.search,
        limit=query.limit,
        items=items,
        older_cursor=older_cursor,
        newer_cursor=newer_cursor,
        cursor_rotated=cursor_rotated,
        live_supported=True,
        unavailable_sources=unavailable_sources,
    )
