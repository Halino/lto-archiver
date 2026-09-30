from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import nullcontext
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from ..application import LtoApplication
from ..catalog import Catalog
from ..errors import CatalogError, NoNewSourceFiles, ValidationError
from ..managed_sources import (
    ManagedSourceAdmissionError,
    ManagedSourceVerifier,
    normalize_managed_source_subpath,
)
from ..media import require_ltfs_profile
from ..settings import Settings, load_settings
from ..share_broker.client import CredentialStatus, ShareBrokerUnavailable
from ..share_broker.protocol import ShareMountReceiptV1, mount_receipt_sha256
from ..share_broker.systemd import mount_unit_name, source_identity_sha256
from ..shares import (
    SHARE_SAFE_ERROR_CODES,
    EndpointPolicy,
    NfsShareConfig,
    ShareConfig,
    ShareValidationError,
    SmbShareConfig,
    derive_mount_target,
    normalize_share_id,
)
from ..util import RunLock
from .boundary_status import boundary_refresh_status
from .native_frozen import NativeSourceCheckpoint
from .sequence_coordinator import SequenceCandidate


class JobPlanError(ValidationError):
    code = "job_plan_error"


class PlanStale(JobPlanError):
    code = "plan_stale"


class PlanConsumed(JobPlanError):
    code = "plan_consumed"


class PlanExpired(JobPlanError):
    code = "plan_expired"


class PlanNotFound(JobPlanError):
    code = "plan_not_found"


class PlanDigestMismatch(JobPlanError):
    code = "plan_digest_mismatch"


class PlanBuilding(JobPlanError):
    code = "plan_building"


class PlanFailed(JobPlanError):
    code = "plan_failed"


class PlanKindUnsupported(JobPlanError):
    code = "plan_kind_unsupported"


class PlanLabelsInexact(JobPlanError):
    code = "plan_labels_inexact"


class PlanLibraryConflict(JobPlanError):
    code = "plan_library_conflict"


class PlanLabelUnavailable(JobPlanError):
    code = "plan_label_unavailable"


class PlanLabelRegistered(JobPlanError):
    code = "plan_label_registered"


class PlanLabelIdentityAmbiguous(JobPlanError):
    code = "plan_label_identity_ambiguous"


class PlanSourceEvidenceChanged(JobPlanError):
    code = "managed_source_evidence_changed"


class PlanConsumptionConflict(JobPlanError):
    code = "plan_consumption_conflict"


class AutomaticFormatAuthorizationRequired(JobPlanError):
    code = "automatic_format_authorization_required"


_PLAN_CONSUMPTION_ERRORS: dict[str, type[JobPlanError]] = {
    error.code: error
    for error in (
        PlanStale,
        PlanConsumed,
        PlanExpired,
        PlanNotFound,
        PlanDigestMismatch,
        PlanBuilding,
        PlanFailed,
        PlanKindUnsupported,
        PlanLabelsInexact,
        PlanLibraryConflict,
        PlanLabelUnavailable,
        PlanLabelRegistered,
        PlanLabelIdentityAmbiguous,
        PlanSourceEvidenceChanged,
        PlanConsumptionConflict,
        AutomaticFormatAuthorizationRequired,
    )
}


def _plan_consumption_error(error: CatalogError) -> JobPlanError:
    code = str(error)
    error_type = _PLAN_CONSUMPTION_ERRORS.get(code)
    if error_type is None:
        raise error
    return error_type(code)


class LibraryManagementError(ValidationError):
    code = "library_error"


class LibraryPathInvalid(LibraryManagementError):
    code = "library_path_invalid"


class LibraryNotFound(LibraryManagementError):
    code = "library_not_found"


class LibraryAlreadyExists(LibraryManagementError):
    code = "library_already_exists"


class LibrarySourceChanged(LibraryManagementError):
    code = "library_source_changed"


class ShareIdentityChanged(LibraryManagementError):
    code = "share_identity_changed"


class LibraryInUse(LibraryManagementError):
    code = "library_in_use"


class LibraryStateConflict(LibraryManagementError):
    code = "library_state_conflict"


class LibraryRevisionConflict(LibraryManagementError):
    code = "library_revision_conflict"


class LibraryConfirmationMismatch(LibraryManagementError):
    code = "library_confirmation_mismatch"


class IdempotencyConflict(LibraryManagementError):
    code = "idempotency_conflict"


class JobManagementError(ValidationError):
    code = "job_error"


class JobNotFound(JobManagementError):
    code = "job_not_found"


class JobStateConflict(JobManagementError):
    code = "job_state_conflict"


class JobRevisionConflict(JobManagementError):
    code = "job_revision_conflict"


class JobImportedFrozen(JobManagementError):
    code = "job_imported_frozen"


class JobConfirmationMismatch(JobManagementError):
    code = "job_confirmation_mismatch"


class ApplicationSettingsManagementError(ValidationError):
    code = "application_settings_error"


class ApplicationSettingsRevisionConflict(ApplicationSettingsManagementError):
    code = "settings_revision_conflict"


class ApplicationSettingsIdempotencyConflict(ApplicationSettingsManagementError):
    code = "idempotency_conflict"


class ShareManagementError(ValidationError):
    code = "share_state_conflict"

    def __init__(self, message: str = "share operation conflicts with current state"):
        super().__init__(message)
        if message in SHARE_SAFE_ERROR_CODES:
            self.code = message


class ShareNotFound(ShareManagementError):
    code = "share_not_found"


class ShareBusy(ShareManagementError):
    code = "share_busy"


class ShareRevisionConflict(ShareManagementError):
    code = "share_revision_conflict"


class ShareCredentialsRequired(ShareManagementError):
    code = "share_credentials_required"


class ShareConfirmationMismatch(ShareManagementError):
    code = "share_state_conflict"


class ShareCallQuiescedTimeout(TimeoutError):
    def __init__(self, result: object | None = None) -> None:
        self.result = result
        super().__init__()


class ShareCallRecoveryPending(TimeoutError):
    pass


class _DaemonThreadExecutor:
    def submit(self, function: Callable[[], None]) -> None:
        threading.Thread(
            target=function,
            name="lto-share-operation",
            daemon=True,
        ).start()


async def _run_in_worker(function: Callable[..., Any], *args, **kwargs) -> Any:
    """Run finite source/catalog work off-loop without a shared executor."""

    outcome: dict[str, Any] = {}

    def worker() -> None:
        try:
            outcome["result"] = function(*args, **kwargs)
        except Exception as exc:
            outcome["error"] = exc

    thread = threading.Thread(target=worker, name="lto-plan-worker")
    thread.start()
    try:
        while thread.is_alive():
            await asyncio.sleep(0.01)
    finally:
        thread.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("result")


class ManagementService:
    """Catalog/source-only management operations for immutable job drafts.

    Daemon startup initializes and migrates the catalog before exposing the API.
    Read projections rely on that schema: initializing on each read would acquire
    a write lock and block WAL readers behind an active library scan.
    """

    def __init__(
        self,
        application: LtoApplication,
        *,
        broker: object | None = None,
        drive_lock: object | None = None,
        now: Callable[[], datetime] | None = None,
        source_roots: Sequence[Path] | None = None,
        min_age_seconds: int = 0,
        buffer_bytes: int = 16 * 1024**2,
        on_library_change: Callable[[dict[str, Any]], None] | None = None,
        share_broker: object | None = None,
        share_endpoint_policy: EndpointPolicy | None = None,
        share_resolver: Callable[[str], Sequence[object]] | None = None,
        share_probe: Callable[[Path], object] | None = None,
        share_executor: object | None = None,
        managed_source_mount_root: Path = Path("/mnt/lto-archiver/sources"),
        share_owner_id: str | None = None,
        share_timeout_seconds: float = 30.0,
        share_recovery_timeout_seconds: float = 30.0,
        on_share_change: Callable[[dict[str, Any]], None] | None = None,
        share_credential_request_key: bytes | None = None,
    ) -> None:
        self.application = application
        # These dependencies are accepted so composition roots can inject the
        # same sentinels as operation services.  Plan methods never access them.
        self._broker = broker
        self._drive_lock = drive_lock
        self._now = now or (lambda: datetime.now(UTC))
        self._source_roots = tuple(Path(root) for root in (source_roots or ()))
        self._min_age_seconds = min_age_seconds
        self._buffer_bytes = buffer_bytes
        self._library_mutation_lock = threading.RLock()
        self._on_library_change = on_library_change
        self._scan_threads: set[threading.Thread] = set()
        self._scan_threads_lock = threading.RLock()
        self._share_broker = share_broker
        self._share_endpoint_policy = share_endpoint_policy
        self._share_resolver = share_resolver
        self._share_probe = share_probe or (lambda target: target.stat())
        self._share_executor = share_executor or _DaemonThreadExecutor()
        self._managed_source_mount_root = Path(managed_source_mount_root)
        self._share_owner_id = share_owner_id or f"share-daemon-{uuid.uuid4().hex}"
        if (
            not self._managed_source_mount_root.is_absolute()
            or type(share_timeout_seconds) not in {int, float}
            or type(share_timeout_seconds) is bool
            or not 0 < float(share_timeout_seconds) <= 600
            or type(share_recovery_timeout_seconds) not in {int, float}
            or type(share_recovery_timeout_seconds) is bool
            or not 0 < float(share_recovery_timeout_seconds) <= 600
        ):
            raise ValidationError("invalid managed share execution policy")
        self._share_timeout_seconds = float(share_timeout_seconds)
        self._share_recovery_timeout_seconds = float(share_recovery_timeout_seconds)
        self._share_locks: dict[str, threading.RLock] = {}
        self._share_locks_guard = threading.RLock()
        self._share_broker_call_locks: dict[str, threading.Lock] = {}
        self._on_share_change = on_share_change
        credential_request_key = share_credential_request_key or secrets.token_bytes(32)
        if (
            type(credential_request_key) is not bytes
            or len(credential_request_key) != 32
        ):
            raise ValidationError("invalid share credential request key")
        self._share_credential_request_key = bytes(credential_request_key)
        self._managed_source_verifier = ManagedSourceVerifier(
            self.application.paths.catalog_file,
            self._managed_source_mount_root,
            parse_config=self._share_config,
            inspect_mount=self._inspect_actual_mount,
        )

    def _utc_now(self) -> datetime:
        value = self._now()
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValidationError("management clock must return UTC")
        return value.astimezone(UTC).replace(microsecond=0)

    async def create_restore_plan(
        self,
        file_version_ids: Sequence[int],
        *,
        destination_root: str,
        destination_subdirectory: str = "",
        allowed_restore_roots: Sequence[Path],
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        versions = tuple(file_version_ids)
        destination = PurePosixPath(destination_root)
        allowed = tuple(PurePosixPath(str(root)) for root in allowed_restore_roots)
        subdirectory = PurePosixPath(destination_subdirectory)
        if (
            not allowed
            or not destination.is_absolute()
            or any(part in {".", ".."} for part in destination.parts)
            or destination not in allowed
            or (
                destination_subdirectory
                and (
                    destination_subdirectory == "."
                    or destination_subdirectory.startswith("/")
                    or "\\" in destination_subdirectory
                    or "\x00" in destination_subdirectory
                    or len(destination_subdirectory) > 2048
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for character in destination_subdirectory
                    )
                    or any(part in {".", ".."} for part in subdirectory.parts)
                    or subdirectory.as_posix() != destination_subdirectory
                )
            )
        ):
            raise ValidationError("restore_destination_not_allowed")
        resolved_destination = destination.joinpath(subdirectory)
        if resolved_destination.parts[: len(destination.parts)] != destination.parts:
            raise ValidationError("restore_destination_not_allowed")
        request_sha256 = self._request_sha256(
            {
                "destination_kind": "local",
                "destination_anchor": str(destination),
                "destination_root": str(destination),
                "destination_subdirectory": destination_subdirectory,
                "resolved_destination": str(resolved_destination),
                "file_version_ids": list(versions),
            }
        )
        return await _run_in_worker(
            self._create_restore_plan,
            versions,
            str(resolved_destination),
            "local",
            str(destination),
            actor,
            idempotency_key,
            request_sha256,
        )

    def _create_restore_plan(
        self,
        file_version_ids: tuple[int, ...],
        destination_root: str,
        destination_kind: str,
        destination_anchor: str,
        actor: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.create_restore_plan(
                file_version_ids,
                destination_root,
                destination_kind=destination_kind,
                destination_anchor=destination_anchor,
                actor=actor,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )

    def get_restore_plan(self, plan_id: str) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.get_restore_plan(plan_id)

    def inspect_managed_share_mount(self, share_id: str) -> ShareMountReceiptV1:
        """Return one closed, broker-validated inspection receipt for a managed share."""

        try:
            normalized_id = normalize_share_id(share_id)
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                share = catalog.get_managed_share(normalized_id)
            config = self._share_config(share)
            return self._inspect_actual_mount(share, config)
        except ShareManagementError:
            raise
        except Exception:  # noqa: BLE001 - do not expose catalog/broker detail
            raise ShareManagementError("share mount inspection failed") from None

    def authorize_restore_item_replacement(
        self,
        run_id: str,
        item_sequence: int,
        *,
        administrator: str,
        fresh_reauthentication: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.authorize_restore_item_replacement(
                run_id,
                item_sequence,
                administrator=administrator,
                fresh_reauthentication=fresh_reauthentication,
                idempotency_key=idempotency_key,
            )

    def _share_lock(self, share_id: str) -> threading.RLock:
        with self._share_locks_guard:
            return self._share_locks.setdefault(share_id, threading.RLock())

    def _share_broker_call_lock(self, share_id: str) -> threading.Lock:
        with self._share_locks_guard:
            return self._share_broker_call_locks.setdefault(share_id, threading.Lock())

    def _bounded_share_call(self, function: Callable[..., Any], *args, **kwargs) -> Any:
        outcome: dict[str, Any] = {}
        done = threading.Event()

        def invoke() -> None:
            try:
                outcome["result"] = function(*args, **kwargs)
            except BaseException as exc:  # retain only for the local caller
                outcome["error"] = exc
            finally:
                done.set()

        threading.Thread(
            target=invoke,
            name="lto-share-bounded-call",
            daemon=True,
        ).start()
        if not done.wait(self._share_timeout_seconds):
            raise TimeoutError
        if "error" in outcome:
            raise outcome["error"]
        return outcome.get("result")

    def _bounded_share_broker_call(
        self, share_id: str, function: Callable[..., Any], *args, **kwargs
    ) -> Any:
        """Keep post-timeout inspection behind the ambiguous broker call."""

        lock = self._share_broker_call_lock(share_id)
        outcome: dict[str, Any] = {}
        done = threading.Event()

        def serialized_call() -> None:
            try:
                with lock:
                    outcome["result"] = function(*args, **kwargs)
            except BaseException as exc:  # retain only for this local boundary
                outcome["error"] = exc
            finally:
                done.set()

        threading.Thread(
            target=serialized_call,
            name="lto-share-broker-bounded-call",
            daemon=True,
        ).start()
        if done.wait(self._share_timeout_seconds):
            if "error" in outcome:
                raise outcome["error"]
            return outcome.get("result")
        if not done.wait(self._share_recovery_timeout_seconds):
            raise ShareCallRecoveryPending
        raise ShareCallQuiescedTimeout(outcome.get("result"))

    @staticmethod
    def _share_config(row: Mapping[str, Any]) -> ShareConfig:
        try:
            payload = json.loads(str(row["config_json"]))
            if payload.get("kind") == "nfs":
                return NfsShareConfig.model_validate(payload)
            if payload.get("kind") == "smb":
                return SmbShareConfig.model_validate(payload)
        except Exception:  # noqa: BLE001 - never expose persisted endpoint detail
            pass
        raise ShareManagementError("share configuration is invalid")

    def _resolve_share(self, config: ShareConfig) -> tuple[str, ...]:
        if self._share_endpoint_policy is None or self._share_resolver is None:
            raise ShareManagementError("share endpoint policy is unavailable")
        try:
            resolved = self._bounded_share_call(self._share_resolver, config.server)
            return tuple(
                sorted(self._share_endpoint_policy.admit(config.server, resolved))
            )
        except TimeoutError:
            raise
        except Exception:  # noqa: BLE001 - endpoint diagnostics stay local
            raise ShareManagementError("share_endpoint_not_allowed") from None

    @staticmethod
    def _translate_share_catalog_error(exc: CatalogError) -> ShareManagementError:
        code = str(exc)
        if code == "share_not_found":
            return ShareNotFound(code)
        if code == "share_revision_conflict":
            return ShareRevisionConflict(code)
        if code in {"share_busy", "idempotency_conflict"}:
            return ShareBusy(code)
        return ShareManagementError(code)

    def _share_event_payload(
        self, share: Mapping[str, Any], operation: Mapping[str, Any] | None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "share": {
                "share_id": share["share_id"],
                "display_name": share["display_name"],
                "protocol": share["protocol"],
                "lifecycle": share["lifecycle"],
                "desired_state": share["desired_state"],
                "observed_state": share["observed_state"],
                "safe_error_code": share["safe_error_code"],
                "revision": share["revision"],
                "last_checked_at": share["last_checked_at"],
            }
        }
        if operation is not None:
            payload["operation"] = {
                key: operation[key]
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
        return payload

    def _notify_share_change(
        self, share: Mapping[str, Any], operation: Mapping[str, Any] | None
    ) -> None:
        if self._on_share_change is not None:
            self._on_share_change(self._share_event_payload(share, operation))

    def create_network_share(
        self,
        share_id: str,
        display_name: str,
        config_payload: Mapping[str, Any],
        *,
        auto_connect: bool,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_id = normalize_share_id(share_id)
        try:
            raw_config = dict(config_payload)
            fingerprint = self._request_sha256(
                {
                    "auto_connect": auto_connect,
                    "config": raw_config,
                    "display_name": display_name,
                    "share_id": normalized_id,
                }
            )
        except Exception:  # noqa: BLE001 - closed public validation boundary
            raise ShareManagementError("share configuration is invalid") from None
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                replay = catalog.management_idempotency_replay(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action="share.create",
                    target_id=normalized_id,
                    request_sha256=fingerprint,
                )
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
            if replay is not None:
                return replay
        try:
            config: ShareConfig = (
                NfsShareConfig.model_validate(raw_config)
                if raw_config.get("kind") == "nfs"
                else SmbShareConfig.model_validate(raw_config)
            )
        except Exception:  # noqa: BLE001 - closed public validation boundary
            raise ShareManagementError("share configuration is invalid") from None
        self._resolve_share(config)
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                created = catalog.create_managed_share(
                    normalized_id,
                    display_name,
                    config.kind,
                    json.dumps(
                        config.model_dump(mode="json"),
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                    desired_state="connected",
                    observed_state="connecting",
                    auto_connect=True,
                )
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
        self._notify_share_change(created, None)
        self.start_network_share_operation(
            normalized_id,
            "connect",
            expected_revision=int(created["revision"]),
            actor=actor,
            idempotency_key=f"{idempotency_key}-connect",
        )
        return created

    def list_network_shares(self) -> tuple[dict[str, Any], ...]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            rows = catalog.list_managed_shares()
            return tuple(
                {
                    **row,
                    "current_operation": catalog.get_current_share_operation(
                        row["share_id"]
                    ),
                    "latest_operation": catalog.get_latest_share_operation(
                        row["share_id"]
                    ),
                }
                for row in rows
            )

    def get_network_share(self, share_id: str) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                share = catalog.get_managed_share(share_id)
                return {
                    **share,
                    "current_operation": catalog.get_current_share_operation(
                        share["share_id"]
                    ),
                    "latest_operation": catalog.get_latest_share_operation(
                        share["share_id"]
                    ),
                }
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None

    def get_network_share_operation(self, operation_id: str) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                return catalog.get_share_operation(operation_id)
            except CatalogError as exc:
                if str(exc) == "share_operation_not_found":
                    raise ShareNotFound("share_operation_not_found") from None
                raise self._translate_share_catalog_error(exc) from None

    def update_network_share(
        self,
        share_id: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
        display_name: str | None = None,
        config_payload: Mapping[str, Any] | None = None,
        auto_connect: bool | None = None,
        lifecycle: str | None = None,
    ) -> dict[str, Any]:
        normalized_id = normalize_share_id(share_id)
        try:
            raw_config = None if config_payload is None else dict(config_payload)
            fingerprint = self._request_sha256(
                {
                    "auto_connect": auto_connect,
                    "config": raw_config,
                    "display_name": display_name,
                    "expected_revision": expected_revision,
                    "lifecycle": lifecycle,
                    "share_id": normalized_id,
                }
            )
        except Exception:  # noqa: BLE001 - closed public validation boundary
            raise ShareManagementError("share configuration is invalid") from None
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                replay = catalog.management_idempotency_replay(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action="share.update",
                    target_id=normalized_id,
                    request_sha256=fingerprint,
                )
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
            if replay is not None:
                return replay
        config: ShareConfig | None = None
        if raw_config is not None:
            try:
                config = (
                    NfsShareConfig.model_validate(raw_config)
                    if raw_config.get("kind") == "nfs"
                    else SmbShareConfig.model_validate(raw_config)
                )
            except Exception:  # noqa: BLE001 - closed public validation boundary
                raise ShareManagementError("share configuration is invalid") from None
            self._resolve_share(config)
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                current = catalog.get_managed_share(normalized_id)
                target_lifecycle = str(lifecycle or current["lifecycle"])
                target_auto_connect = target_lifecycle == "active"
                target_desired_state = (
                    "connected" if target_auto_connect else "disconnected"
                )
                changed = catalog.update_managed_share(
                    share_id,
                    expected_revision=expected_revision,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                    display_name=display_name,
                    protocol=None if config is None else config.kind,
                    config_json=(
                        None
                        if config is None
                        else json.dumps(
                            config.model_dump(mode="json"),
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                    ),
                    desired_state=target_desired_state,
                    auto_connect=target_auto_connect,
                    lifecycle=lifecycle,
                    queue_lifecycle_operation=True,
                    lifecycle_operation_id=f"share-{uuid.uuid4().hex}",
                )
                queued = catalog.get_current_share_operation(normalized_id)
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
        self._notify_share_change(changed, queued)
        if queued is not None:
            self._share_executor.submit(
                lambda: self._execute_network_share_operation(
                    str(queued["operation_id"])
                )
            )
        return changed

    def retire_network_share(
        self,
        share_id: str,
        *,
        typed_share_id: str,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_id = normalize_share_id(share_id)
        if not secrets.compare_digest(normalized_id, typed_share_id):
            raise ShareConfirmationMismatch("share confirmation does not match")
        fingerprint = self._request_sha256(
            {
                "expected_revision": expected_revision,
                "share_id": normalized_id,
                "typed_share_id": typed_share_id,
            }
        )
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                changed = catalog.retire_managed_share(
                    normalized_id,
                    expected_revision=expected_revision,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                )
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
        self._notify_share_change(changed, None)
        return changed

    def remove_network_share(
        self,
        share_id: str,
        *,
        typed_share_id: str,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_id = normalize_share_id(share_id)
        if not secrets.compare_digest(normalized_id, typed_share_id):
            raise ShareConfirmationMismatch("share confirmation does not match")
        fingerprint = self._request_sha256(
            {
                "expected_revision": expected_revision,
                "share_id": normalized_id,
                "typed_share_id": typed_share_id,
            }
        )
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                removed = catalog.finalize_managed_share_removal(
                    normalized_id,
                    expected_revision=expected_revision,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                )
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
        self._notify_share_change(removed, None)
        return removed

    def _credential_request_sha256(
        self,
        *,
        share_id: str,
        expected_revision: int,
        username: str | None,
        domain: str | None,
        password: str | None,
        clear: bool,
    ) -> str:
        encoded = json.dumps(
            {
                "clear": clear,
                "domain": domain,
                "expected_revision": expected_revision,
                "password": password,
                "share_id": share_id,
                "username": username,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(
            self._share_credential_request_key,
            b"lto-share-credential-daemon-request-v1\0" + encoded,
            hashlib.sha256,
        ).hexdigest()

    def start_network_share_credential(
        self,
        share_id: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
        username: str,
        password: str,
        domain: str | None = None,
    ) -> dict[str, Any]:
        return self._start_network_share_credential_operation(
            share_id,
            expected_revision=expected_revision,
            actor=actor,
            idempotency_key=idempotency_key,
            username=username,
            password=password,
            domain=domain,
            clear=False,
        )

    def clear_network_share_credential(
        self,
        share_id: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return self._start_network_share_credential_operation(
            share_id,
            expected_revision=expected_revision,
            actor=actor,
            idempotency_key=idempotency_key,
            username=None,
            password=None,
            domain=None,
            clear=True,
        )

    def _start_network_share_credential_operation(
        self,
        share_id: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
        username: str | None,
        password: str | None,
        domain: str | None,
        clear: bool,
    ) -> dict[str, Any]:
        normalized_id = normalize_share_id(share_id)
        action = "credential.clear" if clear else "credential.install"
        fingerprint = self._credential_request_sha256(
            share_id=normalized_id,
            expected_revision=expected_revision,
            username=username,
            domain=domain,
            password=password,
            clear=clear,
        )
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                replay = catalog.replay_share_operation(
                    share_id=normalized_id,
                    action=action,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                    expected_share_revision=expected_revision,
                )
                if replay is not None:
                    return replay
                share = catalog.get_managed_share(normalized_id)
                if share["protocol"] != "smb":
                    raise ShareManagementError("NFS shares do not use credentials")
                if (
                    share["desired_state"] != "disconnected"
                    or share["observed_state"] != "disconnected"
                ):
                    raise ShareManagementError(
                        "share credential changes require disconnect"
                    )
                generation = (
                    int(share["credential_generation"])
                    if clear
                    else int(share["credential_generation"]) + 1
                )
                if clear and not share["credential_configured"]:
                    raise ShareCredentialsRequired
                operation = catalog.queue_share_operation(
                    f"share-{uuid.uuid4().hex}",
                    normalized_id,
                    action,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                    expected_share_revision=expected_revision,
                )
                admitted_share = catalog.get_managed_share(normalized_id)
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
        self._notify_share_change(admitted_share, operation)
        credential_values = (username, domain, password)
        self._share_executor.submit(
            lambda: self._execute_network_share_credential(
                operation["operation_id"],
                generation=generation,
                values=credential_values,
                clear=clear,
            )
        )
        return operation

    def _execute_network_share_credential(
        self,
        operation_id: str,
        *,
        generation: int,
        values: tuple[str | None, str | None, str | None],
        clear: bool,
    ) -> None:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            operation = catalog.get_share_operation(operation_id)
        share_id = str(operation["share_id"])
        with self._share_lock(share_id):
            try:
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    operation = catalog.claim_share_operation(
                        operation_id, owner_id=self._share_owner_id
                    )
                    catalog.get_managed_share(share_id)
                if self._share_broker is None:
                    raise ShareBrokerUnavailable
                username, domain, password = values
                try:
                    if clear:
                        status = self._bounded_share_broker_call(
                            share_id,
                            self._share_broker.delete_smb_credential,
                            share_id,
                            generation,
                        )
                    else:
                        if username is None or password is None:
                            raise ShareManagementError("credential payload is invalid")
                        status = self._bounded_share_broker_call(
                            share_id,
                            self._share_broker.install_smb_credential,
                            share_id,
                            generation,
                            username=username,
                            password=password,
                            domain=domain,
                        )
                except ShareCallQuiescedTimeout:
                    status = self._bounded_share_broker_call(
                        share_id,
                        self._share_broker.inspect_credential,
                        share_id,
                    )
                if (
                    status.share_id != share_id
                    or status.generation != generation
                    or status.configured is clear
                ):
                    raise ShareManagementError("credential broker status is invalid")
                receipt_sha256 = self._credential_status_sha256(status)
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    finished = catalog.finish_share_operation(
                        operation_id,
                        state="succeeded",
                        receipt_sha256=receipt_sha256,
                        credential_generation=generation,
                        credential_configured=status.configured,
                        increment_resource_revision=True,
                        last_checked_at=self._utc_now().isoformat(),
                    )
                    terminal_share = catalog.get_managed_share(share_id)
            except Exception as exc:  # noqa: BLE001 - secret boundary is redacted
                if isinstance(exc, ShareCallRecoveryPending):
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        recovering = catalog.mark_share_operation_recovering(
                            operation_id,
                            owner_id=self._share_owner_id,
                            recovery_deadline=(
                                self._utc_now()
                                + timedelta(
                                    seconds=self._share_recovery_timeout_seconds
                                )
                            ).isoformat(),
                        )
                        recovering_share = catalog.get_managed_share(share_id)
                    self._notify_share_change(recovering_share, recovering)
                    return
                safe_error = (
                    "share_operation_timeout"
                    if isinstance(exc, TimeoutError)
                    else exc.safe_error_code
                    if isinstance(exc, ShareBrokerUnavailable)
                    else exc.code
                    if isinstance(exc, ShareManagementError)
                    else "share_authentication_failed"
                )
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    finished = catalog.finish_share_operation(
                        operation_id,
                        state="failed",
                        receipt_sha256=None,
                        safe_error_code=safe_error,
                        last_checked_at=self._utc_now().isoformat(),
                    )
                    terminal_share = catalog.get_managed_share(share_id)
            self._notify_share_change(terminal_share, finished)

    @staticmethod
    def _credential_status_sha256(status: CredentialStatus) -> str:
        return hashlib.sha256(
            b"lto-share-credential-status-v1\0"
            + json.dumps(
                {
                    "configured": status.configured,
                    "generation": status.generation,
                    "share_id": status.share_id,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()

    def recover_network_shares(self) -> tuple[dict[str, Any], ...]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            shares = tuple(catalog.list_managed_shares())
        fence_failed = False
        if self._share_broker is not None:
            try:
                self._bounded_share_call(
                    self._share_broker.fence_unknown_mounts,
                    tuple(str(share["share_id"]) for share in shares),
                )
            except Exception:  # noqa: BLE001 - each share remains independently visible
                fence_failed = True
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            recovered = catalog.recover_interrupted_share_operations(
                owner_id=self._share_owner_id
            )
            current = {
                share["share_id"]: catalog.get_managed_share(share["share_id"])
                for share in shares
            }
        for operation in recovered:
            self._notify_share_change(current[operation["share_id"]], operation)

        reconciled: dict[str, dict[str, Any]] = {}
        actual_receipts: dict[str, ShareMountReceiptV1] = {}
        credential_statuses: dict[str, CredentialStatus] = {}
        for share_id, share in current.items():
            observed_state = "error"
            safe_error_code: str | None = "share_recovery_required"
            mount_identity_sha256 = share.get("mount_identity_sha256")
            mounted_config_revision = share.get("mounted_config_revision")
            mounted_credential_generation = share.get("mounted_credential_generation")
            try:
                config = self._share_config(share)
                actual = self._inspect_actual_mount(share, config)
                actual_receipts[share_id] = actual
                credential_mismatch = False
                if type(config) is SmbShareConfig:
                    if self._share_broker is None:
                        raise ShareBrokerUnavailable
                    credential = self._bounded_share_broker_call(
                        share_id, self._share_broker.inspect_credential, share_id
                    )
                    if type(credential) is CredentialStatus:
                        credential_statuses[share_id] = credential
                    credential_mismatch = (
                        type(credential) is not CredentialStatus
                        or credential.share_id != share_id
                        or credential.generation != int(share["credential_generation"])
                        or credential.configured
                        is not bool(share["credential_configured"])
                    )
                if actual.result == "mounted":
                    mount_identity_sha256 = actual.mount_identity_sha256
                    mounted_config_revision = actual.config_revision
                    mounted_credential_generation = actual.credential_generation
                    if share["desired_state"] == "disconnected":
                        absent, final = self._verify_failed_operation_cleanup(
                            share, config, cleanup_allowed=True
                        )
                        if absent:
                            if final is not None:
                                actual_receipts[share_id] = final
                            observed_state = "disconnected"
                            safe_error_code = None
                            mount_identity_sha256 = None
                            mounted_config_revision = None
                            mounted_credential_generation = None
                        elif final is not None and final.result == "mounted":
                            mount_identity_sha256 = final.mount_identity_sha256
                            mounted_config_revision = final.config_revision
                            mounted_credential_generation = final.credential_generation
                    elif not credential_mismatch:
                        observed_state = "connected"
                        safe_error_code = None
                else:
                    observed_state = "disconnected"
                    safe_error_code = None
                    mount_identity_sha256 = None
                    mounted_config_revision = None
                    mounted_credential_generation = None
                if credential_mismatch:
                    observed_state = "error"
                    safe_error_code = "share_credentials_required"
                if fence_failed:
                    observed_state = "error"
                    safe_error_code = "share_recovery_required"
            except Exception:  # noqa: BLE001 - persist one safe per-share failure
                observed_state = "error"
                safe_error_code = "share_recovery_required"
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                try:
                    reconciled_share = catalog.record_managed_share_observation(
                        share_id,
                        actor=self._share_owner_id,
                        observed_state=observed_state,
                        safe_error_code=safe_error_code,
                        mount_identity_sha256=mount_identity_sha256,
                        mounted_config_revision=mounted_config_revision,
                        mounted_credential_generation=mounted_credential_generation,
                        checked_at=self._utc_now().isoformat(),
                    )
                except CatalogError:
                    continue
            reconciled[share_id] = reconciled_share
            self._notify_share_change(reconciled_share, None)

        for operation in recovered:
            share_id = str(operation["share_id"])
            action = str(operation["action"])
            actual = actual_receipts.get(share_id)
            credential = credential_statuses.get(share_id)
            finish_kwargs: dict[str, Any] | None = None
            if action in {"credential.install", "credential.clear"}:
                frozen_generation = int(operation["frozen_credential_generation"])
                target_generation = frozen_generation
                configured = action == "credential.install"
                if configured:
                    target_generation += 1
                if (
                    credential is not None
                    and credential.share_id == share_id
                    and credential.generation == target_generation
                    and credential.configured is configured
                ):
                    finish_kwargs = {
                        "state": "succeeded",
                        "receipt_sha256": self._credential_status_sha256(credential),
                        "observed_state": "disconnected",
                        "credential_generation": target_generation,
                        "credential_configured": configured,
                        "increment_resource_revision": True,
                    }
                elif (
                    credential is not None
                    and credential.share_id == share_id
                    and credential.generation == frozen_generation
                    and credential.configured
                    is bool(current[share_id]["credential_configured"])
                ):
                    finish_kwargs = {
                        "state": "failed",
                        "receipt_sha256": self._credential_status_sha256(credential),
                        "safe_error_code": (
                            "share_operation_timeout"
                            if operation.get("recovery_deadline") is not None
                            else "share_recovery_required"
                        ),
                    }
            elif actual is not None and not fence_failed:
                if action in {"connect", "reconcile"}:
                    if actual.result == "mounted":
                        try:
                            share = current[share_id]
                            absent, final = self._verify_failed_operation_cleanup(
                                share,
                                self._share_config(share),
                                cleanup_allowed=True,
                            )
                        except Exception:  # noqa: BLE001 - still not quiescent
                            continue
                        if final is not None:
                            actual = final
                        if not absent:
                            continue
                    finish_kwargs = {
                        "state": "failed",
                        "receipt_sha256": mount_receipt_sha256(actual),
                        "safe_error_code": (
                            "share_operation_timeout"
                            if operation.get("recovery_deadline") is not None
                            else "share_recovery_required"
                        ),
                        "observed_state": "error",
                        "mount_identity_sha256": None,
                        "mounted_config_revision": None,
                        "mounted_credential_generation": None,
                    }
                elif action == "disconnect" and actual.result == "unmounted":
                    finish_kwargs = {
                        "state": "succeeded",
                        "receipt_sha256": mount_receipt_sha256(actual),
                        "observed_state": "disconnected",
                        "mount_identity_sha256": None,
                        "mounted_config_revision": None,
                        "mounted_credential_generation": None,
                    }
                elif actual.result == "unmounted":
                    finish_kwargs = {
                        "state": "failed",
                        "receipt_sha256": mount_receipt_sha256(actual),
                        "safe_error_code": "share_recovery_required",
                        "observed_state": "error",
                        "mount_identity_sha256": None,
                        "mounted_config_revision": None,
                        "mounted_credential_generation": None,
                    }
            if finish_kwargs is None:
                continue
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                try:
                    finished = catalog.finish_share_operation(
                        str(operation["operation_id"]),
                        last_checked_at=self._utc_now().isoformat(),
                        **finish_kwargs,
                    )
                    terminal_share = catalog.get_managed_share(share_id)
                except CatalogError:
                    continue
            reconciled[share_id] = terminal_share
            self._notify_share_change(terminal_share, finished)

        for observed in reconciled.values():
            share = observed
            target_auto_connect = share["lifecycle"] == "active"
            target_desired_state = (
                "connected" if target_auto_connect else "disconnected"
            )
            if (
                share["auto_connect"] is not target_auto_connect
                or share["desired_state"] != target_desired_state
            ):
                request_fingerprint = self._request_sha256(
                    {
                        "auto_connect": target_auto_connect,
                        "desired_state": target_desired_state,
                        "share_id": share["share_id"],
                    }
                )
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    try:
                        share = catalog.update_managed_share(
                            str(share["share_id"]),
                            expected_revision=int(share["revision"]),
                            actor=self._share_owner_id,
                            idempotency_key=f"startup-state-{uuid.uuid4().hex}",
                            request_fingerprint_sha256=request_fingerprint,
                            desired_state=target_desired_state,
                            auto_connect=target_auto_connect,
                        )
                    except CatalogError:
                        continue
                self._notify_share_change(share, None)
            if fence_failed or share["safe_error_code"] is not None:
                continue
            action = (
                "reconcile"
                if share["lifecycle"] == "active"
                and share["observed_state"] == "disconnected"
                else "disconnect"
                if share["lifecycle"] == "disabled"
                and share["observed_state"] == "connected"
                else None
            )
            if action is None:
                continue
            try:
                self.start_network_share_operation(
                    share["share_id"],
                    action,
                    expected_revision=int(share["revision"]),
                    actor=self._share_owner_id,
                    idempotency_key=f"startup-{uuid.uuid4().hex}",
                )
            except ShareManagementError:
                continue
        return recovered

    def start_network_share_operation(
        self,
        share_id: str,
        action: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_id = normalize_share_id(share_id)
        if action not in {"connect", "disconnect", "test", "reconcile"}:
            raise ShareManagementError("share operation is invalid")
        fingerprint = self._request_sha256(
            {
                "action": action,
                "expected_revision": expected_revision,
                "share_id": normalized_id,
            }
        )
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                replay = catalog.replay_share_operation(
                    share_id=normalized_id,
                    action=action,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                    expected_share_revision=expected_revision,
                )
                if replay is not None:
                    return replay
                share = catalog.get_managed_share(normalized_id)
                current = catalog.get_current_share_operation(normalized_id)
                if current is not None:
                    raise ShareBusy("share_busy")
                if share["lifecycle"] != "active" and not (
                    action == "disconnect" and share["lifecycle"] == "disabled"
                ):
                    raise ShareManagementError("share is not active")
                if action == "disconnect" and share["observed_state"] not in {
                    "connected",
                    "disconnecting",
                }:
                    raise ShareManagementError("share is not connected")
                if action == "disconnect" and catalog.share_has_active_library_consumer(
                    normalized_id
                ):
                    raise ShareManagementError("share_in_use")
                if action == "connect" and share["observed_state"] == "connected":
                    raise ShareManagementError("share is already connected")
                desired_state = (
                    "connected"
                    if action in {"connect", "reconcile"}
                    else "disconnected"
                    if action == "disconnect"
                    else None
                )
                observed_state = (
                    "disconnecting"
                    if action == "disconnect"
                    else "connecting"
                    if action in {"connect", "reconcile"}
                    or (action == "test" and share["observed_state"] != "connected")
                    else None
                )
                queued = catalog.queue_share_operation(
                    f"share-{uuid.uuid4().hex}",
                    normalized_id,
                    action,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_fingerprint_sha256=fingerprint,
                    expected_share_revision=expected_revision,
                    desired_state=desired_state,
                    observed_state=observed_state,
                    require_no_consumers=action in {"disconnect", "credential.delete"},
                )
                admitted_share = catalog.get_managed_share(normalized_id)
            except CatalogError as exc:
                raise self._translate_share_catalog_error(exc) from None
        self._notify_share_change(admitted_share, queued)
        self._share_executor.submit(
            lambda: self._execute_network_share_operation(queued["operation_id"])
        )
        return queued

    def _validate_mount_receipt(
        self,
        receipt: ShareMountReceiptV1,
        *,
        action: str,
        share: Mapping[str, Any],
        config: ShareConfig,
        admitted_addresses: tuple[str, ...],
        expected_result: str,
    ) -> None:
        expected_action = {
            "connect": "mount.start",
            "reconcile": "mount.start",
            "test": "mount.start",
            "inspect": "mount.inspect",
            "disconnect": "mount.stop",
        }[action]
        if (
            type(receipt) is not ShareMountReceiptV1
            or receipt.action != expected_action
            or receipt.share_id != share["share_id"]
            or receipt.config_revision != int(share["config_revision"])
            or receipt.credential_generation != int(share["credential_generation"])
            or receipt.unit_name
            != mount_unit_name(
                derive_mount_target(
                    self._managed_source_mount_root, str(share["share_id"])
                )
            )
        ):
            raise ShareManagementError("share broker receipt is invalid")
        if receipt.result == "failed":
            if (
                receipt.read_only
                or receipt.mount_identity_sha256 is not None
                or receipt.filesystem_type is not None
                or receipt.source_sha256 is not None
                or receipt.safe_error_code is None
                or receipt.endpoint_server != config.server
                or (
                    admitted_addresses
                    and receipt.admitted_addresses != admitted_addresses
                )
            ):
                raise ShareManagementError("share broker failure evidence is invalid")
            raise ShareManagementError(receipt.safe_error_code)
        if receipt.result != expected_result:
            raise ShareManagementError("share broker receipt result is invalid")
        if expected_result == "mounted":
            address = admitted_addresses[0]
            source = (
                f"[{address}]:{config.export}"
                if type(config) is NfsShareConfig and ":" in address
                else f"{address}:{config.export}"
                if type(config) is NfsShareConfig
                else f"//{address}/{config.share}"
            )
            allowed_fs = (
                {"cifs"}
                if type(config) is SmbShareConfig
                else {"nfs"}
                if config.version == "3"
                else {"nfs", "nfs4"}
            )
            if (
                receipt.endpoint_server != config.server
                or receipt.admitted_addresses != admitted_addresses
                or receipt.filesystem_type not in allowed_fs
                or receipt.source_sha256 != source_identity_sha256(source)
                or receipt.read_only is not True
                or receipt.mount_identity_sha256 is None
                or receipt.safe_error_code is not None
            ):
                raise ShareManagementError("share broker evidence is invalid")
        elif (
            receipt.read_only
            or receipt.mount_identity_sha256 is not None
            or receipt.filesystem_type is not None
            or receipt.source_sha256 is not None
            or receipt.safe_error_code is not None
        ):
            raise ShareManagementError("share broker cleanup evidence is invalid")

    def _inspect_actual_mount(
        self,
        share: Mapping[str, Any],
        config: ShareConfig,
    ) -> ShareMountReceiptV1:
        if self._share_broker is None:
            raise ShareBrokerUnavailable
        share_id = str(share["share_id"])
        admitted_addresses = self._resolve_share(config)
        receipt = self._bounded_share_broker_call(
            share_id,
            self._share_broker.inspect,
            share_id,
            config,
            config_revision=int(share["config_revision"]),
            credential_generation=int(share["credential_generation"]),
            admitted_addresses=admitted_addresses,
        )
        self._validate_mount_receipt(
            receipt,
            action="inspect",
            share=share,
            config=config,
            admitted_addresses=admitted_addresses
            if receipt.result == "mounted"
            else (),
            expected_result=receipt.result,
        )
        return receipt

    def _verify_failed_operation_cleanup(
        self,
        share: Mapping[str, Any],
        config: ShareConfig,
        *,
        cleanup_allowed: bool,
    ) -> tuple[bool, ShareMountReceiptV1 | None]:
        """Serialize behind the broker call and prove absence after ambiguity."""

        try:
            actual = self._inspect_actual_mount(share, config)
        except ShareManagementError as exc:
            if not cleanup_allowed or exc.code != "share_identity_changed":
                raise
            actual = None
        if actual is not None and actual.result == "unmounted":
            return True, actual
        if not cleanup_allowed or self._share_broker is None:
            return False, actual
        try:
            cleanup = self._bounded_share_broker_call(
                str(share["share_id"]),
                self._share_broker.unmount,
                str(share["share_id"]),
            )
            self._validate_mount_receipt(
                cleanup,
                action="disconnect",
                share=share,
                config=config,
                admitted_addresses=(),
                expected_result="unmounted",
            )
        except Exception:  # noqa: BLE001 - inspection resolves ambiguous timeout
            final = self._inspect_actual_mount(share, config)
            return final.result == "unmounted", final
        final = self._inspect_actual_mount(share, config)
        return final.result == "unmounted", final

    def _execute_network_share_operation(self, operation_id: str) -> None:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            operation = catalog.get_share_operation(operation_id)
        share_id = str(operation["share_id"])
        with self._share_lock(share_id):
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                try:
                    operation = catalog.claim_share_operation(
                        operation_id, owner_id=self._share_owner_id
                    )
                    current_share = catalog.get_managed_share(share_id)
                    share = {
                        **current_share,
                        "config_json": operation["frozen_config_json"],
                        "config_revision": operation["frozen_config_revision"],
                        "credential_generation": operation[
                            "frozen_credential_generation"
                        ],
                        "observed_state": operation["frozen_observed_state"],
                    }
                except CatalogError:
                    return
            config = self._share_config(share)
            mounted = False
            receipt: ShareMountReceiptV1 | None = None
            admitted_addresses: tuple[str, ...] = ()
            action = str(operation["action"])
            try:
                if self._share_broker is None:
                    raise ShareBrokerUnavailable
                if action == "disconnect":
                    receipt = self._bounded_share_broker_call(
                        share_id, self._share_broker.unmount, share_id
                    )
                    self._validate_mount_receipt(
                        receipt,
                        action="disconnect",
                        share=share,
                        config=config,
                        admitted_addresses=(),
                        expected_result="unmounted",
                    )
                    terminal_observed = "disconnected"
                else:
                    admitted_addresses = self._resolve_share(config)
                    if type(config) is SmbShareConfig:
                        credential = self._bounded_share_broker_call(
                            share_id, self._share_broker.inspect_credential, share_id
                        )
                        if not credential.configured or credential.generation != int(
                            share["credential_generation"]
                        ):
                            raise ShareCredentialsRequired
                    if action == "test" and share["observed_state"] == "connected":
                        receipt = self._bounded_share_broker_call(
                            share_id,
                            self._share_broker.inspect,
                            share_id,
                            config,
                            config_revision=int(share["config_revision"]),
                            credential_generation=int(share["credential_generation"]),
                            admitted_addresses=admitted_addresses,
                        )
                        receipt_action = "inspect"
                    else:
                        receipt = self._bounded_share_broker_call(
                            share_id,
                            self._share_broker.mount,
                            share_id,
                            config,
                            config_revision=int(share["config_revision"]),
                            credential_generation=int(share["credential_generation"]),
                            admitted_addresses=admitted_addresses,
                        )
                        receipt_action = action
                        mounted = True
                    self._validate_mount_receipt(
                        receipt,
                        action=receipt_action,
                        share=share,
                        config=config,
                        admitted_addresses=admitted_addresses,
                        expected_result="mounted",
                    )
                    self._bounded_share_call(
                        self._share_probe,
                        derive_mount_target(self._managed_source_mount_root, share_id),
                    )
                    if action == "test" and mounted:
                        cleanup = self._bounded_share_broker_call(
                            share_id, self._share_broker.unmount, share_id
                        )
                        self._validate_mount_receipt(
                            cleanup,
                            action="disconnect",
                            share=share,
                            config=config,
                            admitted_addresses=(),
                            expected_result="unmounted",
                        )
                        mounted = False
                        terminal_observed = "disconnected"
                    else:
                        terminal_observed = "connected"
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    finished = catalog.finish_share_operation(
                        operation_id,
                        state="succeeded",
                        receipt_sha256=mount_receipt_sha256(receipt),
                        observed_state=terminal_observed,
                        mount_identity_sha256=(
                            receipt.mount_identity_sha256
                            if terminal_observed == "connected"
                            else None
                        ),
                        mounted_config_revision=(
                            receipt.config_revision
                            if terminal_observed == "connected"
                            else None
                        ),
                        mounted_credential_generation=(
                            receipt.credential_generation
                            if terminal_observed == "connected"
                            else None
                        ),
                        last_checked_at=self._utc_now().isoformat(),
                    )
                    terminal_share = catalog.get_managed_share(share_id)
            except Exception as exc:  # noqa: BLE001 - map the entire network boundary
                if isinstance(exc, ShareCallRecoveryPending):
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        recovering = catalog.mark_share_operation_recovering(
                            operation_id,
                            owner_id=self._share_owner_id,
                            recovery_deadline=(
                                self._utc_now()
                                + timedelta(
                                    seconds=self._share_recovery_timeout_seconds
                                )
                            ).isoformat(),
                        )
                        recovering_share = catalog.get_managed_share(share_id)
                    self._notify_share_change(recovering_share, recovering)
                    return
                if (
                    isinstance(exc, ShareCallQuiescedTimeout)
                    and type(exc.result) is ShareMountReceiptV1
                ):
                    late_receipt = exc.result
                    try:
                        self._validate_mount_receipt(
                            late_receipt,
                            action=("disconnect" if action == "disconnect" else action),
                            share=share,
                            config=config,
                            admitted_addresses=(
                                () if action == "disconnect" else admitted_addresses
                            ),
                            expected_result=(
                                "unmounted" if action == "disconnect" else "mounted"
                            ),
                        )
                        receipt = late_receipt
                    except ShareManagementError:
                        receipt = None
                cleanup_verified = False
                actual_receipt: ShareMountReceiptV1 | None = None
                connected_test = (
                    action == "test" and share["observed_state"] == "connected"
                )
                if self._share_broker is not None:
                    try:
                        cleanup_verified, actual_receipt = (
                            self._verify_failed_operation_cleanup(
                                share,
                                config,
                                cleanup_allowed=not connected_test,
                            )
                        )
                    except ShareCallRecoveryPending:
                        with Catalog(self.application.paths.catalog_file) as catalog:
                            catalog.initialize()
                            recovering = catalog.mark_share_operation_recovering(
                                operation_id,
                                owner_id=self._share_owner_id,
                                recovery_deadline=(
                                    self._utc_now()
                                    + timedelta(
                                        seconds=self._share_recovery_timeout_seconds
                                    )
                                ).isoformat(),
                            )
                            recovering_share = catalog.get_managed_share(share_id)
                        self._notify_share_change(recovering_share, recovering)
                        return
                    except Exception:  # noqa: BLE001 - ambiguity remains closed
                        cleanup_verified = False
                safe_error = (
                    "share_operation_timeout"
                    if isinstance(exc, TimeoutError)
                    else exc.safe_error_code
                    if isinstance(exc, ShareBrokerUnavailable)
                    else exc.code
                    if isinstance(exc, ShareManagementError)
                    else "share_endpoint_not_allowed"
                    if isinstance(exc, ShareValidationError)
                    else "share_mount_failed"
                )
                if not cleanup_verified:
                    safe_error = "share_recovery_required"
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    evidence_updates: dict[str, object] = {}
                    if cleanup_verified:
                        evidence_updates = {
                            "mount_identity_sha256": None,
                            "mounted_config_revision": None,
                            "mounted_credential_generation": None,
                        }
                    elif (
                        actual_receipt is not None
                        and actual_receipt.result == "mounted"
                    ):
                        evidence_updates = {
                            "mount_identity_sha256": actual_receipt.mount_identity_sha256,
                            "mounted_config_revision": actual_receipt.config_revision,
                            "mounted_credential_generation": (
                                actual_receipt.credential_generation
                            ),
                        }
                    finished = catalog.finish_share_operation(
                        operation_id,
                        state="failed",
                        receipt_sha256=(
                            None if receipt is None else mount_receipt_sha256(receipt)
                        ),
                        safe_error_code=safe_error,
                        observed_state="error",
                        last_checked_at=self._utc_now().isoformat(),
                        **evidence_updates,
                    )
                    terminal_share = catalog.get_managed_share(share_id)
            self._notify_share_change(terminal_share, finished)

    def initialize_application_settings(self) -> dict[str, Any]:
        """Import the legacy JSON once; a committed catalog row wins thereafter."""

        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            if catalog.application_settings_initialized():
                catalog.backfill_compatibility_policy_snapshots()
                return catalog.get_application_settings()
        config = self.application.paths.config_file
        if config.exists():
            payload = config.read_bytes()
            legacy = load_settings(self.application.paths)
            source_sha256 = hashlib.sha256(payload).hexdigest()
        else:
            legacy = Settings(
                buffer_bytes=self._buffer_bytes,
                min_age_seconds=self._min_age_seconds,
            )
            legacy.validate()
            source_sha256 = None
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.import_application_settings_once(
                legacy, legacy_source_sha256=source_sha256
            )

    def application_settings(self) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            return catalog.get_application_settings()

    @staticmethod
    def _legacy_settings_from_authority(authority: Mapping[str, Any]) -> Settings:
        return Settings(
            reserve_bytes=int(authority["capacity_reserve_bytes"]),
            tape_capacity_bytes=int(authority["legacy_tape_capacity_bytes"]),
            buffer_bytes=int(authority["copy_buffer_bytes"]),
            min_age_seconds=int(authority["minimum_source_file_age_seconds"]),
            tape_root_directory=str(authority["tape_root_directory"]),
            verify_unchanged_content=(
                authority["content_verification_policy"] == "full"
            ),
            default_media_key=str(authority["default_media_profile"]),
        )

    async def update_application_settings(
        self,
        candidate: Mapping[str, Any],
        *,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        normalized = dict(candidate)
        if "default_media_profile" in normalized:
            normalized["default_media_profile"] = require_ltfs_profile(
                normalized["default_media_profile"]
            ).key
        request_sha256 = self._request_sha256(
            {"candidate": normalized, "expected_revision": expected_revision}
        )
        with (
            RunLock(self.application.paths.lock_file),
            Catalog(self.application.paths.catalog_file) as catalog,
        ):
            catalog.initialize()
            try:
                return catalog.update_application_settings(
                    normalized,
                    expected_revision=expected_revision,
                    actor=actor,
                    idempotency_key=idempotency_key,
                    request_sha256=request_sha256,
                )
            except CatalogError as exc:
                if str(exc) == "settings_revision_conflict":
                    raise ApplicationSettingsRevisionConflict(str(exc)) from None
                if str(exc) == "idempotency_conflict":
                    raise ApplicationSettingsIdempotencyConflict(str(exc)) from None
                raise

    @staticmethod
    def _library_summary(row: dict[str, Any] | Any) -> dict[str, Any]:
        status = str(row["status"])
        source_kind = str(row["source_kind"] or "local")
        state = (
            "retired"
            if status == "retired"
            else "active"
            if bool(row["enabled"])
            else "disabled"
        )
        summary = {
            "id": str(row["id"]),
            "display_name": str(row["name"]),
            "source_root": str(row["source_root"]) if source_kind == "local" else None,
            "state": state,
            "scan_state": str(row["scan_state"]),
            "last_successful_scan_at": row["last_scanned_at"],
            "file_count": int(row["last_scan_files"] or 0),
            "byte_count": int(row["last_scan_bytes"] or 0),
            "revision": int(row["metadata_revision"]),
            "scan_fingerprint_sha256": row["scan_fingerprint_sha256"],
        }
        summary["source"] = (
            {"kind": "configured_path", "source_root": str(row["source_root"])}
            if source_kind == "local"
            else {
                "kind": "managed_share",
                "share_id": str(row["bound_share_id"]),
                "relative_subpath": str(row["bound_relative_subpath"]),
            }
        )
        return summary

    @staticmethod
    def _request_sha256(payload: dict[str, Any]) -> str:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    @staticmethod
    def _source_identity(canonical_root: Path) -> str:
        metadata = canonical_root.stat()
        payload = json.dumps(
            {
                "canonical_root": str(canonical_root),
                "device": int(metadata.st_dev),
                "inode": int(metadata.st_ino),
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _inspect_source_root(self, source_root: str) -> tuple[str, str, str]:
        if not isinstance(source_root, str) or not source_root or "\x00" in source_root:
            raise LibraryPathInvalid("library source root is invalid")
        candidate = Path(source_root)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise LibraryPathInvalid("library source root is invalid")
        if not self._source_roots:
            raise LibraryPathInvalid("library source allowlist is empty")
        try:
            canonical = candidate.resolve(strict=True)
            allowed = tuple(root.resolve(strict=True) for root in self._source_roots)
            if not canonical.is_dir() or any(not root.is_dir() for root in allowed):
                raise LibraryPathInvalid("library source root is unavailable")
            if not any(
                canonical == root or canonical.is_relative_to(root) for root in allowed
            ):
                raise LibraryPathInvalid("library source root is outside the allowlist")
            identity = self._source_identity(canonical)
        except LibraryPathInvalid:
            raise
        except (OSError, RuntimeError, ValueError):
            raise LibraryPathInvalid("library source root is unavailable") from None
        locator = os.path.normpath(str(candidate))
        return locator, str(canonical), identity

    def _inspect_existing_library(self, row: dict[str, Any]) -> tuple[str, str]:
        if str(row.get("source_kind") or "local") == "network":
            try:
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    expected = catalog.get_library_share_binding_evidence(
                        str(row["id"])
                    )
                verified = self._managed_source_verifier.verify_library(
                    str(row["id"]), expected=expected
                )
                return (
                    str(verified.derived_root),
                    str(verified.evidence["source_identity_sha256"]),
                )
            except (CatalogError, ManagedSourceAdmissionError):
                raise ShareIdentityChanged() from None
        try:
            _locator, canonical, identity = self._inspect_source_root(
                str(row["source_root"])
            )
        except LibraryPathInvalid:
            raise LibrarySourceChanged("library source identity changed") from None
        stored_canonical = row.get("source_canonical_root")
        stored_identity = row.get("source_identity_sha256")
        if (stored_canonical is not None and str(stored_canonical) != canonical) or (
            stored_identity is not None and str(stored_identity) != identity
        ):
            raise LibrarySourceChanged("library source identity changed")
        return canonical, identity

    @staticmethod
    def _last_successful_scan(row: dict[str, Any]) -> tuple[object, object, object]:
        return (
            row.get("last_scan_files"),
            row.get("last_scan_bytes"),
            row.get("last_scanned_at"),
        )

    @staticmethod
    def _translate_catalog_error(exc: CatalogError) -> LibraryManagementError | None:
        code = str(exc).partition(":")[0]
        if code == "library_in_use":
            return LibraryInUse("library is referenced by immutable work")
        if code == "library_not_found":
            return LibraryNotFound("library was not found")
        if code == "library_already_exists":
            return LibraryAlreadyExists("library already exists")
        if code == "library_revision_conflict":
            return LibraryRevisionConflict("library revision changed")
        if code in {
            "library_state_conflict",
            "library_restore_required",
            "library_scan_disabled",
            "library_scan_running",
        }:
            return LibraryStateConflict("library state does not allow this operation")
        if code == "idempotency_conflict":
            return IdempotencyConflict("idempotency key conflicts with another request")
        return None

    async def list_libraries(self) -> list[dict[str, Any]]:
        return await _run_in_worker(self._list_libraries)

    def _list_libraries(self) -> list[dict[str, Any]]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            return [self._library_summary(row) for row in catalog.list_named_libraries()]

    async def get_library(self, library_id: str) -> dict[str, Any]:
        return await _run_in_worker(self._get_library, library_id)

    def _get_library(self, library_id: str) -> dict[str, Any]:
        try:
            with Catalog(self.application.paths.catalog_file) as catalog:
                return self._library_summary(catalog.get_named_library(library_id))
        except CatalogError as exc:
            translated = self._translate_catalog_error(exc)
            if translated is not None:
                raise translated from None
            raise

    def _atomic_library_mutation(
        self,
        *,
        actor: str,
        idempotency_key: str,
        action: str,
        target_id: str,
        request_sha256: str,
        mutate: Callable[[Catalog], Any],
    ) -> tuple[dict[str, Any], bool]:
        """Commit a mutation, receipt, event, and accepted audit as one unit."""

        try:
            with (
                RunLock(self.application.paths.lock_file),
                Catalog(self.application.paths.catalog_file) as catalog,
                catalog.transaction(),
            ):
                catalog.initialize()
                replay = catalog.management_idempotency_replay(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action=action,
                    target_id=target_id,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return dict(replay), True
                summary = self._library_summary(mutate(catalog))
                response = catalog.record_management_idempotency(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action=action,
                    target_id=target_id,
                    request_sha256=request_sha256,
                    response=summary,
                )
                response = json.loads(
                    json.dumps(
                        response,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                catalog.record_audit(
                    actor,
                    action,
                    "accepted",
                    f"request-{uuid.uuid4().hex}",
                    None,
                    {"library_id": summary["id"]},
                )
                return response, False
        except CatalogError as exc:
            translated = self._translate_catalog_error(exc)
            if translated is not None:
                raise translated from None
            raise

    async def create_library(
        self,
        library_id: str,
        display_name: str,
        source_root: str | None,
        *,
        source: Mapping[str, Any] | None = None,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        result, _replayed = await self.create_library_with_replay(
            library_id,
            display_name,
            source_root,
            source=source,
            actor=actor,
            idempotency_key=idempotency_key,
        )
        return result

    async def create_library_with_replay(
        self,
        library_id: str,
        display_name: str,
        source_root: str | None,
        *,
        source: Mapping[str, Any] | None = None,
        actor: str,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], bool]:
        return self._create_library(
            library_id, display_name, source_root, source, actor, idempotency_key
        )

    def _create_library(
        self,
        library_id: str,
        display_name: str,
        source_root: str | None,
        source: Mapping[str, Any] | None,
        actor: str,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], bool]:
        if (source_root is None) == (source is None):
            raise LibraryPathInvalid("exactly one library source is required")
        if source is None:
            source_payload = {"kind": "configured_path", "source_root": source_root}
            request_payload = {
                "display_name": display_name,
                "library_id": library_id,
                "source_root": source_root,
            }
        else:
            source_payload = dict(source)
            request_payload = {
                "display_name": display_name,
                "library_id": library_id,
                "source": source_payload,
            }
        request_sha256 = self._request_sha256(request_payload)
        with self._library_mutation_lock:
            if source_payload.get("kind") == "managed_share":
                if set(source_payload) != {"kind", "share_id", "relative_subpath"}:
                    raise LibraryPathInvalid("library source contract is invalid")
                try:
                    subpath = normalize_managed_source_subpath(
                        source_payload["relative_subpath"]
                    )
                    verified = self._managed_source_verifier.verify_candidate(
                        str(source_payload["share_id"]), subpath
                    )
                except (KeyError, ManagedSourceAdmissionError, ValidationError):
                    raise ShareIdentityChanged() from None

                def create_network(catalog: Catalog):
                    catalog.add_named_network_library(
                        library_id,
                        display_name,
                        str(verified.derived_root),
                        verified.evidence["source_identity_sha256"],
                        verified.evidence["share_id"],
                        subpath,
                        expected_share_revision=verified.evidence["resource_revision"],
                        binding_evidence=verified.evidence,
                    )
                    return catalog.get_named_library(library_id)

                return self._atomic_library_mutation(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action="library.create",
                    target_id=library_id,
                    request_sha256=request_sha256,
                    mutate=create_network,
                )

            if (
                set(source_payload) != {"kind", "source_root"}
                or source_payload.get("kind") != "configured_path"
            ):
                raise LibraryPathInvalid("library source contract is invalid")
            configured_root = source_payload.get("source_root")
            if not isinstance(configured_root, str):
                raise LibraryPathInvalid("library source root is invalid")

            def create(catalog: Catalog):
                locator, canonical, identity = self._inspect_source_root(
                    configured_root
                )
                catalog.add_named_library(
                    library_id,
                    display_name,
                    locator,
                    canonical,
                    identity,
                )
                return catalog.get_named_library(library_id)

            return self._atomic_library_mutation(
                actor=actor,
                idempotency_key=idempotency_key,
                action="library.create",
                target_id=library_id,
                request_sha256=request_sha256,
                mutate=create,
            )

    def start_library_scan(
        self,
        library_id: str,
        *,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Admit a daemon-owned source scan and return before source traversal."""

        with self._library_mutation_lock:
            summary, replayed, admitted = self._admit_library_scan(
                library_id, actor, idempotency_key
            )
            if replayed:
                return self._library_summary(
                    self.application.get_named_library(library_id)
                )
            assert admitted is not None
            admitted_id, expected_identity, previous_scan, evidence, lease_id = admitted
            thread = threading.Thread(
                target=self._background_library_scan,
                args=(
                    admitted_id,
                    expected_identity,
                    previous_scan,
                    evidence,
                    lease_id,
                ),
                name=f"lto-library-scan-{admitted_id.casefold()}",
                daemon=True,
            )
            with self._scan_threads_lock:
                self._scan_threads.add(thread)
            self._notify_library_change(summary)
            thread.start()
            return summary

    def _admit_library_scan(
        self,
        library_id: str,
        actor: str,
        idempotency_key: str,
    ) -> tuple[
        dict[str, Any],
        bool,
        tuple[
            str,
            tuple[str, str],
            tuple[object, object, object],
            dict[str, Any] | None,
            str | None,
        ]
        | None,
    ]:
        request_sha256 = self._request_sha256({"library_id": library_id.casefold()})
        lease_id: str | None = None
        evidence: dict[str, Any] | None = None
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            inspected_row = dict(catalog.get_named_library(library_id))
            previous_scan = self._last_successful_scan(inspected_row)
            if str(inspected_row.get("source_kind") or "local") == "network":
                binding = catalog.get_library_share_binding(str(inspected_row["id"]))
                lease_id = catalog.acquire_managed_source_lease(
                    str(binding["share_id"]),
                    consumer_kind="scan",
                    consumer_id=str(inspected_row["id"]),
                    owner_id=self._share_owner_id,
                    daemon_generation=0,
                )
            else:
                binding = None
        try:
            if binding is not None:
                verified = self._managed_source_verifier.verify_library(
                    str(inspected_row["id"])
                )
                expected_identity = (
                    str(verified.derived_root),
                    str(verified.evidence["source_identity_sha256"]),
                )
                evidence = verified.evidence
            else:
                expected_identity = self._inspect_existing_library(inspected_row)
        except (LibraryManagementError, ManagedSourceAdmissionError):
            if lease_id is not None:
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.release_managed_source_lease(
                        lease_id,
                        owner_id=self._share_owner_id,
                        daemon_generation=0,
                    )
            if binding is not None:
                raise ShareIdentityChanged() from None
            with (
                RunLock(self.application.paths.lock_file),
                Catalog(self.application.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                catalog.fail_named_library_scan(
                    str(inspected_row["id"]),
                    invalidate_ready_plans=True,
                    previous_scan=previous_scan,
                )
            raise

        admitted: list[
            tuple[
                str,
                tuple[str, str],
                tuple[object, object, object],
                dict[str, Any] | None,
                str | None,
            ]
        ] = []

        def start(catalog: Catalog):
            row = dict(catalog.get_named_library(library_id))
            if (
                str(row["id"]).casefold() != str(inspected_row["id"]).casefold()
                or self._last_successful_scan(row) != previous_scan
                or (
                    evidence is not None
                    and catalog.get_library_share_binding(str(row["id"])) != binding
                )
            ):
                raise CatalogError("managed_source_evidence_changed")
            running = catalog.start_named_library_scan(
                str(row["id"]),
                managed_source_lease_id=lease_id,
                managed_source_evidence=evidence,
            )
            admitted.append(
                (
                    str(row["id"]),
                    expected_identity,
                    previous_scan,
                    evidence,
                    lease_id,
                )
            )
            return running

        try:
            summary, replayed = self._atomic_library_mutation(
                actor=actor,
                idempotency_key=idempotency_key,
                action="library.scan",
                target_id=library_id,
                request_sha256=request_sha256,
                mutate=start,
            )
        except LibrarySourceChanged:
            with (
                RunLock(self.application.paths.lock_file),
                Catalog(self.application.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                current = dict(catalog.get_named_library(library_id))
                catalog.fail_named_library_scan(
                    str(current["id"]),
                    invalidate_ready_plans=True,
                    previous_scan=self._last_successful_scan(current),
                )
            raise
        except Exception:
            if lease_id is not None:
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    try:
                        catalog.release_managed_source_lease(
                            lease_id,
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    except CatalogError:
                        pass
            raise
        if replayed and lease_id is not None:
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.release_managed_source_lease(
                    lease_id,
                    owner_id=self._share_owner_id,
                    daemon_generation=0,
                )
        return summary, replayed, None if replayed else admitted[0]

    def _background_library_scan(
        self,
        library_id: str,
        expected_identity: tuple[str, str],
        previous_scan: tuple[object, object, object],
        evidence: dict[str, Any] | None = None,
        lease_id: str | None = None,
    ) -> None:
        try:
            try:
                row = self.application.scan_named_library(
                    library_id,
                    expected_source_identity=expected_identity,
                    min_age_seconds=self._min_age_seconds,
                    buffer_bytes=self._buffer_bytes,
                    managed_source_evidence=evidence,
                    managed_source_lease_id=lease_id,
                    reverify_managed_source=(
                        None
                        if evidence is None
                        else lambda: self._reverify_managed_library_identity(
                            library_id, evidence
                        )
                    ),
                )
            except (CatalogError, OSError, RuntimeError, ValidationError):
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    current = dict(catalog.get_named_library(library_id))
                try:
                    changed = (
                        self._inspect_existing_library(current) != expected_identity
                    )
                except (LibrarySourceChanged, ShareIdentityChanged):
                    changed = True
                with (
                    RunLock(self.application.paths.lock_file),
                    Catalog(self.application.paths.catalog_file) as catalog,
                ):
                    catalog.initialize()
                    row = dict(
                        catalog.fail_named_library_scan(
                            library_id,
                            invalidate_ready_plans=changed,
                            previous_scan=previous_scan,
                        )
                    )
                    if lease_id is not None:
                        try:
                            catalog.release_managed_source_lease(
                                lease_id,
                                owner_id=self._share_owner_id,
                                daemon_generation=0,
                            )
                        except CatalogError:
                            pass
            self._notify_library_change(self._library_summary(row))
        finally:
            current_thread = threading.current_thread()
            with self._scan_threads_lock:
                self._scan_threads.discard(current_thread)

    def boundary_dispatcher(self, daemon_generation: int):
        """Compose boundary refresh with the same job-pinned source verifiers."""
        from .boundary_coordinator import BoundaryReplanCoordinator
        from .boundary_dispatcher import BoundaryDispatcher
        from .boundary_sources import BoundarySourceProvider

        def catalog_factory():
            return Catalog(self.application.paths.catalog_file)

        with catalog_factory() as catalog, catalog.transaction():
            owner = catalog.current_daemon_fence()
            if owner is None or owner.generation != daemon_generation:
                raise CatalogError("boundary_owner_changed")
            catalog.activate_boundary_replanning()
        return BoundaryDispatcher(
            catalog_factory,
            daemon_generation=daemon_generation,
            coordinator=BoundaryReplanCoordinator(
                catalog_factory,
                daemon_generation=daemon_generation,
                source_context=BoundarySourceProvider(
                    catalog_factory,
                    self._share_owner_id,
                    self._inspect_existing_library,
                    self._reverify_managed_library_identity,
                ),
            ),
        )

    def _reverify_managed_library_identity(
        self, library_id: str, evidence: Mapping[str, Any]
    ) -> tuple[str, str]:
        try:
            verified = self._managed_source_verifier.verify_library(
                library_id, expected=evidence
            )
            return (
                str(verified.derived_root),
                str(verified.evidence["source_identity_sha256"]),
            )
        except ManagedSourceAdmissionError:
            raise ShareIdentityChanged() from None

    def verify_cassette_source_library(
        self, candidate: SequenceCandidate, library: dict[str, Any]
    ) -> tuple[str, str]:
        """Metadata-only checkpoint verification against the cassette's source pin."""
        if not bool(library.get("enabled", True)) or library.get("status", "active") != "active":
            raise LibraryStateConflict("source library is not active")
        if str(library.get("source_kind") or "local") != "network":
            return self._inspect_existing_library(library)
        with Catalog(self.application.paths.catalog_file) as catalog:
            row = catalog.connection.execute(
                "SELECT evidence.evidence_json FROM automatic_cassette_share_evidence evidence "
                "WHERE evidence.job_id=? AND evidence.cassette_sequence=? "
                "AND evidence.library_id=? COLLATE NOCASE AND evidence.creation_plan_id=("
                "SELECT creation_plan_id FROM automatic_cassette_share_evidence_sets "
                "WHERE job_id=? AND cassette_sequence=? ORDER BY rowid DESC LIMIT 1)",
                (candidate.job_id, candidate.cassette_sequence, library["id"],
                 candidate.job_id, candidate.cassette_sequence),
            ).fetchone()
        if row is None:
            raise ShareIdentityChanged()
        return self._reverify_managed_library_identity(
            str(library["id"]), json.loads(row["evidence_json"])
        )

    def admit_job_managed_sources(
        self, job_id: str, operation_id: str, daemon_generation: int
    ) -> tuple[str, ...]:
        """Lease, reverify and persist every managed source before worker I/O."""

        leases: dict[str, str] = {}
        evidence_by_library: dict[str, dict[str, Any]] = {}
        try:
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                fence = catalog.connection.execute(
                    "SELECT 1 FROM managed_source_job_fences WHERE job_id=?",
                    (job_id,),
                ).fetchone()
                if fence is not None:
                    raise ShareIdentityChanged()
                managed_library_ids = {
                    str(row["library_id"]).casefold()
                    for row in catalog.connection.execute(
                        "SELECT link.library_id FROM automatic_job_libraries AS link "
                        "JOIN libraries AS library ON library.id=link.library_id "
                        "COLLATE NOCASE WHERE link.job_id=? "
                        "AND library.source_kind='network'",
                        (job_id,),
                    )
                }
                job_evidence_ids = {
                    str(row["library_id"]).casefold()
                    for row in catalog.connection.execute(
                        "SELECT library_id FROM automatic_job_share_evidence "
                        "WHERE job_id=?",
                        (job_id,),
                    )
                }
                if managed_library_ids != job_evidence_ids:
                    raise ShareIdentityChanged()
                operation = catalog.connection.execute(
                    "SELECT job_id,cassette_sequence,state FROM daemon_operations "
                    "WHERE id=?",
                    (operation_id,),
                ).fetchone()
                if (
                    operation is None
                    or str(operation["job_id"]).casefold() != job_id.casefold()
                    or operation["state"] not in {"running", "recovery_required"}
                ):
                    raise ShareIdentityChanged()
                cassette_sequence = operation["cassette_sequence"]
                cassette_library_ids = {
                    str(row["library_id"]).casefold()
                    for row in catalog.connection.execute(
                        "SELECT DISTINCT item.library_id "
                        "FROM automatic_cassette_items AS item "
                        "JOIN libraries AS library ON library.id=item.library_id "
                        "COLLATE NOCASE WHERE item.job_id=? AND item.sequence=? "
                        "AND library.source_kind='network'",
                        (job_id, cassette_sequence),
                    )
                }
                latest_set = catalog.connection.execute(
                    "SELECT creation_plan_id FROM "
                    "automatic_cassette_share_evidence_sets "
                    "WHERE job_id=? AND cassette_sequence=? "
                    "ORDER BY rowid DESC LIMIT 1",
                    (job_id, cassette_sequence),
                ).fetchone()
                if managed_library_ids and latest_set is None:
                    raise ShareIdentityChanged()
                rows = (
                    []
                    if latest_set is None
                    else catalog.connection.execute(
                        "SELECT evidence.library_id,evidence.evidence_json "
                        "FROM automatic_cassette_share_evidence AS evidence "
                        "WHERE evidence.job_id=? AND evidence.cassette_sequence=? "
                        "AND evidence.creation_plan_id=? COLLATE NOCASE "
                        "ORDER BY evidence.library_id COLLATE NOCASE",
                        (job_id, cassette_sequence, latest_set["creation_plan_id"]),
                    ).fetchall()
                )
                cassette_evidence_ids = {
                    str(row["library_id"]).casefold() for row in rows
                }
                if cassette_library_ids != cassette_evidence_ids:
                    raise ShareIdentityChanged()
            for row in rows:
                library_id = str(row["library_id"])
                folded_id = library_id.casefold()
                evidence = json.loads(str(row["evidence_json"]))
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    lease_id = catalog.acquire_managed_source_lease(
                        str(evidence["share_id"]),
                        consumer_kind="worker",
                        consumer_id="worker-"
                        + hashlib.sha256(
                            f"{operation_id}\0{folded_id}".encode()
                        ).hexdigest()[:32],
                        owner_id=self._share_owner_id,
                        daemon_generation=daemon_generation,
                    )
                leases[folded_id] = lease_id
                self._reverify_managed_library_identity(library_id, evidence)
                evidence_by_library[folded_id] = evidence
            if rows:
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    catalog.record_operation_share_evidence(
                        operation_id, evidence_by_library, leases
                    )
            return tuple(leases.values())
        except Exception:
            self.release_job_managed_sources(tuple(leases.values()), daemon_generation)
            raise

    def release_job_managed_sources(
        self, lease_ids: Sequence[str], daemon_generation: int
    ) -> None:
        for lease_id in lease_ids:
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                try:
                    catalog.release_managed_source_lease(
                        lease_id,
                        owner_id=self._share_owner_id,
                        daemon_generation=daemon_generation,
                    )
                except CatalogError:
                    pass

    def _notify_library_change(self, summary: dict[str, Any]) -> None:
        if self._on_library_change is not None:
            try:
                self._on_library_change(dict(summary))
            except RuntimeError:
                # The daemon event stream may close after a bounded shutdown wait.
                pass

    def recover_interrupted_library_scans(self) -> tuple[dict[str, Any], ...]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.recover_stale_managed_source_leases(
                owner_id=self._share_owner_id, daemon_generation=0
            )
            rows = catalog.recover_interrupted_named_library_scans()
        summaries = tuple(self._library_summary(row) for row in rows)
        for summary in summaries:
            self._notify_library_change(summary)
        return summaries

    def wait_for_library_scans(self, timeout_seconds: float) -> None:
        deadline = time.monotonic() + max(0.0, timeout_seconds)
        with self._scan_threads_lock:
            threads = tuple(self._scan_threads)
        for thread in threads:
            thread.join(max(0.0, deadline - time.monotonic()))

    async def update_library(
        self,
        library_id: str,
        *,
        display_name: str | None = None,
        source_root: str | None = None,
        source: Mapping[str, Any] | None = None,
        state: str | None = None,
        expected_revision: int | None = None,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        result, _replayed = await self.update_library_with_replay(
            library_id,
            display_name=display_name,
            source_root=source_root,
            source=source,
            state=state,
            expected_revision=expected_revision,
            actor=actor,
            idempotency_key=idempotency_key,
        )
        return result

    async def update_library_with_replay(
        self,
        library_id: str,
        *,
        display_name: str | None = None,
        source_root: str | None = None,
        source: Mapping[str, Any] | None = None,
        state: str | None = None,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        return self._update_library(
            library_id,
            display_name,
            source_root,
            source,
            state,
            expected_revision,
            actor,
            idempotency_key,
        )

    def _update_library(
        self,
        library_id: str,
        display_name: str | None,
        source_root: str | None,
        source: Mapping[str, Any] | None,
        state: str | None,
        expected_revision: int | None,
        actor: str,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], bool]:
        if source_root is not None and source is not None:
            raise LibraryPathInvalid("library source is ambiguous")
        configured_root = source_root
        managed_source: dict[str, Any] | None = None
        if source is None:
            request_payload = {
                "display_name": display_name,
                "expected_revision": expected_revision,
                "library_id": library_id,
                "source_root": source_root,
                "state": state,
            }
        else:
            source_payload = dict(source)
            request_payload = {
                "display_name": display_name,
                "expected_revision": expected_revision,
                "library_id": library_id,
                "source": source_payload,
                "state": state,
            }
            if source_payload.get("kind") == "configured_path":
                if set(source_payload) != {"kind", "source_root"} or not isinstance(
                    source_payload.get("source_root"), str
                ):
                    raise LibraryPathInvalid("library source contract is invalid")
                configured_root = str(source_payload["source_root"])
            elif source_payload.get("kind") == "managed_share":
                if set(source_payload) != {"kind", "share_id", "relative_subpath"}:
                    raise LibraryPathInvalid("library source contract is invalid")
                try:
                    subpath = normalize_managed_source_subpath(
                        source_payload["relative_subpath"]
                    )
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        row = dict(catalog.get_named_library(library_id))
                        binding = catalog.get_library_share_binding(library_id)
                        expected = catalog.get_library_share_binding_evidence(
                            library_id
                        )
                    if (
                        str(row.get("source_kind") or "local") != "network"
                        or str(binding["share_id"]).casefold()
                        != str(source_payload["share_id"]).casefold()
                        or str(binding["relative_subpath"]) != subpath
                    ):
                        raise LibraryStateConflict(library_id)
                    self._managed_source_verifier.verify_library(
                        library_id, expected=expected
                    )
                    managed_source = source_payload
                except LibraryStateConflict:
                    raise
                except (
                    CatalogError,
                    KeyError,
                    ManagedSourceAdmissionError,
                    ValidationError,
                ):
                    raise ShareIdentityChanged() from None
            else:
                raise LibraryPathInvalid("library source contract is invalid")
        request_sha256 = self._request_sha256(request_payload)
        with self._library_mutation_lock:

            def update(catalog: Catalog):
                source_values = (
                    None
                    if configured_root is None
                    else self._inspect_source_root(configured_root)
                )
                current = catalog.get_named_library(library_id)
                if (
                    source_values is not None
                    and str(current["source_kind"] or "local") == "network"
                ):
                    raise CatalogError(f"library_state_conflict:{library_id}")
                if (
                    managed_source is not None
                    and str(current["source_kind"] or "local") != "network"
                ):
                    raise CatalogError(f"library_state_conflict:{library_id}")
                return catalog.update_named_library(
                    library_id,
                    display_name=display_name,
                    source_root=None if source_values is None else source_values[0],
                    source_canonical_root=(
                        None if source_values is None else source_values[1]
                    ),
                    source_identity_sha256=(
                        None if source_values is None else source_values[2]
                    ),
                    requested_state=state,
                    expected_revision=expected_revision,
                )

            return self._atomic_library_mutation(
                actor=actor,
                idempotency_key=idempotency_key,
                action="library.update",
                target_id=library_id,
                request_sha256=request_sha256,
                mutate=update,
            )

    async def retire_library(
        self,
        library_id: str,
        *,
        typed_library_id: str,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        result, _replayed = await self.retire_library_with_replay(
            library_id,
            typed_library_id=typed_library_id,
            expected_revision=expected_revision,
            actor=actor,
            idempotency_key=idempotency_key,
        )
        return result

    async def retire_library_with_replay(
        self,
        library_id: str,
        *,
        typed_library_id: str,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> tuple[dict[str, Any], bool]:
        return self._retire_library(
            library_id,
            typed_library_id,
            expected_revision,
            actor,
            idempotency_key,
        )

    def _retire_library(
        self,
        library_id: str,
        typed_library_id: str,
        expected_revision: int | None,
        actor: str,
        idempotency_key: str,
    ) -> tuple[dict[str, Any], bool]:
        if not secrets.compare_digest(library_id, typed_library_id):
            raise LibraryConfirmationMismatch("library confirmation does not match")
        request_sha256 = self._request_sha256(
            {
                "expected_revision": expected_revision,
                "library_id": library_id,
                "typed_library_id": typed_library_id,
            }
        )
        with self._library_mutation_lock:
            return self._atomic_library_mutation(
                actor=actor,
                idempotency_key=idempotency_key,
                action="library.retire",
                target_id=library_id,
                request_sha256=request_sha256,
                mutate=lambda catalog: catalog.retire_named_library(
                    library_id, expected_revision=expected_revision
                ),
            )

    async def scan_library(
        self,
        library_id: str,
        *,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return await _run_in_worker(
            self._scan_library,
            library_id,
            actor,
            idempotency_key,
        )

    def _scan_library(
        self,
        library_id: str,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        with self._library_mutation_lock:
            _summary, replayed, admitted = self._admit_library_scan(
                library_id, actor, idempotency_key
            )
        if replayed:
            return self._library_summary(self.application.get_named_library(library_id))
        assert admitted is not None
        admitted_id, expected_identity, previous_scan, evidence, lease_id = admitted
        try:
            scanned = self.application.scan_named_library(
                admitted_id,
                expected_source_identity=expected_identity,
                min_age_seconds=self._min_age_seconds,
                buffer_bytes=self._buffer_bytes,
                managed_source_evidence=evidence,
                managed_source_lease_id=lease_id,
                reverify_managed_source=(
                    None
                    if evidence is None
                    else lambda: self._reverify_managed_library_identity(
                        admitted_id, evidence
                    )
                ),
            )
        except (LibrarySourceChanged, LibraryPathInvalid, ShareIdentityChanged):
            with (
                RunLock(self.application.paths.lock_file),
                Catalog(self.application.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                catalog.fail_named_library_scan(
                    admitted_id,
                    invalidate_ready_plans=True,
                    previous_scan=previous_scan,
                )
                if lease_id is not None:
                    try:
                        catalog.release_managed_source_lease(
                            lease_id,
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    except CatalogError:
                        pass
            raise LibrarySourceChanged("library source identity changed") from None
        except (CatalogError, OSError, RuntimeError, ValidationError):
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                current = dict(catalog.get_named_library(admitted_id))
            try:
                source_changed = (
                    self._inspect_existing_library(current) != expected_identity
                )
            except (LibrarySourceChanged, ShareIdentityChanged):
                source_changed = True
            with (
                RunLock(self.application.paths.lock_file),
                Catalog(self.application.paths.catalog_file) as catalog,
            ):
                catalog.initialize()
                catalog.fail_named_library_scan(
                    admitted_id,
                    invalidate_ready_plans=source_changed,
                    previous_scan=previous_scan,
                )
                if lease_id is not None:
                    try:
                        catalog.release_managed_source_lease(
                            lease_id,
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    except CatalogError:
                        pass
            if source_changed:
                raise LibrarySourceChanged("library source identity changed") from None
            raise LibraryManagementError("library scan failed") from None
        return self._library_summary(scanned)

    async def create_plan(
        self,
        library_ids: str | Sequence[str],
        *,
        media_key: str,
        creator: str,
        kind: str = "create",
        plan_id: str | None = None,
        base_job_id: str | None = None,
        base_job_revision: int | None = None,
        base_job_fingerprint_sha256: str | None = None,
    ) -> dict[str, Any]:
        """Persist building state, then freeze and publish one planner pass."""

        authority = self.initialize_application_settings()
        settings_snapshot = self._legacy_settings_from_authority(authority)
        selected = tuple(
            self.application._normalize_library_ids(  # noqa: SLF001 - app boundary
                library_ids if isinstance(library_ids, str) else list(library_ids)
            )
        )
        created = self._utc_now()
        expires = created + timedelta(hours=24)
        draft_id = plan_id or (
            "PLAN-" + created.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:8]
        )
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.create_job_plan_draft(
                plan_id=draft_id,
                kind=kind,  # type: ignore[arg-type]
                creator=creator,
                created_at=created.isoformat(),
                expires_at=expires.isoformat(),
                media_key=media_key,
                library_ids=selected,
                base_job_id=base_job_id,
                base_job_revision=base_job_revision,
                base_job_fingerprint_sha256=base_job_fingerprint_sha256,
            )

        try:
            # Yield after persisting `building` so another request can observe
            # the shared draft before this daemon-owned planner slice runs.
            await asyncio.sleep(0)
            source_identities: dict[str, tuple[str, str]] = {}
            managed_source_contexts: dict[str, dict[str, Any]] = {}
            for library_id in selected:
                library = await _run_in_worker(
                    self.application.get_named_library, library_id
                )
                folded_id = str(library["id"]).casefold()
                if str(library.get("source_kind") or "local") == "network":
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        expected = catalog.get_library_share_binding_evidence(
                            str(library["id"])
                        )
                        consumer_id = (
                            "plan-"
                            + hashlib.sha256(
                                f"{draft_id}\0{folded_id}".encode()
                            ).hexdigest()[:32]
                        )
                        lease_id = catalog.acquire_managed_source_lease(
                            str(expected["share_id"]),
                            consumer_kind="plan",
                            consumer_id=consumer_id,
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    try:
                        identity = self._reverify_managed_library_identity(
                            str(library["id"]), expected
                        )
                    except Exception:
                        with Catalog(self.application.paths.catalog_file) as catalog:
                            catalog.initialize()
                            catalog.release_managed_source_lease(
                                lease_id,
                                owner_id=self._share_owner_id,
                                daemon_generation=0,
                            )
                        raise
                    managed_source_contexts[folded_id] = {
                        "evidence": expected,
                        "lease_id": lease_id,
                        "reverify": lambda library_id=str(library["id"]), evidence=expected: (
                            self._reverify_managed_library_identity(
                                library_id, evidence
                            )
                        ),
                    }
                    source_identities[folded_id] = identity
                else:
                    source_identities[folded_id] = self._inspect_existing_library(
                        library
                    )
            frozen = await _run_in_worker(
                self.application.freeze_automatic_job_plan,
                list(selected),
                kind=kind,
                media_key=media_key,
                base_job_id=base_job_id,
                base_job_revision=base_job_revision,
                base_job_fingerprint_sha256=base_job_fingerprint_sha256,
                source_identities=source_identities,
                settings=settings_snapshot,
                application_settings_revision=int(authority["revision"]),
                content_verification_policy=str(
                    authority["content_verification_policy"]
                ),
                managed_source_contexts=managed_source_contexts,
                source_change_detection_policy=str(
                    authority["source_change_detection_policy"]
                ),
            )
            if managed_source_contexts:
                frozen["managed_source_leases"] = {
                    library_id: context["lease_id"]
                    for library_id, context in managed_source_contexts.items()
                }
            return await _run_in_worker(self._complete_plan, draft_id, frozen)
        except Exception as exc:
            if "managed_source_contexts" in locals():
                for context in managed_source_contexts.values():
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        try:
                            catalog.release_managed_source_lease(
                                str(context["lease_id"]),
                                owner_id=self._share_owner_id,
                                daemon_generation=0,
                            )
                        except CatalogError:
                            pass
            return await _run_in_worker(self._fail_plan, draft_id, exc)

    async def create_initial_plan(
        self,
        library_ids: Sequence[str],
        *,
        media_key: str,
        creator: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        return await self._create_plan_idempotently(
            library_ids=tuple(library_ids),
            media_key=require_ltfs_profile(media_key).key,
            creator=creator,
            idempotency_key=idempotency_key,
            kind="create",
        )

    async def _create_plan_idempotently(
        self,
        *,
        library_ids: tuple[str, ...],
        media_key: str,
        creator: str,
        idempotency_key: str,
        kind: str,
        base_job_id: str | None = None,
        base_job_revision: int | None = None,
        base_job_fingerprint_sha256: str | None = None,
    ) -> dict[str, Any]:
        request = {
            "base_job_fingerprint_sha256": base_job_fingerprint_sha256,
            "base_job_id": base_job_id,
            "base_job_revision": base_job_revision,
            "kind": kind,
            "library_ids": list(library_ids),
            "media_key": media_key,
        }
        request_sha256 = self._request_sha256(request)
        action = "job-plan.create"
        target_id = "job-plan"
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                replay = catalog.management_idempotency_replay(
                    actor=creator,
                    idempotency_key=idempotency_key,
                    action=action,
                    target_id=target_id,
                    request_sha256=request_sha256,
                )
            except CatalogError as exc:
                if str(exc) == "idempotency_conflict":
                    raise IdempotencyConflict(
                        "idempotency key conflicts with another request"
                    ) from None
                raise
        if replay is not None:
            replayed_plan = await self.get_plan(str(replay["plan_id"]))
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.record_audit(
                    creator,
                    action,
                    "accepted",
                    f"request-{uuid.uuid4().hex}",
                    None,
                    {"plan_id": replayed_plan["id"], "replayed": True},
                )
            return replayed_plan

        plan_id = (
            "PLAN-"
            + hashlib.sha256(
                b"lto-job-plan-idempotency-v1\0"
                + creator.encode("utf-8")
                + b"\0"
                + idempotency_key.encode("utf-8")
            ).hexdigest()[:24]
        )
        try:
            result = await self.create_plan(
                library_ids,
                media_key=media_key,
                creator=creator,
                kind=kind,
                plan_id=plan_id,
                base_job_id=base_job_id,
                base_job_revision=base_job_revision,
                base_job_fingerprint_sha256=base_job_fingerprint_sha256,
            )
        except CatalogError as exc:
            if not str(exc).startswith("job plan already exists"):
                raise
            result = await self.get_plan(plan_id)
            observed = {
                "base_job_fingerprint_sha256": result.get(
                    "base_job_fingerprint_sha256"
                ),
                "base_job_id": result.get("base_job_id"),
                "base_job_revision": result.get("base_job_revision"),
                "kind": result["kind"],
                "library_ids": list(result["library_ids"]),
                "media_key": result["media_key"],
            }
            if observed != request:
                raise IdempotencyConflict(
                    "idempotency key conflicts with another request"
                ) from None

        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                with catalog.transaction():
                    catalog.record_management_idempotency(
                        actor=creator,
                        idempotency_key=idempotency_key,
                        action=action,
                        target_id=target_id,
                        request_sha256=request_sha256,
                        response={"plan_id": plan_id},
                    )
                    catalog.record_audit(
                        creator,
                        action,
                        "accepted",
                        f"request-{uuid.uuid4().hex}",
                        None,
                        {"plan_id": plan_id, "replayed": False},
                    )
            except CatalogError as exc:
                if str(exc) == "idempotency_conflict":
                    raise IdempotencyConflict(
                        "idempotency key conflicts with another request"
                    ) from None
                raise
        return result

    def _complete_plan(self, plan_id: str, frozen: dict[str, Any]) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            plan = catalog.complete_job_plan_draft(plan_id, frozen)
            policy = catalog.get_job_plan_policy_snapshot(plan_id)
            plan["capacity_reserve_bytes"] = int(policy["capacity_reserve_bytes"])
            return plan

    def _fail_plan(self, plan_id: str, exc: Exception) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            try:
                failure_code = getattr(exc, "code", "plan_failed")
                if not isinstance(failure_code, str) or not re.fullmatch(
                    r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", failure_code
                ):
                    failure_code = "plan_failed"
                return catalog.fail_job_plan_draft(
                    plan_id,
                    failure_code,
                    "The job plan could not be built from current source evidence.",
                )
            except CatalogError:
                return catalog.get_job_plan(plan_id)

    async def get_plan(self, plan_id: str) -> dict[str, Any]:
        return await _run_in_worker(self._get_plan, plan_id)

    def _get_plan(self, plan_id: str) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.cleanup_expired_job_plans(self._utc_now().isoformat())
            plan = catalog.get_job_plan(plan_id)
            if plan["state"] != "ready":
                return plan
            policy = catalog.get_job_plan_policy_snapshot(plan_id)
            plan["capacity_reserve_bytes"] = int(policy["capacity_reserve_bytes"])
            return plan

    @staticmethod
    def _page_offset(cursor: str | None, limit: int) -> int:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 200
        ):
            raise ValueError("page limit must be between 1 and 200")
        if cursor is None:
            return 0
        if (
            not isinstance(cursor, str)
            or not cursor.isascii()
            or not cursor.isdecimal()
        ):
            raise ValueError("page cursor is invalid")
        offset = int(cursor)
        if offset < 0 or offset > 1_000_000_000:
            raise ValueError("page cursor is invalid")
        return offset

    @staticmethod
    def _job_checkpoint(job: Any, current_phase: str | None = None) -> str:
        if current_phase:
            return current_phase
        return {
            "planned": "saved",
            "waiting_media": "waiting_media",
            "formatting": "formatting_media",
            "mounting": "mounting",
            "writing": "writing",
            "unmounting": "unmounting",
            "paused": "paused",
            "completed": "completed",
            "failed": "failed",
        }.get(str(job["status"]), str(job["status"]))

    @staticmethod
    def _job_capabilities(
        job: Any, *, imported: bool, retired: bool = False
    ) -> dict[str, bool]:
        if retired:
            return {
                "start": False,
                "resume": False,
                "pause": False,
                "rename": False,
                "extend": False,
                "reserve_label": False,
                "retire": False,
                "scan_now": False,
                "reset_failed_cassette": False,
            }
        state = str(job["status"])
        terminal = state in {"completed", "failed"}
        return {
            "start": not imported and state == "planned",
            "resume": state in {"paused", "waiting_media", "failed"},
            "pause": state
            in {"waiting_media", "formatting", "mounting", "writing", "unmounting"},
            "rename": not imported and not terminal,
            "extend": not imported
            and state in {"planned", "paused", "waiting_media", "completed", "failed"},
            "reserve_label": not imported
            and state in {"planned", "paused", "waiting_media", "completed"},
            "retire": not imported
            and state in {"planned", "waiting_media", "paused", "completed", "failed"},
            "scan_now": not imported and state == "completed",
            "reset_failed_cassette": False,
        }

    @staticmethod
    def _cassette_projection(cassette: Any) -> dict[str, Any]:
        operation = str(cassette["operation"])
        return {
            "sequence": int(cassette["sequence"]),
            "physical_label": str(cassette["physical_label"]),
            "objects": int(cassette["planned_files"]),
            "bytes": int(cassette["planned_bytes"]),
            "allocation_bytes": int(cassette["planned_bytes"]),
            "capacity_utilization": 0.0,
            "format_required": operation == "format",
            "operation": operation,
            "state": str(cassette["status"]),
            "error": cassette["error"],
        }

    @staticmethod
    def _incremental_policy_projection(policy: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(policy)
        result.pop("updated_at", None)
        latest = result.get("latest_event")
        if latest is not None:
            result["latest_event"] = {
                key: latest[key]
                for key in (
                    "state",
                    "recorded_at",
                    "discovered_files",
                    "discovered_bytes",
                    "required_additional_labels",
                    "plan_id",
                    "plan_digest_sha256",
                    "error_code",
                )
            }
        return result

    @classmethod
    def _sequence_status_projection(cls, catalog: Catalog, job: Any) -> dict[str, Any]:
        job_id = str(job["id"])
        cassettes = catalog.list_automatic_cassettes(job_id)
        next_cassette = catalog.next_automatic_cassette(job_id)
        format_rows = tuple(
            row
            for row in cassettes
            if str(row["status"]) in {"pending", "waiting_media"}
            and str(row["operation"]) == "format"
        )
        sequence_authorized = not format_rows or all(
            catalog.format_sequence_authorization(job_id, int(row["sequence"]))
            is not None
            for row in format_rows
        )
        latest_epoch = catalog.latest_layout_epoch(job_id)
        return {
            "authorization_state": (
                "not_required"
                if not format_rows
                else "authorized" if sequence_authorized else "pending"
            ),
            "layout_fingerprint_sha256": str(
                latest_epoch["layout_fingerprint_sha256"]
            ),
            "next_expected_sequence": (
                None if next_cassette is None else int(next_cassette["sequence"])
            ),
            "next_expected_label": (
                None if next_cassette is None else str(next_cassette["physical_label"])
            ),
            "waiting_for_media": str(job["status"]) == "waiting_media",
        }

    @classmethod
    def _job_projection(cls, catalog: Catalog, job: Any) -> dict[str, Any]:
        job_id = str(job["id"])
        libraries = tuple(
            str(row["library_id"])
            for row in catalog.list_automatic_job_libraries(job_id)
        )
        cassettes = catalog.list_automatic_cassettes(job_id)
        manifest_totals = catalog.connection.execute(
            "SELECT COUNT(*) AS objects,COALESCE(SUM(size),0) AS bytes FROM ("
            "SELECT size FROM automatic_cassette_items WHERE job_id=? "
            "UNION ALL SELECT size FROM job_manifest_history WHERE job_id=?)",
            (job_id, job_id),
        ).fetchone()
        total_objects = int(manifest_totals["objects"])
        total_bytes = int(manifest_totals["bytes"])
        historical_progress = catalog.connection.execute(
            "SELECT COUNT(*) AS objects,COALESCE(SUM(size),0) AS bytes "
            "FROM job_manifest_history WHERE job_id=?",
            (job_id,),
        ).fetchone()
        completed_objects = int(historical_progress["objects"]) + sum(
            int(row["copied_files"])
            for row in cassettes
            if row["status"] != "completed"
            or not catalog.connection.execute(
                "SELECT 1 FROM job_manifest_history WHERE job_id=? "
                "AND cassette_sequence=? LIMIT 1",
                (job_id, int(row["sequence"])),
            ).fetchone()
        )
        completed_bytes = int(historical_progress["bytes"]) + sum(
            int(row["copied_bytes"])
            for row in cassettes
            if row["status"] != "completed"
            or not catalog.connection.execute(
                "SELECT 1 FROM job_manifest_history WHERE job_id=? "
                "AND cassette_sequence=? LIMIT 1",
                (job_id, int(row["sequence"])),
            ).fetchone()
        )
        completed_cassettes = sum(row["status"] == "completed" for row in cassettes)
        imported = catalog.get_import_policy(job_id) is not None
        management_state = catalog.job_management_state(job_id)
        retired = management_state["retired_at"] is not None
        fenced = (
            catalog.connection.execute(
                "SELECT 1 FROM managed_source_job_fences WHERE job_id=?", (job_id,)
            ).fetchone()
            is not None
        )
        operation = catalog.connection.execute(
            "SELECT phase FROM daemon_operations WHERE job_id=? "
            "ORDER BY started_at DESC,id DESC LIMIT 1",
            (job_id,),
        ).fetchone()
        checkpoint = str(management_state["current_checkpoint"])
        if operation is not None and operation["phase"] is not None:
            checkpoint = str(operation["phase"])
        last_activity = next(
            (
                value
                for value in (
                    job["completed_at"],
                    job["started_at"],
                    job["created_at"],
                )
                if value is not None
            ),
            str(job["created_at"]),
        )
        cassette_rows = tuple(cls._cassette_projection(row) for row in cassettes)
        next_cassette = catalog.next_automatic_cassette(job_id)
        sequence_status = cls._sequence_status_projection(catalog, job)
        capabilities = cls._job_capabilities(job, imported=imported, retired=retired)
        failed_cassettes = tuple(
            row for row in cassettes if str(row["status"]) == "failed"
        )
        capabilities["reset_failed_cassette"] = bool(
            not imported
            and not retired
            and not fenced
            and str(job["status"]) == "failed"
            and len(failed_cassettes) == 1
        )
        if capabilities["reset_failed_cassette"]:
            capabilities["resume"] = False
        if fenced:
            capabilities["start"] = False
            capabilities["resume"] = False
        try:
            incremental = cls._incremental_policy_projection(
                catalog.incremental_policy(job_id)
            )
        except CatalogError:
            incremental = None
        boundary_refresh = boundary_refresh_status(
            catalog.connection,
            job_id,
            paused=(
                str(job["status"]) == "paused"
                or management_state["pause_requested_at"] is not None
            ),
        )
        return {
            "id": job_id,
            "display_name": str(job["display_name"]),
            "state": "retired" if retired else str(job["status"]),
            "library_ids": libraries,
            "media_profile": str(job["media_key"]),
            "cassette_progress": {
                "completed": completed_cassettes,
                "total": len(cassettes),
            },
            "manifest_totals": {"objects": total_objects, "bytes": total_bytes},
            "progress": {
                "objects_completed": completed_objects,
                "objects_total": total_objects,
                "bytes_completed": completed_bytes,
                "bytes_total": total_bytes,
            },
            "created_at": str(job["created_at"]),
            "last_activity_at": str(last_activity),
            "current_checkpoint": checkpoint,
            "last_error": job["last_error"],
            "source_check": NativeSourceCheckpoint.latest(catalog, job_id),
            "catalog_cleanup": cls._catalog_cleanup_projection(catalog, job_id),
            "boundary_refresh": boundary_refresh,
            "imported": imported,
            "revision": int(management_state["revision"]),
            "pause_requested": management_state["pause_requested_at"] is not None,
            "pause_acknowledged": management_state["pause_acknowledged_at"] is not None,
            "resumable": capabilities["resume"],
            "requires_format_confirmation": (
                sequence_status["authorization_state"] == "pending"
            ),
            "capabilities": capabilities,
            "cassettes": cassette_rows,
            "incremental": incremental,
        }

    @staticmethod
    def _catalog_cleanup_projection(catalog: Catalog, job_id: str) -> dict | None:
        row = catalog.connection.execute(
            "SELECT payload_json FROM job_management_history "
            "WHERE job_id=? AND action='job.catalog_cleanup' ORDER BY id DESC LIMIT 1",
            (job_id,),
        ).fetchone()
        if row is None:
            return None
        report = json.loads(row["payload_json"])
        return {
            **report,
            "deleted_tape_count": len(report["deleted_tapes"]),
            "preserved_tape_count": len(report["preserved_tapes"]),
            "deleted_tapes": report["deleted_tapes"][:100],
            "preserved_tapes": report["preserved_tapes"][:100],
        }

    async def list_jobs(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        include_retired: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(include_retired, bool):
            raise ValueError("include_retired is invalid")
        return await _run_in_worker(self._list_jobs, limit, cursor, include_retired)

    def _list_jobs(
        self, limit: int, cursor: str | None, include_retired: bool
    ) -> dict[str, Any]:
        offset = self._page_offset(cursor, limit)
        with Catalog(self.application.paths.catalog_file) as catalog:
            rows = catalog.connection.execute(
                "SELECT * FROM automatic_jobs AS job WHERE NOT EXISTS("
                "SELECT 1 FROM deleted_automatic_job_tombstones AS deleted "
                "WHERE deleted.job_id=job.id COLLATE NOCASE) AND (? OR NOT EXISTS("
                "SELECT 1 FROM job_management_state AS state "
                "WHERE state.job_id=job.id COLLATE NOCASE "
                "AND state.retired_at IS NOT NULL)) "
                "ORDER BY created_at DESC,id DESC "
                "LIMIT ? OFFSET ?",
                (int(include_retired), limit + 1, offset),
            ).fetchall()
            items = [self._job_projection(catalog, row) for row in rows[:limit]]
            return {
                "items": items,
                "next_cursor": str(offset + limit) if len(rows) > limit else None,
                "current_job_id": catalog.current_job_id(),
            }

    async def get_job(self, job_id: str) -> dict[str, Any]:
        return await _run_in_worker(self._get_job, job_id)

    def _get_job(self, job_id: str) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            return self._job_projection(catalog, catalog.get_automatic_job(job_id))

    async def get_job_sequence_status(self, job_id: str) -> dict[str, Any]:
        return await _run_in_worker(self._get_job_sequence_status, job_id)

    def _get_job_sequence_status(self, job_id: str) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            return self._sequence_status_projection(
                catalog, catalog.get_automatic_job(job_id)
            )

    async def list_job_cassettes(
        self, job_id: str, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        return await _run_in_worker(self._list_job_cassettes, job_id, limit, cursor)

    def _list_job_cassettes(
        self, job_id: str, limit: int, cursor: str | None
    ) -> dict[str, Any]:
        offset = self._page_offset(cursor, limit)
        with Catalog(self.application.paths.catalog_file) as catalog:
            live = catalog.connection.execute(
                "SELECT 1 FROM automatic_jobs AS job WHERE job.id=? AND NOT EXISTS("
                "SELECT 1 FROM deleted_automatic_job_tombstones AS deleted "
                "WHERE deleted.job_id=job.id COLLATE NOCASE)",
                (job_id,),
            ).fetchone()
            if live is None:
                raise JobNotFound("job was not found")
            rows = catalog.connection.execute(
                "SELECT sequence,physical_label,planned_files,planned_bytes,operation,"
                "status,error "
                "FROM automatic_cassettes WHERE job_id=? ORDER BY sequence "
                "LIMIT ? OFFSET ?",
                (job_id, limit + 1, offset),
            ).fetchall()
        return {
            "items": tuple(self._cassette_projection(row) for row in rows[:limit]),
            "next_cursor": str(offset + limit) if len(rows) > limit else None,
        }

    async def list_job_manifest(
        self, job_id: str, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        return await _run_in_worker(self._list_job_manifest, job_id, limit, cursor)

    def _list_job_manifest(
        self, job_id: str, limit: int, cursor: str | None
    ) -> dict[str, Any]:
        offset = self._page_offset(cursor, limit)
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.get_automatic_job(job_id)
            rows = catalog.connection.execute(
                "SELECT cassette_sequence,item_sequence,library_id,relative_path,size,mtime_ns "
                "FROM (SELECT sequence AS cassette_sequence,item_sequence,library_id,"
                "relative_path,size,mtime_ns,2147483647 AS revision "
                "FROM automatic_cassette_items WHERE job_id=? "
                "UNION ALL SELECT cassette_sequence,item_sequence,library_id,"
                "relative_path,size,mtime_ns,revision FROM job_manifest_history "
                "WHERE job_id=?) ORDER BY cassette_sequence,revision,item_sequence "
                "LIMIT ? OFFSET ?",
                (job_id, job_id, limit + 1, offset),
            ).fetchall()
            return {
                "items": [dict(row) for row in rows[:limit]],
                "next_cursor": str(offset + limit) if len(rows) > limit else None,
            }

    async def list_job_history(
        self, job_id: str, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        return await _run_in_worker(self._list_job_history, job_id, limit, cursor)

    def _list_job_history(
        self, job_id: str, limit: int, cursor: str | None
    ) -> dict[str, Any]:
        offset = self._page_offset(cursor, limit)
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.get_automatic_job(job_id)
            rows = catalog.connection.execute(
                "SELECT id,occurred_at,action,payload_json,actor,checkpoint "
                "FROM job_management_history WHERE job_id=? COLLATE NOCASE "
                "ORDER BY id LIMIT ? OFFSET ?",
                (job_id, limit + 1, offset),
            ).fetchall()
            return {
                "items": [
                    {
                        "id": int(row["id"]),
                        "occurred_at": str(row["occurred_at"]),
                        "action": str(row["action"]),
                        "actor": str(row["actor"]),
                        "checkpoint": str(row["checkpoint"]),
                    }
                    for row in rows[:limit]
                ],
                "next_cursor": str(offset + limit) if len(rows) > limit else None,
            }

    @staticmethod
    def _translate_job_catalog_error(exc: CatalogError) -> JobManagementError | None:
        code = str(exc).partition(":")[0]
        if code in {"job_not_found", "Job automatico non trovato"}:
            return JobNotFound("job was not found")
        if code == "job_imported_frozen":
            return JobImportedFrozen("imported job policy is frozen")
        if code == "job_confirmation_mismatch":
            return JobConfirmationMismatch("job confirmation does not match")
        if code == "job_revision_conflict":
            return JobRevisionConflict("job revision changed")
        if code == "automatic_format_authorization_required":
            return AutomaticFormatAuthorizationRequired(
                "automatic formatting authorization is required"
            )
        if code in {
            "automatic_sequence_revision_conflict",
            "automatic_sequence_layout_conflict",
        }:
            return JobRevisionConflict("job revision or layout changed")
        if code == "automatic_sequence_job_not_found":
            return JobNotFound("job was not found")
        if code.startswith("automatic_sequence_"):
            return JobStateConflict("job state does not allow this operation")
        if code == "idempotency_conflict":
            return IdempotencyConflict("idempotency key conflicts with another request")
        if code.startswith("job_"):
            return JobStateConflict("job state does not allow this operation")
        return None

    def _atomic_job_mutation(
        self,
        *,
        actor: str,
        idempotency_key: str,
        action: str,
        job_id: str,
        request_sha256: str,
        mutate: Callable[[Catalog], Any],
        audit_action: str | None = None,
        audit_payload: Mapping[str, Any] | None = None,
        use_run_lock: bool = True,
    ) -> tuple[dict[str, Any], bool]:
        try:
            lock_context = (
                RunLock(self.application.paths.lock_file)
                if use_run_lock
                else nullcontext()
            )
            with (
                lock_context,
                Catalog(self.application.paths.catalog_file) as catalog,
                catalog.transaction(),
            ):
                catalog.initialize()
                replay = catalog.management_idempotency_replay(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action=action,
                    target_id=job_id,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return dict(replay), True
                mutate(catalog)
                summary = self._job_projection(
                    catalog, catalog.get_automatic_job(job_id)
                )
                state = catalog.job_management_state(job_id)
                catalog._job_history_tx(  # noqa: SLF001 - atomic catalog boundary
                    catalog.connection,
                    job_id,
                    actor,
                    action,
                    str(state["current_checkpoint"]),
                    {},
                )
                response = catalog.record_management_idempotency(
                    actor=actor,
                    idempotency_key=idempotency_key,
                    action=action,
                    target_id=job_id,
                    request_sha256=request_sha256,
                    response=summary,
                )
                response = json.loads(
                    json.dumps(
                        response,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    )
                )
                catalog.record_audit(
                    actor,
                    audit_action or action,
                    "accepted",
                    f"request-{uuid.uuid4().hex}",
                    None,
                    dict(audit_payload or {"job_id": job_id}),
                )
                return response, False
        except CatalogError as exc:
            translated = self._translate_job_catalog_error(exc)
            if translated is not None:
                raise translated from None
            raise

    async def rename_job(
        self,
        job_id: str,
        display_name: str,
        *,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        request_sha256 = self._request_sha256(
            {
                "display_name": display_name,
                "expected_revision": expected_revision,
                "job_id": job_id,
            }
        )
        result, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="job.rename",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=lambda catalog: catalog.rename_managed_job(
                job_id, display_name, expected_revision=expected_revision
            ),
        )
        return result

    async def reserve_job_labels(
        self,
        job_id: str,
        labels: Sequence[str],
        *,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
        authorize_automatic_formatting: bool = False,
    ) -> dict[str, Any]:
        normalized = tuple(str(label).strip().upper() for label in labels)
        request_sha256 = self._request_sha256(
            {
                "expected_revision": expected_revision,
                "job_id": job_id,
                "labels": list(normalized),
                "authorize_automatic_formatting": authorize_automatic_formatting,
            }
        )
        def reserve(catalog: Catalog) -> Any:
            if catalog.pending_boundary_replan_record(job_id) is not None:
                from .boundary_store import BoundaryStore

                owner = catalog.current_daemon_fence()
                if owner is None:
                    raise CatalogError("boundary_owner_changed")
                return BoundaryStore(
                    lambda: Catalog(self.application.paths.catalog_file), owner.generation,
                ).reserve_pending_labels(
                    job_id, normalized, actor=actor,
                    authorize_automatic_formatting=authorize_automatic_formatting,
                    expected_revision=expected_revision, request_sha256=request_sha256,
                    caller_catalog=catalog,
                )
            return catalog.reserve_job_labels(
                job_id, normalized, expected_revision=expected_revision,
                actor=actor, authorize_automatic_formatting=authorize_automatic_formatting,
                request_sha256=request_sha256,
            )

        result, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="job.reserve_labels",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=reserve,
        )
        return result

    async def incremental_policy(self, job_id: str) -> dict[str, Any]:
        try:
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                return self._incremental_policy_projection(
                    catalog.incremental_policy(job_id)
                )
        except CatalogError as exc:
            translated = self._translate_job_catalog_error(exc)
            if translated is not None:
                raise translated from None
            raise

    async def update_incremental_policy(
        self, job_id: str, cadence: str, *, expected_revision: int,
        actor: str, idempotency_key: str,
    ) -> dict[str, Any]:
        request_sha256 = self._request_sha256(
            {"cadence": cadence,"expected_revision": expected_revision,"job_id": job_id}
        )
        def update() -> dict[str, Any]:
            with RunLock(self.application.paths.lock_file), Catalog(self.application.paths.catalog_file) as catalog, catalog.transaction():
                catalog.initialize()
                replay = catalog.management_idempotency_replay(
                    actor=actor,idempotency_key=idempotency_key,action="job.incremental_policy",
                    target_id=job_id,request_sha256=request_sha256)
                if replay is not None:
                    return dict(replay)
                try:
                    result = catalog.update_incremental_policy(
                        job_id,cadence,expected_revision=expected_revision,
                        updated_at=self._utc_now().isoformat())
                except CatalogError as exc:
                    if str(exc) == "job_incremental_revision_conflict":
                        raise JobRevisionConflict("incremental policy revision changed") from None
                    raise
                result = self._incremental_policy_projection(result)
                catalog._job_history_tx(
                    catalog.connection,job_id,actor,"job.incremental_policy",
                    str(catalog.job_management_state(job_id)["current_checkpoint"]),{"cadence": cadence})
                return catalog.record_management_idempotency(
                    actor=actor,idempotency_key=idempotency_key,action="job.incremental_policy",
                    target_id=job_id,request_sha256=request_sha256,response=result)
        return update()

    async def retire_job(
        self,
        job_id: str,
        *,
        typed_job_id: str,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
    ) -> dict[str, Any]:
        if not secrets.compare_digest(job_id, typed_job_id):
            raise JobConfirmationMismatch("job confirmation does not match")
        request_sha256 = self._request_sha256(
            {
                "expected_revision": expected_revision,
                "job_id": job_id,
                "typed_job_id": typed_job_id,
            }
        )
        result, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="job.retire",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=lambda catalog: catalog.retire_managed_job(
                job_id, expected_revision=expected_revision, actor=actor
            ),
        )
        return result

    async def request_job_pause(
        self,
        job_id: str,
        *,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        request_sha256 = self._request_sha256({"job_id": job_id})
        result, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="job.pause",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=lambda catalog: catalog.request_job_pause(job_id, actor),
        )
        return result

    async def resume_job(
        self,
        job_id: str,
        *,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        request_sha256 = self._request_sha256({"job_id": job_id})

        def clear(catalog: Catalog) -> None:
            job = catalog.get_automatic_job(job_id)
            state = catalog.job_management_state(job_id)
            if state["retired_at"] is not None or job["status"] not in {
                "paused",
                "waiting_media",
                "failed",
            }:
                raise CatalogError("job_resume_state_conflict")
            catalog.clear_job_pause(job_id, actor)

        result, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="job.resume",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=clear,
        )
        return result

    async def reset_failed_cassette(
        self,
        job_id: str,
        cassette_sequence: int,
        typed_physical_label: str,
        *,
        expected_revision: int,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        normalized_label = typed_physical_label.strip().upper()
        request_sha256 = self._request_sha256(
            {
                "cassette_sequence": cassette_sequence,
                "expected_revision": expected_revision,
                "job_id": job_id,
                "typed_physical_label": normalized_label,
            }
        )

        def reset(catalog: Catalog) -> None:
            job = catalog.get_automatic_job(job_id)
            state = catalog.job_management_state(job_id)
            if catalog.get_import_policy(job_id) is not None:
                raise CatalogError("job_imported_frozen")
            if int(state["revision"]) != expected_revision:
                raise CatalogError("job_revision_conflict")
            if (
                state["retired_at"] is not None
                or str(job["status"]) != "failed"
                or int(job["current_sequence"]) != cassette_sequence
            ):
                raise CatalogError("job_reset_state_conflict")
            fenced = catalog.connection.execute(
                "SELECT 1 FROM managed_source_job_fences WHERE job_id=? LIMIT 1",
                (job_id,),
            ).fetchone()
            active_operation = catalog.connection.execute(
                "SELECT 1 FROM daemon_operations WHERE job_id=? "
                "AND state IN ('running','recovery_required') LIMIT 1",
                (job_id,),
            ).fetchone()
            unquiesced_command = catalog.connection.execute(
                "SELECT 1 FROM hardware_command_executions "
                "WHERE state!='quiesced' LIMIT 1"
            ).fetchone()
            if (
                fenced is not None
                or active_operation is not None
                or unquiesced_command is not None
            ):
                raise CatalogError("job_reset_state_conflict")
            failed = tuple(
                row
                for row in catalog.list_automatic_cassettes(job_id)
                if str(row["status"]) == "failed"
            )
            if len(failed) != 1 or int(failed[0]["sequence"]) != cassette_sequence:
                raise CatalogError("job_reset_state_conflict")
            expected_label = str(failed[0]["physical_label"]).upper()
            if not secrets.compare_digest(expected_label, normalized_label):
                raise CatalogError("job_confirmation_mismatch")
            catalog.reset_automatic_cassette(
                job_id,
                cassette_sequence,
                "Administrator-authorized retry of an uncertain cassette",
            )
            now = self._utc_now().isoformat()
            catalog.enable_automatic_sequence_for_start(
                job_id,
                actor=actor,
                enabled_at=now,
            )
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='waiting_media',error=NULL "
                "WHERE job_id=? AND sequence=? AND status='pending'",
                (job_id, cassette_sequence),
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='waiting_media',current_sequence=?,"
                "completed_at=NULL,last_error=NULL WHERE id=?",
                (cassette_sequence, job_id),
            )
            catalog.connection.execute(
                "UPDATE job_management_state SET revision=revision+1,"
                "current_checkpoint='resuming',pause_requested_at=NULL,"
                "pause_acknowledged_at=NULL,updated_at=? WHERE job_id=?",
                (now, job_id),
            )

        result, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="job.failed_cassette.reset",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=reset,
            audit_payload={
                "job_id": job_id,
                "cassette_sequence": cassette_sequence,
                "physical_label": normalized_label,
            },
        )
        return result

    async def create_job_from_plan(
        self,
        plan_id: str,
        digest_sha256: str,
        labels: Sequence[str],
        *,
        idempotency_key: str,
        display_name: str,
        device_name: str = "TAPE0",
        mount_path: str = "AUTO",
        actor: str = "system",
        allow_registered_reuse: bool = False,
        authorize_automatic_formatting: bool,
    ) -> dict[str, Any]:
        try:
            return await _run_in_worker(
                self._create_job_from_plan,
                plan_id,
                digest_sha256,
                tuple(labels),
                idempotency_key,
                display_name,
                device_name,
                mount_path,
                actor,
                allow_registered_reuse,
                authorize_automatic_formatting,
            )
        except CatalogError as exc:
            raise _plan_consumption_error(exc) from None

    async def create_extension_plan(
        self, job_id: str, *, creator: str, idempotency_key: str
    ) -> dict[str, Any]:
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            evidence = catalog.job_extension_evidence(job_id)
        if evidence["imported"]:
            raise JobImportedFrozen("imported job policy is frozen")
        if evidence["retired"] or evidence["status"] not in {
            "planned",
            "paused",
            "waiting_media",
            "completed",
            "failed",
        }:
            raise JobStateConflict("job state does not allow extension")
        result = await self._create_plan_idempotently(
            library_ids=tuple(evidence["libraries"]),
            media_key=str(evidence["media_key"]),
            creator=creator,
            idempotency_key=idempotency_key,
            kind="extend",
            base_job_id=job_id,
            base_job_revision=int(evidence["revision"]),
            base_job_fingerprint_sha256=str(evidence["fingerprint_sha256"]),
        )
        if (
            result.get("state") == "failed"
            and result.get("failure_code") == "no_new_source_files"
        ):
            raise NoNewSourceFiles("no new source versions")
        return result

    async def extend_job(
        self,
        job_id: str,
        plan_id: str,
        digest_sha256: str,
        labels: Sequence[str],
        *,
        actor: str,
        idempotency_key: str,
        expected_revision: int | None = None,
        authorize_automatic_formatting: bool = False,
    ) -> dict[str, Any]:
        normalized = tuple(str(label).strip().upper() for label in labels)
        consumed_at = self._utc_now()
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            plan = catalog.get_job_plan(plan_id)
            plan_share_rows = catalog.connection.execute(
                "SELECT library_id,evidence_json FROM job_plan_share_evidence "
                "WHERE plan_id=? ORDER BY library_id COLLATE NOCASE",
                (plan_id,),
            ).fetchall()
            managed_library_ids = {
                str(row["library_id"]).casefold()
                for row in catalog.connection.execute(
                    "SELECT plan_library.library_id "
                    "FROM job_plan_libraries AS plan_library "
                    "JOIN libraries AS library ON library.id=plan_library.library_id "
                    "WHERE plan_library.plan_id=? AND library.source_kind='network'",
                    (plan_id,),
                )
            }
        if managed_library_ids != {
            str(row["library_id"]).casefold() for row in plan_share_rows
        }:
            raise ShareIdentityChanged()
        managed_source_leases: dict[str, str] = {}
        if plan["state"] != "consumed":
            if plan["state"] == "expired":
                raise PlanExpired("plan_expired")
            if plan["state"] != "ready":
                raise JobPlanError(f"plan_{plan['state']}")
            if plan["digest_sha256"] != digest_sha256:
                raise JobPlanError("plan_digest_mismatch")
            try:
                for row in plan_share_rows:
                    evidence = json.loads(str(row["evidence_json"]))
                    library_id = str(row["library_id"])
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        lease_id = catalog.acquire_managed_source_lease(
                            str(evidence["share_id"]),
                            consumer_kind="save",
                            consumer_id="extend-"
                            + hashlib.sha256(
                                f"{plan_id}\0{library_id}".encode()
                            ).hexdigest()[:32],
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    managed_source_leases[library_id.casefold()] = lease_id
                    self._reverify_managed_library_identity(library_id, evidence)
                if not self.application.frozen_job_plan_sources_are_current(plan):
                    raise PlanStale("plan_stale")
            except Exception:
                for lease_id in managed_source_leases.values():
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        try:
                            catalog.release_managed_source_lease(
                                lease_id,
                                owner_id=self._share_owner_id,
                                daemon_generation=0,
                            )
                        except CatalogError:
                            pass
                raise
        request_sha256 = self._request_sha256(
            {
                "digest_sha256": digest_sha256,
                "expected_revision": expected_revision,
                "job_id": job_id,
                "labels": list(normalized),
                "plan_id": plan_id,
                "authorize_automatic_formatting": authorize_automatic_formatting,
            }
        )
        try:
            result, _replayed = self._atomic_job_mutation(
                actor=actor,
                idempotency_key=idempotency_key,
                action="job.extend",
                job_id=job_id,
                request_sha256=request_sha256,
                mutate=lambda catalog: catalog.consume_extension_plan(
                    plan_id=plan_id,
                    digest_sha256=digest_sha256,
                    labels=normalized,
                    idempotency_key=idempotency_key,
                    request_sha256=request_sha256,
                    job_id=job_id,
                    consumed_at=consumed_at.isoformat(),
                    expected_revision=expected_revision,
                    managed_source_leases=managed_source_leases,
                    actor=actor,
                    authorize_automatic_formatting=authorize_automatic_formatting,
                ),
            )
        except Exception:
            for lease_id in managed_source_leases.values():
                with Catalog(self.application.paths.catalog_file) as catalog:
                    catalog.initialize()
                    try:
                        catalog.release_managed_source_lease(
                            lease_id,
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    except CatalogError:
                        pass
            raise
        return result

    def _create_job_from_plan(
        self,
        plan_id: str,
        digest_sha256: str,
        labels: tuple[str, ...],
        idempotency_key: str,
        display_name: str,
        device_name: str,
        mount_path: str,
        actor: str,
        allow_registered_reuse: bool,
        authorize_automatic_formatting: bool,
    ) -> dict[str, Any]:
        normalized_labels = tuple(str(label).strip().upper() for label in labels)
        if any(not re.fullmatch(r"[A-Z0-9]{6}", label) for label in normalized_labels):
            raise ValidationError("physical label is invalid")
        consumed_at = self._utc_now()
        with Catalog(self.application.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.cleanup_expired_job_plans(consumed_at.isoformat())
            plan = catalog.get_job_plan(plan_id)
            plan_share_rows = catalog.connection.execute(
                "SELECT library_id,evidence_json FROM job_plan_share_evidence "
                "WHERE plan_id=? ORDER BY library_id COLLATE NOCASE",
                (plan_id,),
            ).fetchall()
            managed_library_ids = {
                str(row["library_id"]).casefold()
                for row in catalog.connection.execute(
                    "SELECT plan_library.library_id "
                    "FROM job_plan_libraries AS plan_library "
                    "JOIN libraries AS library ON library.id=plan_library.library_id "
                    "WHERE plan_library.plan_id=? AND library.source_kind='network'",
                    (plan_id,),
                )
            }
        if managed_library_ids != {
            str(row["library_id"]).casefold() for row in plan_share_rows
        }:
            raise ShareIdentityChanged()
        managed_source_leases: dict[str, str] = {}
        if plan["state"] != "consumed":
            if plan["state"] == "expired":
                raise PlanExpired("plan_expired")
            if plan["state"] != "ready":
                raise JobPlanError(f"plan_{plan['state']}")
            if plan["digest_sha256"] != digest_sha256:
                raise JobPlanError("plan_digest_mismatch")
            try:
                for row in plan_share_rows:
                    evidence = json.loads(str(row["evidence_json"]))
                    library_id = str(row["library_id"])
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        lease_id = catalog.acquire_managed_source_lease(
                            str(evidence["share_id"]),
                            consumer_kind="save",
                            consumer_id="save-"
                            + hashlib.sha256(
                                f"{plan_id}\0{library_id}".encode()
                            ).hexdigest()[:32],
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    managed_source_leases[library_id.casefold()] = lease_id
                    self._reverify_managed_library_identity(library_id, evidence)
                if not self.application.frozen_job_plan_sources_are_current(plan):
                    raise PlanStale("plan_stale")
            except Exception:
                for lease_id in managed_source_leases.values():
                    with Catalog(self.application.paths.catalog_file) as catalog:
                        catalog.initialize()
                        try:
                            catalog.release_managed_source_lease(
                                lease_id,
                                owner_id=self._share_owner_id,
                                daemon_generation=0,
                            )
                        except CatalogError:
                            pass
                raise

        request_json = json.dumps(
            {
                "device_name": device_name,
                "digest_sha256": digest_sha256,
                "display_name": display_name.strip(),
                "labels": list(normalized_labels),
                "mount_path": mount_path,
                "plan_id": plan_id,
                "allow_registered_reuse": allow_registered_reuse,
                "authorize_automatic_formatting": authorize_automatic_formatting,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        request_sha256 = hashlib.sha256(request_json.encode("utf-8")).hexdigest()
        candidate_job_id = (
            "AUTO-" + consumed_at.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
        )
        try:
            with Catalog(self.application.paths.catalog_file) as catalog:
                catalog.initialize()
                job_id, _replayed = catalog.consume_job_plan(
                    plan_id=plan_id,
                    digest_sha256=digest_sha256,
                    labels=normalized_labels,
                    idempotency_key=idempotency_key,
                    request_sha256=request_sha256,
                    job_id=candidate_job_id,
                    display_name=display_name,
                    device_name=device_name,
                    mount_path=mount_path,
                    consumed_at=consumed_at.isoformat(),
                    actor=actor,
                    managed_source_leases=managed_source_leases,
                    allow_registered_reuse=allow_registered_reuse,
                    authorize_automatic_formatting=authorize_automatic_formatting,
                )
        except CatalogError as exc:
            for lease_id in managed_source_leases.values():
                with Catalog(self.application.paths.catalog_file) as release_catalog:
                    release_catalog.initialize()
                    try:
                        release_catalog.release_managed_source_lease(
                            lease_id,
                            owner_id=self._share_owner_id,
                            daemon_generation=0,
                        )
                    except CatalogError:
                        pass
            raise
        return self.application.automatic_job(job_id)

    async def authorize_automatic_sequence(
        self,
        job_id: str,
        *,
        expected_revision: int,
        layout_fingerprint_sha256: str,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        try:
            return await _run_in_worker(
                self._authorize_automatic_sequence,
                job_id,
                expected_revision,
                layout_fingerprint_sha256,
                actor,
                idempotency_key,
            )
        except CatalogError as exc:
            translated = self._translate_job_catalog_error(exc)
            if translated is not None:
                raise translated from None
            raise

    def _before_sequence_authorization_transaction(self) -> None:
        """Provide a narrow synchronization seam for authorization contention tests."""

    def _authorize_automatic_sequence(
        self,
        job_id: str,
        expected_revision: int,
        layout_fingerprint_sha256: str,
        actor: str,
        idempotency_key: str,
    ) -> dict[str, Any]:
        request_sha256 = self._request_sha256(
            {
                "authorize_automatic_formatting": True,
                "expected_revision": expected_revision,
                "job_id": job_id,
                "layout_fingerprint_sha256": layout_fingerprint_sha256,
            }
        )

        def grant_authority(catalog: Catalog) -> None:
            catalog.authorize_automatic_format_sequence(
                job_id,
                expected_revision=expected_revision,
                layout_fingerprint_sha256=layout_fingerprint_sha256,
                actor=actor,
                idempotency_key=idempotency_key,
                authorized_at=self._utc_now().isoformat(),
                request_sha256=request_sha256,
                record_idempotency=False,
            )

        self._before_sequence_authorization_transaction()
        response, _replayed = self._atomic_job_mutation(
            actor=actor,
            idempotency_key=idempotency_key,
            action="automatic.format_sequence.authorize",
            job_id=job_id,
            request_sha256=request_sha256,
            mutate=grant_authority,
            audit_action="job.automatic_sequence.authorize",
            audit_payload={"job_id": job_id, "expected_revision": expected_revision},
            use_run_lock=False,
        )
        return response
