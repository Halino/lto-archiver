from __future__ import annotations

import asyncio
import hashlib
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from ..catalog import Catalog
from ..errors import CatalogError, NoNewSourceFiles, ValidationError
from .management import PlanExpired, PlanStale

IncrementalCadence = Literal[
    "off", "every_6_hours", "every_12_hours", "daily", "weekly"
]
IncrementalTrigger = Literal[
    "scheduled", "manual", "labels_added", "startup_catchup"
]

_TERMINAL = frozenset(
    {
        "no_changes",
        "extension_queued",
        "waiting_labels",
        "deferred_busy",
        "plan_stale",
        "source_unavailable",
        "failed_safe",
    }
)
_CADENCE_DELAYS = {
    "every_6_hours": timedelta(hours=6),
    "every_12_hours": timedelta(hours=12),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
}


class IncrementalScanCoordinator:
    """Single daemon owner for scheduled and explicit source discovery."""

    def __init__(
        self,
        catalog_path: Path,
        management: Any,
        *,
        daemon_generation: Callable[[], int],
        now: Callable[[], datetime] | None = None,
        pending_plan_loader: Callable[[str, dict[str, Any]], dict[str, Any] | None]
        | None = None,
        target_resolver: Callable[[str, dict[str, Any]], tuple[int, ...]] | None = None,
    ) -> None:
        self._catalog_path = Path(catalog_path)
        self._management = management
        self._daemon_generation = daemon_generation
        self._now = now or (lambda: datetime.now(UTC))
        self._pending_plan_loader = pending_plan_loader
        self._target_resolver = target_resolver

    def _timestamp(self) -> str:
        value = self._now()
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValidationError("incremental clock must return UTC")
        return value.astimezone(UTC).isoformat()

    @staticmethod
    def _run_id(job_id: str, trigger: str, idempotency_key: str) -> str:
        digest = hashlib.sha256(
            f"{job_id}\0{trigger}\0{idempotency_key}".encode()
        ).hexdigest()
        return "incremental-" + digest[:40]

    def _next_eligible(self, job_id: str, *, deferred: bool = False) -> str | None:
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            cadence = str(catalog.incremental_policy(job_id)["cadence"])
        now = self._now().astimezone(UTC)
        if deferred:
            return (now + timedelta(minutes=1)).isoformat()
        delay = _CADENCE_DELAYS.get(cadence)
        return None if delay is None else (now + delay).isoformat()

    def _finish(
        self,
        run_id: str,
        state: str,
        *,
        next_eligible_at: str | None,
        **values: Any,
    ) -> dict[str, Any]:
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            event = catalog.finish_incremental_scan_run(
                run_id,
                state=state,
                daemon_generation=self._daemon_generation(),
                recorded_at=self._timestamp(),
                next_eligible_at=next_eligible_at,
                **values,
            )
        return {**event, "next_eligible_at": next_eligible_at}

    @staticmethod
    def _plan_counts(plan: dict[str, Any]) -> tuple[int, int]:
        rows = tuple(plan.get("cassettes", ()))
        return (
            sum(int(row.get("objects", 0)) for row in rows),
            sum(int(row.get("payload_bytes", 0)) for row in rows),
        )

    def _required_labels(self, job_id: str, plan: dict[str, Any]) -> int:
        operations = [str(row.get("operation")) for row in plan.get("cassettes", ())]
        reserve_bound = operations.count("reserve")
        format_count = operations.count("format")
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            available = catalog.incremental_reserve_capacity(job_id)
        newly_available = max(0, available - reserve_bound)
        return max(0, format_count - newly_available)

    def _target_sequences(self, job_id: str, plan: dict[str, Any]) -> tuple[int, ...]:
        operations = [str(row["operation"]) for row in plan.get("cassettes", ())]
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            rows = catalog.list_automatic_cassettes(job_id)
        append = [int(row["sequence"]) for row in rows if row["operation"] == "append" and row["status"] == "pending"]
        formats = [int(row["sequence"]) for row in rows if row["operation"] == "format" and row["status"] == "pending" and int(row["planned_files"]) > 0]
        result: list[int] = []
        for operation in operations:
            if operation == "append" and append:
                result.append(append.pop(0))
            elif formats:
                result.append(formats.pop(0))
            else:
                raise CatalogError("layout_target_mapping_incomplete")
        return tuple(result)

    async def _consume_ready(
        self,
        job_id: str,
        plan: dict[str, Any],
        *, actor: str,
        idempotency_key: str,
        authorize_automatic_formatting: bool,
    ) -> None:
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            revision = int(catalog.job_management_state(job_id)["revision"])
        await self._management.extend_job(
            job_id,
            str(plan["id"]),
            str(plan["digest_sha256"]),
            (),
            actor=actor,
            idempotency_key=idempotency_key,
            expected_revision=revision,
            authorize_automatic_formatting=authorize_automatic_formatting,
        )
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            targets = (
                self._target_resolver(job_id, plan)
                if self._target_resolver is not None
                else self._target_sequences(job_id, plan)
            )
            catalog.clear_incremental_extension_and_record_epoch(
                job_id,
                plan_id=str(plan["id"]),
                plan_digest_sha256=str(plan["digest_sha256"]),
                target_sequences=targets,
                target_operations=tuple(
                    str(row["operation"]) for row in plan.get("cassettes", ())
                ),
                created_at=self._timestamp(),
            )

    async def run_job(
        self,
        job_id: str,
        trigger: IncrementalTrigger,
        *,
        actor: str,
        idempotency_key: str,
        authorize_automatic_formatting: bool = False,
    ) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", job_id):
            raise ValidationError("invalid incremental job ID")
        if trigger not in {"scheduled", "manual", "labels_added", "startup_catchup"}:
            raise ValidationError("invalid incremental trigger")
        key_digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        run_id = self._run_id(job_id, trigger, idempotency_key)
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            claimed, replayed, admitted = catalog.claim_incremental_scan_run(
                run_id,
                job_id,
                trigger,
                daemon_generation=self._daemon_generation(),
                idempotency_key_sha256=key_digest,
                recorded_at=self._timestamp(),
            )
        if replayed:
            return dict(claimed)
        if not admitted:
            return self._finish(
                run_id,
                "deferred_busy",
                next_eligible_at=self._next_eligible(job_id, deferred=True),
            )
        try:
            pending = None
            reuse_pending = trigger == "labels_added"
            if trigger != "labels_added":
                with Catalog(self._catalog_path) as catalog:
                    catalog.initialize()
                    pending = catalog.pending_incremental_extension(job_id)
                if pending is not None:
                    reuse_pending = True
            if reuse_pending:
                with Catalog(self._catalog_path) as catalog:
                    catalog.initialize()
                    if pending is None:
                        pending = catalog.pending_incremental_extension(job_id)
                    if pending is None:
                        plan = None
                    elif self._pending_plan_loader is not None:
                        plan = self._pending_plan_loader(job_id, pending)
                    else:
                        try:
                            plan = catalog.get_job_plan(str(pending["plan_id"]))
                        except CatalogError as exc:
                            if not str(exc).startswith("job plan not found:"):
                                raise
                            plan = None
                if pending is None:
                    return self._finish(
                        run_id, "plan_stale", next_eligible_at=self._next_eligible(job_id),
                        error_code="pending_extension_missing",
                    )
                expired = plan is not None and (
                    plan.get("state") == "expired"
                    or (
                        plan.get("expires_at") is not None
                        and datetime.fromisoformat(str(plan["expires_at"])) <= self._now()
                    )
                )
                if (
                    plan is None
                    or expired
                    or plan.get("state", "ready") != "ready"
                    or plan.get("digest_sha256") != pending["plan_digest_sha256"]
                ):
                    return self._finish(
                        run_id, "plan_stale", next_eligible_at=self._next_eligible(job_id),
                        error_code=("pending_plan_missing" if plan is None else
                                    "plan_expired" if expired else "plan_stale"),
                        invalidate_pending=True,
                        plan_id=str(pending["plan_id"]),
                        plan_digest_sha256=str(pending["plan_digest_sha256"]),
                        discovered_files=int(pending["discovered_files"]),
                        discovered_bytes=int(pending["discovered_bytes"]),
                        required_additional_labels=int(pending["required_additional_labels"]),
                    )
                if trigger != "labels_added" and int(pending["required_additional_labels"]) > 0:
                    return self._finish(
                        run_id, "waiting_labels",
                        next_eligible_at=self._next_eligible(job_id),
                        plan_id=str(pending["plan_id"]),
                        plan_digest_sha256=str(pending["plan_digest_sha256"]),
                        discovered_files=int(pending["discovered_files"]),
                        discovered_bytes=int(pending["discovered_bytes"]),
                        required_additional_labels=int(pending["required_additional_labels"]),
                    )
            else:
                with Catalog(self._catalog_path) as catalog:
                    catalog.initialize()
                    catalog.append_incremental_scan_event(
                        run_id, "scanning", daemon_generation=self._daemon_generation(),
                        recorded_at=self._timestamp(),
                    )
                plan = await self._management.create_extension_plan(
                    job_id, creator=actor, idempotency_key="incremental-plan-" + key_digest[:32]
                )
                if plan.get("state", "ready") != "ready" or not plan.get("cassettes"):
                    raise RuntimeError("incremental planner returned no ready allocation")
            files, bytes_ = self._plan_counts(plan)
            required = self._required_labels(job_id, plan)
            with Catalog(self._catalog_path) as catalog:
                catalog.initialize()
                if not reuse_pending:
                    catalog.retain_incremental_extension(
                        job_id, plan_id=str(plan["id"]),
                        plan_digest_sha256=str(plan["digest_sha256"]),
                        discovered_files=files, discovered_bytes=bytes_,
                        required_additional_labels=required, created_at=self._timestamp(),
                    )
                else:
                    catalog.update_incremental_extension_label_deficit(
                        job_id,
                        plan_id=str(plan["id"]),
                        plan_digest_sha256=str(plan["digest_sha256"]),
                        required_additional_labels=required,
                    )
                catalog.append_incremental_scan_event(
                    run_id, "extension_ready", daemon_generation=self._daemon_generation(),
                    recorded_at=self._timestamp(), plan_id=str(plan["id"]),
                    plan_digest_sha256=str(plan["digest_sha256"]),
                    discovered_files=files, discovered_bytes=bytes_,
                    required_additional_labels=required,
                )
            if required:
                return self._finish(
                    run_id, "waiting_labels", next_eligible_at=self._next_eligible(job_id),
                    plan_id=str(plan["id"]), plan_digest_sha256=str(plan["digest_sha256"]),
                    discovered_files=files, discovered_bytes=bytes_,
                    required_additional_labels=required,
                )
            try:
                await self._consume_ready(
                    job_id, plan, actor=actor,
                    idempotency_key="incremental-consume-" + key_digest[:32],
                    authorize_automatic_formatting=authorize_automatic_formatting,
                )
            except (PlanExpired, PlanStale) as exc:
                return self._finish(
                    run_id, "plan_stale", next_eligible_at=self._next_eligible(job_id),
                    invalidate_pending=True, error_code=exc.code,
                    plan_id=str(plan["id"]), plan_digest_sha256=str(plan["digest_sha256"]),
                    discovered_files=files, discovered_bytes=bytes_,
                    required_additional_labels=required,
                )
            return self._finish(
                run_id, "extension_queued", next_eligible_at=self._next_eligible(job_id),
                plan_id=str(plan["id"]), plan_digest_sha256=str(plan["digest_sha256"]),
                discovered_files=files, discovered_bytes=bytes_,
            )
        except (OSError, FileNotFoundError):
            return self._finish(
                run_id, "source_unavailable", next_eligible_at=self._next_eligible(job_id),
                error_code="source_unavailable",
            )
        except NoNewSourceFiles:
            return self._finish(
                run_id, "no_changes", next_eligible_at=self._next_eligible(job_id)
            )
        except ValidationError:
            return self._finish(
                run_id, "plan_stale", next_eligible_at=self._next_eligible(job_id),
                error_code="plan_stale",
            )
        except Exception:  # noqa: BLE001 - terminal fail-closed public boundary
            return self._finish(
                run_id, "failed_safe", next_eligible_at=self._next_eligible(job_id),
                error_code="incremental_failed_safe",
            )

    async def run_due(
        self,
        now: datetime,
        *,
        trigger: Literal["scheduled", "startup_catchup"] = "scheduled",
    ) -> tuple[dict[str, Any], ...]:
        with Catalog(self._catalog_path) as catalog:
            catalog.initialize()
            jobs = catalog.due_incremental_jobs(now.astimezone(UTC).isoformat())
        results = []
        for job_id in jobs:
            key = "scheduled-" + hashlib.sha256(
                f"{job_id}\0{now.astimezone(UTC).isoformat()}".encode()
            ).hexdigest()[:32]
            try:
                results.append(
                    await self.run_job(
                        job_id, trigger, actor="scheduler", idempotency_key=key
                    )
                )
            except CatalogError as exc:
                if str(exc) not in {
                    "incremental_scan_busy",
                    "job_imported_frozen",
                    "job_not_found",
                    "job_retired",
                }:
                    raise
        return tuple(results)


class IncrementalScheduler:
    def __init__(self, coordinator: IncrementalScanCoordinator, *, interval_seconds: float = 60.0) -> None:
        self._coordinator = coordinator
        self._interval = interval_seconds
        self._stop = asyncio.Event()
        self._runner: asyncio.Task[None] | None = None

    async def run(self) -> None:
        self._runner = asyncio.current_task()
        try:
            first = True
            while not self._stop.is_set():
                await self._coordinator.run_due(
                    datetime.now(UTC),
                    trigger="startup_catchup" if first else "scheduled",
                )
                first = False
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=self._interval)
                except TimeoutError:
                    pass
        except asyncio.CancelledError:
            if not self._stop.is_set():
                raise
        finally:
            self._runner = None

    def stop(self) -> None:
        self._stop.set()
        if self._runner is not None and not self._runner.done():
            self._runner.cancel()
