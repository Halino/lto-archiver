"""Select completed native boundaries before ordinary automatic admission.

This component performs no hardware operation. A false result defers the
sequence coordinator; successful refresh is followed by a new catalog lookup
on its next tick. Pending label deficits already have their own durable fence.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from collections.abc import Callable
from typing import Protocol

from ..catalog import Catalog
from ..errors import CatalogError, ValidationError
from ..util import utc_now
from .boundary_retention import BoundaryDraftRetention
from .boundary_store import BoundaryStore


class BoundaryProcessor(Protocol):
    def refresh(self, job_id: str) -> dict: ...

    def resume_pending(self, job_id: str) -> dict: ...

    def refresh_pending(self, job_id: str, *, candidate_sha256: str, reason: str) -> dict: ...


class BoundaryDispatcher:
    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        *,
        daemon_generation: int,
        coordinator: BoundaryProcessor,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._factory = catalog_factory
        self._generation = daemon_generation
        self._coordinator = coordinator
        self._store = BoundaryStore(catalog_factory, daemon_generation)
        self._retention = BoundaryDraftRetention(catalog_factory, daemon_generation)
        self._cleanup_after_job = ""
        self._clock = clock
        self._retry_after: dict[str, float] = {}

    def reconcile_once(self) -> bool:
        with self._factory() as catalog:
            owner = catalog.current_daemon_fence()
            if owner is None or owner.generation != self._generation:
                raise CatalogError("boundary_owner_changed")
            if catalog.connection.execute(
                "SELECT 1 FROM daemon_operations WHERE state IN ('running','recovery_required') "
                "UNION ALL SELECT 1 FROM hardware_command_executions WHERE state<>'quiesced' LIMIT 1"
            ).fetchone():
                return False
            cleanup_jobs = catalog.connection.execute(
                "SELECT DISTINCT job.id FROM automatic_jobs job "
                "JOIN job_plan_drafts draft ON draft.base_job_id=job.id "
                "WHERE job.status IN ('paused','waiting_media','completed') "
                "AND job.id>? COLLATE NOCASE AND draft.creator='boundary-coordinator' "
                "AND draft.kind='extend' AND draft.state IN ('building','ready','expired') "
                "ORDER BY job.id COLLATE NOCASE LIMIT 8",
                (self._cleanup_after_job,),
            ).fetchall()
            rows = catalog.connection.execute(
                "SELECT job.id,MAX(completed.sequence) AS boundary_sequence FROM automatic_jobs job "
                "JOIN automatic_sequence_state sequence ON sequence.job_id=job.id "
                "JOIN job_management_state management ON management.job_id=job.id "
                "JOIN job_policy_snapshots policy ON policy.job_id=job.id "
                "JOIN automatic_cassettes completed ON completed.job_id=job.id AND completed.status='completed' "
                "WHERE management.retired_at IS NULL AND management.pause_requested_at IS NULL "
                "AND ((job.status='waiting_media' AND sequence.state='enabled') "
                "OR (job.status='completed' AND sequence.state='completed' AND sequence.enabled_by IS NOT NULL "
                "AND EXISTS(SELECT 1 FROM daemon_operations terminal JOIN metadata activation "
                "ON activation.key='boundary_replanning_activated_at' WHERE terminal.job_id=job.id "
                "AND terminal.kind='archive.native' AND terminal.state='succeeded' "
                "AND terminal.cassette_sequence=job.current_sequence AND terminal.finished_at>=activation.value))) "
                "AND NOT EXISTS(SELECT 1 FROM imported_job_policies imported WHERE imported.job_id=job.id) "
                "AND NOT EXISTS(SELECT 1 FROM automatic_cassettes pending WHERE pending.job_id=job.id "
                "AND pending.status<>'completed' AND (pending.status NOT IN ('pending','waiting_media') "
                "OR pending.operation<>'format' OR pending.started_at IS NOT NULL "
                "OR EXISTS(SELECT 1 FROM daemon_operations attempt WHERE attempt.job_id=job.id "
                "AND attempt.cassette_sequence=pending.sequence))) "
                "GROUP BY job.id ORDER BY job.id COLLATE NOCASE"
            ).fetchall()
        self._cleanup_after_job = cleanup_jobs[-1][0] if len(cleanup_jobs) == 8 else ""
        for cleanup_job in cleanup_jobs:
            try:
                self._retention.collect(str(cleanup_job[0]))
            except (CatalogError, OSError, sqlite3.Error):
                logging.getLogger(__name__).warning("boundary.draft_cleanup.deferred")
        for row in rows:
            job_id = str(row["id"])
            with self._factory() as catalog:
                applied = any(
                    json.loads(event[0]).get("completed_sequence")
                    == row["boundary_sequence"]
                    for event in catalog.connection.execute(
                        "SELECT payload_json FROM job_management_history WHERE job_id=? "
                        "AND action='job.boundary_replan.applied'",
                        (job_id,),
                    )
                )
                suffix_count = catalog.connection.execute(
                    "SELECT COUNT(*) FROM automatic_cassettes WHERE job_id=? AND sequence>?",
                    (job_id, row["boundary_sequence"]),
                ).fetchone()[0]
            if applied:
                self._retry_after.pop(job_id, None)
                continue
            if self._retry_after.get(job_id, 0.0) > self._clock():
                continue
            try:
                pending = self._store.pending(job_id)
                if pending is not None and self._store.pending_expired(pending):
                    self._coordinator.refresh_pending(
                        job_id, candidate_sha256=pending["candidate_sha256"], reason="expired",
                    )
                elif pending is not None:
                    # No repeated scans/publications while waiting. An added
                    # reserve triggers replay even if the addition is partial.
                    if suffix_count <= len(pending["plan"]["assignments"]):
                        continue
                    self._coordinator.resume_pending(job_id)
                else:
                    self._coordinator.refresh(job_id)
            except (CatalogError, ValidationError, OSError, sqlite3.Error) as exc:
                code = (
                    "boundary_catalog_conflict"
                    if isinstance(exc, sqlite3.Error)
                    else str(exc)
                    if isinstance(exc, CatalogError)
                    else "boundary_source_unavailable"
                )
                if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", code) is None:
                    code = "boundary_refresh_failed"
                with self._factory() as catalog, catalog.transaction() as db:
                    catalog._job_history_tx(
                        db,
                        job_id,
                        "boundary-coordinator",
                        "job.boundary_replan.deferred",
                        "boundary_blocked",
                        {
                            "completed_sequence": row["boundary_sequence"],
                            "error_code": code,
                        },
                        occurred_at=utc_now(),
                    )
                self._retry_after[job_id] = self._clock() + 60.0
                continue
            self._retry_after.pop(job_id, None)
            return False
        return True
