"""Retire abandoned boundary drafts without altering any committed evidence."""

from __future__ import annotations

import re
from collections.abc import Callable

from ..catalog import Catalog
from ..errors import CatalogError
from ..util import utc_now


class BoundaryDraftRetention:
    def __init__(self, catalog_factory: Callable[[], Catalog], daemon_generation: int):
        self._factory = catalog_factory
        self._generation = daemon_generation
        self._after_plan: dict[str, str] = {}

    def collect(self, job_id: str, *, limit: int = 8) -> int:
        """Bound one idle dispatcher pass; each retirement rechecks its guards."""
        if type(limit) is not int or not 1 <= limit <= 32:
            raise ValueError("invalid boundary cleanup batch size")
        with self._factory() as catalog:
            rows = catalog.connection.execute(
                "SELECT DISTINCT draft.id FROM job_plan_drafts draft "
                "JOIN job_management_history failed ON failed.job_id=draft.base_job_id "
                "AND failed.actor='boundary-coordinator' "
                "AND failed.action='job.boundary_replan.failed' "
                "AND draft.id='PLAN-' || json_extract(failed.payload_json,'$.run_id') "
                "WHERE draft.base_job_id=? AND draft.id>? COLLATE NOCASE "
                "AND draft.creator='boundary-coordinator' "
                "AND draft.kind='extend' AND draft.state IN ('building','ready','expired') "
                "ORDER BY draft.id LIMIT ?",
                (job_id, self._after_plan.get(job_id, ""), limit),
            ).fetchall()
        # Advance even past protected candidates so they cannot starve later
        # eligible rows. Wrap after a bounded pass reaches the end.
        self._after_plan[job_id] = rows[-1][0] if len(rows) == limit else ""
        return sum(self.retire(job_id, row[0][len("PLAN-"):]) for row in rows)

    def retire(self, job_id: str, run_id: str) -> bool:
        """Delete one proven failed run's unreferenced draft, with compact audit.

        All guards and deletion share the catalog write transaction. Any active
        source lease conservatively defers cleanup, including hashed boundary
        lease identities. Existing schema triggers remain enabled.
        """
        if re.fullmatch(r"boundary-[0-9a-f]{32}", run_id) is None:
            return False
        plan_id = "PLAN-" + run_id
        with self._factory() as catalog, catalog.transaction() as db:
            owner = catalog.current_daemon_fence()
            if owner is None or owner.generation != self._generation:
                raise CatalogError("boundary_owner_changed")
            plan = db.execute(
                "SELECT * FROM job_plan_drafts WHERE id=? AND base_job_id=? "
                "AND creator='boundary-coordinator' AND kind='extend' "
                "AND state IN ('building','ready','expired') "
                "AND consumed_at IS NULL AND consumed_job_id IS NULL "
                "AND consumption_key IS NULL AND consumption_request_sha256 IS NULL",
                (plan_id, job_id),
            ).fetchone()
            if plan is None:
                return False
            if db.execute(
                "SELECT 1 FROM daemon_operations WHERE state IN ('running','recovery_required') "
                "UNION ALL SELECT 1 FROM hardware_command_executions WHERE state<>'quiesced' "
                "UNION ALL SELECT 1 FROM managed_source_leases "
                "UNION ALL SELECT 1 FROM job_incremental_scan_leases WHERE job_id=? "
                "UNION ALL SELECT 1 FROM managed_source_job_fences WHERE job_id=? LIMIT 1",
                (job_id, job_id),
            ).fetchone() or catalog.pending_boundary_replan_record(job_id) is not None:
                return False
            # Some immutable references deliberately do not have SQL FKs.
            for table, column in (
                ("job_layout_epochs", "plan_id"),
                ("job_incremental_pending_extensions", "plan_id"),
                ("job_incremental_scan_events", "plan_id"),
                ("job_management_state", "creation_plan_id"),
                ("job_extension_commits", "plan_id"),
                ("job_policy_snapshots", "plan_id"),
                ("automatic_job_share_evidence", "creation_plan_id"),
                ("automatic_cassette_share_evidence", "creation_plan_id"),
                ("automatic_cassette_share_evidence_sets", "creation_plan_id"),
            ):
                if db.execute(
                    f"SELECT 1 FROM {table} WHERE {column}=? COLLATE NOCASE LIMIT 1",
                    (plan_id,),
                ).fetchone():
                    return False
            for action in ("job.boundary_replan.claimed", "job.boundary_replan.failed"):
                if db.execute(
                    "SELECT 1 FROM job_management_history WHERE job_id=? "
                    "AND actor='boundary-coordinator' AND action=? "
                    "AND json_extract(payload_json,'$.run_id')=? LIMIT 1",
                    (job_id, action, run_id),
                ).fetchone() is None:
                    return False
            totals = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(size),0) FROM job_plan_items WHERE plan_id=?",
                (plan_id,),
            ).fetchone()
            now = utc_now()
            catalog._job_history_tx(
                db, job_id, "boundary-coordinator", "job.boundary_replan.draft_retired",
                "boundary_cleanup", {
                    "run_id": run_id, "plan_id": plan_id,
                    "digest_sha256": plan["digest_sha256"],
                    "files": totals[0], "bytes": totals[1],
                }, occurred_at=now,
            )
            db.execute(
                "UPDATE job_plan_drafts SET state='expired',updated_at=? WHERE id=?",
                (now, plan_id),
            )
            previous = catalog._expired_plan_cleanup_active
            catalog._expired_plan_cleanup_active = True
            try:
                db.execute("DELETE FROM job_plan_share_evidence WHERE plan_id=?", (plan_id,))
                db.execute("DELETE FROM job_plan_drafts WHERE id=?", (plan_id,))
            finally:
                catalog._expired_plan_cleanup_active = previous
            return True
