"""Small, redacted projection of cassette-boundary refresh history."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

_BOUNDARY_ACTIONS = (
    "job.boundary_resume.requested",
    "job.boundary_replan.claimed",
    "job.boundary_replan.failed",
    "job.boundary_replan.deferred",
    "job.boundary_replan.waiting_labels",
    "job.boundary_replan.applied",
    "job.boundary_replan.discarded",
)
_SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")


def _optional_nonnegative(value: object) -> int | None:
    if type(value) is int and value >= 0:
        return value
    return None


def _optional_positive(value: object) -> int | None:
    if type(value) is int and value > 0:
        return value
    return None


def _safe_code(value: object) -> str | None:
    return value if isinstance(value, str) and _SAFE_CODE.fullmatch(value) else None


def boundary_refresh_status(
    connection: sqlite3.Connection,
    job_id: str,
    *,
    paused: bool = False,
) -> dict[str, Any] | None:
    """Return only bounded scalar status fields from the latest boundary event."""

    placeholders = ",".join("?" for _ in _BOUNDARY_ACTIONS)
    row = connection.execute(
        "WITH latest AS ("
        "SELECT id,action,occurred_at,"
        "json_extract(payload_json,'$.run_id') AS run_id,"
        "json_extract(payload_json,'$.completed_sequence') AS completed_sequence,"
        "json_extract(payload_json,'$.required_additional_labels') "
        "AS required_additional_labels,"
        "json_extract(payload_json,'$.candidate_files') AS candidate_files,"
        "json_extract(payload_json,'$.candidate_bytes') AS candidate_bytes,"
        "json_extract(payload_json,'$.error_code') AS error_code,"
        "json_extract(payload_json,'$.reason') AS discard_reason "
        "FROM job_management_history WHERE job_id=? AND action IN ("
        f"{placeholders}) ORDER BY id DESC LIMIT 1) "
        "SELECT latest.*,lease.run_id AS lease_run_id,"
        "lease.daemon_generation AS lease_generation,"
        "owner.generation AS owner_generation FROM latest "
        "LEFT JOIN job_incremental_scan_leases AS lease ON lease.job_id=? "
        "LEFT JOIN daemon_ownership AS owner ON owner.singleton=1",
        (job_id, *_BOUNDARY_ACTIONS, job_id),
    ).fetchone()
    if row is None:
        return None

    action = str(row["action"])
    if action == "job.boundary_resume.requested":
        state = "queued"
    elif action == "job.boundary_replan.claimed":
        lease_is_current = (
            isinstance(row["run_id"], str)
            and row["run_id"] == row["lease_run_id"]
            and row["lease_generation"] is not None
            and row["lease_generation"] == row["owner_generation"]
        )
        state = "paused" if paused and lease_is_current else (
            "scanning" if lease_is_current else "stale"
        )
    elif action == "job.boundary_replan.waiting_labels":
        state = "waiting_labels"
    elif action in {
        "job.boundary_replan.failed",
        "job.boundary_replan.deferred",
    }:
        state = "blocked"
    elif action == "job.boundary_replan.applied":
        state = "applied"
    else:
        state = "stale"

    if paused and state in {"queued", "scanning", "waiting_labels"}:
        state = "paused"

    error_code = _safe_code(
        row["discard_reason"]
        if action == "job.boundary_replan.discarded"
        else row["error_code"]
    )
    return {
        "state": state,
        "completed_sequence": _optional_positive(row["completed_sequence"]),
        "required_additional_labels": _optional_nonnegative(
            row["required_additional_labels"]
        ),
        "candidate_files": _optional_nonnegative(row["candidate_files"]),
        "candidate_bytes": _optional_nonnegative(row["candidate_bytes"]),
        "error_code": error_code,
        "occurred_at": str(row["occurred_at"]),
    }
