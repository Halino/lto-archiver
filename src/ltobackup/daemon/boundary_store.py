"""Fenced catalog-only suffix replacement; never performs tape or source I/O.

This is deliberately separate from ordinary extension consumption. The caller
must retain verified source leases across scanning, draft publication and this
commit. Old epoch payloads remain the immutable superseded manifest evidence;
job history records the boundary/run linking old and new epochs.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable, Mapping
from contextlib import nullcontext
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from ..catalog import Catalog
from ..errors import CatalogError
from ..models import ScanItem
from ..util import ltfs_tape_relative_path, utc_now, validate_source_relative_path
from .boundary_replan import BoundaryPlan


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _source_baseline(state: dict) -> dict:
    return {key: state[key] for key in (
        "prefix", "operation", "commands", "committed_catalog",
        "libraries", "source_libraries", "source_evidence", "policy_records",
    )}


@dataclass(frozen=True)
class BoundarySnapshot:
    job_id: str
    run_id: str
    daemon_generation: int
    completed_sequence: int
    revision: int
    epoch_number: int
    layout_fingerprint_sha256: str
    state_json: str
    pending_candidate_sha256: str | None = None
    source_roots_json: str | None = None


class BoundaryStore:
    def __init__(self, catalog_factory: Callable[[], Catalog], daemon_generation: int):
        self._factory = catalog_factory
        self._generation = daemon_generation

    def _state(self, catalog: Catalog, job_id: str, *, resume_pending_pause: bool = False) -> dict:
        db = catalog.connection
        owner = catalog.current_daemon_fence()
        if owner is None or owner.generation != self._generation:
            raise CatalogError("boundary_owner_changed")
        job = dict(catalog.get_automatic_job(job_id))
        management = catalog.job_management_state(job_id)
        if (
            catalog.get_import_policy(job_id) is not None
            or management["retired_at"] is not None
            or job["status"] not in {"waiting_media", "paused", "completed"}
        ):
            raise CatalogError("boundary_job_unavailable")
        if db.execute(
            "SELECT 1 FROM daemon_operations WHERE state IN ('running','recovery_required') UNION ALL SELECT 1 FROM hardware_command_executions WHERE state<>'quiesced' LIMIT 1"
        ).fetchone():
            raise CatalogError("boundary_hardware_busy")
        if db.execute(
            "SELECT 1 FROM managed_source_job_fences WHERE job_id=? UNION ALL SELECT 1 FROM job_incremental_pending_extensions WHERE job_id=? LIMIT 1",
            (job_id, job_id),
        ).fetchone():
            raise CatalogError("boundary_job_fenced")
        rows = [dict(row) for row in catalog.list_automatic_cassettes(job_id)]
        prefix, suffix = [], []
        for row in rows:
            if row["status"] == "completed" and not suffix:
                prefix.append(row)
            else:
                if (
                    row["status"] not in {"pending", "waiting_media"}
                    or row["operation"] != "format"
                    or any(
                        row[key] is not None
                        for key in ("started_at", "completed_at", "tape_id", "block_id")
                    )
                    or row["copied_files"]
                    or row["copied_bytes"]
                    or db.execute(
                        "SELECT 1 FROM daemon_operations WHERE job_id=? AND cassette_sequence=?",
                        (job_id, row["sequence"]),
                    ).fetchone()
                ):
                    raise CatalogError("boundary_suffix_started")
                suffix.append(row)
        if not prefix:
            raise CatalogError("boundary_completed_prefix_required")
        boundary = prefix[-1]
        operation = db.execute(
            "SELECT * FROM daemon_operations WHERE job_id=? AND cassette_sequence=? AND kind='archive.native' ORDER BY started_at DESC,rowid DESC LIMIT 1",
            (job_id, boundary["sequence"]),
        ).fetchone()
        if (
            operation is None
            or operation["state"] != "succeeded"
            or operation["finished_at"] is None
            or operation["error_code"] is not None
            or boundary["completed_at"] is None
            or boundary["copied_files"] != boundary["planned_files"]
            or boundary["copied_bytes"] != boundary["planned_bytes"]
        ):
            raise CatalogError("boundary_terminal_evidence_missing")
        block_ids = str(boundary["block_id"] or "").split(",")
        committed = []
        if (
            not boundary["tape_id"]
            or not all(block_ids)
            or len(set(block_ids)) != len(block_ids)
        ):
            raise CatalogError("boundary_catalog_evidence_missing")
        for block_id in block_ids:
            block = db.execute(
                "SELECT * FROM blocks WHERE id=? AND tape_id=? AND status='completed' AND visible=1",
                (block_id, boundary["tape_id"]),
            ).fetchone()
            if block is None:
                raise CatalogError("boundary_catalog_evidence_missing")
            versions = [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM file_versions WHERE block_id=? AND tape_id=? AND visible=1 ORDER BY id",
                    (block_id, boundary["tape_id"]),
                )
            ]
            if (
                len(versions) != block["copied_files"]
                or sum(row["size"] for row in versions) != block["copied_bytes"]
            ):
                raise CatalogError("boundary_catalog_evidence_inexact")
            committed.append({"block": dict(block), "versions": versions})
        if (
            sum(value["block"]["copied_files"] for value in committed)
            != boundary["copied_files"]
            or sum(value["block"]["copied_bytes"] for value in committed)
            != boundary["copied_bytes"]
        ):
            raise CatalogError("boundary_catalog_evidence_inexact")
        commands = [
            dict(row)
            for row in db.execute(
                "SELECT * FROM hardware_command_executions WHERE operation_id=? ORDER BY created_at,rowid",
                (operation["id"],),
            )
        ]
        # Native mount/unmount are owned broker LTFS sessions, not these command
        # rows. A succeeded native operation is recorded only after the runtime
        # validates finalization and then observes the exact post-eject probe.
        # Do not invent synthetic mount/unmount command evidence here.
        for kind in ("unload",):
            matching = [row for row in commands if row["command_kind"] == kind]
            if not matching or any(
                row["state"] != "quiesced"
                or row["exit_outcome"] != "completed"
                or row["terminal_exit_code"] != 0
                or row["quiesced_at"] is None
                for row in matching
            ):
                raise CatalogError("boundary_finalization_unproven")
        unload = [row for row in commands if row["command_kind"] == "unload"][-1]
        if not commands or not (
            commands[-1]["command_kind"] == "probe_media"
            and commands[-1]["terminal_exit_code"] == 3
            and commands[-1]["exit_outcome"] == "completed"
            and commands[-1]["quiesced_at"] is not None
            and commands[-1]["created_at"] >= unload["quiesced_at"]
        ):
            raise CatalogError("boundary_eject_unproven")
        epoch = catalog.latest_layout_epoch(job_id)
        sequence_state = dict(catalog.automatic_sequence_state(job_id))
        if sequence_state["state"] == "pause_pending" and not (
            resume_pending_pause
            and management["pause_requested_at"] is not None
            and management["pause_acknowledged_at"] is None
        ):
            raise CatalogError("boundary_pause_pending")
        if (
            sequence_state["layout_epoch"] != epoch["epoch_number"]
            or sequence_state["layout_fingerprint_sha256"]
            != epoch["layout_fingerprint_sha256"]
        ):
            raise CatalogError("boundary_layout_conflict")
        authorities = []
        for row in suffix:
            authority = catalog.format_sequence_authorization(job_id, row["sequence"])
            if authority is None:
                raise CatalogError("boundary_format_authority_missing")
            authorities.append(dict(authority))
        return {
            "job": job,
            "management": management,
            "epoch": epoch,
            "libraries": [
                dict(row) for row in catalog.list_automatic_job_libraries(job_id)
            ],
            "source_libraries": [
                dict(catalog.get_library(row["library_id"]))
                for row in catalog.list_automatic_job_libraries(job_id)
            ],
            "source_evidence": [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM automatic_job_share_evidence WHERE job_id=? ORDER BY library_id COLLATE NOCASE",
                    (job_id,),
                )
            ],
            "policy_records": [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM job_policy_snapshots WHERE job_id=?", (job_id,)
                )
            ],
            "sequence_state": sequence_state,
            "prefix": prefix,
            "suffix": suffix,
            "authorities": authorities,
            "operation": dict(operation),
            "commands": commands,
            "committed_catalog": committed,
            "manifest": [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM automatic_cassette_items WHERE job_id=? ORDER BY sequence,item_sequence",
                    (job_id,),
                )
            ],
        }

    @staticmethod
    def _applied(catalog: Catalog, job_id: str, sequence: int) -> bool:
        return any(
            json.loads(row[0]).get("completed_sequence") == sequence
            for row in catalog.connection.execute(
                "SELECT payload_json FROM job_management_history WHERE job_id=? AND action='job.boundary_replan.applied'",
                (job_id,),
            )
        )

    def capture(self, job_id: str) -> BoundarySnapshot:
        with self._factory() as catalog, catalog.transaction() as db:
            if catalog.pending_boundary_replan_record(job_id) is not None:
                raise CatalogError("boundary_pending_resolution_required")
            state = self._state(catalog, job_id)
            anchor = db.execute(
                "SELECT action,payload_json FROM job_management_history WHERE job_id=? "
                "AND action IN ('job.boundary_replan.discarded','job.boundary_replan.applied',"
                "'job.boundary_replan.waiting_labels') ORDER BY id DESC LIMIT 1", (job_id,),
            ).fetchone()
            source_roots_json = None
            if anchor is not None and anchor["action"] == "job.boundary_replan.discarded":
                baseline = json.loads(anchor["payload_json"])
                if baseline.get("source_baseline_sha256") != hashlib.sha256(
                    _canonical(_source_baseline(state)).encode()
                ).hexdigest():
                    raise CatalogError("boundary_snapshot_stale")
                source_roots_json = _canonical(baseline.get("source_roots", {}))
            sequence = int(state["prefix"][-1]["sequence"])
            if self._applied(catalog, job_id, sequence):
                raise CatalogError("boundary_already_applied")
            if db.execute(
                "SELECT 1 FROM job_incremental_scan_leases WHERE job_id=?", (job_id,)
            ).fetchone():
                raise CatalogError("boundary_scan_busy")
            run_id = "boundary-" + uuid.uuid4().hex
            now = utc_now()
            db.execute(
                "INSERT INTO job_incremental_scan_leases(job_id,run_id,daemon_generation,claimed_at) VALUES(?,?,?,?)",
                (job_id, run_id, self._generation, now),
            )
            catalog._job_history_tx(
                db,
                job_id,
                "boundary-coordinator",
                "job.boundary_replan.claimed",
                "scanning_boundary",
                {
                    "run_id": run_id,
                    "completed_sequence": sequence,
                    "layout_fingerprint_sha256": state["epoch"][
                        "layout_fingerprint_sha256"
                    ],
                    "snapshot_sha256": hashlib.sha256(
                        _canonical(state).encode()
                    ).hexdigest(),
                    # Original layouts stay in immutable epochs. Record the
                    # current working-set identity without copying thousands
                    # of rows into history on every failed retry.
                    "layout_epoch": state["epoch"]["epoch_number"],
                    "working_manifest_files": len(state["manifest"]),
                    "working_manifest_sha256": hashlib.sha256(
                        _canonical(state["manifest"]).encode()
                    ).hexdigest(),
                },
                occurred_at=now,
            )
            return BoundarySnapshot(
                job_id,
                run_id,
                self._generation,
                sequence,
                int(state["management"]["revision"]),
                int(state["epoch"]["epoch_number"]),
                state["epoch"]["layout_fingerprint_sha256"],
                _canonical(state),
                source_roots_json=source_roots_json,
            )

    def release(self, snapshot: BoundarySnapshot, error_code: str) -> None:
        if re.fullmatch(r"[a-z][a-z0-9_]{0,63}", error_code) is None:
            raise CatalogError("boundary_error_code_invalid")
        with self._factory() as catalog, catalog.transaction() as db:
            cursor = db.execute(
                "DELETE FROM job_incremental_scan_leases WHERE job_id=? AND run_id=? AND daemon_generation=?",
                (snapshot.job_id, snapshot.run_id, snapshot.daemon_generation),
            )
            if cursor.rowcount:
                catalog._job_history_tx(
                    db,
                    snapshot.job_id,
                    "boundary-coordinator",
                    "job.boundary_replan.failed",
                    "boundary_" + error_code,
                    {
                        "run_id": snapshot.run_id,
                        "completed_sequence": snapshot.completed_sequence,
                        "error_code": error_code,
                    },
                    occurred_at=utc_now(),
                )

    def _validated_state(
        self, catalog: Catalog, snapshot: BoundarySnapshot, plan: BoundaryPlan
    ) -> dict:
        pending = self._pending(catalog, snapshot.job_id)
        if (
            pending is not None
            and snapshot.pending_candidate_sha256 != pending["candidate_sha256"]
        ):
            raise CatalogError("boundary_pending_resolution_required")
        if pending is None and snapshot.pending_candidate_sha256 is not None:
            raise CatalogError("boundary_pending_evidence_changed")
        if pending is not None and datetime.fromisoformat(
            pending["expires_at"]
        ) <= datetime.now(UTC):
            raise CatalogError("boundary_pending_expired")
        if pending is not None:
            retained_items = sorted(
                _canonical(item)
                for group in ("assignments", "unassigned_batches")
                for batch in pending["plan"][group]
                for item in batch["items"]
            )
            proposed_items = sorted(
                _canonical({**asdict(item), "source_path": str(item.source_path)})
                for batch in (*plan.assignments, *plan.unassigned_batches)
                for item in batch.items
            )
            if proposed_items != retained_items:
                raise CatalogError("boundary_pending_items_changed")
        state = self._state(catalog, snapshot.job_id)
        lease = catalog.connection.execute(
            "SELECT * FROM job_incremental_scan_leases WHERE job_id=?",
            (snapshot.job_id,),
        ).fetchone()
        if (
            snapshot.daemon_generation != self._generation
            or lease is None
            or lease["run_id"] != snapshot.run_id
            or lease["daemon_generation"] != self._generation
            or _canonical(state) != snapshot.state_json
            or plan.completed_sequence != snapshot.completed_sequence
        ):
            raise CatalogError("boundary_snapshot_stale")
        if self._applied(catalog, snapshot.job_id, snapshot.completed_sequence):
            raise CatalogError("boundary_already_applied")
        if [(a.sequence, a.label) for a in plan.assignments] != [
            (row["sequence"], row["physical_label"]) for row in state["suffix"]
        ]:
            raise CatalogError("boundary_target_mapping_changed")
        return state

    def retain_pending(
        self, snapshot: BoundarySnapshot, plan: BoundaryPlan, *,
        verified_roots: Mapping[str, Any] | None = None,
    ) -> dict:
        """Retain the complete overflowing candidate and keep admission fenced.

        Source leases may be released after this call; any later consumption
        must reacquire and reverify them. The job scan lease stays until that
        explicit retry/discard transition, so the old layout cannot run.
        """
        if plan.ready:
            raise CatalogError("boundary_label_deficit_required")
        encoded_plan = asdict(plan)
        for group in (encoded_plan["assignments"], encoded_plan["unassigned_batches"]):
            for batch in group:
                for item in batch["items"]:
                    item["source_path"] = str(item["source_path"])
        payload = {
            "version": 1,
            "run_id": snapshot.run_id,
            "completed_sequence": snapshot.completed_sequence,
            "required_additional_labels": plan.required_additional_labels,
            "candidate_files": sum(len(batch.items) for batch in (*plan.assignments, *plan.unassigned_batches)),
            "candidate_bytes": sum(item.size for batch in (*plan.assignments, *plan.unassigned_batches) for item in batch.items),
            "snapshot": asdict(snapshot),
            "plan": encoded_plan,
            "source_roots": dict(verified_roots or {}),
            "expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat(),
        }
        payload["candidate_sha256"] = hashlib.sha256(
            _canonical(payload).encode()
        ).hexdigest()
        with self._factory() as catalog, catalog.transaction() as db:
            self._validated_state(catalog, snapshot, plan)
            if snapshot.pending_candidate_sha256 is not None:
                previous = self._pending(catalog, snapshot.job_id)
                payload["expires_at"] = previous["expires_at"]
                payload.pop("candidate_sha256")
                payload["candidate_sha256"] = hashlib.sha256(
                    _canonical(payload).encode()
                ).hexdigest()
            catalog._job_history_tx(
                db,
                snapshot.job_id,
                "boundary-coordinator",
                "job.boundary_replan.waiting_labels",
                "boundary_waiting_labels",
                payload,
                occurred_at=utc_now(),
            )
        return {
            "state": "waiting_labels",
            "run_id": snapshot.run_id,
            "completed_sequence": snapshot.completed_sequence,
            "required_additional_labels": plan.required_additional_labels,
            "candidate_sha256": payload["candidate_sha256"],
        }

    def pending(self, job_id: str) -> dict | None:
        """Read durable evidence, including expired candidates, without claiming it."""
        with self._factory() as catalog:
            return self._pending(catalog, job_id)

    @staticmethod
    def pending_expired(pending: dict) -> bool:
        return datetime.fromisoformat(pending["expires_at"]) <= datetime.now(UTC)

    def discard_pending(self, job_id: str, *, candidate_sha256: str, reason: str) -> None:
        """Retire only stale scan evidence, retaining its audit and native gate."""
        with self._factory() as catalog, catalog.transaction():
            self._discard_pending_tx(catalog, job_id, candidate_sha256, reason)

    def _discard_pending_tx(
        self, catalog: Catalog, job_id: str, candidate_sha256: str, reason: str,
    ) -> None:
        if reason not in {"expired", "source_changed"}:
            raise CatalogError("boundary_discard_reason_invalid")
        pending = self._pending(catalog, job_id)
        if pending is None or pending["candidate_sha256"] != candidate_sha256:
            raise CatalogError("boundary_pending_evidence_changed")
        state = self._state(catalog, job_id)
        if reason == "expired" and not self.pending_expired(pending):
            raise CatalogError("boundary_pending_not_expired")
        original = json.loads(pending["snapshot"]["state_json"])
        # File changes are refreshable. Changed source configuration/pins or
        # completed tape evidence must not be silently adopted by a new scan.
        if _source_baseline(state) != _source_baseline(original):
            raise CatalogError("boundary_snapshot_stale")
        db = catalog.connection
        if db.execute("SELECT 1 FROM metadata WHERE key='boundary_replanning_activated_at'").fetchone() is None:
            raise CatalogError("boundary_activation_required")
        if state["suffix"] and not catalog.boundary_replan_required(
            job_id, int(state["suffix"][0]["sequence"]),
        ):
            raise CatalogError("boundary_admission_fence_missing")
        lease = db.execute("SELECT * FROM job_incremental_scan_leases WHERE job_id=?", (job_id,)).fetchone()
        if lease is not None and (
            lease["run_id"] != pending["run_id"]
            or lease["daemon_generation"] != pending["snapshot"]["daemon_generation"]
        ):
            raise CatalogError("boundary_scan_busy")
        db.execute(
            "DELETE FROM job_incremental_scan_leases WHERE job_id=? AND run_id=? AND daemon_generation=?",
            (job_id, pending["run_id"], pending["snapshot"]["daemon_generation"]),
        )
        catalog._job_history_tx(
            db, job_id, "boundary-coordinator", "job.boundary_replan.discarded",
            "boundary_refresh_required", {
                "candidate_sha256": candidate_sha256, "reason": reason,
                "completed_sequence": pending["completed_sequence"],
                "source_baseline_sha256": hashlib.sha256(_canonical(_source_baseline(state)).encode()).hexdigest(),
                "source_roots": pending.get("source_roots", {}),
            }, occurred_at=utc_now(),
        )

    @staticmethod
    def _pending(catalog: Catalog, job_id: str) -> dict | None:
        row = catalog.pending_boundary_replan_record(job_id)
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        digest = payload.pop("candidate_sha256", None)
        if (
            payload.get("version") != 1
            or hashlib.sha256(_canonical(payload).encode()).hexdigest() != digest
        ):
            raise CatalogError("boundary_pending_evidence_invalid")
        return {**payload, "candidate_sha256": digest}

    def _claim_pending_tx(
        self, catalog: Catalog, job_id: str
    ) -> tuple[BoundarySnapshot, dict]:
        pending = self._pending(catalog, job_id)
        if pending is None:
            raise CatalogError("boundary_pending_missing")
        if datetime.fromisoformat(pending["expires_at"]) <= datetime.now(UTC):
            raise CatalogError("boundary_pending_expired")
        state = self._state(catalog, job_id)
        original = json.loads(pending["snapshot"]["state_json"])
        if (
            state["management"]["pause_requested_at"] is not None
            and state["management"]["pause_acknowledged_at"] is not None
            and state["sequence_state"]["state"] == "disabled"
            and state["job"]["status"] in {"waiting_media", "paused"}
        ):
            # An acknowledged pause is a restriction, never renewed permission.
            # Accept only its exact fields; every source, manifest and epoch
            # field must still match the retained scan's original snapshot.
            for key in (
                "pause_requested_at",
                "pause_acknowledged_at",
                "current_checkpoint",
                "updated_at",
            ):
                original["management"][key] = state["management"][key]
            original["job"]["status"] = state["job"]["status"]
            original["sequence_state"]["state"] = "disabled"
            original["sequence_state"]["updated_at"] = state["sequence_state"][
                "updated_at"
            ]
        if _canonical(state) != _canonical(original):
            raise CatalogError("boundary_snapshot_stale")
        db = catalog.connection
        lease = db.execute(
            "SELECT * FROM job_incremental_scan_leases WHERE job_id=?",
            (job_id,),
        ).fetchone()
        if lease is not None and (
            lease["run_id"] != pending["run_id"]
            or lease["daemon_generation"] != pending["snapshot"]["daemon_generation"]
        ):
            raise CatalogError("boundary_scan_busy")
        snapshot = BoundarySnapshot(
            job_id,
            "boundary-" + uuid.uuid4().hex,
            self._generation,
            pending["completed_sequence"],
            int(state["management"]["revision"]),
            int(state["epoch"]["epoch_number"]),
            state["epoch"]["layout_fingerprint_sha256"],
            _canonical(state),
            pending["candidate_sha256"],
        )
        db.execute(
            "INSERT INTO job_incremental_scan_leases(job_id,run_id,daemon_generation,claimed_at) VALUES(?,?,?,?) "
            "ON CONFLICT(job_id) DO UPDATE SET run_id=excluded.run_id,daemon_generation=excluded.daemon_generation,claimed_at=excluded.claimed_at",
            (job_id, snapshot.run_id, self._generation, utc_now()),
        )
        catalog._job_history_tx(
            db, job_id, "boundary-coordinator", "job.boundary_replan.claimed",
            "resuming_boundary", {
                "run_id": snapshot.run_id,
                "completed_sequence": snapshot.completed_sequence,
                "layout_epoch": snapshot.epoch_number,
                "layout_fingerprint_sha256": snapshot.layout_fingerprint_sha256,
                "snapshot_sha256": hashlib.sha256(snapshot.state_json.encode()).hexdigest(),
                "working_manifest_files": len(state["manifest"]),
                "working_manifest_sha256": hashlib.sha256(_canonical(state["manifest"]).encode()).hexdigest(),
                "candidate_sha256": pending["candidate_sha256"],
            },
        )
        return snapshot, pending

    def claim_pending(self, job_id: str) -> tuple[BoundarySnapshot, dict]:
        """Reclaim only the retained candidate, without rescanning or dropping its fence."""
        with self._factory() as catalog, catalog.transaction():
            return self._claim_pending_tx(catalog, job_id)

    def request_resume(
        self, job_id: str, *, actor: str, idempotency_key: str,
        confirmation_label: str | None = None,
    ) -> dict | None:
        """Accept an explicitly authorized Resume before any source or tape I/O.

        The caller owns authentication. This transaction grants no formatting
        authority: every target must already have its exact approved tuple.
        The normal dispatcher performs the work; native admission stays fenced.
        """
        request_sha = hashlib.sha256(_canonical({
            "job_id": job_id, "confirmation_label": confirmation_label,
        }).encode()).hexdigest()
        with self._factory() as catalog, catalog.transaction() as db:
            replay = catalog.management_idempotency_replay(
                actor=actor, idempotency_key=idempotency_key, action="job.boundary_resume",
                target_id=job_id, request_sha256=request_sha,
            )
            if replay is not None:
                return dict(replay)
            if db.execute("SELECT 1 FROM metadata WHERE key='boundary_replanning_activated_at'").fetchone() is None:
                return None
            job = catalog.get_automatic_job(job_id)
            if job["status"] not in {"paused", "waiting_media"} or catalog.get_import_policy(job_id) is not None:
                return None
            cassette = catalog.next_automatic_cassette(job_id)
            pending = self._pending(catalog, job_id)
            expired = pending is not None and self.pending_expired(pending)
            if expired:
                self._discard_pending_tx(catalog, job_id, pending["candidate_sha256"], "expired")
                pending = None
            if pending is None and not expired and (cassette is None or not catalog.boundary_replan_required(job_id, int(cassette["sequence"]))):
                return None
            state = self._state(catalog, job_id, resume_pending_pause=True)
            if confirmation_label is not None and (
                cassette is None or cassette["physical_label"] != confirmation_label
            ):
                raise CatalogError("boundary_confirmation_mismatch")
            if state["sequence_state"]["state"] == "pause_pending":
                # Explicit authenticated Resume only. _state has proved the
                # completed prefix, finalization/eject, untouched suffix,
                # quiescent hardware and exact layout/format authority in this
                # transaction. No running worker remains to acknowledge pause.
                catalog.acknowledge_job_pause(job_id, "unloaded")
                state = self._state(catalog, job_id)
            already_enabled = (
                state["job"]["status"] == "waiting_media"
                and state["sequence_state"]["state"] == "enabled"
                and state["management"]["pause_requested_at"] is None
            )
            if not already_enabled:
                snapshot = None
                if pending is not None:
                    snapshot, pending = self._claim_pending_tx(catalog, job_id)
                elif db.execute("SELECT 1 FROM job_incremental_scan_leases WHERE job_id=?", (job_id,)).fetchone():
                    raise CatalogError("boundary_scan_busy")
                catalog.clear_job_pause(job_id, actor)
                catalog.set_automatic_sequence_enabled(
                    job_id, expected_revision=state["sequence_state"]["revision"],
                    layout_fingerprint_sha256=state["epoch"]["layout_fingerprint_sha256"],
                    actor=actor, enabled_at=utc_now(),
                )
                db.execute("UPDATE automatic_jobs SET status='waiting_media' WHERE id=?", (job_id,))
                if snapshot is not None:
                    self._rebind_pending_tx(catalog, snapshot, pending, actor=actor, transition="resume")
            result = {
                "kind": "boundary.refresh", "state": "accepted", "job_id": job_id,
                "request_id": "boundary-resume-" + hashlib.sha256(
                    _canonical([actor, job_id, idempotency_key]).encode()
                ).hexdigest()[:32],
            }
            catalog._job_history_tx(
                db, job_id, actor, "job.boundary_resume.requested", "boundary_refresh_queued",
                result, occurred_at=utc_now(),
            )
            catalog.record_management_idempotency(
                actor=actor, idempotency_key=idempotency_key, action="job.boundary_resume",
                target_id=job_id, request_sha256=request_sha, response=result,
            )
            return result

    def _rebind_pending_tx(
        self, catalog: Catalog, snapshot: BoundarySnapshot, pending: dict, *,
        actor: str, transition: str, added_labels: tuple[str, ...] = (),
    ) -> None:
        state = self._state(catalog, snapshot.job_id)
        rebound = BoundarySnapshot(
            snapshot.job_id, snapshot.run_id, self._generation, snapshot.completed_sequence,
            int(state["management"]["revision"]), int(state["epoch"]["epoch_number"]),
            state["epoch"]["layout_fingerprint_sha256"], _canonical(state),
        )
        payload = {
            **pending, "snapshot": asdict(rebound), "run_id": rebound.run_id,
            "previous_candidate_sha256": pending["candidate_sha256"],
            "transition": transition, "added_labels": list(added_labels),
        }
        payload.pop("candidate_sha256")
        payload["candidate_sha256"] = hashlib.sha256(_canonical(payload).encode()).hexdigest()
        catalog._job_history_tx(
            catalog.connection, snapshot.job_id, actor, "job.boundary_replan.waiting_labels",
            "boundary_waiting_labels", payload, occurred_at=utc_now(),
        )

    def reserve_pending_labels(
        self,
        job_id: str,
        labels: tuple[str, ...],
        *,
        actor: str,
        authorize_automatic_formatting: bool = False,
        expected_revision: int | None = None,
        request_sha256: str | None = None,
        caller_catalog: Catalog | None = None,
    ) -> dict:
        """Append user-authorized reserves and rebind only an unchanged candidate.

        Candidate items and original expiry remain untouched. Reservation and
        evidence rebinding are one transaction; deliberate disabled state is
        preserved as well as the enabled continuation lineage.
        """
        connection = (
            nullcontext(caller_catalog)
            if caller_catalog is not None
            else self._factory()
        )
        with connection as catalog, catalog.transaction() as db:
            snapshot, pending = self._claim_pending_tx(catalog, job_id)
            old = json.loads(snapshot.state_json)["sequence_state"]
            catalog.reserve_job_labels(
                job_id,
                labels,
                actor=actor,
                authorize_automatic_formatting=authorize_automatic_formatting,
                expected_revision=expected_revision,
                request_sha256=request_sha256,
            )
            db.execute(
                "UPDATE automatic_sequence_state SET state=?,enabled_by=?,enabled_at=? WHERE job_id=?",
                (old["state"], old["enabled_by"], old["enabled_at"], job_id),
            )
            self._rebind_pending_tx(
                catalog, snapshot, pending, actor=actor, transition="labels_added", added_labels=labels,
            )
            return dict(catalog.get_automatic_job(job_id))

    def commit_no_change(
        self,
        snapshot: BoundarySnapshot,
        *,
        scanned_items: tuple[ScanItem, ...],
        managed_evidence: Mapping[str, Mapping[str, Any]],
        managed_source_leases: Mapping[str, str] | None = None,
        managed_source_owner_id: str | None = None,
        managed_source_generation: int = 0,
    ) -> dict:
        """Record a verified terminal scan without inventing a plan or epoch."""
        if scanned_items:
            raise CatalogError("boundary_no_change_requires_empty_scan")
        empty_plan = BoundaryPlan(snapshot.completed_sequence, (), ())
        with self._factory() as catalog, catalog.transaction() as db:
            state = self._validated_state(catalog, snapshot, empty_plan)
            if state["suffix"]:
                raise CatalogError("boundary_no_change_requires_terminal_suffix")
            supplied = {
                key.casefold(): dict(value) for key, value in managed_evidence.items()
            }
            lease_ids = {
                key.casefold(): value
                for key, value in (managed_source_leases or {}).items()
            }
            network = {
                row[0].casefold()
                for row in db.execute(
                    "SELECT link.library_id FROM automatic_job_libraries link "
                    "JOIN libraries library ON library.id=link.library_id "
                    "WHERE link.job_id=? AND library.source_kind='network'",
                    (snapshot.job_id,),
                )
            }
            if (
                set(supplied) != network
                or set(lease_ids) != network
                or (
                    network
                    and (
                        not managed_source_owner_id
                        or type(managed_source_generation) is not int
                        or managed_source_generation < 0
                    )
                )
            ):
                raise CatalogError("boundary_source_evidence_inexact")
            for key, source in supplied.items():
                saved = db.execute(
                    "SELECT * FROM automatic_job_share_evidence "
                    "WHERE job_id=? AND library_id=? COLLATE NOCASE",
                    (snapshot.job_id, key),
                ).fetchone()
                if (
                    saved is None
                    or json.loads(saved["evidence_json"]) != source
                    or not catalog._managed_source_evidence_matches_share_tx(db, source)
                    or not db.execute(
                        "SELECT 1 FROM managed_source_leases WHERE lease_id=? "
                        "AND share_id=? AND consumer_kind='plan' AND owner_id=? "
                        "AND daemon_generation=?",
                        (
                            lease_ids[key],
                            saved["share_id"],
                            managed_source_owner_id,
                            managed_source_generation,
                        ),
                    ).fetchone()
                ):
                    raise CatalogError("boundary_source_evidence_changed")
            now = utc_now()
            result = {
                "state": "applied",
                "outcome": "no_change",
                "run_id": snapshot.run_id,
                "completed_sequence": snapshot.completed_sequence,
                "epoch_number": snapshot.epoch_number,
                "layout_fingerprint_sha256": snapshot.layout_fingerprint_sha256,
                "prior_layout_fingerprint_sha256": snapshot.layout_fingerprint_sha256,
                "next_sequence": None,
            }
            db.execute(
                "UPDATE job_management_state SET revision=revision+1,"
                "current_checkpoint=?,updated_at=? WHERE job_id=?",
                ("boundary_no_change", now, snapshot.job_id),
            )
            catalog._job_history_tx(
                db,
                snapshot.job_id,
                "boundary-coordinator",
                "job.boundary_replan.applied",
                "boundary_no_change",
                result,
                occurred_at=now,
            )
            db.execute(
                "DELETE FROM job_incremental_scan_leases WHERE job_id=? AND run_id=?",
                (snapshot.job_id, snapshot.run_id),
            )
            return result

    def commit(
        self,
        snapshot: BoundarySnapshot,
        plan: BoundaryPlan,
        *,
        creation_plan_id: str,
        managed_evidence: Mapping[str, Mapping[str, Any]],
        managed_source_leases: Mapping[str, str] | None = None,
        managed_source_owner_id: str | None = None,
        managed_source_generation: int = 0,
    ) -> dict:
        if not plan.ready:
            raise CatalogError("boundary_waiting_labels")
        with self._factory() as catalog, catalog.transaction() as db:
            state = self._validated_state(catalog, snapshot, plan)
            draft = db.execute(
                "SELECT * FROM job_plan_drafts WHERE id=?", (creation_plan_id,)
            ).fetchone()
            evidence = catalog.job_extension_evidence(snapshot.job_id)
            if (
                draft is None
                or draft["state"] != "ready"
                or draft["kind"] != "extend"
                or draft["creator"] != "boundary-coordinator"
                or draft["base_job_id"] != snapshot.job_id
                or draft["base_job_revision"] != snapshot.revision
                or draft["media_key"] != state["job"]["media_key"]
                or json.loads(draft["requested_library_ids_json"])
                != evidence["libraries"]
                or draft["base_job_fingerprint_sha256"]
                != evidence["fingerprint_sha256"]
                or draft["expires_at"] <= utc_now()
                or hashlib.sha256(draft["canonical_json"].encode()).hexdigest()
                != draft["digest_sha256"]
            ):
                raise CatalogError("boundary_verified_plan_required")
            active_assignments = [a for a in plan.assignments if a.items]
            plan_cassettes = list(
                db.execute(
                    "SELECT * FROM job_plan_cassettes WHERE plan_id=? ORDER BY sequence",
                    (creation_plan_id,),
                )
            )
            if len(plan_cassettes) != len(plan.assignments):
                raise CatalogError("boundary_plan_mapping_inexact")
            for planned, assignment in zip(plan_cassettes, plan.assignments):
                expected = [
                    (
                        i.library_id,
                        i.relative_path,
                        ltfs_tape_relative_path(i.relative_path),
                        i.size,
                        i.mtime_ns,
                    )
                    for i in assignment.items
                ]
                actual = [
                    tuple(row)
                    for row in db.execute(
                        "SELECT library_id,relative_path,tape_relative_path,size,mtime_ns FROM job_plan_items WHERE plan_id=? AND cassette_sequence=? ORDER BY item_sequence",
                        (creation_plan_id, planned["sequence"]),
                    )
                ]
                if actual != expected or planned["operation"] not in {
                    "format",
                    "reserve",
                }:
                    raise CatalogError("boundary_plan_manifest_inexact")
            known_libraries = {
                row["library_id"]
                for row in catalog.list_automatic_job_libraries(snapshot.job_id)
            }
            supplied = {
                key.casefold(): dict(value) for key, value in managed_evidence.items()
            }
            lease_ids = {
                key.casefold(): value
                for key, value in (managed_source_leases or {}).items()
            }
            network = {
                row[0].casefold()
                for row in db.execute(
                    "SELECT link.library_id FROM automatic_job_libraries link JOIN libraries library ON library.id=link.library_id WHERE link.job_id=? AND library.source_kind='network'",
                    (snapshot.job_id,),
                )
            }
            if (
                set(supplied) != network
                or set(lease_ids) != network
                or (
                    network
                    and (
                        not managed_source_owner_id
                        or type(managed_source_generation) is not int
                        or managed_source_generation < 0
                    )
                )
            ):
                raise CatalogError("boundary_source_evidence_inexact")
            for key, source in supplied.items():
                saved = db.execute(
                    "SELECT * FROM job_plan_share_evidence WHERE plan_id=? AND library_id=? COLLATE NOCASE",
                    (creation_plan_id, key),
                ).fetchone()
                if (
                    saved is None
                    or json.loads(saved["evidence_json"]) != source
                    or not catalog._managed_source_evidence_matches_share_tx(db, source)
                    or not db.execute(
                        "SELECT 1 FROM managed_source_leases WHERE lease_id=? AND share_id=? AND consumer_kind='save' AND owner_id=? AND daemon_generation=?",
                        (
                            lease_ids[key],
                            saved["share_id"],
                            managed_source_owner_id,
                            managed_source_generation,
                        ),
                    ).fetchone()
                ):
                    raise CatalogError("boundary_source_evidence_changed")
            seen = set()
            for assignment in plan.assignments:
                for item in assignment.items:
                    validate_source_relative_path(item.relative_path)
                    key = (item.library_id.casefold(), item.relative_path.casefold())
                    if (
                        item.library_id not in known_libraries
                        or key in seen
                        or type(item.size) is not int
                        or item.size < 0
                        or type(item.mtime_ns) is not int
                        or item.mtime_ns < 0
                    ):
                        raise CatalogError("boundary_manifest_invalid")
                    seen.add(key)
            now = utc_now()
            # Source paths are unique across the job, so clear every validated
            # unused assignment before moving any file between cassettes.
            # The surrounding transaction restores the entire suffix on failure.
            for assignment in plan.assignments:
                db.execute(
                    "DELETE FROM automatic_cassette_items WHERE job_id=? AND sequence=?",
                    (snapshot.job_id, assignment.sequence),
                )
            for assignment in plan.assignments:
                db.execute(
                    "UPDATE automatic_cassettes SET planned_files=?,planned_bytes=? WHERE job_id=? AND sequence=?",
                    (
                        len(assignment.items),
                        sum(i.size for i in assignment.items),
                        snapshot.job_id,
                        assignment.sequence,
                    ),
                )
                db.executemany(
                    "INSERT INTO automatic_cassette_items(job_id,sequence,item_sequence,library_id,relative_path,tape_relative_path,size,mtime_ns) VALUES(?,?,?,?,?,?,?,?)",
                    [
                        (
                            snapshot.job_id,
                            assignment.sequence,
                            n,
                            i.library_id,
                            i.relative_path,
                            ltfs_tape_relative_path(i.relative_path),
                            i.size,
                            i.mtime_ns,
                        )
                        for n, i in enumerate(assignment.items, 1)
                    ],
                )
                if network:
                    db.execute(
                        "INSERT INTO automatic_cassette_share_evidence_sets(job_id,cassette_sequence,creation_plan_id,admitted_at) VALUES(?,?,?,?)",
                        (snapshot.job_id, assignment.sequence, creation_plan_id, now),
                    )
                    for library_id in sorted(
                        {
                            i.library_id
                            for i in assignment.items
                            if i.library_id.casefold() in network
                        }
                    ):
                        db.execute(
                            "INSERT INTO automatic_cassette_share_evidence(job_id,cassette_sequence,library_id,creation_plan_id,share_id,evidence_json,evidence_sha256,admitted_at) SELECT ?,?,library_id,plan_id,share_id,evidence_json,evidence_sha256,? FROM job_plan_share_evidence WHERE plan_id=? AND library_id=? COLLATE NOCASE",
                            (
                                snapshot.job_id,
                                assignment.sequence,
                                now,
                                creation_plan_id,
                                library_id,
                            ),
                        )
            epoch = catalog._insert_layout_epoch_tx(
                db,
                snapshot.job_id,
                kind="extension",
                plan_id=creation_plan_id,
                plan_digest_sha256=draft["digest_sha256"],
                created_at=now,
                target_sequences=tuple(a.sequence for a in plan.assignments),
            )
            old_state = state["sequence_state"]
            continuation_state = old_state["state"]
            if continuation_state == "completed" and active_assignments:
                continuation_state = (
                    "enabled"
                    if old_state["enabled_by"]
                    and old_state["enabled_at"]
                    and state["job"]["status"] != "paused"
                    else "disabled"
                )
            catalog._rebind_automatic_sequence_layout_tx(
                db,
                snapshot.job_id,
                epoch,
                actor="boundary-coordinator",
                changed_at=now,
                request_sha256=draft["digest_sha256"],
                authorize_automatic_formatting=True,
            )
            db.execute(
                "UPDATE automatic_sequence_state SET state=?,enabled_by=?,enabled_at=? WHERE job_id=?",
                (
                    continuation_state,
                    old_state["enabled_by"],
                    old_state["enabled_at"],
                    snapshot.job_id,
                ),
            )
            first = (
                active_assignments[0].sequence
                if active_assignments
                else snapshot.completed_sequence
            )
            paused = (
                state["job"]["status"] == "paused"
                or old_state["state"] == "pause_pending"
            )
            status = (
                "paused"
                if paused
                else ("waiting_media" if active_assignments else "completed")
            )
            db.execute(
                "UPDATE automatic_jobs SET current_sequence=?,status=?,completed_at=?,last_error=NULL WHERE id=?",
                (
                    first,
                    status,
                    now if status == "completed" else None,
                    snapshot.job_id,
                ),
            )
            if active_assignments:
                db.execute(
                    "UPDATE automatic_cassettes SET status=CASE WHEN sequence=? THEN 'waiting_media' ELSE 'pending' END WHERE job_id=? AND sequence>?",
                    (first, snapshot.job_id, snapshot.completed_sequence),
                )
            if status == "completed":
                db.execute(
                    "UPDATE automatic_sequence_state SET state='completed' WHERE job_id=?",
                    (snapshot.job_id,),
                )
            db.execute(
                "UPDATE job_management_state SET revision=revision+1,current_checkpoint=?,updated_at=? WHERE job_id=?",
                ("boundary_replanned", now, snapshot.job_id),
            )
            db.execute(
                "UPDATE job_plan_drafts SET state='consumed',updated_at=?,consumed_at=?,consumed_job_id=?,consumption_key=?,consumption_request_sha256=? WHERE id=?",
                (
                    now,
                    now,
                    snapshot.job_id,
                    snapshot.run_id,
                    draft["digest_sha256"],
                    creation_plan_id,
                ),
            )
            result = {
                "run_id": snapshot.run_id,
                "completed_sequence": snapshot.completed_sequence,
                "epoch_number": int(epoch["epoch_number"]),
                "layout_fingerprint_sha256": epoch["layout_fingerprint_sha256"],
                "prior_layout_fingerprint_sha256": snapshot.layout_fingerprint_sha256,
                "creation_plan_id": creation_plan_id,
                "next_sequence": first if active_assignments else None,
            }
            catalog._job_history_tx(
                db,
                snapshot.job_id,
                "boundary-coordinator",
                "job.boundary_replan.applied",
                "boundary_replanned",
                result,
                occurred_at=now,
            )
            db.execute(
                "DELETE FROM job_incremental_scan_leases WHERE job_id=? AND run_id=?",
                (snapshot.job_id, snapshot.run_id),
            )
            return result
