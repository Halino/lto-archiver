"""Leased, single-scan boundary publication; no hardware interface.

The lifecycle owner supplies job-pinned source admission contexts. This module
does not decide when to run, resume a paused job, or admit a tape operation.
"""

from __future__ import annotations

import json
import logging
import stat
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from ..catalog import Catalog
from ..errors import ValidationError
from ..media import require_ltfs_profile
from ..models import ScanItem
from .boundary_evidence import build_boundary_plan_evidence
from .boundary_replan import (
    BoundaryCassette,
    plan_pending_suffix,
    scan_boundary_sources,
)
from .boundary_retention import BoundaryDraftRetention
from .boundary_store import BoundarySnapshot, BoundaryStore


@dataclass(frozen=True)
class BoundarySources:
    verify_library: Callable[[dict], tuple[str, str]]
    managed_evidence: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    managed_source_leases: Mapping[str, str] = field(default_factory=dict)
    owner_id: str | None = None
    daemon_generation: int = 0


class SourceContext(Protocol):
    def __call__(
        self, snapshot: BoundarySnapshot, *, phase: str, plan_id: str
    ) -> AbstractContextManager[BoundarySources]: ...


class BoundaryCandidateChanged(ValidationError):
    """A file changed inside already verified source roots; rescan is required."""


class BoundaryReplanCoordinator:
    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        *,
        daemon_generation: int,
        source_context: SourceContext,
    ):
        self._factory = catalog_factory
        self._store = BoundaryStore(catalog_factory, daemon_generation)
        self._sources = source_context

    def refresh(self, job_id: str) -> dict:
        snapshot = self._store.capture(job_id)
        return self._execute(snapshot)

    def resume_pending(self, job_id: str) -> dict:
        snapshot, pending = self._store.claim_pending(job_id)
        try:
            return self._execute(snapshot, pending)
        except BoundaryCandidateChanged:
            return self.refresh_pending(
                job_id, candidate_sha256=pending["candidate_sha256"], reason="source_changed",
            )

    def refresh_pending(self, job_id: str, *, candidate_sha256: str, reason: str) -> dict:
        self._store.discard_pending(job_id, candidate_sha256=candidate_sha256, reason=reason)
        return self.refresh(job_id)

    @staticmethod
    def _verify_items(items: tuple[ScanItem, ...], libraries: tuple[dict, ...]) -> None:
        roots = {
            str(row["id"]).casefold(): Path(row["source_root"]) for row in libraries
        }
        for item in items:
            path = roots[str(item.library_id).casefold()]
            for part in Path(item.relative_path).parts:
                path = path / part
                if path.is_symlink():
                    raise BoundaryCandidateChanged("boundary source path changed")
            try:
                info = path.lstat()
            except FileNotFoundError:
                raise BoundaryCandidateChanged("boundary source file disappeared") from None
            if not stat.S_ISREG(info.st_mode) or item.source_identity != (
                info.st_dev,
                info.st_ino,
                info.st_ctime_ns,
                info.st_size,
                info.st_mtime_ns,
            ):
                raise BoundaryCandidateChanged("boundary source file changed after scan")

    def _execute(self, snapshot: BoundarySnapshot, pending: dict | None = None) -> dict:
        job_id = snapshot.job_id
        plan_id = "PLAN-" + snapshot.run_id
        pending_retained = False
        try:
            state = json.loads(snapshot.state_json)
            libraries = tuple(state["source_libraries"])
            with self._factory() as catalog:
                policy = catalog.get_job_policy_snapshot(job_id)
                base = catalog.job_extension_evidence(job_id)
                profile = require_ltfs_profile(policy["selected_media_profile"])

            roots = {}
            expected_roots = (
                pending.get("source_roots", {}) if pending is not None
                else json.loads(snapshot.source_roots_json) if snapshot.source_roots_json is not None
                else None
            )
            verified_roots = {}

            def verify(sources: BoundarySources, library: dict) -> tuple[str, str]:
                identity = sources.verify_library(library)
                root = Path(library["source_root"])
                info = root.lstat()
                if not stat.S_ISDIR(info.st_mode) or root.resolve() != Path(
                    identity[0]
                ):
                    raise ValidationError("boundary source root changed")
                key = str(library["id"]).casefold()
                observed = identity, info.st_dev, info.st_ino
                pin = {
                    "root": identity[0], "identity": identity[1],
                    "device": info.st_dev, "inode": info.st_ino,
                }
                if (
                    expected_roots is not None
                    and str(library.get("source_kind") or "local") != "network"
                    and expected_roots.get(key) != pin
                ):
                    raise ValidationError("boundary source root identity changed")
                if key in roots and roots[key] != observed:
                    raise ValidationError("boundary source identity changed")
                roots[key] = observed
                verified_roots[key] = pin
                return identity

            with self._sources(snapshot, phase="plan", plan_id=plan_id) as sources:
                if pending is None:
                    with self._factory() as catalog:
                        items = scan_boundary_sources(
                            catalog,
                            tuple(row["id"] for row in libraries),
                            verify_library=lambda library: verify(sources, library),
                            minimum_age_seconds=policy[
                                "minimum_source_file_age_seconds"
                            ],
                            verify_unchanged_content=policy[
                                "content_verification_policy"
                            ]
                            == "full",
                        )
                else:
                    items = tuple(
                        ScanItem(
                            **{
                                **item,
                                "source_path": Path(item["source_path"]),
                                "source_identity": tuple(item["source_identity"]),
                            }
                        )
                        for group in ("assignments", "unassigned_batches")
                        for batch in pending["plan"][group]
                        for item in batch["items"]
                    )
                    for library in libraries:
                        verify(sources, library)
                    self._verify_items(items, libraries)
                plan = plan_pending_suffix(
                    cassettes=tuple(
                        BoundaryCassette(
                            row["sequence"],
                            row["physical_label"],
                            row["status"],
                            row["operation"],
                        )
                        for row in (*state["prefix"], *state["suffix"])
                    ),
                    scanned_items=items,
                    completed_versions=(),
                    usable_bytes=int(profile.ltfs_usable_bytes or 0)
                    - policy["capacity_reserve_bytes"],
                    nominal_capacity_bytes=int(profile.ltfs_usable_bytes or 0),
                )
                if not plan.ready:
                    result = self._store.retain_pending(snapshot, plan, verified_roots=verified_roots)
                    pending_retained = True
                    return result
                if not plan.assignments:
                    for library in libraries:
                        verify(sources, library)
                    self._verify_items(items, libraries)
                    return self._store.commit_no_change(
                        snapshot,
                        scanned_items=items,
                        managed_evidence=sources.managed_evidence,
                        managed_source_leases=sources.managed_source_leases,
                        managed_source_owner_id=sources.owner_id,
                        managed_source_generation=sources.daemon_generation,
                    )
                with self._factory() as catalog:
                    now = datetime.now(UTC)
                    catalog.create_job_plan_draft(
                        plan_id=plan_id,
                        kind="extend",
                        creator="boundary-coordinator",
                        created_at=now.isoformat(),
                        expires_at=(now + timedelta(days=1)).isoformat(),
                        media_key=profile.key,
                        library_ids=tuple(row["id"] for row in libraries),
                        base_job_id=job_id,
                        base_job_revision=snapshot.revision,
                        base_job_fingerprint_sha256=base["fingerprint_sha256"],
                    )
                frozen = build_boundary_plan_evidence(
                    plan,
                    libraries=libraries,
                    policy=policy,
                    base_job={
                        "id": job_id,
                        "revision": snapshot.revision,
                        "fingerprint_sha256": base["fingerprint_sha256"],
                    },
                    managed_evidence=sources.managed_evidence,
                    managed_source_leases=sources.managed_source_leases,
                )
                # Publication consumes plan leases. Acquire save leases first,
                # so managed shares never have an unleased window before commit.
                with self._sources(snapshot, phase="save", plan_id=plan_id) as saving:
                    if dict(saving.managed_evidence) != dict(sources.managed_evidence):
                        raise ValidationError("boundary source evidence changed")
                    with self._factory() as catalog:
                        catalog.complete_job_plan_draft(plan_id, frozen)
                    for library in libraries:
                        verify(saving, library)
                    self._verify_items(items, libraries)
                    return self._store.commit(
                        snapshot,
                        plan,
                        creation_plan_id=plan_id,
                        managed_evidence=saving.managed_evidence,
                        managed_source_leases=saving.managed_source_leases,
                        managed_source_owner_id=saving.owner_id,
                        managed_source_generation=saving.daemon_generation,
                    )
        finally:
            if not pending_retained:
                self._store.release(snapshot, "refresh_failed")
                try:
                    BoundaryDraftRetention(self._factory, snapshot.daemon_generation).retire(
                        job_id, snapshot.run_id,
                    )
                except Exception:  # noqa: BLE001 - cleanup cannot change a committed outcome.
                    # Cleanup is retriable and must not replace a publication
                    # failure or turn a committed layout into a failed result.
                    logging.getLogger(__name__).warning("boundary.draft_cleanup.deferred")
