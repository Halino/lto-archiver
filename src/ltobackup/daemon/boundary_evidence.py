"""Canonical plan publication input for one verified boundary scan.

No rescan, tape access or catalog writes occur here. Empty suffix assignments
are real empty reserves, not fake files or a fabricated consumed plan.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from ..errors import ValidationError
from ..media import require_ltfs_profile
from ..planner import LTFS_CAPACITY_MODEL
from ..util import ltfs_tape_relative_path
from .boundary_replan import BoundaryPlan


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def build_boundary_plan_evidence(
    plan: BoundaryPlan,
    *,
    libraries: tuple[dict, ...],
    policy: Mapping[str, Any],
    base_job: Mapping[str, Any],
    managed_evidence: Mapping[str, Mapping[str, Any]] | None = None,
    managed_source_leases: Mapping[str, str] | None = None,
) -> dict:
    profile = require_ltfs_profile(policy["selected_media_profile"])
    reserve = policy["capacity_reserve_bytes"]
    if type(reserve) is not int or reserve < 0:
        raise ValidationError("invalid boundary capacity reserve")
    usable = int(profile.ltfs_usable_bytes or 0) - reserve
    if usable <= 0 or not plan.ready or not plan.assignments or not libraries:
        raise ValidationError("boundary candidate is not publishable")
    policy_keys = (
        "capacity_reserve_bytes",
        "default_media_profile",
        "minimum_source_file_age_seconds",
        "selected_media_profile",
        "settings_revision",
        "tape_root_directory",
    )
    frozen_policy = {key: policy[key] for key in policy_keys}
    settings_sha = hashlib.sha256(_json(frozen_policy).encode()).hexdigest()
    selected = {str(library["id"]).casefold() for library in libraries}
    if len(selected) != len(libraries):
        raise ValidationError("duplicate boundary library selection")
    canonical_cassettes = []
    for sequence, assignment in enumerate(plan.assignments, 1):
        allocation = LTFS_CAPACITY_MODEL.batch_bytes(assignment.items)
        if allocation > usable:
            raise ValidationError(
                "boundary allocation exceeds calibrated LTFS capacity"
            )
        items = []
        for item in assignment.items:
            if str(item.library_id).casefold() not in selected:
                raise ValidationError("boundary item library is not selected")
            items.append(
                {
                    "library_id": item.library_id,
                    "relative_path": item.relative_path,
                    "tape_relative_path": ltfs_tape_relative_path(item.relative_path),
                    "size": item.size,
                    "mtime_ns": item.mtime_ns,
                }
            )
        canonical_cassettes.append(
            {
                "sequence": sequence,
                "operation": "format",
                "objects": len(items),
                "payload_bytes": sum(item["size"] for item in items),
                "allocation_bytes": allocation,
                "capacity_utilization": allocation / usable,
                "items": items,
            }
        )
    canonical_libraries = []
    for library in libraries:
        library_id = str(library["id"])
        # This fingerprint belongs to this actual boundary scan, not to an
        # unrelated cached GUI scan. Consumers validate this draft's own items.
        scanned = [
            item
            for cassette in canonical_cassettes
            for item in cassette["items"]
            if item["library_id"].casefold() == library_id.casefold()
        ]
        canonical_libraries.append(
            {
                "library_id": library_id,
                "source_root": str(library["source_root"]),
                "scan_revision": int(library.get("scan_revision") or 0),
                "scan_fingerprint_sha256": hashlib.sha256(
                    _json(scanned).encode()
                ).hexdigest(),
            }
        )
    sources = [
        {
            "library_id": str(library["id"]),
            "evidence": dict(managed_evidence[str(library["id"]).casefold()]),
        }
        for library in libraries
        if str(library["id"]).casefold() in (managed_evidence or {})
    ]
    payload = {
        "application_settings": {
            "revision": frozen_policy["settings_revision"],
            "fingerprint_sha256": settings_sha,
        },
        "base_job": dict(base_job),
        "canonical_json_version": 1,
        "plan_schema_version": 1,
        "planner_version": "automatic-ltfs-v1",
        "kind": "extend",
        "media_key": profile.key,
        "library_ids": [library["library_id"] for library in canonical_libraries],
        "libraries": canonical_libraries,
        "cassettes": canonical_cassettes,
    }
    if sources:
        payload["managed_sources"] = sources
    canonical = _json(payload)
    frozen = {
        "canonical_json": canonical,
        "digest_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
        "canonical_json_version": 1,
        "plan_schema_version": 1,
        "planner_version": "automatic-ltfs-v1",
        "application_settings_revision": frozen_policy["settings_revision"],
        "application_settings_fingerprint_sha256": settings_sha,
        "policy_snapshot": frozen_policy,
        "libraries": [
            {"sequence": n, **library}
            for n, library in enumerate(canonical_libraries, 1)
        ],
        "cassettes": [
            {
                **cassette,
                "items": [
                    {"item_sequence": n, **item}
                    for n, item in enumerate(cassette["items"], 1)
                ],
            }
            for cassette in canonical_cassettes
        ],
    }
    if sources:
        frozen.update(
            managed_sources=sources,
            managed_source_leases=dict(managed_source_leases or {}),
        )
    return frozen
