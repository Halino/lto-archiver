"""Job-pinned source admission across boundary scan and plan publication.

The caller overlaps plan and save contexts because canonical publication
consumes plan leases. Only injected verifiers perform source filesystem I/O;
this adapter owns catalog identity checks and the exact source leases.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from types import MappingProxyType
from typing import Any

from ..catalog import Catalog
from ..errors import CatalogError, ValidationError
from ..managed_sources import canonical_managed_source_evidence
from ..util import validate_id
from .boundary_coordinator import BoundarySources
from .boundary_store import BoundarySnapshot


class BoundarySourceProvider:
    def __init__(
        self,
        catalog_factory: Callable[[], Catalog],
        owner_id: str,
        verify_local: Callable[[dict], tuple[str, str]],
        verify_network: Callable[[str, Mapping[str, Any]], tuple[str, str]],
    ):
        self._factory = catalog_factory
        self._owner_id = owner_id
        self._verify_local = verify_local
        self._verify_network = verify_network

    @contextmanager
    def __call__(
        self, snapshot: BoundarySnapshot, *, phase: str, plan_id: str
    ) -> Iterator[BoundarySources]:
        if phase not in {"plan", "save"}:
            raise ValidationError("invalid boundary source phase")
        validate_id(plan_id, "plan ID")
        state = json.loads(snapshot.state_json)
        libraries = state["source_libraries"]
        selected = {str(library["id"]).casefold(): library for library in libraries}
        linked_ids = [str(row["library_id"]).casefold() for row in state["libraries"]]
        if (
            not libraries
            or len(selected) != len(libraries)
            or list(selected) != linked_ids
        ):
            raise CatalogError("boundary_source_selection_changed")
        network = {
            key
            for key, library in selected.items()
            if str(library.get("source_kind") or "local") == "network"
        }
        evidence = {}
        for row in state["source_evidence"]:
            key = str(row["library_id"]).casefold()
            source = canonical_managed_source_evidence(json.loads(row["evidence_json"]))
            encoded = json.dumps(
                source, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            )
            digest = hashlib.sha256(
                b"lto-managed-source-evidence-v1\0" + encoded.encode("utf-8")
            ).hexdigest()
            if (
                key in evidence
                or str(row["job_id"]).casefold() != snapshot.job_id.casefold()
                or str(row["share_id"]).casefold() != source["share_id"].casefold()
                or encoded != row["evidence_json"]
                or digest != row["evidence_sha256"]
            ):
                raise CatalogError("boundary_source_evidence_changed")
            evidence[key] = source
        if set(evidence) != network:
            raise CatalogError("boundary_source_evidence_inexact")

        leases: dict[str, str] = {}
        consumers: dict[str, str] = {}

        def check(*, require_leases: bool = True) -> None:
            with self._factory() as catalog:
                fence = catalog.current_daemon_fence()
                run = catalog.connection.execute(
                    "SELECT run_id,daemon_generation FROM job_incremental_scan_leases WHERE job_id=?",
                    (snapshot.job_id,),
                ).fetchone()
                if (
                    fence is None
                    or fence.generation != snapshot.daemon_generation
                    or run is None
                    or run["run_id"] != snapshot.run_id
                    or run["daemon_generation"] != snapshot.daemon_generation
                ):
                    raise CatalogError("boundary_source_owner_changed")
                current_links = [
                    dict(row)
                    for row in catalog.list_automatic_job_libraries(snapshot.job_id)
                ]
                current_libraries = [
                    dict(catalog.get_library(row["library_id"]))
                    for row in current_links
                ]
                current_evidence = [
                    dict(row)
                    for row in catalog.connection.execute(
                        "SELECT * FROM automatic_job_share_evidence WHERE job_id=? ORDER BY library_id COLLATE NOCASE",
                        (snapshot.job_id,),
                    )
                ]
                if (
                    current_links != state["libraries"]
                    or current_libraries != libraries
                    or current_evidence != state["source_evidence"]
                    or any(
                        row.get("status", "active") != "active"
                        or not row.get("enabled", True)
                        or str(row.get("source_kind") or "local")
                        not in {"local", "network"}
                        for row in current_libraries
                    )
                ):
                    raise CatalogError("boundary_source_metadata_changed")
                if require_leases:
                    if set(leases) != network:
                        raise CatalogError("boundary_source_lease_lost")
                    for key, lease_id in leases.items():
                        lease = catalog.connection.execute(
                            "SELECT * FROM managed_source_leases WHERE lease_id=?",
                            (lease_id,),
                        ).fetchone()
                        if (
                            lease is None
                            or lease["owner_id"] != self._owner_id
                            or lease["daemon_generation"] != snapshot.daemon_generation
                            or lease["consumer_kind"] != phase
                            or lease["consumer_id"] != consumers[key]
                            or str(lease["share_id"]).casefold()
                            != evidence[key]["share_id"].casefold()
                            or not catalog._managed_source_evidence_matches_share_tx(
                                catalog.connection, evidence[key]
                            )
                        ):
                            raise CatalogError("boundary_source_lease_lost")

        def verify_library(library: dict) -> tuple[str, str]:
            check()
            key = str(library["id"]).casefold()
            if key not in selected or dict(library) != selected[key]:
                raise CatalogError("boundary_source_metadata_changed")
            if key in network:
                # Passing original expected evidence retains release140's
                # proven NFS device-renumbering compatibility inside verifier.
                identity = self._verify_network(
                    str(selected[key]["id"]), dict(evidence[key])
                )
                if identity != (
                    str(selected[key]["source_root"]),
                    str(evidence[key]["source_identity_sha256"]),
                ):
                    raise CatalogError("boundary_source_identity_changed")
            else:
                identity = self._verify_local(dict(selected[key]))
                canonical = selected[key].get("source_canonical_root")
                digest = selected[key].get("source_identity_sha256")
                if (canonical is not None and identity[0] != canonical) or (
                    digest is not None and identity[1] != digest
                ):
                    raise CatalogError("boundary_source_identity_changed")
            check()
            return identity

        try:
            check(require_leases=False)
            for key, source in evidence.items():
                consumer_id = (
                    "boundary-"
                    + hashlib.sha256(
                        f"{snapshot.run_id}\0{plan_id}\0{phase}\0{key}".encode()
                    ).hexdigest()[:32]
                )
                consumers[key] = consumer_id
                with self._factory() as catalog:
                    leases[key] = catalog.acquire_managed_source_lease(
                        source["share_id"],
                        consumer_kind=phase,
                        consumer_id=consumer_id,
                        owner_id=self._owner_id,
                        daemon_generation=snapshot.daemon_generation,
                    )
            for library in libraries:
                verify_library(library)
            check()
            yield BoundarySources(
                verify_library=verify_library,
                managed_evidence=MappingProxyType(
                    {key: MappingProxyType(value) for key, value in evidence.items()}
                ),
                managed_source_leases=MappingProxyType(leases),
                owner_id=self._owner_id,
                daemon_generation=snapshot.daemon_generation,
            )
        finally:
            cleanup_error = None
            for lease_id in leases.values():
                try:
                    with self._factory() as catalog:
                        catalog.release_managed_source_lease(
                            lease_id,
                            owner_id=self._owner_id,
                            daemon_generation=snapshot.daemon_generation,
                        )
                except CatalogError as exc:
                    # Publication consumes plan leases; recovery may already
                    # remove owned leases. Other catalog errors remain visible.
                    absent = False
                    if str(exc) == "managed_source_lease_lost":
                        with self._factory() as catalog:
                            absent = (
                                catalog.connection.execute(
                                    "SELECT 1 FROM managed_source_leases WHERE lease_id=?",
                                    (lease_id,),
                                ).fetchone()
                                is None
                            )
                    if not absent and cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                raise cleanup_error
