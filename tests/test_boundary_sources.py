"""Real catalog leases around the external source-verification boundary."""

from __future__ import annotations

import hashlib
import importlib
import json
import unittest
from datetime import UTC, datetime, timedelta

from ltobackup.daemon.boundary_evidence import build_boundary_plan_evidence
from ltobackup.daemon.boundary_replan import BoundaryAssignment, BoundaryPlan
from ltobackup.errors import CatalogError, ValidationError
from tests import test_boundary_store


class BoundarySourceTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_boundary_store.BoundaryStoreTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.factory = self.fixture.factory
        self.evidence = {}
        self.calls = []
        self.observed_export = "d" * 64
        self.on_verify = lambda: None
        self.policy = {
            "capacity_reserve_bytes": 100_000_000,
            "default_media_profile": "LTO-6",
            "minimum_source_file_age_seconds": 0,
            "selected_media_profile": "LTO-6",
            "settings_revision": 1,
            "tape_root_directory": "lto",
        }
        with self.factory() as catalog:
            for sequence, library_id in enumerate(("NET1", "NET2"), 2):
                share_id = library_id.lower()
                share = catalog.create_managed_share(
                    share_id,
                    library_id,
                    "nfs",
                    json.dumps(
                        {
                            "kind": "nfs",
                            "server": "nas.example.test",
                            "export": "/" + share_id,
                        }
                    ),
                    actor="admin",
                    idempotency_key=share_id,
                    request_fingerprint_sha256="a" * 64,
                    desired_state="connected",
                    observed_state="connected",
                )
                catalog.record_managed_share_observation(
                    share_id,
                    actor="daemon",
                    observed_state="connected",
                    safe_error_code=None,
                    mount_identity_sha256="c" * 64,
                    mounted_config_revision=1,
                    mounted_credential_generation=0,
                    checked_at="2026-09-12T10:00:00+00:00",
                )
                evidence = {
                    "kind": "managed_share",
                    "share_id": share_id,
                    "resource_revision": share["revision"],
                    "config_revision": 1,
                    "credential_generation": 0,
                    "mount_identity_sha256": "c" * 64,
                    "read_only": True,
                    "filesystem_type": "nfs4",
                    "source_sha256": "d" * 64,
                    "admitted_endpoints_sha256": "e" * 64,
                    "relative_subpath": "",
                    "source_identity_sha256": "f" * 64,
                }
                root = self.fixture.root / share_id
                root.mkdir()
                catalog.add_named_network_library(
                    library_id,
                    library_id,
                    str(root),
                    "f" * 64,
                    share_id,
                    "",
                    expected_share_revision=share["revision"],
                    binding_evidence=evidence,
                )
                self.evidence[library_id.casefold()] = evidence
                with catalog.transaction() as db:
                    db.execute(
                        "INSERT INTO automatic_job_libraries(job_id,library_id,sequence) VALUES('JOB1',?,?)",
                        (library_id, sequence),
                    )
            self._draft(catalog, "ORIGINAL")
            with catalog.transaction() as db:
                for library_id, evidence in self.evidence.items():
                    encoded = json.dumps(
                        evidence, sort_keys=True, separators=(",", ":")
                    )
                    digest = hashlib.sha256(
                        b"lto-managed-source-evidence-v1\0" + encoded.encode()
                    ).hexdigest()
                    db.execute(
                        "INSERT INTO automatic_job_share_evidence(job_id,library_id,creation_plan_id,share_id,evidence_json,evidence_sha256,admitted_at) VALUES('JOB1',?,'ORIGINAL',?,?,?,'2026-09-12T10:00:00+00:00')",
                        (library_id.upper(), evidence["share_id"], encoded, digest),
                    )

    def _draft(self, catalog, plan_id):
        now = datetime.now(UTC)
        base = catalog.job_extension_evidence("JOB1")
        catalog.create_job_plan_draft(
            plan_id=plan_id,
            kind="extend",
            creator="boundary-coordinator",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(days=1)).isoformat(),
            media_key="LTO-6",
            library_ids=("LIB1", "NET1", "NET2"),
            base_job_id="JOB1",
            base_job_revision=base["revision"],
            base_job_fingerprint_sha256=base["fingerprint_sha256"],
        )
        return base

    def provider(self):
        name = "ltobackup.daemon.boundary_sources"
        self.assertIsNotNone(
            importlib.util.find_spec(name), "boundary source adapter missing"
        )
        return importlib.import_module(name).BoundarySourceProvider(
            self.factory,
            owner_id="boundary-owner",
            verify_local=self.verify_local,
            verify_network=self.verify_network,
        )

    def verify_local(self, library):
        self.calls.append(("local", library["id"]))
        return library["source_root"], "a" * 64

    def verify_network(self, library_id, evidence):
        self.calls.append((library_id, dict(evidence)))
        rows = self.leases()
        # Every managed job source is leased before any verifier performs I/O.
        self.assertEqual({row["share_id"] for row in rows}, {"net1", "net2"})
        self.assertEqual(evidence, self.evidence[library_id.casefold()])
        self.on_verify()
        if evidence["source_sha256"] != self.observed_export:
            raise ValidationError("export changed")
        with self.factory() as catalog:
            library = catalog.get_library(library_id)
            return library["source_root"], evidence["source_identity_sha256"]

    def leases(self):
        with self.factory() as catalog:
            return [
                dict(row)
                for row in catalog.connection.execute(
                    "SELECT * FROM managed_source_leases ORDER BY share_id,consumer_kind"
                )
            ]

    def test_all_job_sources_use_original_evidence_and_exact_owned_leases(self):
        snapshot = self.fixture.store.capture("JOB1")
        with self.provider()(snapshot, phase="plan", plan_id="BOUNDARY") as sources:
            self.assertEqual(dict(sources.managed_evidence), self.evidence)
            self.assertEqual(set(sources.managed_source_leases), {"net1", "net2"})
            rows = self.leases()
            self.assertEqual(
                {row["lease_id"] for row in rows},
                set(sources.managed_source_leases.values()),
            )
            self.assertTrue(
                all(
                    row["owner_id"] == sources.owner_id == "boundary-owner"
                    for row in rows
                )
            )
            self.assertTrue(
                all(
                    row["daemon_generation"]
                    == snapshot.daemon_generation
                    == sources.daemon_generation
                    for row in rows
                )
            )
            self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.leases(), [])

    def test_missing_original_job_pin_fails_before_verification(self):
        # Construct a genuine job that never received NET2's original pin.
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("DROP TRIGGER trg_automatic_job_share_evidence_no_delete")
            db.execute(
                "DELETE FROM automatic_job_share_evidence WHERE library_id='NET2'"
            )
        snapshot = self.fixture.store.capture("JOB1")
        with (
            self.assertRaises((CatalogError, ValidationError)),
            self.provider()(snapshot, phase="plan", plan_id="BOUNDARY"),
        ):
            self.fail("missing pin admitted")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.leases(), [])

    def test_bad_original_evidence_digest_fails_before_verification(self):
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("DROP TRIGGER trg_automatic_job_share_evidence_no_update")
            db.execute(
                "UPDATE automatic_job_share_evidence SET evidence_sha256=? WHERE library_id='NET2'",
                ("0" * 64,),
            )
        snapshot = self.fixture.store.capture("JOB1")
        with (
            self.assertRaises((CatalogError, ValidationError)),
            self.provider()(snapshot, phase="plan", plan_id="BOUNDARY"),
        ):
            self.fail("bad digest admitted")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.leases(), [])

    def test_export_drift_is_checked_against_original_and_cleans_all_leases(self):
        snapshot = self.fixture.store.capture("JOB1")
        self.observed_export = "9" * 64
        with (
            self.assertRaisesRegex(ValidationError, "export changed"),
            self.provider()(snapshot, phase="plan", plan_id="BOUNDARY"),
        ):
            self.fail("changed export admitted")
        self.assertEqual(self.leases(), [])

    def test_metadata_drift_after_snapshot_fails_before_verification(self):
        snapshot = self.fixture.store.capture("JOB1")
        with self.factory() as catalog, catalog.transaction() as db:
            db.execute("UPDATE libraries SET enabled=0 WHERE id='LIB1'")
        with (
            self.assertRaises((CatalogError, ValidationError)),
            self.provider()(snapshot, phase="plan", plan_id="BOUNDARY"),
        ):
            self.fail("disabled source admitted")
        self.assertEqual(self.calls, [])
        self.assertEqual(self.leases(), [])

    def test_callback_rejects_catalog_source_change(self):
        snapshot = self.fixture.store.capture("JOB1")
        with self.provider()(snapshot, phase="plan", plan_id="BOUNDARY") as sources:
            with self.factory() as catalog, catalog.transaction() as db:
                library = dict(catalog.get_library("LIB1"))
                db.execute(
                    "UPDATE libraries SET source_root='/changed' WHERE id='LIB1'"
                )
            with self.assertRaises((CatalogError, ValidationError)):
                sources.verify_library(library)
        self.assertEqual(self.leases(), [])

    def test_save_overlap_survives_real_publication_consuming_only_plan_leases(self):
        snapshot = self.fixture.store.capture("JOB1")
        with self.factory() as catalog:
            base = self._draft(catalog, "BOUNDARY")
        provider = self.provider()
        with (
            provider(snapshot, phase="plan", plan_id="BOUNDARY") as planning,
            provider(snapshot, phase="save", plan_id="BOUNDARY") as saving,
        ):
            self.assertEqual(len(self.leases()), 4)
            frozen = build_boundary_plan_evidence(
                BoundaryPlan(1, (BoundaryAssignment(2, "TAPE02", ()),), ()),
                libraries=tuple(json.loads(snapshot.state_json)["source_libraries"]),
                policy=self.policy,
                base_job={
                    "id": "JOB1",
                    "revision": snapshot.revision,
                    "fingerprint_sha256": base["fingerprint_sha256"],
                },
                managed_evidence=planning.managed_evidence,
                managed_source_leases=planning.managed_source_leases,
            )
            with self.factory() as catalog:
                catalog.complete_job_plan_draft("BOUNDARY", frozen)
            self.assertEqual(
                {row["lease_id"] for row in self.leases()},
                set(saving.managed_source_leases.values()),
            )
            self.assertTrue(
                all(row["consumer_kind"] == "save" for row in self.leases())
            )
            for library in json.loads(snapshot.state_json)["source_libraries"]:
                saving.verify_library(library)
        self.assertEqual(self.leases(), [])

    def test_callback_rejects_lost_run_lease(self):
        snapshot = self.fixture.store.capture("JOB1")
        with self.provider()(snapshot, phase="plan", plan_id="BOUNDARY") as sources:
            with self.factory() as catalog, catalog.transaction() as db:
                library = dict(catalog.get_library("LIB1"))
                db.execute(
                    "UPDATE job_incremental_scan_leases SET run_id='replacement' WHERE job_id='JOB1'"
                )
            with self.assertRaises(CatalogError):
                sources.verify_library(library)
        self.assertEqual(self.leases(), [])

    def test_callback_rejects_changed_daemon_generation(self):
        snapshot = self.fixture.store.capture("JOB1")
        with self.provider()(snapshot, phase="plan", plan_id="BOUNDARY") as sources:
            with self.factory() as catalog:
                library = dict(catalog.get_library("LIB1"))
                catalog.claim_daemon_owner("replacement-owner")
            with self.assertRaises(CatalogError):
                sources.verify_library(library)
        self.assertEqual(self.leases(), [])

    def test_lease_loss_during_external_verification_cannot_yield(self):
        snapshot = self.fixture.store.capture("JOB1")

        def lose_run():
            with self.factory() as catalog, catalog.transaction() as db:
                db.execute(
                    "DELETE FROM job_incremental_scan_leases WHERE job_id='JOB1'"
                )

        self.on_verify = lose_run
        with (
            self.assertRaises(CatalogError),
            self.provider()(snapshot, phase="plan", plan_id="BOUNDARY"),
        ):
            self.fail("lost run admitted")
        self.assertEqual(self.leases(), [])
