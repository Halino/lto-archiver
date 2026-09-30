"""Publish real canonical boundary candidates through the Catalog contract."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from ltobackup.catalog import Catalog
from ltobackup.daemon import boundary_evidence
from ltobackup.daemon.boundary_replan import BoundaryAssignment, BoundaryPlan
from ltobackup.errors import ValidationError
from ltobackup.models import ScanItem


class BoundaryEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.catalog = Catalog(self.root / "catalog.db")
        self.catalog.initialize()
        self.addCleanup(self.catalog.close)
        self.catalog.add_library("LIB", "Library", str(self.root))
        self.policy = {
            "capacity_reserve_bytes": 100_000_000,
            "default_media_profile": "LTO-6",
            "minimum_source_file_age_seconds": 0,
            "selected_media_profile": "LTO-6",
            "settings_revision": 1,
            "tape_root_directory": "lto",
        }
        self.base = {"id": "JOB", "revision": 2, "fingerprint_sha256": "a" * 64}

    def publish(self, plan):
        frozen = boundary_evidence.build_boundary_plan_evidence(
            plan,
            libraries=(dict(self.catalog.get_library("LIB")),),
            policy=self.policy,
            base_job=self.base,
        )
        now = datetime.now(UTC)
        self.catalog.create_job_plan_draft(
            plan_id="BOUNDARY1",
            kind="extend",
            creator="boundary-coordinator",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(days=1)).isoformat(),
            media_key="LTO-6",
            library_ids=("LIB",),
            base_job_id="JOB",
            base_job_revision=2,
            base_job_fingerprint_sha256="a" * 64,
        )
        return self.catalog.complete_job_plan_draft("BOUNDARY1", frozen)

    def test_candidate_publishes_with_real_items_and_retains_empty_reserves(self):
        value = ScanItem(self.root / "new", "new", 9, 2, library_id="LIB")
        plan = BoundaryPlan(
            1,
            (
                BoundaryAssignment(2, "TAPE02", (value,)),
                BoundaryAssignment(3, "TAPE03", ()),
            ),
            (),
        )
        saved = self.publish(plan)
        self.assertEqual(saved["state"], "ready")
        self.assertEqual([c["objects"] for c in saved["cassettes"]], [1, 0])
        rows = self.catalog.connection.execute(
            "SELECT relative_path,size,mtime_ns FROM job_plan_items WHERE plan_id='BOUNDARY1'"
        ).fetchall()
        self.assertEqual([tuple(row) for row in rows], [("new", 9, 2)])
        self.assertEqual(
            self.catalog.get_job_plan_policy_snapshot("BOUNDARY1"), self.policy
        )
        canonical = saved["canonical_json"]
        self.assertEqual(
            hashlib.sha256(canonical.encode()).hexdigest(), saved["digest_sha256"]
        )
        self.assertEqual(json.loads(canonical)["base_job"], self.base)

    def test_successful_empty_scan_is_a_real_empty_ready_suffix(self):
        saved = self.publish(
            BoundaryPlan(1, (BoundaryAssignment(2, "TAPE02", ()),), ())
        )
        self.assertEqual(saved["state"], "ready")
        self.assertEqual(saved["cassettes"][0]["objects"], 0)
        self.assertEqual(saved["cassettes"][0]["allocation_bytes"], 0)

    def test_oversized_candidate_is_rejected_before_publication(self):
        value = ScanItem(
            self.root / "large", "large", 3_000_000_000_000, 2, library_id="LIB"
        )
        with self.assertRaises(ValidationError):
            self.publish(
                BoundaryPlan(1, (BoundaryAssignment(2, "TAPE02", (value,)),), ())
            )

    def test_library_not_selected_by_job_cannot_be_published(self):
        value = ScanItem(self.root / "new", "new", 9, 2, library_id="OTHER")
        with self.assertRaises(ValidationError):
            self.publish(
                BoundaryPlan(1, (BoundaryAssignment(2, "TAPE02", (value,)),), ())
            )


if __name__ == "__main__":
    unittest.main()
