from __future__ import annotations

import asyncio
import hashlib
import sqlite3
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, patch

from pydantic import ValidationError

from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.api_models import UpdateIncrementalPolicyRequestV1
from ltobackup.daemon.incremental import (
    IncrementalScanCoordinator,
    IncrementalScheduler,
)
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.management import PlanStale
from ltobackup.daemon.models import (
    MutationAdmissionClosed,
    OperationFence,
    OperationRecord,
)
from ltobackup.errors import CatalogError
from ltobackup.errors import ValidationError as LtoValidationError
from ltobackup.migration.validator import MigrationValidator


class IncrementalCatalogTests(unittest.TestCase):
    def test_pending_invalidation_rolls_back_if_terminal_audit_insert_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                owner = catalog.claim_daemon_owner("daemon-invalidation")
                catalog.retain_incremental_extension(
                    "JOB-1", plan_id="PLAN-OLD", plan_digest_sha256="a" * 64,
                    discovered_files=2, discovered_bytes=20,
                    required_additional_labels=1,
                    created_at="2026-08-29T14:00:00+00:00",
                )
                catalog.claim_incremental_scan_run(
                    "RUN-INVALIDATE", "JOB-1", "manual",
                    daemon_generation=owner.generation,
                    idempotency_key_sha256="b" * 64,
                    recorded_at="2026-08-29T14:01:00+00:00",
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    catalog.finish_incremental_scan_run(
                        "RUN-INVALIDATE", state="plan_stale",
                        daemon_generation=owner.generation,
                        recorded_at="2026-08-29T14:02:00+00:00",
                        next_eligible_at=None, invalidate_pending=True,
                        plan_id="PLAN-OLD", plan_digest_sha256="a" * 64,
                        discovered_files=-1,
                    )
                self.assertEqual("PLAN-OLD", catalog.pending_incremental_extension("JOB-1")["plan_id"])
                self.assertEqual("claimed", catalog.incremental_policy("JOB-1")["latest_event"]["state"])

    def test_incremental_policy_request_is_closed_and_revisioned(self) -> None:
        request = UpdateIncrementalPolicyRequestV1(cadence="daily", expected_revision=3)
        self.assertEqual("daily", request.cadence)
        with self.assertRaises(ValidationError):
            UpdateIncrementalPolicyRequestV1(cadence="hourly", expected_revision=3)
        with self.assertRaises(ValidationError):
            UpdateIncrementalPolicyRequestV1(cadence="off", expected_revision=3, extra=True)

    def _schema_34_native_job(self, root: Path) -> Path:
        database = root / "catalog.db"
        source = root / "source"
        source.mkdir()
        with Catalog(database) as catalog:
            catalog.initialize(target_version=34)
            catalog.add_named_library(
                "LIB-1", "Library one", str(source), str(source), "a" * 64
            )
            catalog.create_automatic_job(
                "JOB-1",
                "LIB-1",
                "TAPE0",
                "AUTO",
                [("AB1234", "AB1234", 1, 10)],
                media_key="LTO-6",
                force_format=True,
            )
        BackupManager(database, root / "backups").prepare_and_initialize()
        return database

    def test_schema_35_migrates_native_job_with_policy_and_immutable_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                self.assertEqual(41, SCHEMA_VERSION)
                policy = catalog.incremental_policy("JOB-1")
                epoch = catalog.latest_layout_epoch("JOB-1")

                self.assertEqual("off", policy["cadence"])
                self.assertEqual(1, policy["revision"])
                self.assertEqual(1, epoch["epoch_number"])
                self.assertEqual("initial", epoch["kind"])
                self.assertEqual(64, len(epoch["layout_fingerprint_sha256"]))
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "immutable_layout_epoch"
                ):
                    catalog.connection.execute(
                        "UPDATE job_layout_epochs SET kind='extension' "
                        "WHERE job_id='JOB-1' AND epoch_number=1"
                    )

    def test_schema_35_validator_requires_incremental_tables_and_path_columns(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.connection.execute(
                    "ALTER TABLE job_layout_targets RENAME TO missing_layout_targets"
                )
                report = MigrationValidator.inspect(catalog, "JOB-1")
                self.assertIn("required-table-missing", report.error_codes)

    def test_scan_run_is_fenced_idempotent_contiguous_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-test")
                digest = hashlib.sha256(b"scan-key").hexdigest()
                first, replayed, admitted = catalog.claim_incremental_scan_run(
                    "RUN-1",
                    "JOB-1",
                    "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=digest,
                    recorded_at="2026-08-29T08:00:00+00:00",
                )
                replay, replayed_again, _ = catalog.claim_incremental_scan_run(
                    "RUN-1",
                    "JOB-1",
                    "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=digest,
                    recorded_at="2026-08-29T08:00:00+00:00",
                )
                self.assertFalse(replayed)
                self.assertTrue(replayed_again)
                self.assertEqual(first["run_id"], replay["run_id"])
                self.assertFalse(admitted)  # planned cassette makes the job busy
                catalog.finish_incremental_scan_run(
                    "RUN-1",
                    state="deferred_busy",
                    daemon_generation=fence.generation,
                    recorded_at="2026-08-29T08:00:01+00:00",
                    next_eligible_at="2026-08-29T08:01:01+00:00",
                )
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "immutable_incremental_scan_event"
                ):
                    catalog.connection.execute(
                        "UPDATE job_incremental_scan_events SET state='failed_safe' "
                        "WHERE run_id='RUN-1' AND event_sequence=2"
                    )

    def test_direct_scan_claim_requires_lowercase_sha_and_current_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-sha-fence")
                epoch = catalog.latest_layout_epoch("JOB-1")
                values = (
                    "JOB-1",
                    "manual",
                    epoch["epoch_number"],
                    epoch["layout_fingerprint_sha256"],
                    "claimed",
                    "2026-08-29T08:00:00.000000+00:00",
                )
                with self.assertRaises(sqlite3.IntegrityError):
                    catalog.connection.execute(
                        "INSERT INTO job_incremental_scan_events("
                        "run_id,event_sequence,job_id,trigger,base_layout_epoch,"
                        "base_layout_fingerprint,idempotency_key_sha256,state,"
                        "daemon_generation,recorded_at) VALUES(?,1,?,?,?,?,?,?,?,?)",
                        (
                            "RUN-UPPER",
                            *values[:4],
                            "A" * 64,
                            values[4],
                            fence.generation,
                            values[5],
                        ),
                    )
                with self.assertRaises(sqlite3.IntegrityError):
                    catalog.connection.execute(
                        "INSERT INTO job_incremental_scan_events("
                        "run_id,event_sequence,job_id,trigger,base_layout_epoch,"
                        "base_layout_fingerprint,idempotency_key_sha256,state,"
                        "daemon_generation,recorded_at) VALUES(?,1,?,?,?,?,?,?,?,?)",
                        (
                            "RUN-STALE",
                            *values[:4],
                            "a" * 64,
                            values[4],
                            fence.generation + 1,
                            values[5],
                        ),
                    )

    def test_completed_native_job_accepts_ordered_zero_payload_reserves(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                catalog.connection.commit()
                before = catalog.latest_layout_epoch("JOB-1")
                catalog.reserve_job_labels(
                    "JOB-1", ("CD5678", "EF9012"), expected_revision=0,
                    actor="admin", authorize_automatic_formatting=True,
                )
                rows = catalog.list_automatic_cassettes("JOB-1")
                after = catalog.latest_layout_epoch("JOB-1")

                self.assertEqual(
                    [(2, "CD5678", "format"), (3, "EF9012", "format")],
                    [
                        (int(row["sequence"]), row["physical_label"], row["operation"])
                        for row in rows[1:]
                    ],
                )
                self.assertNotEqual(
                    before["layout_fingerprint_sha256"],
                    after["layout_fingerprint_sha256"],
                )

    def test_waiting_extension_cannot_be_replaced_by_another_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.retain_incremental_extension(
                    "JOB-1", plan_id="PLAN-A", plan_digest_sha256="a" * 64,
                    discovered_files=1, discovered_bytes=10,
                    required_additional_labels=1,
                    created_at="2026-08-29T08:00:00+00:00",
                )
                catalog.retain_incremental_extension(
                    "JOB-1", plan_id="PLAN-A", plan_digest_sha256="a" * 64,
                    discovered_files=1, discovered_bytes=10,
                    required_additional_labels=1,
                    created_at="2026-08-29T08:00:00+00:00",
                )
                with self.assertRaisesRegex(CatalogError, "incremental_extension_conflict"):
                    catalog.retain_incremental_extension(
                        "JOB-1", plan_id="PLAN-B", plan_digest_sha256="b" * 64,
                        discovered_files=2, discovered_bytes=20,
                        required_additional_labels=2,
                        created_at="2026-08-29T08:01:00+00:00",
                    )
                pending = catalog.pending_incremental_extension("JOB-1")
                self.assertEqual("PLAN-A", pending["plan_id"])
                self.assertEqual("a" * 64, pending["plan_digest_sha256"])

    def test_terminal_event_policy_and_lease_release_are_atomic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-atomic")
                catalog.claim_incremental_scan_run(
                    "RUN-ATOMIC", "JOB-1", "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=hashlib.sha256(b"atomic").hexdigest(),
                    recorded_at="2026-08-29T09:00:00+00:00",
                )
                catalog.connection.execute(
                    "CREATE TRIGGER reject_incremental_policy_update "
                    "BEFORE UPDATE ON job_incremental_policies "
                    "BEGIN SELECT RAISE(ABORT,'injected_policy_failure'); END"
                )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "injected_policy_failure"):
                    catalog.finish_incremental_scan_run(
                        "RUN-ATOMIC", state="deferred_busy",
                        daemon_generation=fence.generation,
                        recorded_at="2026-08-29T09:00:01+00:00",
                        next_eligible_at="2026-08-29T09:01:01+00:00",
                    )
                events = catalog.connection.execute(
                    "SELECT state FROM job_incremental_scan_events "
                    "WHERE run_id='RUN-ATOMIC' ORDER BY event_sequence"
                ).fetchall()
                lease = catalog.connection.execute(
                    "SELECT run_id FROM job_incremental_scan_leases WHERE job_id='JOB-1'"
                ).fetchone()
                self.assertEqual(["claimed"], [row["state"] for row in events])
                self.assertEqual("RUN-ATOMIC", lease["run_id"])

    def test_scan_event_times_are_canonical_utc_and_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-time")
                with self.assertRaisesRegex(LtoValidationError, "canonical UTC"):
                    catalog.claim_incremental_scan_run(
                        "RUN-TIME-BAD", "JOB-1", "manual",
                        daemon_generation=fence.generation,
                        idempotency_key_sha256=hashlib.sha256(b"bad-time").hexdigest(),
                        recorded_at="2026-08-29T10:00:00+01:00",
                    )
                catalog.claim_incremental_scan_run(
                    "RUN-TIME", "JOB-1", "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=hashlib.sha256(b"good-time").hexdigest(),
                    recorded_at="2026-08-29T10:00:00+00:00",
                )
                with self.assertRaisesRegex(LtoValidationError, "monotonic"):
                    catalog.append_incremental_scan_event(
                        "RUN-TIME", "scanning",
                        daemon_generation=fence.generation,
                        recorded_at="2026-08-29T09:59:59+00:00",
                    )

    def test_job_delete_preserves_immutable_layout_and_scan_history(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-delete")
                catalog.claim_incremental_scan_run(
                    "RUN-DELETE", "JOB-1", "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=hashlib.sha256(b"delete").hexdigest(),
                    recorded_at="2026-08-29T11:00:00+00:00",
                )
                catalog.finish_incremental_scan_run(
                    "RUN-DELETE", state="deferred_busy",
                    daemon_generation=fence.generation,
                    recorded_at="2026-08-29T11:00:01+00:00",
                    next_eligible_at="2026-08-29T11:01:01+00:00",
                )
                epoch_before = dict(catalog.connection.execute(
                    "SELECT * FROM job_layout_epochs WHERE job_id='JOB-1'"
                ).fetchone())
                events_before = [dict(row) for row in catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_events WHERE job_id='JOB-1' "
                    "ORDER BY run_id,event_sequence"
                )]
                catalog.update_incremental_policy(
                    "JOB-1",
                    "daily",
                    expected_revision=1,
                    updated_at="2026-08-28T11:00:00+00:00",
                )
                catalog.delete_automatic_job("JOB-1")
                epoch_after = dict(catalog.connection.execute(
                    "SELECT * FROM job_layout_epochs WHERE job_id='JOB-1'"
                ).fetchone())
                events_after = [dict(row) for row in catalog.connection.execute(
                    "SELECT * FROM job_incremental_scan_events WHERE job_id='JOB-1' "
                    "ORDER BY run_id,event_sequence"
                )]
                self.assertEqual(epoch_before, epoch_after)
                self.assertEqual(events_before, events_after)
                self.assertEqual((), catalog.due_incremental_jobs(
                    "2026-08-30T11:00:00+00:00"
                ))
                with self.assertRaisesRegex(CatalogError, "job_not_found"):
                    catalog.incremental_policy("JOB-1")

    def test_resolved_historical_recovery_retry_does_not_block_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-recovery-fold")
                catalog.admit_operation(
                    OperationRecord(
                        id="OP-RECOVERY", kind="catalog.test", state="running",
                        phase=None, idempotency_key="recovery-fold", principal="operator",
                        job_id="JOB-1", cassette_sequence=1,
                        started_at="2026-08-29T12:00:00+00:00", finished_at=None,
                    ),
                    fence,
                    admission_open=True,
                )
                catalog.begin_recovery_attempt(
                    "OP-RECOVERY", 1, fence, trigger="daemon_restart",
                    evidence_sha256="a" * 64, decision="retry_identification",
                    recorded_at="2026-08-29T12:00:01+00:00",
                )
                catalog.finish_recovery_attempt(
                    "OP-RECOVERY", 1, fence, state="retry_scheduled",
                    evidence_sha256="b" * 64, decision="retry_identification",
                    recorded_at="2026-08-29T12:00:02+00:00",
                    next_eligible_at="2026-08-29T12:01:00+00:00",
                )
                catalog.begin_recovery_attempt(
                    "OP-RECOVERY", 2, fence, trigger="scheduled_retry",
                    evidence_sha256="c" * 64, decision="retry_identification",
                    recorded_at="2026-08-29T12:01:01+00:00",
                )
                catalog.finish_recovery_attempt(
                    "OP-RECOVERY", 2, fence, state="succeeded",
                    evidence_sha256="d" * 64, decision="retry_identification",
                    recorded_at="2026-08-29T12:01:02+00:00",
                    next_eligible_at=None,
                )
                catalog.finish_operation(
                    OperationFence("OP-RECOVERY", fence.generation), "succeeded"
                )
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                catalog.connection.commit()
                _, _, admitted = catalog.claim_incremental_scan_run(
                    "RUN-AFTER-RECOVERY", "JOB-1", "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=hashlib.sha256(b"after-recovery").hexdigest(),
                    recorded_at="2026-08-29T12:02:00+00:00",
                )
                self.assertTrue(admitted)

    def test_extension_fingerprint_covers_prior_targets_but_not_mutable_counters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234", "AB1234", "AB1234", "LTFS", "/synthetic/tape"
                )
                catalog.create_block(
                    "BLOCK-1", "LIB-1", "AB1234", "blocks/BLOCK-1", 1, 10
                )
                catalog.complete_block("BLOCK-1")
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed',tape_id='AB1234',"
                    "block_id='BLOCK-1',copied_files=999,copied_bytes=9999 "
                    "WHERE job_id='JOB-1' AND sequence=1"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                with catalog.transaction() as db:
                    epoch = catalog._insert_layout_epoch_tx(
                        db, "JOB-1", kind="extension", plan_id="PLAN-FINGERPRINT",
                        plan_digest_sha256="9" * 64,
                        created_at="2026-08-29T12:30:00+00:00",
                        target_sequences=(1,), target_operations=("append",),
                    )
                payload = epoch["canonical_json"]
                self.assertIn('"prior_targets"', payload)
                self.assertIn('"block_id":"BLOCK-1"', payload)
                self.assertNotIn("copied_files", payload)
                self.assertNotIn("copied_bytes", payload)

    def test_reserve_backed_extension_target_freezes_physical_format_operation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = self._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                with catalog.transaction() as db:
                    catalog._insert_layout_epoch_tx(
                        db,
                        "JOB-1",
                        kind="extension",
                        plan_id="PLAN-RESERVE",
                        plan_digest_sha256="d" * 64,
                        created_at="2026-08-29T14:00:00.000000+00:00",
                        target_sequences=(1,),
                        target_operations=("reserve",),
                    )
                target = catalog.connection.execute(
                    "SELECT operation FROM job_layout_targets "
                    "WHERE job_id='JOB-1' AND epoch_number=2"
                ).fetchone()
                self.assertEqual("format", target["operation"])


class _FakeManagement:
    def __init__(self, plan: dict | None = None) -> None:
        self.plan = plan
        self.scan_calls = 0
        self.extend_calls = []
        self.extend_authorities = []

    async def create_extension_plan(self, job_id: str, *, creator: str, idempotency_key: str):
        self.scan_calls += 1
        if self.plan is None:
            return {"id": "PLAN-NONE", "digest_sha256": "b" * 64, "cassettes": []}
        return dict(self.plan)

    async def extend_job(self, job_id: str, plan_id: str, digest_sha256: str, labels, **kwargs):
        self.extend_calls.append((job_id, plan_id, digest_sha256, tuple(labels)))
        self.extend_authorities.append(kwargs.get("authorize_automatic_formatting", False))
        return {"id": job_id}


class IncrementalCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_stale_source_detected_at_consumption_releases_pending_plan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            plan = {
                "id": "PLAN-SOURCE-STALE", "digest_sha256": "c" * 64,
                "cassettes": [{"operation": "append", "objects": 1, "payload_bytes": 10}],
            }
            with Catalog(database) as catalog:
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed'")
                catalog.connection.commit()
            management = _FakeManagement(plan)
            management.extend_job = AsyncMock(side_effect=PlanStale("plan_stale"))
            coordinator = IncrementalScanCoordinator(
                database, management, daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 30, 14, 1, tzinfo=UTC),
            )
            result = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="source-stale",
            )
            self.assertEqual("plan_stale", result["state"])
            with Catalog(database) as catalog:
                self.assertIsNone(catalog.pending_incremental_extension("JOB-1"))
            self.assertEqual("PLAN-SOURCE-STALE", result["plan_id"])

    async def test_invalid_pending_plan_releases_pointer_preserving_audit_and_epochs(self) -> None:
        for trigger in ("manual", "scheduled", "startup_catchup", "labels_added"):
            for invalid in ("expired", "stale", "digest", "missing", "deadline"):
                with self.subTest(trigger=trigger, invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                    database, generation = self._ready(Path(temporary))
                    with Catalog(database) as catalog:
                        catalog.connection.execute("UPDATE automatic_cassettes SET status='completed'")
                        catalog.connection.execute("UPDATE automatic_jobs SET status='completed'")
                        catalog.connection.commit()
                        catalog.retain_incremental_extension(
                            "JOB-1", plan_id="PLAN-OLD", plan_digest_sha256="a" * 64,
                            discovered_files=2, discovered_bytes=20,
                            required_additional_labels=1,
                            created_at="2026-08-29T14:00:00+00:00",
                        )
                        epoch = catalog.latest_layout_epoch("JOB-1")
                    stale_plan = None if invalid == "missing" else {
                        "id": "PLAN-OLD", "state": "ready" if invalid in {"digest", "deadline"} else invalid,
                        "digest_sha256": "b" * 64 if invalid == "digest" else "a" * 64,
                        "expires_at": "2026-08-30T14:00:00+00:00" if invalid == "deadline" else None,
                    }
                    management = _FakeManagement({
                        "id": "PLAN-FRESH", "digest_sha256": "c" * 64,
                        "cassettes": [{"operation": "format", "objects": 3, "payload_bytes": 30}],
                    })
                    coordinator = IncrementalScanCoordinator(
                        database, management, daemon_generation=lambda: generation,
                        now=lambda: datetime(2026, 8, 30, 14, 1, tzinfo=UTC),
                        pending_plan_loader=lambda _job, _pending: stale_plan,
                    )
                    rejected = await coordinator.run_job(
                        "JOB-1", trigger, actor="operator", idempotency_key="stale",
                    )
                    self.assertEqual("plan_stale", rejected["state"])
                    with Catalog(database) as catalog:
                        self.assertIsNone(catalog.pending_incremental_extension("JOB-1"))
                        self.assertEqual(epoch, catalog.latest_layout_epoch("JOB-1"))
                        self.assertEqual("PLAN-OLD", catalog.incremental_policy("JOB-1")["latest_event"]["plan_id"])
                    fresh = await coordinator.run_job(
                        "JOB-1", "manual", actor="operator", idempotency_key="fresh",
                    )
                    self.assertEqual("waiting_labels", fresh["state"])
                    self.assertEqual("PLAN-FRESH", fresh["plan_id"])
                    self.assertEqual(1, management.scan_calls)

    def _ready(self, root: Path) -> tuple[Path, int]:
        database = IncrementalCatalogTests()._schema_34_native_job(root)
        with Catalog(database) as catalog:
            catalog.initialize()
            fence = catalog.claim_daemon_owner("daemon-coordinator")
        return database, fence.generation

    async def test_busy_job_defers_without_scanning_and_sets_future_eligibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            management = _FakeManagement()
            now = datetime(2026, 8, 29, 9, 0, tzinfo=UTC)
            coordinator = IncrementalScanCoordinator(
                database, management, daemon_generation=lambda: generation,
                now=lambda: now,
            )
            result = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="scan-busy"
            )
            self.assertEqual("deferred_busy", result["state"])
            self.assertEqual(0, management.scan_calls)
            self.assertGreater(result["next_eligible_at"], now.isoformat())

    async def test_waiting_plan_is_reused_after_labels_added_without_rescan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'")
                catalog.connection.commit()
            plan = {
                "id": "PLAN-EXT-1", "digest_sha256": "c" * 64,
                "cassettes": [{"operation": "format", "objects": 1, "payload_bytes": 10}],
            }
            management = _FakeManagement(plan)
            coordinator = IncrementalScanCoordinator(
                database, management, daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 10, 0, tzinfo=UTC),
                pending_plan_loader=lambda _job_id, _pending: plan,
                target_resolver=lambda _job_id, _plan: (1,),
            )
            waiting = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="scan-wait"
            )
            self.assertEqual("waiting_labels", waiting["state"])
            self.assertEqual(1, waiting["required_additional_labels"])
            with Catalog(database) as catalog:
                catalog.reserve_job_labels(
                    "JOB-1", ("CD5678",), expected_revision=0,
                    actor="admin", authorize_automatic_formatting=True,
                )
            queued = await coordinator.run_job(
                "JOB-1", "labels_added", actor="admin", idempotency_key="labels-added",
                authorize_automatic_formatting=True,
            )
            self.assertEqual("extension_queued", queued["state"])
            self.assertEqual(1, management.scan_calls)
            self.assertEqual(("JOB-1", "PLAN-EXT-1", "c" * 64, ()), management.extend_calls[-1])
            self.assertIs(True, management.extend_authorities[-1])

    async def test_partial_labels_added_persists_exact_remaining_deficit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed' "
                    "WHERE job_id='JOB-1'"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                catalog.connection.commit()
            plan = {
                "id": "PLAN-EXT-PARTIAL",
                "digest_sha256": "d" * 64,
                "cassettes": [
                    {"operation": "format", "objects": 1, "payload_bytes": 10},
                    {"operation": "format", "objects": 1, "payload_bytes": 20},
                ],
            }
            management = _FakeManagement(plan)
            coordinator = IncrementalScanCoordinator(
                database,
                management,
                daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 10, 30, tzinfo=UTC),
                pending_plan_loader=lambda _job_id, _pending: plan,
            )
            first = await coordinator.run_job(
                "JOB-1",
                "manual",
                actor="operator",
                idempotency_key="partial-labels-plan",
            )
            self.assertEqual(2, first["required_additional_labels"])
            with Catalog(database) as catalog:
                catalog.reserve_job_labels(
                    "JOB-1", ("CD5678",), expected_revision=0,
                    actor="admin", authorize_automatic_formatting=True,
                )

            partial = await coordinator.run_job(
                "JOB-1",
                "labels_added",
                actor="operator",
                idempotency_key="partial-labels-one",
            )
            replay = await coordinator.run_job(
                "JOB-1",
                "labels_added",
                actor="operator",
                idempotency_key="partial-labels-one",
            )

            self.assertEqual("waiting_labels", partial["state"])
            self.assertEqual(1, partial["required_additional_labels"])
            self.assertEqual(1, replay["required_additional_labels"])
            self.assertEqual(1, management.scan_calls)
            self.assertEqual([], management.extend_calls)
            with Catalog(database) as catalog:
                pending = catalog.pending_incremental_extension("JOB-1")
                policy = catalog.incremental_policy("JOB-1")
            self.assertIsNotNone(pending)
            self.assertEqual(1, pending["required_additional_labels"])
            self.assertEqual(
                1, policy["pending_extension"]["required_additional_labels"]
            )

    async def test_every_noncompleted_state_defers_without_scan_or_plan_mutation(self) -> None:
        for state in ("planned", "waiting_media", "formatting_media", "mounting", "writing", "unmounting", "paused", "failed"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                database, generation = self._ready(Path(temporary))
                with Catalog(database) as catalog:
                    catalog.connection.execute(
                        "UPDATE automatic_jobs SET status=? WHERE id='JOB-1'", (state,)
                    )
                    catalog.connection.commit()
                    before = catalog.latest_layout_epoch("JOB-1")["canonical_json"]
                management = _FakeManagement()
                coordinator = IncrementalScanCoordinator(
                    database,
                    management,
                    daemon_generation=lambda generation=generation: generation,
                    now=lambda: datetime(2026, 8, 29, 11, 0, tzinfo=UTC),
                )
                result = await coordinator.run_job(
                    "JOB-1", "scheduled", actor="scheduler",
                    idempotency_key=f"busy-{state}",
                )
                with Catalog(database) as catalog:
                    after = catalog.latest_layout_epoch("JOB-1")["canonical_json"]
                self.assertEqual("deferred_busy", result["state"])
                self.assertEqual(0, management.scan_calls)
                self.assertEqual(before, after)

    async def test_duplicate_manual_key_and_stale_daemon_lease_are_exactly_once(self) -> None:
        from ltobackup.errors import NoNewSourceFiles

        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'")
                catalog.connection.execute(
                    "INSERT INTO job_incremental_scan_leases(job_id,run_id,daemon_generation,claimed_at) "
                    "VALUES('JOB-1','STALE-RUN',?,?)",
                    (generation, "2026-08-29T10:00:00+00:00"),
                )
                catalog.connection.commit()
                replacement = catalog.claim_daemon_owner("daemon-restarted")
                stale_lease = catalog.connection.execute(
                    "SELECT 1 FROM job_incremental_scan_leases "
                    "WHERE job_id='JOB-1'"
                ).fetchone()
                self.assertIsNone(stale_lease)
            management = _FakeManagement()

            async def no_new_files(*_args, **_kwargs):
                management.scan_calls += 1
                raise NoNewSourceFiles("no new versions")

            management.create_extension_plan = no_new_files
            coordinator = IncrementalScanCoordinator(
                database, management, daemon_generation=lambda: replacement.generation,
                now=lambda: datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
            )
            first = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="exactly-once"
            )
            replay = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="exactly-once"
            )
            self.assertEqual("no_changes", first["state"])
            self.assertEqual(first["run_id"], replay["run_id"])
            self.assertEqual(1, management.scan_calls)

    def test_archive_admission_refuses_live_scan_lease_and_stale_event_fence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = IncrementalCatalogTests()._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                fence = catalog.claim_daemon_owner("daemon-admission")
                catalog.claim_incremental_scan_run(
                    "RUN-ADMISSION", "JOB-1", "manual",
                    daemon_generation=fence.generation,
                    idempotency_key_sha256=hashlib.sha256(b"admission").hexdigest(),
                    recorded_at="2026-08-29T13:00:00+00:00",
                )
                candidate = OperationRecord(
                    id="operation-archive", kind="archive.native", state="running",
                    phase=None, idempotency_key="archive-after-scan", principal="operator",
                    job_id="JOB-1", cassette_sequence=1,
                    started_at="2026-08-29T13:00:01+00:00", finished_at=None,
                )
                with self.assertRaises(MutationAdmissionClosed):
                    catalog.admit_operation(candidate, fence, admission_open=True)
                replacement = catalog.claim_daemon_owner("daemon-new")
                latest = catalog.connection.execute(
                    "SELECT recorded_at FROM job_incremental_scan_events "
                    "WHERE run_id='RUN-ADMISSION' "
                    "ORDER BY event_sequence DESC LIMIT 1"
                ).fetchone()
                assert latest is not None
                stale_event_at = (
                    datetime.fromisoformat(str(latest["recorded_at"]))
                    + timedelta(seconds=1)
                ).isoformat()
                with self.assertRaisesRegex(
                    sqlite3.IntegrityError, "incremental_event_fence_invalid"
                ):
                    catalog.append_incremental_scan_event(
                        "RUN-ADMISSION", "scanning",
                        daemon_generation=fence.generation,
                        recorded_at=stale_event_at,
                    )
                self.assertGreater(replacement.generation, fence.generation)

    def test_cassette_lifetime_exceeds_sixty_four_without_hidden_cap(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = IncrementalCatalogTests()._schema_34_native_job(Path(temporary))
            with Catalog(database) as catalog:
                catalog.initialize()
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'")
                catalog.connection.commit()
                first = tuple(f"A{index:05d}" for index in range(64))
                catalog.reserve_job_labels(
                    "JOB-1", first, expected_revision=0,
                    actor="admin", authorize_automatic_formatting=True,
                )
                second = tuple(f"B{index:05d}" for index in range(6))
                catalog.reserve_job_labels(
                    "JOB-1", second, expected_revision=1,
                    actor="admin", authorize_automatic_formatting=True,
                )
                rows = catalog.list_automatic_cassettes("JOB-1")
                self.assertEqual(71, len(rows))
                self.assertEqual(71, int(rows[-1]["sequence"]))
                self.assertEqual("B00005", rows[-1]["physical_label"])

    async def test_missing_waiting_plan_is_stale_and_audit_evidence_is_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'")
                catalog.connection.commit()
                catalog.retain_incremental_extension(
                    "JOB-1", plan_id="MISSING-PLAN", plan_digest_sha256="d" * 64,
                    discovered_files=1, discovered_bytes=10,
                    required_additional_labels=1,
                    created_at="2026-08-29T14:00:00+00:00",
                )
            coordinator = IncrementalScanCoordinator(
                database, _FakeManagement(), daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 14, 1, tzinfo=UTC),
            )
            result = await coordinator.run_job(
                "JOB-1", "labels_added", actor="operator", idempotency_key="missing-plan"
            )
            with Catalog(database) as catalog:
                pending = catalog.pending_incremental_extension("JOB-1")
            self.assertEqual("plan_stale", result["state"])
            self.assertIsNone(pending)
            self.assertEqual("MISSING-PLAN", result["plan_id"])
            self.assertEqual(10, result["discovered_bytes"])

    async def test_manual_tick_while_waiting_labels_replays_pending_without_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                catalog.connection.commit()
                catalog.retain_incremental_extension(
                    "JOB-1", plan_id="PLAN-WAIT", plan_digest_sha256="f" * 64,
                    discovered_files=3, discovered_bytes=30,
                    required_additional_labels=2,
                    created_at="2026-08-29T14:30:00+00:00",
                )
            management = _FakeManagement({
                "id": "PLAN-OTHER", "digest_sha256": "1" * 64,
                "cassettes": [{"operation": "format", "objects": 1, "payload_bytes": 10}],
            })
            coordinator = IncrementalScanCoordinator(
                database, management, daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 14, 31, tzinfo=UTC),
                pending_plan_loader=lambda _job, _pending: {
                    "id": "PLAN-WAIT", "state": "ready", "digest_sha256": "f" * 64,
                },
            )
            result = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="pending-manual"
            )
            with Catalog(database) as catalog:
                pending = catalog.pending_incremental_extension("JOB-1")
            self.assertEqual("waiting_labels", result["state"])
            self.assertEqual("PLAN-WAIT", result["plan_id"])
            self.assertEqual("f" * 64, pending["plan_digest_sha256"])
            self.assertEqual(0, management.scan_calls)

    async def test_startup_catchup_consumes_zero_deficit_pending_without_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            plan = {
                "id": "PLAN-CRASH-READY",
                "digest_sha256": "4" * 64,
                "state": "ready",
                "cassettes": [
                    {"operation": "reserve", "objects": 1, "payload_bytes": 10}
                ],
            }
            with Catalog(database) as catalog:
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed' "
                    "WHERE job_id='JOB-1' AND sequence=1"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                catalog.connection.commit()
                catalog.retain_incremental_extension(
                    "JOB-1",
                    plan_id=plan["id"],
                    plan_digest_sha256=plan["digest_sha256"],
                    discovered_files=1,
                    discovered_bytes=10,
                    required_additional_labels=0,
                    created_at="2026-08-29T14:00:00.000000+00:00",
                )
            management = _FakeManagement(plan)
            coordinator = IncrementalScanCoordinator(
                database,
                management,
                daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 14, 5, tzinfo=UTC),
                pending_plan_loader=lambda _job_id, _pending: plan,
                target_resolver=lambda _job_id, _plan: (1,),
            )
            result = await coordinator.run_job(
                "JOB-1",
                "startup_catchup",
                actor="scheduler",
                idempotency_key="startup-zero-deficit",
            )
            self.assertEqual("extension_queued", result["state"])
            self.assertEqual(0, management.scan_calls)
            self.assertEqual(1, len(management.extend_calls))
            with Catalog(database) as catalog:
                self.assertIsNone(catalog.pending_incremental_extension("JOB-1"))

    async def test_missing_physical_target_fails_closed_and_retains_pending(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'")
                catalog.connection.commit()
            plan = {"id": "PLAN-TARGET", "digest_sha256": "e" * 64,
                    "state": "ready", "cassettes": [{"operation": "append", "objects": 1, "payload_bytes": 10}]}
            management = _FakeManagement(plan)
            coordinator = IncrementalScanCoordinator(
                database, management, daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 15, 0, tzinfo=UTC),
                pending_plan_loader=lambda _job_id, _pending: plan,
            )
            result = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="missing-target"
            )
            with Catalog(database) as catalog:
                pending = catalog.pending_incremental_extension("JOB-1")
            self.assertEqual("failed_safe", result["state"])
            self.assertIsNotNone(pending)

    async def test_typed_no_new_files_outcome_is_locale_independent(self) -> None:
        from ltobackup.errors import NoNewSourceFiles

        class NoChanges(_FakeManagement):
            async def create_extension_plan(self, *args, **kwargs):
                self.scan_calls += 1
                raise NoNewSourceFiles("translated message is irrelevant")

        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute("UPDATE automatic_cassettes SET status='completed' WHERE job_id='JOB-1'")
                catalog.connection.execute("UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'")
                catalog.connection.commit()
            coordinator = IncrementalScanCoordinator(
                database, NoChanges(), daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 16, 0, tzinfo=UTC),
            )
            result = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="no-changes-typed"
            )
            self.assertEqual("no_changes", result["state"])

    async def test_failed_empty_plan_is_never_misclassified_as_no_changes(self) -> None:
        class FailedPlanner(_FakeManagement):
            async def create_extension_plan(self, *args, **kwargs):
                self.scan_calls += 1
                return {
                    "id": "PLAN-FAILED",
                    "state": "failed",
                    "failure_code": "source_scan_corrupt",
                    "cassettes": [],
                }

        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            with Catalog(database) as catalog:
                catalog.connection.execute(
                    "UPDATE automatic_cassettes SET status='completed' "
                    "WHERE job_id='JOB-1'"
                )
                catalog.connection.execute(
                    "UPDATE automatic_jobs SET status='completed' WHERE id='JOB-1'"
                )
                catalog.connection.commit()
            coordinator = IncrementalScanCoordinator(
                database,
                FailedPlanner(),
                daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 16, 30, tzinfo=UTC),
            )
            result = await coordinator.run_job(
                "JOB-1", "manual", actor="operator", idempotency_key="failed-plan"
            )
            self.assertEqual("failed_safe", result["state"])

    async def test_due_tick_isolates_retired_job_race_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database, generation = self._ready(Path(temporary))
            coordinator = IncrementalScanCoordinator(
                database,
                _FakeManagement(),
                daemon_generation=lambda: generation,
                now=lambda: datetime(2026, 8, 29, 17, 0, tzinfo=UTC),
            )
            coordinator.run_job = AsyncMock(  # type: ignore[method-assign]
                side_effect=[CatalogError("job_retired"), {"job_id": "JOB-2"}]
            )
            with patch.object(
                Catalog, "due_incremental_jobs", return_value=("JOB-1", "JOB-2")
            ):
                results = await coordinator.run_due(
                    datetime(2026, 8, 29, 17, 0, tzinfo=UTC)
                )
            self.assertEqual(({"job_id": "JOB-2"},), results)
            self.assertEqual(2, coordinator.run_job.await_count)


class IncrementalSchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def test_stop_cancels_and_awaits_an_inflight_scan_tick(self) -> None:
        started = asyncio.Event()
        cancelled = asyncio.Event()

        class Coordinator:
            async def run_due(self, _now: datetime, *, trigger: str = "scheduled"):
                started.set()
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()

        scheduler = IncrementalScheduler(Coordinator(), interval_seconds=60)
        task = asyncio.create_task(scheduler.run())
        await started.wait()
        scheduler.stop()
        done, _pending = await asyncio.wait({task}, timeout=0.1)
        self.assertEqual({task}, done)
        self.assertTrue(cancelled.is_set())
        self.assertIsNone(task.exception())

    async def test_startup_catchup_runs_once_then_periodic_ticks_and_stops_cleanly(self) -> None:
        class Coordinator:
            def __init__(self) -> None:
                self.triggers: list[str] = []

            async def run_due(self, _now: datetime, *, trigger: str = "scheduled"):
                self.triggers.append(trigger)

        coordinator = Coordinator()
        scheduler = IncrementalScheduler(coordinator, interval_seconds=0.001)
        task = __import__("asyncio").create_task(scheduler.run())
        while len(coordinator.triggers) < 2:
            await __import__("asyncio").sleep(0.001)
        scheduler.stop()
        await task
        self.assertEqual("startup_catchup", coordinator.triggers[0])
        self.assertEqual("scheduled", coordinator.triggers[1])


if __name__ == "__main__":
    unittest.main()
