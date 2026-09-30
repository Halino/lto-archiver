from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from ltobackup.application import (
    LtoApplication,
    _plan_ltfs_batches,
    _select_ltfs_batch,
    _source_identity,
)
from ltobackup.catalog import SCHEMA_VERSION, Catalog
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.native_frozen import FrozenNativeCassettePlan
from ltobackup.errors import CatalogError, CopyError, ValidationError
from ltobackup.media import lto_media_profiles
from ltobackup.models import VolumeInfo
from ltobackup.settings import (
    DEFAULT_RESERVE_BYTES,
    LTO6_LTFS_DATA_BYTES,
    Settings,
    save_settings,
)
from ltobackup.util import copy_and_hash


def managed_plan_context(
    application: LtoApplication,
    source: Path,
    *,
    library_id: str = "NETWORK",
    share_id: str = "archive",
) -> tuple[dict, tuple[str, str], list[str]]:
    application.add_library(library_id, library_id, str(source))
    identity = _source_identity(source)
    calls: list[str] = []
    with Catalog(application.paths.catalog_file) as catalog:
        share = catalog.create_managed_share(
            share_id,
            share_id,
            "nfs",
            json.dumps(
                {
                    "kind": "nfs",
                    "server": "nas.example.test",
                    "export": f"/{share_id}",
                    "version": "4.2",
                    "timeout_seconds": 60,
                    "retransmissions": 2,
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            actor="admin-1",
            idempotency_key=f"create-{share_id}",
            request_fingerprint_sha256="a" * 64,
        )
        share = catalog.update_managed_share(
            share_id,
            expected_revision=int(share["revision"]),
            actor="admin-1",
            idempotency_key=f"connect-{share_id}",
            request_fingerprint_sha256="b" * 64,
            desired_state="connected",
        )
        catalog.record_managed_share_observation(
            share_id,
            actor="share-daemon",
            observed_state="connected",
            safe_error_code=None,
            mount_identity_sha256="c" * 64,
            mounted_config_revision=1,
            mounted_credential_generation=0,
            checked_at="2026-08-26T12:00:00+00:00",
        )
        catalog.bind_library_to_share(
            library_id,
            share_id,
            "media",
            expected_share_revision=int(share["revision"]),
            actor="admin-1",
            idempotency_key=f"bind-{library_id.casefold()}",
            request_fingerprint_sha256="d" * 64,
        )
        evidence = {
            "kind": "managed_share",
            "share_id": share_id,
            "resource_revision": int(share["revision"]),
            "config_revision": 1,
            "credential_generation": 0,
            "mount_identity_sha256": "c" * 64,
            "read_only": True,
            "filesystem_type": "nfs4",
            "source_sha256": "e" * 64,
            "admitted_endpoints_sha256": "f" * 64,
            "relative_subpath": "media",
            "source_identity_sha256": identity[1],
        }
        scan_lease = catalog.acquire_managed_source_lease(
            share_id,
            consumer_kind="scan",
            consumer_id=f"scan-{library_id.casefold()}",
            owner_id="application-test",
            daemon_generation=0,
        )
        catalog.start_named_library_scan(
            library_id,
            managed_source_lease_id=scan_lease,
            managed_source_evidence=evidence,
        )
        catalog.fail_named_library_scan(library_id)
        catalog.release_managed_source_lease(
            scan_lease, owner_id="application-test", daemon_generation=0
        )
        plan_lease = catalog.acquire_managed_source_lease(
            share_id,
            consumer_kind="plan",
            consumer_id=f"plan-{library_id.casefold()}",
            owner_id="application-test",
            daemon_generation=0,
        )

    def reverify() -> tuple[str, str]:
        calls.append(library_id)
        return identity

    return (
        {
            "evidence": evidence,
            "lease_id": plan_lease,
            "reverify": reverify,
        },
        identity,
        calls,
    )


class ApplicationTests(unittest.TestCase):
    def test_ltfs_batch_helpers_require_explicit_nominal_capacity(self) -> None:
        with self.assertRaises(TypeError):
            _plan_ltfs_batches((), 500_000_000_000)
        with self.assertRaises(TypeError):
            _select_ltfs_batch((), 500_000_000_000)

        nominal = 2_500_000_000_000
        sentinel = object()
        with (
            patch(
                "ltobackup.application.capacity_model_for_media",
                return_value=sentinel,
            ) as capacity_model,
            patch(
                "ltobackup.application.plan_tape_batches", return_value=()
            ) as planner,
        ):
            self.assertEqual(
                (),
                _plan_ltfs_batches(
                    (),
                    500_000_000_000,
                    nominal_capacity_bytes=nominal,
                ),
            )
        capacity_model.assert_called_once_with(nominal)
        planner.assert_called_once_with((), 500_000_000_000, capacity_model=sentinel)

    def test_interrupted_named_scan_never_publishes_partial_success_evidence(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            source.joinpath("first.bin").write_bytes(b"first")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            expected_identity = _source_identity(source)
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.start_named_library_scan("LIB1")
            application.scan_named_library(
                "LIB1", expected_source_identity=expected_identity
            )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                baseline = dict(catalog.get_named_library("LIB1"))
                catalog.start_named_library_scan("LIB1")
            source.joinpath("second.bin").write_bytes(b"second")

            with (
                patch.object(
                    Catalog,
                    "complete_named_library_scan",
                    side_effect=SystemExit("simulated abrupt stop"),
                ),
                self.assertRaises(SystemExit),
            ):
                application.scan_named_library(
                    "LIB1", expected_source_identity=expected_identity
                )

            evidence_fields = (
                "last_scan_files",
                "last_scan_bytes",
                "last_scanned_at",
                "scan_revision",
                "scan_fingerprint_sha256",
            )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                interrupted = dict(catalog.get_named_library("LIB1"))
                recovered = catalog.recover_interrupted_named_library_scans()[0]
            self.assertEqual("running", interrupted["scan_state"])
            self.assertEqual(
                tuple(baseline[field] for field in evidence_fields),
                tuple(interrupted[field] for field in evidence_fields),
            )
            self.assertEqual("failed", recovered["scan_state"])
            self.assertEqual(
                tuple(baseline[field] for field in evidence_fields),
                tuple(recovered[field] for field in evidence_fields),
            )

    def test_application_delete_compatibility_method_soft_retires_library(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\")
                catalog.create_block(
                    "BLOCK1", "LIB1", "TAPE1", ".lto-backup/BLOCK1", 1, 3
                )
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK1",
                    "TAPE1",
                    "one.bin",
                    ".lto-backup/BLOCK1/files/one.bin",
                    3,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK1")

            result = application.delete_library("LIB1")

            self.assertEqual("retired", result.get("status"))
            with Catalog(application.paths.catalog_file) as catalog:
                library = catalog.get_named_library("LIB1")
                self.assertEqual("retired", library["status"])
                self.assertEqual(
                    ["BLOCK1"],
                    [
                        row["id"]
                        for row in catalog.list_blocks("LIB1", include_forgotten=True)
                    ],
                )
                self.assertEqual(1, len(catalog.latest_versions("LIB1")))

    def test_initialization_upgrades_schema_thirteen_through_protected_backup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            database = state / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=13)
                catalog.event("schema.thirteen.fixture", {"preserved": True})

            application = LtoApplication(state)
            application.ensure_initialized(min_age_seconds=0)
            application.ensure_initialized(min_age_seconds=0)

            with closing(sqlite3.connect(database)) as connection:
                version = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                event_count = connection.execute(
                    "SELECT COUNT(*) FROM events WHERE action='schema.thirteen.fixture'"
                ).fetchone()[0]
            protected = BackupManager(
                database, state / "backups" / "catalog"
            ).list_backups(protected=True)
            self.assertEqual(str(SCHEMA_VERSION), version)
            self.assertEqual(1, event_count)
            self.assertEqual(
                set(range(13, SCHEMA_VERSION)),
                {record.schema_version for record in protected},
            )
            self.assertTrue(all(record.verified for record in protected))

    def test_initialization_leaves_schema_thirteen_unchanged_if_backup_is_invalid(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            database = state / "catalog.db"
            with Catalog(database) as catalog:
                catalog.initialize(target_version=13)
                catalog.event("schema.thirteen.fixture", {"preserved": True})

            def write_invalid_backup(_catalog, destination):
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"not a sqlite database")
                return destination

            application = LtoApplication(state)
            with (
                patch.object(
                    Catalog,
                    "backup_to",
                    autospec=True,
                    side_effect=write_invalid_backup,
                ) as backup_to,
                self.assertRaisesRegex(CatalogError, "verification failed"),
            ):
                application.ensure_initialized(min_age_seconds=0)

            backup_to.assert_called_once()
            with closing(sqlite3.connect(database)) as connection:
                version = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()[0]
                daemon_table = connection.execute(
                    "SELECT 1 FROM sqlite_master "
                    "WHERE type='table' AND name='daemon_operations'"
                ).fetchone()
                event_count = connection.execute(
                    "SELECT COUNT(*) FROM events WHERE action='schema.thirteen.fixture'"
                ).fetchone()[0]
            self.assertEqual("13", version)
            self.assertIsNone(daemon_table)
            self.assertEqual(1, event_count)

    def test_failed_job_still_reserves_its_libraries_until_reset_or_delete(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            failed = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.update_automatic_cassette(
                    failed["id"], 1, "failed", error="copy failed"
                )
                catalog.update_automatic_job(
                    failed["id"], "failed", current_sequence=1, error="copy failed"
                )

            context = application.automatic_job_creation_context("LIB1", "TAPE0")

            self.assertEqual(
                [failed["id"]],
                [row["id"] for row in context["conflicting_jobs"]],
            )
            with self.assertRaisesRegex(ValidationError, failed["id"]):
                application.create_automatic_job(
                    "LIB1", ["CD5678"], destructive_confirmed=True
                )

    def test_job_creation_context_distinguishes_conflicts_from_independent_saved_jobs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            for library_id in ("LIB1", "LIB2"):
                source = root / library_id
                source.mkdir()
                (source / "payload.bin").write_bytes(library_id.encode("ascii"))
                application.add_library(library_id, library_id, str(source))
            first = application.create_automatic_job(
                "LIB1", ["AB1234"], device_name="TAPE0", destructive_confirmed=True
            )

            conflict = application.automatic_job_creation_context(["lib1"], "tape0")
            independent = application.automatic_job_creation_context(["LIB2"], "TAPE0")

            self.assertEqual(
                [first["id"]], [row["id"] for row in conflict["conflicting_jobs"]]
            )
            self.assertEqual(
                ["LIB1"], conflict["conflicting_jobs"][0]["overlapping_libraries"]
            )
            self.assertEqual([], conflict["saved_on_device"])
            self.assertEqual([], independent["conflicting_jobs"])
            self.assertEqual(
                [first["id"]], [row["id"] for row in independent["saved_on_device"]]
            )

    def test_job_start_context_identifies_next_cassette_and_other_saved_jobs_on_drive(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            jobs = []
            for library_id, label in (("LIB1", "AB1234"), ("LIB2", "CD5678")):
                source = root / library_id
                source.mkdir()
                (source / "payload.bin").write_bytes(library_id.encode("ascii"))
                application.add_library(library_id, library_id, str(source))
                jobs.append(
                    application.create_automatic_job(
                        library_id,
                        [label],
                        device_name="TAPE0",
                        destructive_confirmed=True,
                    )
                )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.update_automatic_job(
                    jobs[0]["id"], "failed", current_sequence=1, error="copy failed"
                )

            context = application.automatic_job_start_context(jobs[1]["id"])

            self.assertEqual(jobs[1]["id"], context["job"]["id"])
            self.assertEqual("CD5678", context["next_cassette"]["physical_label"])
            self.assertEqual(
                [jobs[0]["id"]], [row["id"] for row in context["other_jobs_on_device"]]
            )

    def test_automatic_job_can_explicitly_queue_a_registered_tape_for_reformat(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "new.bin").write_bytes(b"new")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )

            with self.assertRaisesRegex(CatalogError, "gia registrata"):
                application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )

            job = application.create_automatic_job(
                "LIB1",
                ["AB1234"],
                destructive_confirmed=True,
                allow_registered_reuse=True,
            )

            self.assertEqual(1, job["cassettes"][0]["reuse_registered"])

    def test_doctor_rejects_an_empty_mount_converted_to_current_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            application = LtoApplication(Path(temporary) / "state")
            with self.assertRaisesRegex(ValidationError, "mount LTFS"):
                application.doctor("TAPE1", Path(""))

    def test_first_start_initializes_state_and_exposes_dashboard_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            source = root / "source"
            source.mkdir()

            application = LtoApplication(state)
            application.ensure_initialized()
            application.add_library("MEDIA_01", "Media 01", str(source))

            snapshot = application.snapshot()

            self.assertTrue((state / "config.json").is_file())
            self.assertTrue((state / "catalog.db").is_file())
            self.assertEqual(
                DEFAULT_RESERVE_BYTES, snapshot["settings"]["reserve_bytes"]
            )
            self.assertEqual(
                LTO6_LTFS_DATA_BYTES, snapshot["settings"]["tape_capacity_bytes"]
            )
            self.assertEqual("MEDIA_01", snapshot["libraries"][0]["id"])
            self.assertEqual([], snapshot["tapes"])
            self.assertEqual([], snapshot["blocks"])

    def test_startup_migrates_only_the_legacy_capacity_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            (state / "config.json").write_text(
                json.dumps(
                    {
                        "reserve_bytes": 200 * 1024**3,
                        "tape_capacity_bytes": 2_500_000_000_000,
                        "buffer_bytes": 8 * 1024**2,
                        "min_age_seconds": 123,
                        "tape_root_directory": ".lto-backup",
                    }
                ),
                encoding="utf-8",
            )

            application = LtoApplication(state)
            application.ensure_initialized()
            settings = application.snapshot()["settings"]

            self.assertEqual(DEFAULT_RESERVE_BYTES, settings["reserve_bytes"])
            self.assertEqual(LTO6_LTFS_DATA_BYTES, settings["tape_capacity_bytes"])
            self.assertEqual(8 * 1024**2, settings["buffer_bytes"])
            self.assertEqual(123, settings["min_age_seconds"])

    def test_startup_preserves_a_custom_extra_margin(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            custom_reserve = 64 * 1024**3
            (state / "config.json").write_text(
                json.dumps(
                    {
                        "reserve_bytes": custom_reserve,
                        "tape_capacity_bytes": 2_500_000_000_000,
                        "buffer_bytes": 16 * 1024**2,
                        "min_age_seconds": 900,
                        "tape_root_directory": ".lto-backup",
                    }
                ),
                encoding="utf-8",
            )

            application = LtoApplication(state)
            application.ensure_initialized()
            settings = application.snapshot()["settings"]

            self.assertEqual(custom_reserve, settings["reserve_bytes"])
            self.assertEqual(LTO6_LTFS_DATA_BYTES, settings["tape_capacity_bytes"])

    def test_startup_removes_the_previous_200_gib_default_from_current_capacity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            state.mkdir()
            (state / "config.json").write_text(
                json.dumps(
                    {
                        "reserve_bytes": 200 * 1024**3,
                        "tape_capacity_bytes": LTO6_LTFS_DATA_BYTES,
                        "buffer_bytes": 16 * 1024**2,
                        "min_age_seconds": 900,
                        "tape_root_directory": ".lto-backup",
                    }
                ),
                encoding="utf-8",
            )

            application = LtoApplication(state)
            application.ensure_initialized()

            self.assertEqual(0, application.snapshot()["settings"]["reserve_bytes"])

    def test_scan_result_is_ready_for_graphical_display(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            source = root / "source"
            source.mkdir()
            (source / "video.mxf").write_bytes(b"x" * 4096)

            application = LtoApplication(state)
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("MEDIA_01", "Media 01", str(source))

            result = application.scan("MEDIA_01")

            self.assertEqual("MEDIA_01", result["library_id"])
            self.assertEqual(1, result["files"])
            self.assertEqual(4096, result["bytes"])
            self.assertIn("human", result)

    def test_scan_persists_total_library_size_for_the_libraries_screen(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            archived = source / "archived.bin"
            archived.write_bytes(b"a" * 10)
            (source / "new.bin").write_bytes(b"b" * 20)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            archived_stat = archived.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape("TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\")
                catalog.create_block("BLOCK1", "LIB1", "TAPE1", "blocks/BLOCK1", 1, 10)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK1",
                    "TAPE1",
                    "archived.bin",
                    "blocks/BLOCK1/files/archived.bin",
                    10,
                    archived_stat.st_mtime_ns,
                    "archived-hash",
                )
                catalog.complete_block("BLOCK1")

            result = application.scan("LIB1")
            library = application.snapshot()["libraries"][0]

            self.assertEqual(1, result["files"])
            self.assertEqual(20, result["bytes"])
            self.assertEqual(2, result["source_files"])
            self.assertEqual(30, result["source_bytes"])
            self.assertEqual(2, library["last_scan_files"])
            self.assertEqual(30, library["last_scan_bytes"])
            self.assertIsNotNone(library["last_scanned_at"])

    def test_scan_all_libraries_reports_aggregate_progress_and_results(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            for library_id, size in (("LIB_A", 10), ("LIB_B", 20)):
                source = root / library_id
                source.mkdir()
                (source / "file.bin").write_bytes(b"x" * size)
                application.add_library(library_id, library_id, str(source))
            events: list[dict] = []

            result = application.scan_all_libraries(progress=events.append)

            self.assertEqual(2, result["total_libraries"])
            self.assertEqual(2, result["completed_libraries"])
            self.assertEqual(2, result["total_files"])
            self.assertEqual(30, result["total_bytes"])
            self.assertEqual(
                [
                    ("library.scan.start", "LIB_A", 1, 2),
                    ("library.scan.complete", "LIB_A", 1, 2),
                    ("library.scan.start", "LIB_B", 2, 2),
                    ("library.scan.complete", "LIB_B", 2, 2),
                ],
                [
                    (
                        event["event"],
                        event["library_id"],
                        event["index"],
                        event["total"],
                    )
                    for event in events
                ],
            )

    def test_search_result_exposes_physical_cassette_location(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100"
                )
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 123
                )
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "film/master.mxf",
                    ".lto-backup/block1/files/film/master.mxf",
                    123,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("block1")

            rows = application.search_files("master.mxf")

            self.assertEqual(1, len(rows))
            self.assertEqual("CASS-0100", rows[0]["cassette_number"])
            self.assertEqual(
                ".lto-backup/block1/files/film/master.mxf",
                rows[0]["tape_relative_path"],
            )

    def test_offline_browser_is_available_without_source_or_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100"
                )
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 123
                )
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "film/master.mxf",
                    ".lto-backup/block1/files/film/master.mxf",
                    123,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("block1")
            source.rmdir()

            root_children = application.browse_backup_children("LIB1", "")
            film_children = application.browse_backup_children("LIB1", "film")

            self.assertEqual(["film"], [row["name"] for row in root_children])
            self.assertEqual(["master.mxf"], [row["name"] for row in film_children])

    def test_library_analysis_lists_files_and_plans_tape_distribution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            archived = source / "archived.mxf"
            archived.write_bytes(b"a" * 120)
            (source / "new.mov").write_bytes(b"b" * 80)
            archived_stat = archived.stat()
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library 1", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.import_application_settings_once(
                    Settings(min_age_seconds=0), legacy_source_sha256=None
                )
                catalog.register_tape(
                    "TAPE1", "SERIAL1", "Tape 1", "LTFS", "L:\\", "CASS-0100"
                )
                catalog.create_block(
                    "block1", "LIB1", "TAPE1", ".lto-backup/block1", 1, 120
                )
                catalog.record_file_version(
                    "LIB1",
                    "block1",
                    "TAPE1",
                    "archived.mxf",
                    ".lto-backup/block1/files/archived.mxf",
                    120,
                    archived_stat.st_mtime_ns,
                    "a" * 64,
                )
                catalog.complete_block("block1")
                catalog.connection.execute(
                    "UPDATE application_settings SET "
                    "source_change_detection_policy='size_mtime_change' "
                    "WHERE singleton=1"
                )

            result = application.analyze_library("LIB1")

            self.assertEqual(2, result["total_files"])
            self.assertEqual(1, result["archived_files"])
            self.assertEqual(1, result["legacy_uncovered_files"])
            self.assertEqual(
                "size_mtime_change", result["source_change_detection_policy"]
            )
            self.assertEqual(
                "best_effort_metadata", result["source_change_detection_assurance"]
            )
            self.assertEqual(1, result["pending_files"])
            self.assertEqual(1, result["estimated_tapes"])
            self.assertEqual(
                "CASS-0100", result["tape_distribution"][0]["cassette_number"]
            )
            locations = {row["relative_path"]: row for row in result["listing"]}
            self.assertEqual("archived", locations["archived.mxf"]["status"])
            self.assertEqual("CASS-0100", locations["archived.mxf"]["cassette_number"])
            self.assertEqual("pending", locations["new.mov"]["status"])

    def test_automatic_job_plans_multiple_libraries_as_one_cumulative_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            for library_id, size in (("LIB_A", 10), ("LIB_B", 20)):
                source = root / library_id
                source.mkdir()
                (source / "file.bin").write_bytes(b"x" * size)
                application.add_library(library_id, library_id, str(source))

            job = application.create_automatic_job(
                ["LIB_A", "LIB_B"],
                ["AB1234"],
                destructive_confirmed=True,
            )

            self.assertEqual(["LIB_A", "LIB_B"], job["library_ids"])
            self.assertEqual("AUTO", job["mount_path"])
            self.assertEqual(1, job["force_format"])
            self.assertEqual(1, len(job["cassettes"]))
            self.assertEqual(2, job["cassettes"][0]["planned_files"])
            self.assertEqual(30, job["cassettes"][0]["planned_bytes"])

    def test_frozen_plan_is_canonical_and_revision_bound_for_identical_source_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            payload = source / "payload.bin"
            payload.write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            first = application.freeze_automatic_job_plan(
                "LIB1", kind="create", media_key="LTO-6"
            )
            second = application.freeze_automatic_job_plan(
                "LIB1", kind="create", media_key="LTO-6"
            )

            self.assertNotEqual(first["canonical_json"], second["canonical_json"])
            self.assertEqual(
                hashlib.sha256(first["canonical_json"].encode("utf-8")).hexdigest(),
                first["digest_sha256"],
            )
            self.assertEqual(
                hashlib.sha256(second["canonical_json"].encode("utf-8")).hexdigest(),
                second["digest_sha256"],
            )
            self.assertEqual(1, first["canonical_json_version"])
            self.assertEqual(1, first["plan_schema_version"])
            self.assertEqual("automatic-ltfs-v1", first["planner_version"])
            self.assertEqual(1, first["libraries"][0]["scan_revision"])
            self.assertEqual(2, second["libraries"][0]["scan_revision"])
            self.assertEqual(
                first["libraries"][0]["scan_fingerprint_sha256"],
                second["libraries"][0]["scan_fingerprint_sha256"],
            )
            self.assertEqual(first["cassettes"], second["cassettes"])
            self.assertEqual(
                ("LIB1", "payload.bin", 7),
                (
                    first["cassettes"][0]["items"][0]["library_id"],
                    first["cassettes"][0]["items"][0]["relative_path"],
                    first["cassettes"][0]["items"][0]["size"],
                ),
            )


    def test_new_policy_plan_rejects_same_size_mtime_changed_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            payload = source / "payload.bin"
            payload.write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            frozen = application.freeze_automatic_job_plan(
                "LIB1",
                settings=Settings(min_age_seconds=0),
                source_change_detection_policy="size_mtime_change",
            )
            self.assertTrue(application.frozen_job_plan_sources_are_current(frozen))
            before = payload.stat()
            payload.write_bytes(b"changed")
            os.utime(payload, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertFalse(application.frozen_job_plan_sources_are_current(frozen))
    def test_direct_plan_freeze_rejects_missing_network_context_before_scan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "network"
            source.mkdir()
            source.joinpath("payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            _context, identity, calls = managed_plan_context(application, source)

            with (
                patch(
                    "ltobackup.application.analyze_library",
                    side_effect=AssertionError("path scan must not occur"),
                ),
                self.assertRaisesRegex(ValidationError, "managed source context"),
            ):
                application.freeze_automatic_job_plan(
                    "NETWORK", source_identities={"network": identity}
                )

            self.assertEqual([], calls)

    def test_direct_plan_freeze_rejects_extra_or_duplicate_context_before_scan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "network"
            source.mkdir()
            source.joinpath("payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            context, identity, calls = managed_plan_context(application, source)
            cases = (
                {"network": context, "unexpected": context},
                {"NETWORK": context, "network": context},
            )

            for index, contexts in enumerate(cases, 1):
                with (
                    self.subTest(index=index),
                    patch(
                        "ltobackup.application.analyze_library",
                        side_effect=AssertionError("path scan must not occur"),
                    ),
                    self.assertRaisesRegex(ValidationError, "managed source context"),
                ):
                    application.freeze_automatic_job_plan(
                        "NETWORK",
                        source_identities={"network": identity},
                        managed_source_contexts=contexts,
                    )

            self.assertEqual([], calls)

    def test_direct_plan_freeze_rejects_mixed_local_network_context_before_scan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network = root / "network"
            local = root / "local"
            network.mkdir()
            local.mkdir()
            network.joinpath("network.bin").write_bytes(b"network")
            local.joinpath("local.bin").write_bytes(b"local")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            context, network_identity, calls = managed_plan_context(
                application, network
            )
            application.add_library("LOCAL", "Local", str(local))

            with (
                patch(
                    "ltobackup.application.analyze_library",
                    side_effect=AssertionError("path scan must not occur"),
                ),
                self.assertRaisesRegex(ValidationError, "managed source context"),
            ):
                application.freeze_automatic_job_plan(
                    ["NETWORK", "LOCAL"],
                    source_identities={
                        "network": network_identity,
                        "local": _source_identity(local),
                    },
                    managed_source_contexts={"local": context},
                )

            self.assertEqual([], calls)

    def test_direct_plan_freeze_rejects_mixed_binding_evidence_before_scan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "network"
            source.mkdir()
            source.joinpath("payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            context, identity, calls = managed_plan_context(application, source)
            mixed_context = dict(context)
            mixed_context["evidence"] = {
                **context["evidence"],
                "source_sha256": "0" * 64,
            }

            with (
                patch(
                    "ltobackup.application.analyze_library",
                    side_effect=AssertionError("path scan must not occur"),
                ),
                self.assertRaisesRegex(ValidationError, "managed source context"),
            ):
                application.freeze_automatic_job_plan(
                    "NETWORK",
                    source_identities={"network": identity},
                    managed_source_contexts={"network": mixed_context},
                )

            self.assertEqual([], calls)

    def test_direct_plan_freeze_accepts_exact_network_and_legacy_local_contexts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            network = root / "network"
            local = root / "local"
            network.mkdir()
            local.mkdir()
            network.joinpath("network.bin").write_bytes(b"network")
            local.joinpath("local.bin").write_bytes(b"local")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            context, identity, calls = managed_plan_context(application, network)

            network_plan = application.freeze_automatic_job_plan(
                "NETWORK",
                source_identities={"network": identity},
                managed_source_contexts={"network": context},
            )
            application.add_library("LOCAL", "Local", str(local))
            local_plan = application.freeze_automatic_job_plan("LOCAL")

            self.assertEqual(["NETWORK", "NETWORK"], calls)
            self.assertEqual(
                "NETWORK", network_plan["managed_sources"][0]["library_id"]
            )
            self.assertNotIn("managed_sources", local_plan)

    def test_frozen_plan_uses_one_settings_snapshot_for_planning_and_fingerprint(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            planning_settings = Settings(reserve_bytes=0, min_age_seconds=0)
            changed_settings = Settings(reserve_bytes=1, min_age_seconds=0)

            with patch(
                "ltobackup.application.load_settings",
                side_effect=(planning_settings, changed_settings),
            ) as load:
                plan = application.freeze_automatic_job_plan("LIB1")

            settings_json = json.dumps(
                asdict(planning_settings),
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            expected_fingerprint = hashlib.sha256(
                settings_json.encode("utf-8")
            ).hexdigest()
            self.assertEqual(1, load.call_count)
            self.assertEqual(
                expected_fingerprint,
                plan["application_settings_fingerprint_sha256"],
            )
            self.assertEqual(
                expected_fingerprint,
                json.loads(plan["canonical_json"])["application_settings"][
                    "fingerprint_sha256"
                ],
            )

    def test_automatic_job_persists_selected_media_type_and_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            plan = application.plan_automatic_job("LIB1", media_key="LTO-5")
            job = application.create_automatic_job(
                "LIB1", ["AB1234L5"], media_key="LTO-5", destructive_confirmed=True
            )

            self.assertEqual("LTO-5", plan["media_key"])
            self.assertEqual(
                1_430_000_000_000 - DEFAULT_RESERVE_BYTES,
                plan["usable_tape_bytes"],
            )
            self.assertEqual("LTO-5", job["media_key"])

    def test_automatic_planner_uses_profile_ltfs_capacity_for_every_supported_media(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=2_000_000_000_000,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))

            for profile in lto_media_profiles():
                with self.subTest(media_key=profile.key):
                    plan = application.plan_automatic_job("LIB1", media_key=profile.key)
                    self.assertEqual(
                        profile.ltfs_usable_bytes, plan["nominal_tape_bytes"]
                    )
                    self.assertEqual(
                        profile.ltfs_usable_bytes, plan["usable_tape_bytes"]
                    )
                    self.assertEqual(0, plan["reserve_bytes"])
                    cassette = plan["cassettes"][0]
                    self.assertGreater(
                        cassette["capacity_used_bytes"], cassette["total_bytes"]
                    )
                    self.assertEqual(
                        cassette["capacity_used_bytes"] - cassette["total_bytes"],
                        cassette["ltfs_overhead_bytes"],
                    )

    def test_lto4_is_outside_the_supported_job_range(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            with self.assertRaisesRegex(ValidationError, "non supportato.*LTO-4"):
                application.plan_automatic_job("LIB1", media_key="LTO-4")

    def test_automatic_job_keeps_surplus_labels_as_future_reserve(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            job = application.create_automatic_job(
                "LIB1",
                ["AB1234", "CD5678L6", "EF9012"],
                destructive_confirmed=True,
            )

            self.assertEqual(3, job["total_cassettes"])
            self.assertEqual(
                [(1, 1, 7), (2, 0, 0), (3, 0, 0)],
                [
                    (row["sequence"], row["planned_files"], row["planned_bytes"])
                    for row in job["cassettes"]
                ],
            )

    def test_automatic_job_name_can_be_changed_and_survives_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "file.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )

            renamed = application.rename_automatic_job(job["id"], "Archivio marketing")
            refreshed = next(
                row
                for row in application.snapshot()["automatic_jobs"]
                if row["id"] == job["id"]
            )

            self.assertEqual(job["id"], renamed["id"])
            self.assertEqual("Archivio marketing", renamed["display_name"])
            self.assertEqual("Archivio marketing", refreshed["display_name"])

    def test_automatic_job_can_be_deleted_without_deleting_its_library(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )

            deleted = application.delete_automatic_job(job["id"])

            self.assertEqual(job["id"], deleted["id"])
            snapshot = application.snapshot()
            self.assertEqual([], snapshot["automatic_jobs"])
            self.assertEqual("LIB1", snapshot["libraries"][0]["id"])

    def test_completed_job_activates_a_reserved_cassette_for_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=5):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678L6"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block(
                    "BLOCK-1", "LIB1", "AB1234", "blocks/BLOCK-1", 1, 3
                )
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-1",
                    "AB1234",
                    "old.bin",
                    "blocks/BLOCK-1/files/old.bin",
                    3,
                    old_stat.st_mtime_ns,
                    "old-hash",
                )
                catalog.complete_block("BLOCK-1")
                catalog.update_automatic_cassette(job["id"], 1, "completed")
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "new.bin").write_bytes(b"new payload")
            prepared = application.prepare_automatic_job_run(job["id"])

            self.assertEqual("planned", prepared["status"])
            self.assertEqual(1, prepared["cassettes"][1]["planned_files"])
            self.assertEqual(
                len(b"new payload"), prepared["cassettes"][1]["planned_bytes"]
            )

    def test_completed_job_appends_new_files_to_last_tape_without_formatting(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 3)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-OLD",
                    "AB1234",
                    "old.bin",
                    "old/files/old.bin",
                    3,
                    old_stat.st_mtime_ns,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"],
                    1,
                    "completed",
                    tape_id="AB1234",
                    block_id="BLOCK-OLD",
                    copied_files=1,
                    copied_bytes=3,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "new.bin").write_bytes(b"new!")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                prepared = application.prepare_automatic_job_run(job["id"])

            self.assertEqual("planned", prepared["status"])
            self.assertEqual(1, len(prepared["cassettes"]))
            cassette = prepared["cassettes"][0]
            self.assertEqual("append", cassette["operation"])
            self.assertEqual("pending", cassette["status"])
            self.assertEqual(
                (1, 4), (cassette["planned_files"], cassette["planned_bytes"])
            )
            self.assertEqual("AB1234", cassette["tape_id"])

    def test_append_capacity_includes_existing_ltfs_objects_and_block_metadata(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234", "CD5678L6"], destructive_confirmed=True
            )
            capacity = 2_410_000_000_000
            recorded_size = capacity - 7 * 1024**2

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block(
                    "BLOCK-OLD", "LIB1", "AB1234", "old", 1, recorded_size
                )
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-OLD",
                    "AB1234",
                    "old.bin",
                    "old/files/old.bin",
                    recorded_size,
                    old_file.stat().st_mtime_ns,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"],
                    1,
                    "completed",
                    tape_id="AB1234",
                    block_id="BLOCK-OLD",
                    copied_files=1,
                    copied_bytes=recorded_size,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            old_file.unlink()
            (source / "new.bin").write_bytes(b"new")
            prepared = application.prepare_automatic_job_run(job["id"])

            self.assertEqual("completed", prepared["cassettes"][0]["status"])
            self.assertEqual("format", prepared["cassettes"][1]["operation"])
            self.assertEqual(1, prepared["cassettes"][1]["planned_files"])

    def test_append_fills_last_tape_then_uses_reserved_new_tape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"12345678")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 8)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-OLD",
                    "AB1234",
                    "old.bin",
                    "old/files/old.bin",
                    8,
                    old_stat.st_mtime_ns,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"],
                    1,
                    "completed",
                    tape_id="AB1234",
                    block_id="BLOCK-OLD",
                    copied_files=1,
                    copied_bytes=8,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "small.bin").write_bytes(b"12")
            (source / "large.bin").write_bytes(b"3456")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                prepared = application.prepare_automatic_job_run(job["id"])

            first, second = prepared["cassettes"]
            self.assertEqual(
                ("append", "pending", 1, 2),
                (
                    first["operation"],
                    first["status"],
                    first["planned_files"],
                    first["planned_bytes"],
                ),
            )
            self.assertEqual(
                ("format", "pending", 1, 4),
                (
                    second["operation"],
                    second["status"],
                    second["planned_files"],
                    second["planned_bytes"],
                ),
            )

    def test_reset_failed_cassette_preserves_completed_tapes_and_makes_it_retryable(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "payload.bin").write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["DONE01", "FAIL02"], destructive_confirmed=True
            )

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                for tape_id in ("DONE01", "FAIL02"):
                    catalog.register_tape(
                        tape_id,
                        tape_id,
                        tape_id,
                        "LTFS",
                        "L:\\",
                        cassette_number=tape_id,
                    )
                catalog.create_block("BLOCK-DONE", "LIB1", "DONE01", "done", 1, 7)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-DONE",
                    "DONE01",
                    "done.bin",
                    "done/done.bin",
                    7,
                    1,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-DONE")
                catalog.update_automatic_cassette(
                    job["id"],
                    1,
                    "completed",
                    tape_id="DONE01",
                    block_id="BLOCK-DONE",
                    copied_files=1,
                    copied_bytes=7,
                )
                catalog.create_block("BLOCK-FAIL", "LIB1", "FAIL02", "failed", 1, 7)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-FAIL",
                    "FAIL02",
                    "partial.bin",
                    "failed/partial.bin",
                    4,
                    2,
                    "b" * 64,
                )
                catalog.update_automatic_cassette(
                    job["id"],
                    2,
                    "failed",
                    tape_id="FAIL02",
                    block_id="BLOCK-FAIL",
                    copied_files=1,
                    copied_bytes=4,
                    error="controller unavailable",
                )
                catalog.update_automatic_job(
                    job["id"],
                    "failed",
                    current_sequence=2,
                    error="controller unavailable",
                )

            reset_method = getattr(application, "reset_failed_automatic_cassette", None)
            self.assertIsNotNone(
                reset_method, "manca il reset applicativo della cassetta"
            )
            reset = reset_method(job["id"], 2)

            self.assertEqual("paused", reset["status"])
            self.assertEqual("pending", reset["cassettes"][1]["status"])
            self.assertEqual(0, reset["cassettes"][1]["copied_bytes"])
            self.assertEqual({"blocks": 1, "files": 1, "tapes": 1}, reset["discarded"])
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual(
                    ["BLOCK-DONE"], [row["id"] for row in catalog.list_blocks()]
                )
                self.assertEqual(
                    ["DONE01"], [row["id"] for row in catalog.list_tapes()]
                )

    def test_job_extension_uses_existing_reserve_before_new_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=5,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))
            job = application.create_automatic_job(
                "LIB1", ["AB1234", "CD5678L6"], destructive_confirmed=True
            )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block(
                    "BLOCK-1", "LIB1", "AB1234", "blocks/BLOCK-1", 1, 3
                )
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-1",
                    "AB1234",
                    "old.bin",
                    "blocks/BLOCK-1/files/old.bin",
                    3,
                    old_stat.st_mtime_ns,
                    "old-hash",
                )
                catalog.complete_block("BLOCK-1")
                catalog.update_automatic_cassette(job["id"], 1, "completed")
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "new-1.bin").write_bytes(b"1111")
            (source / "new-2.bin").write_bytes(b"2222")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=5):
                extended = application.extend_automatic_job(
                    job["id"], ["EF9012"], destructive_confirmed=True
                )

            self.assertEqual(3, extended["total_cassettes"])
            self.assertEqual(
                [(1, 4), (1, 4)],
                [
                    (row["planned_files"], row["planned_bytes"])
                    for row in extended["cassettes"][1:]
                ],
            )

    def test_job_extension_appends_to_last_tape_before_new_labels(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"12345678")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block("BLOCK-OLD", "LIB1", "AB1234", "old", 1, 8)
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-OLD",
                    "AB1234",
                    "old.bin",
                    "old/files/old.bin",
                    8,
                    old_stat.st_mtime_ns,
                    "a" * 64,
                )
                catalog.complete_block("BLOCK-OLD")
                catalog.update_automatic_cassette(
                    job["id"],
                    1,
                    "completed",
                    tape_id="AB1234",
                    block_id="BLOCK-OLD",
                    copied_files=1,
                    copied_bytes=8,
                )
                catalog.update_automatic_job(job["id"], "completed", current_sequence=1)

            (source / "small.bin").write_bytes(b"12")
            (source / "large.bin").write_bytes(b"3456")
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=10):
                extended = application.extend_automatic_job(
                    job["id"], ["CD5678"], destructive_confirmed=True
                )

            first, second = extended["cassettes"]
            self.assertEqual(
                ("append", 1, 2),
                (first["operation"], first["planned_files"], first["planned_bytes"]),
            )
            self.assertEqual(
                ("format", 1, 4),
                (second["operation"], second["planned_files"], second["planned_bytes"]),
            )

    def test_job_planner_distributes_multiple_libraries_across_shared_cassettes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=100 * 1024**3,
                    tape_capacity_bytes=100 * 1024**3 + 100,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            payloads = {
                "LIB_A": (70, 10),
                "LIB_B": (60, 20),
            }
            for library_id, sizes in payloads.items():
                source = root / library_id
                source.mkdir()
                for index, size in enumerate(sizes, 1):
                    (source / f"file-{index}.bin").write_bytes(b"x" * size)
                application.add_library(library_id, library_id, str(source))

            events: list[dict] = []
            simulated_capacity = 100 * 1024**3 + 100
            with patch.object(
                LtoApplication, "_media_tape_capacity", return_value=simulated_capacity
            ):
                plan = application.plan_automatic_job(
                    ["LIB_A", "LIB_B"], progress=events.append
                )

            self.assertEqual(["LIB_A", "LIB_B"], plan["library_ids"])
            self.assertEqual(4, plan["pending_files"])
            self.assertEqual(160, plan["pending_bytes"])
            self.assertEqual(2, plan["estimated_tapes"])
            self.assertEqual(
                [
                    ("library.scan.start", "LIB_A", 1, 2),
                    ("library.scan.complete", "LIB_A", 1, 2),
                    ("library.scan.start", "LIB_B", 2, 2),
                    ("library.scan.complete", "LIB_B", 2, 2),
                ],
                [
                    (
                        event["event"],
                        event["library_id"],
                        event["index"],
                        event["total"],
                    )
                    for event in events
                ],
            )
            self.assertEqual(
                [
                    (1, 3, 100, [("LIB_A", 2, 80), ("LIB_B", 1, 20)]),
                    (2, 1, 60, [("LIB_B", 1, 60)]),
                ],
                [
                    (
                        cassette["sequence"],
                        cassette["file_count"],
                        cassette["total_bytes"],
                        [
                            (row["library_id"], row["file_count"], row["total_bytes"])
                            for row in cassette["libraries"]
                        ],
                    )
                    for cassette in plan["cassettes"]
                ],
            )

    def test_completed_automatic_job_plans_new_files_on_appended_cassettes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            old_file = source / "old.bin"
            old_file.write_bytes(b"old")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            original = application.create_automatic_job(
                "LIB1", ["AB1234"], destructive_confirmed=True
            )

            old_stat = old_file.stat()
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.register_tape(
                    "AB1234",
                    "AB1234",
                    "AB1234",
                    "LTFS",
                    "L:\\",
                    cassette_number="AB1234",
                )
                catalog.create_block(
                    "BLOCK-1", "LIB1", "AB1234", "blocks/BLOCK-1", 1, 3
                )
                catalog.record_file_version(
                    "LIB1",
                    "BLOCK-1",
                    "AB1234",
                    "old.bin",
                    "blocks/BLOCK-1/files/old.bin",
                    3,
                    old_stat.st_mtime_ns,
                    "old-hash",
                )
                catalog.complete_block("BLOCK-1")
                catalog.update_automatic_cassette(original["id"], 1, "completed")
                catalog.update_automatic_job(
                    original["id"], "completed", current_sequence=1
                )

            (source / "new.bin").write_bytes(b"new payload")
            extended = application.extend_automatic_job(
                original["id"], ["CD5678L6", "EF9012"], destructive_confirmed=True
            )

            self.assertEqual(original["id"], extended["id"])
            self.assertEqual("planned", extended["status"])
            self.assertEqual(3, extended["total_cassettes"])
            self.assertEqual(
                [1, 2, 3], [row["sequence"] for row in extended["cassettes"]]
            )
            self.assertEqual(
                ["AB1234", "CD5678L6", "EF9012"],
                [row["physical_label"] for row in extended["cassettes"]],
            )
            self.assertEqual(1, extended["cassettes"][1]["planned_files"])
            self.assertEqual(
                len(b"new payload"), extended["cassettes"][1]["planned_bytes"]
            )
            self.assertEqual(0, extended["cassettes"][2]["planned_files"])
            self.assertEqual(0, extended["cassettes"][2]["planned_bytes"])

    def test_resume_keeps_existing_assignments_and_adds_new_files_to_residual_space(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "largest.mxf").write_bytes(b"a" * 7)
            (source / "small.mxf").write_bytes(b"b" * 3)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))

            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678"], destructive_confirmed=True
                )

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                before = [
                    [
                        row["relative_path"]
                        for row in catalog.list_automatic_cassette_manifest(
                            job["id"], sequence
                        )
                    ]
                    for sequence in (1, 2)
                ]

            (source / "added-later.mxf").write_bytes(b"c" * 4)
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                application.prepare_automatic_job_run(job["id"])

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                after = [
                    [
                        row["relative_path"]
                        for row in catalog.list_automatic_cassette_manifest(
                            job["id"], sequence
                        )
                    ]
                    for sequence in (1, 2)
                ]

            self.assertEqual([["largest.mxf"], ["small.mxf"]], before)
            self.assertEqual([["largest.mxf"], ["small.mxf", "added-later.mxf"]], after)

    def test_paused_job_can_append_a_label_for_new_files_without_moving_the_plan(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "first.mxf").write_bytes(b"a" * 7)
            (source / "second.mxf").write_bytes(b"b" * 7)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234", "CD5678"], destructive_confirmed=True
                )
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                before = [
                    [
                        row["relative_path"]
                        for row in catalog.list_automatic_cassette_manifest(
                            job["id"], sequence
                        )
                    ]
                    for sequence in (1, 2)
                ]
                catalog.update_automatic_job(job["id"], "paused", current_sequence=1)

            (source / "new.mxf").write_bytes(b"n" * 6)
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                extended = application.extend_automatic_job(
                    job["id"], ["EF9012"], destructive_confirmed=True
                )

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                after = [
                    [
                        row["relative_path"]
                        for row in catalog.list_automatic_cassette_manifest(
                            job["id"], sequence
                        )
                    ]
                    for sequence in (1, 2, 3)
                ]
            self.assertEqual(before, after[:2])
            self.assertEqual(["new.mxf"], after[2])
            self.assertEqual(3, extended["total_cassettes"])

    def test_automatic_batch_never_marks_a_missing_manifest_file_as_completed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            mount = root / "tape"
            source.mkdir()
            mount.mkdir()
            planned = source / "planned.mxf"
            planned.write_bytes(b"payload")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=100,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=100):
                job = application.create_automatic_job(
                    "LIB1", ["AB1234"], destructive_confirmed=True
                )
            volume = VolumeInfo(mount, "LTFS", "AB1234", "AB1234", 100, 100)
            application.register_tape("AB1234", "AB1234", mount, known_volume=volume)
            planned.unlink()

            with self.assertRaisesRegex(ValidationError, "mancanti"):
                application.backup_automatic_batch(
                    ["LIB1"],
                    "AB1234",
                    mount,
                    known_volume=volume,
                    tape_capacity_bytes=100,
                    automatic_job_id=job["id"],
                )

    def test_automatic_batch_executes_frozen_native_plan_without_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            z_source = root / "z-source"
            a_source = root / "a-source"
            mount = root / "tape"
            z_source.mkdir()
            a_source.mkdir()
            mount.mkdir()
            (z_source / "z.bin").write_bytes(b"payload-z")
            (a_source / "a.bin").write_bytes(b"payload-a")
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            settings = Settings(
                reserve_bytes=0,
                tape_capacity_bytes=100,
                buffer_bytes=1024**2,
                min_age_seconds=0,
            )
            save_settings(application.paths, settings)
            application.add_library("ZLIB", "Z Library", str(z_source))
            application.add_library("ALIB", "A Library", str(a_source))
            with patch.object(LtoApplication, "_media_tape_capacity", return_value=100):
                job = application.create_automatic_job(
                    ["ZLIB", "ALIB"], ["AB1234"], destructive_confirmed=True
                )
            volume = VolumeInfo(mount, "LTFS", "AB1234", "AB1234", 100, 100)
            application.register_tape("AB1234", "AB1234", mount, known_volume=volume)
            with Catalog(application.paths.catalog_file) as catalog:
                frozen = FrozenNativeCassettePlan.load(catalog, job["id"], 1)
                self.assertEqual(
                    ("ZLIB", "ALIB"),
                    tuple(
                        row["library_id"]
                        for row in catalog.list_automatic_job_libraries(job["id"])
                    ),
                )
                self.assertEqual(
                    (("ALIB", "a.bin"), ("ZLIB", "z.bin")),
                    tuple(
                        (row["library_id"], row["relative_path"])
                        for row in catalog.list_automatic_cassette_manifest(job["id"], 1)
                    ),
                )
            progress_events: list[dict] = []

            with (
                patch(
                    "ltobackup.application.analyze_library",
                    side_effect=AssertionError("frozen recovery analyzed a source root"),
                ) as analyzer,
                patch(
                    "ltobackup.scanner.analyze_library",
                    side_effect=AssertionError("frozen recovery analyzed a source root"),
                ) as scanner_analyzer,
                patch(
                    "ltobackup.scanner.scan_library",
                    side_effect=AssertionError("frozen recovery scanned a source tree"),
                ) as scanner_alias,
                patch(
                    "ltobackup.engine.BackupEngine.scan",
                    side_effect=AssertionError("frozen recovery scanned a source root"),
                ) as scan,
                patch(
                    "ltobackup.engine.plan_tape_batches",
                    side_effect=AssertionError("frozen recovery repacked the manifest"),
                ) as planner,
                patch(
                    "ltobackup.engine.select_tape_batch",
                    side_effect=AssertionError("frozen recovery reselected the manifest"),
                ) as selector,
                patch(
                    "ltobackup.application._plan_ltfs_batches",
                    side_effect=AssertionError("frozen recovery repacked the manifest"),
                ) as application_planner,
                patch(
                    "ltobackup.application._select_ltfs_batch",
                    side_effect=AssertionError("frozen recovery reselected the manifest"),
                ) as application_selector,
                patch(
                    "ltobackup.engine.ltfs_tape_relative_path",
                    side_effect=AssertionError("frozen recovery remapped a tape path"),
                ) as mapper,
                patch(
                    "ltobackup.application.ltfs_tape_relative_path",
                    side_effect=AssertionError("frozen recovery remapped a tape path"),
                ) as application_mapper,
                patch(
                    "ltobackup.catalog.ltfs_tape_relative_path",
                    side_effect=AssertionError("frozen recovery remapped a tape path"),
                ) as catalog_mapper,
                patch(
                    "ltobackup.daemon.archive_runner.ltfs_tape_relative_path",
                    side_effect=AssertionError("frozen recovery remapped a tape path"),
                ) as archive_mapper,
                patch.object(
                    Path,
                    "iterdir",
                    side_effect=AssertionError("frozen recovery enumerated a source tree"),
                ) as iterdir,
                patch.object(
                    Path,
                    "glob",
                    side_effect=AssertionError("frozen recovery globbed a source tree"),
                ) as glob,
                patch.object(
                    Path,
                    "rglob",
                    side_effect=AssertionError("frozen recovery globbed a source tree"),
                ) as rglob,
                patch.object(
                    os,
                    "scandir",
                    side_effect=AssertionError("frozen recovery enumerated a source tree"),
                ) as scandir,
                patch.object(
                    os,
                    "walk",
                    side_effect=AssertionError("frozen recovery walked a source tree"),
                ) as walk,
            ):
                result = application.backup_automatic_batch(
                    list(frozen.library_ids),
                    "AB1234",
                    mount,
                    progress=progress_events.append,
                    known_volume=volume,
                    tape_capacity_bytes=100,
                    automatic_job_id=job["id"],
                    settings=settings,
                    frozen_plans_by_library=frozen.plans_by_library,
                )

            analyzer.assert_not_called()
            scanner_analyzer.assert_not_called()
            scanner_alias.assert_not_called()
            scan.assert_not_called()
            planner.assert_not_called()
            selector.assert_not_called()
            application_planner.assert_not_called()
            application_selector.assert_not_called()
            mapper.assert_not_called()
            application_mapper.assert_not_called()
            catalog_mapper.assert_not_called()
            archive_mapper.assert_not_called()
            iterdir.assert_not_called()
            glob.assert_not_called()
            rglob.assert_not_called()
            scandir.assert_not_called()
            walk.assert_not_called()
            started_order = tuple(
                str(event["relative_path"])
                for event in progress_events
                if event.get("event") == "file.start"
            )
            completed_order = tuple(
                str(event["relative_path"])
                for event in progress_events
                if event.get("event") == "file.complete"
            )
            self.assertEqual(("ALIB", "ZLIB"), frozen.library_ids)
            self.assertEqual(("a.bin", "z.bin"), started_order)
            self.assertEqual(("a.bin", "z.bin"), completed_order)
            self.assertEqual("pending-commit", result["status"])

    def test_frozen_batch_rejects_same_metadata_symlink_swap_after_plan_load(self):
        for swap in ("final", "intermediate"):
            with self.subTest(swap=swap), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source"
                mount = root / "tape"
                outside = root / "outside"
                source.mkdir()
                mount.mkdir()
                outside.mkdir()
                relative = Path("dir") / "planned.mxf"
                planned = source / relative
                planned.parent.mkdir()
                planned.write_bytes(b"PUBLIC!")
                original_stat = planned.stat()
                application = LtoApplication(root / "state")
                application.ensure_initialized(min_age_seconds=0)
                settings = Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=100,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                )
                save_settings(application.paths, settings)
                application.add_library("LIB1", "Library", str(source))
                with patch.object(
                    LtoApplication, "_media_tape_capacity", return_value=100
                ):
                    job = application.create_automatic_job(
                        "LIB1", ["AB1234"], destructive_confirmed=True
                    )
                volume = VolumeInfo(
                    mount, "LTFS", "AB1234", "AB1234", 100, 100
                )
                application.register_tape(
                    "AB1234", "AB1234", mount, known_volume=volume
                )
                with Catalog(application.paths.catalog_file) as catalog:
                    frozen = FrozenNativeCassettePlan.load(catalog, job["id"], 1)

                if swap == "final":
                    outside_file = outside / "outside.mxf"
                    outside_file.write_bytes(b"SECRET!")
                    os.utime(
                        outside_file,
                        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                    )
                    planned.unlink()
                    planned.symlink_to(outside_file)
                else:
                    original_dir = source / "original-dir"
                    planned.parent.rename(original_dir)
                    outside_planned = outside / "planned.mxf"
                    outside_planned.write_bytes(b"SECRET!")
                    os.utime(
                        outside_planned,
                        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                    )
                    (source / "dir").symlink_to(outside, target_is_directory=True)

                with self.assertRaises(CopyError):
                    application.backup_automatic_batch(
                        ["LIB1"],
                        "AB1234",
                        mount,
                        known_volume=volume,
                        tape_capacity_bytes=100,
                        automatic_job_id=job["id"],
                        settings=settings,
                        frozen_plans_by_library=frozen.plans_by_library,
                    )

    def test_frozen_copy_rejects_final_symlink_swap_immediately_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination" / "planned.mxf"
            outside = root / "outside.mxf"
            source.mkdir()
            planned = source / "planned.mxf"
            planned.write_bytes(b"PUBLIC!")
            observed = planned.lstat()
            identity = (
                observed.st_dev,
                observed.st_ino,
                observed.st_ctime_ns,
                observed.st_size,
                observed.st_mtime_ns,
            )
            outside.write_bytes(b"SECRET!")
            os.utime(
                outside,
                ns=(observed.st_atime_ns, observed.st_mtime_ns),
            )
            real_open = os.open
            swapped = False

            def swap_before_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if path == "planned.mxf" and kwargs.get("dir_fd") is not None:
                    planned.unlink()
                    planned.symlink_to(outside)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            with patch("ltobackup.util.os.open", side_effect=swap_before_open):
                with self.assertRaises(CopyError):
                    copy_and_hash(
                        planned,
                        destination,
                        1024,
                        source_root=source,
                        source_relative_path="planned.mxf",
                        expected_source_identity=identity,
                    )

            self.assertTrue(swapped)
            self.assertFalse(destination.exists())

    def test_frozen_copy_rejects_descriptor_mutation_during_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            destination = root / "destination" / "planned.mxf"
            source.mkdir()
            planned = source / "planned.mxf"
            planned.write_bytes(b"PUBLIC!")
            observed = planned.lstat()
            identity = (
                observed.st_dev,
                observed.st_ino,
                observed.st_ctime_ns,
                observed.st_size,
                observed.st_mtime_ns,
            )
            mutated = False

            def mutate_after_first_chunk(_copied: int) -> None:
                nonlocal mutated
                if mutated:
                    return
                for _attempt in range(100):
                    planned.write_bytes(b"CHANGED")
                    os.utime(
                        planned,
                        ns=(observed.st_atime_ns, observed.st_mtime_ns),
                    )
                    if planned.lstat().st_ctime_ns != observed.st_ctime_ns:
                        break
                    time.sleep(0.002)
                mutated = True

            with self.assertRaises(CopyError):
                copy_and_hash(
                    planned,
                    destination,
                    2,
                    progress=mutate_after_first_chunk,
                    source_root=source,
                    source_relative_path="planned.mxf",
                    expected_source_identity=identity,
                )

            self.assertTrue(mutated)

    def test_legacy_job_freezes_all_remaining_paths_before_next_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "largest.mxf").write_bytes(b"a" * 7)
            (source / "small.mxf").write_bytes(b"b" * 3)
            application = LtoApplication(root / "state")
            application.ensure_initialized(min_age_seconds=0)
            save_settings(
                application.paths,
                Settings(
                    reserve_bytes=0,
                    tape_capacity_bytes=7,
                    buffer_bytes=1024**2,
                    min_age_seconds=0,
                ),
            )
            application.add_library("LIB1", "Library", str(source))
            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                catalog.create_automatic_job(
                    "LEGACY",
                    "LIB1",
                    "TAPE0",
                    "AUTO",
                    [("AB1234", "AB1234", 1, 7), ("CD5678", "CD5678", 1, 3)],
                    force_format=True,
                )

            with patch.object(LtoApplication, "_media_tape_capacity", return_value=7):
                application.prepare_automatic_job_run("LEGACY")

            with Catalog(application.paths.catalog_file) as catalog:
                catalog.initialize()
                self.assertEqual(
                    [["largest.mxf"], ["small.mxf"]],
                    [
                        [
                            row["relative_path"]
                            for row in catalog.list_automatic_cassette_manifest(
                                "LEGACY", sequence
                            )
                        ]
                        for sequence in (1, 2)
                    ],
                )


if __name__ == "__main__":
    unittest.main()
