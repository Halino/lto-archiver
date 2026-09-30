from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
import unittest
from concurrent.futures import Executor, Future
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from ltobackup.catalog import Catalog
from ltobackup.daemon.api_models import (
    CutoverAuthorizationRequestV1,
    CreateNativeJobRequestV1,
    OperationRequest,
    SignedAcceptanceReportV1,
    UpdateApplicationSettingsRequestV1,
)
from ltobackup.daemon.archive_runtime import ArchiveResumeAdmission
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.events import EventBus
from ltobackup.daemon.models import (
    HardwareTargetBinding,
    sequence_continuation_idempotency_key,
)
from ltobackup.daemon.operations import OperationManager
from ltobackup.daemon.sequence_coordinator import SequenceCandidate
from ltobackup.daemon.service import DaemonService, Principal
from ltobackup.errors import CatalogError
from ltobackup.linux_settings import LinuxPaths, LinuxSettings


class _ImmediateExecutor(Executor):
    def __init__(self) -> None:
        self.submissions = 0

    def submit(self, fn, /, *args, **kwargs):
        self.submissions += 1
        future: Future[None] = Future()
        try:
            future.set_result(fn(*args, **kwargs))
        except BaseException as exc:
            future.set_exception(exc)
        return future


class _HoldingExecutor(Executor):
    def __init__(self) -> None:
        self.futures: list[Future[None]] = []

    def submit(self, fn, /, *args, **kwargs):
        future: Future[None] = Future()
        self.futures.append(future)
        return future


class ProgressBaselineServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.settings = LinuxSettings(
            state_dir=root / "state",
            socket_path=root / "run" / "daemon.sock",
            restore_roots=(root / "restore",),
        )
        self.paths = LinuxPaths.from_settings(self.settings)
        self.backups = BackupManager(self.paths.catalog_file, self.paths.backup_dir)
        self.backups.prepare_and_initialize()
        with Catalog(self.paths.catalog_file) as catalog:
            owner = catalog.claim_daemon_owner("progress-baseline-service-test")
        self.executor = _HoldingExecutor()
        self.operations = OperationManager(
            lambda: Catalog(self.paths.catalog_file),
            owner,
            executor=self.executor,
        )
        self.service = DaemonService(
            self.paths,
            self.settings,
            self.backups,
            self.operations,
            EventBus(lambda: Catalog(self.paths.catalog_file)),
        )
        self.service.startup()

    def tearDown(self) -> None:
        for future in self.executor.futures:
            future.cancel()
        self.service.shutdown(0.0)

    def test_retry_baseline_excludes_discarded_partial_file_bytes(self) -> None:
        """A retry must show all bytes written by the new operation window."""

        telemetry = self.service.archive_telemetry_sink
        telemetry.begin_window()
        telemetry.record_file(1)
        telemetry.record_progress(4)

        self.service.start_operation(
            OperationRequest(kind="diagnostic"),
            "retry-progress-baseline",
            Principal("admin"),
        )
        waiting = self.service.status()
        self.assertEqual(0, waiting.progress.files_completed)
        self.assertEqual(0, waiting.progress.bytes_completed)
        self.assertIsNone(waiting.telemetry.current_mib_per_second)
        self.assertIsNone(waiting.telemetry.effective_mib_per_second)
        self.assertEqual((), waiting.telemetry.samples)

        telemetry.begin_window()
        telemetry.record_progress(10)
        telemetry.complete_file()

        progress = self.service.status().progress
        self.assertEqual(1, progress.files_completed)
        self.assertEqual(10, progress.bytes_completed)

    def test_operation_sse_progress_matches_status_baseline(self) -> None:
        """A state.patch must use the same operation-relative counters as status."""

        telemetry = self.service.archive_telemetry_sink
        telemetry.begin_window()
        telemetry.record_file(7)
        self.service.start_operation(
            OperationRequest(kind="diagnostic"),
            "sse-progress-baseline",
            Principal("admin"),
        )
        published: list[tuple[str, dict]] = []
        publish = self.service._events.publish

        def capture(event_type: str, payload: dict):
            published.append((event_type, payload))
            return publish(event_type, payload)

        with patch.object(self.service._events, "publish", side_effect=capture):
            telemetry.begin_window()
            telemetry.record_progress(3)
            telemetry.complete_file()

        status_progress = self.service.status().progress.model_dump(mode="json")
        patches = [payload for event, payload in published if event == "state.patch"]
        self.assertTrue(patches)
        self.assertEqual(status_progress, patches[-1]["progress"])

    def test_replacement_admission_hook_scopes_inline_recovery_progress(self) -> None:
        """Replacement progress must start at its first new telemetry window."""

        telemetry = self.service.archive_telemetry_sink
        telemetry.begin_window()
        telemetry.record_file(7)
        telemetry.record_progress(4)
        replacement = self.operations.start(
            "diagnostic",
            "replacement-progress-hook",
            "admin",
            lambda _context: None,
        )

        remember = self.service.prepare_replacement_admission()
        remember(replacement)

        waiting = self.service.status()
        self.assertEqual(replacement.id, waiting.operation.id)
        self.assertEqual(0, waiting.progress.files_completed)
        self.assertEqual(0, waiting.progress.bytes_completed)
        self.assertIsNone(waiting.telemetry.current_mib_per_second)

        telemetry.begin_window()
        telemetry.record_progress(3)
        telemetry.complete_file()

        progress = self.service.status().progress
        self.assertEqual(1, progress.files_completed)
        self.assertEqual(3, progress.bytes_completed)


class NativeResetServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.sources = (root / "Film", root / "Anime")
        for source in self.sources:
            source.mkdir(parents=True)
        self.settings = LinuxSettings(
            state_dir=root / "state",
            socket_path=root / "run" / "daemon.sock",
            source_roots=self.sources,
            restore_roots=(root / "restore",),
        )
        self.paths = LinuxPaths.from_settings(self.settings)
        self.backups = BackupManager(self.paths.catalog_file, self.paths.backup_dir)
        self.backups.prepare_and_initialize()
        with Catalog(self.paths.catalog_file) as catalog:
            catalog.add_library("OLD-FILM", "Film", str(self.sources[0]))
            catalog.add_library("OLD-ANIME", "Anime", str(self.sources[1]))
            catalog.create_automatic_job(
                "JOB-OLD",
                "OLD-FILM",
                "/dev/tape/by-id/drive-nst",
                "/mnt/tape",
                [("TAPE01", "TAPE01", 1, 10), ("TAPE02", "TAPE02", 1, 20)],
                library_ids=["OLD-FILM", "OLD-ANIME"],
                force_format=True,
            )
            owner = catalog.claim_daemon_owner("native-reset-service-test")
        self.executor = _ImmediateExecutor()
        self.operations = OperationManager(
            lambda: Catalog(self.paths.catalog_file),
            owner,
            executor=self.executor,
        )
        self.service = DaemonService(
            self.paths,
            self.settings,
            self.backups,
            self.operations,
            EventBus(lambda: Catalog(self.paths.catalog_file)),
        )
        self.service.startup()
        self.addCleanup(self.service.shutdown)

    def request(self) -> CreateNativeJobRequestV1:
        return CreateNativeJobRequestV1(
            display_name="Backup completo",
            labels=("TAPE01", "TAPE02"),
            expected_job_id="JOB-OLD",
            typed_job_id="JOB-OLD",
        )

    def test_success_supersedes_only_after_complete_plan_exists(self) -> None:
        (self.sources[0] / "film.mkv").write_bytes(b"film")
        (self.sources[1] / "anime.mkv").write_bytes(b"anime")

        accepted = self.service.start_native_job(
            self.request(), "native-reset-success", Principal("admin")
        )
        completed = self.service.operation(accepted.id)

        self.assertIsNotNone(completed)
        self.assertEqual("succeeded", completed.state)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("failed", catalog.get_automatic_job("JOB-OLD")["status"])
            new_job = catalog.get_automatic_job(accepted.job_id)
            cassettes = catalog.list_automatic_cassettes(accepted.job_id)
            manifest = catalog.list_automatic_cassette_manifest(accepted.job_id, 1)
        self.assertEqual("planned", new_job["status"])
        self.assertEqual(2, sum(int(row["planned_files"]) for row in cassettes))
        self.assertEqual(2, len(manifest))
        self.assertIsNone(self.service.status().operation)
        self.assertTrue(self.backups.list_backups(protected=True)[0].verified)

    def test_preflight_failure_leaves_old_job_and_libraries_active(self) -> None:
        accepted = self.service.start_native_job(
            self.request(), "native-reset-failure", Principal("admin")
        )
        completed = self.service.operation(accepted.id)

        self.assertIsNotNone(completed)
        self.assertEqual("failed", completed.state)
        with Catalog(self.paths.catalog_file) as catalog:
            self.assertEqual("planned", catalog.get_automatic_job("JOB-OLD")["status"])
            self.assertEqual(["JOB-OLD"], [row["id"] for row in catalog.list_automatic_jobs()])
            active_libraries = catalog.connection.execute(
                "SELECT id FROM libraries WHERE status='active' ORDER BY id"
            ).fetchall()
        self.assertEqual(["OLD-ANIME", "OLD-FILM"], [row["id"] for row in active_libraries])
        self.assertIsNone(self.service.status().operation)

    def test_native_reset_replay_keeps_the_original_audit_and_worker(self) -> None:
        first = self.service.start_native_job(
            self.request(), "native-reset-replay", Principal("admin")
        )
        submissions_after_first = self.executor.submissions
        replay = self.service.start_native_job(
            self.request(), "native-reset-replay", Principal("admin")
        )

        self.assertEqual(first.id, replay.id)
        self.assertEqual(1, submissions_after_first)
        self.assertEqual(submissions_after_first, self.executor.submissions)
        with Catalog(self.paths.catalog_file) as catalog:
            persisted = catalog.find_operation_by_key("native-reset-replay")
            audits = tuple(
                json.loads(str(row["payload_json"]))
                for row in catalog.connection.execute(
                    "SELECT payload_json FROM audit_entries "
                    "WHERE action='job.native_reset_create' ORDER BY id"
                )
            )
        self.assertIsNotNone(persisted)
        self.assertEqual(first.job_id, persisted["job_id"])
        self.assertEqual(
            ({"job_id": first.job_id, "operation_id": first.id},),
            audits,
        )

    def test_native_reset_preserves_application_choices_and_freezes_job_policy(
        self,
    ) -> None:
        film = self.sources[0] / "film.mkv"
        anime = self.sources[1] / "anime.mkv"
        film.write_bytes(b"film")
        anime.write_bytes(b"anime")
        old = time.time() - 120
        os.utime(film, (old, old))
        os.utime(anime, (old, old))
        current = self.service.application_settings(Principal("admin"))
        legacy_config = self.paths.state_dir / "config.json"
        legacy_payload = (
            legacy_config.read_bytes() if legacy_config.exists() else None
        )
        updated = asyncio.run(
            self.service.update_application_settings(
                UpdateApplicationSettingsRequestV1(
                    expected_revision=current.revision,
                    capacity_reserve_bytes=123,
                    minimum_source_file_age_seconds=77,
                    copy_buffer_bytes=2 * 1024**2,
                    content_verification_policy="full",
                    default_media_profile="LTO-10 PA",
                    tape_root_directory=".lto-backup",
                ),
                "native-reset-settings",
                Principal("admin"),
            )
        )
        self.assertEqual(
            legacy_payload,
            legacy_config.read_bytes() if legacy_config.exists() else None,
        )

        request = CreateNativeJobRequestV1(
            display_name="Backup completo",
            labels=("TAPE01",),
            expected_job_id="JOB-OLD",
            typed_job_id="JOB-OLD",
        )
        accepted = self.service.start_native_job(
            request, "native-reset-preserve-settings", Principal("admin")
        )
        completed = self.service.operation(accepted.id)
        self.assertIsNotNone(completed)
        self.assertEqual("succeeded", completed.state)

        self.assertEqual(
            updated,
            self.service.application_settings(Principal("admin")),
        )
        self.assertEqual(
            legacy_payload,
            legacy_config.read_bytes() if legacy_config.exists() else None,
        )
        with Catalog(self.paths.catalog_file) as catalog:
            job = catalog.get_automatic_job(accepted.job_id)
            policy = catalog.get_job_policy_snapshot(accepted.job_id)
        self.assertEqual("LTO-10 PA", job["media_key"])
        self.assertEqual("LTO-10 PA", policy["selected_media_profile"])
        self.assertEqual("full", policy["content_verification_policy"])
        self.assertEqual(77, policy["minimum_source_file_age_seconds"])

    def test_public_requests_cannot_replay_sequence_continuation(self) -> None:
        """Only the immutable coordinator provenance may replay a continuation."""

        with Catalog(self.paths.catalog_file) as catalog:
            epoch = catalog.latest_layout_epoch("JOB-OLD")
            authorities = catalog.authorize_automatic_format_sequence(
                "JOB-OLD",
                expected_revision=0,
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="authorizer",
                idempotency_key="authorize-job-old",
                authorized_at="2026-08-31T09:00:00+00:00",
            )
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='completed' "
                "WHERE job_id='JOB-OLD' AND sequence=1"
            )
            catalog.connection.execute(
                "UPDATE automatic_cassettes SET status='waiting_media' "
                "WHERE job_id='JOB-OLD' AND sequence=2"
            )
            catalog.connection.execute(
                "UPDATE automatic_jobs SET status='waiting_media',current_sequence=2 "
                "WHERE id='JOB-OLD'"
            )
            catalog.connection.commit()
            state = catalog.automatic_sequence_state("JOB-OLD")
            catalog.set_automatic_sequence_enabled(
                "JOB-OLD",
                expected_revision=int(state["revision"]),
                layout_fingerprint_sha256=epoch["layout_fingerprint_sha256"],
                actor="operator-1",
                enabled_at="2026-08-31T09:00:01+00:00",
            )

        target = HardwareTargetBinding.from_verified_inputs(
            self.paths.state_dir.parent / "mount",
            "tape-by-id",
            "scsi-by-id",
            ("archive.native", "JOB-OLD", "2", "TAPE02", "", ""),
        )
        callbacks: list[str] = []
        self.service._callbacks["archive.native"] = (  # noqa: SLF001 - composition seam
            lambda context: callbacks.append(context.record.id)
        )
        self.service._native_archive_admission = (  # noqa: SLF001 - composition seam
            lambda job_id: ArchiveResumeAdmission(job_id, 2, target)
        )
        self.service._cutover_environment = (  # noqa: SLF001 - composition seam
            lambda _job_id: ("host-a", "d" * 64)
        )
        fingerprint = str(epoch["layout_fingerprint_sha256"])
        continuation_key = sequence_continuation_idempotency_key(
            "JOB-OLD", fingerprint, 2, self.operations.daemon_fence.generation
        )
        candidate = SequenceCandidate(
            job_id="JOB-OLD",
            cassette_sequence=2,
            authorization_id=authorities[1],
            layout_fingerprint_sha256=fingerprint,
            idempotency_key=continuation_key,
        )

        admitted = self.service._admit_sequence_candidate(candidate)  # noqa: SLF001 - coordinator boundary
        self.assertEqual([admitted.id], callbacks)

        with Catalog(self.paths.catalog_file) as catalog:
            before_actions = tuple(
                row[0]
                for row in catalog.connection.execute(
                    "SELECT action FROM audit_entries WHERE action IN "
                    "('automatic.sequence.continuation.admitted',"
                    "'automatic.sequence.continuation.replayed') ORDER BY id"
                )
            )
            before_operations = catalog.connection.execute(
                "SELECT COUNT(*) FROM daemon_operations"
            ).fetchone()[0]

        attempts = (
            lambda: self.service.start_operation(
                OperationRequest(kind="diagnostic"),
                continuation_key,
                Principal("admin"),
            ),
            lambda: self.service.start_operation(
                OperationRequest(kind="archive.native", job_id="JOB-OLD"),
                continuation_key,
                Principal("admin"),
            ),
            lambda: self.service.start_operation(
                OperationRequest(kind="archive.resume", job_id="JOB-OLD"),
                continuation_key,
                Principal("admin"),
            ),
            lambda: self.service.start_native_job(
                self.request(), continuation_key, Principal("admin")
            ),
            lambda: self.service.start_cutover_authorization(
                CutoverAuthorizationRequestV1(
                    acceptance_report=SignedAcceptanceReportV1(
                        job_id="JOB-OLD",
                        next_sequence=4,
                        bundle_sha256="a" * 64,
                        catalog_binding_sha256="b" * 64,
                        assignment_sha256="c" * 64,
                        expected_label="TAPE02",
                        host_id="host-a",
                        drive_serial_sha256="d" * 64,
                        expires_at=(
                            datetime.now(UTC) + timedelta(minutes=15)
                        ).isoformat(),
                    ),
                    credential_sha256="e" * 64,
                ),
                continuation_key,
                Principal("admin", direct_local_admin=True),
            ),
        )
        for attempt in attempts:
            with self.assertRaisesRegex(CatalogError, "^idempotency_conflict$"):
                attempt()

        self.assertEqual([admitted.id], callbacks)
        with Catalog(self.paths.catalog_file) as catalog:
            after_actions = tuple(
                row[0]
                for row in catalog.connection.execute(
                    "SELECT action FROM audit_entries WHERE action IN "
                    "('automatic.sequence.continuation.admitted',"
                    "'automatic.sequence.continuation.replayed') ORDER BY id"
                )
            )
            self.assertEqual(
                before_operations,
                catalog.connection.execute("SELECT COUNT(*) FROM daemon_operations").fetchone()[0],
            )
        self.assertEqual(before_actions, after_actions)

        replayed = self.operations.start(
            "archive.native",
            continuation_key,
            "sequence-coordinator",
            lambda _context: self.fail("exact replay dispatched a callback"),
            job_id="JOB-OLD",
            cassette_sequence=2,
            hardware_target=target,
            sequence_authorization_id=authorities[1],
            sequence_layout_fingerprint_sha256=fingerprint,
        )

        self.assertEqual(admitted.id, replayed.id)
        self.assertEqual([admitted.id], callbacks)
        with Catalog(self.paths.catalog_file) as catalog:
            actions = tuple(
                row[0]
                for row in catalog.connection.execute(
                    "SELECT action FROM audit_entries WHERE action IN "
                    "('automatic.sequence.continuation.admitted',"
                    "'automatic.sequence.continuation.replayed') ORDER BY id"
                )
            )
        self.assertEqual(
            (
                "automatic.sequence.continuation.admitted",
                "automatic.sequence.continuation.replayed",
            ),
            actions,
        )


if __name__ == "__main__":
    unittest.main()
