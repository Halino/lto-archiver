from __future__ import annotations

import asyncio
import logging
import re
import sqlite3
import tempfile
import time
import unittest
from datetime import UTC, datetime
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient
from pydantic import ValidationError

from ltobackup.client import (
    DaemonConflict,
    DaemonProtocolError,
    DaemonRequestError,
    DaemonUnavailable,
)
from ltobackup.daemon.api_models import (
    ApplicationSettingsV1,
    AuthorizeAutomaticSequenceRequestV1,
    CatalogBrowsePageV1,
    CatalogFileVersionV1,
    CatalogSearchPageV1,
    CriticalRecoveryProofV1,
    CriticalRecoveryTargetV1,
    HostSettingsV1,
    IncrementalPolicyV1,
    IncrementalScanResultV1,
    JobCassettePageV1,
    JobDetailV1,
    JobHistoryPageV1,
    JobListPageV1,
    JobManifestPageV1,
    JobPlanV1,
    LibrarySummaryV1,
    LogsPageV1,
    MediaProfilesV1,
    ShareOperationV1,
    ShareSummaryV1,
    ShareV1,
    SystemLogsPageV1,
)
from ltobackup.log_reader.protocol import (
    LogDirection,
    LogRange,
    LogSource,
    Severity,
)
from ltobackup.web.app import ShareSummaryView, WebSettings, create_web_app
from ltobackup.web.auth_store import AuthStore
from tests.web.english_surface import assert_english_document, assert_english_surface


class _FieldAssociationParser(HTMLParser):
    _VOID = frozenset(
        {
            "area",
            "base",
            "br",
            "col",
            "embed",
            "hr",
            "img",
            "input",
            "link",
            "meta",
            "source",
            "track",
            "wbr",
        }
    )

    def __init__(self) -> None:
        super().__init__()
        self.nodes: list[dict[str, object]] = []
        self._stack: list[int] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        node = {
            "tag": tag,
            "attrs": dict(attrs),
            "parent": self._stack[-1] if self._stack else None,
        }
        self.nodes.append(node)
        if tag not in self._VOID:
            self._stack.append(len(self.nodes) - 1)

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID:
            self._stack.pop()

    def handle_endtag(self, tag: str) -> None:
        for offset in range(len(self._stack) - 1, -1, -1):
            if self.nodes[self._stack[offset]]["tag"] == tag:
                del self._stack[offset:]
                return

    def is_descendant(self, candidate: int, ancestor: int) -> bool:
        parent = self.nodes[candidate]["parent"]
        while parent is not None:
            if parent == ancestor:
                return True
            parent = self.nodes[parent]["parent"]
        return False


def _library(library_id: str, name: str, *, state: str = "active") -> LibrarySummaryV1:
    return LibrarySummaryV1(
        id=library_id,
        display_name=name,
        source_root=f"/srv/source/{library_id}",
        state=state,
        scan_state="ready",
        last_successful_scan_at="2026-08-25T10:00:00+00:00",
        file_count=2,
        byte_count=7,
        revision=3,
    )


def _catalog_version(
    *,
    version_id: int = 42,
    relative_path: str = "clips/example.mxf",
    physical_label: str | None = "B00100",
    is_current: bool = True,
) -> CatalogFileVersionV1:
    parent_path, _, file_name = relative_path.rpartition("/")
    return CatalogFileVersionV1(
        id=version_id,
        library_id="PHOTOS",
        library_name="Foto <famiglia>",
        job_id="JOB-1",
        job_display_name="Backup <notturno>",
        block_id="BLOCK-1",
        block_status="completed",
        tape_id="TAPE-1",
        cassette_number="CASS-1",
        physical_label=physical_label,
        volume_label="LTFS-001",
        volume_serial="serial-1",
        relative_path=relative_path,
        parent_path=parent_path,
        file_name=file_name,
        tape_relative_path=f".lto/BLOCK-1/files/{relative_path}",
        size=1024,
        mtime_ns=1,
        created_ns=2,
        accessed_ns=3,
        source_mode=0o644,
        windows_attributes=None,
        owner_name="owner <unsafe>",
        owner_sid="S-1-5-21",
        security_descriptor="D:(A;;FA;;;SY)",
        alternate_streams=(),
        metadata_state="complete",
        metadata_error=None,
        sha256="a" * 64,
        copied_at="2026-08-22T10:00:00+00:00",
        is_current=is_current,
    )


def _restore_run(*, state: str = "waiting_media", conflict: bool = False):
    plan_item = SimpleNamespace(
        sequence=1,
        file_version_id=42,
        library_id="PHOTOS",
        relative_path="clips/example.mxf",
        tape_relative_path=".lto/BLOCK-1/files/clips/example.mxf",
        tape_id="TAPE-1",
        cassette_number="CASS-1",
        physical_label="B00100",
        volume_label="LTFS-001",
        block_id="BLOCK-1",
        size=1024,
        sha256="a" * 64,
    )
    conflict_record = (
        SimpleNamespace(
            id="conflict-1",
            state="recorded",
            canonical_destination="/srv/restore/PHOTOS/clips/example.mxf",
            observed_size=9,
            observed_sha256="b" * 64,
        )
        if conflict
        else None
    )
    item = SimpleNamespace(
        sequence=1,
        cassette_sequence=1,
        destination_relative_path="PHOTOS/clips/example.mxf",
        canonical_destination="/srv/restore/PHOTOS/clips/example.mxf",
        state="recovery_required" if conflict else "pending",
        bytes_copied=0,
        observed_sha256=None,
        error_code="destination_conflict" if conflict else None,
        conflict=conflict_record,
        plan_item=plan_item,
    )
    cassette = SimpleNamespace(
        sequence=1,
        plan_cassette_sequence=1,
        tape_id="TAPE-1",
        cassette_number="CASS-1",
        physical_label="B00100",
        volume_label="LTFS-001",
        state="recovery_required" if conflict else state,
        item_count=1,
        total_bytes=1024,
        restored_files=0,
        skipped_files=0,
        failed_files=0,
        copied_bytes=0,
        operation_id="operation-restore-1",
        last_error_code="destination_conflict" if conflict else None,
    )
    return SimpleNamespace(
        id="RESTORE-RUN-1",
        plan_id="RESTORE-1",
        actor="web-user-2",
        state="recovery_required" if conflict else state,
        current_cassette_sequence=1,
        total_files=1,
        total_bytes=1024,
        restored_files=0,
        skipped_files=0,
        failed_files=0,
        copied_bytes=0,
        last_error_code="destination_conflict" if conflict else None,
        cassettes=(cassette,),
        items=(item,),
    )


def _share(*, protocol: str = "smb") -> ShareV1:
    config = (
        {
            "kind": "smb",
            "server": "secret-nas.example",
            "share": "private-media",
            "dialect": "3.1.1",
        }
        if protocol == "smb"
        else {
            "kind": "nfs",
            "server": "secret-nfs.example",
            "export": "/private/export",
            "version": "4.2",
            "timeout_seconds": 60,
            "retransmissions": 2,
        }
    )
    return ShareV1.model_validate(
        {
            "share_id": f"{protocol}-media",
            "display_name": f"{protocol.upper()} media",
            "protocol": protocol,
            "lifecycle": "active",
            "desired_state": "connected",
            "observed_state": "connected",
            "safe_error_code": None,
            "last_checked_at": "2026-08-26T10:00:00+00:00",
            "revision": 4,
            "current_operation": None,
            "latest_operation": None,
            "config": config,
            "config_revision": 2,
            "credential_generation": 1 if protocol == "smb" else 0,
            "credential_configured": protocol == "smb",
            "auto_connect": True,
            "mount_identity_sha256": "a" * 64,
            "mounted_config_revision": 2,
            "mounted_credential_generation": 1 if protocol == "smb" else 0,
            "created_at": "2026-08-26T09:00:00+00:00",
            "updated_at": "2026-08-26T10:00:00+00:00",
        }
    )


def _plan(
    *, kind: str = "create", requires_automatic_format_authorization: bool = False
) -> JobPlanV1:
    base = (
        {
            "base_job_id": "JOB-1",
            "base_job_revision": 4,
            "base_job_fingerprint_sha256": "b" * 64,
        }
        if kind == "extend"
        else {}
    )
    return JobPlanV1.model_validate(
        {
            "id": "PLAN-1",
            "state": "ready",
            "kind": kind,
            "creator": "web-user-1",
            "created_at": "2026-08-25T10:00:00+00:00",
            "expires_at": "2026-08-26T10:00:00+00:00",
            "library_ids": ("PHOTOS", "VIDEOS"),
            "media_profile": "LTO-10 PA",
            "capacity_reserve_bytes": 1024,
            "digest_sha256": "a" * 64,
            "requires_automatic_format_authorization": requires_automatic_format_authorization,
            "cassettes": (
                {
                    "sequence": 1,
                    "physical_label": None,
                    "bytes": 7,
                    "objects": 2,
                    "allocation_bytes": 8192,
                    "capacity_utilization": 0.1,
                    "format_required": True,
                    "operation": "format",
                },
            ),
            **base,
        }
    )


class ShareErrorPresentationTests(unittest.TestCase):
    def test_authorization_failure_has_safe_actionable_presentation(self) -> None:
        operation = ShareOperationV1(
            operation_id="share-op-denied",
            share_id="nfs-media",
            action="test",
            state="failed",
            safe_error_code="share_mount_authorization_failed",
            queued_at="2026-08-28T09:40:00+00:00",
            started_at="2026-08-28T09:40:01+00:00",
            finished_at="2026-08-28T09:40:02+00:00",
        )
        model = _share(protocol="nfs").model_copy(
            update={
                "observed_state": "error",
                "safe_error_code": "share_mount_authorization_failed",
                "last_checked_at": "2026-08-28T09:40:02+00:00",
                "latest_operation": operation,
            }
        )

        error = ShareSummaryView.from_model(model).error_detail

        self.assertIsNotNone(error)
        self.assertEqual("Connection blocked by the system", error.title)
        self.assertEqual(
            "Check the installed SELinux/systemd policy, then repeat the test.",
            error.recommendation,
        )
        self.assertEqual("Test share", error.operation)
        self.assertEqual("2026-08-28T09:40:02+00:00", error.occurred_at)
        self.assertEqual("share_mount_authorization_failed", error.code)

    def test_share_operation_error_labels_are_english(self) -> None:
        expected_labels = {
            "connect": "Connection",
            "disconnect": "Disconnection",
            "test": "Test share",
            "reconcile": "Reconciliation",
            "credential.install": "Install credentials",
            "credential.clear": "Remove credentials",
        }

        for action, expected_label in expected_labels.items():
            with self.subTest(action=action):
                operation = ShareOperationV1(
                    operation_id=f"share-op-{action}",
                    share_id="nfs-media",
                    action=action,
                    state="failed",
                    safe_error_code="share_mount_authorization_failed",
                    queued_at="2026-08-28T09:40:00+00:00",
                    started_at="2026-08-28T09:40:01+00:00",
                    finished_at="2026-08-28T09:40:02+00:00",
                )
                model = _share(protocol="nfs").model_copy(
                    update={
                        "observed_state": "error",
                        "safe_error_code": "share_mount_authorization_failed",
                        "latest_operation": operation,
                    }
                )

                error = ShareSummaryView.from_model(model).error_detail

                self.assertIsNotNone(error)
                self.assertEqual(expected_label, error.operation)


def _job() -> JobDetailV1:
    return JobDetailV1.model_validate(
        {
            "id": "JOB-1",
            "display_name": "Backup foto",
            "state": "planned",
            "library_ids": ("PHOTOS", "VIDEOS"),
            "media_profile": "LTO-10 PA",
            "cassettes": (
                {
                    "sequence": 1,
                    "physical_label": "AB1234",
                    "bytes": 7,
                    "objects": 2,
                    "allocation_bytes": 8192,
                    "capacity_utilization": 0.1,
                    "format_required": True,
                    "operation": "format",
                },
            ),
            "requires_format_confirmation": True,
            "resumable": False,
            "revision": 4,
            "created_at": "2026-08-25T10:00:00+00:00",
            "last_activity_at": "2026-08-25T10:00:00+00:00",
            "capabilities": {
                "start": True,
                "rename": True,
                "extend": True,
                "reserve_label": True,
                "retire": True,
                "scan_now": True,
            },
        }
    )


class IncrementalApiModelContractTests(unittest.TestCase):
    def test_v1_job_detail_rejects_sequence_status_extension(self) -> None:
        # A V1 client must continue to reject a new wire field; sequence state
        # therefore belongs on a separately versioned endpoint.
        payload = _job().model_dump()
        payload["sequence_status"] = {
            "authorization_state": "pending",
            "layout_fingerprint_sha256": "b" * 64,
            "next_expected_sequence": 1,
            "next_expected_label": "AB1234",
            "waiting_for_media": False,
        }

        with self.assertRaises(ValidationError):
            JobDetailV1.model_validate(payload)

    def test_incremental_policy_and_scan_result_enforce_schema_35_domains(self):
        terminal_outcomes = (
            "no_changes",
            "extension_queued",
            "waiting_labels",
            "deferred_busy",
            "plan_stale",
            "source_unavailable",
            "failed_safe",
        )
        run_states = (
            "claimed",
            "scanning",
            "no_changes",
            "extension_ready",
            "extension_queued",
            "waiting_labels",
            "deferred_busy",
            "plan_stale",
            "source_unavailable",
            "failed_safe",
        )
        for outcome in terminal_outcomes:
            with self.subTest(last_outcome=outcome):
                policy = IncrementalPolicyV1(
                    job_id="JOB-1",
                    cadence="daily",
                    last_outcome=outcome,
                    revision=1,
                )
                self.assertEqual(outcome, policy.last_outcome)
        for state in run_states:
            with self.subTest(state=state):
                result = IncrementalScanResultV1(
                    run_id="incremental-run-1",
                    state=state,
                    recorded_at="2026-08-29T10:00:00+00:00",
                    plan_id="PLAN-1",
                    plan_digest_sha256="a" * 64,
                    error_code="source_identity_changed",
                )
                self.assertEqual(state, result.state)

        invalid_policy = IncrementalPolicyV1(
            job_id="JOB-1", cadence="daily", revision=1
        ).model_dump()
        invalid_result = IncrementalScanResultV1(
            run_id="incremental-run-1",
            state="no_changes",
            recorded_at="2026-08-29T10:00:00+00:00",
        ).model_dump()
        for mutation in (
            {"last_outcome": "scanning"},
            {"last_outcome": "success"},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                IncrementalPolicyV1.model_validate({**invalid_policy, **mutation})
        for mutation in (
            {"run_id": "../unsafe"},
            {"state": "success"},
            {"plan_id": "../unsafe"},
            {"plan_digest_sha256": "A" * 64},
            {"error_code": "unsafe-code"},
            {"error_code": "a" * 65},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(ValidationError):
                IncrementalScanResultV1.model_validate({**invalid_result, **mutation})

    def test_job_detail_requires_authoritative_format_confirmation_summary(self):
        payload = _job().model_dump()
        payload.pop("requires_format_confirmation")

        with self.assertRaises(ValidationError):
            JobDetailV1.model_validate(payload)

        detail = JobDetailV1.model_validate(
            {**payload, "requires_format_confirmation": True}
        )
        self.assertIs(True, detail.requires_format_confirmation)


class ManagementDaemonFake:
    def __init__(self) -> None:
        self.libraries = (
            _library("PHOTOS", "Foto <famiglia>"),
            _library("VIDEOS", "Video"),
        )
        self.plan = _plan()
        self.job = _job()
        self.retired_job = self.job.model_copy(
            update={
                "id": "JOB-RETIRED",
                "display_name": "Retired archive",
                "state": "retired",
                "capabilities": self.job.capabilities.model_copy(
                    update={
                        "start": False,
                        "resume": False,
                        "pause": False,
                        "rename": False,
                        "extend": False,
                        "reserve_label": False,
                        "retire": False,
                        "scan_now": False,
                    }
                ),
            }
        )
        self.cassettes = self.job.cassettes
        self.sequence_status = {
            "authorization_state": "pending",
            "layout_fingerprint_sha256": "b" * 64,
            "next_expected_sequence": 1,
            "next_expected_label": "AB1234",
            "waiting_for_media": False,
        }
        self.sequence_authorization_receipts: dict[
            str, tuple[tuple[str, object], JobDetailV1]
        ] = {}
        self.sequence_authorization_mutations: list[tuple[str, object]] = []
        self.cassette_calls: list[dict[str, object]] = []
        self.calls: list[tuple[str, object]] = []
        self.catalog_version = _catalog_version()
        self.catalog_history_version = _catalog_version(
            version_id=41,
            relative_path="clips/older.mxf",
            physical_label=None,
            is_current=False,
        )
        self.failure: Exception | None = None
        self.mutation_failure: Exception | None = None
        self.restore_plans: dict[str, object] = {}
        self.restore_plan_receipts: dict[
            str, tuple[tuple[tuple[int, ...], str], object]
        ] = {}
        self.restore_runs: dict[str, object] = {}
        self.restore_run_receipts: dict[str, object] = {}
        self.replacement_response_loss_once = False
        self.replacement_authorization_receipts: dict[str, tuple[tuple[object, ...], object]] = {}
        self.replacement_clock = 1_778_000_000.0
        self.replacement_capability_expiries: dict[str, float] = {}
        self.application = ApplicationSettingsV1(
            revision=2,
            capacity_reserve_bytes=1024,
            minimum_source_file_age_seconds=60,
            copy_buffer_bytes=1024 * 1024,
            content_verification_policy="manifest",
            source_change_detection_policy="size_mtime_change",
            default_media_profile="LTO-10 PA",
            tape_root_directory="archive",
            legacy_tape_capacity_bytes=12_000,
        )
        self.host = HostSettingsV1(
            daemon_socket_path="/run/lto/daemon.sock",
            service_group="lto-web",
            state_directory="/var/lib/lto",
            tape_device_path="/dev/tape/by-id/drive-nst",
            scsi_device_path="/dev/lto-archiver-scsi-drive",
            mount_path="/mnt/lto-archiver/tape",
            managed_source_mount_root="/mnt/lto-archiver/sources",
            source_allowlist=("/srv/source",),
            restore_roots=("/srv/restore",),
            required_restart=False,
        )
        self.shares = (
            _share(),
            _share(protocol="nfs").model_copy(
                update={
                    "desired_state": "disconnected",
                    "observed_state": "disconnected",
                    "mount_identity_sha256": None,
                    "mounted_config_revision": None,
                    "mounted_credential_generation": None,
                }
            ),
        )
        self.critical_proof = CriticalRecoveryProofV1(
            operation_id="critical-op-1",
            job_id="JOB-1",
            cassette_sequence=1,
            expected_label="TAPE01",
            target=CriticalRecoveryTargetV1(
                mount_path_sha256="1" * 64,
                tape_device_identity_sha256="2" * 64,
                scsi_device_identity_sha256="3" * 64,
                expected_media_scope_sha256="4" * 64,
            ),
            daemon_generation=4,
            attempt_number=1,
            last_safe_checkpoint="unmounting",
            evidence_category="contradictory_evidence",
            evidence_sha256="5" * 64,
            observed_media_identity_sha256="6" * 64,
            commands_quiescent=True,
            mount_quiescent=True,
            processes_quiescent=True,
            observed_at="2026-08-28T10:00:00+00:00",
            safe_explanation="Recovery cannot decide safely.",
            safe_next_action="Review a bounded action.",
        )

    def _fail(self) -> None:
        if self.failure is not None:
            raise self.failure

    def get(
        self,
        path: str,
        *,
        response_model,
        principal: str | None = None,
        role: str | None = None,
    ):
        del response_model, principal, role
        self._fail()
        if path == "/api/v1/status":
            from tests.web.test_dashboard import authoritative_status

            return authoritative_status()
        if path == "/api/v1/diagnostics/summary":
            from tests.web.test_runtime_diagnostics import _runtime_summary

            return _runtime_summary()
        if path.startswith("/api/v1/logs?"):
            return LogsPageV1(items=(), next_after_id=None)
        raise AssertionError(f"unexpected daemon GET: {path}")

    def get_system_logs(
        self,
        *,
        source: str,
        severity: str,
        range: str,
        direction: str,
        cursor: str | None,
        search: str | None,
        limit: int,
        principal: str,
        role: str,
    ) -> SystemLogsPageV1:
        del cursor, principal, role
        self._fail()
        return SystemLogsPageV1(
            source=LogSource(source),
            severity=Severity(severity),
            range=LogRange(range),
            direction=LogDirection(direction),
            search=search,
            limit=limit,
            items=(),
            older_cursor=None,
            newer_cursor=None,
            cursor_rotated=False,
            live_supported=True,
            unavailable_sources=(),
        )

    def post(
        self,
        path: str,
        payload: dict,
        idempotency_key: str,
        *,
        principal: str,
        role: str = "admin",
    ) -> dict[str, object]:
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(
            (
                "post",
                {
                    "path": path,
                    "payload": payload,
                    "idempotency_key": idempotency_key,
                    "principal": principal,
                    "role": role,
                },
            )
        )
        return {"id": "operation-1", "state": "accepted"}

    def search_catalog(self, **kwargs):
        self._fail()
        self.calls.append(("search_catalog", kwargs))
        return CatalogSearchPageV1(
            items=(self.catalog_version, self.catalog_history_version),
            next_cursor="catalog-next",
        )

    def browse_catalog(self, **kwargs):
        self._fail()
        self.calls.append(("browse_catalog", kwargs))
        return CatalogBrowsePageV1.model_validate(
            {
                "items": (
                    {
                        "kind": "directory",
                        "name": "clips",
                        "library_id": "PHOTOS",
                        "relative_path": "clips",
                    },
                    {
                        "kind": "file",
                        "name": self.catalog_version.file_name,
                        **self.catalog_version.model_dump(),
                    },
                ),
                "next_cursor": "browse-next",
            }
        )

    def get_catalog_file_version(self, version_id: int, **kwargs):
        self._fail()
        self.calls.append(("get_catalog_file_version", (version_id, kwargs)))
        if version_id != self.catalog_version.id:
            raise DaemonRequestError(404, "catalog_file_version_not_found")
        return self.catalog_version

    def get_catalog_restore_options(self, **kwargs):
        self._fail()
        self.calls.append(("get_catalog_restore_options", kwargs))
        return SimpleNamespace(restore_roots=("/srv/restore", "/srv/restore-alt"))

    def create_catalog_restore_plan(self, request, key: str, **kwargs):
        self._fail()
        self.calls.append(
            ("create_catalog_restore_plan", (request, key, kwargs))
        )
        fingerprint = (
            tuple(request.file_version_ids),
            request.destination_root,
            request.destination_subdirectory,
        )
        receipt = self.restore_plan_receipts.get(key)
        if receipt is not None:
            if receipt[0] != fingerprint:
                raise DaemonRequestError(409, "idempotency_conflict")
            return receipt[1]
        items = tuple(
            SimpleNamespace(
                sequence=index,
                file_version_id=version_id,
                library_id="PHOTOS",
                relative_path=(
                    "clips/example.mxf" if version_id == 42 else "clips/older.mxf"
                ),
                tape_relative_path=(
                    ".lto/BLOCK-1/files/clips/example.mxf"
                    if version_id == 42
                    else ".lto/BLOCK-1/files/clips/older.mxf"
                ),
                tape_id="TAPE-1" if version_id == 42 else "TAPE-2",
                cassette_number="CASS-1" if version_id == 42 else "CASS-2",
                physical_label="B00100" if version_id == 42 else "B00101",
                volume_label="LTFS-001" if version_id == 42 else "LTFS-002",
                block_id="BLOCK-1" if version_id == 42 else "BLOCK-2",
                size=1024,
                sha256=("a" if version_id == 42 else "b") * 64,
                copied_at="2026-08-22T10:00:00+00:00",
                is_current=version_id == 42,
            )
            for index, version_id in enumerate(request.file_version_ids, 1)
        )
        cassettes = tuple(
            SimpleNamespace(
                sequence=index,
                tape_id=item.tape_id,
                cassette_number=item.cassette_number,
                physical_label=item.physical_label,
                item_count=1,
                total_bytes=item.size,
            )
            for index, item in enumerate(items, 1)
        )
        plan = SimpleNamespace(
            id="RESTORE-1",
            state="planned",
            identity_state="exact",
            invalidation_reason=None,
            destination_root=request.destination_root,
            created_by=kwargs["principal"],
            created_at="2026-08-28T10:00:00+00:00",
            total_files=len(items),
            total_bytes=sum(item.size for item in items),
            cassettes=cassettes,
            items=items,
        )
        self.restore_plans[plan.id] = plan
        self.restore_plan_receipts[key] = (fingerprint, plan)
        if self.mutation_failure is not None:
            raise self.mutation_failure
        return plan

    def get_catalog_restore_plan(self, plan_id: str, **kwargs):
        self._fail()
        self.calls.append(("get_catalog_restore_plan", (plan_id, kwargs)))
        return self.restore_plans[plan_id]

    def start_catalog_restore_run(self, plan_id: str, key: str, **kwargs):
        self.calls.append(("start_catalog_restore_run", (plan_id, key, kwargs)))
        run = self.restore_run_receipts.get(key)
        if run is None:
            run = _restore_run()
            self.restore_run_receipts[key] = run
            self.restore_runs[run.id] = run
        if self.mutation_failure is not None:
            raise self.mutation_failure
        return run

    def get_catalog_restore_run(self, run_id: str, **kwargs):
        self.calls.append(("get_catalog_restore_run", (run_id, kwargs)))
        return self.restore_runs[run_id]

    def pause_catalog_restore_run(self, run_id: str, key: str, **kwargs):
        return self._restore_control(run_id, "pause", "paused", key, kwargs)

    def resume_catalog_restore_run(self, run_id: str, key: str, **kwargs):
        return self._restore_control(run_id, "resume", "waiting_media", key, kwargs)

    def cancel_catalog_restore_run(self, run_id: str, key: str, **kwargs):
        return self._restore_control(run_id, "cancel", "cancelled", key, kwargs)

    def _restore_control(self, run_id, action, state, key, kwargs):
        self.calls.append((f"{action}_catalog_restore_run", (run_id, key, kwargs)))
        if self.mutation_failure is not None:
            raise self.mutation_failure
        run = self.restore_runs[run_id]
        run.state = state
        return run

    def issue_catalog_restore_replacement_capability(
        self, key: str, *, reauthentication_context, **kwargs
    ):
        self.calls.append(
            (
                "issue_catalog_restore_replacement_capability",
                (key, reauthentication_context, kwargs),
            )
        )
        capability = "c" * 48
        expiry = self.replacement_clock + 300
        self.replacement_capability_expiries[capability] = expiry
        return SimpleNamespace(
            capability=capability,
            expires_at=datetime.fromtimestamp(expiry, UTC).isoformat(),
        )

    def authorize_catalog_restore_item_replacement(
        self, run_id: str, item_sequence: int, request, key: str, **kwargs
    ):
        self.calls.append(
            (
                "authorize_catalog_restore_item_replacement",
                (run_id, item_sequence, request, key, kwargs),
            )
        )
        fingerprint = (run_id, item_sequence, request.capability)
        receipt = self.replacement_authorization_receipts.get(key)
        if receipt is not None:
            if receipt[0] != fingerprint:
                raise DaemonRequestError(409, "idempotency_conflict")
            return receipt[1]
        if self.replacement_clock > self.replacement_capability_expiries.get(
            request.capability, 0
        ):
            raise DaemonRequestError(409, "restore_run_state_conflict")
        result = SimpleNamespace(id="authorization-1", state="authorized")
        self.replacement_authorization_receipts[key] = (fingerprint, result)
        if self.replacement_response_loss_once:
            self.replacement_response_loss_once = False
            raise DaemonUnavailable()
        return result

    def get_network_share_options(self, **kwargs):
        self._fail()
        return SimpleNamespace(
            nfs_versions=("3", "4", "4.1", "4.2"),
            nfs_timeout_seconds=(5, 15, 30, 60, 120, 300, 600),
            nfs_retransmissions=(1, 2, 3, 5, 10),
            smb_dialects=("3.0", "3.1.1"),
            lifecycles=("active", "disabled"),
        )

    def list_libraries(self, **_kwargs):
        self._fail()
        return self.libraries

    def get_library(self, library_id: str, **_kwargs):
        self._fail()
        return next(item for item in self.libraries if item.id == library_id)

    def create_library(self, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("create_library", (request, key)))
        return _library(request.id, request.display_name)

    def update_library(self, library_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("update_library", (library_id, request, key)))
        return _library(library_id, request.display_name or "Updated")

    def scan_library(self, library_id: str, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("scan_library", (library_id, key)))
        return self.get_library(library_id)

    def retire_library(self, library_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("retire_library", (library_id, request, key)))
        return _library(library_id, "Retired", state="retired")

    def get_media_profiles(self, **_kwargs):
        return MediaProfilesV1.model_validate(
            {
                "default_media_profile": "LTO-10 PA",
                "items": (
                    {
                        "key": "LTO-10 PA",
                        "generation": 10,
                        "native_capacity_bytes": 40_000_000_000_000,
                        "ltfs_usable_bytes": 37_030_000_000_000,
                    },
                ),
            }
        )

    def create_job_plan(self, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("create_job_plan", (request, key)))
        return self.plan

    def get_job_plan(self, _plan_id: str, **_kwargs):
        self._fail()
        return self.plan

    def create_job_from_plan(self, plan_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("create_job_from_plan", (plan_id, request, key)))
        return self.job

    def list_jobs(self, *, include_retired: bool = False, **_kwargs):
        self._fail()
        self.calls.append(("list_jobs", {"include_retired": include_retired}))
        candidates = (self.job, self.retired_job)
        jobs = tuple(
            job for job in candidates if include_retired or job.state != "retired"
        )
        return JobListPageV1(items=jobs, next_cursor=None, current_job_id=None)

    def get_job(self, _job_id: str, **_kwargs):
        self._fail()
        return self.job

    def get_job_sequence_status(self, _job_id: str, **_kwargs):
        self._fail()
        from ltobackup.daemon.api_models import JobSequenceStatusV1

        return JobSequenceStatusV1.model_validate(self.sequence_status)

    def get_job_cassettes(
        self, job_id: str, *, limit: int, cursor: str | None, **_kwargs
    ):
        self._fail()
        self.cassette_calls.append(
            {"job_id": job_id, "limit": limit, "cursor": cursor}
        )
        offset = 0 if cursor is None else int(cursor)
        items = self.cassettes[offset : offset + limit]
        next_offset = offset + len(items)
        return JobCassettePageV1(
            items=items,
            next_cursor=(str(next_offset) if next_offset < len(self.cassettes) else None),
        )

    def get_job_manifest(self, _job_id: str, **_kwargs):
        return JobManifestPageV1(items=(), next_cursor=None)

    def get_job_history(self, _job_id: str, **_kwargs):
        return JobHistoryPageV1(items=(), next_cursor=None)

    def start_job(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("start_job", (job_id, request, key)))

    def resume_job(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("resume_job", (job_id, request, key)))

    def reset_failed_cassette(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("reset_failed_cassette", (job_id, request, key)))
        return self.job

    def authorize_automatic_sequence(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("authorize_automatic_sequence", (job_id, request, key)))
        fingerprint = (job_id, request)
        receipt = self.sequence_authorization_receipts.get(key)
        if receipt is not None:
            if receipt[0] != fingerprint:
                raise DaemonRequestError(409, "idempotency_conflict")
            return receipt[1]
        self.job = self.job.model_copy(
            update={
                "requires_format_confirmation": False,
            }
        )
        self.sequence_status = {**self.sequence_status, "authorization_state": "authorized"}
        self.sequence_authorization_mutations.append(fingerprint)
        self.sequence_authorization_receipts[key] = (fingerprint, self.job)
        return self.job

    def pause_job(self, job_id: str, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("pause_job", (job_id, key)))
        return self.job

    def update_job(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("update_job", (job_id, request, key)))
        return self.job

    def reserve_job_labels(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("reserve_job_labels", (job_id, request, key)))
        return self.job

    def update_incremental_policy(self, job_id: str, request, key: str, **_kwargs):
        self._fail()
        self.calls.append(("update_incremental_policy", (job_id, request, key)))
        return SimpleNamespace(
            job_id=job_id, cadence=request.cadence, revision=request.expected_revision + 1
        )

    def scan_job_now(self, job_id: str, key: str, **_kwargs):
        self._fail()
        self.calls.append(("scan_job_now", (job_id, key)))
        return SimpleNamespace(run_id="RUN-1", state="no_changes")

    def extend_job(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("extend_job", (job_id, request, key)))
        return self.job

    def retire_job(self, job_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("retire_job", (job_id, request, key)))
        self.job = self.job.model_copy(
            update={
                "state": "retired",
                "capabilities": self.retired_job.capabilities,
            }
        )
        return self.job

    def get_application_settings(self, **_kwargs):
        self._fail()
        return self.application

    def get_host_settings(self, **_kwargs):
        self._fail()
        return self.host

    def get_critical_recovery(self, operation_id: str, **_kwargs):
        self._fail()
        self.calls.append(("get_critical_recovery", operation_id))
        return self.critical_proof

    def update_application_settings(self, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("update_application_settings", (request, key)))
        return self.application.model_copy(update={"revision": 3})

    def list_network_shares(self, **_kwargs):
        self._fail()
        return tuple(
            ShareSummaryV1.model_validate(
                item.model_dump(
                    include={
                        "share_id",
                        "display_name",
                        "protocol",
                        "lifecycle",
                        "desired_state",
                        "observed_state",
                        "safe_error_code",
                        "last_checked_at",
                        "revision",
                        "current_operation",
                        "latest_operation",
                    }
                )
            )
            for item in self.shares
        )

    def get_network_share(self, share_id: str, **_kwargs):
        self._fail()
        return next(item for item in self.shares if item.share_id == share_id)

    def create_network_share(self, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("create_network_share", (request, key)))
        return self.shares[0]

    def update_network_share(self, share_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("update_network_share", (share_id, request, key)))
        return self.get_network_share(share_id)

    def install_network_share_credential(
        self, share_id: str, request, key: str, **_kwargs
    ):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(
            ("install_network_share_credential", (share_id, request, key))
        )
        return self._share_operation(share_id, "credential.install")

    def clear_network_share_credential(
        self, share_id: str, request, key: str, **_kwargs
    ):
        self.calls.append(("clear_network_share_credential", (share_id, request, key)))
        return self._share_operation(share_id, "credential.clear")

    def test_network_share(self, share_id: str, request, key: str, **_kwargs):
        self.calls.append(("test_network_share", (share_id, request, key)))
        return self._share_operation(share_id, "test")

    def connect_network_share(self, share_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("connect_network_share", (share_id, request, key)))
        return self._share_operation(share_id, "connect")

    def disconnect_network_share(self, share_id: str, request, key: str, **_kwargs):
        if self.mutation_failure is not None:
            raise self.mutation_failure
        self.calls.append(("disconnect_network_share", (share_id, request, key)))
        return self._share_operation(share_id, "disconnect")

    def reconcile_network_share(self, share_id: str, request, key: str, **_kwargs):
        self.calls.append(("reconcile_network_share", (share_id, request, key)))
        return self._share_operation(share_id, "reconcile")

    def retire_network_share(self, share_id: str, request, key: str, **_kwargs):
        self.calls.append(("retire_network_share", (share_id, request, key)))
        return self.get_network_share(share_id)

    def remove_network_share(self, share_id: str, request, key: str, **_kwargs):
        self.calls.append(("remove_network_share", (share_id, request, key)))
        return self.get_network_share(share_id)

    def get_network_share_operation(self, operation_id: str, **_kwargs):
        return self._share_operation("smb-media", "connect", operation_id=operation_id)

    @staticmethod
    def _share_operation(
        share_id: str, action: str, *, operation_id: str = "share-op-1"
    ):
        return ShareOperationV1(
            operation_id=operation_id,
            share_id=share_id,
            action=action,
            state="queued",
            safe_error_code=None,
            queued_at="2026-08-26T10:00:00+00:00",
            started_at=None,
            finished_at=None,
        )


class ManagementViewTests(unittest.TestCase):
    def test_job_source_check_shows_safe_action_and_escaped_file_names(self):
        payload = self.daemon.job.model_dump()
        payload["source_check"] = {
            "cassette_sequence": 2, "state": "blocked", "checked_files": 3,
            "missing_files": 1, "changed_files": 1, "unavailable_libraries": 0,
            "checked_at": "2026-09-06T17:00:00+00:00",
            "issues": [{"library_id": "LIB1", "relative_path": "<script>bad</script>.bin",
                        "code": "source_missing"}],
        }
        self.daemon.job = JobDetailV1.model_validate(payload)
        self.login("admin", "correct horse battery staple")
        response = self.client.get("/jobs/JOB-1")
        self.assertEqual(200, response.status_code, response.text)
        self.assertIn("Source check", response.text)
        self.assertIn("Automatic continuation was held at this check", response.text)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;.bin", response.text)
        self.assertNotIn("<script>bad</script>", response.text)
        refreshed = self.client.get("/partials/jobs/JOB-1/runtime")
        self.assertEqual(200, refreshed.status_code, refreshed.text)
        self.assertIn("Source check", refreshed.text)
        self.assertIn("&lt;script&gt;bad&lt;/script&gt;.bin", refreshed.text)

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = AuthStore(Path(self.temporary.name) / "auth.db")
        self.admin = self.store.create_admin("admin", "correct horse battery staple")
        self.operator = self.store.create_user(
            "operator",
            "operator password material",
            role="operator",
            actor_user_id=self.admin.id,
            idempotency_key="create-operator",
        )
        self.daemon = ManagementDaemonFake()
        self.app = create_web_app(WebSettings(), self.store, self.daemon)
        self.client = TestClient(
            self.app,
            base_url="https://console.example",
            follow_redirects=False,
        )
        self.addCleanup(self.client.close)

    def login(self, username: str, password: str) -> None:
        page = self.client.get("/login")
        token = re.search(r'name="login_csrf" value="([A-Za-z0-9_-]+)"', page.text)
        assert token is not None
        response = self.client.post(
            "/login",
            data={
                "username": username,
                "password": password,
                "login_csrf": token.group(1),
            },
        )
        self.assertEqual(303, response.status_code, response.text)

    def establish_session(self, user) -> None:
        session = self.app.state.session_manager.create(user)
        self.client.cookies.set("lto_archiver_session", session.cookie)
        self.client.cookies.set("lto_archiver_csrf", session.csrf_token)

    @staticmethod
    def hidden(response, name: str) -> str:
        match = re.search(rf'name="{re.escape(name)}" value="([^"]*)"', response.text)
        if match is None:
            raise AssertionError(f"missing hidden field {name}: {response.text}")
        return match.group(1)

    def successful_form_fields(
        self,
        response,
        action: str,
        *,
        updates: dict[str, str | None] | None = None,
    ) -> dict[str, str]:
        parser = _FieldAssociationParser()
        parser.feed(response.text)
        forms = [
            index
            for index, node in enumerate(parser.nodes)
            if node["tag"] == "form" and node["attrs"].get("action") == action
        ]
        self.assertEqual(1, len(forms), response.text)
        form_index = forms[0]
        payload: dict[str, str] = {}
        available: set[str] = set()
        for index, node in enumerate(parser.nodes):
            if not parser.is_descendant(index, form_index):
                continue
            attrs = node["attrs"]
            name = attrs.get("name")
            if not isinstance(name, str):
                continue
            available.add(name)
            if node["tag"] == "input":
                input_type = str(attrs.get("type", "text")).casefold()
                if input_type in {"submit", "button", "reset", "file"}:
                    continue
                if input_type in {"checkbox", "radio"} and "checked" not in attrs:
                    continue
                payload[name] = str(attrs.get("value", "on"))
            elif node["tag"] == "select":
                options = [
                    candidate
                    for candidate_index, candidate in enumerate(parser.nodes)
                    if candidate["tag"] == "option"
                    and parser.is_descendant(candidate_index, index)
                ]
                selected = next(
                    (option for option in options if "selected" in option["attrs"]),
                    options[0] if options else None,
                )
                if selected is not None:
                    payload[name] = str(selected["attrs"].get("value", ""))
        for name, value in (updates or {}).items():
            self.assertIn(name, available, (name, action, response.text))
            if value is None:
                payload.pop(name, None)
            else:
                payload[name] = value
        return payload

    def assert_field_error_association(
        self,
        response,
        *,
        field: str,
        action: str,
        control_name: str | None,
        allowed_data: tuple[str, ...] = (),
    ) -> None:
        assert_english_document(
            self,
            response.text,
            allowed_data=allowed_data,
        )
        parser = _FieldAssociationParser()
        parser.feed(response.text)
        errors = [
            (index, node)
            for index, node in enumerate(parser.nodes)
            if node["attrs"].get("data-field-error") == field
        ]
        self.assertEqual(1, len(errors), response.text)
        _error_index, error = errors[0]
        error_id = error["attrs"].get("id")
        self.assertIsInstance(error_id, str, response.text)
        self.assertEqual(
            1,
            sum(node["attrs"].get("id") == error_id for node in parser.nodes),
            response.text,
        )
        references = []
        for index, node in enumerate(parser.nodes):
            attrs = node["attrs"]
            tokens = (
                str(attrs.get("aria-describedby", "")).split()
                + str(attrs.get("aria-errormessage", "")).split()
            )

            if error_id in tokens:
                references.append((index, node))
        self.assertTrue(references, response.text)

        forms = [
            (index, node)
            for index, node in enumerate(parser.nodes)
            if node["tag"] == "form" and node["attrs"].get("action") == action
        ]
        self.assertEqual(1, len(forms), response.text)
        form_index, form = forms[0]
        form_references = [
            (index, node)
            for index, node in references
            if index == form_index or parser.is_descendant(index, form_index)
        ]
        self.assertTrue(form_references, response.text)
        self.assertEqual(references, form_references, response.text)
        for _index, node in form_references:
            self.assertEqual("true", node["attrs"].get("aria-invalid"), response.text)
        if control_name is None:
            self.assertIn((form_index, form), form_references, response.text)
        else:
            self.assertTrue(
                any(
                    node["attrs"].get("name") == control_name
                    or (
                        node["tag"] == "fieldset"
                        and any(
                            descendant["attrs"].get("name") == control_name
                            and parser.is_descendant(descendant_index, index)
                            for descendant_index, descendant in enumerate(parser.nodes)
                        )
                    )
                    for index, node in form_references
                ),
                response.text,
            )

    def auth_mutation_snapshot(self) -> tuple[object, ...]:
        with sqlite3.connect(self.store.database) as connection:
            users = tuple(
                connection.execute(
                    "SELECT id, login_name, role, lifecycle, credential_generation "
                    "FROM web_users ORDER BY id"
                )
            )
            sessions = tuple(
                connection.execute(
                    "SELECT token_hash, user_id, credential_generation, revoked_at, "
                    "reauthenticated_at FROM web_sessions ORDER BY token_hash"
                )
            )
            receipts = tuple(
                connection.execute(
                    "SELECT * FROM web_idempotency ORDER BY idempotency_key"
                )
            )
            audit = tuple(
                connection.execute("SELECT * FROM web_auth_audit ORDER BY id")
            )
        return users, sessions, receipts, audit

    def test_critical_recovery_page_has_exactly_three_closed_admin_forms(self):
        self.establish_session(self.admin)
        cookie = self.client.cookies.get("lto_archiver_session")
        assert cookie is not None
        self.assertTrue(
            self.app.state.session_manager.reauthenticate(
                cookie,
                "correct horse battery staple",
                idempotency_key="management-critical-reauth",
            )
        )

        response = self.client.get("/critical-recovery/critical-op-1")

        self.assertEqual(200, response.status_code, response.text)
        parser = _FieldAssociationParser()
        parser.feed(response.text)
        actions = [
            node["attrs"].get("action")
            for node in parser.nodes
            if node["tag"] == "form"
            and str(node["attrs"].get("action", "")).startswith(
                "/critical-recovery/"
            )
        ]
        self.assertEqual(
            [
                "/critical-recovery/critical-op-1/reconcile",
                "/critical-recovery/critical-op-1/authorize-replacement",
                "/critical-recovery/critical-op-1/abandon",
            ],
            actions,
        )
        self.assertNotIn("command=", response.text)
        self.assertNotIn("arguments", response.text)
        self.assertNotIn("force", response.text)

    def test_standard_testclient_language_route_fragment_and_error_matrix(self):
        login = self.client.get("/login")
        self.assertEqual(200, login.status_code, login.text)
        assert_english_document(self, login.text)

        self.establish_session(self.admin)
        cookie = self.client.cookies.get("lto_archiver_session")
        assert cookie is not None
        self.assertTrue(
            self.app.state.session_manager.reauthenticate(
                cookie,
                "correct horse battery staple",
                idempotency_key="language-matrix-reauthentication",
            )
        )
        restore_plan = self.daemon.create_catalog_restore_plan(
            SimpleNamespace(
                file_version_ids=(42,),
                destination_root="/srv/restore",
                destination_subdirectory="",
            ),
            "language-matrix-restore",
            principal="web-user-1",
            role="admin",
        )

        pages = {
            "dashboard": self.client.get("/"),
            "libraries": self.client.get("/libraries"),
            "library-detail": self.client.get("/libraries/PHOTOS"),
            "shares": self.client.get("/shares"),
            "share-new": self.client.get("/shares/new?protocol=nfs"),
            "share-detail": self.client.get("/shares/smb-media"),
            "jobs": self.client.get("/jobs"),
            "job-new": self.client.get("/jobs/new"),
            "job-detail": self.client.get("/jobs/JOB-1"),
            "job-plan": self.client.get("/jobs/plans/PLAN-1"),
            "media": self.client.get("/media"),
            "catalog": self.client.get("/catalog?q=example"),
            "catalog-detail": self.client.get("/catalog/file-versions/42"),
            "restore-plan": self.client.get(f"/restore-plans/{restore_plan.id}"),
            "diagnostics": self.client.get("/diagnostics"),
            "logs": self.client.get("/logs?limit=50"),
            "settings": self.client.get("/settings"),
            "users": self.client.get("/users"),
            "account": self.client.get("/account"),
            "critical-recovery": self.client.get(
                "/critical-recovery/critical-op-1"
            ),
        }

        restore_plan.identity_state = "legacy_invalid"
        restore_plan.invalidation_reason = "legacy_physical_identity_ambiguous"
        restore_plan.cassettes[0].physical_label = None
        restore_plan.items[0].physical_label = None
        pages["restore-plan-invalid"] = self.client.get(
            f"/restore-plans/{restore_plan.id}"
        )

        self.daemon.mutation_failure = DaemonUnavailable()
        pages["restore-retry"] = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(pages["catalog"], "csrf"),
                "idempotency_key": str(uuid4()),
                "destination_root": "/srv/restore",
                "file_version_ids": ["42", "41"],
            },
        )
        self.daemon.mutation_failure = None

        self.daemon.mutation_failure = DaemonUnavailable()
        pages["share-update-retry"] = self.client.post(
            "/shares/smb-media/update",
            data={
                "csrf": self.hidden(pages["share-detail"], "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
                "display_name": "Archivio SMB",
                "protocol": "smb",
                "server": "nas-retry.example",
                "remote_resource": "archive-retry",
                "dialect": "3.0",
                "lifecycle": "disabled",
            },
        )
        self.daemon.mutation_failure = None

        self.daemon.mutation_failure = DaemonUnavailable()
        pages["share-credential-retry"] = self.client.post(
            "/shares/smb-media/credential",
            data={
                "csrf": self.hidden(pages["share-detail"], "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
                "username": "retry-user",
                "domain": "RETRY",
                "password": "retry-secret-never-rendered",
            },
        )
        self.daemon.mutation_failure = None

        self.daemon.mutation_failure = DaemonUnavailable()
        pages["share-status-retry"] = self.client.post(
            "/shares/smb-media/disconnect",
            data={
                "csrf": self.hidden(pages["share-detail"], "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
                "typed_share_id": "smb-media",
            },
        )
        self.daemon.mutation_failure = None

        self.daemon.mutation_failure = DaemonConflict(
            "active_operation",
            {
                "id": "active-op-1",
                "kind": "archive",
                "state": "running",
                "phase": "copying",
                "job_id": "JOB-1",
                "cassette_sequence": 4,
                "started_at": "2026-08-29T10:00:00Z",
            },
        )
        pages["operation-conflict"] = self.client.post(
            "/media/4/format",
            data={
                "csrf": self.hidden(pages["account"], "csrf"),
                "idempotency_key": str(uuid4()),
                "typed_label": "TAPE<04>",
            },
        )
        self.daemon.mutation_failure = None
        allowed_user_data = {
            "dashboard": (
                "Archivio <script>alert(1)</script>",
                "LTO & <drive>",
                "TAPE<04>",
            ),
            "libraries": ("Foto <famiglia>", "Video"),
            "library-detail": ("Foto <famiglia>",),
            "shares": ("SMB media", "NFS media"),
            "share-new": (),
            "share-detail": ("SMB media",),
            "jobs": ("Backup foto",),
            "job-new": ("Foto <famiglia>", "Video"),
            "job-detail": ("Backup foto",),
            "job-plan": (),
            "media": ("TAPE<04>",),
            "catalog": ("Foto <famiglia>", "Backup <notturno>"),
            "catalog-detail": ("Foto <famiglia>", "Backup <notturno>"),
            "restore-plan": (),
            "diagnostics": (),
            "logs": (),
            "settings": (),
            "users": ("admin", "operator"),
            "account": ("admin",),
            "critical-recovery": (),
            "restore-plan-invalid": (),
            "restore-retry": (),
            "share-update-retry": ("Archivio SMB",),
            "share-credential-retry": (),
            "share-status-retry": (),
            "operation-conflict": (),
        }
        self.assertEqual(set(pages), set(allowed_user_data))
        for name, page in pages.items():
            with self.subTest(route=name):
                self.assertIn(page.status_code, (200, 409, 503), page.text)
                assert_english_document(
                    self,
                    page.text,
                    allowed_data=allowed_user_data[name],
                )

        fragments = {
            "status": self.client.get("/status-fragment"),
            "share-status": self.client.get(
                "/shares/smb-media/status-fragment"
            ),
            "diagnostics-summary": self.client.get(
                "/diagnostics/summary-fragment"
            ),
        }
        fragment_user_data = {
            "status": (
                "Archivio <script>alert(1)</script>",
                "LTO & <drive>",
                "TAPE<04>",
            ),
            "share-status": ("SMB media",),
            "diagnostics-summary": (),
        }
        self.assertEqual(set(fragments), set(fragment_user_data))
        for name, fragment in fragments.items():
            with self.subTest(fragment=name):
                self.assertEqual(200, fragment.status_code, fragment.text)
                assert_english_surface(
                    self,
                    fragment.text,
                    allowed_data=fragment_user_data[name],
                )

        validation_pages = {
            "catalog-query": self.client.get("/catalog?limit=0"),
            "critical-identifier": self.client.get(
                f"/critical-recovery/{'x' * 129}"
            ),
        }
        for name, page in validation_pages.items():
            with self.subTest(validation=name):
                self.assertEqual(422, page.status_code, page.text)
                assert_english_document(self, page.text)

        self.daemon.failure = DaemonUnavailable()
        daemon_unavailable = self.client.get("/catalog")
        self.daemon.failure = None
        self.assertEqual(503, daemon_unavailable.status_code, daemon_unavailable.text)
        assert_english_document(self, daemon_unavailable.text)

        self.daemon.failure = DaemonRequestError(
            409,
            "settings_revision_conflict",
        )
        revision_conflict = self.client.get("/settings")
        self.daemon.failure = None
        self.assertEqual(409, revision_conflict.status_code, revision_conflict.text)
        assert_english_document(self, revision_conflict.text)

    def test_catalog_requires_authentication_and_is_present_in_navigation(self):
        anonymous = self.client.get("/catalog")
        self.assertEqual(303, anonymous.status_code, anonymous.text)
        self.assertEqual("/login", anonymous.headers["location"])

        self.login("admin", "correct horse battery staple")
        page = self.client.get("/catalog")

        self.assertEqual(200, page.status_code, page.text)
        self.assertIn('href="/catalog" aria-current="page"', page.text)
        self.assertIn("Catalog", page.text)
        self.assertIn('class="catalog-search"', page.text)
        self.assertIn("The catalog does not read bytes from tapes", page.text)

    def test_catalog_search_forwards_all_bounded_filters_and_escapes_results(self):
        self.login("admin", "correct horse battery staple")
        query = {
            "mode": "search",
            "q": "example",
            "library_id": "PHOTOS",
            "job_id": "JOB-1",
            "cassette": "B00100",
            "sha256": "a" * 64,
            "min_size": "1",
            "max_size": "2048",
            "copied_after": "2026-08-01T00:00:00+00:00",
            "copied_before": "2026-08-23T00:00:00+00:00",
            "include_history": "true",
            "limit": "25",
            "cursor": "search-cursor",
        }

        response = self.client.get("/catalog", params=query)

        self.assertEqual(200, response.status_code, response.text)
        self.assertIn("B00100", response.text)
        self.assertIn("LTFS-001", response.text)
        self.assertIn("Historical", response.text)
        self.assertIn("Foto &lt;famiglia&gt;", response.text)
        self.assertIn("Backup &lt;notturno&gt;", response.text)
        self.assertNotIn("owner <unsafe>", response.text)
        self.assertIn("catalog-next", response.text)
        name, kwargs = self.daemon.calls[-1]
        self.assertEqual("search_catalog", name)
        self.assertEqual("example", kwargs["q"])
        self.assertEqual("PHOTOS", kwargs["library_id"])
        self.assertEqual("JOB-1", kwargs["job_id"])
        self.assertEqual("B00100", kwargs["cassette"])
        self.assertEqual(1, kwargs["min_size"])
        self.assertEqual(2048, kwargs["max_size"])
        self.assertTrue(kwargs["include_history"])
        self.assertEqual(25, kwargs["limit"])
        self.assertEqual("search-cursor", kwargs["cursor"])

        next_link = re.search(r'href="([^"]*catalog-next[^"]*)"', response.text)
        self.assertIsNotNone(next_link, response.text)
        follow = self.client.get(unescape(next_link.group(1)))
        self.assertEqual(200, follow.status_code, follow.text)
        name, next_kwargs = self.daemon.calls[-1]
        self.assertEqual("search_catalog", name)
        self.assertTrue(next_kwargs["include_history"])
        self.assertEqual("catalog-next", next_kwargs["cursor"])

    def test_catalog_browse_paginates_safe_paths_and_detail_is_metadata_only(self):
        self.login("admin", "correct horse battery staple")
        browse = self.client.get(
            "/catalog",
            params={
                "mode": "browse",
                "library_id": "PHOTOS",
                "parent_path": "clips",
                "browse_cursor": "browse-cursor",
                "limit": "50",
            },
        )

        self.assertEqual(200, browse.status_code, browse.text)
        self.assertIn("clips", browse.text)
        self.assertIn("browse-next", browse.text)
        self.assertIn("parent_path=clips", browse.text)
        name, kwargs = self.daemon.calls[-1]
        self.assertEqual("browse_catalog", name)
        self.assertEqual("PHOTOS", kwargs["library_id"])
        self.assertEqual("clips", kwargs["parent_path"])
        self.assertEqual("browse-cursor", kwargs["cursor"])
        self.assertEqual(50, kwargs["limit"])

        browse_next = re.search(r'href="([^"]*browse-next[^"]*)"', browse.text)
        self.assertIsNotNone(browse_next, browse.text)
        next_page = self.client.get(unescape(browse_next.group(1)))
        self.assertEqual(200, next_page.status_code, next_page.text)
        name, next_kwargs = self.daemon.calls[-1]
        self.assertEqual("browse_catalog", name)
        self.assertEqual("clips", next_kwargs["parent_path"])
        self.assertEqual("browse-next", next_kwargs["cursor"])
        self.assertEqual(50, next_kwargs["limit"])

        breadcrumb = re.search(
            r'<nav class="catalog-breadcrumbs"[^>]*>(.*?)</nav>',
            browse.text,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(breadcrumb, browse.text)
        breadcrumb_href = next(
            href
            for href in re.findall(r'href="([^"]+)"', breadcrumb.group(1))
            if "parent_path=clips" in unescape(href)
        )
        crumb_page = self.client.get(unescape(breadcrumb_href))
        self.assertEqual(200, crumb_page.status_code, crumb_page.text)
        name, crumb_kwargs = self.daemon.calls[-1]
        self.assertEqual("browse_catalog", name)
        self.assertEqual("clips", crumb_kwargs["parent_path"])
        self.assertIsNone(crumb_kwargs["cursor"])
        self.assertEqual(50, crumb_kwargs["limit"])

        detail = self.client.get("/catalog/file-versions/42")
        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn(".lto/BLOCK-1/files/clips/example.mxf", detail.text)
        self.assertIn("does not read bytes from tapes or mount tapes", detail.text)
        self.assertIn("SHA-256", detail.text)
        self.assertNotIn("/dev/tape", detail.text)

    def test_catalog_uses_explicit_modes_and_rejects_mixed_cursors_or_filters(self):
        self.login("admin", "correct horse battery staple")
        default_search = self.client.get("/catalog", params={"library_id": "PHOTOS"})
        self.assertEqual(200, default_search.status_code, default_search.text)
        self.assertEqual("search_catalog", self.daemon.calls[-1][0])

        search = self.client.get(
            "/catalog", params={"mode": "search", "library_id": "PHOTOS"}
        )
        self.assertEqual(200, search.status_code, search.text)
        self.assertEqual("search_catalog", self.daemon.calls[-1][0])

        browse = self.client.get(
            "/catalog",
            params={"mode": "browse", "library_id": "PHOTOS", "limit": "25"},
        )
        self.assertEqual(200, browse.status_code, browse.text)
        self.assertEqual("browse_catalog", self.daemon.calls[-1][0])
        self.assertIn("mode=browse", unescape(browse.text))

        for query in (
            "mode=search&library_id=PHOTOS&parent_path=clips",
            "mode=search&library_id=PHOTOS&browse_cursor=next",
            "mode=browse",
            "mode=browse&library_id=PHOTOS&q=forbidden",
            "mode=browse&library_id=PHOTOS&cursor=search-next",
        ):
            with self.subTest(query=query):
                response = self.client.get(f"/catalog?{query}")
                self.assertEqual(422, response.status_code, response.text)

    def test_catalog_normalizes_client_compatible_filters_and_escapes_browse_and_detail(
        self,
    ):
        self.login("admin", "correct horse battery staple")
        uppercase_hash = "A" * 64
        accepted = self.client.get(
            "/catalog",
            params={
                "mode": "search",
                "library_id": "LIBRARY-1",
                "job_id": "JOB." + "x" * 124,
                "sha256": uppercase_hash,
            },
        )
        self.assertEqual(200, accepted.status_code, accepted.text)
        self.assertEqual(uppercase_hash.lower(), self.daemon.calls[-1][1]["sha256"])

        for query in (
            "library_id=A%3AB",
            f"library_id={'A' * 65}",
            f"job_id={'A' * 129}",
            f"cassette={'A' * 129}",
        ):
            with self.subTest(query=query):
                self.assertEqual(422, self.client.get(f"/catalog?{query}").status_code)

        malicious = "clips/<svg onload=alert(1)>"
        browse = self.client.get(
            "/catalog",
            params={
                "mode": "browse",
                "library_id": "PHOTOS",
                "parent_path": malicious,
                "limit": "25",
            },
        )
        self.assertEqual(200, browse.status_code, browse.text)
        self.assertNotIn("<svg onload=alert(1)>", browse.text)
        self.assertIn("parent_path=clips%2F%3Csvg", unescape(browse.text))
        self.assertIn("limit=25", unescape(browse.text))
        self.assertIn('role="region"', browse.text)
        self.assertIn('tabindex="0"', browse.text)
        self.assertIn('aria-label="Catalog results"', browse.text)

        self.daemon.catalog_version = self.daemon.catalog_version.model_copy(
            update={"owner_name": "<img src=x onerror=alert(1)>"}
        )
        detail = self.client.get("/catalog/file-versions/42")
        self.assertEqual(200, detail.status_code, detail.text)
        self.assertNotIn("<img src=x onerror=alert(1)>", detail.text)

        missing = self.client.get("/catalog/file-versions/99")
        self.assertEqual(404, missing.status_code, missing.text)

    def test_catalog_rejects_invalid_queries_and_handles_operator_and_daemon_errors(
        self,
    ):
        self.login("admin", "correct horse battery staple")
        invalid = self.client.get("/catalog?limit=201&limit=1")
        self.assertEqual(422, invalid.status_code, invalid.text)

        self.client.post(
            "/logout", data={"csrf": self.hidden(self.client.get("/catalog"), "csrf")}
        )
        self.login("operator", "operator password material")
        operator = self.client.get("/catalog")
        self.assertEqual(200, operator.status_code, operator.text)
        self.assertIn("Catalog", operator.text)

        self.daemon.failure = DaemonUnavailable()
        unavailable = self.client.get("/catalog")
        self.assertEqual(503, unavailable.status_code, unavailable.text)
        self.assertIn("Daemon unavailable", unavailable.text)

    def test_catalog_builds_a_durable_offline_restore_plan_without_operations(self):
        # Removing the typed planning POST, cassette ordering, or exact version
        # identity would leave catalog search unable to prepare an offline restore.
        self.login("operator", "operator password material")
        catalog = self.client.get("/catalog", params={"q": "example"})

        self.assertEqual(200, catalog.status_code, catalog.text)
        self.assertIn('action="/catalog/restore-plans"', catalog.text)
        self.assertIn('name="file_version_ids" value="42"', catalog.text)
        self.assertRegex(
            catalog.text,
            r'<select name="destination_root"[^>]*>.*?'
            r'<option value="/srv/restore">/srv/restore</option>',
        )

        created = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(catalog, "csrf"),
                "idempotency_key": self.hidden(catalog, "idempotency_key"),
                "destination_root": "/srv/restore",
                "file_version_ids": ["42", "41"],
            },
        )

        self.assertEqual(303, created.status_code, created.text)
        self.assertEqual("/restore-plans/RESTORE-1", created.headers["location"])
        detail = self.client.get(created.headers["location"])
        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn("B00100", detail.text)
        self.assertIn("B00101", detail.text)
        self.assertLess(detail.text.index("B00100"), detail.text.index("B00101"))
        self.assertIn("clips/example.mxf", detail.text)
        self.assertIn("clips/older.mxf", detail.text)
        self.assertIn("Catalog version 42", detail.text)
        self.assertIn("Catalog version 41", detail.text)
        self.assertIn("/srv/restore", detail.text)
        name, (request, key, kwargs) = next(
            call
            for call in self.daemon.calls
            if call[0] == "create_catalog_restore_plan"
        )
        self.assertEqual("create_catalog_restore_plan", name)
        self.assertEqual((42, 41), request.file_version_ids)
        self.assertEqual("/srv/restore", request.destination_root)
        self.assertTrue(key)
        self.assertEqual("operator", kwargs["role"])
        self.assertFalse(
            any(
                call_name in {
                    "start_job",
                    "resume_job",
                    "scan_library",
                    "connect_network_share",
                    "test_network_share",
                }
                for call_name, _payload in self.daemon.calls
            )
        )

    def test_restore_plan_preserves_versions_and_rejects_unsafe_subdirectories_before_daemon(self):
        """Removing WebUI subdirectory validation would mutate the daemon with an escaping path."""
        self.login("operator", "operator password material")
        catalog = self.client.get("/catalog", params={"q": "example"})
        self.assertIn('name="destination_subdirectory"', catalog.text)
        self.assertRegex(catalog.text, r'<select name="destination_root"[^>]*>')

        before = len([call for call in self.daemon.calls if call[0] == "create_catalog_restore_plan"])
        for unsafe in ("../escape", "/absolute", "folder\\child", "folder\x00child"):
            with self.subTest(unsafe=repr(unsafe)):
                response = self.client.post(
                    "/catalog/restore-plans",
                    data={
                        "csrf": self.hidden(catalog, "csrf"),
                        "idempotency_key": str(uuid4()),
                        "destination_root": "/srv/restore",
                        "destination_subdirectory": unsafe,
                        "file_version_ids": ["42", "41"],
                    },
                )
                self.assertEqual(422, response.status_code, response.text)
        after = len([call for call in self.daemon.calls if call[0] == "create_catalog_restore_plan"])
        self.assertEqual(before, after)

        created = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(catalog, "csrf"),
                "idempotency_key": str(uuid4()),
                "destination_root": "/srv/restore",
                "destination_subdirectory": "requested/2026",
                "file_version_ids": ["42", "41"],
            },
        )
        self.assertEqual(303, created.status_code, created.text)
        request = next(
            payload[0]
            for name, payload in reversed(self.daemon.calls)
            if name == "create_catalog_restore_plan"
        )
        self.assertEqual((42, 41), request.file_version_ids)
        self.assertEqual("requested/2026", request.destination_subdirectory)

    def test_restore_plan_starts_and_run_controls_are_guided_and_replay_safe(self):
        """Removing the run routes or replay key would make restore require manual tape controls."""
        self.login("operator", "operator password material")
        catalog = self.client.get("/catalog")
        created = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(catalog, "csrf"),
                "idempotency_key": str(uuid4()),
                "destination_root": "/srv/restore",
                "destination_subdirectory": "",
                "file_version_ids": ["42"],
            },
        )
        plan = self.client.get(created.headers["location"])
        self.assertIn("Start restore", plan.text)
        self.assertIn('data-required-cassette="B00100"', plan.text)
        self.assertNotRegex(plan.text.casefold(), r'name="cassette|>load<|>continue<')

        key = self.hidden(plan, "idempotency_key")
        self.daemon.mutation_failure = DaemonUnavailable()
        ambiguous = self.client.post(
            "/restore-plans/RESTORE-1/runs",
            data={"csrf": self.hidden(plan, "csrf"), "idempotency_key": key},
        )
        self.assertEqual(503, ambiguous.status_code, ambiguous.text)
        self.assertIn(f'name="idempotency_key" value="{key}"', ambiguous.text)
        self.daemon.mutation_failure = None
        replay = self.client.post(
            "/restore-plans/RESTORE-1/runs",
            data={"csrf": self.hidden(ambiguous, "csrf"), "idempotency_key": key},
        )
        self.assertEqual(303, replay.status_code, replay.text)
        self.assertEqual("/restore-runs/RESTORE-RUN-1", replay.headers["location"])
        self.assertEqual(1, len(self.daemon.restore_runs))

        run = self.client.get(replay.headers["location"])
        self.assertIn("Insert cassette B00100", run.text)
        self.assertIn("Instantaneous rate (raw)", run.text)
        self.assertIn("Effective rate (operation window)", run.text)
        self.assertIn("Cancellation keeps files already restored", run.text)
        self.assertIn('data-live-fragment-url="/restore-runs/RESTORE-RUN-1/status-fragment"', run.text)
        pause = self.client.post(
            "/restore-runs/RESTORE-RUN-1/pause",
            data={"csrf": self.hidden(run, "csrf"), "idempotency_key": str(uuid4())},
        )
        self.assertEqual(303, pause.status_code, pause.text)
        paused = self.client.get("/restore-runs/RESTORE-RUN-1")
        self.assertIn("Resume", paused.text)

    def test_restore_replacement_requires_recent_admin_and_sends_only_session_digest(self):
        """Removing the recent-admin gate would expose exact replacement to ordinary operators."""
        self.login("operator", "operator password material")
        self.daemon.restore_runs["RESTORE-RUN-1"] = _restore_run(conflict=True)
        operator = self.client.get("/restore-runs/RESTORE-RUN-1")
        self.assertIn("Existing destination differs", operator.text)
        self.assertNotIn("Authorize exact replacement", operator.text)

        self.client.post("/logout", data={"csrf": self.hidden(operator, "csrf")})
        self.login("admin", "correct horse battery staple")
        stale = self.client.get("/restore-runs/RESTORE-RUN-1")
        self.assertNotIn("Authorize exact replacement", stale.text)
        self.app.state.session_manager.reauthenticate(
            self.client.cookies.get("lto_archiver_session"),
            "correct horse battery staple",
            idempotency_key="restore-admin-reauth",
        )
        fresh = self.client.get("/restore-runs/RESTORE-RUN-1")
        self.assertIn("Authorize exact replacement", fresh.text)
        self.assertNotIn(self.client.cookies.get("lto_archiver_session"), fresh.text)
        response = self.client.post(
            "/restore-runs/RESTORE-RUN-1/items/1/replacement-authorizations",
            data={"csrf": self.hidden(fresh, "csrf"), "idempotency_key": str(uuid4())},
        )
        self.assertEqual(303, response.status_code, response.text)
        names = [name for name, _ in self.daemon.calls[-2:]]
        self.assertEqual(
            [
                "issue_catalog_restore_replacement_capability",
                "authorize_catalog_restore_item_replacement",
            ],
            names,
        )
        context = self.daemon.calls[-2][1][1]
        self.assertRegex(context.session_binding_sha256, r"^[0-9a-f]{64}$")

    def test_catalog_and_restore_surfaces_keep_label_first_identity_fields_separate(self):
        self.login("operator", "operator password material")
        logical_path = "I Flintstones /<unsafe>.mkv"
        physical_path = "~lto1~I Flintstones%20/%3Cunsafe%3E.mkv"
        self.daemon.catalog_version = _catalog_version(
            relative_path=logical_path,
            physical_label=None,
        ).model_copy(update={"tape_relative_path": physical_path})

        search = self.client.get("/catalog", params={"q": "unsafe"})
        browse = self.client.get(
            "/catalog",
            params={"mode": "browse", "library_id": "PHOTOS"},
        )
        detail = self.client.get("/catalog/file-versions/42")

        for page in (search, browse, detail):
            with self.subTest(url=str(page.url)):
                self.assertEqual(200, page.status_code, page.text)
                self.assertIn('data-catalog-field="physical-label"', page.text)
                self.assertIn('data-value-state="unknown"', page.text)
                self.assertIn('data-catalog-field="tape-id"', page.text)
                self.assertIn('data-catalog-field="cassette-number"', page.text)
                self.assertIn('data-catalog-field="volume-label"', page.text)
                self.assertIn('data-catalog-field="block-id"', page.text)
                self.assertIn('data-catalog-field="logical-path"', page.text)
                self.assertIn('data-catalog-field="tape-relative-path"', page.text)
                self.assertIn('data-catalog-field="sha256"', page.text)
                self.assertIn('data-catalog-field="version-state"', page.text)
                self.assertIn('data-catalog-field="size"', page.text)
                self.assertIn('data-catalog-field="copied-at"', page.text)
                self.assertIn('data-catalog-field="library-id"', page.text)
                self.assertIn('data-catalog-field="library-name"', page.text)
                self.assertIn('data-catalog-field="job-id"', page.text)
                self.assertIn('data-catalog-field="job-name"', page.text)
                for selection_field in (
                    "physical-label",
                    "tape-id",
                    "cassette-number",
                    "volume-label",
                    "block-id",
                    "logical-path",
                    "tape-relative-path",
                    "size",
                    "sha256",
                    "version-state",
                ):
                    self.assertIn(
                        f'data-restore-selection-field="{selection_field}"',
                        page.text,
                    )
                self.assertNotIn("LTFS-001 / cassetta CASS-1", page.text)
                self.assertNotIn(logical_path, page.text)
                self.assertIn("I Flintstones /&lt;unsafe&gt;.mkv", page.text)
                self.assertIn(physical_path, page.text)
                self.assertNotRegex(
                    page.text,
                    r'(?:href|action|id)="[^"]*I Flintstones',
                )
                assert_english_document(
                    self,
                    page.text,
                    allowed_data=("Foto <famiglia>",),
                )

        created = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(search, "csrf"),
                "idempotency_key": self.hidden(search, "idempotency_key"),
                "destination_root": "/srv/restore",
                "file_version_ids": ["42"],
            },
        )
        plan = self.daemon.restore_plans["RESTORE-1"]
        plan.cassettes[0].physical_label = None
        plan.items[0].physical_label = None
        plan.items[0].relative_path = logical_path
        plan.items[0].tape_relative_path = physical_path
        restore = self.client.get(created.headers["location"])
        self.assertEqual(200, restore.status_code, restore.text)
        for field in (
            "physical-label",
            "tape-id",
            "cassette-number",
            "volume-label",
            "block-id",
            "logical-path",
            "tape-relative-path",
            "size",
            "copied-at",
            "sha256",
            "version-state",
        ):
            self.assertIn(f'data-catalog-field="{field}"', restore.text)
        self.assertIn('data-value-state="unknown"', restore.text)
        self.assertNotIn("Cassette CASS-1", restore.text)
        self.assertNotRegex(
            restore.text,
            r'(?:href|action|id)="[^"]*I Flintstones',
        )
        assert_english_document(
            self,
            restore.text,
            allowed_data=("Foto <famiglia>",),
        )

    def test_restore_response_loss_replays_exact_selection_and_rejects_collision(self):
        self.login("operator", "operator password material")
        catalog = self.client.get("/catalog", params={"q": "example"})
        key = self.hidden(catalog, "idempotency_key")
        submitted = {
            "csrf": self.hidden(catalog, "csrf"),
            "idempotency_key": key,
            "destination_root": "/srv/restore",
            "file_version_ids": ["42", "41"],
        }
        self.daemon.mutation_failure = DaemonUnavailable()

        ambiguous = self.client.post("/catalog/restore-plans", data=submitted)

        self.assertEqual(503, ambiguous.status_code, ambiguous.text)
        self.assertIn('action="/catalog/restore-plans"', ambiguous.text)
        self.assertIn(f'name="idempotency_key" value="{key}"', ambiguous.text)
        self.assertIn('name="destination_root" value="/srv/restore"', ambiguous.text)
        self.assertIn('name="file_version_ids" value="42"', ambiguous.text)
        self.assertIn('name="file_version_ids" value="41"', ambiguous.text)
        self.assertEqual(1, len(self.daemon.restore_plans))

        self.daemon.mutation_failure = None
        replay = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(ambiguous, "csrf"),
                "idempotency_key": key,
                "destination_root": "/srv/restore",
                "file_version_ids": ["42", "41"],
            },
        )
        self.assertEqual(303, replay.status_code, replay.text)
        self.assertEqual("/restore-plans/RESTORE-1", replay.headers["location"])
        self.assertEqual(1, len(self.daemon.restore_plans))

        collision = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(ambiguous, "csrf"),
                "idempotency_key": key,
                "destination_root": "/srv/restore",
                "file_version_ids": ["42"],
            },
        )
        self.assertEqual(409, collision.status_code, collision.text)
        self.assertIn('data-error-code="idempotency_conflict"', collision.text)
        self.assertIn("Field: idempotency_key", collision.text)
        restore_calls = [
            payload
            for name, payload in self.daemon.calls
            if name == "create_catalog_restore_plan"
        ]
        self.assertEqual(3, len(restore_calls))
        self.assertEqual(
            [(42, 41), (42, 41), (42,)],
            [tuple(payload[0].file_version_ids) for payload in restore_calls],
        )
        self.assertEqual([key, key, key], [payload[1] for payload in restore_calls])

    def test_legacy_invalid_restore_plan_renders_safe_non_executable_status(self):
        self.login("operator", "operator password material")
        catalog = self.client.get("/catalog")
        created = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(catalog, "csrf"),
                "idempotency_key": self.hidden(catalog, "idempotency_key"),
                "destination_root": "/srv/restore",
                "file_version_ids": ["42"],
            },
        )
        plan = self.daemon.restore_plans["RESTORE-1"]
        plan.identity_state = "legacy_invalid"
        plan.invalidation_reason = "legacy_physical_identity_ambiguous"
        plan.cassettes[0].physical_label = None
        plan.items[0].physical_label = None

        detail = self.client.get(created.headers["location"])

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn(
            'data-error-code="legacy_physical_identity_ambiguous"', detail.text
        )
        self.assertIn("Historical plan cannot be used", detail.text)
        self.assertNotIn("percorso LTFS", detail.text)
        self.assertNotIn("Avvia", detail.text)
        self.assertFalse(
            any(
                name in {"start_job", "scan_library", "connect_network_share"}
                for name, _payload in self.daemon.calls
            )
        )

    def test_restore_protocol_loss_preserves_the_bounded_replay_authority(self):
        self.login("operator", "operator password material")
        catalog = self.client.get("/catalog")
        key = self.hidden(catalog, "idempotency_key")
        self.daemon.mutation_failure = DaemonProtocolError(
            "restore response was outside the closed contract"
        )

        ambiguous = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(catalog, "csrf"),
                "idempotency_key": key,
                "destination_root": "/srv/restore",
                "file_version_ids": ["42", "41"],
            },
        )

        self.assertEqual(503, ambiguous.status_code, ambiguous.text)
        self.assertIn(
            'data-error-code="restore_plan_outcome_ambiguous"', ambiguous.text
        )
        self.assertIn(f'name="idempotency_key" value="{key}"', ambiguous.text)
        self.assertIn('name="file_version_ids" value="42"', ambiguous.text)
        self.assertIn('name="file_version_ids" value="41"', ambiguous.text)
        self.assertNotIn("outside the closed contract", ambiguous.text)

    def test_generic_daemon_errors_expose_safe_context_and_stable_codes(self):
        self.login("admin", "correct horse battery staple")
        cases = (
            (
                DaemonUnavailable(),
                "/catalog",
                503,
                "daemon_unavailable",
                "/catalog",
            ),
            (
                DaemonRequestError(409, "settings_revision_conflict"),
                "/settings",
                409,
                "settings_revision_conflict",
                "/settings",
            ),
            (
                DaemonRequestError(404, "catalog_file_version_not_found"),
                "/catalog/file-versions/42",
                404,
                "catalog_file_version_not_found",
                "/catalog",
            ),
        )
        for failure, path, status, code, next_path in cases:
            with self.subTest(code=code):
                self.daemon.failure = failure
                response = self.client.get(path)
                self.assertEqual(status, response.status_code, response.text)
                self.assertIn(f'data-error-code="{code}"', response.text)
                self.assertIn(f"Code: {code}", response.text)
                self.assertIn('data-error-part="explanation"', response.text)
                self.assertIn('data-error-part="next-action"', response.text)
                self.assertIn(f'href="{next_path}"', response.text)
                assert_english_document(self, response.text)
        self.daemon.failure = None

    def test_generic_daemon_error_codes_fail_closed_for_get_and_mutation(self):
        self.login("admin", "correct horse battery staple")
        catalog = self.client.get("/catalog")
        failures = (None, "", "unknown_daemon_detail", "x" * 129, "bad/code")
        for detail in failures:
            with self.subTest(detail=detail):
                self.daemon.failure = DaemonRequestError(500, detail)
                response = self.client.get("/catalog")
                self.assertEqual(503, response.status_code, response.text)
                self.assertIn('data-error-code="daemon_rejected"', response.text)
                self.assertIn("Operation unavailable", response.text)
                self.assertIn('data-error-part="next-action"', response.text)
                assert_english_document(self, response.text)

        self.daemon.failure = None
        self.daemon.mutation_failure = DaemonRequestError(500, None)
        mutation = self.client.post(
            "/catalog/restore-plans",
            data={
                "csrf": self.hidden(catalog, "csrf"),
                "idempotency_key": self.hidden(catalog, "idempotency_key"),
                "destination_root": "/srv/restore",
                "file_version_ids": ["42"],
            },
        )
        self.assertEqual(503, mutation.status_code, mutation.text)
        self.assertIn('data-error-code="daemon_rejected"', mutation.text)
        self.assertIn("Action: restore.plan.create", mutation.text)
        assert_english_document(
            self,
            mutation.text,
            allowed_data=("Foto <famiglia>", "Backup foto"),
        )

    def test_library_pages_escape_values_render_degraded_html_and_enforce_roles(self):
        self.login("admin", "correct horse battery staple")
        listing = self.client.get("/libraries")
        detail = self.client.get("/libraries/PHOTOS")

        self.assertEqual(200, listing.status_code)
        self.assertEqual(200, detail.status_code)
        self.assertIn("Foto &lt;famiglia&gt;", listing.text)
        self.assertIn('action="/libraries"', listing.text)
        self.assertIn('action="/libraries/PHOTOS/retire"', detail.text)
        self.client.post("/logout", data={"csrf": self.hidden(listing, "csrf")})
        self.login("operator", "operator password material")
        operator_detail = self.client.get("/libraries/PHOTOS")
        self.assertIn('action="/libraries/PHOTOS/scan"', operator_detail.text)
        self.assertNotIn('action="/libraries/PHOTOS/retire"', operator_detail.text)

        self.daemon.failure = DaemonUnavailable()
        degraded = self.client.get("/libraries")
        self.assertEqual(503, degraded.status_code)
        self.assertIn("Daemon unavailable", degraded.text)
        self.assertNotIn('{"error":', degraded.text)

    def test_library_pages_present_the_guided_source_workflow(self):
        # Removing the workflow explanation or rendering both source modes at
        # once makes it unclear which fields configure a usable library.
        self.login("admin", "correct horse battery staple")
        listing = self.client.get("/libraries")
        detail = self.client.get("/libraries/PHOTOS")

        self.assertEqual(200, listing.status_code, listing.text)
        self.assertIn(
            "A library identifies source data to include in backups",
            listing.text,
        )
        self.assertIn('data-library-form', listing.text)
        self.assertIn(
            'data-library-source-panel="configured_path"', listing.text
        )
        self.assertIn(
            'data-library-source-panel="managed_share"', listing.text
        )
        self.assertIn('href="/shares"', listing.text)
        self.assertIn("The ID is suggested automatically", listing.text)
        self.assertIn("Create library", listing.text)

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn("Next step", detail.text)
        self.assertIn("Scan and verify", detail.text)

    def test_library_list_translates_every_scan_state_for_operators(self):
        # A running scan must not leak the daemon enum into the Italian UI.
        self.daemon.libraries = (
            self.daemon.libraries[0].model_copy(update={"scan_state": "running"}),
            self.daemon.libraries[1],
        )
        self.login("admin", "correct horse battery staple")

        listing = self.client.get("/libraries")

        self.assertEqual(200, listing.status_code, listing.text)
        self.assertIn("Scan running", listing.text)
        self.assertNotIn(">running<", listing.text)

    def test_library_list_formats_file_counts_and_storage_sizes_for_operators(self):
        """Raw catalog integers make large libraries difficult to compare."""
        self.daemon.libraries = (
            self.daemon.libraries[0].model_copy(
                update={"file_count": 35_894, "byte_count": 2_409_544_728_948}
            ),
        )
        self.login("admin", "correct horse battery staple")

        listing = self.client.get("/libraries")

        self.assertEqual(200, listing.status_code, listing.text)
        self.assertIn('data-label="Files">35,894', listing.text)
        self.assertIn('data-label="Size">2.19 TiB', listing.text)
        self.assertNotIn("2409544728948", listing.text)

    def test_library_edit_only_offers_source_changes_supported_by_daemon(self):
        # Existing managed-share bindings are immutable; offering a source
        # selector here would advertise transitions the daemon rejects.
        self.login("admin", "correct horse battery staple")
        local = self.client.get("/libraries/PHOTOS")
        self.assertEqual(200, local.status_code, local.text)
        self.assertIn(
            'type="hidden" name="source_kind" value="configured_path"',
            local.text,
        )
        self.assertIn('name="source_root"', local.text)
        self.assertNotIn('type="radio" name="source_kind"', local.text)

        managed = LibrarySummaryV1.model_validate(
            {
                **self.daemon.libraries[0].model_dump(),
                "source_root": None,
                "source": {
                    "kind": "managed_share",
                    "share_id": "smb-media",
                    "relative_subpath": "films",
                },
            }
        )
        self.daemon.libraries = (managed, self.daemon.libraries[1])
        page = self.client.get("/libraries/PHOTOS")
        self.assertEqual(200, page.status_code, page.text)
        self.assertIn("To change the source, create a new library", page.text)
        self.assertIn(
            'type="hidden" name="source_kind" value="managed_share"',
            page.text,
        )
        self.assertIn('type="hidden" name="share_id" value="smb-media"', page.text)
        self.assertNotIn('<select id="library-share"', page.text)
        self.assertNotIn('type="radio" name="source_kind"', page.text)

        renamed = self.client.post(
            "/libraries/PHOTOS/update",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "expected_revision": str(managed.revision),
                "display_name": "Film rinominati",
                "source_kind": "managed_share",
                "share_id": "smb-media",
                "relative_subpath": "films",
                "state": managed.state,
            },
        )
        self.assertEqual(303, renamed.status_code, renamed.text)
        _name, (_library_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual("Film rinominati", request.display_name)
        self.assertIsNone(request.source)
        self.assertIsNone(request.source_root)

    def test_library_mutations_use_csrf_exact_ids_and_prg(self):
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/libraries")
        response = self.client.post(
            "/libraries",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "library_id": "MUSIC",
                "display_name": "Musica",
                "source_root": "/srv/source/music",
            },
        )
        self.assertEqual(303, response.status_code, response.text)
        self.assertEqual("/libraries/MUSIC", response.headers["location"])
        name, (request, _key) = self.daemon.calls[-1]
        self.assertEqual("create_library", name)
        self.assertEqual("MUSIC", request.id)

        detail = self.client.get("/libraries/PHOTOS")
        duplicated = self.client.post(
            "/libraries/PHOTOS/update",
            content=(
                f"csrf={self.hidden(detail, 'csrf')}&"
                f"idempotency_key={self.hidden(detail, 'idempotency_key')}&"
                "display_name=One&display_name=Two"
            ),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(422, duplicated.status_code)
        self.assertEqual(1, len(self.daemon.calls))

    def test_share_pages_are_role_redacted_and_protocol_specific(self):
        self.login("admin", "correct horse battery staple")
        listing = self.client.get("/shares")
        smb = self.client.get("/shares/smb-media")
        nfs = self.client.get("/shares/nfs-media")

        self.assertEqual(200, listing.status_code, listing.text)
        self.assertEqual(200, smb.status_code, smb.text)
        self.assertEqual(1, smb.text.count('aria-current="page"'))
        self.assertIn("SMB media", listing.text)
        self.assertIn("secret-nas.example", smb.text)
        self.assertIn('name="password"', smb.text)
        self.assertNotIn('name="password"', nfs.text)
        self.assertNotIn('name="username"', nfs.text)

        self.client.post("/logout", data={"csrf": self.hidden(smb, "csrf")})
        self.login("operator", "operator password material")
        operator = self.client.get("/shares/smb-media")
        self.assertEqual(200, operator.status_code, operator.text)
        self.assertIn("SMB media", operator.text)
        self.assertIn(
            "<dt>State</dt><dd>Active — automatic connection</dd>",
            operator.text,
        )
        self.assertNotIn("secret-nas.example", operator.text)
        self.assertNotIn("private-media", operator.text)
        self.assertNotIn('name="password"', operator.text)
        self.assertNotIn('action="/shares/smb-media/', operator.text)

    def test_share_failure_is_actionable_in_detail_and_concise_in_list(self):
        failed_operation = ShareOperationV1(
            operation_id="share-op-denied",
            share_id="nfs-media",
            action="test",
            state="failed",
            safe_error_code="share_mount_authorization_failed",
            queued_at="2026-08-28T09:40:00+00:00",
            started_at="2026-08-28T09:40:01+00:00",
            finished_at="2026-08-28T09:40:02+00:00",
        )
        self.daemon.shares = (
            self.daemon.shares[0],
            self.daemon.shares[1].model_copy(
                update={
                    "observed_state": "error",
                    "safe_error_code": "share_mount_authorization_failed",
                    "last_checked_at": "2026-08-28T09:40:02+00:00",
                    "latest_operation": failed_operation,
                }
            ),
        )
        self.login("admin", "correct horse battery staple")

        detail = self.client.get("/shares/nfs-media")
        listing = self.client.get("/shares")
        fragment = self.client.get("/shares/nfs-media/status-fragment")

        for response in (detail, fragment):
            self.assertEqual(200, response.status_code, response.text)
            self.assertIn('class="share-error-panel"', response.text)
            self.assertIn('role="alert"', response.text)
            self.assertIn("Connection blocked by the system", response.text)
            self.assertIn(
                "Check the installed SELinux/systemd policy", response.text
            )
            self.assertIn("Test share", response.text)
            self.assertIn("2026-08-28T09:40:02+00:00", response.text)
            self.assertIn("<summary>Technical details</summary>", response.text)
            self.assertIn("share_mount_authorization_failed", response.text)
        self.assertEqual(200, listing.status_code, listing.text)
        self.assertIn("Connection blocked by the system", listing.text)
        self.assertNotIn("share_mount_authorization_failed", listing.text)

    def test_operator_missing_share_is_a_closed_not_found_response(self):
        self.login("operator", "operator password material")

        detail = self.client.get("/shares/missing-share")
        fragment = self.client.get("/shares/missing-share/status-fragment")

        for response in (detail, fragment):
            self.assertEqual(404, response.status_code, response.text)
            self.assertIn("Share unavailable", response.text)
            self.assertNotIn("StopIteration", response.text)
            self.assertNotIn("raw daemon", response.text)

    def test_share_list_exposes_refreshable_status_fragments_for_each_row(self):
        self.login("admin", "correct horse battery staple")

        listing = self.client.get("/shares")

        self.assertEqual(200, listing.status_code, listing.text)
        for share_id in ("smb-media", "nfs-media"):
            self.assertEqual(
                1,
                listing.text.count(f'id="share-status-{share_id}"'),
                listing.text,
            )
            self.assertIn(
                f'data-share-id="{share_id}" data-share-mode="list"',
                listing.text,
            )

    def test_share_protocol_forms_submit_only_the_active_discriminated_variant(self):
        self.login("admin", "correct horse battery staple")
        nfs_create = self.client.get("/shares/new?protocol=nfs")
        smb_create = self.client.get("/shares/new?protocol=smb")
        connected = self.client.get("/shares/smb-media")
        disconnected = self.client.get("/shares/nfs-media")

        self.assertIn('name="protocol" value="nfs"', nfs_create.text)
        self.assertIn('name="nfs_version"', nfs_create.text)
        self.assertNotIn('name="dialect"', nfs_create.text)
        self.assertIn('name="protocol" value="smb"', smb_create.text)
        self.assertIn('name="dialect"', smb_create.text)
        self.assertNotIn('name="nfs_version"', smb_create.text)
        self.assertNotIn('name="timeout_seconds"', smb_create.text)
        self.assertNotIn('name="retransmissions"', smb_create.text)
        self.assertIn('type="hidden" name="protocol" value="smb"', connected.text)
        self.assertNotIn('type="radio" name="protocol"', connected.text)
        self.assertIn('type="radio" name="protocol" value="nfs"', disconnected.text)
        self.assertIn('type="radio" name="protocol" value="smb"', disconnected.text)

    def test_share_lifecycle_is_the_only_connection_control(self):
        self.login("admin", "correct horse battery staple")
        create_page = self.client.get("/shares/new?protocol=nfs")
        connected_detail = self.client.get("/shares/smb-media")

        self.assertNotIn('name="auto_connect"', create_page.text)
        self.assertNotIn('name="auto_connect"', connected_detail.text)
        self.assertNotIn('/shares/smb-media/connect', connected_detail.text)
        self.assertNotIn('/shares/smb-media/disconnect', connected_detail.text)
        for retained_action in (
            "test",
            "reconcile",
            "credential/clear",
            "retire",
            "delete",
        ):
            self.assertIn(
                f'/shares/smb-media/{retained_action}', connected_detail.text
            )
        self.assertIn(
            "Active shares connect automatically.",
            create_page.text,
        )
        self.assertIn(
            "Disable the share to keep it disconnected.",
            connected_detail.text,
        )
        self.assertIn(
            "Active — automatic connection",
            connected_detail.text,
        )
        self.assertIn("Disabled — disconnected", connected_detail.text)

        self.daemon.shares = (
            self.daemon.shares[0],
            self.daemon.shares[1].model_copy(update={"lifecycle": "disabled"}),
        )
        disabled_detail = self.client.get("/shares/nfs-media")
        self.assertIn(
            "<dt>State</dt><dd>Disabled — disconnected</dd>",
            disabled_detail.text,
        )

        create_payload = self.successful_form_fields(
            create_page,
            "/shares",
            updates={
                "share_id": "automatic-nfs",
                "display_name": "NFS automatica",
                "server": "nas.example.example",
                "remote_resource": "/archive",
                "nfs_version": "4.1",
                "timeout_seconds": "60",
                "retransmissions": "2",
            },
        )
        created = self.client.post("/shares", data=create_payload)

        self.assertEqual(303, created.status_code, created.text)
        name, (request, _key) = self.daemon.calls[-1]
        self.assertEqual("create_network_share", name)
        self.assertTrue(request.auto_connect)

    def test_no_javascript_nfs_to_smb_preview_then_update_uses_present_controls(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/nfs-media")
        preview_action = "/shares/nfs-media/update-preview"
        preview_payload = self.successful_form_fields(
            detail,
            preview_action,
            updates={
                "protocol": "smb",
                "display_name": "Archivio rete",
                "server": "files.example.example",
                "lifecycle": "disabled",
            },
        )
        self.assertNotIn("idempotency_key", preview_payload)
        baseline = len(self.daemon.calls)

        preview = self.client.post(preview_action, data=preview_payload)

        self.assertEqual(200, preview.status_code, preview.text)
        self.assertEqual(baseline, len(self.daemon.calls))
        update_action = "/shares/nfs-media/update"
        update_payload = self.successful_form_fields(
            preview,
            update_action,
            updates={"remote_resource": "archive", "dialect": "3.0"},
        )
        self.assertNotIn("nfs_version", update_payload)
        self.assertNotIn("timeout_seconds", update_payload)
        self.assertNotIn("retransmissions", update_payload)
        self.assertNotIn("username", update_payload)
        self.assertNotIn("domain", update_payload)
        self.assertNotIn("password", update_payload)

        updated = self.client.post(update_action, data=update_payload)

        self.assertEqual(303, updated.status_code, updated.text)
        name, (_share_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual("update_network_share", name)
        self.assertEqual("smb", request.config.kind)
        self.assertEqual("3.0", request.config.dialect)
        self.assertEqual("Archivio rete", request.display_name)
        self.assertIsNone(request.auto_connect)
        self.assertEqual("disabled", request.lifecycle)

    def test_no_javascript_smb_to_nfs_preview_then_update_uses_present_controls(self):
        self.daemon.shares = (
            self.daemon.shares[0].model_copy(
                update={
                    "desired_state": "disconnected",
                    "observed_state": "disconnected",
                    "mount_identity_sha256": None,
                    "mounted_config_revision": None,
                    "mounted_credential_generation": None,
                }
            ),
            self.daemon.shares[1],
        )
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        preview_action = "/shares/smb-media/update-preview"
        preview_payload = self.successful_form_fields(
            detail,
            preview_action,
            updates={"protocol": "nfs", "server": "nfs.example.example"},
        )
        self.assertNotIn("idempotency_key", preview_payload)
        baseline = len(self.daemon.calls)

        preview = self.client.post(preview_action, data=preview_payload)

        self.assertEqual(200, preview.status_code, preview.text)
        self.assertEqual(baseline, len(self.daemon.calls))
        self.assertNotIn('name="username"', preview.text)
        self.assertNotIn('name="domain"', preview.text)
        self.assertNotIn('name="password"', preview.text)
        update_action = "/shares/smb-media/update"
        update_payload = self.successful_form_fields(
            preview,
            update_action,
            updates={
                "remote_resource": "/exports/archive",
                "nfs_version": "4.1",
                "timeout_seconds": "120",
                "retransmissions": "5",
            },
        )
        self.assertNotIn("dialect", update_payload)
        self.assertNotIn("username", update_payload)
        self.assertNotIn("domain", update_payload)
        self.assertNotIn("password", update_payload)

        updated = self.client.post(update_action, data=update_payload)

        self.assertEqual(303, updated.status_code, updated.text)
        name, (_share_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual("update_network_share", name)
        self.assertEqual("nfs", request.config.kind)
        self.assertEqual("4.1", request.config.version)
        self.assertEqual(120, request.config.timeout_seconds)
        self.assertEqual(5, request.config.retransmissions)

    def test_share_update_preview_is_closed_csrf_guarded_and_admin_only(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/nfs-media")
        csrf = self.hidden(detail, "csrf")
        baseline = len(self.daemon.calls)

        missing_csrf = self.client.post(
            "/shares/nfs-media/update-preview",
            data={"expected_revision": "4", "protocol": "smb"},
        )
        self.assertEqual(403, missing_csrf.status_code, missing_csrf.text)

        duplicate = self.client.post(
            "/shares/nfs-media/update-preview",
            content=(f"csrf={csrf}&expected_revision=4&protocol=nfs&protocol=smb"),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(422, duplicate.status_code, duplicate.text)

        secret = "must-not-cross-preview"
        extra_credential = self.client.post(
            "/shares/nfs-media/update-preview",
            data={
                "csrf": csrf,
                "expected_revision": "4",
                "protocol": "smb",
                "password": secret,
            },
        )
        self.assertEqual(422, extra_credential.status_code, extra_credential.text)
        self.assertNotIn(secret, extra_credential.text)
        self.assertEqual(baseline, len(self.daemon.calls))

        self.client.post("/logout", data={"csrf": csrf})
        self.login("operator", "operator password material")
        account = self.client.get("/account")
        denied = self.client.post(
            "/shares/nfs-media/update-preview",
            data={
                "csrf": self.hidden(account, "csrf"),
                "expected_revision": "4",
                "protocol": "smb",
            },
        )
        self.assertEqual(403, denied.status_code, denied.text)
        self.assertEqual(baseline, len(self.daemon.calls))

    def test_share_update_preview_rejects_stale_and_connected_state_on_protocol(self):
        self.login("admin", "correct horse battery staple")
        disconnected = self.client.get("/shares/nfs-media")
        baseline = len(self.daemon.calls)

        stale = self.client.post(
            "/shares/nfs-media/update-preview",
            data={
                "csrf": self.hidden(disconnected, "csrf"),
                "expected_revision": "3",
                "display_name": "NFS media",
                "protocol": "smb",
                "server": "nas.example.example",
                "remote_resource": "/private/export",
                "nfs_version": "4.2",
                "timeout_seconds": "60",
                "retransmissions": "2",
                "lifecycle": "active",
            },
        )
        self.assertEqual(422, stale.status_code, stale.text)
        self.assert_field_error_association(
            stale,
            field="expected_revision",
            action="/shares/nfs-media/update-preview",
            control_name="expected_revision",
        )

        connected = self.client.get("/shares/smb-media")
        rejected = self.client.post(
            "/shares/smb-media/update-preview",
            data={
                "csrf": self.hidden(connected, "csrf"),
                "expected_revision": "4",
                "display_name": "SMB media",
                "protocol": "nfs",
                "server": "nfs.example.example",
                "remote_resource": "private-media",
                "dialect": "3.1.1",
                "lifecycle": "active",
            },
        )
        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assert_field_error_association(
            rejected,
            field="protocol",
            action="/shares/smb-media/update",
            control_name="protocol",
        )
        self.assertEqual(baseline, len(self.daemon.calls))

    def test_connected_share_rejects_protocol_change_before_mutation(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        baseline = len(self.daemon.calls)

        changed = self.client.post(
            "/shares/smb-media/update",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "display_name": "SMB media",
                "protocol": "nfs",
                "server": "nfs.example.example",
                "remote_resource": "/export/archive",
                "nfs_version": "4.2",
                "timeout_seconds": "60",
                "retransmissions": "2",
                "lifecycle": "active",
            },
        )

        self.assertEqual(422, changed.status_code, changed.text)
        self.assertEqual(baseline, len(self.daemon.calls))
        self.assert_field_error_association(
            changed,
            field="protocol",
            action="/shares/smb-media/update",
            control_name=None,
        )

    def test_disconnected_share_rejects_unknown_protocol_before_mutation(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/nfs-media")
        baseline = len(self.daemon.calls)

        changed = self.client.post(
            "/shares/nfs-media/update",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "display_name": "NFS media",
                "protocol": "ftp",
                "server": "files.example.example",
                "remote_resource": "archive",
                "dialect": "3.1.1",
                "lifecycle": "active",
            },
        )

        self.assertEqual(422, changed.status_code, changed.text)
        self.assertEqual(baseline, len(self.daemon.calls))
        self.assert_field_error_association(
            changed,
            field="protocol",
            action="/shares/nfs-media/update",
            control_name="protocol",
        )

    def test_share_create_and_credentials_are_closed_write_only_prg_forms(self):
        password = "do-not-render-this-secret"
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/shares/new")
        created = self.client.post(
            "/shares",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "share_id": "smb-new",
                "display_name": "Nuovo SMB",
                "protocol": "smb",
                "server": "nas.example",
                "remote_resource": "archive",
                "dialect": "3.1.1",
            },
        )
        self.assertEqual(303, created.status_code, created.text)
        self.assertEqual("/shares/smb-media", created.headers["location"])

        detail = self.client.get("/shares/smb-media")
        installed = self.client.post(
            "/shares/smb-media/credential",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "username": "backup-user",
                "domain": "ARCHIVE",
                "password": password,
            },
        )
        self.assertEqual(303, installed.status_code, installed.text)
        self.assertNotIn(password, installed.text)
        _name, (_share_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual(password, request.password)

        self.daemon.mutation_failure = DaemonRequestError(
            422, "share_authentication_failed"
        )
        failed = self.client.post(
            "/shares/smb-media/credential",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
                "username": "backup-user",
                "domain": "ARCHIVE",
                "password": password,
            },
        )
        self.assertEqual(422, failed.status_code)
        self.assertNotIn(password, failed.text)
        self.assertNotIn("raw daemon", failed.text)
        self.assertNotIn('value="backup-user"', failed.text)
        self.assertNotIn('value="ARCHIVE"', failed.text)
        self.assertNotRegex(failed.text, r'name="password"[^>]+value=')

    def test_share_create_validation_preserves_safe_protocol_fields_and_targets_control(
        self,
    ):
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/shares/new")
        key = self.hidden(page, "idempotency_key")

        invalid = self.client.post(
            "/shares",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": key,
                "share_id": "nfs-retry",
                "display_name": "Archivio NFS",
                "protocol": "nfs",
                "server": "nfs.example.example",
                "remote_resource": "/exports/archive",
                "nfs_version": "4.1",
                "timeout_seconds": "not-an-integer",
                "retransmissions": "7",
            },
        )

        self.assertEqual(422, invalid.status_code, invalid.text)
        for expected in (
            'name="share_id" required value="nfs-retry"',
            'name="display_name" required value="Archivio NFS"',
            'name="server" required value="nfs.example.example"',
            'name="remote_resource" required value="/exports/archive"',
            'name="protocol" value="nfs" required checked',
            'select name="timeout_seconds"',
            'select name="retransmissions"',
        ):
            self.assertIn(expected, invalid.text)
        self.assertNotIn('<option value="7">', invalid.text)
        self.assertRegex(
            invalid.text,
            r'<option value="4\.1" selected>4\.1</option>',
        )
        self.assert_field_error_association(
            invalid,
            field="timeout_seconds",
            action="/shares",
            control_name="timeout_seconds",
        )

    def test_closed_daemon_share_validation_preserves_safe_fields_on_exact_control(
        self,
    ):
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/shares/new?protocol=smb")
        self.daemon.mutation_failure = DaemonRequestError(
            422, "share_endpoint_not_allowed"
        )

        rejected = self.client.post(
            "/shares",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "share_id": "smb-rejected",
                "display_name": "Archivio SMB rifiutato",
                "protocol": "smb",
                "server": "blocked.example.example",
                "remote_resource": "archive",
                "dialect": "3.0",
            },
        )

        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertIn('name="share_id" required value="smb-rejected"', rejected.text)
        self.assertIn(
            'name="server" required value="blocked.example.example"', rejected.text
        )
        self.assertIn('<option value="3.0" selected>3.0</option>', rejected.text)
        self.assertNotIn('name="auto_connect"', rejected.text)
        self.assertNotIn("raw daemon", rejected.text)
        self.assert_field_error_association(
            rejected,
            field="server",
            action="/shares",
            control_name="server",
        )

    def test_share_update_daemon_validation_preserves_all_safe_controls(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")

        def reject_update(*_args, **_kwargs):
            raise DaemonRequestError(422, "share_endpoint_not_allowed")

        self.daemon.update_network_share = reject_update
        rejected = self.client.post(
            "/shares/smb-media/update",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "display_name": "Archivio SMB",
                "protocol": "smb",
                "server": "blocked-update.example",
                "remote_resource": "archive-update",
                "dialect": "3.0",
                "lifecycle": "disabled",
            },
        )

        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertIn(
            'name="display_name" required value="Archivio SMB"', rejected.text
        )
        self.assertIn(
            'name="server" required value="blocked-update.example"', rejected.text
        )
        self.assertIn(
            'name="remote_resource" required value="archive-update"', rejected.text
        )
        self.assertIn('<option value="3.0" selected>3.0</option>', rejected.text)
        self.assertNotIn('name="auto_connect"', rejected.text)
        self.assertIn(
            '<option value="disabled" selected>Disabled — disconnected</option>',
            rejected.text,
        )
        self.assert_field_error_association(
            rejected,
            field="server",
            action="/shares/smb-media/update",
            control_name="server",
        )

    def test_share_update_pydantic_error_preserves_disabled_lifecycle(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")

        rejected = self.client.post(
            "/shares/smb-media/update",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "display_name": "Archivio SMB",
                "protocol": "smb",
                "server": "nas.example.example",
                "remote_resource": "archive",
                "dialect": "1.0",
                "lifecycle": "disabled",
            },
        )

        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertNotIn('name="auto_connect"', rejected.text)
        self.assertIn(
            '<option value="disabled" selected>Disabled — disconnected</option>',
            rejected.text,
        )
        self.assert_field_error_association(
            rejected,
            field="dialect",
            action="/shares/smb-media/update",
            control_name="dialect",
        )

    def test_share_credential_validation_targets_control_without_replaying_secrets(
        self,
    ):
        secret = "never-replay-this-password"
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")

        rejected = self.client.post(
            "/shares/smb-media/credential",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "username": "",
                "domain": "ARCHIVE",
                "password": secret,
            },
        )

        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertNotIn(secret, rejected.text)
        self.assertNotIn('value="ARCHIVE"', rejected.text)
        self.assert_field_error_association(
            rejected,
            field="username",
            action="/shares/smb-media/credential",
            control_name="username",
        )

    def test_share_operations_require_exact_confirmation_and_do_not_resubmit(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        csrf = self.hidden(detail, "csrf")
        disconnected = self.client.post(
            "/shares/smb-media/disconnect",
            data={
                "csrf": csrf,
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "typed_share_id": "wrong-share",
            },
        )
        self.assertEqual(422, disconnected.status_code)
        self.assertNotIn(
            'action="/shares/smb-media/disconnect"', disconnected.text
        )
        self.assertFalse(
            any(name == "disconnect_network_share" for name, _ in self.daemon.calls)
        )

        accepted = self.client.post(
            "/shares/smb-media/disconnect",
            data={
                "csrf": csrf,
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
                "typed_share_id": "smb-media",
            },
        )
        self.assertEqual(303, accepted.status_code, accepted.text)
        self.assertEqual("/shares/smb-media", accepted.headers["location"])
        self.assertEqual(
            1, sum(name == "disconnect_network_share" for name, _ in self.daemon.calls)
        )

        reloaded = self.client.get(accepted.headers["location"])
        self.assertEqual(200, reloaded.status_code)
        self.assertEqual(
            1, sum(name == "disconnect_network_share" for name, _ in self.daemon.calls)
        )

    def test_library_forms_build_tagged_managed_share_source(self):
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/libraries")
        self.assertIn('value="managed_share"', page.text)
        self.assertIn('value="smb-media"', page.text)
        self.assertNotIn('value="nfs-media"', page.text)

        response = self.client.post(
            "/libraries",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "library_id": "NETWORK",
                "display_name": "Rete",
                "source_kind": "managed_share",
                "share_id": "smb-media",
                "relative_subpath": "films/2026",
                "source_root": "",
            },
        )
        self.assertEqual(303, response.status_code, response.text)
        _name, (request, _key) = self.daemon.calls[-1]
        self.assertIsNone(request.source_root)
        self.assertEqual("managed_share", request.source.kind)
        self.assertEqual("smb-media", request.source.share_id)
        self.assertEqual("films/2026", request.source.relative_subpath)

    def test_library_form_creates_a_library_for_an_entire_managed_share(self):
        # Making relative_subpath mandatory contradicts the form's optional
        # whole-share workflow and rejects the request before it reaches the daemon.
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/libraries")

        response = self.client.post(
            "/libraries",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "library_id": "WHOLE-SHARE",
                "display_name": "Intera condivisione",
                "source_kind": "managed_share",
                "share_id": "smb-media",
                "relative_subpath": "",
            },
        )

        self.assertEqual(303, response.status_code, response.text)
        name, (request, _key) = self.daemon.calls[-1]
        self.assertEqual("create_library", name)
        self.assertEqual("smb-media", request.source.share_id)
        self.assertEqual("", request.source.relative_subpath)

    def test_library_validation_error_preserves_connected_share_selection(self):
        # Dropping share_options from the 422 response leaves the administrator
        # unable to correct and resubmit a managed-share library form.
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/libraries")

        response = self.client.post(
            "/libraries",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "library_id": "",
                "display_name": "Intera condivisione",
                "source_kind": "managed_share",
                "share_id": "smb-media",
                "relative_subpath": "",
            },
        )

        self.assertEqual(422, response.status_code, response.text)
        self.assertIn('data-field-error="library_id"', response.text)
        self.assertIn('value="smb-media" selected', response.text)

    def test_share_status_fragment_is_redacted_and_all_admin_actions_are_typed(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        csrf = self.hidden(detail, "csrf")
        for action, expected_call, confirmed in (
            ("test", "test_network_share", False),
            ("connect", "connect_network_share", False),
            ("reconcile", "reconcile_network_share", False),
            ("credential/clear", "clear_network_share_credential", True),
            ("retire", "retire_network_share", True),
            ("delete", "remove_network_share", True),
        ):
            with self.subTest(action=action):
                data = {
                    "csrf": csrf,
                    "idempotency_key": str(uuid4()),
                    "expected_revision": "4",
                }
                if confirmed:
                    data["typed_share_id"] = "smb-media"
                response = self.client.post(f"/shares/smb-media/{action}", data=data)
                self.assertEqual(303, response.status_code, response.text)
                self.assertEqual(expected_call, self.daemon.calls[-1][0])

        self.client.post("/logout", data={"csrf": csrf})
        self.login("operator", "operator password material")
        fragment = self.client.get("/shares/smb-media/status-fragment")
        self.assertEqual(200, fragment.status_code, fragment.text)
        self.assertIn('aria-live="polite"', fragment.text)
        self.assertNotIn("secret-nas.example", fragment.text)
        denied = self.client.post(
            "/shares/smb-media/connect",
            data={
                "csrf": self.hidden(self.client.get("/shares/smb-media"), "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
            },
        )
        self.assertEqual(403, denied.status_code)

    def test_share_update_is_sparse_and_does_not_reapply_connected_config(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        updated = self.client.post(
            "/shares/smb-media/update",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "display_name": "SMB media rinominata",
                "protocol": "smb",
                "server": "secret-nas.example",
                "remote_resource": "private-media",
                "dialect": "3.1.1",
                "lifecycle": "active",
            },
        )
        self.assertEqual(303, updated.status_code, updated.text)
        _name, (_share_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual("SMB media rinominata", request.display_name)
        self.assertIsNone(request.config)
        self.assertIsNone(request.auto_connect)
        self.assertIsNone(request.lifecycle)

    def test_share_and_library_details_show_only_redacted_dependency_metadata(self):
        self.daemon.libraries = (
            LibrarySummaryV1.model_validate(
                {
                    **self.daemon.libraries[0].model_dump(),
                    "source_root": None,
                    "source": {
                        "kind": "managed_share",
                        "share_id": "smb-media",
                        "relative_subpath": "films",
                    },
                }
            ),
            self.daemon.libraries[1],
        )
        self.login("admin", "correct horse battery staple")
        share = self.client.get("/shares/smb-media")
        library = self.client.get("/libraries/PHOTOS")

        self.assertIn("Foto &lt;famiglia&gt; (PHOTOS)", share.text)
        self.assertIn("SMB media — SMB — connected", library.text)
        self.assertIn("films", library.text)
        self.assertNotIn("secret-nas.example", library.text)
        self.assertNotIn("private-media", library.text)

    def test_share_mutations_reject_unsafe_path_ids_before_daemon_calls(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        baseline = len(self.daemon.calls)
        response = self.client.post(
            "/shares/BAD_ID/connect",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
            },
        )
        self.assertEqual(422, response.status_code, response.text)
        self.assertEqual(baseline, len(self.daemon.calls))

    def test_share_forms_reject_missing_csrf_and_duplicate_scalar_fields(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        baseline = len(self.daemon.calls)
        missing_csrf = self.client.post(
            "/shares/smb-media/connect",
            data={
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
            },
        )
        self.assertEqual(403, missing_csrf.status_code, missing_csrf.text)

        duplicate = self.client.post(
            "/shares/smb-media/connect",
            content=(
                f"csrf={self.hidden(detail, 'csrf')}&"
                f"idempotency_key={uuid4()}&"
                "expected_revision=4&expected_revision=5"
            ),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(422, duplicate.status_code, duplicate.text)
        self.assertEqual(baseline, len(self.daemon.calls))

    def test_share_transport_failure_reuses_key_and_never_repopulates_password(self):
        password = "transport-secret-never-render"
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        key = str(uuid4())
        self.daemon.mutation_failure = DaemonUnavailable()
        self.daemon.failure = DaemonUnavailable()
        failed = self.client.post(
            "/shares/smb-media/credential",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": key,
                "expected_revision": "4",
                "username": "retry-user",
                "domain": "RETRY",
                "password": password,
            },
        )
        self.assertEqual(503, failed.status_code, failed.text)
        self.assertIn('action="/shares/smb-media/credential"', failed.text)
        self.assertIn(f'value="{key}"', failed.text)
        self.assertIn('name="expected_revision" value="4"', failed.text)
        self.assertNotIn(password, failed.text)
        self.assertNotIn('value="retry-user"', failed.text)
        self.assertNotIn('value="RETRY"', failed.text)
        self.assertNotRegex(failed.text, r'name="password"[^>]+value=')

        operation_key = str(uuid4())
        operation = self.client.post(
            "/shares/smb-media/connect",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": operation_key,
                "expected_revision": "4",
            },
        )
        self.assertEqual(503, operation.status_code, operation.text)
        self.assertIn("Ambiguous outcome", operation.text)
        self.assertIn("refresh its status", operation.text)
        self.assertNotIn('action="/shares/smb-media/connect"', operation.text)
        self.assertNotIn(f'value="{operation_key}"', operation.text)
        self.assertNotIn('name="expected_revision" value="4"', operation.text)

    def test_ambiguous_share_update_and_confirmed_action_retry_exact_safe_payload(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/shares/smb-media")
        csrf = self.hidden(detail, "csrf")

        def fail_update_after_acceptance(*_args, **_kwargs):
            self.daemon.failure = DaemonUnavailable()
            raise DaemonUnavailable()

        self.daemon.update_network_share = fail_update_after_acceptance
        update_key = str(uuid4())
        update_payload = {
            "csrf": csrf,
            "idempotency_key": update_key,
            "expected_revision": "4",
            "display_name": "Archivio SMB",
            "protocol": "smb",
            "server": "nas-retry.example",
            "remote_resource": "archive-retry",
            "dialect": "3.0",
            "lifecycle": "disabled",
        }

        update = self.client.post("/shares/smb-media/update", data=update_payload)

        self.assertEqual(503, update.status_code, update.text)
        self.assertIn('action="/shares/smb-media/update"', update.text)
        for name, value in update_payload.items():
            if name == "csrf":
                continue
            self.assertIn(f'name="{name}" value="{value}"', update.text)

        self.daemon.failure = None

        def fail_disconnect_after_acceptance(*_args, **_kwargs):
            self.daemon.failure = DaemonUnavailable()
            raise DaemonUnavailable()

        self.daemon.disconnect_network_share = fail_disconnect_after_acceptance
        disconnect_key = str(uuid4())
        disconnected = self.client.post(
            "/shares/smb-media/disconnect",
            data={
                "csrf": csrf,
                "idempotency_key": disconnect_key,
                "expected_revision": "4",
                "typed_share_id": "smb-media",
            },
        )

        self.assertEqual(503, disconnected.status_code, disconnected.text)
        self.assertIn("Ambiguous outcome", disconnected.text)
        self.assertIn("refresh its status", disconnected.text)
        self.assertNotIn(
            'action="/shares/smb-media/disconnect"', disconnected.text
        )
        self.assertNotIn(
            f'name="idempotency_key" value="{disconnect_key}"', disconnected.text
        )
        self.assertNotIn('name="expected_revision" value="4"', disconnected.text)
        self.assertNotIn('name="typed_share_id" value="smb-media"', disconnected.text)

    def test_library_update_is_sparse_revision_guarded_and_state_aware(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/libraries/PHOTOS")

        renamed = self.client.post(
            "/libraries/PHOTOS/update",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "3",
                "display_name": "Foto nuove",
                "source_root": "/srv/source/PHOTOS",
                "state": "active",
            },
        )

        self.assertEqual(303, renamed.status_code, renamed.text)
        _name, (_library_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual(3, request.expected_revision)
        self.assertEqual("Foto nuove", request.display_name)
        self.assertIsNone(request.source_root)
        self.assertIsNone(request.state)

    def test_extension_plan_renders_immutable_append_and_reserve_rows(self):
        self.login("operator", "operator password material")
        self.daemon.plan = _plan(kind="extend").model_copy(
            update={
                "cassettes": (
                    self.daemon.plan.cassettes[0].model_copy(
                        update={
                            "sequence": 1,
                            "operation": "append",
                            "format_required": False,
                            "physical_label": "OLD001",
                        }
                    ),
                    self.daemon.plan.cassettes[0].model_copy(
                        update={
                            "sequence": 2,
                            "operation": "reserve",
                            "physical_label": "RES001",
                        }
                    ),
                    self.daemon.plan.cassettes[0].model_copy(
                        update={"sequence": 3, "operation": "format"}
                    ),
                )
            }
        )

        page = self.client.get("/jobs/plans/PLAN-1")

        self.assertEqual(200, page.status_code)
        self.assertIn("OLD001", page.text)
        self.assertIn("RES001", page.text)
        self.assertEqual(1, page.text.count('name="labels"'))

    def test_job_new_profile_option_shows_native_and_ltfs_usable_capacity(self):
        self.establish_session(self.operator)

        page = self.client.get("/jobs/new")

        self.assertEqual(200, page.status_code, page.text)
        option = re.search(
            r'<option value="LTO-10 PA"[^>]*>([^<]*)</option>', page.text
        )
        self.assertIsNotNone(option, page.text)
        option_text = unescape(option.group(1))
        self.assertIn("Native capacity: 40,000,000,000,000 B", option_text)
        self.assertIn("Usable LTFS: 37,030,000,000,000 B", option_text)

    def test_job_new_renders_all_seven_literal_media_profile_choices(self):
        self.establish_session(self.operator)
        literal_profiles = (
            (
                "LTO-5",
                5,
                1_500_000_000_000,
                1_430_000_000_000,
                "1,500,000,000,000",
                "1,430,000,000,000",
            ),
            (
                "LTO-6",
                6,
                2_500_000_000_000,
                2_410_000_000_000,
                "2,500,000,000,000",
                "2,410,000,000,000",
            ),
            (
                "LTO-7",
                7,
                6_000_000_000_000,
                5_730_000_000_000,
                "6,000,000,000,000",
                "5,730,000,000,000",
            ),
            (
                "LTO-8",
                8,
                12_000_000_000_000,
                11_710_000_000_000,
                "12,000,000,000,000",
                "11,710,000,000,000",
            ),
            (
                "LTO-9",
                9,
                18_000_000_000_000,
                17_550_000_000_000,
                "18,000,000,000,000",
                "17,550,000,000,000",
            ),
            (
                "LTO-10 LA",
                10,
                30_000_000_000_000,
                27_830_000_000_000,
                "30,000,000,000,000",
                "27,830,000,000,000",
            ),
            (
                "LTO-10 PA",
                10,
                40_000_000_000_000,
                37_030_000_000_000,
                "40,000,000,000,000",
                "37,030,000,000,000",
            ),
        )
        self.daemon.get_media_profiles = lambda **_kwargs: MediaProfilesV1.model_validate(
            {
                "default_media_profile": "LTO-10 LA",
                "items": tuple(
                    {
                        "key": key,
                        "generation": generation,
                        "native_capacity_bytes": native,
                        "ltfs_usable_bytes": usable,
                    }
                    for key, generation, native, usable, _native_copy, _usable_copy
                    in literal_profiles
                ),
            }
        )

        page = self.client.get("/jobs/new")

        self.assertEqual(200, page.status_code, page.text)
        self.assertEqual(7, page.text.count('<option value="LTO-'))
        for (
            key,
            _generation,
            _native,
            _usable,
            native_copy,
            usable_copy,
        ) in literal_profiles:
            with self.subTest(key=key):
                option = re.search(
                    rf'<option value="{re.escape(key)}"[^>]*>([^<]*)</option>',
                    page.text,
                )
                self.assertIsNotNone(option, page.text)
                option_text = unescape(option.group(1))
                self.assertIn(f"Native capacity: {native_copy} B", option_text)
                self.assertIn(f"Usable LTFS: {usable_copy} B", option_text)

    def test_job_plan_shows_total_and_per_cassette_capacity_accounting(self):
        self.establish_session(self.operator)
        first = self.daemon.plan.cassettes[0]
        self.daemon.plan = self.daemon.plan.model_copy(
            update={
                "cassettes": (
                    first,
                    first.model_copy(
                        update={
                            "sequence": 2,
                            "bytes": 11,
                            "objects": 3,
                            "allocation_bytes": 16384,
                            "capacity_utilization": 0.2,
                        }
                    ),
                )
            }
        )

        page = self.client.get("/jobs/plans/PLAN-1")

        self.assertEqual(200, page.status_code, page.text)
        for expected in (
            "Total payload: 18 B",
            "Total allocation: 24,576 B",
            "Capacity reserve: 1,024 B",
            "Effective capacity per cassette: 37,029,999,998,976 B",
            "24,558 B",
            "74,059,999,997,952 B",
            "74,059,999,973,376 B",
            "Cassette 1 — payload: 7 B — allocation: 8,192 B — utilization: 10.0%",
            "8,185 B",
            "37,029,999,990,784 B",
            "Cassette 2 — payload: 11 B — allocation: 16,384 B — utilization: 20.0%",
            "16,373 B",
            "37,029,999,982,592 B",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, page.text)

    def test_operator_plan_uses_frozen_capacity_without_admin_settings(self):
        self.establish_session(self.operator)
        self.daemon.get_application_settings = lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("operator plan must not read administrator settings")
        )

        page = self.client.get("/jobs/plans/PLAN-1")

        self.assertEqual(200, page.status_code, page.text)
        self.assertIn("Capacity reserve: 1,024 B", page.text)

    def test_extension_append_uses_frozen_residual_capacity(self):
        self.establish_session(self.operator)
        append = self.daemon.plan.cassettes[0].model_copy(
            update={
                "physical_label": "AB1234",
                "operation": "append",
                "format_required": False,
            }
        )
        self.daemon.plan = _plan(kind="extend").model_copy(
            update={
                "cassettes": (append,),
                "residual_append_capacity_bytes": 10_000,
            }
        )

        page = self.client.get("/jobs/plans/PLAN-1")

        self.assertEqual(200, page.status_code, page.text)
        self.assertIn("Capacity used: 10,000 B", page.text)
        self.assertIn("Remaining space: 1,808 B", page.text)
        self.assertIn("Total effective capacity</dt><dd>10,000 B", page.text)

    def test_job_settings_and_detail_format_display_quantities_only(self):
        self.establish_session(self.admin)
        payload = self.daemon.job.model_dump()
        payload.update(
            {
                "revision": 1234,
                "cassette_progress": {"completed": 1234, "total": 5678},
                "progress": {
                    "objects_completed": 1234,
                    "objects_total": 5678,
                    "bytes_completed": 1_234_567,
                    "bytes_total": 9_876_543,
                },
                "cassettes": (
                    {
                        **payload["cassettes"][0],
                        "objects": 1234,
                        "bytes": 1_234_567,
                    },
                ),
            }
        )
        self.daemon.job = JobDetailV1.model_validate(payload)
        self.daemon.cassettes = self.daemon.job.cassettes
        self.daemon.get_job_manifest = lambda _job_id, **_kwargs: (
            JobManifestPageV1.model_validate(
                {
                    "items": (
                        {
                            "cassette_sequence": 1,
                            "item_sequence": 1,
                            "library_id": "PHOTOS",
                            "relative_path": "album/foto.jpg",
                            "size": 1_234_567,
                            "mtime_ns": 1,
                        },
                    ),
                    "next_cursor": None,
                }
            )
        )

        jobs = self.client.get("/jobs")
        detail = self.client.get("/jobs/JOB-1")
        settings = self.client.get("/settings")

        self.assertIn("1,234 / 5,678 cassettes", jobs.text)
        self.assertIn("1,234,567 / 9,876,543 bytes", jobs.text)
        self.assertRegex(
            detail.text,
            r"Cassettes</dt><dd>1,234 / 5,678</dd>",
        )
        self.assertRegex(
            detail.text,
            r"Bytes</dt><dd>1,234,567 / 9,876,543</dd>",
        )
        self.assertIn("1,234 objects / 1,234,567 bytes", detail.text)
        self.assertIn("<td>1,234,567 B</td>", detail.text)
        self.assertIn("Usable LTFS: 37,030,000,000,000 B", settings.text)
        self.assertIn('name="expected_revision" value="1234"', detail.text)
        self.assertNotIn('name="expected_revision" value="1,234"', detail.text)
        self.assertIn('name="capacity_reserve_bytes" value="1024"', settings.text)

    def test_non_ready_plan_is_safe_remediation_step_without_save(self):
        self.login("operator", "operator password material")
        for state in ("building", "failed", "expired", "consumed"):
            with self.subTest(state=state):
                self.daemon.plan = _plan().model_copy(update={"state": state})
                page = self.client.get("/jobs/plans/PLAN-1")
                self.assertEqual(200, page.status_code)
                self.assertNotIn('action="/jobs/plans/PLAN-1/jobs"', page.text)
                self.assertIn("New estimate", page.text)

    def test_job_save_parses_ordered_multiline_labels_and_does_not_start(self):
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/jobs/plans/PLAN-1")

        self.assertEqual(1, page.text.count('name="labels"'))
        self.assertIn("<textarea", page.text)
        saved = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Archive",
                "labels": "AB1234\r\n\r\nAB1235\n AB1236 ",
                "authorize_automatic_formatting": "on",
            },
        )

        self.assertEqual(303, saved.status_code)
        request = self.daemon.calls[-1][1][1]
        self.assertEqual(("AB1234", "AB1235", "AB1236"), request.labels)
        self.assertFalse(
            any(name in {"start_job", "resume_job"} for name, _args in self.daemon.calls)
        )

    def test_plan_requires_explicit_automatic_format_authority(self) -> None:
        # Removing the consent checkbox or accepting a non-literal value would
        # let a save silently become destructive authority.
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/jobs/plans/PLAN-1")

        self.assertIn('name="authorize_automatic_formatting"', page.text)
        saved = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Archive",
                "labels": "AB1234",
                "authorize_automatic_formatting": "on",
            },
        )

        self.assertEqual(303, saved.status_code, saved.text)
        request = self.daemon.calls[-1][1][1]
        self.assertIs(True, request.authorize_automatic_formatting)

    def test_legacy_native_job_requires_one_time_sequence_authorization(self) -> None:
        # Restoring a typed label box here would make a legacy job look like it
        # gained destructive authority before an administrator grants it.
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/jobs/JOB-1")

        self.assertIn("Authorize automatic cassette sequence", detail.text)
        self.assertIn('action="/jobs/JOB-1/automatic-sequence/authorize"', detail.text)
        self.assertNotIn("Confirm physical label to format", detail.text)
        self.assertNotIn('action="/jobs/JOB-1/start"', detail.text)

    def test_authorized_native_start_sends_no_legacy_label(self) -> None:
        self.login("admin", "correct horse battery staple")
        pending = self.client.get("/jobs/JOB-1")
        authorized = self.client.post(
            "/jobs/JOB-1/automatic-sequence/authorize",
            data=self.successful_form_fields(
                pending, "/jobs/JOB-1/automatic-sequence/authorize"
            ),
        )

        self.assertEqual(303, authorized.status_code, authorized.text)
        granted = self.daemon.calls[-1][1][1]
        self.assertEqual(4, granted.expected_revision)
        self.assertEqual("b" * 64, granted.layout_fingerprint_sha256)
        detail = self.client.get("/jobs/JOB-1")
        self.assertNotIn('name="format_confirmation_label"', detail.text)
        started = self.client.post(
            "/jobs/JOB-1/start",
            data=self.successful_form_fields(detail, "/jobs/JOB-1/start"),
        )
        self.assertEqual(303, started.status_code, started.text)
        self.assertIsNone(self.daemon.calls[-1][1][1].format_confirmation_label)

    def test_mixed_version_sequence_status_fails_closed_without_blank_authorization(self) -> None:
        self.login("admin", "correct horse battery staple")

        def unavailable(*_args, **_kwargs):
            raise DaemonRequestError(404, "not_found")

        self.daemon.get_job_sequence_status = unavailable  # type: ignore[method-assign]
        detail = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn("Cassette-sequence status is unavailable", detail.text)
        self.assertNotIn('automatic-sequence/authorize" method="post"', detail.text)
        self.assertNotIn('action="/jobs/JOB-1/start"', detail.text)
        self.assertNotIn('action="/jobs/JOB-1/resume"', detail.text)

    def test_plan_rejects_nonliteral_format_consent_and_preserves_checked_state(self) -> None:
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/jobs/plans/PLAN-1")
        rejected = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Archive",
                "labels": "AB1234",
                "authorize_automatic_formatting": "true",
            },
        )

        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertIn('data-field-error="authorize_automatic_formatting"', rejected.text)
        self.assertEqual([], self.daemon.calls)

    def test_registered_reuse_checkbox_is_admin_only_forwarded_and_preserved_on_conflict(
        self,
    ) -> None:
        self.login("operator", "operator password material")
        operator_page = self.client.get("/jobs/plans/PLAN-1")
        self.assertNotIn('name="allow_registered_reuse"', operator_page.text)
        self.client.post(
            "/logout", data={"csrf": self.hidden(operator_page, "csrf")}
        )

        self.login("admin", "correct horse battery staple")
        admin_page = self.client.get("/jobs/plans/PLAN-1")
        self.assertIn('name="allow_registered_reuse"', admin_page.text)
        self.assertIn(
            "Authorize every planned format operation during this job, including registered-media reuse",
            admin_page.text,
        )
        self.assertNotRegex(
            admin_page.text,
            r'name="allow_registered_reuse"[^>]*checked',
        )
        self.assertIn('class="warning-panel" role="note"', admin_page.text)
        self.assertIn(
            "Only after format succeeds, the previous backup becomes unreadable and its catalogue entry is invalidated.",
            admin_page.text,
        )
        self.assertIn("that order is authoritative for this job", admin_page.text)
        self.daemon.mutation_failure = DaemonRequestError(
            409, "plan_label_registered"
        )
        refused = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(admin_page, "csrf"),
                "idempotency_key": self.hidden(admin_page, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Archive",
                "labels": "AB1234",
                "allow_registered_reuse": "on",
                "authorize_automatic_formatting": "on",
            },
        )

        self.assertEqual(409, refused.status_code, refused.text)
        self.assertRegex(
            refused.text,
            r'name="allow_registered_reuse"[^>]*checked',
        )
        self.assertIn(
            "This label is already catalogued. Select registered-label reuse to continue.",
            refused.text,
        )

        self.daemon.mutation_failure = None
        accepted = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(refused, "csrf"),
                "idempotency_key": self.hidden(refused, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Archive",
                "labels": "AB1234",
                "allow_registered_reuse": "on",
                "authorize_automatic_formatting": "on",
            },
        )
        self.assertEqual(303, accepted.status_code, accepted.text)
        request = self.daemon.calls[-1][1][1]
        self.assertTrue(request.allow_registered_reuse)

    def test_job_plan_conflicts_attach_to_current_plan_state(self) -> None:
        self.login("admin", "correct horse battery staple")
        for code in (
            "plan_library_conflict",
            "managed_source_evidence_changed",
            "share_identity_changed",
            "plan_consumption_conflict",
        ):
            with self.subTest(code=code):
                page = self.client.get("/jobs/plans/PLAN-1")
                self.daemon.mutation_failure = DaemonRequestError(409, code)
                response = self.client.post(
                    "/jobs/plans/PLAN-1/jobs",
                    data={
                        "csrf": self.hidden(page, "csrf"),
                        "idempotency_key": self.hidden(page, "idempotency_key"),
                        "digest_sha256": "a" * 64,
                        "display_name": "Archive",
                        "labels": "AB1234",
                        "authorize_automatic_formatting": "on",
                    },
                )
                self.assertEqual(409, response.status_code, response.text)
                self.assertIn('data-field-error="state"', response.text)
        self.daemon.mutation_failure = None

    def test_ambiguous_registered_label_error_is_actionable(self) -> None:
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/jobs/plans/PLAN-1")
        self.daemon.mutation_failure = DaemonRequestError(
            409, "plan_label_identity_ambiguous"
        )

        response = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Archive",
                "labels": "AB1234",
                "allow_registered_reuse": "on",
                "authorize_automatic_formatting": "on",
            },
        )

        self.assertEqual(409, response.status_code, response.text)
        self.assertIn('data-field-error="labels"', response.text)
        self.assertIn(
            "This physical label matches multiple catalogued tapes. Resolve duplicate catalogue identities before saving.",
            response.text,
        )

    def test_jobs_hide_retired_by_default_and_offer_manage_links_and_toggle(self):
        self.login("admin", "correct horse battery staple")

        current = self.client.get("/jobs")
        with_retired = self.client.get("/jobs?show_retired=1")

        self.assertEqual(200, current.status_code, current.text)
        self.assertIn("Backup foto", current.text)
        self.assertNotIn("Retired archive", current.text)
        self.assertIn("Manage", current.text)
        self.assertIn('href="/jobs/JOB-1"', current.text)
        self.assertIn('href="/jobs?show_retired=1"', current.text)
        self.assertEqual(200, with_retired.status_code, with_retired.text)
        self.assertIn("Retired archive", with_retired.text)
        self.assertIn('href="/jobs"', with_retired.text)
        self.assertEqual(
            [False, True],
            [
                call[1]["include_retired"]
                for call in self.daemon.calls
                if call[0] == "list_jobs"
            ][-2:],
        )

    def test_admin_delete_explains_exclusive_catalog_removal_and_safe_exclusions(self):
        self.login("admin", "correct horse battery staple")
        eligible = self.client.get("/jobs/JOB-1")
        self.assertIn(">Delete job</button>", eligible.text)
        self.assertIn("Only tapes owned exclusively by this job", eligible.text)
        self.assertIn("Physical tape data is not erased", eligible.text)
        self.assertIn('action="/jobs/JOB-1/retire"', eligible.text)

        for state, imported, reason in (
            ("writing", False, "Pause or finish the active operation before deleting this job."),
            ("planned", True, "Imported jobs keep their frozen history and cannot be deleted."),
            ("retired", False, "This job is already deleted from the active list."),
        ):
            with self.subTest(state=state, imported=imported):
                capabilities = self.daemon.job.capabilities.model_copy(
                    update={"retire": False}
                )
                self.daemon.job = self.daemon.job.model_copy(
                    update={
                        "state": state,
                        "imported": imported,
                        "capabilities": capabilities,
                    }
                )
                page = self.client.get("/jobs/JOB-1")
                self.assertIn(reason, page.text)
                self.assertNotIn('action="/jobs/JOB-1/retire"', page.text)

    def test_logical_delete_redirects_and_job_disappears_from_default_list(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/jobs/JOB-1")
        response = self.client.post(
            "/jobs/JOB-1/retire",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "4",
                "typed_job_id": "JOB-1",
            },
        )
        result = self.client.get(response.headers["location"])
        listing = self.client.get("/jobs")

        self.assertEqual(303, response.status_code, response.text)
        self.assertEqual("/jobs/JOB-1", response.headers["location"])
        self.assertIn("This job is already deleted from the active list", result.text)
        self.assertNotIn("Backup foto", listing.text)

    def test_deleted_job_reports_removed_and_preserved_tape_catalogs(self):
        payload = self.daemon.job.model_dump()
        payload["state"] = "retired"
        payload["catalog_cleanup"] = {
            "deleted_tape_count": 1, "preserved_tape_count": 1,
            "deleted_tapes": ["AB1234"],
            "preserved_tapes": [{"tape_id": "AB1235", "reason": "shared_tape"}],
            "deleted_blocks": 2, "deleted_files": 10, "tape_data_deleted": False,
        }
        self.daemon.job = JobDetailV1.model_validate(payload)
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/jobs/JOB-1")
        self.assertEqual(200, page.status_code, page.text)
        self.assertIn("Catalog cleanup result", page.text)
        self.assertIn("AB1234", page.text)
        self.assertIn("AB1235", page.text)
        self.assertIn("shared tape", page.text)
        self.assertIn("10 file records", page.text)

    def test_job_save_preserves_multiline_labels_after_validation_failures(self):
        self.login("admin", "correct horse battery staple")
        cases = (
            ("AB1234\n<bad>", None),
            ("AB1234\nAB1234", None),
            ("AB1234", DaemonRequestError(422, "plan_labels_inexact")),
            ("AB1234\nAB1235", DaemonRequestError(422, "plan_stale")),
            ("AB1234\nAB1235", DaemonRequestError(422, "plan_label_unavailable")),
        )
        for labels, failure in cases:
            with self.subTest(failure=None if failure is None else failure.error_code):
                page = self.client.get("/jobs/plans/PLAN-1")
                self.daemon.mutation_failure = failure
                response = self.client.post(
                    "/jobs/plans/PLAN-1/jobs",
                    data={
                        "csrf": self.hidden(page, "csrf"),
                        "idempotency_key": self.hidden(page, "idempotency_key"),
                        "digest_sha256": "a" * 64,
                        "display_name": "Archive",
                        "labels": labels,
                        "authorize_automatic_formatting": "on",
                    },
                )

                self.assertEqual(422, response.status_code, response.text)
                self.assertIn("&lt;bad&gt;" if "<bad>" in labels else labels, response.text)
                self.assertIn(labels, unescape(response.text))
        self.daemon.mutation_failure = None

    def test_three_step_wizard_forwards_exact_digest_and_saves_without_starting(self):
        self.login("admin", "correct horse battery staple")
        new = self.client.get("/jobs/new")
        self.assertEqual(200, new.status_code, new.text)
        planned = self.client.post(
            "/jobs/plans",
            data={
                "csrf": self.hidden(new, "csrf"),
                "idempotency_key": self.hidden(new, "idempotency_key"),
                "library_ids": ["PHOTOS", "VIDEOS"],
                "media_profile": "LTO-10 PA",
            },
        )
        self.assertEqual(303, planned.status_code, planned.text)
        self.assertEqual("/jobs/plans/PLAN-1", planned.headers["location"])

        plan_page = self.client.get("/jobs/plans/PLAN-1")
        self.assertIn("a" * 64, plan_page.text)
        saved = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(plan_page, "csrf"),
                "idempotency_key": self.hidden(plan_page, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Backup completo",
                "labels": ["AB1234"],
                "authorize_automatic_formatting": "on",
            },
        )
        self.assertEqual(303, saved.status_code, saved.text)
        self.assertEqual("/jobs/JOB-1", saved.headers["location"])
        name, (plan_id, request, _key) = self.daemon.calls[-1]
        self.assertEqual("create_job_from_plan", name)
        self.assertEqual("PLAN-1", plan_id)
        self.assertEqual("a" * 64, request.digest_sha256)
        self.assertEqual(("AB1234",), request.labels)
        self.assertFalse(
            any(call[0] in {"start_job", "resume_job"} for call in self.daemon.calls)
        )

    def test_wizard_errors_rebuild_choices_and_preserve_only_non_secret_inputs(self):
        self.login("admin", "correct horse battery staple")
        new = self.client.get("/jobs/new")
        invalid_selection = self.client.post(
            "/jobs/plans",
            data={
                "csrf": self.hidden(new, "csrf"),
                "idempotency_key": self.hidden(new, "idempotency_key"),
                "media_profile": "LTO-10 PA",
            },
        )

        self.assertEqual(422, invalid_selection.status_code)
        self.assertIn("Foto &lt;famiglia&gt;", invalid_selection.text)
        self.assertIn("Video", invalid_selection.text)
        self.assertIn("LTO-10 PA", invalid_selection.text)
        self.assertIn('data-field-error="library_ids"', invalid_selection.text)

        plan = self.client.get("/jobs/plans/PLAN-1")
        invalid_labels = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(plan, "csrf"),
                "idempotency_key": self.hidden(plan, "idempotency_key"),
                "digest_sha256": "a" * 64,
                "display_name": "Backup da conservare",
                "authorize_automatic_formatting": "on",
            },
        )

        self.assertEqual(422, invalid_labels.status_code)
        self.assertIn("Backup da conservare", invalid_labels.text)
        self.assertIn("a" * 64, invalid_labels.text)
        self.assertIn('data-field-error="labels"', invalid_labels.text)
        self.assertNotIn("daemon request failed", invalid_labels.text)

    def test_job_detail_settings_and_safe_conflicts_remain_typed_html(self):
        self.login("admin", "correct horse battery staple")
        jobs = self.client.get("/jobs")
        detail = self.client.get("/jobs/JOB-1")
        settings = self.client.get("/settings")
        self.assertEqual(200, jobs.status_code)
        self.assertEqual(200, detail.status_code)
        self.assertEqual(200, settings.status_code)
        self.assertIn("Backup foto", jobs.text)
        self.assertIn("LTO-10 PA", detail.text)
        self.assertIn("Daemon socket path", settings.text)
        self.assertNotIn('name="legacy_tape_capacity_bytes"', settings.text)
        self.assertIn("/mnt/lto-archiver/sources", settings.text)
        self.assertIn("/srv/source", settings.text)
        self.assertIn("/srv/restore", settings.text)

        self.daemon.failure = DaemonRequestError(409, "settings_revision_conflict")
        conflict = self.client.get("/settings")
        self.assertEqual(409, conflict.status_code)
        self.assertIn("conflict", conflict.text.casefold())
        self.assertNotIn("safe public message", conflict.text)

    def test_job_detail_exposes_closed_incremental_policy_and_multiline_reserves(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        cadence = re.search(
            r'<select[^>]*name="cadence"[^>]*>(.*?)</select>', detail.text, re.DOTALL
        )
        self.assertIsNotNone(cadence, detail.text)
        assert cadence is not None
        self.assertEqual(
            ["off", "every_6_hours", "every_12_hours", "daily", "weekly"],
            re.findall(r'<option value="([^"]+)"', cadence.group(1)),
        )
        self.assertIn('action="/jobs/JOB-1/incremental-scan"', detail.text)
        self.assertRegex(
            detail.text,
            r'<textarea[^>]+name="labels"[^>]*></textarea>',
        )
        self.assertNotRegex(detail.text, r'<input[^>]+name="cadence"')

    def test_job_detail_paginates_cassettes_without_a_sixty_four_row_limit(self):
        first = self.daemon.job.cassettes[0]
        self.daemon.cassettes = tuple(
            first.model_copy(
                update={
                    "sequence": sequence,
                    "physical_label": f"C{sequence:05d}",
                    "format_required": sequence == 1,
                    "operation": "format" if sequence == 1 else "append",
                }
            )
            for sequence in range(1, 71)
        )
        self.login("admin", "correct horse battery staple")

        first_page = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, first_page.status_code, first_page.text)
        self.assertIn("C00001", first_page.text)
        self.assertIn("C00064", first_page.text)
        self.assertNotIn("C00065", first_page.text)
        self.assertIn("cassette_cursor=64", first_page.text)
        self.assertEqual(
            {
                "job_id": "JOB-1",
                "limit": 64,
                "cursor": None,
            },
            self.daemon.cassette_calls[-1],
        )

        second_page = self.client.get("/jobs/JOB-1?cassette_cursor=64")

        self.assertEqual(200, second_page.status_code, second_page.text)
        self.assertNotIn("C00064", second_page.text)
        self.assertIn("C00065", second_page.text)
        self.assertIn("C00070", second_page.text)
        self.assertIn(
            'action="/jobs/JOB-1/automatic-sequence/authorize"', second_page.text
        )
        self.assertFalse(
            any(
                name in {"scan_job_now", "update_incremental_policy"}
                for name, _payload in self.daemon.calls
            )
        )

    def test_job_detail_uses_format_summary_without_iterating_detail_cassettes(self):
        class DetailCassettesMustNotBeIterated(tuple):
            def __iter__(self):
                raise AssertionError("job detail cassettes were iterated")

        self.daemon.job = self.daemon.job.model_copy(
            update={
                "cassettes": DetailCassettesMustNotBeIterated(
                    self.daemon.job.cassettes
                ),
                "requires_format_confirmation": True,
            }
        )
        self.login("admin", "correct horse battery staple")

        detail = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn(
            'action="/jobs/JOB-1/automatic-sequence/authorize"', detail.text
        )

    def test_job_detail_starts_append_without_lifetime_format_confirmation(self):
        first = self.daemon.job.cassettes[0]
        self.daemon.job = self.daemon.job.model_copy(
            update={
                "cassettes": (
                    first.model_copy(
                        update={"sequence": 1, "operation": "format"}
                    ),
                    first.model_copy(
                        update={
                            "sequence": 2,
                            "physical_label": "AB1235",
                            "objects": 0,
                            "bytes": 0,
                            "operation": "format",
                        }
                    ),
                    first.model_copy(
                        update={
                            "sequence": 3,
                            "objects": 1,
                            "bytes": 8,
                            "operation": "append",
                            "format_required": False,
                        }
                    ),
                ),
                "requires_format_confirmation": False,
            }
        )
        self.daemon.sequence_status = {
            **self.daemon.sequence_status,
            "authorization_state": "authorized",
            "next_expected_sequence": 3,
            "next_expected_label": "AB1234",
        }
        self.login("operator", "operator password material")

        detail = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn('action="/jobs/JOB-1/start"', detail.text)
        self.assertNotIn('name="format_confirmation_label"', detail.text)

    def test_admin_can_confirm_and_reset_one_failed_cassette_from_job_detail(self):
        failed = self.daemon.job.cassettes[0].model_copy(
            update={"state": "failed", "error": "uncertain format attempt"}
        )
        self.daemon.job = self.daemon.job.model_copy(
            update={
                "state": "failed",
                "cassettes": (failed,),
                "revision": 9,
                "resumable": False,
                "capabilities": self.daemon.job.capabilities.model_copy(
                    update={
                        "start": False,
                        "resume": False,
                        "reset_failed_cassette": True,
                    }
                ),
            }
        )
        self.daemon.cassettes = self.daemon.job.cassettes
        self.login("admin", "correct horse battery staple")

        detail = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn('action="/jobs/JOB-1/failed-cassette/reset"', detail.text)
        self.assertIn('name="expected_revision" value="9"', detail.text)
        self.assertIn('name="cassette_sequence" value="1"', detail.text)
        self.assertIn("uncertain format attempt", detail.text)
        response = self.client.post(
            "/jobs/JOB-1/failed-cassette/reset",
            data={
                "csrf": self.hidden(detail, "csrf"),
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "9",
                "cassette_sequence": "1",
                "typed_physical_label": "AB1234",
            },
            follow_redirects=False,
        )

        self.assertEqual(303, response.status_code, response.text)
        name, call = self.daemon.calls[-1]
        self.assertEqual("reset_failed_cassette", name)
        self.assertEqual("JOB-1", call[0])
        self.assertEqual(9, call[1].expected_revision)
        self.assertEqual(1, call[1].cassette_sequence)
        self.assertEqual("AB1234", call[1].typed_physical_label)

    def test_job_detail_renders_exact_pending_plan_identity_digest_and_deficit(self):
        digest = "a" * 64
        incremental = IncrementalPolicyV1.model_validate(
            {
                "job_id": "JOB-1",
                "cadence": "daily",
                "next_eligible_at": "2026-08-30T10:00:00+00:00",
                "last_attempt_at": "2026-08-29T10:00:00+00:00",
                "last_success_at": "2026-08-28T10:00:00+00:00",
                "last_outcome": "waiting_labels",
                "revision": 7,
                "pending_extension": {
                    "plan_id": "PLAN-WAIT-7",
                    "plan_digest_sha256": digest,
                    "discovered_files": 23,
                    "discovered_bytes": 4567,
                    "required_additional_labels": 1,
                },
            }
        )
        self.daemon.job = self.daemon.job.model_copy(
            update={"incremental": incremental}
        )
        self.login("admin", "correct horse battery staple")

        detail = self.client.get("/jobs/JOB-1")
        reloaded = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertEqual(200, reloaded.status_code, reloaded.text)
        self.assertIn("PLAN-WAIT-7", detail.text)
        self.assertIn(digest, detail.text)
        self.assertIn("23 files / 4,567 bytes", detail.text)
        self.assertIn("Additional labels required", detail.text)
        self.assertRegex(detail.text, r"Additional labels required</dt><dd>1</dd>")
        self.assertRegex(reloaded.text, r"Additional labels required</dt><dd>1</dd>")

    def test_job_detail_renders_latest_discovery_without_a_pending_extension(self):
        incremental = IncrementalPolicyV1.model_validate(
            {
                "job_id": "JOB-1",
                "cadence": "daily",
                "last_attempt_at": "2026-08-29T10:00:00+00:00",
                "last_success_at": "2026-08-29T10:00:00+00:00",
                "last_outcome": "no_changes",
                "revision": 8,
                "latest_event": {
                    "state": "no_changes",
                    "recorded_at": "2026-08-29T10:00:00+00:00",
                    "discovered_files": 11,
                    "discovered_bytes": 222,
                    "required_additional_labels": 0,
                },
                "pending_extension": None,
            }
        )
        self.daemon.job = self.daemon.job.model_copy(
            update={"incremental": incremental}
        )
        self.login("admin", "correct horse battery staple")

        detail = self.client.get("/jobs/JOB-1")

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertRegex(detail.text, r"Discovered</dt><dd>11 files / 222 bytes</dd>")
        self.assertNotIn("Pending plan", detail.text)

    def test_incremental_forms_enforce_csrf_closed_cadence_and_multiline_labels(self):
        self.login("admin", "correct horse battery staple")
        detail = self.client.get("/jobs/JOB-1")
        csrf = self.hidden(detail, "csrf")

        rejected = self.client.post(
            "/jobs/JOB-1/incremental-policy",
            data={
                "csrf": csrf,
                "idempotency_key": self.hidden(detail, "idempotency_key"),
                "expected_revision": "1",
                "cadence": "hourly",
            },
        )
        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertFalse(
            any(call[0] == "update_incremental_policy" for call in self.daemon.calls)
        )
        missing_csrf = self.client.post(
            "/jobs/JOB-1/incremental-scan",
            data={"idempotency_key": str(uuid4())},
        )
        self.assertEqual(403, missing_csrf.status_code)
        accepted = self.client.post(
            "/jobs/JOB-1/incremental-policy",
            data={
                "csrf": csrf,
                "idempotency_key": str(uuid4()),
                "expected_revision": "1",
                "cadence": "daily",
            },
        )
        scanned = self.client.post(
            "/jobs/JOB-1/incremental-scan",
            data={"csrf": csrf, "idempotency_key": str(uuid4())},
        )
        reserved = self.client.post(
            "/jobs/JOB-1/reserve-labels",
            data={
                "csrf": csrf,
                "idempotency_key": str(uuid4()),
                "expected_revision": "4",
                "labels": "CD5678\nEF9012\n",
                "authorize_automatic_formatting": "on",
            },
        )
        self.assertEqual(303, accepted.status_code, accepted.text)
        self.assertEqual(303, scanned.status_code, scanned.text)
        self.assertEqual(303, reserved.status_code, reserved.text)
        reserve_call = next(
            call for call in reversed(self.daemon.calls) if call[0] == "reserve_job_labels"
        )
        self.assertEqual(("CD5678", "EF9012"), reserve_call[1][1].labels)

    def test_settings_use_authoritative_choices_for_finite_domains(self):
        # Replacing the media-profile select with free text, or sourcing its
        # options from a stale WebUI list, would let an administrator submit a
        # value outside the daemon's currently advertised domain.
        self.login("admin", "correct horse battery staple")

        settings = self.client.get("/settings")

        self.assertEqual(200, settings.status_code, settings.text)
        media_select = re.search(
            r'<select name="default_media_profile"[^>]*>(.*?)</select>',
            settings.text,
            re.DOTALL,
        )
        self.assertIsNotNone(media_select, settings.text)
        assert media_select is not None
        self.assertEqual(
            ["LTO-10 PA"],
            re.findall(r'<option value="([^"]+)"', media_select.group(1)),
        )
        self.assertRegex(media_select.group(1), r'<option value="LTO-10 PA"[^>]* selected(?:\s|>)')
        self.assertNotRegex(
            settings.text,
            r'<input[^>]+name="default_media_profile"',
        )

        verification_select = re.search(
            r'<select name="content_verification_policy"[^>]*>(.*?)</select>',
            settings.text,
            re.DOTALL,
        )
        self.assertIsNotNone(verification_select, settings.text)
        assert verification_select is not None
        self.assertEqual(
            ["none", "manifest", "full"],
            re.findall(r'<option value="([^"]+)"', verification_select.group(1)),
        )
        source_select = re.search(
            r'<select name="source_change_detection_policy"[^>]*>(.*?)</select>',
            settings.text,
            re.DOTALL,
        )
        self.assertIsNotNone(source_select, settings.text)
        assert source_select is not None
        self.assertEqual(
            ["size_mtime", "size_mtime_change"],
            re.findall(r'<option value="([^"]+)"', source_select.group(1)),
        )
        self.assertRegex(
            settings.text,
            r'<input type="number" min="1048576" max="67108864" '
            r'name="copy_buffer_bytes"',
        )

    def test_settings_validation_rerender_preserves_authoritative_selects(self):
        # A validation error must not fall back to the old free-text control or
        # lose the user's valid finite-domain selections.
        self.login("admin", "correct horse battery staple")
        settings = self.client.get("/settings")

        invalid = self.client.post(
            "/settings/application",
            data={
                "csrf": self.hidden(settings, "csrf"),
                "idempotency_key": "settings-select-rerender",
                "expected_revision": "2",
                "capacity_reserve_bytes": "2048",
                "minimum_source_file_age_seconds": "60",
                "copy_buffer_bytes": "1",
                "content_verification_policy": "full",
                "source_change_detection_policy": "size_mtime",
                "default_media_profile": "LTO-10 PA",
                "tape_root_directory": "archive",
            },
        )

        self.assertEqual(422, invalid.status_code, invalid.text)
        self.assertRegex(
            invalid.text,
            r'<select name="default_media_profile"[^>]*>.*?'
            r'<option value="LTO-10 PA"[^>]* selected(?:\s|>)',
        )
        self.assertRegex(
            invalid.text,
            r'<select name="content_verification_policy"[^>]*>.*?'
            r'<option value="full" selected>',
        )
        self.assertRegex(
            invalid.text,
            r'<select name="source_change_detection_policy"[^>]*>.*?'
            r'<option value="size_mtime" selected>',
        )
        self.assertNotRegex(
            invalid.text,
            r'<input[^>]+name="default_media_profile"',
        )

    def test_settings_submit_explicit_source_change_policy(self):
        self.login("admin", "correct horse battery staple")
        settings = self.client.get("/settings")
        posted = self.client.post(
            "/settings/application",
            data={
                "csrf": self.hidden(settings, "csrf"),
                "idempotency_key": self.hidden(settings, "idempotency_key"),
                "expected_revision": "2",
                "capacity_reserve_bytes": "1024",
                "minimum_source_file_age_seconds": "60",
                "copy_buffer_bytes": str(1024 * 1024),
                "content_verification_policy": "manifest",
                "source_change_detection_policy": "size_mtime",
                "default_media_profile": "LTO-10 PA",
                "tape_root_directory": "archive",
            },
        )
        self.assertEqual(303, posted.status_code, posted.text)
        request = next(
            args[0] for name, args in reversed(self.daemon.calls)
            if name == "update_application_settings"
        )
        self.assertEqual("size_mtime", request.source_change_detection_policy)

    def test_nfs_timeout_and_retry_are_daemon_supplied_closed_selects(self):
        # Replacing either select with a numeric input would let the browser
        # submit a value outside the daemon's advertised finite contract.
        self.login("admin", "correct horse battery staple")
        page = self.client.get("/shares/new?protocol=nfs")

        self.assertEqual(200, page.status_code, page.text)
        for field, expected in (
            ("timeout_seconds", ["5", "15", "30", "60", "120", "300", "600"]),
            ("retransmissions", ["1", "2", "3", "5", "10"]),
        ):
            select = re.search(
                rf'<select name="{field}"[^>]*>(.*?)</select>',
                page.text,
                re.DOTALL,
            )
            self.assertIsNotNone(select, page.text)
            assert select is not None
            self.assertEqual(
                expected,
                re.findall(r'<option value="([^"]+)"', select.group(1)),
            )
            self.assertNotRegex(page.text, rf'<input[^>]+name="{field}"')

        before = len(self.daemon.calls)
        rejected = self.client.post(
            "/shares",
            data={
                "csrf": self.hidden(page, "csrf"),
                "idempotency_key": self.hidden(page, "idempotency_key"),
                "share_id": "closed-nfs",
                "display_name": "Closed NFS",
                "protocol": "nfs",
                "server": "nas.example.test",
                "remote_resource": "/archive",
                "nfs_version": "4.2",
                "timeout_seconds": "47",
                "retransmissions": "4",
            },
        )
        self.assertEqual(422, rejected.status_code, rejected.text)
        self.assertIn('data-field-error="timeout_seconds"', rejected.text)
        self.assertFalse(
            any(
                name == "create_network_share"
                for name, _ in self.daemon.calls[before:]
            )
        )

    def test_revision_conflicts_rerender_fresh_resources_with_safe_field_values(self):
        self.login("admin", "correct horse battery staple")
        calls_before = list(self.daemon.calls)
        auth_before = self.auth_mutation_snapshot()
        library = self.client.get("/libraries/PHOTOS")
        self.daemon.mutation_failure = DaemonRequestError(
            409, "library_revision_conflict"
        )
        library_conflict = self.client.post(
            "/libraries/PHOTOS/update",
            data={
                "csrf": self.hidden(library, "csrf"),
                "idempotency_key": self.hidden(library, "idempotency_key"),
                "expected_revision": "2",
                "display_name": "Nome tentato",
                "source_root": "/srv/source/PHOTOS",
                "state": "active",
            },
        )
        self.assertEqual(409, library_conflict.status_code)
        self.assertIn("Nome tentato", library_conflict.text)
        self.assertIn('name="expected_revision" value="3"', library_conflict.text)
        self.assertIn('data-field-error="expected_revision"', library_conflict.text)
        self.assertIn('action="/libraries/PHOTOS/update"', library_conflict.text)

        self.daemon.mutation_failure = DaemonRequestError(
            409, "settings_revision_conflict"
        )
        settings = self.client.get("/settings")
        settings_conflict = self.client.post(
            "/settings/application",
            data={
                "csrf": self.hidden(settings, "csrf"),
                "idempotency_key": self.hidden(settings, "idempotency_key"),
                "expected_revision": "1",
                "capacity_reserve_bytes": "2048",
                "minimum_source_file_age_seconds": "60",
                "copy_buffer_bytes": str(1024 * 1024),
                "content_verification_policy": "manifest",
                "default_media_profile": "LTO-10 PA",
                "tape_root_directory": "attempted-root",
            },
        )
        self.assertEqual(409, settings_conflict.status_code)
        self.assertIn("attempted-root", settings_conflict.text)
        self.assertIn('name="expected_revision" value="2"', settings_conflict.text)
        self.assertIn('data-field-error="expected_revision"', settings_conflict.text)

        self.daemon.mutation_failure = DaemonRequestError(409, "job_revision_conflict")
        job = self.client.get("/jobs/JOB-1")
        job_conflict = self.client.post(
            "/jobs/JOB-1/update",
            data={
                "csrf": self.hidden(job, "csrf"),
                "idempotency_key": self.hidden(job, "idempotency_key"),
                "expected_revision": "3",
                "display_name": "Nome job tentato",
            },
        )
        self.assertEqual(409, job_conflict.status_code)
        self.assertIn("Nome job tentato", job_conflict.text)
        self.assertIn('name="expected_revision" value="4"', job_conflict.text)
        self.assertIn('data-field-error="expected_revision"', job_conflict.text)
        self.assertEqual(calls_before, self.daemon.calls)
        self.assertEqual(auth_before, self.auth_mutation_snapshot())

    def test_revision_conflict_matrix_rebuilds_retire_reserve_and_extend_forms(self):
        self.login("admin", "correct horse battery staple")
        calls_before = list(self.daemon.calls)
        auth_before = self.auth_mutation_snapshot()
        library = self.client.get("/libraries/PHOTOS")
        self.daemon.mutation_failure = DaemonRequestError(
            409, "library_revision_conflict"
        )
        library_retire = self.client.post(
            "/libraries/PHOTOS/retire",
            data={
                "csrf": self.hidden(library, "csrf"),
                "idempotency_key": self.hidden(library, "idempotency_key"),
                "expected_revision": "2",
                "typed_library_id": "PHOTOS",
            },
        )
        self.assertEqual(409, library_retire.status_code)
        self.assertIn('action="/libraries/PHOTOS/retire"', library_retire.text)
        self.assertIn('name="expected_revision" value="3"', library_retire.text)

        job = self.client.get("/jobs/JOB-1")
        self.daemon.mutation_failure = DaemonRequestError(409, "job_revision_conflict")
        reserve = self.client.post(
            "/jobs/JOB-1/reserve-labels",
            data={
                "csrf": self.hidden(job, "csrf"),
                "idempotency_key": self.hidden(job, "idempotency_key"),
                "expected_revision": "3",
                "labels": "RS0001",
                "authorize_automatic_formatting": "on",
            },
        )
        self.assertEqual(409, reserve.status_code)
        self.assertIn("RS0001", reserve.text)
        self.assertIn('name="expected_revision" value="4"', reserve.text)

        retired = self.client.post(
            "/jobs/JOB-1/retire",
            data={
                "csrf": self.hidden(job, "csrf"),
                "idempotency_key": str(uuid4()),
                "expected_revision": "3",
                "typed_job_id": "JOB-1",
            },
        )
        self.assertEqual(409, retired.status_code)
        self.assertIn('action="/jobs/JOB-1/retire"', retired.text)

        self.daemon.plan = _plan(kind="extend")
        plan = self.client.get("/jobs/plans/PLAN-1")
        extended = self.client.post(
            "/jobs/JOB-1/extend",
            data={
                "csrf": self.hidden(plan, "csrf"),
                "idempotency_key": self.hidden(plan, "idempotency_key"),
                "expected_revision": "3",
                "plan_id": "PLAN-1",
                "digest_sha256": "a" * 64,
                "labels": "EX0001",
                "authorize_automatic_formatting": "on",
            },
        )
        self.assertEqual(409, extended.status_code)
        self.assertIn('action="/jobs/JOB-1/extend"', extended.text)
        self.assertIn("EX0001", extended.text)
        self.assertIn('name="expected_revision" value="4"', extended.text)
        self.assertEqual(calls_before, self.daemon.calls)
        self.assertEqual(auth_before, self.auth_mutation_snapshot())

    def test_local_user_forms_clear_passwords_and_never_call_daemon(self):
        self.login("admin", "correct horse battery staple")
        users = self.client.get("/users")
        calls_before = list(self.daemon.calls)
        created = self.client.post(
            "/users",
            data={
                "csrf": self.hidden(users, "csrf"),
                "idempotency_key": self.hidden(users, "idempotency_key"),
                "username": "new-operator",
                "role": "operator",
                "password": "new operator password",
            },
        )
        self.assertEqual(303, created.status_code, created.text)
        self.assertEqual("/users", created.headers["location"])
        self.assertEqual(calls_before, self.daemon.calls)

        refreshed = self.client.get("/users")
        failed = self.client.post(
            "/users",
            data={
                "csrf": self.hidden(refreshed, "csrf"),
                "idempotency_key": self.hidden(refreshed, "idempotency_key"),
                "username": "bad-user",
                "role": "operator",
                "password": "TOP-SECRET",
            },
        )
        self.assertEqual(422, failed.status_code)
        self.assertNotIn("TOP-SECRET", failed.text)
        self.assertIn("bad-user", failed.text)
        self.assertIn('data-field-error="password"', failed.text)

    def test_account_validation_rerenders_action_page_and_clears_all_passwords(self):
        self.login("operator", "operator password material")
        account = self.client.get("/account")
        failed = self.client.post(
            "/account/password-change",
            data={
                "csrf": self.hidden(account, "csrf"),
                "idempotency_key": self.hidden(account, "idempotency_key"),
                "current_password": "CURRENT-SECRET",
                "new_password": "NEW-SECRET",
            },
        )

        self.assertEqual(422, failed.status_code)
        self.assertIn('action="/account/password-change"', failed.text)
        self.assertIn('data-field-error="new_password"', failed.text)
        self.assertNotIn("CURRENT-SECRET", failed.text)
        self.assertNotIn("NEW-SECRET", failed.text)
        self.assertNotRegex(failed.text, r'type="password"[^>]+value=')

    def test_operator_can_revoke_own_sessions_and_never_sees_format_action(self):
        self.login("operator", "operator password material")
        account = self.client.get("/account")
        job = self.client.get("/jobs/JOB-1")

        self.assertIn('action="/account/sessions/revoke"', account.text)
        self.assertNotIn('action="/jobs/JOB-1/start"', job.text)
        revoked = self.client.post(
            "/account/sessions/revoke",
            data={
                "csrf": self.hidden(account, "csrf"),
                "idempotency_key": self.hidden(account, "idempotency_key"),
            },
        )
        self.assertEqual(303, revoked.status_code)
        self.assertEqual("/login", revoked.headers["location"])

    def test_invalid_expected_revisions_are_field_errors_with_fresh_state(self):
        self.login("admin", "correct horse battery staple")
        library = self.client.get("/libraries/PHOTOS")
        settings = self.client.get("/settings")
        job = self.client.get("/jobs/JOB-1")
        self.daemon.plan = _plan(kind="extend")
        plan = self.client.get("/jobs/plans/PLAN-1")
        cases = (
            (
                "/libraries/PHOTOS/update",
                library,
                {
                    "display_name": "Nome valido",
                    "source_root": "/srv/source/PHOTOS",
                    "state": "active",
                },
                'name="expected_revision" value="3"',
            ),
            (
                "/libraries/PHOTOS/retire",
                library,
                {"typed_library_id": "PHOTOS"},
                'name="expected_revision" value="3"',
            ),
            (
                "/settings/application",
                settings,
                {
                    "capacity_reserve_bytes": "2048",
                    "minimum_source_file_age_seconds": "60",
                    "copy_buffer_bytes": str(1024 * 1024),
                    "content_verification_policy": "manifest",
                    "default_media_profile": "LTO-10 PA",
                    "tape_root_directory": "archive",
                },
                'name="expected_revision" value="2"',
            ),
            (
                "/jobs/JOB-1/update",
                job,
                {"display_name": "Nome valido"},
                'name="expected_revision" value="4"',
            ),
            (
                "/jobs/JOB-1/reserve-labels",
                job,
                {
                    "labels": "RS0001",
                    "authorize_automatic_formatting": "on",
                },
                'name="expected_revision" value="4"',
            ),
            (
                "/jobs/JOB-1/extend",
                plan,
                {
                    "plan_id": "PLAN-1",
                    "digest_sha256": "a" * 64,
                    "labels": "EX0001",
                    "authorize_automatic_formatting": "on",
                },
                'name="expected_revision" value="4"',
            ),
            (
                "/jobs/JOB-1/retire",
                job,
                {"typed_job_id": "JOB-1"},
                'name="expected_revision" value="4"',
            ),
        )
        with TestClient(
            self.app,
            base_url="https://console.example",
            follow_redirects=False,
            raise_server_exceptions=False,
        ) as safe_client:
            safe_client.cookies.update(self.client.cookies)
            for index, (path, page, fields, fresh_revision) in enumerate(cases):
                with self.subTest(path=path):
                    response = safe_client.post(
                        path,
                        data={
                            "csrf": self.hidden(page, "csrf"),
                            "idempotency_key": f"invalid-revision-{index}",
                            "expected_revision": "not-an-integer",
                            **fields,
                        },
                    )
                    self.assertEqual(422, response.status_code, response.text)
                    self.assertIn('data-field-error="expected_revision"', response.text)
                    self.assertIn(fresh_revision, response.text)

    def test_management_validation_errors_name_the_exact_control_or_action_form(self):
        self.login("admin", "correct horse battery staple")

        libraries = self.client.get("/libraries")
        invalid_library = self.client.post(
            "/libraries",
            data={
                "csrf": self.hidden(libraries, "csrf"),
                "idempotency_key": "a11y-invalid-library",
                "library_id": "bad library id",
                "display_name": "Musica",
                "source_root": "/srv/source/music",
            },
        )
        self.assert_field_error_association(
            invalid_library,
            field="library_id",
            action="/libraries",
            control_name="library_id",
        )

        library = self.client.get("/libraries/PHOTOS")
        invalid_revision = self.client.post(
            "/libraries/PHOTOS/update",
            data={
                "csrf": self.hidden(library, "csrf"),
                "idempotency_key": "a11y-library-revision",
                "expected_revision": "not-an-integer",
                "display_name": "Foto",
                "source_root": "/srv/source/PHOTOS",
                "state": "active",
            },
        )
        self.assert_field_error_association(
            invalid_revision,
            field="expected_revision",
            action="/libraries/PHOTOS/update",
            control_name=None,
        )

        job_new = self.client.get("/jobs/new")
        invalid_selection = self.client.post(
            "/jobs/plans",
            data={
                "csrf": self.hidden(job_new, "csrf"),
                "idempotency_key": "a11y-job-selection",
                "media_profile": "LTO-10 PA",
            },
        )
        self.assert_field_error_association(
            invalid_selection,
            field="library_ids",
            action="/jobs/plans",
            control_name="library_ids",
        )

        plan = self.client.get("/jobs/plans/PLAN-1")
        invalid_plan = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(plan, "csrf"),
                "idempotency_key": "a11y-plan-labels",
                "digest_sha256": "a" * 64,
                "display_name": "Backup",
                "authorize_automatic_formatting": "on",
            },
        )
        self.assert_field_error_association(
            invalid_plan,
            field="labels",
            action="/jobs/plans/PLAN-1/jobs",
            control_name="labels",
        )

        job = self.client.get("/jobs/JOB-1")
        invalid_job = self.client.post(
            "/jobs/JOB-1/update",
            data={
                "csrf": self.hidden(job, "csrf"),
                "idempotency_key": "a11y-job-name",
                "expected_revision": "4",
                "display_name": "   ",
            },
        )
        self.assert_field_error_association(
            invalid_job,
            field="display_name",
            action="/jobs/JOB-1/update",
            control_name="display_name",
        )

        users = self.client.get("/users")
        invalid_user = self.client.post(
            "/users",
            data={
                "csrf": self.hidden(users, "csrf"),
                "idempotency_key": "a11y-user-name",
                "username": "",
                "role": "operator",
                "password": "not-rendered-password",
            },
        )
        self.assert_field_error_association(
            invalid_user,
            field="username",
            action="/users",
            control_name="username",
        )

        settings = self.client.get("/settings")
        invalid_settings = self.client.post(
            "/settings/application",
            data={
                "csrf": self.hidden(settings, "csrf"),
                "idempotency_key": "a11y-settings-buffer",
                "expected_revision": "2",
                "capacity_reserve_bytes": "2048",
                "minimum_source_file_age_seconds": "60",
                "copy_buffer_bytes": "1",
                "content_verification_policy": "manifest",
                "default_media_profile": "LTO-10 PA",
                "tape_root_directory": "archive",
            },
        )
        self.assert_field_error_association(
            invalid_settings,
            field="copy_buffer_bytes",
            action="/settings/application",
            control_name="copy_buffer_bytes",
        )

        key = "a11y-user-idempotency"
        created = self.client.post(
            "/users",
            data={
                "csrf": self.hidden(users, "csrf"),
                "idempotency_key": key,
                "username": "first-a11y-user",
                "role": "operator",
                "password": "first a11y password",
            },
        )
        self.assertEqual(303, created.status_code, created.text)
        conflict = self.client.post(
            "/users",
            data={
                "csrf": self.hidden(users, "csrf"),
                "idempotency_key": key,
                "username": "second-a11y-user",
                "role": "operator",
                "password": "second a11y password",
            },
        )
        self.assert_field_error_association(
            conflict,
            field="idempotency_key",
            action="/users",
            control_name=None,
        )

        self.client.post("/logout", data={"csrf": self.hidden(users, "csrf")})
        self.login("operator", "operator password material")
        account = self.client.get("/account")
        invalid_account = self.client.post(
            "/account/password-change",
            data={
                "csrf": self.hidden(account, "csrf"),
                "idempotency_key": "a11y-account-password",
                "current_password": "wrong current password",
                "new_password": "valid replacement password",
            },
        )
        self.assert_field_error_association(
            invalid_account,
            field="current_password",
            action="/account/password-change",
            control_name="current_password",
        )

    def test_validation_locations_render_exact_fields_and_authoritative_choices(self):
        self.login("admin", "correct horse battery staple")
        libraries = self.client.get("/libraries")
        invalid_library = self.client.post(
            "/libraries",
            data={
                "csrf": self.hidden(libraries, "csrf"),
                "idempotency_key": "invalid-library-root",
                "library_id": "bad library id",
                "display_name": "Musica tentata",
                "source_root": "/srv/source/music",
            },
        )
        self.assertEqual(422, invalid_library.status_code)
        self.assertIn('data-field-error="library_id"', invalid_library.text)
        self.assertNotIn('data-field-error="candidate"', invalid_library.text)
        self.assertIn("Foto &lt;famiglia&gt;", invalid_library.text)
        self.assertIn("Musica tentata", invalid_library.text)

        settings = self.client.get("/settings")
        invalid_settings = self.client.post(
            "/settings/application",
            data={
                "csrf": self.hidden(settings, "csrf"),
                "idempotency_key": "invalid-settings-buffer",
                "expected_revision": "2",
                "capacity_reserve_bytes": "2048",
                "minimum_source_file_age_seconds": "60",
                "copy_buffer_bytes": "1",
                "content_verification_policy": "manifest",
                "default_media_profile": "LTO-10 PA",
                "tape_root_directory": "attempted-root",
            },
        )
        self.assertEqual(422, invalid_settings.status_code)
        self.assertIn('data-field-error="copy_buffer_bytes"', invalid_settings.text)
        self.assertNotIn('data-field-error="candidate"', invalid_settings.text)
        self.assertIn("attempted-root", invalid_settings.text)

        users = self.client.get("/users")
        invalid_user = self.client.post(
            "/users",
            data={
                "csrf": self.hidden(users, "csrf"),
                "idempotency_key": "invalid-user-name",
                "username": "",
                "role": "operator",
                "password": "DO-NOT-RENDER-THIS-PASSWORD",
            },
        )
        self.assertEqual(422, invalid_user.status_code)
        self.assertIn('data-field-error="username"', invalid_user.text)
        self.assertNotIn("DO-NOT-RENDER-THIS-PASSWORD", invalid_user.text)

        self.client.post("/logout", data={"csrf": self.hidden(users, "csrf")})
        self.login("operator", "operator password material")
        account = self.client.get("/account")
        invalid_password = self.client.post(
            "/account/password-change",
            data={
                "csrf": self.hidden(account, "csrf"),
                "idempotency_key": "invalid-current-password",
                "current_password": "WRONG-CURRENT-SECRET",
                "new_password": "valid replacement password",
            },
        )
        self.assertEqual(422, invalid_password.status_code)
        self.assertIn('data-field-error="current_password"', invalid_password.text)
        self.assertNotIn("WRONG-CURRENT-SECRET", invalid_password.text)
        self.assertNotIn("valid replacement password", invalid_password.text)

    def test_job_plan_and_action_validation_marks_the_responsible_field(self):
        self.login("operator", "operator password material")
        new = self.client.get("/jobs/new")
        invalid_profile = self.client.post(
            "/jobs/plans",
            data={
                "csrf": self.hidden(new, "csrf"),
                "idempotency_key": "invalid-media-profile",
                "library_ids": "PHOTOS",
                "media_profile": "NOT-A-PROFILE",
            },
        )
        self.assertEqual(422, invalid_profile.status_code)
        self.assertIn('data-field-error="media_profile"', invalid_profile.text)
        self.assertIn("Foto &lt;famiglia&gt;", invalid_profile.text)

        self.client.post("/logout", data={"csrf": self.hidden(new, "csrf")})
        self.login("admin", "correct horse battery staple")
        plan = self.client.get("/jobs/plans/PLAN-1")
        invalid_name = self.client.post(
            "/jobs/plans/PLAN-1/jobs",
            data={
                "csrf": self.hidden(plan, "csrf"),
                "idempotency_key": "invalid-job-name",
                "digest_sha256": "a" * 64,
                "display_name": "   ",
                "labels": "AB1234",
                "authorize_automatic_formatting": "on",
            },
        )
        self.assertEqual(422, invalid_name.status_code)
        self.assertIn('data-field-error="display_name"', invalid_name.text)
        self.assertNotIn('data-field-error="labels"', invalid_name.text)

        job = self.client.get("/jobs/JOB-1")
        action_cases = (
            (
                "/jobs/JOB-1/start",
                {"format_confirmation_label": "bad label"},
                "format_confirmation_label",
            ),
            (
                "/jobs/JOB-1/resume",
                {"format_confirmation_label": "bad label"},
                "format_confirmation_label",
            ),
            (
                "/jobs/JOB-1/update",
                {"expected_revision": "4", "display_name": "   "},
                "display_name",
            ),
            (
                "/jobs/JOB-1/reserve-labels",
                {
                    "expected_revision": "4",
                    "labels": "bad label",
                    "authorize_automatic_formatting": "on",
                },
                "labels",
            ),
        )
        for index, (path, values, field) in enumerate(action_cases):
            with self.subTest(path=path):
                response = self.client.post(
                    path,
                    data={
                        "csrf": self.hidden(job, "csrf"),
                        "idempotency_key": f"invalid-job-action-{index}",
                        **values,
                    },
                )
                self.assertEqual(422, response.status_code, response.text)
                self.assertIn(f'data-field-error="{field}"', response.text)
                self.assertIn('name="expected_revision" value="4"', response.text)

        self.client.post("/logout", data={"csrf": self.hidden(job, "csrf")})
        self.login("admin", "correct horse battery staple")
        admin_job = self.client.get("/jobs/JOB-1")
        invalid_retire = self.client.post(
            "/jobs/JOB-1/retire",
            data={
                "csrf": self.hidden(admin_job, "csrf"),
                "idempotency_key": "invalid-job-retire-id",
                "expected_revision": "4",
                "typed_job_id": "bad id",
            },
        )
        self.assertEqual(422, invalid_retire.status_code)
        self.assertIn('data-field-error="typed_job_id"', invalid_retire.text)

    def test_daemon_validation_codes_rebuild_each_action_on_the_exact_field(self):
        self.login("admin", "correct horse battery staple")
        libraries = self.client.get("/libraries")
        library = self.client.get("/libraries/PHOTOS")
        job = self.client.get("/jobs/JOB-1")
        plan = self.client.get("/jobs/plans/PLAN-1")
        cases = (
            (
                "/libraries",
                libraries,
                {
                    "library_id": "MUSIC",
                    "display_name": "Musica tentata",
                    "source_root": "/outside/allowlist",
                },
                DaemonRequestError(422, "library_path_invalid"),
                "source_root",
                "Musica tentata",
            ),
            (
                "/libraries/PHOTOS/scan",
                library,
                {},
                DaemonRequestError(409, "library_state_conflict"),
                "state",
                "Foto &lt;famiglia&gt;",
            ),
            (
                "/jobs/plans/PLAN-1/jobs",
                plan,
                {
                    "digest_sha256": "a" * 64,
                    "display_name": "Backup tentato",
                    "labels": "AB1234",
                    "authorize_automatic_formatting": "on",
                },
                DaemonRequestError(409, "plan_digest_mismatch"),
                "digest_sha256",
                "Backup tentato",
            ),
            (
                "/jobs/JOB-1/start",
                job,
                {"format_confirmation_label": "AB1234"},
                DaemonRequestError(422, "format_confirmation_required"),
                "format_confirmation_label",
                "AB1234",
            ),
            (
                "/jobs/JOB-1/pause",
                job,
                {},
                DaemonRequestError(409, "job_state_conflict"),
                "state",
                "Backup foto",
            ),
            (
                "/jobs/JOB-1/extension-plan",
                job,
                {},
                DaemonRequestError(409, "job_state_conflict"),
                "state",
                "Backup foto",
            ),
        )
        for index, (path, page, values, failure, field, preserved) in enumerate(cases):
            with self.subTest(path=path, code=failure.error_code):
                self.daemon.mutation_failure = failure
                response = self.client.post(
                    path,
                    data={
                        "csrf": self.hidden(page, "csrf"),
                        "idempotency_key": f"daemon-validation-{index}",
                        **values,
                    },
                )
                self.assertIn(response.status_code, {409, 422}, response.text)
                self.assertIn(f'data-field-error="{field}"', response.text)
                self.assertIn(preserved, response.text)
        self.daemon.mutation_failure = None

    def test_recent_admin_reauthentication_rejections_map_to_sessions(self):
        second_admin = self.store.create_user(
            "second-admin",
            "second administrator password",
            role="admin",
            actor_user_id=self.admin.id,
            idempotency_key="create-second-admin-for-web-errors",
        )
        self.login("admin", "correct horse battery staple")
        users = self.client.get("/users")
        csrf = self.hidden(users, "csrf")
        cases = (
            (
                f"/users/{self.operator.id}/password-reset",
                {"new_password": "replacement password material"},
            ),
            (f"/users/{self.operator.id}/retire", {}),
            (f"/users/{second_admin.id}/role", {"role": "operator"}),
            ("/sessions/revoke-all", {}),
        )
        for index, (path, values) in enumerate(cases):
            with self.subTest(path=path):
                response = self.client.post(
                    path,
                    data={
                        "csrf": csrf,
                        "idempotency_key": f"recent-reauth-required-{index}",
                        **values,
                    },
                )
                self.assertEqual(422, response.status_code, response.text)
                self.assertIn('data-field-error="sessions"', response.text)
                self.assertNotIn('data-field-error="role"', response.text)
                self.assertNotIn("replacement password material", response.text)

    def test_auth_idempotency_conflict_maps_to_key_and_clears_password(self):
        self.login("admin", "correct horse battery staple")
        users = self.client.get("/users")
        csrf = self.hidden(users, "csrf")
        key = "web-create-user-idempotency-conflict"
        created = self.client.post(
            "/users",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "username": "first-idempotent-user",
                "role": "operator",
                "password": "first idempotent password",
            },
        )
        self.assertEqual(303, created.status_code, created.text)

        conflict = self.client.post(
            "/users",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "username": "second-idempotent-user",
                "role": "operator",
                "password": "SECOND-IDEMPOTENT-SECRET",
            },
        )

        self.assertEqual(422, conflict.status_code, conflict.text)
        self.assertIn('data-field-error="idempotency_key"', conflict.text)
        self.assertNotIn('data-field-error="password"', conflict.text)
        self.assertIn("second-idempotent-user", conflict.text)
        self.assertNotIn("SECOND-IDEMPOTENT-SECRET", conflict.text)

    def test_reauthentication_replay_conflicts_are_key_errors_without_secrets(self):
        self.login("admin", "correct horse battery staple")
        users = self.client.get("/users")
        csrf = self.hidden(users, "csrf")

        ordinary_bad = self.client.post(
            "/account/reauthenticate",
            data={
                "csrf": csrf,
                "idempotency_key": "ordinary-bad-reauthentication",
                "password": "ordinary wrong password",
            },
        )
        self.assertEqual(401, ordinary_bad.status_code)
        self.assertIn('data-field-error="password"', ordinary_bad.text)

        key = "http-reauthentication-replay"
        accepted = self.client.post(
            "/account/reauthenticate",
            data={
                "csrf": csrf,
                "idempotency_key": key,
                "password": "correct horse battery staple",
            },
        )
        self.assertEqual(303, accepted.status_code, accepted.text)
        accepted_state = self.auth_mutation_snapshot()

        records: list[str] = []

        class CaptureHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record.getMessage())

        handler = CaptureHandler()
        logging.getLogger().addHandler(handler)
        different_secret = "DIFFERENT-REAUTHENTICATION-SECRET"
        try:
            conflict = self.client.post(
                "/account/reauthenticate",
                data={
                    "csrf": csrf,
                    "idempotency_key": key,
                    "password": different_secret,
                },
            )
        finally:
            logging.getLogger().removeHandler(handler)

        self.assertEqual(422, conflict.status_code, conflict.text)
        self.assertIn('data-field-error="idempotency_key"', conflict.text)
        self.assertNotIn('data-field-error="password"', conflict.text)
        self.assertNotIn(different_secret, conflict.text)
        self.assertNotIn(different_secret, "\n".join(records))
        self.assertNotIn(different_secret, str(self.store.list_audit_events()))
        self.assertNotIn(different_secret.encode(), self.store.database.read_bytes())
        self.assertEqual(accepted_state, self.auth_mutation_snapshot())

        with sqlite3.connect(self.store.database) as connection:
            connection.execute(
                "UPDATE web_idempotency SET receipt_json = ? WHERE idempotency_key = ?",
                ('{"user_id":1}', key),
            )
            connection.commit()
        malformed_receipt_state = self.auth_mutation_snapshot()
        records.clear()
        logging.getLogger().addHandler(handler)
        try:
            bad_receipt = self.client.post(
                "/account/reauthenticate",
                data={
                    "csrf": csrf,
                    "idempotency_key": key,
                    "password": "correct horse battery staple",
                },
            )
        finally:
            logging.getLogger().removeHandler(handler)
        self.assertEqual(422, bad_receipt.status_code, bad_receipt.text)
        self.assertIn('data-field-error="idempotency_key"', bad_receipt.text)
        self.assertNotIn("correct horse battery staple", bad_receipt.text)
        self.assertNotIn("correct horse battery staple", "\n".join(records))
        self.assertNotIn(
            "correct horse battery staple", str(self.store.list_audit_events())
        )
        self.assertNotIn(
            b"correct horse battery staple", self.store.database.read_bytes()
        )
        self.assertEqual(malformed_receipt_state, self.auth_mutation_snapshot())

    def test_every_management_post_rejects_missing_csrf_before_side_effects(self):
        self.login("admin", "correct horse battery staple")
        paths = (
            "/libraries",
            "/libraries/PHOTOS/update",
            "/libraries/PHOTOS/scan",
            "/libraries/PHOTOS/retire",
            "/jobs/plans",
            "/jobs/plans/PLAN-1/jobs",
            "/jobs/JOB-1/start",
            "/jobs/JOB-1/resume",
            "/jobs/JOB-1/failed-cassette/reset",
            "/jobs/JOB-1/pause",
            "/jobs/JOB-1/update",
            "/jobs/JOB-1/reserve-labels",
            "/jobs/JOB-1/extension-plan",
            "/jobs/JOB-1/extend",
            "/jobs/JOB-1/retire",
            "/jobs/native",
            "/settings/application",
            "/users",
            f"/users/{self.operator.id}/enable",
            f"/users/{self.operator.id}/disable",
            f"/users/{self.operator.id}/retire",
            f"/users/{self.operator.id}/role",
            f"/users/{self.operator.id}/password-reset",
            f"/users/{self.operator.id}/sessions/revoke",
            "/account/reauthenticate",
            "/account/sessions/revoke",
            "/account/password-change",
            "/sessions/revoke-all",
            "/media/1/format",
            "/logout",
        )
        calls_before = list(self.daemon.calls)
        auth_before = self.auth_mutation_snapshot()

        for path in paths:
            with self.subTest(path=path):
                response = self.client.post(
                    path, data={"idempotency_key": "csrf-matrix"}
                )
                self.assertEqual(403, response.status_code, response.text)

        self.assertEqual(calls_before, self.daemon.calls)
        self.assertEqual(auth_before, self.auth_mutation_snapshot())

    def test_operator_rbac_matrix_rejects_every_admin_only_management_post(self):
        self.login("operator", "operator password material")
        account = self.client.get("/account")
        csrf = self.hidden(account, "csrf")
        paths = (
            "/libraries",
            "/libraries/PHOTOS/update",
            "/libraries/PHOTOS/retire",
            "/jobs/JOB-1/retire",
            "/jobs/JOB-1/failed-cassette/reset",
            "/settings/application",
            "/users",
            f"/users/{self.admin.id}/enable",
            f"/users/{self.admin.id}/disable",
            f"/users/{self.admin.id}/retire",
            f"/users/{self.admin.id}/role",
            f"/users/{self.admin.id}/password-reset",
            f"/users/{self.admin.id}/sessions/revoke",
            "/sessions/revoke-all",
            "/media/1/format",
        )
        calls_before = list(self.daemon.calls)
        auth_before = self.auth_mutation_snapshot()

        for path in paths:
            with self.subTest(path=path):
                response = self.client.post(
                    path,
                    data={"csrf": csrf, "idempotency_key": "operator-rbac"},
                )
                self.assertEqual(403, response.status_code, response.text)

        self.assertEqual(calls_before, self.daemon.calls)
        self.assertEqual(auth_before, self.auth_mutation_snapshot())

class ControlledWebClientTests(unittest.TestCase):
    """Real request/session middleware without Argon2 login setup or daemon lifespan."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = AuthStore(Path(self.temporary.name) / "auth.db")
        with sqlite3.connect(self.store.database) as connection:
            connection.execute(
                "INSERT INTO web_users (login_name,normalized_login,password_hash,role,"
                "lifecycle,credential_generation,created_at,last_login_at,retired_at) "
                "VALUES ('admin','admin','unused','admin','active',1,0,NULL,NULL)"
            )
            connection.commit()
        admin = self.store.get_user_by_login("admin")
        assert admin is not None
        self.daemon = ManagementDaemonFake()
        self.app = create_web_app(WebSettings(), self.store, self.daemon)
        session = self.app.state.session_manager.create(admin)
        self.admin = admin
        self.session = session
        self.cookies = (
            f"lto_archiver_session={session.cookie}; "
            f"lto_archiver_csrf={session.csrf_token}"
        )

    def mark_recent_reauthentication(self) -> None:
        with sqlite3.connect(self.store.database) as connection:
            connection.execute(
                "UPDATE web_sessions SET reauthenticated_at = ? WHERE token_hash = ?",
                (time.time(), self.app.state.session_manager._hash_token(self.session.cookie)),
            )
            connection.commit()

    def test_replacement_response_loss_replays_exact_server_side_capability(self) -> None:
        self.mark_recent_reauthentication()
        self.daemon.restore_runs["RESTORE-RUN-1"] = _restore_run(conflict=True)
        page = asyncio.run(self.request("GET", "/restore-runs/RESTORE-RUN-1"))
        form = re.search(
            r'action="/restore-runs/RESTORE-RUN-1/items/1/replacement-authorizations".*?'
            r'name="csrf" value="([^"]+)".*?name="idempotency_key" value="([^"]+)"',
            page.text,
            re.S,
        )
        self.assertIsNotNone(form, page.text)
        assert form is not None
        data = {"csrf": form.group(1), "idempotency_key": form.group(2)}
        self.daemon.replacement_response_loss_once = True

        ambiguous = asyncio.run(
            self.request(
                "POST",
                "/restore-runs/RESTORE-RUN-1/items/1/replacement-authorizations",
                data=data,
            )
        )
        self.assertEqual(503, ambiguous.status_code, ambiguous.text)
        self.daemon.replacement_clock += 301
        replay = asyncio.run(
            self.request(
                "POST",
                "/restore-runs/RESTORE-RUN-1/items/1/replacement-authorizations",
                data=data,
            )
        )
        self.assertEqual(303, replay.status_code, replay.text)
        issue_calls = [call for call in self.daemon.calls if call[0] == "issue_catalog_restore_replacement_capability"]
        authorization_calls = [call for call in self.daemon.calls if call[0] == "authorize_catalog_restore_item_replacement"]
        self.assertEqual(1, len(issue_calls))
        self.assertEqual(2, len(authorization_calls))
        self.assertEqual(
            authorization_calls[0][1][2].capability,
            authorization_calls[1][1][2].capability,
        )
        receipt = self.store.restore_replacement_authorization_receipt(
            actor_user_id=self.admin.id,
            session_binding_sha256=self.app.state.session_manager._hash_token(self.session.cookie),
            run_id="RESTORE-RUN-1",
            item_sequence=1,
            idempotency_key=data["idempotency_key"],
        )
        self.assertEqual("complete", receipt.state)
        self.assertIsNone(receipt.capability)
        collision = asyncio.run(
            self.request(
                "POST",
                "/restore-runs/RESTORE-RUN-1/items/2/replacement-authorizations",
                data=data,
            )
        )
        self.assertEqual(409, collision.status_code, collision.text)
        self.assertNotIn("c" * 48, collision.text)
        issue_calls_after_collision = [
            call
            for call in self.daemon.calls
            if call[0] == "issue_catalog_restore_replacement_capability"
        ]
        self.assertEqual(
            1,
            len(issue_calls_after_collision),
            "a collision must not issue another capability",
        )

    def test_restore_controls_enforce_csrf_and_surface_state_and_key_conflicts(self) -> None:
        self.daemon.restore_runs["RESTORE-RUN-1"] = _restore_run()
        page = asyncio.run(self.request("GET", "/restore-runs/RESTORE-RUN-1"))
        csrf = self.hidden(page, "csrf")
        calls_before = len(self.daemon.calls)
        denied = asyncio.run(
            self.request(
                "POST",
                "/restore-runs/RESTORE-RUN-1/pause",
                data={"csrf": "wrong", "idempotency_key": "pause-csrf"},
            )
        )
        self.assertEqual(403, denied.status_code, denied.text)
        self.assertEqual(calls_before, len(self.daemon.calls))

        self.daemon.mutation_failure = DaemonRequestError(409, "restore_run_state_invalid")
        invalid_state = asyncio.run(
            self.request(
                "POST",
                "/restore-runs/RESTORE-RUN-1/resume",
                data={"csrf": csrf, "idempotency_key": "resume-invalid-state"},
            )
        )
        self.assertEqual(409, invalid_state.status_code, invalid_state.text)
        self.assertIn('data-error-code="daemon_rejected"', invalid_state.text)
        self.assertIn("Field: state", invalid_state.text)

        self.daemon.mutation_failure = DaemonRequestError(409, "idempotency_conflict")
        collision = asyncio.run(
            self.request(
                "POST",
                "/restore-runs/RESTORE-RUN-1/cancel",
                data={"csrf": csrf, "idempotency_key": "shared-control-key"},
            )
        )
        self.assertEqual(409, collision.status_code, collision.text)
        self.assertIn("idempotency_conflict", collision.text)

    async def request(self, method: str, path: str, **kwargs):
        headers = {"Cookie": self.cookies, **kwargs.pop("headers", {})}
        transport = httpx.ASGITransport(app=self.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="https://console.example",
            follow_redirects=False,
        ) as client:
            return await client.request(
                method, path, headers=headers, **kwargs
            )

    @staticmethod
    def hidden(response, name: str) -> str:
        match = re.search(rf'name="{re.escape(name)}" value="([^"]*)"', response.text)
        assert match is not None, response.text
        return match.group(1)

    def test_controlled_client_completes_sequence_detail_request(self) -> None:
        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn("Authorize automatic cassette sequence", detail.text)

    def test_plan_format_consent_is_required_and_preserved_on_errors(self) -> None:
        page = asyncio.run(self.request("GET", "/jobs/plans/PLAN-1"))
        base = {
            "csrf": self.hidden(page, "csrf"),
            "idempotency_key": self.hidden(page, "idempotency_key"),
            "digest_sha256": "a" * 64,
            "display_name": "Archive",
            "labels": "AB1234",
        }
        saved = asyncio.run(self.request("POST", "/jobs/plans/PLAN-1/jobs", data=base))
        self.assertEqual(422, saved.status_code, saved.text)
        self.assertIn('data-field-error="authorize_automatic_formatting"', saved.text)
        self.assertEqual([], self.daemon.calls)

        checked = asyncio.run(
            self.request(
                "POST",
                "/jobs/plans/PLAN-1/jobs",
                data={
                    **base,
                    "idempotency_key": "literal-checked",
                    "authorize_automatic_formatting": "on",
                },
            )
        )
        self.assertEqual(303, checked.status_code, checked.text)
        self.assertIs(True, self.daemon.calls[-1][1][1].authorize_automatic_formatting)

        malformed = asyncio.run(
            self.request(
                "POST",
                "/jobs/plans/PLAN-1/jobs",
                data={**base, "idempotency_key": "malformed-consent", "authorize_automatic_formatting": "true"},
            )
        )
        self.assertEqual(422, malformed.status_code, malformed.text)
        self.assertIn('data-field-error="authorize_automatic_formatting"', malformed.text)
        self.assertEqual(1, len(self.daemon.calls))

        duplicate = asyncio.run(
            self.request(
                "POST",
                "/jobs/plans/PLAN-1/jobs",
                content=(
                    f"csrf={base['csrf']}&idempotency_key=duplicate-consent&"
                    f"digest_sha256={'a' * 64}&display_name=Archive&labels=AB1234&"
                    "authorize_automatic_formatting=on&authorize_automatic_formatting=on"
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        )
        self.assertEqual(422, duplicate.status_code, duplicate.text)
        self.assertEqual(1, len(self.daemon.calls))

        invalid = asyncio.run(
            self.request(
                "POST",
                "/jobs/plans/PLAN-1/jobs",
                data={**base, "idempotency_key": "preserve-consent", "display_name": "   ", "authorize_automatic_formatting": "on"},
            )
        )
        self.assertEqual(422, invalid.status_code, invalid.text)
        self.assertRegex(invalid.text, r'name="authorize_automatic_formatting"[^>]*checked')

        self.daemon.mutation_failure = DaemonRequestError(409, "plan_stale")
        daemon_error = asyncio.run(
            self.request(
                "POST",
                "/jobs/plans/PLAN-1/jobs",
                data={
                    **base,
                    "idempotency_key": "daemon-error-consent",
                    "authorize_automatic_formatting": "on",
                },
            )
        )
        self.assertEqual(409, daemon_error.status_code, daemon_error.text)
        self.assertRegex(
            daemon_error.text,
            r'name="authorize_automatic_formatting"[^>]*checked',
        )

    def test_extension_requires_visible_admin_grant_and_preserves_checked_conflict(self) -> None:
        """A reserve extension must disclose and retain its format grant."""
        self.daemon.plan = JobPlanV1.model_validate(
            {
                **_plan(
                    kind="extend", requires_automatic_format_authorization=True
                ).model_dump(),
                "cassettes": (
                    {
                        "sequence": 1,
                        "physical_label": "RS0001",
                        "bytes": 7,
                        "objects": 2,
                        "allocation_bytes": 8192,
                        "capacity_utilization": 0.1,
                        "format_required": True,
                        "operation": "reserve",
                    },
                ),
            }
        )
        page = asyncio.run(self.request("GET", "/jobs/plans/PLAN-1"))
        self.assertEqual(200, page.status_code, page.text)
        self.assertEqual(1, page.text.count('name="authorize_automatic_formatting"'))
        form = {
            "csrf": self.hidden(page, "csrf"),
            "idempotency_key": self.hidden(page, "idempotency_key"),
            "expected_revision": "4",
            "plan_id": "PLAN-1",
            "digest_sha256": "a" * 64,
        }
        unchecked = asyncio.run(
            self.request("POST", "/jobs/JOB-1/extend", data=form)
        )
        self.assertEqual(422, unchecked.status_code, unchecked.text)
        self.assertIn('data-field-error="authorize_automatic_formatting"', unchecked.text)
        self.assertEqual([], self.daemon.calls)

        checked_form = {**form, "idempotency_key": "extension-authorized", "authorize_automatic_formatting": "on"}
        accepted = asyncio.run(
            self.request("POST", "/jobs/JOB-1/extend", data=checked_form)
        )
        self.assertEqual(303, accepted.status_code, accepted.text)
        self.assertIs(True, self.daemon.calls[-1][1][1].authorize_automatic_formatting)

        self.daemon.mutation_failure = DaemonRequestError(
            409, "automatic_format_authorization_required"
        )
        conflict = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/extend",
                data={**checked_form, "idempotency_key": "extension-conflict"},
            )
        )
        self.assertEqual(409, conflict.status_code, conflict.text)
        self.assertIn('data-field-error="authorize_automatic_formatting"', conflict.text)
        self.assertRegex(
            conflict.text, r'name="authorize_automatic_formatting"[^>]*checked'
        )

    def test_extension_conflict_retains_editable_label(self) -> None:
        self.daemon.plan = _plan(
            kind="extend", requires_automatic_format_authorization=True
        )
        page = asyncio.run(self.request("GET", "/jobs/plans/PLAN-1"))
        form = {
            "csrf": self.hidden(page, "csrf"),
            "idempotency_key": "extension-label-conflict",
            "expected_revision": "4",
            "plan_id": "PLAN-1",
            "digest_sha256": "a" * 64,
            "labels": "EX0001",
            "authorize_automatic_formatting": "on",
        }
        self.daemon.mutation_failure = DaemonRequestError(
            409, "automatic_format_authorization_required"
        )

        response = asyncio.run(self.request("POST", "/jobs/JOB-1/extend", data=form))

        self.assertEqual(409, response.status_code, response.text)
        self.assertIn('name="labels" value="EX0001"', response.text)
        self.assertRegex(
            response.text, r'name="authorize_automatic_formatting"[^>]*checked'
        )

    def test_required_extension_operator_is_blocked_without_daemon_mutation(self) -> None:
        self.daemon.plan = _plan(
            kind="extend", requires_automatic_format_authorization=True
        )
        with sqlite3.connect(self.store.database) as connection:
            connection.execute(
                "INSERT INTO web_users (login_name,normalized_login,password_hash,role,"
                "lifecycle,credential_generation,created_at,last_login_at,retired_at) "
                "VALUES ('operator','operator','unused','operator','active',1,0,NULL,NULL)"
            )
            connection.commit()
        operator = self.store.get_user_by_login("operator")
        assert operator is not None
        session = self.app.state.session_manager.create(operator)
        self.cookies = (
            f"lto_archiver_session={session.cookie}; "
            f"lto_archiver_csrf={session.csrf_token}"
        )
        page = asyncio.run(self.request("GET", "/jobs/plans/PLAN-1"))
        self.assertEqual(200, page.status_code, page.text)
        self.assertIn("Administrator authorization required", page.text)
        self.assertNotIn('action="/jobs/JOB-1/extend"', page.text)

        response = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/extend",
                data={
                    "csrf": session.csrf_token,
                    "idempotency_key": "operator-crafted-extension",
                    "expected_revision": "4",
                    "plan_id": "PLAN-1",
                    "digest_sha256": "a" * 64,
                    "authorize_automatic_formatting": "on",
                },
            )
        )
        self.assertEqual(403, response.status_code, response.text)
        self.assertEqual([], self.daemon.calls)

    def test_append_only_extension_hides_grant_and_forwards_false(self) -> None:
        self.daemon.plan = JobPlanV1.model_validate(
            {
                **_plan(kind="extend").model_dump(),
                "cassettes": (
                    {
                        "sequence": 1,
                        "physical_label": "AB1234",
                        "bytes": 7,
                        "objects": 2,
                        "allocation_bytes": 8192,
                        "capacity_utilization": 0.1,
                        "format_required": False,
                        "operation": "append",
                    },
                ),
            }
        )
        page = asyncio.run(self.request("GET", "/jobs/plans/PLAN-1"))
        self.assertNotIn('name="authorize_automatic_formatting"', page.text)
        response = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/extend",
                data={
                    "csrf": self.hidden(page, "csrf"),
                    "idempotency_key": "append-without-grant",
                    "expected_revision": "4",
                    "plan_id": "PLAN-1",
                    "digest_sha256": "a" * 64,
                },
            )
        )
        self.assertEqual(303, response.status_code, response.text)
        self.assertIs(False, self.daemon.calls[-1][1][1].authorize_automatic_formatting)

    def test_missing_required_plan_field_is_unavailable_without_extension_form(self) -> None:
        self.daemon.get_job_plan = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            DaemonProtocolError("missing requires_automatic_format_authorization")
        )

        page = asyncio.run(self.request("GET", "/jobs/plans/PLAN-1"))

        self.assertEqual(503, page.status_code, page.text)
        self.assertNotIn('action="/jobs/JOB-1/extend"', page.text)
        self.assertEqual([], self.daemon.calls)

    def test_sequence_authorization_rejects_csrf_and_renders_stale_conflict(self) -> None:
        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        denied = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                data={
                    "csrf": "bad",
                    "idempotency_key": self.hidden(detail, "idempotency_key"),
                    "expected_revision": "4",
                    "layout_fingerprint_sha256": "b" * 64,
                },
            )
        )
        self.assertEqual(403, denied.status_code, denied.text)
        self.assertEqual([], self.daemon.calls)

        self.daemon.mutation_failure = DaemonRequestError(
            409, "automatic_sequence_layout_conflict"
        )
        stale = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                data={
                    "csrf": self.hidden(detail, "csrf"),
                    "idempotency_key": "stale-sequence",
                    "expected_revision": "4",
                    "layout_fingerprint_sha256": "b" * 64,
                },
            )
        )
        self.assertEqual(409, stale.status_code, stale.text)
        self.assertIn("Sequence authority is no longer current", stale.text)

    def test_mixed_version_404_explicitly_hides_sequence_controls(self) -> None:
        self.daemon.get_job_sequence_status = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            DaemonRequestError(404, "not_found")
        )

        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn("until the daemon is upgraded", detail.text)
        self.assertNotIn('name="layout_fingerprint_sha256"', detail.text)
        self.assertNotIn('action="/jobs/JOB-1/automatic-sequence/authorize"', detail.text)
        self.assertNotIn('action="/jobs/JOB-1/start"', detail.text)
        self.assertNotIn('action="/jobs/JOB-1/resume"', detail.text)

    def test_sequence_authorization_rejects_duplicate_and_malformed_authority(self) -> None:
        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        csrf = self.hidden(detail, "csrf")
        key = self.hidden(detail, "idempotency_key")
        invalid_cases = (
            {
                "expected_revision": "not-a-revision",
                "layout_fingerprint_sha256": "b" * 64,
            },
            {"expected_revision": "4", "layout_fingerprint_sha256": "bad"},
        )
        for fields in invalid_cases:
            with self.subTest(fields=fields):
                response = asyncio.run(
                    self.request(
                        "POST",
                        "/jobs/JOB-1/automatic-sequence/authorize",
                        data={"csrf": csrf, "idempotency_key": key, **fields},
                    )
                )
                self.assertEqual(422, response.status_code, response.text)
                self.assertIn("Sequence authorization is no longer current", response.text)
                self.assertEqual([], self.daemon.calls)

        duplicate = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                content=(
                    f"csrf={csrf}&idempotency_key=duplicate-key&expected_revision=4"
                    f"&expected_revision=5&layout_fingerprint_sha256={'b' * 64}"
                ),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        )
        self.assertEqual(422, duplicate.status_code, duplicate.text)
        self.assertEqual([], self.daemon.calls)

    def test_sequence_authorization_replays_one_idempotency_key_and_stale_revision(self) -> None:
        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        form = {
            "csrf": self.hidden(detail, "csrf"),
            "idempotency_key": "same-sequence-key",
            "expected_revision": "4",
            "layout_fingerprint_sha256": "b" * 64,
        }
        first = asyncio.run(
            self.request("POST", "/jobs/JOB-1/automatic-sequence/authorize", data=form)
        )
        replay = asyncio.run(
            self.request("POST", "/jobs/JOB-1/automatic-sequence/authorize", data=form)
        )
        self.assertEqual(303, first.status_code, first.text)
        self.assertEqual(303, replay.status_code, replay.text)
        calls = [call for call in self.daemon.calls if call[0] == "authorize_automatic_sequence"]
        self.assertEqual(["same-sequence-key", "same-sequence-key"], [call[1][2] for call in calls])
        self.assertEqual(1, len(self.daemon.sequence_authorization_mutations))
        self.assertIs(
            self.daemon.sequence_authorization_receipts["same-sequence-key"][1],
            self.daemon.job,
        )

        self.daemon.mutation_failure = DaemonRequestError(
            409, "automatic_sequence_revision_conflict"
        )
        stale = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                data={**form, "idempotency_key": "stale-revision", "expected_revision": "3"},
            )
        )
        self.assertEqual(409, stale.status_code, stale.text)
        self.assertIn("Sequence authority is no longer current", stale.text)

    def test_sequence_authorization_conflict_names_key_and_rotates_retry(self) -> None:
        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        conflicted_key = "conflicted-sequence-key"
        form = {
            "csrf": self.hidden(detail, "csrf"),
            "idempotency_key": conflicted_key,
            "expected_revision": "4",
            "layout_fingerprint_sha256": "b" * 64,
        }
        prior_request = AuthorizeAutomaticSequenceRequestV1(
            expected_revision=3,
            layout_fingerprint_sha256="b" * 64,
            authorize_automatic_formatting=True,
        )
        self.daemon.sequence_authorization_receipts[conflicted_key] = (
            ("JOB-1", prior_request),
            self.daemon.job,
        )

        conflict = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                data=form,
            )
        )

        self.assertEqual(409, conflict.status_code, conflict.text)
        self.assertIn('data-field-error="idempotency_key"', conflict.text)
        self.assertNotIn('data-field-error="state"', conflict.text)
        self.assertNotIn('data-field-error="expected_revision"', conflict.text)
        self.assertNotIn('data-field-error="layout_fingerprint_sha256"', conflict.text)
        self.assertIn("This request key was already used", conflict.text)
        self.assertIn("Submit the authorization again", conflict.text)
        self.assertNotIn("Sequence authority is no longer current", conflict.text)
        self.assertIn('name="expected_revision" value="4"', conflict.text)
        self.assertIn(
            f'name="layout_fingerprint_sha256" value="{"b" * 64}"',
            conflict.text,
        )
        fresh_key = self.hidden(conflict, "idempotency_key")
        self.assertNotEqual(conflicted_key, fresh_key)
        self.assertEqual([], self.daemon.sequence_authorization_mutations)

        retry = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                data={**form, "idempotency_key": fresh_key},
            )
        )
        self.assertEqual(303, retry.status_code, retry.text)
        self.assertEqual(
            fresh_key,
            self.daemon.calls[-1][1][2],
        )
        self.assertEqual(1, len(self.daemon.sequence_authorization_mutations))

    def test_transient_sequence_status_failure_is_not_described_as_upgrade(self) -> None:
        self.daemon.get_job_sequence_status = lambda *_args, **_kwargs: (_ for _ in ()).throw(
            DaemonRequestError(503, "daemon_unavailable")
        )

        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertIn("could not provide cassette-sequence status", detail.text)
        self.assertNotIn("until the daemon is upgraded", detail.text)
        self.assertNotIn("Authorize automatic cassette sequence", detail.text)
        self.assertNotIn('action="/jobs/JOB-1/start"', detail.text)
        self.assertNotIn('action="/jobs/JOB-1/resume"', detail.text)

    def test_operator_is_denied_sequence_authorization_before_daemon_mutation(self) -> None:
        with sqlite3.connect(self.store.database) as connection:
            connection.execute("UPDATE web_users SET role = 'operator' WHERE login_name = 'admin'")
            connection.commit()
        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        denied = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/automatic-sequence/authorize",
                data={
                    "csrf": self.hidden(detail, "csrf"),
                    "idempotency_key": "operator-denied",
                    "expected_revision": "4",
                    "layout_fingerprint_sha256": "b" * 64,
                },
            )
        )
        self.assertEqual(403, denied.status_code, denied.text)
        self.assertEqual([], self.daemon.calls)

    def test_native_commands_omit_label_and_imported_commands_retain_it(self) -> None:
        self.daemon.sequence_status = {
            **self.daemon.sequence_status,
            "authorization_state": "authorized",
        }
        self.daemon.job = self.daemon.job.model_copy(
            update={
                "resumable": True,
                "capabilities": self.daemon.job.capabilities.model_copy(
                    update={"resume": True}
                ),
            }
        )
        native = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        self.assertNotIn('name="format_confirmation_label"', native.text)
        for action in ("start", "resume"):
            response = asyncio.run(
                self.request(
                    "POST",
                    f"/jobs/JOB-1/{action}",
                    data={
                        "csrf": self.hidden(native, "csrf"),
                        "idempotency_key": f"native-{action}",
                    },
                )
            )
            self.assertEqual(303, response.status_code, response.text)
        self.assertIsNone(self.daemon.calls[-2][1][1].format_confirmation_label)
        self.assertIsNone(self.daemon.calls[-1][1][1].format_confirmation_label)

        self.daemon.job = self.daemon.job.model_copy(update={"imported": True})
        imported = asyncio.run(self.request("GET", "/jobs/JOB-1"))
        self.assertIn('name="format_confirmation_label"', imported.text)
        response = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/start",
                data={
                    "csrf": self.hidden(imported, "csrf"),
                    "idempotency_key": "imported-start",
                    "format_confirmation_label": "AB1234",
                },
            )
        )
        self.assertEqual(303, response.status_code, response.text)
        self.assertEqual("AB1234", self.daemon.calls[-1][1][1].format_confirmation_label)
        resumed = asyncio.run(
            self.request(
                "POST",
                "/jobs/JOB-1/resume",
                data={
                    "csrf": self.hidden(imported, "csrf"),
                    "idempotency_key": "imported-resume",
                    "format_confirmation_label": "AB1234",
                },
            )
        )
        self.assertEqual(303, resumed.status_code, resumed.text)
        self.assertEqual("AB1234", self.daemon.calls[-1][1][1].format_confirmation_label)

    def test_active_native_operation_hides_duplicate_resume_action(self) -> None:
        """A redirected job page must not offer Resume for its running operation."""

        from tests.web.test_dashboard import authoritative_status

        self.daemon.sequence_status = {
            **self.daemon.sequence_status,
            "authorization_state": "authorized",
        }
        self.daemon.job = self.daemon.job.model_copy(
            update={
                "resumable": True,
                "capabilities": self.daemon.job.capabilities.model_copy(
                    update={"resume": True}
                ),
            }
        )
        status = authoritative_status()
        active = status.model_copy(
            update={
                "job": status.job.model_copy(update={"id": "JOB-1"}),
                "operation": status.operation.model_copy(
                    update={"kind": "archive.native", "job_id": "JOB-1"}
                ),
            }
        )
        original_get = self.daemon.get

        def get(path: str, **kwargs):
            if path == "/api/v1/status":
                return active
            return original_get(path, **kwargs)

        self.daemon.get = get

        detail = asyncio.run(self.request("GET", "/jobs/JOB-1"))

        self.assertEqual(200, detail.status_code, detail.text)
        self.assertNotIn('action="/jobs/JOB-1/resume"', detail.text)
        self.assertIn("already running", detail.text)


if __name__ == "__main__":
    unittest.main()
