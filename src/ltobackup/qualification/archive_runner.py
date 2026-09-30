"""Isolated physical qualification for the production archive runner path."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import secrets
import sqlite3
import stat
import sys
import uuid
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Protocol

from ltobackup.broker.client import UnixBrokeredCgroupScopeApi
from ltobackup.catalog import Catalog
from ltobackup.daemon.archive_runner import ArchiveRunner
from ltobackup.daemon.archive_runtime import (
    BrokeredLtfsInfoMediaIdentityProbe,
    _production_supervisor,
    load_broker_capability,
)
from ltobackup.daemon.backups import BackupManager
from ltobackup.daemon.frozen_job import FrozenJobPlan
from ltobackup.daemon.models import (
    HardwareTargetBinding,
    OperationFence,
    OperationRecord,
    cutover_catalog_binding_sha256,
    media_identity_sha256,
)
from ltobackup.daemon.operations import OperationContext
from ltobackup.daemon.restore_destination import RestoreDestinationVerifier
from ltobackup.daemon.restore_runner import RestoreCassetteRunner
from ltobackup.linux_settings import LinuxSettings, load_linux_settings
from ltobackup.migration.validator import (
    MigrationValidator,
    canonical_cassette_plan_sha256,
)
from ltobackup.operational_log import (
    JournalOperationalEventSink,
    NullOperationalEventSink,
    OperationalEvent,
    OperationalEventSink,
    OperationalSeverity,
    OperationalSource,
    closed_operational_correlation,
)
from ltobackup.settings import Settings
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupExecutionScopeManager,
    CommandFailed,
    CompletedCommand,
    ReadOnlyCgroupPrivilegeBoundary,
)
from ltobackup.tape.linux_ltfs import (
    LinuxLtfsBackend,
    MediaIdentityError,
    SysfsDeviceIdentityProvider,
)
from ltobackup.tape.models import ExpectedMedia, MediaIdentity, MountedTape

_JOB_ID = "QUAL-ARCHIVE-RUNNER"
_LIBRARY_ID = "QUALIFICATION"
_CASSETTE_SEQUENCE = 4
_APPROVED_MAM_VOLUME_SERIAL = "Q210531120"
_FIXED_MTIME_NS = 1_700_000_000_000_000_000
_PRODUCTION_STATE = Path("/var/lib/lto-archiver")
_MAX_JSON_BYTES = 64 * 1024
_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
_PAYLOADS = (
    ("alpha.txt", b"lto-archive-runner-qualification-v1\n"),
    ("nested/pattern.bin", bytes(range(32))),
)
_MANIFEST_KEYS = frozenset(
    {
        "library_id",
        "relative_path",
        "tape_relative_path",
        "size",
        "mtime_ns",
        "sha256",
    }
)
_BLOCK_KEYS = frozenset(
    {
        "block_id",
        "library_id",
        "tape_id",
        "completed_at",
        "file_count",
        "total_bytes",
        "format",
        "copy_mode",
        "sha256_recorded_during_source_stream",
    }
)


class QualificationArchiveRefused(RuntimeError):
    """The physical archive qualification cannot produce unambiguous proof."""


@dataclass(frozen=True, slots=True)
class QualificationArchiveEvidence:
    run_id: str
    physical_label: str
    volume_uuid: str
    file_count: int
    payload_sha256: tuple[tuple[str, str], ...]
    manifest_sha256: str
    block_sha256: str
    catalog_snapshot_sha256: str
    evidence_sha256: str
    catalog_path: Path
    evidence_path: Path
    readback_release_receipt_sha256: str
    restore: QualificationRestoreEvidence | None = None


@dataclass(frozen=True, slots=True)
class QualificationRestoreEvidence:
    plan_id: str
    run_id: str
    operation_id: str
    plan_fingerprint_sha256: str
    physical_label: str
    ltfs_volume_label: str
    volume_serial: str
    volume_uuid: str
    file_version_ids: tuple[int, ...]
    item_states: tuple[str, ...]
    destination_sha256: tuple[tuple[str, int, str, str], ...]
    restored_files: int
    skipped_files: int
    verified_bytes: int
    release_boundary: str
    unload_command_id: str
    no_medium_proven: bool
    release_receipt_sha256: str


@dataclass(frozen=True, slots=True)
class _PreparedRun:
    run_id: str
    root: Path
    catalog_path: Path
    source_root: Path
    evidence_path: Path
    expected: ExpectedMedia
    target: HardwareTargetBinding
    context: OperationContext
    cutover_credential: str


@dataclass(frozen=True, slots=True)
class _CommittedArchiveProof:
    block_id: str
    tape_id: str
    physical_label: str
    ltfs_volume_label: str
    volume_serial: str
    volume_uuid: str
    observed_media_identity_sha256: str
    archive_started_at: datetime
    committed_at: datetime


class _QualificationLinuxLtfsBackend(LinuxLtfsBackend):
    """Production backend with the approved destructive cassette pinned at probe."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self._physical_unload_complete = False

    def identify_preformat(self) -> MediaIdentity:
        identity = super().identify_preformat()
        if (
            identity.mam_barcode != "TAPE04"
            or identity.mam_volume_serial != _APPROVED_MAM_VOLUME_SERIAL
        ):
            self._preformat_media_snapshot = None
            raise MediaIdentityError()
        return identity

    def format(self, expected: ExpectedMedia) -> None:
        snapshot = self._preformat_media_snapshot
        if snapshot is None or (
            snapshot[0].mam_barcode != "TAPE04"
            or snapshot[0].mam_volume_serial != _APPROVED_MAM_VOLUME_SERIAL
        ):
            raise MediaIdentityError()
        super().format(expected)

    @property
    def qualification_physical_unload_complete(self) -> bool:
        return self._physical_unload_complete

    def unload(self) -> CompletedCommand | None:
        if self._physical_unload_complete:
            raise QualificationArchiveRefused(
                "qualification final eject was already dispatched"
            )
        return super().unload()


class _Backend(Protocol):
    expected: ExpectedMedia
    fence: OperationFence
    qualification_physical_unload_complete: bool
    media_identity_probe: object

    def wait_for_media(
        self, expected: ExpectedMedia, stop_requested: Callable[[], bool]
    ) -> bool: ...

    def identify(self) -> MediaIdentity: ...

    def mount(self, *, read_only: bool) -> MountedTape: ...

    def unmount(self, mounted: MountedTape, observer: object) -> object: ...

    def unload(self) -> CompletedCommand | None: ...


class _UnmountObserver:
    def finalization_started(self) -> None:
        return None

    def mount_release_started(self) -> None:
        return None


def _qualification_eject_proven(backend: _Backend) -> bool:
    try:
        backend.media_identity_probe.identify_unmounted()
    except BaseException as exc:  # noqa: BLE001 - exact closed terminal oracle.
        proven = (
            type(exc) is CommandFailed
            and exc.kind == "probe_media"
            and exc.returncode == 3
        )
        if proven and hasattr(backend, "_physical_unload_complete"):
            backend._physical_unload_complete = True
        return proven
    return False


class ArchiveRunnerPhysicalQualification:
    """Run one bounded archive/write/readback cycle in a fresh state tree.

    Physical dependencies are supplied by the installed runtime.  A production
    caller supplies factories returning ``LinuxLtfsBackend`` instances backed by
    the authenticated command broker.  Tests replace only that hardware edge.
    """

    def __init__(
        self,
        *,
        state_root: Path,
        expected_label: str,
        target_factory: Callable[[ExpectedMedia], HardwareTargetBinding],
        backend_factory: Callable[..., _Backend],
        runner_factory: Callable[..., ArchiveRunner] = ArchiveRunner,
        enable_restore_qualification: bool = False,
        restore_runner_factory: Callable[..., RestoreCassetteRunner] = RestoreCassetteRunner,
        run_id_factory: Callable[[], str] = lambda: str(uuid.uuid4()),
        buffer_bytes: int = 1024 * 1024,
        event_sink: OperationalEventSink | None = None,
    ) -> None:
        self._state_root = Path(state_root)
        self._expected_label = expected_label
        self._target_factory = target_factory
        self._backend_factory = backend_factory
        self._runner_factory = runner_factory
        self._enable_restore_qualification = enable_restore_qualification
        self._restore_runner_factory = restore_runner_factory
        self._run_id_factory = run_id_factory
        self._buffer_bytes = buffer_bytes
        self._event_sink = event_sink or NullOperationalEventSink()

    def run(self) -> QualificationArchiveEvidence:
        self._validate_configuration()
        prepared = self._prepare()
        archive_backend = self._backend(
            prepared,
            prepared.context,
            expected=prepared.expected,
            readback=False,
        )
        runner = self._runner_factory(
            catalog_factory=lambda: Catalog(prepared.catalog_path),
            backups=BackupManager(
                prepared.catalog_path, prepared.root / "backups", retention=2
            ),
            backend=archive_backend,
            host_staging_root=prepared.root / "archive-staging",
            buffer_bytes=self._buffer_bytes,
            event_sink=self._event_sink,
        )
        outcome = runner.resume(_JOB_ID, prepared.context, lambda: False)
        if outcome.state != "succeeded" or outcome.sequence != _CASSETTE_SEQUENCE:
            raise QualificationArchiveRefused(
                "production archive runner did not complete qualification"
            )
        with Catalog(prepared.catalog_path) as catalog:
            catalog.finish_operation(prepared.context.fence, "succeeded")
        committed = self._committed_archive_proof(prepared)
        readback_expected = ExpectedMedia(
            "tape.qualification-readback",
            _JOB_ID,
            _CASSETTE_SEQUENCE,
            committed.physical_label,
            committed.volume_serial,
            committed.volume_uuid,
        )
        readback_target = self._target_factory(readback_expected)
        if type(readback_target) is not HardwareTargetBinding:
            raise QualificationArchiveRefused(
                "qualification readback hardware target is invalid"
            )
        readback_context = self._admit_readback(prepared, readback_target)
        readback_backend = self._backend(
            prepared,
            readback_context,
            expected=readback_expected,
            readback=True,
        )
        mounted: MountedTape | None = None
        unmounted = False
        media_admitted = False
        readback_release_receipt_sha256: str | None = None
        try:
            try:
                if not readback_backend.wait_for_media(
                    readback_expected, lambda: False
                ):
                    raise QualificationArchiveRefused(
                        "qualification media reinsertion is unavailable"
                    )
                media_admitted = True
                identity = readback_backend.identify()
                self._require_identity(identity, committed)
                mounted = readback_backend.mount(read_only=True)
                if mounted.read_only is not True:
                    raise QualificationArchiveRefused(
                        "qualification readback mount is not read-only"
                    )
                proof, readback_records = self._verify_readback(
                    mounted.path, committed
                )
            finally:
                if mounted is not None:
                    try:
                        readback_backend.unmount(mounted, _UnmountObserver())
                        unmounted = True
                    finally:
                        if unmounted:
                            readback_backend.unload()
                            if not _qualification_eject_proven(readback_backend):
                                raise QualificationArchiveRefused(
                                    "qualification readback eject is ambiguous"
                                )
                            with Catalog(prepared.catalog_path) as catalog:
                                readback_release_receipt_sha256 = (
                                    catalog.attest_qualification_readback_eject(
                                        readback_context.fence
                                    )
                                )
                elif media_admitted:
                    readback_backend.unload()
                    if not _qualification_eject_proven(readback_backend):
                        raise QualificationArchiveRefused(
                            "qualification readback eject is ambiguous"
                        )
                    with Catalog(prepared.catalog_path) as catalog:
                        readback_release_receipt_sha256 = (
                            catalog.attest_qualification_readback_eject(
                                readback_context.fence
                            )
                        )
        except BaseException:
            with Catalog(prepared.catalog_path) as catalog:
                operation = catalog.get_operation(readback_context.record.id)
                if operation is not None and operation["state"] == "running":
                    catalog.finish_operation(
                        readback_context.fence,
                        "recovery_required",
                        error_class="operator_required",
                        error_code="recovery_required",
                    )
            raise
        if readback_release_receipt_sha256 is None:
            raise QualificationArchiveRefused(
                "qualification readback eject proof is unavailable"
            )
        with Catalog(prepared.catalog_path) as catalog:
            catalog.finish_operation(readback_context.fence, "succeeded")
        restore = None
        if self._enable_restore_qualification:
            restore = self._run_restore_qualification(
                prepared,
                committed,
                readback_records,
            )
        proof["readback_release_receipt_sha256"] = (
            readback_release_receipt_sha256
        )
        return self._write_evidence(prepared, identity, proof, restore)

    def _run_restore_qualification(
        self,
        prepared: _PreparedRun,
        committed: _CommittedArchiveProof,
        readback_records: tuple[tuple[str, str, str, int, int, str], ...],
    ) -> QualificationRestoreEvidence:
        """Restore the committed proof through the production cassette runner.

        This opt-in stage deliberately starts only after the independent archive
        readback has unmounted and ejected the cartridge.  Reinsertion remains
        an operator action handled by ``wait_for_media``; the stage never loads
        media or exposes a destructive tape action.
        """

        destination_anchor = prepared.root / "restore-destination"
        destination_root = destination_anchor / "selection"
        try:
            destination_root.mkdir(mode=0o700, parents=True)
            destination_anchor.chmod(0o700)
            destination_root.chmod(0o700)
        except OSError:
            raise QualificationArchiveRefused(
                "qualification restore destination is unavailable"
            ) from None
        with Catalog(prepared.catalog_path) as catalog:
            rows = catalog.connection.execute(
                "SELECT id,library_id,relative_path,tape_relative_path,size,mtime_ns,"
                "sha256 FROM file_versions "
                "WHERE block_id=? AND tape_id=? ORDER BY id",
                (committed.block_id, committed.tape_id),
            ).fetchall()
            observed_records = tuple(
                (
                    str(row["library_id"]),
                    str(row["relative_path"]),
                    str(row["tape_relative_path"]),
                    int(row["size"]),
                    int(row["mtime_ns"]),
                    str(row["sha256"]),
                )
                for row in rows
            )
            if (
                len(rows) != len(_PAYLOADS)
                or len(rows) < 2
                or tuple(sorted(observed_records))
                != tuple(sorted(readback_records))
            ):
                raise QualificationArchiveRefused(
                    "qualification restore selection is incomplete"
                )
            version_ids = tuple(int(row["id"]) for row in rows)
            first = rows[0]
            matching = (
                destination_root / str(first["library_id"]) / str(first["relative_path"])
            )
            matching.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            source = prepared.source_root / str(first["relative_path"])
            matching.write_bytes(source.read_bytes())
            matching.chmod(0o600)
            plan = catalog.create_restore_plan(
                version_ids,
                str(destination_root),
                actor="qualification",
                idempotency_key=f"qualification-restore-plan-{prepared.run_id}",
                request_sha256=hashlib.sha256(
                    b"qualification-restore-plan/v1\0"
                    + prepared.run_id.encode("ascii")
                ).hexdigest(),
                destination_kind="local",
                destination_anchor=str(destination_anchor),
            )
            restore_run = catalog.create_restore_run(
                str(plan["id"]),
                actor="qualification",
                idempotency_key=f"qualification-restore-run-{prepared.run_id}",
                request_sha256=hashlib.sha256(
                    b"qualification-restore-run/v1\0"
                    + prepared.run_id.encode("ascii")
                ).hexdigest(),
            )
            cassette = catalog.next_restore_cassette(str(restore_run["id"]))
            owner = catalog.current_daemon_fence()
            if cassette is None or owner is None or int(cassette["sequence"]) != 1:
                raise QualificationArchiveRefused(
                    "qualification restore cassette is unavailable"
                )
            expected = ExpectedMedia(
                "restore.cassette",
                str(restore_run["id"]),
                1,
                str(cassette["physical_label"]),
                str(cassette["volume_serial"]),
                str(cassette["volume_uuid"]),
            )
            target = self._target_factory(expected)
            if type(target) is not HardwareTargetBinding:
                raise QualificationArchiveRefused(
                    "qualification restore hardware target is invalid"
                )
            record = OperationRecord(
                f"qualification-restore-{prepared.run_id}",
                "restore.cassette",
                "running",
                None,
                f"qualification-restore-{prepared.run_id}",
                "qualification",
                str(restore_run["id"]),
                1,
                datetime.now(UTC).isoformat(timespec="microseconds"),
                None,
            )
            admitted = catalog.admit_operation(
                record,
                owner,
                admission_open=True,
                hardware_target=target,
            ).record
        context = OperationContext(
            admitted,
            OperationFence(admitted.id, owner.generation),
            lambda: Catalog(prepared.catalog_path),
        )

        restore_backends: list[_Backend] = []

        def backend_factory(expected: ExpectedMedia, fence: OperationFence) -> _Backend:
            if fence != context.fence:
                raise QualificationArchiveRefused(
                    "qualification restore fence is invalid"
                )
            backend = self._backend(
                prepared,
                context,
                expected=expected,
                readback=True,
            )
            restore_backends.append(backend)
            return backend

        runner = self._restore_runner_factory(
            catalog_factory=lambda: Catalog(prepared.catalog_path),
            backend_factory=backend_factory,
            destination_verifier=RestoreDestinationVerifier(),
            event_sink=self._event_sink,
        )
        outcome = runner.run(str(restore_run["id"]), context, lambda: False)
        if (
            outcome.state != "succeeded"
            or outcome.next_state != "completed"
            or len(restore_backends) != 1
            or getattr(
                restore_backends[0],
                "qualification_physical_unload_complete",
                False,
            )
            is not True
        ):
            raise QualificationArchiveRefused(
                "production restore runner did not complete qualification"
            )
        with Catalog(prepared.catalog_path) as catalog:
            catalog.finish_operation(context.fence, "succeeded")
            durable = catalog.restore_run(str(restore_run["id"]))
            receipt = catalog.connection.execute(
                "SELECT boundary,item_checkpoint_sha256,mount_receipt_sha256,"
                "unmount_receipt_sha256,unload_command_id FROM "
                "restore_release_receipts WHERE operation_id=?",
                (context.fence.operation_id,),
            ).fetchone()
            if receipt is None:
                raise QualificationArchiveRefused(
                    "qualification restore release receipt is unavailable"
                )
            boundary = catalog.restore_release_boundary(
                context.fence.operation_id,
                str(restore_run["id"]),
                1,
                str(durable["plan_fingerprint_sha256"]),
            )
        items = tuple(durable["items"])
        states = tuple(str(item["state"]) for item in items)
        if (
            durable["state"] != "completed"
            or len(items) < 2
            or states.count("skipped_verified") < 1
            or any(state not in {"restored", "skipped_verified"} for state in states)
            or boundary != "post_eject"
        ):
            raise QualificationArchiveRefused(
                "qualification restore durable result is incomplete"
            )
        destination_hashes: list[tuple[str, int, str, str]] = []
        verified_bytes = 0
        for item in items:
            plan_item = item["plan_item"]
            relative = str(
                PurePosixPath(str(plan_item["library_id"]))
                / str(plan_item["relative_path"])
            )
            digest = self._hash_regular(
                destination_root / relative,
                int(plan_item["size"]),
            )
            if digest != plan_item["sha256"]:
                raise QualificationArchiveRefused(
                    "qualification restored destination digest mismatch"
                )
            destination_hashes.append(
                (relative, int(plan_item["size"]), str(plan_item["sha256"]), digest)
            )
            verified_bytes += int(plan_item["size"])
        receipt_body = {
            key: receipt[key]
            for key in (
                "boundary",
                "item_checkpoint_sha256",
                "mount_receipt_sha256",
                "unmount_receipt_sha256",
                "unload_command_id",
            )
        }
        receipt_sha256 = hashlib.sha256(
            json.dumps(
                receipt_body,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
        return QualificationRestoreEvidence(
            plan_id=str(plan["id"]),
            run_id=str(restore_run["id"]),
            operation_id=context.fence.operation_id,
            plan_fingerprint_sha256=str(durable["plan_fingerprint_sha256"]),
            physical_label=str(cassette["physical_label"]),
            ltfs_volume_label=str(cassette["volume_label"]),
            volume_serial=str(cassette["volume_serial"]),
            volume_uuid=str(cassette["volume_uuid"]),
            file_version_ids=version_ids,
            item_states=states,
            destination_sha256=tuple(destination_hashes),
            restored_files=outcome.restored_files,
            skipped_files=outcome.skipped_files,
            verified_bytes=verified_bytes,
            release_boundary=boundary,
            unload_command_id=str(receipt["unload_command_id"]),
            no_medium_proven=True,
            release_receipt_sha256=receipt_sha256,
        )

    def _validate_configuration(self) -> None:
        resolved = self._state_root.resolve(strict=False)
        if (
            not self._state_root.is_absolute()
            or resolved == _PRODUCTION_STATE
            or _PRODUCTION_STATE in resolved.parents
        ):
            raise QualificationArchiveRefused(
                "qualification state overlaps the production catalog namespace"
            )
        if self._state_root.exists():
            try:
                status = self._state_root.stat(follow_symlinks=False)
            except OSError:
                raise QualificationArchiveRefused(
                    "qualification state root is not private"
                ) from None
            if (
                self._state_root.is_symlink()
                or not stat.S_ISDIR(status.st_mode)
                or stat.S_IMODE(status.st_mode) != 0o700
                or status.st_uid != os.geteuid()
                or status.st_gid != os.getegid()
            ):
                raise QualificationArchiveRefused(
                    "qualification state root is not private"
                )
        if type(self._expected_label) is not str or self._expected_label != "TAPE04":
            raise QualificationArchiveRefused(
                "archive qualification requires expected label TAPE04"
            )
        if (
            not callable(self._target_factory)
            or not callable(self._backend_factory)
            or not callable(self._runner_factory)
            or type(self._enable_restore_qualification) is not bool
            or not callable(self._restore_runner_factory)
            or not callable(self._run_id_factory)
            or type(self._buffer_bytes) is not int
            or self._buffer_bytes <= 0
        ):
            raise QualificationArchiveRefused(
                "archive qualification configuration is invalid"
            )

    def _prepare(self) -> _PreparedRun:
        try:
            run_id = self._run_id_factory()
            parsed = uuid.UUID(run_id)
            if parsed.version != 4 or str(parsed) != run_id:
                raise ValueError
            self._state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
            state_status = self._state_root.stat(follow_symlinks=False)
            if not stat.S_ISDIR(state_status.st_mode) or self._state_root.is_symlink():
                raise OSError
            root = self._state_root / run_id
            root.mkdir(mode=0o700)
        except (OSError, TypeError, ValueError):
            raise QualificationArchiveRefused(
                "qualification run state is unavailable or already exists"
            ) from None
        source_root = root / "source"
        source_root.mkdir(mode=0o700)
        for relative_path, payload in _PAYLOADS:
            destination = source_root / relative_path
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_bytes(payload)
            os.utime(destination, ns=(_FIXED_MTIME_NS, _FIXED_MTIME_NS))
        catalog_path = root / "catalog.sqlite3"
        self._seed_catalog(catalog_path, source_root)
        expected = ExpectedMedia(
            "archive.resume",
            _JOB_ID,
            _CASSETTE_SEQUENCE,
            self._expected_label,
            None,
            None,
        )
        target = self._target_factory(expected)
        if type(target) is not HardwareTargetBinding:
            raise QualificationArchiveRefused(
                "qualification hardware target is invalid"
            )
        cutover = secrets.token_hex(32)
        with Catalog(catalog_path) as catalog:
            plan = FrozenJobPlan.load(catalog, _JOB_ID)
            policy = catalog.get_import_policy(_JOB_ID)
            if policy is None:
                raise QualificationArchiveRefused(
                    "qualification catalog policy is unavailable"
                )
            owner = catalog.claim_daemon_owner("qualification-daemon")
            authorization = OperationRecord(
                f"qualification-cutover-{run_id}",
                "cutover.authorize",
                "running",
                None,
                f"qualification-cutover-{run_id}",
                "qualification",
                _JOB_ID,
                _CASSETTE_SEQUENCE,
                datetime.now(UTC).isoformat(timespec="microseconds"),
                None,
            )
            catalog.register_cutover_authorization(
                authorization,
                owner,
                admission_open=True,
                credential_sha256=hashlib.sha256(cutover.encode("ascii")).hexdigest(),
                bundle_sha256=policy.bundle_sha256,
                catalog_binding_sha256=cutover_catalog_binding_sha256(
                    _JOB_ID,
                    policy.bundle_sha256,
                    policy.assignment_sha256,
                    policy.cassette_plan_sha256,
                    policy.completed_evidence_sha256,
                    self._expected_label,
                ),
                assignment_sha256=policy.assignment_sha256,
                expected_label=self._expected_label,
                host_id="qualification-host",
                drive_serial_sha256=target.tape_device_identity_sha256,
                expires_at=(datetime.now(UTC) + timedelta(minutes=30)).isoformat(
                    timespec="microseconds"
                ),
            )
            record = OperationRecord(
                f"qualification-archive-{run_id}",
                "archive.resume",
                "running",
                None,
                f"qualification-archive-{run_id}",
                "qualification",
                _JOB_ID,
                _CASSETTE_SEQUENCE,
                datetime.now(UTC).isoformat(timespec="microseconds"),
                None,
            )
            admitted = catalog.admit_operation(
                record,
                owner,
                admission_open=True,
                hardware_target=target,
                cutover_credential=cutover,
                caller_peer_kind="local_admin",
                current_host_id="qualification-host",
                format_confirmation_label=(
                    self._expected_label
                    if plan.next_cassette().operation == "format"
                    else None
                ),
            ).record
        context = OperationContext(
            admitted,
            OperationFence(admitted.id, owner.generation),
            lambda: Catalog(catalog_path),
        )
        return _PreparedRun(
            run_id,
            root,
            catalog_path,
            source_root,
            root / "evidence.json",
            expected,
            target,
            context,
            cutover,
        )

    @staticmethod
    def _seed_catalog(catalog_path: Path, source_root: Path) -> None:
        with Catalog(catalog_path) as catalog:
            catalog.initialize()
            catalog.import_application_settings_once(
                Settings(), legacy_source_sha256=None
            )
            catalog.add_library(_LIBRARY_ID, "Qualification", str(source_root))
            cassettes = [
                (
                    "TAPE04" if sequence == 4 else f"TAPE{sequence:02d}",
                    (
                        _APPROVED_MAM_VOLUME_SERIAL
                        if sequence == 4
                        else f"SERIAL{sequence:02d}"
                    ),
                    len(_PAYLOADS) if sequence == 4 else 1,
                    (
                        sum(len(payload) for _, payload in _PAYLOADS)
                        if sequence == 4
                        else sequence
                    ),
                )
                for sequence in range(1, 21)
            ]
            catalog.create_automatic_job(
                _JOB_ID,
                _LIBRARY_ID,
                "qualification-drive",
                "/qualification/mount",
                cassettes,
                force_format=True,
            )
            for sequence in range(1, 21):
                if sequence == _CASSETTE_SEQUENCE:
                    manifest = [
                        (
                            _LIBRARY_ID,
                            relative_path,
                            len(payload),
                            _FIXED_MTIME_NS,
                        )
                        for relative_path, payload in _PAYLOADS
                    ]
                else:
                    manifest = [
                        (
                            _LIBRARY_ID,
                            f"cassette-{sequence}/file-1.bin",
                            sequence,
                            sequence,
                        )
                    ]
                catalog.replace_automatic_cassette_manifest(
                    _JOB_ID,
                    sequence,
                    manifest,
                )
            for sequence in range(1, 4):
                tape_id = f"TAPE{sequence:02d}"
                block_id = f"BLOCK{sequence:02d}"
                catalog.register_tape(
                    tape_id,
                    f"SERIAL{sequence:02d}",
                    tape_id,
                    "LTFS",
                    "/qualification/history",
                    cassette_number=tape_id,
                )
                catalog.create_block(
                    block_id, _LIBRARY_ID, tape_id, "archive", 1, sequence
                )
                catalog.record_file_version(
                    _LIBRARY_ID,
                    block_id,
                    tape_id,
                    f"cassette-{sequence}/file-1.bin",
                    f"archive/files/cassette-{sequence}/file-1.bin",
                    sequence,
                    sequence,
                    f"{sequence + 1:064x}",
                )
                catalog.complete_block(block_id)
                catalog.update_automatic_cassette(
                    _JOB_ID,
                    sequence,
                    "completed",
                    tape_id=tape_id,
                    block_id=block_id,
                    copied_files=1,
                    copied_bytes=sequence,
                )
            # Use the same bounded catalog identity that restore plans accept;
            # the physical label/serial/UUID remain independently verified.
            catalog.register_tape(
                "qualification-tape",
                _APPROVED_MAM_VOLUME_SERIAL,
                "TAPE04",
                "LTFS",
                "/qualification/pending",
                cassette_number="TAPE04",
            )
            catalog.update_automatic_job(
                _JOB_ID, "waiting_media", current_sequence=_CASSETTE_SEQUENCE
            )
            report = MigrationValidator.inspect(catalog, _JOB_ID)
            report.require_valid()
            catalog.freeze_imported_job(
                _JOB_ID,
                report.assignment_sha256,
                canonical_cassette_plan_sha256(
                    catalog.connection,
                    _JOB_ID,
                    assignment_sha256=report.assignment_sha256,
                ),
                hashlib.sha256(b"archive-runner-qualification-bundle-v1").hexdigest(),
            )

    @staticmethod
    def _committed_archive_proof(
        prepared: _PreparedRun,
    ) -> _CommittedArchiveProof:
        failure = "qualification committed archive proof is unavailable"
        try:
            with Catalog(prepared.catalog_path) as catalog:
                rows = catalog.connection.execute(
                    "SELECT receipt.operation_id,receipt.owner_generation,"
                    "operation.kind AS operation_kind,operation.state AS operation_state,"
                    "operation.started_at AS operation_started_at,"
                    "receipt.tape_id AS receipt_tape_id,receipt.block_ids_json,"
                    "receipt.observed_media_identity_sha256 AS receipt_media_sha256,"
                    "receipt.terminal_sha256 AS receipt_terminal_sha256,"
                    "receipt.committed_at AS receipt_committed_at,"
                    "terminal.volume_uuid,terminal.observed_volume_label,"
                    "terminal.observed_media_identity_sha256 AS terminal_media_sha256,"
                    "terminal.terminal_sha256,tape.id AS tape_id,"
                    "tape.cassette_number,tape.volume_serial,tape.volume_label,"
                    "tape.filesystem,cassette.physical_label,cassette.status AS cassette_status,"
                    "cassette.tape_id AS cassette_tape_id,cassette.block_id AS cassette_block_id,"
                    "cassette.completed_at AS cassette_completed_at,block.id AS block_id,"
                    "block.library_id,block.tape_id AS block_tape_id,"
                    "block.tape_relative_root,block.status AS block_status,block.visible,"
                    "block.completed_at AS block_completed_at "
                    "FROM imported_cassette_commit_receipts AS receipt "
                    "JOIN daemon_operations AS operation ON operation.id=receipt.operation_id "
                    "JOIN ltfs_terminal_receipts AS terminal "
                    "ON terminal.operation_id=receipt.operation_id "
                    "AND terminal.owner_generation=receipt.owner_generation "
                    "JOIN automatic_cassettes AS cassette "
                    "ON cassette.job_id=receipt.job_id AND cassette.sequence=receipt.sequence "
                    "JOIN blocks AS block ON block.id=cassette.block_id "
                    "JOIN tapes AS tape ON tape.id=cassette.tape_id "
                    "WHERE receipt.job_id=? AND receipt.sequence=?",
                    (_JOB_ID, _CASSETTE_SEQUENCE),
                ).fetchall()
            if len(rows) != 1:
                raise ValueError
            row = rows[0]
            block_ids = json.loads(row["block_ids_json"])
            archive_started_at = datetime.fromisoformat(row["operation_started_at"])
            committed_at = datetime.fromisoformat(row["receipt_committed_at"])
            volume_uuid = str(uuid.UUID(row["volume_uuid"]))
            block_id = row["block_id"]
            tape_id = row["tape_id"]
            if (
                type(block_ids) is not list
                or block_ids != [block_id]
                or row["operation_id"] != prepared.context.fence.operation_id
                or row["owner_generation"] != prepared.context.fence.owner_generation
                or row["operation_kind"] != "archive.resume"
                or row["operation_state"] != "succeeded"
                or archive_started_at.tzinfo is None
                or archive_started_at.utcoffset() != timedelta(0)
                or committed_at.tzinfo is None
                or committed_at.utcoffset() != timedelta(0)
                or volume_uuid != row["volume_uuid"]
                or row["receipt_tape_id"] != tape_id
                or row["cassette_tape_id"] != tape_id
                or row["block_tape_id"] != tape_id
                or row["cassette_block_id"] != block_id
                or row["cassette_status"] != "completed"
                or row["block_status"] != "completed"
                or row["visible"] != 1
                or row["library_id"] != _LIBRARY_ID
                or row["tape_relative_root"]
                != f"libraries/{_LIBRARY_ID}/blocks/{block_id}"
                or row["cassette_completed_at"] != row["receipt_committed_at"]
                or row["block_completed_at"] != row["receipt_committed_at"]
                or row["physical_label"] != "TAPE04"
                or row["cassette_number"] != "TAPE04"
                or not isinstance(row["volume_label"], str)
                or not row["volume_label"]
                or row["volume_serial"] != _APPROVED_MAM_VOLUME_SERIAL
                or row["filesystem"] != "LTFS"
                or row["observed_volume_label"] != row["volume_label"]
                or row["receipt_terminal_sha256"] != row["terminal_sha256"]
                or row["receipt_media_sha256"] != row["terminal_media_sha256"]
            ):
                raise ValueError
            return _CommittedArchiveProof(
                block_id=block_id,
                tape_id=tape_id,
                physical_label="TAPE04",
                ltfs_volume_label=str(row["volume_label"]),
                volume_serial=_APPROVED_MAM_VOLUME_SERIAL,
                volume_uuid=volume_uuid,
                observed_media_identity_sha256=row["receipt_media_sha256"],
                archive_started_at=archive_started_at,
                committed_at=committed_at,
            )
        except (
            AttributeError,
            json.JSONDecodeError,
            sqlite3.DatabaseError,
            TypeError,
            ValueError,
        ):
            raise QualificationArchiveRefused(failure) from None

    def _admit_readback(
        self,
        prepared: _PreparedRun,
        target: HardwareTargetBinding,
    ) -> OperationContext:
        with Catalog(prepared.catalog_path) as catalog:
            owner = catalog.current_daemon_fence()
            if owner is None:
                raise QualificationArchiveRefused(
                    "qualification daemon fence is unavailable"
                )
            record = OperationRecord(
                f"qualification-readback-{prepared.run_id}",
                "tape.qualification-readback",
                "running",
                None,
                f"qualification-readback-{prepared.run_id}",
                "qualification",
                _JOB_ID,
                _CASSETTE_SEQUENCE,
                "2026-08-25T00:01:00+00:00",
                None,
            )
            admitted = catalog.admit_operation(
                record,
                owner,
                admission_open=True,
                hardware_target=target,
            ).record
        return OperationContext(
            admitted,
            OperationFence(admitted.id, owner.generation),
            lambda: Catalog(prepared.catalog_path),
        )

    def _backend(
        self,
        prepared: _PreparedRun,
        context: OperationContext,
        *,
        expected: ExpectedMedia,
        readback: bool,
    ) -> _Backend:
        backend = self._backend_factory(
            catalog_path=prepared.catalog_path,
            context=context,
            expected=expected,
            readback=readback,
        )
        if (
            backend is None
            or getattr(backend, "expected", None) != expected
            or getattr(backend, "fence", None) != context.fence
        ):
            raise QualificationArchiveRefused(
                "qualification backend is not bound to the isolated operation"
            )
        return backend

    def _require_identity(
        self,
        identity: object,
        committed: _CommittedArchiveProof,
    ) -> None:
        if (
            type(identity) is not MediaIdentity
            or identity.mam_barcode != committed.physical_label
            or identity.mam_volume_serial != committed.volume_serial
            or identity.ltfs_volume_label != committed.ltfs_volume_label
            or identity.ltfs_volume_uuid != committed.volume_uuid
            or type(identity.ltfs_volume_uuid) is not str
            or media_identity_sha256(identity.canonical_fields())
            != committed.observed_media_identity_sha256
        ):
            raise QualificationArchiveRefused(
                "qualification readback does not match committed archive identity"
            )
        try:
            if str(uuid.UUID(identity.ltfs_volume_uuid)) != identity.ltfs_volume_uuid:
                raise ValueError
        except (AttributeError, TypeError, ValueError):
            raise QualificationArchiveRefused(
                "qualification readback does not match committed archive identity"
            ) from None

    def _verify_readback(
        self,
        tape_root: Path,
        committed: _CommittedArchiveProof,
    ) -> tuple[
        dict[str, object],
        tuple[tuple[str, str, str, int, int, str], ...],
    ]:
        root = Path(tape_root)
        blocks_root = root / "libraries" / _LIBRARY_ID / "blocks"
        block_root = blocks_root / committed.block_id
        try:
            block_status = block_root.stat(follow_symlinks=False)
        except OSError:
            raise QualificationArchiveRefused(
                "qualification archive block is unavailable"
            ) from None
        if not stat.S_ISDIR(block_status.st_mode) or block_root.is_symlink():
            raise QualificationArchiveRefused(
                "qualification archive block is unavailable"
            )
        manifest_path = block_root / "manifest.jsonl"
        block_path = block_root / "block.json"
        records, manifest_bytes = self._manifest(manifest_path)
        expected_records = []
        payload_hashes = []
        for relative_path, literal in _PAYLOADS:
            tape_relative = (
                PurePosixPath("libraries")
                / _LIBRARY_ID
                / "blocks"
                / block_root.name
                / "files"
                / relative_path
            ).as_posix()
            digest = self._hash_regular(
                root / tape_relative,
                len(literal),
                expected_mtime_ns=_FIXED_MTIME_NS,
            )
            literal_digest = hashlib.sha256(literal).hexdigest()
            if digest != literal_digest:
                raise QualificationArchiveRefused(
                    "qualification payload digest mismatch"
                )
            payload_hashes.append((relative_path, digest))
            expected_records.append(
                {
                    "library_id": _LIBRARY_ID,
                    "relative_path": relative_path,
                    "tape_relative_path": tape_relative,
                    "size": len(literal),
                    "mtime_ns": _FIXED_MTIME_NS,
                    "sha256": literal_digest,
                }
            )
        if records != expected_records:
            raise QualificationArchiveRefused(
                "qualification manifest records do not match literals"
            )
        block, block_bytes = self._closed_json(block_path, _BLOCK_KEYS)
        block_completed_at = self._safe_utc_timestamp(block.get("completed_at"))
        if (
            block["block_id"] != committed.block_id
            or block["library_id"] != _LIBRARY_ID
            or block["tape_id"] != committed.tape_id
            or block_completed_at is None
            or block["completed_at"] != block_completed_at.isoformat(timespec="seconds")
            # ArchiveRunner writes canonical whole-second manifest timestamps.
            # Treat the value as its one-second precision interval so a bounded
            # qualification completed within the admission second stays causal.
            or block_completed_at + timedelta(seconds=1)
            <= committed.archive_started_at
            or block_completed_at > committed.committed_at
            or block["file_count"] != len(_PAYLOADS)
            or block["total_bytes"] != sum(len(value) for _, value in _PAYLOADS)
            or block["format"] != "lto-library-backup-block-v1"
            or block["copy_mode"] != "direct-files-no-tar"
            or block["sha256_recorded_during_source_stream"] is not True
        ):
            raise QualificationArchiveRefused("qualification block manifest is invalid")
        snapshot_path = (
            root / ".lto-backup" / "catalog-snapshots" / f"{block_root.name}.sqlite3"
        )
        snapshot_sha256 = self._verify_snapshot(
            snapshot_path, committed, expected_records
        )
        return (
            {
                "block_id": committed.block_id,
                "tape_id": committed.tape_id,
                "observed_media_identity_sha256": (
                    committed.observed_media_identity_sha256
                ),
                "payload_sha256": tuple(payload_hashes),
                "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "block_sha256": hashlib.sha256(block_bytes).hexdigest(),
                "catalog_snapshot_sha256": snapshot_sha256,
            },
            tuple(
                (
                    str(record["library_id"]),
                    str(record["relative_path"]),
                    str(record["tape_relative_path"]),
                    int(record["size"]),
                    int(record["mtime_ns"]),
                    str(record["sha256"]),
                )
                for record in expected_records
            ),
        )

    @staticmethod
    def _hash_regular(
        path: Path,
        expected_size: int,
        *,
        expected_mtime_ns: int | None = None,
    ) -> str:
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            status = os.fstat(descriptor)
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise OSError
            if status.st_size != expected_size:
                raise QualificationArchiveRefused(
                    "qualification payload digest mismatch"
                )
            if (
                expected_mtime_ns is not None
                and status.st_mtime_ns != expected_mtime_ns
            ):
                raise QualificationArchiveRefused(
                    "qualification payload metadata mismatch"
                )
            digest = hashlib.sha256()
            remaining = status.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise OSError
                digest.update(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise OSError
            return digest.hexdigest()
        except OSError:
            raise QualificationArchiveRefused(
                "qualification payload is unavailable"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @staticmethod
    def _safe_utc_timestamp(value: object) -> datetime | None:
        if type(value) is not str or not value or len(value) > 40:
            return None
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError:
            return None
        if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
            return None
        return parsed

    @classmethod
    def _manifest(cls, path: Path) -> tuple[list[dict[str, object]], bytes]:
        raw = cls._bounded_regular(path, _MAX_JSON_BYTES)
        if not raw or not raw.endswith(b"\n"):
            raise QualificationArchiveRefused("qualification manifest is incomplete")
        try:
            records = [
                json.loads(line, object_pairs_hook=cls._closed_pairs)
                for line in raw.decode("utf-8").splitlines()
            ]
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise QualificationArchiveRefused(
                "qualification manifest is invalid"
            ) from None
        if any(
            type(record) is not dict or frozenset(record) != _MANIFEST_KEYS
            for record in records
        ):
            raise QualificationArchiveRefused("qualification manifest is invalid")
        return records, raw

    @classmethod
    def _closed_json(
        cls, path: Path, keys: frozenset[str]
    ) -> tuple[dict[str, object], bytes]:
        raw = cls._bounded_regular(path, _MAX_JSON_BYTES)
        try:
            value = json.loads(raw, object_pairs_hook=cls._closed_pairs)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise QualificationArchiveRefused(
                "qualification block manifest is invalid"
            ) from None
        if type(value) is not dict or frozenset(value) != keys:
            raise QualificationArchiveRefused("qualification block manifest is invalid")
        return value, raw

    @staticmethod
    def _closed_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if type(key) is not str or key in result:
                raise ValueError
            result[key] = value
        return result

    @staticmethod
    def _bounded_regular(path: Path, maximum: int) -> bytes:
        descriptor = -1
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_nlink != 1
                or not 0 < status.st_size <= maximum
            ):
                raise OSError
            chunks: list[bytes] = []
            remaining = status.st_size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    raise OSError
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise OSError
            return b"".join(chunks)
        except OSError:
            raise QualificationArchiveRefused(
                "qualification artifact is unavailable"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    @classmethod
    def _verify_snapshot(
        cls,
        path: Path,
        committed: _CommittedArchiveProof,
        expected_records: list[dict[str, object]],
    ) -> str:
        try:
            size = path.stat(follow_symlinks=False).st_size
        except OSError:
            raise QualificationArchiveRefused(
                "qualification catalog snapshot is unavailable"
            ) from None
        if not 0 < size <= _MAX_SNAPSHOT_BYTES:
            raise QualificationArchiveRefused(
                "qualification catalog snapshot is too large"
            )
        digest = cls._hash_regular(path, size)
        try:
            with closing(
                sqlite3.connect(f"file:{path}?mode=ro&immutable=1", uri=True)
            ) as db:
                integrity = tuple(
                    row[0] for row in db.execute("PRAGMA integrity_check")
                )
                columns = (
                    "tape_id",
                    "library_id",
                    "relative_path",
                    "tape_relative_path",
                    "size",
                    "mtime_ns",
                    "sha256",
                )
                rows = [
                    dict(zip(columns, row, strict=True))
                    for row in db.execute(
                        "SELECT tape_id,library_id,relative_path,tape_relative_path,size,"
                        "mtime_ns,sha256 FROM file_versions WHERE block_id=? "
                        "AND library_id=? "
                        "ORDER BY relative_path",
                        (committed.block_id, _LIBRARY_ID),
                    )
                ]
                block_rows = db.execute(
                    "SELECT id,library_id,tape_id,tape_relative_root FROM blocks "
                    "WHERE id=?",
                    (committed.block_id,),
                ).fetchall()
                tape_rows = db.execute(
                    "SELECT id,cassette_number,volume_serial,volume_label,filesystem "
                    "FROM tapes WHERE id=?",
                    (committed.tape_id,),
                ).fetchall()
        except (OSError, sqlite3.DatabaseError, ValueError):
            raise QualificationArchiveRefused(
                "qualification catalog snapshot is invalid"
            ) from None
        expected_snapshot_records = [
            {"tape_id": committed.tape_id, **record} for record in expected_records
        ]
        expected_block = (
            committed.block_id,
            _LIBRARY_ID,
            committed.tape_id,
            f"libraries/{_LIBRARY_ID}/blocks/{committed.block_id}",
        )
        expected_tape = (
            committed.tape_id,
            committed.physical_label,
            committed.volume_serial,
            committed.ltfs_volume_label,
            "LTFS",
        )
        if (
            integrity != ("ok",)
            or sorted(rows, key=lambda row: row["relative_path"])
            != sorted(
                expected_snapshot_records,
                key=lambda row: row["relative_path"],
            )
            or [tuple(row) for row in block_rows] != [expected_block]
            or [tuple(row) for row in tape_rows] != [expected_tape]
        ):
            raise QualificationArchiveRefused(
                "qualification catalog snapshot records do not match manifest"
            )
        return digest

    def _write_evidence(
        self,
        prepared: _PreparedRun,
        identity: MediaIdentity,
        proof: dict[str, object],
        restore: QualificationRestoreEvidence | None = None,
    ) -> QualificationArchiveEvidence:
        body = {
            "schema": 2 if restore is not None else 1,
            "run_id": prepared.run_id,
            "physical_label": self._expected_label,
            "volume_uuid": identity.ltfs_volume_uuid,
            "file_count": len(_PAYLOADS),
            **proof,
        }
        if restore is not None:
            body["restore"] = {
                "attestation_state": "passed",
                "plan_id": restore.plan_id,
                "run_id": restore.run_id,
                "operation_id": restore.operation_id,
                "plan_fingerprint_sha256": restore.plan_fingerprint_sha256,
                "physical_label": restore.physical_label,
                "ltfs_volume_label": restore.ltfs_volume_label,
                "volume_serial": restore.volume_serial,
                "volume_uuid": restore.volume_uuid,
                "file_version_ids": restore.file_version_ids,
                "item_states": restore.item_states,
                "destination_sha256": restore.destination_sha256,
                "restored_files": restore.restored_files,
                "skipped_files": restore.skipped_files,
                "verified_bytes": restore.verified_bytes,
                "release_boundary": restore.release_boundary,
                "unload_command_id": restore.unload_command_id,
                "no_medium_proven": restore.no_medium_proven,
                "release_receipt_sha256": restore.release_receipt_sha256,
            }
        canonical = json.dumps(
            body, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        evidence_domain = (
            b"lto-archive-runner-physical-qualification/v2\0"
            if restore is not None
            else b"lto-archive-runner-physical-qualification/v1\0"
        )
        evidence_sha256 = hashlib.sha256(evidence_domain + canonical).hexdigest()
        payload = {**body, "evidence_sha256": evidence_sha256}
        encoded = (
            json.dumps(
                payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode("ascii")
        if len(encoded) > _MAX_JSON_BYTES:
            raise QualificationArchiveRefused(
                "qualification evidence is too large"
            )
        descriptor = -1
        try:
            descriptor = os.open(
                prepared.evidence_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError
                view = view[written:]
            os.fsync(descriptor)
        except OSError:
            try:
                prepared.evidence_path.unlink(missing_ok=True)
            except OSError:
                pass
            raise QualificationArchiveRefused(
                "qualification evidence could not be persisted"
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return QualificationArchiveEvidence(
            run_id=prepared.run_id,
            physical_label=self._expected_label,
            volume_uuid=str(identity.ltfs_volume_uuid),
            file_count=len(_PAYLOADS),
            payload_sha256=tuple(proof["payload_sha256"]),
            manifest_sha256=str(proof["manifest_sha256"]),
            block_sha256=str(proof["block_sha256"]),
            catalog_snapshot_sha256=str(proof["catalog_snapshot_sha256"]),
            evidence_sha256=evidence_sha256,
            catalog_path=prepared.catalog_path,
            evidence_path=prepared.evidence_path,
            readback_release_receipt_sha256=str(
                proof["readback_release_receipt_sha256"]
            ),
            restore=restore,
        )


class BrokeredLinuxArchiveQualification:
    """Concrete installed-runtime composition for the physical protocol."""

    def __init__(
        self,
        *,
        state_root: Path,
        settings: LinuxSettings,
        scope_manager: BrokeredCgroupExecutionScopeManager,
        ltfs_sessions: UnixBrokeredCgroupScopeApi,
        privilege_boundary: ReadOnlyCgroupPrivilegeBoundary,
        ltfs_info_binary: Path,
        enable_restore_qualification: bool = False,
        event_sink: OperationalEventSink | None = None,
    ) -> None:
        self._settings = settings
        self._scope_manager = scope_manager
        self._ltfs_sessions = ltfs_sessions
        self._privilege_boundary = privilege_boundary
        self._ltfs_info_binary = Path(ltfs_info_binary)
        self._devices = SysfsDeviceIdentityProvider()
        self._catalogs: list[Catalog] = []
        self._event_sink = event_sink or NullOperationalEventSink()
        self._stage = ArchiveRunnerPhysicalQualification(
            state_root=state_root,
            expected_label="TAPE04",
            target_factory=lambda expected: LinuxLtfsBackend.target_binding_from(
                self._settings, expected, self._devices
            ),
            backend_factory=self._backend,
            enable_restore_qualification=enable_restore_qualification,
            buffer_bytes=settings.buffer_bytes,
            event_sink=self._event_sink,
        )

    def _backend(
        self,
        *,
        catalog_path: Path,
        context: OperationContext,
        expected: ExpectedMedia,
        readback: bool,
    ) -> LinuxLtfsBackend:
        if type(readback) is not bool:
            raise QualificationArchiveRefused("qualification backend phase is invalid")
        catalog = Catalog(catalog_path)
        try:
            daemon_fence = catalog.current_daemon_fence()
            if (
                daemon_fence is None
                or daemon_fence.generation != context.fence.owner_generation
            ):
                raise QualificationArchiveRefused(
                    "qualification daemon fence is unavailable"
                )
            supervisor = _production_supervisor(
                catalog,
                daemon_fence,
                self._scope_manager,
                self._privilege_boundary,
                event_sink=self._event_sink,
                operation_context=closed_operational_correlation(
                    operation_id=context.record.id,
                    job_id=context.record.job_id,
                    cassette_label=expected.volume_label,
                    cassette_sequence=context.record.cassette_sequence,
                    daemon_generation=context.fence.owner_generation,
                ),
            )
            probe = BrokeredLtfsInfoMediaIdentityProbe(
                supervisor,
                context,
                self._settings,
                self._ltfs_info_binary,
            )
            backend = _QualificationLinuxLtfsBackend(
                settings=self._settings,
                expected=expected,
                fence=context.fence,
                catalog=catalog,
                supervisor=supervisor,
                ltfs_sessions=self._ltfs_sessions,
                device_identities=self._devices,
                media_identity_probe=probe,
            )
        except BaseException:
            catalog.close()
            raise
        self._catalogs.append(catalog)
        return backend

    def run(self) -> QualificationArchiveEvidence:
        try:
            return self._stage.run()
        finally:
            catalogs, self._catalogs = self._catalogs, []
            for catalog in catalogs:
                catalog.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m ltobackup.qualification.archive_runner"
    )
    parser.add_argument(
        "--enable-restore-qualification",
        action="store_true",
        help=(
            "after archive/readback eject, wait for operator reinsertion and run "
            "the isolated read-only multi-file production restore qualification"
        ),
    )
    parser.add_argument(
        "--state-root",
        type=Path,
        default=Path("/var/lib/lto-archiver-qualification/archive-runner"),
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/lto-archiver/config.toml"),
    )
    parser.add_argument(
        "--broker-socket",
        type=Path,
        default=Path("/run/lto-archiver-broker/control.sock"),
    )
    parser.add_argument(
        "--broker-capability-file",
        type=Path,
        default=Path("/etc/lto-archiver/credentials/broker-capability"),
    )
    parser.add_argument(
        "--ltfs-info-binary",
        type=Path,
        default=Path("/usr/bin/ltfs-info"),
    )
    return parser


def _bounded_kernel_control(path: Path, maximum: int = 1024) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or status.st_size < 0
            or status.st_size > maximum
        ):
            raise OSError
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(256, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total == 0 or total > maximum or os.read(descriptor, 1):
            raise OSError
        return b"".join(chunks)
    except OSError:
        raise QualificationArchiveRefused(
            "qualification SELinux execution boundary is unavailable"
        ) from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_enforced_selinux_domain(
    enforce_path: Path = Path("/sys/fs/selinux/enforce"),
    current_path: Path = Path("/proc/self/attr/current"),
) -> None:
    failure = "qualification SELinux execution boundary is unavailable"
    try:
        enforcing = _bounded_kernel_control(enforce_path)
        current = _bounded_kernel_control(current_path)
        if enforcing not in {b"1", b"1\n"}:
            raise ValueError
        if current.endswith(b"\0"):
            current = current[:-1]
        if current.endswith(b"\n"):
            current = current[:-1]
        decoded = current.decode("ascii", errors="strict")
        fields = decoded.split(":", 3)
        if (
            len(fields) != 4
            or any(not field for field in fields)
            or not decoded.isprintable()
            or decoded != decoded.strip()
            or fields[2] != "lto_archiver_t"
        ):
            raise ValueError
    except (QualificationArchiveRefused, UnicodeError, ValueError):
        raise QualificationArchiveRefused(failure) from None


def main(argv: list[str] | None = None) -> int:
    events = JournalOperationalEventSink(
        syslog_identifier="lto-archiver-archive-runner-qualification"
    )
    _emit_archive_qualification_event(events, "started")
    try:
        return _run_main(argv, events)
    except BaseException:
        _emit_archive_qualification_event(events, "failed")
        raise


def _run_main(argv: list[str] | None, events: OperationalEventSink) -> int:
    try:
        daemon = pwd.getpwnam("lto-archiver")
    except KeyError:
        raise SystemExit(
            "archive runner physical qualification requires the configured "
            "lto-archiver identity"
        ) from None
    if (
        not sys.platform.startswith("linux")
        or os.geteuid() != daemon.pw_uid
        or os.getegid() != daemon.pw_gid
    ):
        raise SystemExit(
            "archive runner physical qualification requires the configured "
            "lto-archiver identity"
        )
    _require_enforced_selinux_domain()
    args = build_parser().parse_args(argv)
    settings = load_linux_settings(args.config)
    settings.validate()
    capability = load_broker_capability(args.broker_capability_file)
    broker = UnixBrokeredCgroupScopeApi(
        args.broker_socket,
        capability,
        timeout=30.0,
        ltfs_lifecycle_timeout=86_400.0,
    )
    scope_manager = BrokeredCgroupExecutionScopeManager(broker, capability)
    privilege_boundary = ReadOnlyCgroupPrivilegeBoundary()
    broker.assert_ready()
    privilege_boundary.validate_supervisor()
    runtime = BrokeredLinuxArchiveQualification(
        state_root=args.state_root,
        settings=settings,
        scope_manager=scope_manager,
        ltfs_sessions=broker,
        privilege_boundary=privilege_boundary,
        ltfs_info_binary=args.ltfs_info_binary,
        enable_restore_qualification=args.enable_restore_qualification,
        event_sink=events,
    )
    evidence = runtime.run()
    print(
        json.dumps(
            {
                "schema": 1,
                "run_id": evidence.run_id,
                "physical_label": evidence.physical_label,
                "volume_uuid": evidence.volume_uuid,
                "file_count": evidence.file_count,
                "evidence_sha256": evidence.evidence_sha256,
                "catalog_path": str(evidence.catalog_path),
                "evidence_path": str(evidence.evidence_path),
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    _emit_archive_qualification_event(events, "succeeded")
    return 0


def _emit_archive_qualification_event(
    events: OperationalEventSink, result: str
) -> None:
    severity = (
        OperationalSeverity.INFO
        if result in {"started", "succeeded"}
        else OperationalSeverity.ERROR
    )
    message = {
        "started": "Archive runner qualification started.",
        "succeeded": "Archive runner qualification succeeded.",
        "failed": "Archive runner qualification failed.",
    }[result]
    try:
        events.emit(
            OperationalEvent(
                OperationalSource.QUALIFICATION,
                severity,
                f"archive_qualification.{result}",
                message,
            )
        )
    except BaseException:  # noqa: BLE001 - diagnostics never alter qualification
        pass


if __name__ == "__main__":
    raise SystemExit(main())
