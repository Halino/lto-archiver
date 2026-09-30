from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

from ltobackup.broker.client import (
    BrokerUnavailable,
    LtfsSessionAdmission,
    LtfsSessionHandle,
    LtfsSessionRecoveryAdmission,
    _issue_ltfs_session_handle,
)
from ltobackup.broker.ltfs_session import derive_receipt_operation_uuid
from ltobackup.broker.protocol import ltfs_request_sha256
from ltobackup.catalog import Catalog
from ltobackup.daemon.archive_runner import ArchiveRunner
from ltobackup.daemon.archive_runtime import ProductionArchiveResume
from ltobackup.daemon.frozen_job import FrozenCassette, FrozenItem, FrozenJobPlan
from ltobackup.daemon.models import (
    CommandExitEvidence,
    DaemonFence,
    OperationFence,
    OperationRecord,
    ProcessIdentity,
    RecoveryCommandFence,
    StaleOperationFence,
    expected_media_scope_sha256,
    media_identity_sha256,
)
from ltobackup.daemon.operations import OperationContext
from ltobackup.linux_settings import LinuxSettings
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupScopeReceipt,
    CommandFailed,
    CompletedCommand,
    ExecutionScopeIdentity,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
    RunningCommand,
    redacted_argv_sha256,
)
from ltobackup.tape.linux_ltfs import (
    AnchoredDevicePair,
    BackendUnavailable,
    LinuxLtfsBackend,
    MediaIdentityError,
    MountStateError,
    ProcMountInfoProbe,
    StableDeviceIdentity,
    SysfsDeviceIdentityProvider,
)
from ltobackup.tape.models import ExpectedMedia, MediaIdentityFields, MountedTape


class ExpectedMediaScopeTests(unittest.TestCase):
    def test_scope_hash_requires_the_exact_six_field_expected_media_shape(self) -> None:
        expected = ExpectedMedia(
            operation_kind="archive.resume",
            job_id="JOB-SYNTHETIC",
            cassette_sequence=4,
            volume_label="MD0004",
            volume_serial=None,
            volume_uuid=None,
        )
        canonical = (
            "archive.resume",
            "JOB-SYNTHETIC",
            "4",
            "MD0004",
            "",
            "",
        )

        self.assertEqual(canonical, expected.target_scope())
        self.assertEqual(
            expected_media_scope_sha256(canonical),
            expected_media_scope_sha256(expected.target_scope()),
        )
        with self.assertRaises((TypeError, ValueError)):
            expected_media_scope_sha256(canonical[:4])

    def test_scope_hash_rejects_noncanonical_shapes_and_core_values(self) -> None:
        class StringSubclass(str):
            pass

        canonical = (
            "archive.resume",
            "JOB-SYNTHETIC",
            "4",
            "MD0004",
            "",
            "",
        )
        invalid = (
            (),
            canonical[:5],
            (*canonical, "extra"),
            ("", *canonical[1:]),
            (canonical[0], "", *canonical[2:]),
            (*canonical[:2], "", *canonical[3:]),
            (*canonical[:3], "", *canonical[4:]),
            (*canonical[:2], "04", *canonical[3:]),
            (*canonical[:2], "0", *canonical[3:]),
            ("archive\nresume", *canonical[1:]),
            ("   ", *canonical[1:]),
            (canonical[0], "\t", *canonical[2:]),
            (canonical[0], "   ", *canonical[2:]),
            (*canonical[:3], "MEDIA\x00A", *canonical[4:]),
            (*canonical[:3], "   ", *canonical[4:]),
            (*canonical[:4], "SERIAL\rA", canonical[5]),
            (*canonical[:4], "   ", canonical[5]),
            (*canonical[:5], "   "),
            (StringSubclass(canonical[0]), *canonical[1:]),
            (*canonical[:3], "x" * 257, *canonical[4:]),
        )

        for scope in invalid:
            with self.subTest(scope=scope), self.assertRaises((TypeError, ValueError)):
                expected_media_scope_sha256(scope)


class RecordingSupervisor:
    def __init__(self, catalog: Catalog, fence, daemon_fence: DaemonFence) -> None:
        self.catalog = catalog
        self.fence = fence
        self.daemon_fence = daemon_fence
        self.calls: list[tuple[str, tuple[str, ...]]] = []
        self.counter = 0
        self.termination_identity_override: ProcessIdentity | None = None
        self.responses: dict[str, CompletedCommand] = {
            "identify": CompletedCommand(
                0,
                "Unit serial number: DRIVE-A\n",
                "",
            ),
            "inquiry": CompletedCommand(0, "Unit serial number: DRIVE-A\n", ""),
            "status": CompletedCommand(
                0, "remaining_bytes=1200\nposition_bytes=300\n", ""
            ),
        }

    def run(
        self,
        fence,
        kind: str,
        argv: tuple[str, ...],
        timeout: float,
        pass_fds: tuple[int, ...] = (),
    ):
        self.calls.append((kind, argv))
        self.counter += 1
        command_id = f"fake-command-{fence.owner_generation}-{self.counter}"
        identity = ProcessIdentity(
            "boot-a", 100 + self.counter, 200 + self.counter, 100 + self.counter
        )
        self.catalog.reserve_hardware_command(
            fence, command_id, kind, redacted_argv_sha256(argv)
        )
        self.catalog.record_blocked_process(command_id, fence, identity)
        permit = hashlib.sha256(f"release:{command_id}".encode("ascii")).hexdigest()
        self.catalog.authorize_hardware_command_release(command_id, fence, permit)
        self.catalog.confirm_hardware_command_released(command_id, fence, permit)
        released_at = self.catalog.command(command_id).released_at
        self.catalog.acknowledge_command_quiescence(
            command_id,
            self.daemon_fence,
            CommandExitEvidence(
                command_id,
                identity,
                "completed",
                (
                    datetime.fromisoformat(released_at) + timedelta(microseconds=1)
                ).isoformat(),
            ),
        )
        return self.responses.get(kind, CompletedCommand(0, "", ""))

    def start(
        self,
        fence,
        kind: str,
        argv: tuple[str, ...],
        pass_fds: tuple[int, ...] = (),
    ) -> RunningCommand:
        self.calls.append((kind, argv))
        self.counter += 1
        command_id = f"fake-command-{fence.owner_generation}-{self.counter}"
        identity = ProcessIdentity(
            "boot-a", 100 + self.counter, 200 + self.counter, 100 + self.counter
        )
        self.catalog.reserve_hardware_command(
            fence, command_id, kind, redacted_argv_sha256(argv)
        )
        self.catalog.record_blocked_process(command_id, fence, identity)
        permit = hashlib.sha256(f"release:{command_id}".encode("ascii")).hexdigest()
        self.catalog.authorize_hardware_command_release(command_id, fence, permit)
        self.catalog.confirm_hardware_command_released(command_id, fence, permit)
        return RunningCommand(
            command_id,
            identity,
            ExecutionScopeIdentity(command_id, fence.owner_generation),
        )

    def assert_running(self, command: RunningCommand) -> None:
        durable = self.catalog.command(command.command_id)
        if durable is None or durable.state != "released":
            raise AssertionError("fake mount command is not live")

    def terminate_and_await(self, command_id: str) -> CommandExitEvidence:
        command = self.catalog.command(command_id)
        boundary = command.released_at or command.created_at
        evidence = CommandExitEvidence(
            command_id,
            self.termination_identity_override or command.process,
            "terminated",
            (datetime.fromisoformat(boundary) + timedelta(microseconds=1)).isoformat(),
        )
        self.catalog.acknowledge_command_quiescence(
            command_id, self.daemon_fence, evidence
        )
        return evidence


class FakeDeviceIdentities:
    def __init__(self, drive_serial: str = "DRIVE-A") -> None:
        self.drive_serial = drive_serial

    def resolve(self, path: Path) -> StableDeviceIdentity:
        return StableDeviceIdentity(path.name, self.drive_serial, "unit-a")

    def open_pair(self, tape_path: Path, scsi_path: Path) -> AnchoredDevicePair:
        tape_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        scsi_fd = os.open(os.devnull, os.O_RDONLY | os.O_CLOEXEC)
        return AnchoredDevicePair(
            tape=self.resolve(tape_path),
            scsi=self.resolve(scsi_path),
            tape_exec_path=Path(f"/proc/self/fd/{tape_fd}"),
            scsi_exec_path=Path(f"/proc/self/fd/{scsi_fd}"),
            pass_fds=(tape_fd, scsi_fd),
        )


class FakeLtfsSessions:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []
        self.observe_error: Exception | None = None
        self.finalize_error: Exception | None = None
        self.pending_handle: LtfsSessionHandle | None = None
        self.observed_volume_uuid_override: str | None = None
        self.observed_prior_generation_override: int | None = None
        self.observed_volume_label_override: str | None = None

    def start_ltfs_session(
        self,
        admission: LtfsSessionAdmission,
        *,
        tape_fd: int,
        scsi_fd: int,
    ) -> LtfsSessionHandle:
        os.fstat(tape_fd)
        os.fstat(scsi_fd)
        if self.pending_handle is not None:
            raise BrokerUnavailable()
        self.calls.append(("start", (admission, tape_fd, scsi_fd)))
        scope = BrokeredCgroupScopeReceipt(
            1,
            "ltfs-scope-a",
            admission.owner_generation,
            b"a" * 32,
            "scope-a",
            "8" * 64,
            b"b" * 32,
            b"c" * 32,
            True,
            True,
            True,
        )
        request = LtfsSessionRequest(
            1,
            admission.operation_id,
            admission.owner_generation,
            admission.mount_path_sha256,
            admission.tape_device_identity_sha256,
            admission.scsi_device_identity_sha256,
            admission.expected_media_scope_sha256,
            admission.observed_media_identity_sha256,
            admission.expected_volume_uuid,
            admission.expected_prior_generation,
            admission.read_only,
            "6" * 64,
            "7" * 64,
            scope,
            b"d" * 32,
        )
        request_sha256 = ltfs_request_sha256(request)
        receipt = LtfsSessionReceipt(
            1,
            request.operation_id,
            derive_receipt_operation_uuid(
                operation_id=request.operation_id,
                owner_generation=request.owner_generation,
                request_sha256=request_sha256,
            ),
            self.observed_volume_uuid_override or request.expected_volume_uuid,
            self.observed_prior_generation_override
            or request.expected_prior_generation,
            request.read_only,
            request.owner_generation,
            request.request_nonce,
            "session-a",
            request_sha256,
            4711,
            8123,
            "9" * 64,
            b"e" * 32,
            b"f" * 32,
            True,
            self.observed_volume_label_override or "MD0004",
            request.observed_media_identity_sha256,
        )
        return _issue_ltfs_session_handle(receipt)

    def observe_ltfs_session(self, handle: LtfsSessionHandle) -> LtfsSessionReceipt:
        self.calls.append(("observe", handle.receipt))
        if self.observe_error is not None:
            raise self.observe_error
        return handle.receipt

    def finalize_ltfs_session(
        self, handle: LtfsSessionHandle
    ) -> LtfsFinalizationReceipt:
        self.calls.append(("finalize", handle.receipt))
        if self.finalize_error is not None:
            self.pending_handle = handle
            raise self.finalize_error
        if self.pending_handle is handle:
            self.pending_handle = None
        receipt = handle.receipt
        fields = {
            "schema": 1,
            "stage": "terminal",
            "operation_id": receipt.receipt_operation_uuid,
            "volume_uuid": receipt.observed_volume_uuid,
            "prior_generation": receipt.observed_prior_generation,
            "new_generation": receipt.observed_prior_generation
            if receipt.read_only
            else receipt.observed_prior_generation + 1,
            "bytes_valid": True,
            "bytes": 0,
            "files_valid": True,
            "files": 0,
            "phase_duration_ns": [0] * 11,
            "capture_duration_ns": 0,
            "device_close_duration_ns": 0,
            "device_close_result_valid": True,
            "device_close_result": 0,
            "catalog_ack_duration_ns": 0,
            "media_committed": True,
            "catalog_acknowledged": True,
            "cleanup_failed": False,
            "result": 0,
        }
        terminal_sha256 = hashlib.sha256(
            (json.dumps(fields, separators=(",", ":")) + "\n").encode("ascii")
        ).hexdigest()
        return LtfsFinalizationReceipt(
            1,
            handle.receipt,
            LtfsStandaloneReceipt(
                **{**fields, "phase_duration_ns": tuple(fields["phase_duration_ns"])},
                terminal_sha256=terminal_sha256,
            ),
            b"g" * 32,
            b"h" * 32,
            b"i" * 32,
            True,
            True,
        )

    def recover_pending_ltfs_session(
        self, admission: LtfsSessionRecoveryAdmission
    ) -> LtfsFinalizationReceipt | None:
        self.calls.append(("recover", admission))
        if self.pending_handle is None:
            return None
        return self.finalize_ltfs_session(self.pending_handle)


class FakeMediaIdentityProbe:
    def __init__(self) -> None:
        self.supervisor = None
        self.fence = None
        self.unmounted = MediaIdentityFields(
            mam_barcode="MD0004",
            mam_volume_serial="SERIAL-A",
            ltfs_volume_label="MD0004",
            ltfs_volume_uuid="22222222-2222-4222-8222-222222222222",
            index_generation=7,
        )
        self.mounted = MediaIdentityFields(
            ltfs_volume_label="MD0004", ltfs_volume_uuid="UUID-A"
        )

    def preflight(self) -> None:
        return None

    def identify_unmounted(self) -> MediaIdentityFields:
        if self.supervisor is not None:
            self.supervisor.run(
                self.fence, "probe_media", ("synthetic-media-probe",), 1.0
            )
        return self.unmounted

    def identify_mounted(self, path: Path) -> MediaIdentityFields:
        return self.mounted


class SequencedFormatProbe:
    def __init__(
        self,
        preformat: MediaIdentityFields,
        postformat: MediaIdentityFields,
        supervisor=None,
        fence=None,
    ) -> None:
        self._values = (preformat, postformat)
        self.calls = 0
        self.supervisor = supervisor
        self.fence = fence

    def preflight(self) -> None:
        return None

    def identify_unmounted(self) -> MediaIdentityFields:
        if self.supervisor is not None:
            self.supervisor.run(
                self.fence, "probe_media", ("synthetic-media-probe",), 1.0
            )
        value = self._values[0 if self.calls < 2 else 1]
        self.calls += 1
        return value

    def identify_mounted(self, _path: Path) -> MediaIdentityFields:
        raise AssertionError("mounted probe is not part of format rebinding")


class MediaSequenceProbe:
    def __init__(
        self,
        values: tuple[MediaIdentityFields, ...],
        supervisor,
        fence,
    ) -> None:
        self._values = values
        self.calls = 0
        self.supervisor = supervisor
        self.fence = fence

    def preflight(self) -> None:
        return None

    def identify_unmounted(self) -> MediaIdentityFields:
        self.supervisor.run(self.fence, "probe_media", ("synthetic-media-probe",), 1.0)
        value = self._values[self.calls]
        self.calls += 1
        return value

    def identify_mounted(self, _path: Path) -> MediaIdentityFields:
        raise AssertionError("mounted probe is not part of format continuity")


class FakeMountProbe:
    def __init__(self) -> None:
        self.mounted = False
        self.expectations: list[tuple[str, str]] = []

    def is_mounted(self, path: Path, **_expected) -> bool:
        return self.mounted

    def await_mounted(
        self, path: Path, expected: bool, timeout: float, **_mount_identity
    ) -> None:
        self.expectations.append(
            (_mount_identity["filesystem_type"], _mount_identity["source"])
        )
        self.mounted = expected

    def await_unmounted(self, path: Path, timeout: float) -> None:
        self.mounted = False


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.value += seconds


class Observer:
    def __init__(self) -> None:
        self.events: list[str] = []

    def finalization_started(self) -> None:
        self.events.append("finalization_started")

    def mount_release_started(self) -> None:
        self.events.append("mount_release_started")


class ExecutableResolver:
    def __init__(self, root: Path) -> None:
        self.root = root

    def __call__(self, override: Path | None, name: str) -> Path:
        return override or self.root / name


class LinuxLtfsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.catalog = Catalog(root / "catalog.db")
        self.catalog.initialize()
        self.catalog.add_library("LIB-SYNTHETIC", "Synthetic library", str(root))
        self.catalog.create_automatic_job(
            "JOB-SYNTHETIC",
            "LIB-SYNTHETIC",
            "synthetic-drive",
            str(root / "mount-a"),
            [
                ("SY0001", "SERIAL-1", 1, 1),
                ("SY0002", "SERIAL-2", 1, 1),
                ("SY0003", "SERIAL-3", 1, 1),
                ("MD0004", "SERIAL-A", 1, 1),
            ],
            force_format=True,
        )
        self.daemon_fence = self.catalog.claim_daemon_owner("daemon-a")
        self.expected = ExpectedMedia(
            operation_kind="archive.resume",
            job_id="JOB-SYNTHETIC",
            cassette_sequence=4,
            volume_label="MD0004",
            volume_serial="SERIAL-A",
        )
        self.settings = LinuxSettings(
            state_dir=root / "state",
            socket_path=root / "run" / "daemon.sock",
            tape_device_path=Path("/dev/tape/by-id/synthetic-tape-a-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-synthetic-a"),
            mount_path=root / "mount-a",
            source_roots=(root / "source",),
        )
        target = LinuxLtfsBackend.target_binding_from(
            self.settings,
            self.expected,
            FakeDeviceIdentities(),
        )
        candidate = OperationRecord(
            id="op-a",
            kind="archive.resume",
            state="running",
            phase=None,
            idempotency_key="key-a",
            principal="synthetic-admin",
            job_id="JOB-SYNTHETIC",
            cassette_sequence=4,
            started_at="2026-08-21T12:00:00+00:00",
            finished_at=None,
        )
        self.catalog.admit_operation(
            candidate,
            self.daemon_fence,
            admission_open=True,
            hardware_target=target,
        )
        self.fence = OperationFence("op-a", self.daemon_fence.generation)
        self.supervisor = RecordingSupervisor(
            self.catalog, self.fence, self.daemon_fence
        )
        self.mount_probe = FakeMountProbe()
        self.media_probe = FakeMediaIdentityProbe()
        self.media_probe.supervisor = self.supervisor
        self.media_probe.fence = self.fence
        self.ltfs_sessions = FakeLtfsSessions()
        self.backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            ltfs_sessions=self.ltfs_sessions,
            executable_resolver=ExecutableResolver(root / "bin"),
        )

    def tearDown(self) -> None:
        self.catalog.close()
        self.temporary.cleanup()

    def test_sysfs_identity_accepts_exact_flat_scsi_alias(self) -> None:
        root = Path(self.temporary.name) / "identity"
        device_root = root / "dev"
        sys_class = root / "sys" / "class"
        device_root.mkdir(parents=True)
        target = device_root / "sg0"
        target.write_bytes(b"")
        alias = device_root / "lto-archiver-scsi-drive-a"
        alias.symlink_to(target)
        unit = root / "sys" / "devices" / "unit-a"
        unit.mkdir(parents=True)
        (unit / "vpd_pg80").write_bytes(b"\x00\x80\x00\x07DRIVE-A")
        class_device = sys_class / "scsi_generic" / "sg0"
        class_device.mkdir(parents=True)
        (class_device / "device").symlink_to(unit, target_is_directory=True)

        provider = SysfsDeviceIdentityProvider(sys_class=sys_class)
        self.assertEqual("DRIVE-A", provider.resolve(alias).serial_token)

        near_misses = (
            root / "dev" / "nested" / "by-id" / "lto-archiver-scsi-drive-a",
            root / "dev" / "lto-archiver-scsi-",
            Path("dev/lto-archiver-scsi-drive-a"),
            root / "dev" / "disk" / "by-id" / "lto-archiver-scsi-drive-a",
            root / "dev" / "lto-archiver-scsi-drive-a" / "extra",
        )
        for path in near_misses:
            with self.subTest(path=path), self.assertRaises(BackendUnavailable):
                provider.resolve(path)

    def test_identify_binds_media_once_and_later_commands_copy_binding(self) -> None:
        identity = self.backend.identify()
        binding = self.catalog.observed_media_binding("op-a")
        self.assertIsNotNone(binding)
        self.assertEqual("MD0004", identity.volume_label)

        self.backend.mount(read_only=False)
        latest = self.catalog.hardware_commands_for_operation("op-a")[-1]
        self.assertEqual(binding, latest.observed_media_identity_sha256)
        ledger = repr(self.catalog.hardware_commands_for_operation("op-a"))
        for raw in (
            "synthetic-tape-a",
            "synthetic-scsi-a",
            "MD0004",
            "SERIAL-A",
            "DRIVE-A",
        ):
            self.assertNotIn(raw, ledger)

    def test_label_and_serial_slash_backslash_are_identity_data_end_to_end(
        self,
    ) -> None:
        expected = ExpectedMedia(
            "archive.resume",
            "JOB-SYNTHETIC",
            4,
            "MEDIA/A\\B",
            "SERIAL/A\\B",
        )
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, expected, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = expected
        self.media_probe.unmounted = replace(
            self.media_probe.unmounted,
            mam_barcode="MEDIA/A\\B",
            mam_volume_serial="SERIAL/A\\B",
            ltfs_volume_label="MEDIA/A\\B",
        )
        self.ltfs_sessions.observed_volume_label_override = "MEDIA/A\\B"

        identity = self.backend.identify()
        mounted = self.backend.mount(read_only=False)

        self.assertEqual("MEDIA/A\\B", identity.volume_label)
        self.assertEqual("MEDIA/A\\B", mounted.session_receipt.observed_volume_label)
        self.assertEqual(
            media_identity_sha256(identity.canonical_fields()),
            mounted.session_receipt.observed_media_identity_sha256,
        )

    def test_identity_mismatch_blocks_without_leaking_raw_identifiers(self) -> None:
        self.media_probe.unmounted = MediaIdentityFields(
            mam_barcode="WRONG-MEDIA", mam_volume_serial="WRONG-SERIAL"
        )
        with self.assertRaises(MediaIdentityError) as raised:
            self.backend.identify()
        message = str(raised.exception)
        self.assertNotIn("WRONG", message)
        self.assertNotIn("MD0004", message)
        self.assertNotIn("SERIAL-A", message)

    def test_observed_mam_serial_is_continuity_not_legacy_identity(self) -> None:
        label_first = replace(self.expected, volume_serial=None)
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, label_first, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = label_first
        self.media_probe.unmounted = replace(
            self.media_probe.unmounted, mam_volume_serial="SERIAL-B"
        )
        before = tuple(self.ltfs_sessions.calls)

        identity = self.backend.identify()
        self.assertEqual("SERIAL-B", identity.mam_volume_serial)
        self.media_probe.unmounted = replace(
            self.media_probe.unmounted, mam_volume_serial="SERIAL-C"
        )
        with self.assertRaises(MediaIdentityError):
            self.backend.identify()
        with self.assertRaises(StaleOperationFence):
            self.backend.mount(read_only=False)

        self.assertEqual(before, tuple(self.ltfs_sessions.calls))
        self.assertEqual(0, len(self.backend._active_ltfs_sessions))

    def test_db_label_must_match_mam_and_ltfs_index_independently(self) -> None:
        self.media_probe.unmounted = replace(
            self.media_probe.unmounted,
            mam_barcode="MD0005",
            ltfs_volume_label="MD0004",
        )
        with self.assertRaises(MediaIdentityError):
            self.backend.identify()
        self.assertIsNone(self.catalog.observed_media_binding("op-a"))
        self.assertEqual((), tuple(self.ltfs_sessions.calls))

    def test_ltfs_label_is_exact_and_never_falls_back_to_mam_barcode(self) -> None:
        before = tuple(self.ltfs_sessions.calls)
        for label in (None, "md0004", " MD0004", "MD0004 "):
            with self.subTest(label=label):
                self.media_probe.unmounted = replace(
                    self.media_probe.unmounted,
                    mam_barcode="MD0004",
                    ltfs_volume_label=label,
                )
                with self.assertRaises(MediaIdentityError):
                    self.backend.identify()
        self.assertEqual(before, tuple(self.ltfs_sessions.calls))

    def test_changed_media_after_binding_forces_recovery_without_retargeting(
        self,
    ) -> None:
        self.backend.identify()
        original = self.catalog.observed_media_binding("op-a")
        self.media_probe.unmounted = MediaIdentityFields(
            mam_barcode="MD0005",
            mam_volume_serial="SERIAL-B",
            ltfs_volume_label="MD0004",
            ltfs_volume_uuid="22222222-2222-4222-8222-222222222222",
            index_generation=7,
        )

        with self.assertRaises(MediaIdentityError):
            self.backend.identify()

        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )
        self.assertEqual(original, self.catalog.observed_media_binding("op-a"))

    def test_readonly_and_writable_mount_options_are_explicit(self) -> None:
        self.backend.identify()
        self.backend.mount(read_only=True)
        readonly = self.ltfs_sessions.calls[-2][1][0]
        self.assertTrue(readonly.read_only)

    def test_mount_is_broker_owned_and_daemon_supervisor_never_sees_ltfs(self) -> None:
        self.backend.identify()
        before = len(self.supervisor.calls)

        mounted = self.backend.mount(read_only=False)

        self.assertEqual(
            ["inquiry"], [kind for kind, _argv in self.supervisor.calls[before:]]
        )
        self.assertEqual("session-a", mounted.session_receipt.session_id)
        self.assertEqual(
            ["start", "observe"], [kind for kind, _ in self.ltfs_sessions.calls]
        )
        self.assertEqual(("fuse.ltfs", "ltfs"), self.mount_probe.expectations[-1])

    def test_mounted_ltfs_label_mismatch_terminates_foreground_process(self) -> None:
        self.backend.identify()
        self.ltfs_sessions.observed_volume_uuid_override = (
            "33333333-3333-4333-8333-333333333333"
        )

        with self.assertRaises(BackendUnavailable):
            self.backend.mount(read_only=False)

        self.assertEqual(
            ["start", "finalize"],
            [kind for kind, _value in self.ltfs_sessions.calls],
        )
        self.assertNotIn(
            "mount",
            [
                command.kind
                for command in self.catalog.hardware_commands_for_operation("op-a")
            ],
        )

    def test_mount_unmount_and_unload_are_separate_and_timed(self) -> None:
        self.backend.identify()
        mounted = self.backend.mount(read_only=False)
        observer = Observer()
        result = self.backend.unmount(mounted, observer)
        receipt = self.backend.unload()

        self.assertEqual(
            ["start", "observe", "finalize"],
            [kind for kind, _value in self.ltfs_sessions.calls],
        )
        self.assertFalse(
            {"mount", "unmount"} & {kind for kind, _argv in self.supervisor.calls}
        )
        self.assertEqual("unload", self.supervisor.calls[-1][0])
        self.assertIsInstance(receipt, CompletedCommand)
        self.assertEqual(0, receipt.returncode)
        self.assertEqual("eject", self.supervisor.calls[-1][1][-1])
        self.assertEqual(
            ["finalization_started", "mount_release_started"], observer.events
        )
        self.assertGreaterEqual(result.finalization_seconds, 0)
        self.assertGreaterEqual(result.mount_release_seconds, 0)
        self.assertFalse(self.mount_probe.is_mounted(mounted.path))

    def test_ltfs_receipt_is_one_backend_session_and_cannot_cross_restart(self) -> None:
        self.backend.identify()
        mounted = self.backend.mount(read_only=False)
        self.backend.unmount(mounted, Observer())
        before = tuple(self.ltfs_sessions.calls)

        with self.assertRaises(MountStateError):
            self.backend.unmount(mounted, Observer())
        tampered = MountedTape(
            mounted.path,
            mounted.read_only,
            replace(mounted.session_receipt, session_id="session-tampered"),
        )
        with self.assertRaises(MountStateError):
            self.backend.unmount(tampered, Observer())

        restarted = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            ltfs_sessions=self.ltfs_sessions,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        with self.assertRaises(MountStateError):
            restarted.unmount(mounted, Observer())
        self.assertEqual(before, tuple(self.ltfs_sessions.calls))

    def test_broker_finalize_failure_moves_authority_out_of_local_backend(self) -> None:
        self.backend.identify()
        mounted = self.backend.mount(read_only=False)
        self.ltfs_sessions.finalize_error = BrokerUnavailable()

        with self.assertRaises(BrokerUnavailable):
            self.backend.unmount(mounted, Observer())

        self.assertEqual(0, len(self.backend._active_ltfs_sessions))
        self.assertIsNotNone(self.ltfs_sessions.pending_handle)
        with self.assertRaises(MountStateError):
            self.backend.unmount(mounted, Observer())

    def test_failed_observe_and_cleanup_leave_one_reachable_pending_handle(
        self,
    ) -> None:
        self.backend.identify()
        self.ltfs_sessions.observe_error = BrokerUnavailable()
        self.ltfs_sessions.finalize_error = BrokerUnavailable()

        with self.assertRaises(BrokerUnavailable):
            self.backend.mount(read_only=False)

        self.assertEqual(
            ["start", "observe", "finalize"],
            [kind for kind, _value in self.ltfs_sessions.calls],
        )
        self.assertEqual(0, len(self.backend._active_ltfs_sessions))

        self.ltfs_sessions.observe_error = None
        with self.assertRaises(BrokerUnavailable):
            self.backend.mount(read_only=False)
        self.assertEqual(
            1,
            sum(kind == "start" for kind, _value in self.ltfs_sessions.calls),
        )
        self.assertEqual(
            1, len([1 for kind, _ in self.ltfs_sessions.calls if kind == "finalize"])
        )
        self.assertEqual(0, len(self.backend._active_ltfs_sessions))

        self.ltfs_sessions.finalize_error = None
        with self.assertRaises(BrokerUnavailable):
            self.backend.mount(read_only=False)
        self.assertEqual(
            1, sum(kind == "start" for kind, _value in self.ltfs_sessions.calls)
        )
        self.assertEqual(0, len(self.backend._active_ltfs_sessions))

    def test_pending_cleanup_mismatch_fails_closed_without_finalize_or_start(
        self,
    ) -> None:
        self.backend.identify()
        self.ltfs_sessions.observe_error = BrokerUnavailable()
        self.ltfs_sessions.finalize_error = BrokerUnavailable()
        with self.assertRaises(BrokerUnavailable):
            self.backend.mount(read_only=False)
        before = tuple(self.ltfs_sessions.calls)

        self.backend.fence = OperationFence("different-operation", 99)
        self.ltfs_sessions.observe_error = None
        self.ltfs_sessions.finalize_error = None
        with self.assertRaises(BackendUnavailable):
            self.backend.mount(read_only=False)

        self.assertEqual(before, tuple(self.ltfs_sessions.calls))
        self.assertEqual(0, len(self.backend._active_ltfs_sessions))

        self.backend.fence = self.fence
        self.backend.settings = replace(
            self.settings, mount_path=self.settings.mount_path.parent / "other-mount"
        )
        with self.assertRaises(BackendUnavailable):
            self.backend.mount(read_only=False)

        self.assertEqual(before, tuple(self.ltfs_sessions.calls))
        self.assertEqual(0, len(self.backend._active_ltfs_sessions))

    def test_production_hook_uses_recovery_fence_for_shared_pending_cleanup(
        self,
    ) -> None:
        source_root = Path(self.temporary.name) / "source-library"
        source = source_root / "folder" / "clip.bin"
        source.parent.mkdir(parents=True)
        source.write_bytes(b"data")
        item = FrozenItem(4, 1, "LIB1", "folder/clip.bin", 4, source.stat().st_mtime_ns)
        plan = FrozenJobPlan(
            "JOB-SYNTHETIC",
            "a" * 64,
            "b" * 64,
            "c" * 64,
            "d" * 64,
            "active_linux",
            (
                FrozenCassette(
                    4,
                    "MD0004",
                    "SERIAL-A",
                    "append",
                    "waiting_media",
                    1,
                    4,
                    None,
                    None,
                    0,
                    0,
                    None,
                    None,
                    None,
                    False,
                    (item,),
                ),
            ),
            (("LIB1", source_root),),
            False,
        )
        label_first = replace(self.expected, volume_serial=None)
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, label_first, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = label_first
        record = OperationRecord(
            "op-a",
            "archive.resume",
            "running",
            None,
            "key-a",
            "synthetic-admin",
            "JOB-SYNTHETIC",
            4,
            "2026-08-21T12:00:00+00:00",
            None,
        )
        outer = self

        class RunnerCatalog:
            def __init__(catalog_self) -> None:
                catalog_self.phase: str | None = None

            def __enter__(catalog_self):
                return catalog_self

            def __exit__(catalog_self, *_args):
                return None

            def assert_operation_fence(catalog_self, fence):
                outer.catalog.assert_operation_fence(fence)

            def transition_imported_cassette_phase(catalog_self, _fence, phase) -> None:
                catalog_self.phase = phase

            def get_operation(catalog_self, operation_id):
                operation = outer.catalog.get_operation(operation_id)
                return {**operation, "phase": catalog_self.phase}

            def finish_operation(catalog_self, fence, state, **kwargs) -> None:
                outer.catalog.finish_operation(fence, state, **kwargs)

        runner_catalog = RunnerCatalog()
        context = OperationContext(record, self.fence, lambda: runner_catalog)

        backup_path = Path(self.temporary.name) / "backup"

        class Backups:
            def create_for_operation(self, _fence, _reason):
                return backup_path

        runner = ArchiveRunner(
            catalog_factory=lambda: runner_catalog,
            backups=Backups(),
            backend=self.backend,
            host_staging_root=Path(self.temporary.name) / "staging",
            buffer_bytes=4096,
            plan_loader=lambda _catalog, _job_id: plan,
            copy_file=lambda _request: (_ for _ in ()).throw(
                AssertionError("copy reached after failed mount")
            ),
            manifest_writer_factory=lambda **_kwargs: (_ for _ in ()).throw(
                AssertionError("manifest reached after failed mount")
            ),
        )
        self.ltfs_sessions.observe_error = BrokerUnavailable()
        self.ltfs_sessions.finalize_error = BrokerUnavailable()
        outcome = runner.resume("JOB-SYNTHETIC", context, lambda: False)
        self.assertEqual("recovery_required", outcome.state)
        current = self.catalog.claim_daemon_owner("daemon-recovery")
        recovery_fence = RecoveryCommandFence("op-a", current.generation)
        before = tuple(self.ltfs_sessions.calls)

        with self.assertRaises(StaleOperationFence):
            self.backend.mount(read_only=False)
        self.assertEqual(before, tuple(self.ltfs_sessions.calls))

        self.catalog.recover_interrupted_operations(current)
        recovery = ProductionArchiveResume.__new__(ProductionArchiveResume)
        recovery._settings = self.settings
        recovery._catalog_factory = lambda: Catalog(self.catalog.path)
        recovery._device_identities = FakeDeviceIdentities()
        recovery._ltfs_sessions = self.ltfs_sessions
        recovery._scope_manager = object()
        recovery._privilege_boundary = object()
        self.ltfs_sessions.observe_error = None
        self.ltfs_sessions.finalize_error = None
        with (
            mock.patch(
                "ltobackup.daemon.archive_runtime.FrozenJobPlan.load",
                return_value=plan,
            ),
            mock.patch(
                "ltobackup.daemon.archive_runtime._production_supervisor",
                return_value=self.supervisor,
            ),
            mock.patch.object(
                Catalog,
                "recover_imported_ltfs_terminal_and_commit",
                return_value="waiting_media",
            ),
        ):
            terminal = recovery.reconcile_pending_ltfs_operation("op-a", recovery_fence)

        self.assertIsNotNone(terminal)
        self.assertTrue(terminal.unmounted)
        self.assertIsNone(self.ltfs_sessions.pending_handle)
        self.assertEqual(
            "recovery_required", self.catalog.get_operation("op-a")["state"]
        )
        self.assertEqual(
            1,
            sum(kind == "start" for kind, _value in self.ltfs_sessions.calls),
        )

    def test_same_generation_outcome_lookup_keeps_the_original_operation_fence(
        self,
    ) -> None:
        self.backend.identify()
        mounted = self.backend.mount(read_only=False)
        self.ltfs_sessions.finalize_error = BrokerUnavailable()
        with self.assertRaises(BrokerUnavailable):
            self.backend.unmount(mounted, Observer())
        self.ltfs_sessions.finalize_error = None

        terminal = self.backend.recover_pending_ltfs_session()

        self.assertIsNotNone(terminal)
        recovery_call = next(
            value for kind, value in self.ltfs_sessions.calls if kind == "recover"
        )
        self.assertIs(type(recovery_call.fence), OperationFence)
        self.assertEqual(self.fence, recovery_call.fence)
        self.assertEqual(
            self.fence.owner_generation,
            recovery_call.original_owner_generation,
        )

    def test_confirmed_finalize_cycles_keep_backend_registry_bounded(self) -> None:
        self.backend.identify()
        for _index in range(100):
            mounted = self.backend.mount(read_only=False)
            self.backend.unmount(mounted, Observer())
            self.assertEqual(0, len(self.backend._active_ltfs_sessions))

    def test_stale_catalog_fence_never_starts_a_broker_ltfs_session(self) -> None:
        self.backend.identify()
        self.catalog.claim_daemon_owner("daemon-b")
        self.ltfs_sessions.calls.clear()

        with self.assertRaises(StaleOperationFence):
            self.backend.mount(read_only=False)

        self.assertEqual([], self.ltfs_sessions.calls)

    def test_wrong_expected_media_scope_never_starts_a_broker_session(self) -> None:
        self.backend.identify()
        self.ltfs_sessions.calls.clear()
        wrong_expected = replace(self.expected, volume_label="MD0005")
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=wrong_expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            ltfs_sessions=self.ltfs_sessions,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )

        with self.assertRaises(BackendUnavailable):
            backend.identify()

        self.assertEqual([], self.ltfs_sessions.calls)

    def test_unmount_never_dispatches_before_both_catalog_phase_barriers(self) -> None:
        class FailingFinalizationObserver(Observer):
            def finalization_started(self) -> None:
                super().finalization_started()
                raise RuntimeError("finalization catalog write failed")

        class FailingObserver(Observer):
            def mount_release_started(self) -> None:
                super().mount_release_started()
                raise RuntimeError("catalog write failed")

        for observer in (FailingFinalizationObserver(), FailingObserver()):
            with self.subTest(observer=type(observer).__name__):
                self.backend.identify()
                mounted = self.backend.mount(read_only=False)
                before = tuple(self.ltfs_sessions.calls)

                with self.assertRaisesRegex(RuntimeError, "catalog write failed"):
                    self.backend.unmount(mounted, observer)

                self.assertEqual(before, tuple(self.ltfs_sessions.calls))
                tracked = self.backend._active_ltfs_sessions.pop(
                    mounted.session_receipt.session_id
                )
                self.ltfs_sessions.finalize_ltfs_session(tracked.handle)

    def test_identity_inquiry_uses_generic_scsi_by_id_path(self) -> None:
        self.backend.identify()
        argv = self.supervisor.calls[0][1]
        self.assertTrue(argv[-1].startswith("/proc/self/fd/"))
        self.assertNotEqual(str(self.settings.tape_device_path), argv[-1])
        self.assertNotEqual(str(self.settings.scsi_device_path), argv[-1])

    def test_preflight_rejects_transient_device_numbering(self) -> None:
        for field, value in (
            ("tape_device_path", Path("/dev/st0")),
            ("scsi_device_path", Path("/dev/sg0")),
        ):
            with self.subTest(field=field):
                values = dict(self.settings.__dict__)
                values[field] = value
                backend = LinuxLtfsBackend(
                    settings=LinuxSettings(**values),
                    expected=self.expected,
                    fence=self.fence,
                    catalog=self.catalog,
                    supervisor=self.supervisor,
                    ltfs_sessions=self.ltfs_sessions,
                    device_identities=FakeDeviceIdentities(),
                    mount_probe=self.mount_probe,
                    media_identity_probe=self.media_probe,
                    executable_resolver=ExecutableResolver(
                        Path(self.temporary.name) / "bin"
                    ),
                )
                with self.assertRaises(BackendUnavailable) as raised:
                    backend.preflight()
                self.assertNotIn(str(value), str(raised.exception))

    def test_preflight_requires_supported_typed_media_probe(self) -> None:
        health = self.backend.preflight()
        self.assertTrue(health.available)
        self.assertEqual(("sg_inq", "mkltfs", "mt"), health.required_tools)

        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        with self.assertRaises(BackendUnavailable):
            backend.preflight()

    def test_vendor_command_never_runs_when_device_paths_are_transient(self) -> None:
        values = dict(self.settings.__dict__)
        values["tape_device_path"] = Path("/dev/st0")
        backend = LinuxLtfsBackend(
            settings=LinuxSettings(**values),
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        before = tuple(self.supervisor.calls)
        with self.assertRaises(MediaIdentityError):
            backend.mount(read_only=False)
        self.assertEqual(before, tuple(self.supervisor.calls))

    def test_mount_verification_uses_mount_probe_not_directory_existence(self) -> None:
        self.settings.mount_path.mkdir(parents=True)
        probe = FakeMountProbe()
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=probe,
            media_identity_probe=self.media_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        backend.identify()
        backend.mount(read_only=False)
        self.assertTrue(probe.is_mounted(self.settings.mount_path))

    def test_drive_identity_mismatch_blocks_format_and_mount(self) -> None:
        self.supervisor.responses["inquiry"] = CompletedCommand(
            0, "Unit serial number: WRONG-DRIVE\n", ""
        )
        with self.assertRaises(MediaIdentityError):
            self.backend.format(self.expected)
        self.supervisor.responses["inquiry"] = CompletedCommand(
            0, "Unit serial number: DRIVE-A\n", ""
        )
        self.backend.identify()
        self.supervisor.responses["inquiry"] = CompletedCommand(
            0, "Unit serial number: WRONG-DRIVE\n", ""
        )
        with self.assertRaises(MediaIdentityError):
            self.backend.mount(read_only=False)

    def test_drive_identity_accepts_indented_sg_inq_serial(self) -> None:
        self.supervisor.responses["identify"] = CompletedCommand(
            0, "  Unit serial number: DRIVE-A\n", ""
        )

        identity = self.backend.identify()

        self.assertEqual("DRIVE-A", identity.drive_serial)

    def test_tape_and_scsi_paths_must_resolve_to_same_scsi_unit(self) -> None:
        class MismatchedDeviceIdentities:
            def resolve(self, path: Path) -> StableDeviceIdentity:
                unit = (
                    "unit-tape" if path == self.settings.tape_device_path else "unit-sg"
                )
                return StableDeviceIdentity(path.name, "DRIVE-A", unit)

        identities = MismatchedDeviceIdentities()
        identities.settings = self.settings
        with self.assertRaises(BackendUnavailable):
            LinuxLtfsBackend.target_binding_from(
                self.settings, self.expected, identities
            )

    def test_scsi_unit_pair_is_rechecked_before_destructive_command(self) -> None:
        class ChangedPair(FakeDeviceIdentities):
            def resolve(self, path: Path) -> StableDeviceIdentity:
                unit = "unit-a" if path == self.settings.tape_device_path else "unit-b"
                return StableDeviceIdentity(path.name, "DRIVE-A", unit)

        identities = ChangedPair()
        identities.settings = self.settings
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=identities,
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        before = tuple(self.supervisor.calls)

        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            self.assertRaises(BackendUnavailable),
        ):
            backend.identify_preformat()

        self.assertEqual(before, tuple(self.supervisor.calls))

    def test_format_and_mount_use_anchored_device_fds_at_launch(self) -> None:
        class FormatProbe:
            def __init__(probe_self) -> None:
                probe_self.calls = 0

            def preflight(probe_self) -> None:
                return None

            def identify_unmounted(probe_self) -> MediaIdentityFields:
                self.supervisor.run(
                    self.fence,
                    "probe_media",
                    ("synthetic-media-probe",),
                    1.0,
                )
                probe_self.calls += 1
                if probe_self.calls <= 2:
                    return MediaIdentityFields(
                        mam_barcode="MD0004",
                        mam_volume_serial="SERIAL-A",
                    )
                return MediaIdentityFields(
                    mam_barcode="MD0004",
                    mam_volume_serial="SERIAL-A",
                    ltfs_volume_label="MD0004",
                    ltfs_volume_uuid="33333333-3333-4333-8333-333333333333",
                    index_generation=1,
                )

            def identify_mounted(probe_self, _path: Path) -> MediaIdentityFields:
                raise AssertionError("mounted probe is not part of format rebinding")

        self.backend.media_identity_probe = FormatProbe()

        def rebind(**kwargs) -> None:
            self.catalog.connection.execute(
                "UPDATE operation_media_identity_bindings SET "
                "observed_media_identity_sha256=? WHERE operation_id=?",
                (kwargs["post_media_identity_sha256"], self.fence.operation_id),
            )
            self.catalog.connection.commit()

        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            mock.patch.object(
                self.catalog,
                "rebind_observed_media_after_confirmed_format",
                side_effect=lambda _fence, **kwargs: rebind(**kwargs),
            ) as rebind_call,
        ):
            self.backend.identify_preformat()
            self.backend.format(self.expected)
        self.assertEqual("probe_media", self.supervisor.calls[-1][0])
        format_argv = next(
            argv for kind, argv in self.supervisor.calls if kind == "format"
        )
        inquiry_argv = next(
            argv for kind, argv in reversed(self.supervisor.calls) if kind == "inquiry"
        )
        self.assertEqual(
            inquiry_argv[1], format_argv[format_argv.index("--device") + 1]
        )
        self.assertTrue(
            any(value.startswith("/proc/self/fd/") for value in format_argv)
        )
        self.assertEqual(1, format_argv.count("--force"))
        rebind_call.assert_called_once()

        self.backend.mount(read_only=False)
        admission, tape_fd, scsi_fd = self.ltfs_sessions.calls[-2][1]
        self.assertEqual("op-a", admission.operation_id)
        self.assertEqual(
            "33333333-3333-4333-8333-333333333333",
            admission.expected_volume_uuid,
        )
        self.assertEqual(1, admission.expected_prior_generation)
        self.assertEqual(
            self.catalog.observed_media_binding(self.fence.operation_id),
            admission.observed_media_identity_sha256,
        )
        self.assertNotEqual(tape_fd, scsi_fd)

    def test_preformat_rejects_mam_label_mismatch_before_format(self) -> None:
        self.backend.media_identity_probe = SequencedFormatProbe(
            MediaIdentityFields(
                mam_barcode="WRONG-LABEL",
                mam_volume_serial="SERIAL-A",
            ),
            self.media_probe.unmounted,
            self.supervisor,
            self.fence,
        )
        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            mock.patch.object(self.catalog, "record_audit") as record_audit,
        ):
            for _ in range(2):
                with self.assertRaises(MediaIdentityError):
                    self.backend.identify_preformat()
        self.assertIsNone(self.catalog.observed_media_binding(self.fence.operation_id))
        self.assertFalse(any(kind == "format" for kind, _argv in self.supervisor.calls))
        record_audit.assert_called_once()
        self.assertEqual(
            ["expected_serial_mismatch", "mam_label_mismatch"],
            record_audit.call_args.args[-1]["reason_codes"],
        )

    def test_label_first_preformat_accepts_absent_mam_barcode(self) -> None:
        label_first = replace(self.expected, volume_serial=None)
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, label_first, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = label_first
        self.backend.media_identity_probe = SequencedFormatProbe(
            MediaIdentityFields(
                mam_barcode=None,
                mam_volume_serial="SERIAL-A",
            ),
            self.media_probe.unmounted,
            self.supervisor,
            self.fence,
        )

        with mock.patch.object(self.catalog, "require_consumed_format_confirmation"):
            try:
                observed = self.backend.identify_preformat()
            except MediaIdentityError:
                self.fail("an absent MAM barcode must not reject pre-format media")

        self.assertIsNone(observed.mam_barcode)
        self.assertEqual("SERIAL-A", observed.mam_volume_serial)
        self.assertIsNotNone(
            self.catalog.observed_media_binding(self.fence.operation_id)
        )

    def test_preformat_and_continuity_use_the_driver_preformat_probe(self) -> None:
        """Using unmounted mode here makes an inserted virgin tape look absent."""

        outer = self

        class ModeStrictProbe:
            def __init__(probe_self) -> None:
                probe_self.preformat_calls = 0
                probe_self.unmounted_calls = 0

            def preflight(probe_self) -> None:
                return None

            def identify_preformat(probe_self) -> MediaIdentityFields:
                outer.supervisor.run(
                    outer.fence,
                    "probe_media",
                    ("synthetic-preformat-media-probe",),
                    1.0,
                )
                probe_self.preformat_calls += 1
                return MediaIdentityFields(
                    mam_barcode="MD0004",
                    mam_volume_serial="SERIAL-A",
                )

            def identify_unmounted(probe_self) -> MediaIdentityFields:
                outer.supervisor.run(
                    outer.fence,
                    "probe_media",
                    ("synthetic-unmounted-media-probe",),
                    1.0,
                )
                probe_self.unmounted_calls += 1
                if not any(kind == "format" for kind, _argv in outer.supervisor.calls):
                    raise AssertionError(
                        "unmounted probe cannot identify virgin pre-format media"
                    )
                return MediaIdentityFields(
                    mam_barcode="MD0004",
                    mam_volume_serial="SERIAL-A",
                    ltfs_volume_label="MD0004",
                    ltfs_volume_uuid="33333333-3333-4333-8333-333333333333",
                    index_generation=1,
                )

            def identify_mounted(
                probe_self, _path: Path
            ) -> MediaIdentityFields:
                raise AssertionError("mounted probe is not part of formatting")

        probe = ModeStrictProbe()
        self.backend.media_identity_probe = probe
        with (
            mock.patch.object(
                self.catalog, "require_consumed_format_confirmation"
            ),
            mock.patch.object(
                self.catalog, "rebind_observed_media_after_confirmed_format"
            ),
        ):
            self.backend.identify_preformat()
            self.backend.format(self.expected)

        self.assertEqual(2, probe.preformat_calls)
        self.assertEqual(1, probe.unmounted_calls)

    def test_preformat_records_closed_field_validation_reason_once(self) -> None:
        self.backend.media_identity_probe = SequencedFormatProbe(
            replace(self.media_probe.unmounted, mam_barcode="MD0004 "),
            self.media_probe.unmounted,
            self.supervisor,
            self.fence,
        )

        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            mock.patch.object(self.catalog, "record_audit") as record_audit,
            self.assertRaises(MediaIdentityError),
        ):
            self.backend.identify_preformat()

        record_audit.assert_called_once()
        self.assertEqual(
            ["mam_barcode_invalid"],
            record_audit.call_args.args[-1]["reason_codes"],
        )

    def test_preformat_records_closed_probe_exit_once(self) -> None:
        class FailedProbe:
            def identify_unmounted(self):
                raise CommandFailed("probe_media", 64)

        self.backend.media_identity_probe = FailedProbe()
        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            mock.patch.object(self.catalog, "record_audit") as record_audit,
            self.assertRaises(MediaIdentityError),
        ):
            self.backend.identify_preformat()

        record_audit.assert_called_once()
        self.assertEqual(
            ["probe_command_exit_64"],
            record_audit.call_args.args[-1]["reason_codes"],
        )

    def test_serial_bound_preformat_rejects_unbarcoded_or_wrong_serial_media(
        self,
    ) -> None:
        expected = replace(
            self.expected,
            volume_label="TAPE04",
            volume_serial="Q210531120",
        )
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, expected, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = expected
        invalid = (
            MediaIdentityFields(mam_barcode=None, mam_volume_serial=None),
            MediaIdentityFields(
                mam_barcode=None,
                mam_volume_serial="Q210531120",
            ),
            MediaIdentityFields(
                mam_barcode="TAPE04",
                mam_volume_serial="WRONG-SERIAL",
            ),
        )

        for index, fields in enumerate(invalid):
            with self.subTest(index=index):
                self.backend.media_identity_probe = SequencedFormatProbe(
                    fields,
                    self.media_probe.unmounted,
                    self.supervisor,
                    self.fence,
                )
                before = tuple(self.supervisor.calls)
                with (
                    mock.patch.object(
                        self.catalog, "require_consumed_format_confirmation"
                    ),
                    self.assertRaises(MediaIdentityError),
                ):
                    self.backend.identify_preformat()
                self.assertFalse(
                    any(kind == "format" for kind, _argv in self.supervisor.calls)
                )
                self.assertEqual(
                    ["identify", "probe_media"],
                    [kind for kind, _argv in self.supervisor.calls[len(before) :]],
                )

    def test_preformat_swap_blank_or_wrong_serial_is_refused_before_format(
        self,
    ) -> None:
        expected = replace(
            self.expected,
            volume_label="TAPE04",
            volume_serial="Q210531120",
        )
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, expected, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = expected
        admitted = MediaIdentityFields(
            mam_barcode="TAPE04",
            mam_volume_serial="Q210531120",
        )
        substituted = (
            MediaIdentityFields(),
            MediaIdentityFields(
                mam_barcode=None,
                mam_volume_serial="Q210531120",
            ),
            MediaIdentityFields(
                mam_barcode="TAPE04",
                mam_volume_serial="SWAPPED-SERIAL",
            ),
        )

        for index, current in enumerate(substituted):
            with self.subTest(index=index):
                self.catalog.connection.execute(
                    "DELETE FROM operation_media_identity_bindings "
                    "WHERE operation_id='op-a'"
                )
                self.catalog.connection.commit()
                self.supervisor.calls.clear()
                self.backend.media_identity_probe = MediaSequenceProbe(
                    (admitted, current),
                    self.supervisor,
                    self.fence,
                )

                with mock.patch.object(
                    self.catalog, "require_consumed_format_confirmation"
                ):
                    self.backend.identify_preformat()
                    with self.assertRaises(MediaIdentityError):
                        self.backend.format(expected)

                self.assertEqual(
                    ["identify", "probe_media", "inquiry", "probe_media"],
                    [kind for kind, _argv in self.supervisor.calls],
                )
                self.assertFalse(
                    any(kind == "format" for kind, _ in self.supervisor.calls)
                )
                self.assertIsNone(self.backend._preformat_media_snapshot)

    def test_format_sets_matching_ansi_barcode_for_six_character_label(self) -> None:
        ansi_label = "TAPE04"
        expected = replace(
            self.expected,
            volume_label=ansi_label,
            volume_serial=None,
        )
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, expected, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = expected
        self.backend.media_identity_probe = SequencedFormatProbe(
            MediaIdentityFields(
                mam_barcode=ansi_label,
                mam_volume_serial="SERIAL-A",
            ),
            MediaIdentityFields(
                mam_barcode=ansi_label,
                mam_volume_serial="SERIAL-A",
                ltfs_volume_label=ansi_label,
                ltfs_volume_uuid="33333333-3333-4333-8333-333333333333",
                index_generation=1,
            ),
            self.supervisor,
            self.fence,
        )

        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            mock.patch.object(
                self.catalog, "rebind_observed_media_after_confirmed_format"
            ),
        ):
            self.backend.identify_preformat()
            self.backend.format(expected)

        format_argv = next(
            argv for kind, argv in self.supervisor.calls if kind == "format"
        )
        self.assertEqual(
            ("--volume-name", ansi_label, "--tape-serial", ansi_label),
            format_argv[-4:],
        )

    def test_format_uses_observed_mam_for_continuity_not_legacy_serial(self) -> None:
        label_first = replace(self.expected, volume_serial=None)
        target = LinuxLtfsBackend.target_binding_from(
            self.settings, label_first, FakeDeviceIdentities()
        )
        self.catalog.connection.execute(
            "UPDATE operation_hardware_targets SET expected_media_scope_sha256=? "
            "WHERE operation_id='op-a'",
            (target.expected_media_scope_sha256,),
        )
        self.catalog.connection.commit()
        self.backend.expected = label_first
        observed_mam = "MAM-0401-DIFFERENT-FROM-LEGACY"
        self.backend.media_identity_probe = SequencedFormatProbe(
            MediaIdentityFields(
                mam_barcode="MD0004",
                mam_volume_serial=observed_mam,
            ),
            MediaIdentityFields(
                mam_barcode="MD0004",
                mam_volume_serial=observed_mam,
                ltfs_volume_label="MD0004",
                ltfs_volume_uuid="33333333-3333-4333-8333-333333333333",
                index_generation=1,
            ),
            self.supervisor,
            self.fence,
        )

        with (
            mock.patch.object(self.catalog, "require_consumed_format_confirmation"),
            mock.patch.object(
                self.catalog, "rebind_observed_media_after_confirmed_format"
            ) as rebind,
        ):
            self.backend.identify_preformat()
            self.backend.format(label_first)

        rebind.assert_called_once()
        self.assertEqual(observed_mam, rebind.call_args.kwargs["pre_observed_serial"])
        self.assertEqual(observed_mam, rebind.call_args.kwargs["observed_serial"])

    def test_postformat_rejects_label_serial_or_incomplete_ltfs_identity(self) -> None:
        invalid_postformat = (
            MediaIdentityFields(
                mam_barcode="WRONG-LABEL",
                mam_volume_serial="SERIAL-A",
                ltfs_volume_label="MD0004",
                ltfs_volume_uuid="33333333-3333-4333-8333-333333333333",
                index_generation=1,
            ),
            MediaIdentityFields(
                mam_barcode="MD0004",
                mam_volume_serial="WRONG-SERIAL",
                ltfs_volume_label="MD0004",
                ltfs_volume_uuid="33333333-3333-4333-8333-333333333333",
                index_generation=1,
            ),
            MediaIdentityFields(
                mam_barcode="MD0004",
                mam_volume_serial="SERIAL-A",
                ltfs_volume_label="MD0004",
            ),
        )
        for index, postformat in enumerate(invalid_postformat):
            with self.subTest(index=index):
                database = Path(self.temporary.name) / f"postformat-{index}.db"
                self.catalog.backup_to(database)
                with Catalog(database) as catalog:
                    supervisor = RecordingSupervisor(
                        catalog, self.fence, self.daemon_fence
                    )
                    backend = LinuxLtfsBackend(
                        settings=self.settings,
                        expected=self.expected,
                        fence=self.fence,
                        catalog=catalog,
                        supervisor=supervisor,
                        ltfs_sessions=FakeLtfsSessions(),
                        device_identities=FakeDeviceIdentities(),
                        mount_probe=FakeMountProbe(),
                        media_identity_probe=SequencedFormatProbe(
                            MediaIdentityFields(
                                mam_barcode="MD0004",
                                mam_volume_serial="SERIAL-A",
                            ),
                            postformat,
                            supervisor,
                            self.fence,
                        ),
                        executable_resolver=ExecutableResolver(
                            Path(self.temporary.name) / "bin"
                        ),
                    )
                    with (
                        mock.patch.object(
                            catalog, "require_consumed_format_confirmation"
                        ),
                        mock.patch.object(
                            catalog, "rebind_observed_media_after_confirmed_format"
                        ) as rebind,
                    ):
                        backend.identify_preformat()
                        with self.assertRaises(MediaIdentityError):
                            backend.format(self.expected)
                    rebind.assert_not_called()

    def test_failed_mkltfs_never_rebinds_postformat_identity(self) -> None:
        self.backend.media_identity_probe = SequencedFormatProbe(
            MediaIdentityFields(
                mam_barcode="MD0004",
                mam_volume_serial="SERIAL-A",
            ),
            self.media_probe.unmounted,
            self.supervisor,
            self.fence,
        )
        with mock.patch.object(self.catalog, "require_consumed_format_confirmation"):
            self.backend.identify_preformat()
        original_run = self.backend._run

        def fail_format(kind, argv, timeout=None, pass_fds=()):
            if kind == "format":
                raise RuntimeError("synthetic mkltfs failure")
            return original_run(kind, argv, timeout, pass_fds)

        with (
            mock.patch.object(self.backend, "_run", side_effect=fail_format),
            mock.patch.object(
                self.catalog, "rebind_observed_media_after_confirmed_format"
            ) as rebind,
            self.assertRaisesRegex(RuntimeError, "mkltfs failure"),
        ):
            self.backend.format(self.expected)
        rebind.assert_not_called()

    def test_retargeted_anchored_pair_blocks_format_and_mount_before_exec(self) -> None:
        class RetargetedPair(FakeDeviceIdentities):
            def open_pair(self, tape_path: Path, scsi_path: Path) -> AnchoredDevicePair:
                return AnchoredDevicePair(
                    tape=StableDeviceIdentity(tape_path.name, "DRIVE-B", "unit-b"),
                    scsi=StableDeviceIdentity(scsi_path.name, "DRIVE-B", "unit-b"),
                    tape_exec_path=Path("/proc/self/fd/201"),
                    scsi_exec_path=Path("/proc/self/fd/202"),
                )

        for action in ("format", "mount"):
            with self.subTest(action=action):
                backend = LinuxLtfsBackend(
                    settings=self.settings,
                    expected=self.expected,
                    fence=self.fence,
                    catalog=self.catalog,
                    supervisor=self.supervisor,
                    ltfs_sessions=self.ltfs_sessions,
                    device_identities=RetargetedPair(),
                    mount_probe=self.mount_probe,
                    media_identity_probe=self.media_probe,
                    executable_resolver=ExecutableResolver(
                        Path(self.temporary.name) / "bin"
                    ),
                )
                before = tuple(self.supervisor.calls)
                with self.assertRaises(
                    BackendUnavailable if action == "format" else MediaIdentityError
                ):
                    if action == "format":
                        with mock.patch.object(
                            self.catalog, "require_consumed_format_confirmation"
                        ):
                            backend.identify_preformat()
                    else:
                        backend.mount(read_only=False)
                self.assertEqual(before, tuple(self.supervisor.calls))

    def test_media_identity_uses_typed_probe_not_sg_inq_invented_fields(self) -> None:
        class Probe:
            def __init__(probe_self) -> None:
                probe_self.supervisor = self.supervisor
                probe_self.fence = self.fence

            def preflight(self) -> None:
                return None

            def identify_unmounted(self) -> MediaIdentityFields:
                self.supervisor.run(
                    self.fence,
                    "probe_media",
                    ("synthetic-media-probe",),
                    1.0,
                )
                return MediaIdentityFields(
                    mam_barcode="MD0004",
                    mam_volume_serial="SERIAL-A",
                    ltfs_volume_label="MD0004",
                    ltfs_volume_uuid="22222222-2222-4222-8222-222222222222",
                    index_generation=7,
                )

            def identify_mounted(self, path: Path) -> MediaIdentityFields:
                return MediaIdentityFields(ltfs_volume_label="MD0004")

        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=Probe(),
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        backend.identify()
        self.assertEqual(
            "Unit serial number: DRIVE-A\n",
            self.supervisor.responses["identify"].stdout,
        )

    def test_recovery_identify_validates_existing_digest_without_rebinding(
        self,
    ) -> None:
        self.backend.identify()
        original = self.catalog.observed_media_binding("op-a")
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        recovery_fence = RecoveryCommandFence("op-a", current.generation)
        supervisor = RecordingSupervisor(self.catalog, recovery_fence, current)
        self.media_probe.supervisor = supervisor
        self.media_probe.fence = recovery_fence
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=recovery_fence,
            catalog=self.catalog,
            supervisor=supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )

        identity = backend.identify()

        self.assertEqual("MD0004", identity.volume_label)
        self.assertEqual(original, self.catalog.observed_media_binding("op-a"))

    def test_recovery_identify_mismatch_does_not_replace_observed_digest(self) -> None:
        self.backend.identify()
        original = self.catalog.observed_media_binding("op-a")
        current = self.catalog.claim_daemon_owner("daemon-b")
        self.catalog.recover_interrupted_operations(current)
        self.media_probe.unmounted = MediaIdentityFields(
            mam_barcode="MD0005", mam_volume_serial="SERIAL-B"
        )
        recovery_fence = RecoveryCommandFence("op-a", current.generation)
        recovery_supervisor = RecordingSupervisor(self.catalog, recovery_fence, current)
        self.media_probe.supervisor = recovery_supervisor
        self.media_probe.fence = recovery_fence
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=recovery_fence,
            catalog=self.catalog,
            supervisor=recovery_supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )

        with self.assertRaises(MediaIdentityError):
            backend.identify()

        self.assertEqual(original, self.catalog.observed_media_binding("op-a"))

    def test_wait_for_media_has_bounded_deadline_and_backoff(self) -> None:
        clock = FakeClock()
        self.media_probe.unmounted = MediaIdentityFields(mam_barcode="OTHER")
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=self.media_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            media_wait_timeout=2.5,
            media_poll_seconds=1.0,
        )

        self.assertFalse(backend.wait_for_media(self.expected, lambda: False))
        self.assertEqual([1.0, 1.0, 0.5], clock.sleeps)

    def test_backend_timeouts_must_be_finite_positive_and_bounded(self) -> None:
        for field, value in (
            ("command_timeout", 0.0),
            ("release_timeout", float("nan")),
            ("media_wait_timeout", float("inf")),
            ("media_poll_seconds", 61.0),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                options = {
                    "settings": self.settings,
                    "expected": self.expected,
                    "fence": self.fence,
                    "catalog": self.catalog,
                    "supervisor": self.supervisor,
                    "ltfs_sessions": self.ltfs_sessions,
                    "device_identities": FakeDeviceIdentities(),
                    "mount_probe": self.mount_probe,
                    "media_identity_probe": self.media_probe,
                    "executable_resolver": ExecutableResolver(
                        Path(self.temporary.name) / "bin"
                    ),
                    field: value,
                }
                LinuxLtfsBackend(**options)
        for value in (0.0, float("nan"), float("inf"), 61.0):
            with self.subTest(mount_poll_seconds=value), self.assertRaises(ValueError):
                ProcMountInfoProbe(poll_seconds=value)

    def test_default_media_probe_fails_closed_without_guessing_vendor_output(
        self,
    ) -> None:
        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )
        with self.assertRaises(BackendUnavailable):
            backend.preflight()
        with self.assertRaises(BackendUnavailable):
            backend.identify()

    def test_hostile_media_probe_exception_is_redacted_during_identify(self) -> None:
        class HostileProbe(FakeMediaIdentityProbe):
            def __init__(self, error: Exception) -> None:
                super().__init__()
                self.error = error

            def identify_unmounted(self) -> MediaIdentityFields:
                raise self.error

        for error, expected_error in (
            (RuntimeError("/private/device RAW-MEDIA-ID"), MediaIdentityError),
            (BackendUnavailable("/private/device RAW-MEDIA-ID"), BackendUnavailable),
        ):
            with self.subTest(error=type(error).__name__):
                backend = LinuxLtfsBackend(
                    settings=self.settings,
                    expected=self.expected,
                    fence=self.fence,
                    catalog=self.catalog,
                    supervisor=self.supervisor,
                    ltfs_sessions=self.ltfs_sessions,
                    device_identities=FakeDeviceIdentities(),
                    mount_probe=self.mount_probe,
                    media_identity_probe=HostileProbe(error),
                    executable_resolver=ExecutableResolver(
                        Path(self.temporary.name) / "bin"
                    ),
                )
                with self.assertRaises(expected_error) as raised:
                    backend.identify()
                self.assertNotIn("RAW-MEDIA-ID", str(raised.exception))
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)

    def test_hostile_media_probe_exception_is_redacted_during_mount(self) -> None:
        class HostileProbe(FakeMediaIdentityProbe):
            def __init__(self, error: Exception) -> None:
                super().__init__()
                self.error = error

            def identify_unmounted(self) -> MediaIdentityFields:
                raise self.error

        for error, expected_error in (
            (RuntimeError("/private/mount RAW-LTFS-ID"), MediaIdentityError),
            (BackendUnavailable("/private/mount RAW-LTFS-ID"), BackendUnavailable),
        ):
            with self.subTest(error=type(error).__name__):
                backend = LinuxLtfsBackend(
                    settings=self.settings,
                    expected=self.expected,
                    fence=self.fence,
                    catalog=self.catalog,
                    supervisor=self.supervisor,
                    ltfs_sessions=self.ltfs_sessions,
                    device_identities=FakeDeviceIdentities(),
                    mount_probe=self.mount_probe,
                    media_identity_probe=HostileProbe(error),
                    executable_resolver=ExecutableResolver(
                        Path(self.temporary.name) / "bin"
                    ),
                )
                with self.assertRaises(expected_error) as raised:
                    backend.identify()
                self.assertNotIn("RAW-LTFS-ID", str(raised.exception))
                self.assertIsNone(raised.exception.__cause__)
                self.assertIsNone(raised.exception.__context__)

    def test_hostile_media_field_access_stays_inside_redacted_boundary(self) -> None:
        class HostileString(str):
            def strip(self, *args, **kwargs):
                raise RuntimeError("/private/device RAW-FIELD-ID")

        self.media_probe.unmounted = MediaIdentityFields(
            mam_barcode=HostileString("MD0004"), mam_volume_serial="SERIAL-A"
        )

        try:
            self.backend.identify()
        except Exception as exc:  # noqa: BLE001 - inspect the public boundary
            self.assertIsInstance(exc, MediaIdentityError)
            self.assertNotIn("RAW-FIELD-ID", str(exc))
            self.assertIsNone(exc.__cause__)
            self.assertIsNone(exc.__context__)
        else:
            self.fail("hostile string subclass was accepted")

    def test_media_probe_fields_are_plain_strings_with_bounded_length(self) -> None:
        self.media_probe.unmounted = MediaIdentityFields(
            mam_barcode="MD0004",
            mam_volume_serial="SERIAL-A",
            ltfs_volume_label="MD0004",
            ltfs_volume_uuid="X" * 1025,
            index_generation=7,
        )

        with self.assertRaises(MediaIdentityError):
            self.backend.identify()

    def test_media_probe_fields_reject_every_unicode_other_category(self) -> None:
        for category, unsafe_character in (
            ("Cc", "\u0085"),
            ("Cf", "\u202e"),
            ("Co", "\ue000"),
            ("Cs", "\ud800"),
            ("Cn", "\u0378"),
        ):
            with self.subTest(category=category):
                self.media_probe.unmounted = MediaIdentityFields(
                    mam_barcode="MD0004",
                    mam_volume_serial="SERIAL-A",
                    ltfs_volume_label="MD0004",
                    ltfs_volume_uuid=f"UUID{unsafe_character}",
                    index_generation=7,
                )
                with self.assertRaises(MediaIdentityError):
                    self.backend.identify()

    def test_probe_unavailable_error_is_stable_redacted_and_context_free(self) -> None:
        class UnavailableProbe(FakeMediaIdentityProbe):
            def identify_unmounted(self) -> MediaIdentityFields:
                raise BackendUnavailable("/private/device RAW-PROBE-ID")

        backend = LinuxLtfsBackend(
            settings=self.settings,
            expected=self.expected,
            fence=self.fence,
            catalog=self.catalog,
            supervisor=self.supervisor,
            ltfs_sessions=self.ltfs_sessions,
            device_identities=FakeDeviceIdentities(),
            mount_probe=self.mount_probe,
            media_identity_probe=UnavailableProbe(),
            executable_resolver=ExecutableResolver(Path(self.temporary.name) / "bin"),
        )

        with self.assertRaises(BackendUnavailable) as raised:
            backend.identify()
        self.assertEqual("MediaProbeUnavailable", type(raised.exception).__name__)
        self.assertEqual("media identity probe unavailable", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertIsNone(raised.exception.__context__)

    def test_proc_mount_probe_parses_mountinfo_instead_of_directory_state(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        mountinfo.write_text(
            "41 32 0:39 / /synthetic/mount\\040a rw,nosuid - fuse.ltfs ltfs rw\n",
            encoding="utf-8",
        )
        probe = ProcMountInfoProbe(mountinfo)
        existing_but_unmounted = Path(self.temporary.name) / "empty-directory"
        existing_but_unmounted.mkdir()
        self.assertTrue(probe.is_mounted(Path("/synthetic/mount a")))
        self.assertFalse(probe.is_mounted(existing_but_unmounted))

    def test_proc_mount_probe_rejects_wrong_fs_type_or_source(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        mountinfo.write_text(
            "41 32 0:39 / /synthetic/mount rw - ext4 ltfs rw\n"
            "42 32 0:40 / /synthetic/other rw - fuse.ltfs wrong-source rw\n",
            encoding="utf-8",
        )
        probe = ProcMountInfoProbe(mountinfo)
        self.assertFalse(
            probe.is_mounted(
                Path("/synthetic/mount"),
                filesystem_type="fuse.ltfs",
                source="ltfs",
            )
        )
        self.assertTrue(probe.is_path_mounted(Path("/synthetic/mount")))
        self.assertTrue(probe.is_path_mounted(Path("/synthetic/other")))
        self.assertFalse(
            probe.is_mounted(
                Path("/synthetic/other"),
                filesystem_type="fuse.ltfs",
                source="ltfs",
            )
        )

    def test_proc_mount_probe_requires_exact_ltfs_to_be_the_effective_mount(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        bind_record = "41 32 0:39 / /synthetic/mount rw - ext4 /dev/root rw\n"
        ltfs_above_bind = (
            "42 41 0:40 / /synthetic/mount rw - fuse.ltfs ltfs rw\n"
        )
        probe = ProcMountInfoProbe(mountinfo)

        mountinfo.write_text(bind_record + ltfs_above_bind, encoding="utf-8")
        self.assertTrue(probe.is_mounted(Path("/synthetic/mount")))

        bind_above_ltfs = (
            "43 42 0:41 / /synthetic/mount rw - ext4 /dev/root rw\n"
        )
        mountinfo.write_text(ltfs_above_bind + bind_above_ltfs, encoding="utf-8")
        self.assertFalse(probe.is_mounted(Path("/synthetic/mount")))

        ambiguous_sibling = (
            "43 41 0:41 / /synthetic/mount rw - ext4 /dev/root rw\n"
        )
        mountinfo.write_text(
            ltfs_above_bind + ambiguous_sibling,
            encoding="utf-8",
        )
        self.assertFalse(probe.is_mounted(Path("/synthetic/mount")))

    def test_proc_mount_probe_distinguishes_service_bind_from_fuse_mount(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        bind_record = "41 32 0:39 / /synthetic/mount rw - ext4 /dev/root rw\n"
        fuse_record = (
            "42 41 0:40 / /synthetic/mount rw - fuse.ltfs ltfs rw\n"
        )
        probe = ProcMountInfoProbe(mountinfo)

        mountinfo.write_text(bind_record, encoding="utf-8")
        self.assertTrue(probe.is_path_mounted(Path("/synthetic/mount")))
        self.assertFalse(probe.has_fuse_mount(Path("/synthetic/mount")))

        mountinfo.write_text(bind_record + fuse_record, encoding="utf-8")
        self.assertTrue(probe.has_fuse_mount(Path("/synthetic/mount")))

    def test_await_unmounted_waits_for_ltfs_then_ignores_systemd_bind_mount(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        bind_record = "41 32 0:39 / /synthetic/mount rw - ext4 /dev/root rw\n"
        mountinfo.write_text(
            bind_record
            + "42 41 0:40 / /synthetic/mount rw - fuse.ltfs ltfs rw\n",
            encoding="utf-8",
        )

        class TransitionClock(FakeClock):
            def sleep(self, seconds: float) -> None:
                super().sleep(seconds)
                mountinfo.write_text(bind_record, encoding="utf-8")

        clock = TransitionClock()
        probe = ProcMountInfoProbe(
            mountinfo,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
        )

        probe.await_unmounted(Path("/synthetic/mount"), 1.0)

        self.assertEqual([0.05], clock.sleeps)

    def test_await_unmounted_times_out_or_rejects_an_unexpected_fuse_mount(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        clock = FakeClock()
        probe = ProcMountInfoProbe(
            mountinfo,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.05,
        )
        mountinfo.write_text(
            "42 41 0:40 / /synthetic/mount rw - fuse.ltfs ltfs rw\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MountStateError, "did not become unmounted"):
            probe.await_unmounted(Path("/synthetic/mount"), 0.1)

        mountinfo.write_text(
            "42 41 0:40 / /synthetic/mount rw - fuse.ltfs foreign rw\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MountStateError, "unexpected FUSE"):
            probe.await_unmounted(Path("/synthetic/mount"), 1.0)

        mountinfo.write_text(
            "42 41 0:40 / /synthetic/mount rw - fuse.sshfs foreign rw\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(MountStateError, "unexpected FUSE"):
            probe.await_unmounted(Path("/synthetic/mount"), 1.0)

    def test_await_unmounted_rejects_foreign_fuse_beside_exact_ltfs_immediately(self) -> None:
        mountinfo = Path(self.temporary.name) / "mountinfo"
        mountinfo.write_text(
            "42 41 0:40 / /synthetic/mount rw - fuse.ltfs ltfs rw\n"
            "43 42 0:41 / /synthetic/mount rw - fuse.sshfs foreign rw\n",
            encoding="utf-8",
        )
        clock = FakeClock()
        probe = ProcMountInfoProbe(
            mountinfo,
            monotonic=clock.monotonic,
            sleep=clock.sleep,
            poll_seconds=0.05,
        )

        with self.assertRaisesRegex(MountStateError, "unexpected FUSE"):
            probe.await_unmounted(Path("/synthetic/mount"), 1.0)

        self.assertEqual([], clock.sleeps)


if __name__ == "__main__":
    unittest.main()
