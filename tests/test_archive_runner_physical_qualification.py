from __future__ import annotations

import gc
import hashlib
import inspect
import io
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import warnings
from contextlib import redirect_stdout
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from ltobackup.catalog import Catalog
from ltobackup.daemon.archive_runner import ArchiveRunner
from ltobackup.daemon.models import (
    HardwareTargetBinding,
    ProcessIdentity,
    imported_postcommit_command_sha256,
    media_identity_sha256,
)
from ltobackup.errors import ValidationError
from ltobackup.qualification import archive_runner as qualification_module
from ltobackup.qualification.archive_runner import (
    ArchiveRunnerPhysicalQualification,
    QualificationArchiveEvidence,
    QualificationArchiveRefused,
    main,
)
from ltobackup.tape.command_supervisor import (
    CommandFailed,
    CompletedCommand,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsStandaloneReceipt,
    TrackedCommandSupervisor,
)
from ltobackup.tape.linux_ltfs import LinuxLtfsBackend, MediaIdentityError
from ltobackup.tape.models import (
    ExpectedMedia,
    MediaIdentity,
    MountedTape,
    UnmountResult,
)
from tests.test_command_supervisor import (
    FakeGate,
    FakeLauncher,
    FakeProcessProbe,
    FakeTerminator,
)


class _Backend:
    def __init__(
        self,
        events: list[str],
        tape_root: Path,
        *,
        readback: bool,
        identity: MediaIdentity,
        wait_for_media_result: bool = True,
        catalog_path: Path | None = None,
        context=None,
        final_probe_returncode: int = 3,
        unload_returncode: int = 0,
        continue_after_failed_unload: bool = False,
    ) -> None:
        self.events = events
        self.tape_root = tape_root
        self.readback = readback
        self.identity = identity
        self.wait_for_media_result = wait_for_media_result
        self.expected = None
        self.fence = None
        self.qualification_physical_unload_complete = False
        self._media_loaded = readback
        self.catalog_path = catalog_path
        self.context = context
        self.final_probe_returncode = final_probe_returncode
        self.unload_returncode = unload_returncode
        self.continue_after_failed_unload = continue_after_failed_unload
        self._command_number = 0
        self.media_identity_probe = SimpleNamespace(
            identify_unmounted=self._identify_unmounted
        )

    def _identify_unmounted(self) -> None:
        if self.catalog_path is not None and self.context is not None:
            self._record_command("probe_media", self.final_probe_returncode)
        elif not self._media_loaded and self.final_probe_returncode != 0:
            raise CommandFailed("probe_media", self.final_probe_returncode)

    def _record_command(self, kind: str, terminal_exit_code: int = 0) -> None:
        self._command_number += 1
        command_id = f"readback-{self._command_number}-{kind}"
        process = ProcessIdentity(
            "boot-readback",
            600 + self._command_number,
            700 + self._command_number,
            600 + self._command_number,
        )
        assert self.catalog_path is not None
        assert self.context is not None
        with Catalog(self.catalog_path) as catalog:
            owner = catalog.current_daemon_fence()
            assert owner is not None
            gate = FakeGate(
                process,
                CompletedCommand(terminal_exit_code, "", "simulated drive edge"),
            )
            supervisor = TrackedCommandSupervisor(
                catalog=catalog,
                daemon_fence=owner,
                launcher=FakeLauncher([gate]),
                process_probe=FakeProcessProbe(),
                process_terminator=FakeTerminator(),
                quiescence_timeout=1.0,
                term_timeout=0.1,
                kill_timeout=0.1,
            )
            supervisor.run(
                self.context.fence,
                kind,
                ("simulated-drive-edge", kind, command_id),
                1.0,
            )

    def wait_for_media(self, _expected, _stop_requested) -> bool:
        self.events.append("readback.wait-for-reinsert")
        return self.wait_for_media_result

    def identify(self) -> MediaIdentity:
        self.events.append("readback.identify")
        if self.catalog_path is not None and self.context is not None:
            self._record_command("identify", 0)
            self._record_command("probe_media", 0)
            with Catalog(self.catalog_path) as catalog:
                catalog.bind_observed_media_identity(
                    self.context.fence,
                    media_identity_sha256(self.identity.canonical_fields()),
                )
        return self.identity

    def mount(self, *, read_only: bool) -> MountedTape:
        self.events.append(f"readback.mount.{read_only}")
        if not self.readback or read_only is not True:
            raise AssertionError("only the distinct readback backend may mount here")
        return MountedTape(self.tape_root, True, None)

    def unmount(self, _mounted, observer) -> UnmountResult:
        self.events.append("readback.unmount")
        observer.finalization_started()
        observer.mount_release_started()
        return UnmountResult(0.1, 0.2, None)

    def unload(self) -> None:
        if self.readback:
            self.events.append("readback.unload")
            if self.catalog_path is not None:
                try:
                    self._record_command("unload", self.unload_returncode)
                except CommandFailed:
                    if not self.continue_after_failed_unload:
                        raise
            self._media_loaded = False
        else:
            self.events.append("archive.eject")


class _RealArchiveBackend:
    """Hardware-free edge that lets the production ArchiveRunner own the flow."""

    def __init__(
        self,
        prepared,
        identity: MediaIdentity,
        events: list[str],
        *,
        tape_root: Path | None = None,
        tamper_payload: bool = False,
        wrong_block_tape_id: bool = False,
        changed_payload_mtime: bool = False,
        wrong_restore_tape_path: bool = False,
        extra_restore_row: bool = False,
    ) -> None:
        self.catalog_path = prepared.catalog_path
        self.fence = prepared.context.fence
        self.expected = prepared.expected
        self.tape_root = (
            prepared.root / "real-runner-tape"
            if tape_root is None
            else Path(tape_root)
        )
        self.tape_root.mkdir(parents=True, exist_ok=True)
        self.identity = identity
        self.events = events
        self._command_number = 0
        self._media_loaded = True
        self.tamper_payload = tamper_payload
        self.wrong_block_tape_id = wrong_block_tape_id
        self.changed_payload_mtime = changed_payload_mtime
        self.wrong_restore_tape_path = wrong_restore_tape_path
        self.extra_restore_row = extra_restore_row
        self.media_identity_probe = SimpleNamespace(
            identify_unmounted=self._probe_no_media
        )

    def _command(self, kind: str) -> None:
        self._command_number += 1
        command_id = f"real-runner-{self._command_number}-{kind}"
        identity = ProcessIdentity(
            "boot-real-runner",
            200 + self._command_number,
            300 + self._command_number,
            200 + self._command_number,
        )
        with Catalog(self.catalog_path) as catalog:
            owner = catalog.current_daemon_fence()
            assert owner is not None
            terminal_exit_code = (
                3 if kind == "probe_media" and not self._media_loaded else 0
            )
            gate = FakeGate(
                identity,
                CompletedCommand(terminal_exit_code, "", "simulated drive edge"),
            )
            supervisor = TrackedCommandSupervisor(
                catalog=catalog,
                daemon_fence=owner,
                launcher=FakeLauncher([gate]),
                process_probe=FakeProcessProbe(),
                process_terminator=FakeTerminator(),
                quiescence_timeout=1.0,
                term_timeout=0.1,
                kill_timeout=0.1,
            )
            supervisor.run(
                self.fence,
                kind,
                ("simulated-drive-edge", kind, command_id),
                1.0,
            )

    def wait_for_preformat_media(self, expected, _stop_requested) -> bool:
        self.events.append("real.wait-preformat")
        self.assert_expected(expected)
        self._command("identify")
        self._command("probe_media")
        with Catalog(self.catalog_path) as catalog:
            catalog.bind_observed_media_identity(self.fence, "9" * 64)
        return True

    def assert_expected(self, expected) -> None:
        if expected != self.expected:
            raise AssertionError("real runner expected-media binding changed")

    def format(self, expected) -> None:
        self.events.append("real.format")
        self.assert_expected(expected)
        for kind in ("inquiry", "probe_media", "format", "identify", "probe_media"):
            self._command(kind)
        observed = media_identity_sha256(self.identity.canonical_fields())
        with Catalog(self.catalog_path) as catalog:
            catalog.rebind_observed_media_after_confirmed_format(
                self.fence,
                pre_media_identity_sha256="9" * 64,
                post_media_identity_sha256=observed,
                pre_observed_serial=str(self.identity.mam_volume_serial),
                observed_label=str(self.identity.ltfs_volume_label),
                observed_serial=str(self.identity.mam_volume_serial),
                post_volume_uuid=str(self.identity.ltfs_volume_uuid),
                post_index_generation=1,
            )

    def mount(self, *, read_only: bool) -> MountedTape:
        self.events.append(f"real.mount.{read_only}")
        if read_only:
            raise AssertionError("archive qualification mount must be writable")
        self._command("inquiry")
        observed = media_identity_sha256(self.identity.canonical_fields())
        session = LtfsSessionReceipt(
            1,
            self.fence.operation_id,
            "11111111-1111-4111-8111-111111111111",
            str(self.identity.ltfs_volume_uuid),
            1,
            False,
            self.fence.owner_generation,
            b"a" * 32,
            "real-runner-session",
            "1" * 64,
            200,
            300,
            "2" * 64,
            b"b" * 32,
            b"c" * 32,
            True,
            str(self.identity.ltfs_volume_label),
            observed,
        )
        return MountedTape(self.tape_root, False, session)

    def unmount(self, mounted: MountedTape, observer) -> UnmountResult:
        self.events.append("real.unmount")
        observer.finalization_started()
        observer.mount_release_started()
        session = mounted.session_receipt
        payload_bytes = sum(
            len(payload) for _path, payload in qualification_module._PAYLOADS
        )
        terminal_fields = {
            "schema": 1,
            "stage": "terminal",
            "operation_id": session.receipt_operation_uuid,
            "volume_uuid": session.observed_volume_uuid,
            "prior_generation": 1,
            "new_generation": 2,
            "bytes_valid": True,
            "bytes": payload_bytes,
            "files_valid": True,
            "files": len(qualification_module._PAYLOADS),
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
            (json.dumps(terminal_fields, separators=(",", ":")) + "\n").encode(
                "ascii"
            )
        ).hexdigest()
        standalone = LtfsStandaloneReceipt(
            **{
                **terminal_fields,
                "phase_duration_ns": tuple(terminal_fields["phase_duration_ns"]),
            },
            terminal_sha256=terminal_sha256,
        )
        return UnmountResult(
            0.1,
            0.2,
            LtfsFinalizationReceipt(
                1,
                session,
                standalone,
                b"d" * 32,
                b"e" * 32,
                b"f" * 32,
                True,
                True,
            ),
        )

    def recover_pending_ltfs_session(self):
        return None

    def unload(self) -> CompletedCommand:
        self.events.append("real.eject")
        self._inject_postcommit_faults()
        self._command("unload")
        self._media_loaded = False
        return CompletedCommand(0, "", "")

    def _inject_postcommit_faults(self) -> None:
        alpha = next(self.tape_root.rglob("files/alpha.txt"), None)
        block = next(self.tape_root.rglob("block.json"), None)
        if self.tamper_payload and alpha is not None:
            alpha.write_bytes(b"tampered")
        if self.changed_payload_mtime and alpha is not None:
            current = alpha.stat().st_mtime_ns
            os.utime(alpha, ns=(current, current + 1))
        if self.wrong_block_tape_id and block is not None:
            payload = json.loads(block.read_text(encoding="utf-8"))
            payload["tape_id"] = "wrong-qualification-tape"
            block.write_text(json.dumps(payload, sort_keys=True) + "\n", encoding="utf-8")
        if self.wrong_restore_tape_path or self.extra_restore_row:
            with sqlite3.connect(self.catalog_path) as database:
                if self.wrong_restore_tape_path:
                    database.execute(
                        "UPDATE file_versions SET tape_relative_path=? "
                        "WHERE id=(SELECT MAX(id) FROM file_versions)",
                        ("libraries/QUALIFICATION/blocks/wrong/files/alpha.txt",),
                    )
                if self.extra_restore_row:
                    row = database.execute(
                        "SELECT library_id,block_id,tape_id FROM file_versions "
                        "ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    assert row is not None
                    database.execute(
                        "INSERT INTO file_versions("
                        "library_id,block_id,tape_id,relative_path,tape_relative_path,"
                        "size,mtime_ns,sha256,copied_at,visible) "
                        "VALUES(?,?,?,?,?,?,?,?,?,1)",
                        (
                            *row,
                            "extra.bin",
                            "libraries/QUALIFICATION/blocks/extra/files/extra.bin",
                            1,
                            1,
                            "0" * 64,
                            datetime.now(UTC).isoformat(),
                        ),
                    )
                database.commit()

    def _probe_no_media(self) -> None:
        self.events.append("real.probe-no-media")
        self._command("probe_media")
        if self._media_loaded:
            return
        raise CommandFailed("probe_media", 3)


class _RestoreBackend(_Backend):
    def __init__(
        self,
        events,
        tape_root,
        identity,
        catalog_path,
        context,
        *,
        final_probe_returncode: int | None,
    ) -> None:
        super().__init__(
            events,
            tape_root,
            readback=True,
            identity=identity,
            catalog_path=catalog_path,
            context=context,
            final_probe_returncode=(
                3 if final_probe_returncode is None else final_probe_returncode
            ),
        )
        self.expected = None
        self.fence = context.fence
        self._command_number = 100
        self._physical_unload_complete = False
        self.restore_final_probe_returncode = final_probe_returncode
        self.session: LtfsSessionReceipt | None = None
        self.media_identity_probe = SimpleNamespace(
            identify_unmounted=self._probe_no_medium
        )

    @property
    def qualification_physical_unload_complete(self) -> bool:
        return self._physical_unload_complete

    @qualification_physical_unload_complete.setter
    def qualification_physical_unload_complete(self, value: bool) -> None:
        self._physical_unload_complete = value

    def bind_restore_volume_label(self, label: str) -> None:
        self.events.append(f"restore.bind.{label}")

    def wait_for_media(self, _expected, _stop_requested) -> bool:
        self.events.append("restore.wait_for_media")
        return True

    def identify(self) -> MediaIdentity:
        self.events.append("restore.identify")
        self._record_command("identify", 0)
        self._record_command("probe_media", 0)
        with Catalog(self.catalog_path) as catalog:
            catalog.bind_observed_media_identity(
                self.context.fence,
                media_identity_sha256(self.identity.canonical_fields()),
            )
        return self.identity

    def mount(self, *, read_only: bool) -> MountedTape:
        self.events.append(f"restore.mount.{read_only}")
        if read_only is not True:
            raise AssertionError("restore qualification mount must be read-only")
        self.session = LtfsSessionReceipt(
            1,
            self.context.fence.operation_id,
            "33333333-3333-4333-8333-333333333333",
            str(self.identity.ltfs_volume_uuid),
            1,
            True,
            self.context.fence.owner_generation,
            b"a" * 32,
            "restore-qualification-session",
            "b" * 64,
            1,
            1,
            "c" * 64,
            b"d" * 32,
            b"e" * 32,
            True,
            str(self.identity.ltfs_volume_label),
            media_identity_sha256(self.identity.canonical_fields()),
        )
        return MountedTape(self.tape_root, True, self.session)

    def unmount(self, _mounted, observer) -> UnmountResult:
        self.events.append("restore.unmount")
        observer.finalization_started()
        observer.mount_release_started()
        assert self.session is not None
        standalone = LtfsStandaloneReceipt(
            1,
            "terminal",
            self.session.receipt_operation_uuid,
            self.session.observed_volume_uuid,
            1,
            2,
            True,
            69,
            True,
            2,
            (),
            0,
            0,
            True,
            0,
            0,
            True,
            True,
            False,
            0,
            "f" * 64,
        )
        finalization = LtfsFinalizationReceipt(
            1,
            self.session,
            standalone,
            b"g" * 32,
            b"h" * 32,
            b"i" * 32,
            True,
            True,
        )
        return UnmountResult(0.1, 0.2, finalization)

    def unload(self) -> CompletedCommand:
        self.events.append("restore.unload")
        self._record_command("unload", 0)
        return CompletedCommand(0, "", "")

    def _probe_no_medium(self) -> None:
        self.events.append("restore.probe-no-medium")
        if self.restore_final_probe_returncode is None:
            raise OSError("simulated missing final probe")
        self._record_command(
            "probe_media", self.restore_final_probe_returncode
        )


class ArchiveRunnerPhysicalQualificationTests(unittest.TestCase):
    def test_setup_failure_closes_archive_qualification_lifecycle(self) -> None:
        from ltobackup.qualification import archive_runner

        events = []
        sink = SimpleNamespace(emit=events.append)
        with (
            mock.patch.object(
                archive_runner,
                "JournalOperationalEventSink",
                return_value=sink,
            ),
            mock.patch.object(
                archive_runner.pwd,
                "getpwnam",
                side_effect=KeyError("missing"),
            ),
            self.assertRaises(SystemExit),
        ):
            archive_runner.main([])

        self.assertEqual(
            ["archive_qualification.started", "archive_qualification.failed"],
            [event.code for event in events],
        )

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.events: list[str] = []
        self.tape_root = self.root / "tape"
        self.tape_root.mkdir(mode=0o700)

    def qualification(
        self,
        *,
        tamper_payload: bool = False,
        stale_uuid: bool = False,
        wrong_block_tape_id: bool = False,
        changed_payload_mtime: bool = False,
        enable_restore: bool = False,
        restore_final_probe_returncode: int | None = 3,
        reinsert_media: bool = True,
        wrong_restore_tape_path: bool = False,
        extra_restore_row: bool = False,
        final_probe_returncode: int = 3,
        readback_unload_returncode: int = 0,
    ):
        def target_factory(expected):
            return HardwareTargetBinding.from_verified_inputs(
                (
                    self.tape_root
                    if expected.operation_kind == "restore.cassette"
                    else self.root / "mount"
                ),
                "qualification-tape-device",
                "qualification-scsi-device",
                expected.target_scope(),
            )

        archive_identity = MediaIdentity(
            drive_serial="DRIVE-QUALIFICATION",
            mam_barcode="TAPE04",
            mam_volume_serial="Q210531120",
            ltfs_volume_label="TAPE04",
            ltfs_volume_uuid="22222222-2222-4222-8222-222222222222",
        )
        readback_identity = (
            MediaIdentity(
                drive_serial="DRIVE-QUALIFICATION",
                mam_barcode="TAPE04",
                mam_volume_serial="Q210531120",
                ltfs_volume_label="TAPE04",
                ltfs_volume_uuid="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            )
            if stale_uuid
            else archive_identity
        )

        def backend_factory(*, expected, context, readback, **_kwargs):
            if expected.operation_kind == "restore.cassette":
                backend = _RestoreBackend(
                    self.events,
                    self.tape_root,
                    readback_identity,
                    _kwargs["catalog_path"],
                    context,
                    final_probe_returncode=restore_final_probe_returncode,
                )
            else:
                if readback:
                    backend = _Backend(
                        self.events,
                        self.tape_root,
                        readback=True,
                        identity=readback_identity,
                        wait_for_media_result=reinsert_media,
                        catalog_path=_kwargs["catalog_path"],
                        context=context,
                        final_probe_returncode=final_probe_returncode,
                        unload_returncode=readback_unload_returncode,
                        continue_after_failed_unload=(
                            readback_unload_returncode != 0
                        ),
                    )
                else:
                    prepared = SimpleNamespace(
                        catalog_path=_kwargs["catalog_path"],
                        context=context,
                        expected=expected,
                        root=Path(_kwargs["catalog_path"]).parent,
                    )
                    backend = _RealArchiveBackend(
                        prepared,
                        archive_identity,
                        self.events,
                        tape_root=self.tape_root,
                        tamper_payload=tamper_payload,
                        wrong_block_tape_id=wrong_block_tape_id,
                        changed_payload_mtime=changed_payload_mtime,
                        wrong_restore_tape_path=wrong_restore_tape_path,
                        extra_restore_row=extra_restore_row,
                    )
            backend.expected = expected
            backend.fence = context.fence
            return backend

        return ArchiveRunnerPhysicalQualification(
            state_root=self.root / "qualification-state",
            expected_label="TAPE04",
            target_factory=target_factory,
            backend_factory=backend_factory,
            enable_restore_qualification=enable_restore,
            run_id_factory=lambda: "11111111-1111-4111-8111-111111111111",
        )

    def test_bounded_artifact_reader_accepts_legal_short_reads(self) -> None:
        artifact = self.root / "artifact.json"
        artifact.write_bytes(b'{"ok":true}\n')
        real_read = os.read

        with mock.patch(
            "ltobackup.qualification.archive_runner.os.read",
            side_effect=lambda descriptor, size: real_read(descriptor, min(size, 2)),
        ):
            raw = ArchiveRunnerPhysicalQualification._bounded_regular(artifact, 1024)

        self.assertEqual(b'{"ok":true}\n', raw)

    def test_evidence_writer_completes_legal_short_writes(self) -> None:
        real_write = os.write

        qualification = self.qualification()
        real_writer = qualification._write_evidence

        def short_write_evidence(*args, **kwargs):
            with mock.patch(
                "ltobackup.qualification.archive_runner.os.write",
                side_effect=lambda descriptor, payload: real_write(
                    descriptor, payload[:3]
                ),
            ):
                return real_writer(*args, **kwargs)

        with mock.patch.object(
            qualification,
            "_write_evidence",
            side_effect=short_write_evidence,
        ):
            result = qualification.run()

        evidence = json.loads(result.evidence_path.read_text(encoding="ascii"))
        self.assertEqual(result.evidence_sha256, evidence["evidence_sha256"])

    def test_runner_finishes_before_distinct_read_only_hash_verification(self) -> None:
        result = self.qualification().run()

        self.assertIsInstance(result, QualificationArchiveEvidence)
        self.assertEqual("TAPE04", result.physical_label)
        self.assertEqual(2, result.file_count)
        self.assertRegex(result.evidence_sha256, r"^[0-9a-f]{64}$")
        self.assertRegex(
            result.readback_release_receipt_sha256, r"^[0-9a-f]{64}$"
        )
        self.assertLess(self.events.index("real.eject"), self.events.index("real.probe-no-media"))
        self.assertLess(
            self.events.index("real.probe-no-media"),
            self.events.index("readback.wait-for-reinsert"),
        )
        self.assertEqual(
            [
                "readback.wait-for-reinsert",
                "readback.identify",
                "readback.mount.True",
                "readback.unmount",
                "readback.unload",
            ],
            [event for event in self.events if event.startswith("readback.")],
        )
        self.assertTrue(result.evidence_path.is_file())
        self.assertNotIn("readback.load", self.events)
        self.assertEqual(1, self.events.count("readback.unload"))
        self.assertEqual(
            ["readback.unload"],
            [event for event in self.events if event.endswith("unload")],
        )
        self.assertNotEqual(
            Path("/var/lib/lto-archiver/catalog.db"), result.catalog_path
        )
        expected_readback_target = HardwareTargetBinding.from_verified_inputs(
            self.root / "mount",
            "qualification-tape-device",
            "qualification-scsi-device",
            (
                "tape.qualification-readback",
                "QUAL-ARCHIVE-RUNNER",
                "4",
                "TAPE04",
                "Q210531120",
                "22222222-2222-4222-8222-222222222222",
            ),
        )
        with sqlite3.connect(result.catalog_path) as connection:
            readback = connection.execute(
                "SELECT operation.kind,target.expected_media_scope_sha256 "
                "FROM daemon_operations AS operation "
                "JOIN operation_hardware_targets AS target "
                "ON target.operation_id=operation.id "
                "WHERE operation.kind='tape.qualification-readback'"
            ).fetchall()
            release = connection.execute(
                "SELECT release_receipt_sha256 FROM "
                "qualification_readback_release_receipts"
            ).fetchone()
        self.assertEqual(
            [
                (
                    "tape.qualification-readback",
                    expected_readback_target.expected_media_scope_sha256,
                )
            ],
            readback,
        )
        self.assertEqual(result.readback_release_receipt_sha256, release[0])

    def test_snapshot_verification_closes_read_only_catalog_connection(self) -> None:
        gc.collect()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            result = self.qualification().run()
            del result
            gc.collect()

        self.assertEqual(
            [],
            [
                item
                for item in caught
                if isinstance(item.message, ResourceWarning)
                and "unclosed database" in str(item.message)
            ],
        )

    def test_wrong_final_probe_code_requires_recovery_and_emits_no_evidence(self):
        with self.assertRaisesRegex(
            QualificationArchiveRefused,
            "readback eject is ambiguous",
        ):
            self.qualification(final_probe_returncode=1).run()

        self.assertEqual([], list(self.root.rglob("evidence.json")))
        catalog_path = next(self.root.rglob("catalog.sqlite3"))
        with sqlite3.connect(catalog_path) as connection:
            state = connection.execute(
                "SELECT state FROM daemon_operations "
                "WHERE kind='tape.qualification-readback'"
            ).fetchone()[0]
            receipts = connection.execute(
                "SELECT COUNT(*) FROM qualification_readback_release_receipts"
            ).fetchone()[0]
        self.assertEqual("recovery_required", state)
        self.assertEqual(0, receipts)

    def test_final_probe_without_no_medium_result_cannot_complete(self) -> None:
        with self.assertRaisesRegex(
            QualificationArchiveRefused,
            "readback eject is ambiguous",
        ):
            self.qualification(final_probe_returncode=0).run()

        self.assertEqual([], list(self.root.rglob("evidence.json")))
        catalog_path = next(self.root.rglob("catalog.sqlite3"))
        with sqlite3.connect(catalog_path) as connection:
            state = connection.execute(
                "SELECT state FROM daemon_operations "
                "WHERE kind='tape.qualification-readback'"
            ).fetchone()[0]
            receipts = connection.execute(
                "SELECT COUNT(*) FROM qualification_readback_release_receipts"
            ).fetchone()[0]
        self.assertEqual("recovery_required", state)
        self.assertEqual(0, receipts)

    def test_failed_unload_plus_rc3_probe_cannot_pass_qualification(self) -> None:
        with self.assertRaises(ValidationError):
            self.qualification(readback_unload_returncode=1).run()

        self.assertEqual([], list(self.root.rglob("evidence.json")))
        catalog_path = next(self.root.rglob("catalog.sqlite3"))
        with sqlite3.connect(catalog_path) as connection:
            state = connection.execute(
                "SELECT state FROM daemon_operations "
                "WHERE kind='tape.qualification-readback'"
            ).fetchone()[0]
            commands = connection.execute(
                "SELECT command_kind,terminal_exit_code FROM "
                "hardware_command_executions WHERE operation_id IN ("
                "SELECT id FROM daemon_operations WHERE "
                "kind='tape.qualification-readback') ORDER BY created_at,id"
            ).fetchall()
            receipts = connection.execute(
                "SELECT COUNT(*) FROM qualification_readback_release_receipts"
            ).fetchone()[0]
        self.assertEqual("recovery_required", state)
        self.assertEqual([("unload", 1), ("probe_media", 3)], commands[-2:])
        self.assertEqual(0, receipts)

    def test_production_contract_selects_real_runner_without_deferred_eject(self) -> None:
        runner_parameter = inspect.signature(
            ArchiveRunnerPhysicalQualification.__init__
        ).parameters["runner_factory"]
        backend_parameters = inspect.signature(
            qualification_module._QualificationLinuxLtfsBackend.__init__
        ).parameters

        self.assertIs(ArchiveRunner, runner_parameter.default)
        self.assertNotIn("defer_unload", backend_parameters)

    def test_hardware_free_contract_executes_real_runner_through_exact_eject(self):
        identity = MediaIdentity(
            drive_serial="DRIVE-QUALIFICATION",
            mam_barcode="TAPE04",
            mam_volume_serial="Q210531120",
            ltfs_volume_label="TAPE04",
            ltfs_volume_uuid="22222222-2222-4222-8222-222222222222",
        )
        archive_backend: list[_RealArchiveBackend] = []

        def target_factory(expected):
            return HardwareTargetBinding.from_verified_inputs(
                self.root / "mount",
                "qualification-tape-device",
                "qualification-scsi-device",
                expected.target_scope(),
            )

        def backend_factory(*, catalog_path, context, expected, readback):
            if readback:
                backend = _Backend(
                    self.events,
                    self.tape_root,
                    readback=True,
                    identity=identity,
                    catalog_path=catalog_path,
                    context=context,
                )
                backend.expected = expected
                backend.fence = context.fence
                return backend
            prepared = SimpleNamespace(
                catalog_path=catalog_path,
                context=context,
                expected=expected,
                root=Path(catalog_path).parent,
            )
            backend = _RealArchiveBackend(
                prepared,
                identity,
                self.events,
                tape_root=self.tape_root,
            )
            archive_backend.append(backend)
            return backend

        result = ArchiveRunnerPhysicalQualification(
            state_root=self.root / "real-runner-qualification-state",
            expected_label="TAPE04",
            target_factory=target_factory,
            backend_factory=backend_factory,
            run_id_factory=lambda: "44444444-4444-4444-8444-444444444444",
            buffer_bytes=1024,
        ).run()

        self.assertIsInstance(result, QualificationArchiveEvidence)
        self.assertEqual(1, len(archive_backend))
        self.assertLess(
            self.events.index("real.eject"),
            self.events.index("real.probe-no-media"),
        )
        self.assertLess(
            self.events.index("real.probe-no-media"),
            self.events.index("readback.wait-for-reinsert"),
        )
        with Catalog(result.catalog_path) as catalog:
            archive_operation = catalog.connection.execute(
                "SELECT id FROM daemon_operations "
                "WHERE kind='archive.resume'"
            ).fetchone()
            probe = catalog.connection.execute(
                "SELECT command.* FROM hardware_command_executions AS command "
                "WHERE operation_id=? AND command_kind='probe_media' "
                "ORDER BY created_at DESC LIMIT 1",
                (archive_operation["id"],),
            ).fetchone()
            probe_with_release = catalog._command_with_release_tx(
                catalog.connection, probe["id"]
            )
            proof_rows = catalog.connection.execute(
                "SELECT command_evidence_sha256 FROM "
                "imported_postcommit_command_receipts WHERE command_id=? "
                "UNION ALL SELECT command_evidence_sha256 FROM "
                "imported_runtime_postcommit_command_receipts WHERE command_id=?",
                (probe["id"], probe["id"]),
            ).fetchall()
            expected = imported_postcommit_command_sha256(
                (
                    "exact-no-media-v2",
                    *catalog._postcommit_command_tuple(probe_with_release),
                    3,
                )
            )
            readback_operation = catalog.connection.execute(
                "SELECT id FROM daemon_operations "
                "WHERE kind='tape.qualification-readback'"
            ).fetchone()
            readback_commands = catalog.connection.execute(
                "SELECT command_kind,terminal_exit_code FROM "
                "hardware_command_executions WHERE operation_id=? "
                "ORDER BY created_at,id",
                (readback_operation["id"],),
            ).fetchall()
            readback_receipt = catalog.connection.execute(
                "SELECT release_receipt_sha256 FROM "
                "qualification_readback_release_receipts WHERE operation_id=?",
                (readback_operation["id"],),
            ).fetchone()
        self.assertEqual([(expected,)], [tuple(row) for row in proof_rows])
        self.assertEqual(
            [
                ("identify", 0),
                ("probe_media", 0),
                ("unload", 0),
                ("probe_media", 3),
            ],
            [tuple(row) for row in readback_commands],
        )
        self.assertEqual(
            result.readback_release_receipt_sha256,
            readback_receipt["release_receipt_sha256"],
        )

    def test_readback_missing_reinsertion_fails_before_identify_and_is_recoverable(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            QualificationArchiveRefused,
            "reinsertion is unavailable",
        ):
            self.qualification(reinsert_media=False).run()

        self.assertIn("real.eject", self.events)
        self.assertIn("readback.wait-for-reinsert", self.events)
        self.assertNotIn("readback.identify", self.events)
        catalog_path = next(self.root.rglob("catalog.sqlite3"))
        with sqlite3.connect(catalog_path) as connection:
            state = connection.execute(
                "SELECT state FROM daemon_operations "
                "WHERE kind='tape.qualification-readback'"
            ).fetchone()[0]
        self.assertEqual("recovery_required", state)

    def test_restore_qualification_is_explicit_and_uses_production_runner(self) -> None:
        from ltobackup.daemon.restore_runner import RestoreCassetteRunner

        parameters = inspect.signature(
            ArchiveRunnerPhysicalQualification.__init__
        ).parameters
        self.assertFalse(parameters["enable_restore_qualification"].default)
        self.assertIs(
            RestoreCassetteRunner,
            parameters["restore_runner_factory"].default,
        )
        parser = qualification_module.build_parser()
        self.assertFalse(parser.parse_args([]).enable_restore_qualification)
        self.assertTrue(
            parser.parse_args(
                ["--enable-restore-qualification"]
            ).enable_restore_qualification
        )
        self.assertEqual(
            [("--enable-restore-qualification",)],
            [
                tuple(action.option_strings)
                for action in parser._actions
                if action.const is True and action.default is False
            ],
        )
        source = inspect.getsource(
            ArchiveRunnerPhysicalQualification._run_restore_qualification
        )
        self.assertNotIn("long_wipe", source)
        self.assertNotIn(".load(", source)

    def test_enabled_restore_qualification_executes_production_runner_and_attests(self) -> None:
        try:
            result = self.qualification(enable_restore=True).run()
        except Exception as exc:
            self.fail(f"{exc}; events={self.events}")

        self.assertIsNotNone(result.restore)
        restore = result.restore
        assert restore is not None
        self.assertEqual(2, len(restore.file_version_ids))
        self.assertEqual(("skipped_verified", "restored"), restore.item_states)
        self.assertEqual(1, restore.skipped_files)
        self.assertEqual(1, restore.restored_files)
        self.assertEqual(68, restore.verified_bytes)
        self.assertEqual("post_eject", restore.release_boundary)
        self.assertTrue(restore.unload_command_id)
        self.assertTrue(restore.no_medium_proven)
        self.assertIn("restore.mount.True", self.events)
        self.assertEqual(
            ["restore.unload", "restore.probe-no-medium"], self.events[-2:]
        )
        with sqlite3.connect(result.catalog_path) as connection:
            commands = connection.execute(
                "SELECT id,command_kind,terminal_exit_code FROM "
                "hardware_command_executions WHERE operation_id LIKE "
                "'qualification-restore-%' ORDER BY created_at,id"
            ).fetchall()
        self.assertEqual(
            [
                ("identify", 0),
                ("probe_media", 0),
                ("unload", 0),
                ("probe_media", 3),
            ],
            [(row[1], row[2]) for row in commands],
        )
        self.assertEqual(restore.unload_command_id, commands[-2][0])
        evidence = result.evidence_path.read_bytes()
        self.assertLessEqual(len(evidence), 64 * 1024)
        body = json.loads(evidence)
        self.assertEqual("passed", body["restore"]["attestation_state"])
        self.assertNotIn(str(self.root), evidence.decode("ascii"))
        evidence_sha256 = body.pop("evidence_sha256")
        canonical = json.dumps(
            body, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        self.assertEqual(
            hashlib.sha256(
                b"lto-archive-runner-physical-qualification/v2\0" + canonical
            ).hexdigest(),
            evidence_sha256,
        )

    def test_restore_selection_rejects_wrong_tape_path_and_extra_source_row(self) -> None:
        for arguments in (
            {"wrong_restore_tape_path": True},
            {"extra_restore_row": True},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaisesRegex(
                    QualificationArchiveRefused,
                    "restore selection is incomplete",
                ):
                    self.qualification(enable_restore=True, **arguments).run()
                self.assertEqual([], list(self.root.rglob("evidence.json")))
                shutil.rmtree(self.root)
                self.root.mkdir(mode=0o700)
                self.tape_root.mkdir(mode=0o700)

    def test_schema_two_evidence_writer_rejects_oversized_serialization(self) -> None:
        qualification = self.qualification(enable_restore=True)
        real_writer = qualification._write_evidence

        def constrained_writer(*args, **kwargs):
            with mock.patch.object(qualification_module, "_MAX_JSON_BYTES", 100):
                return real_writer(*args, **kwargs)

        with mock.patch.object(
            qualification,
            "_write_evidence",
            side_effect=constrained_writer,
        ):
            with self.assertRaisesRegex(
                QualificationArchiveRefused,
                "evidence is too large",
            ):
                qualification.run()

        self.assertEqual([], list(self.root.rglob("evidence.json")))

    def test_completed_restore_with_destination_hash_fault_has_no_attestation(self) -> None:
        real_hash = ArchiveRunnerPhysicalQualification._hash_regular

        def faulty_hash(path: Path, expected_size: int, **kwargs) -> str:
            if "restore-destination" in path.parts:
                return "0" * 64
            return real_hash(path, expected_size, **kwargs)

        with mock.patch.object(
            ArchiveRunnerPhysicalQualification,
            "_hash_regular",
            side_effect=faulty_hash,
        ):
            with self.assertRaisesRegex(
                QualificationArchiveRefused,
                "restored destination digest mismatch",
            ):
                self.qualification(enable_restore=True).run()

        self.assertEqual([], list(self.root.rglob("evidence.json")))
        catalog_path = next(self.root.rglob("catalog.sqlite3"))
        with sqlite3.connect(catalog_path) as connection:
            self.assertEqual(
                "completed",
                connection.execute("SELECT state FROM restore_runs").fetchone()[0],
            )

    def test_completed_restore_with_post_run_receipt_fault_has_no_attestation(self) -> None:
        real_boundary = qualification_module.Catalog.restore_release_boundary

        def faulty_boundary(catalog, operation_id, *args, **kwargs):
            boundary = real_boundary(catalog, operation_id, *args, **kwargs)
            if operation_id.startswith("qualification-restore-"):
                return "pre_eject"
            return boundary

        with mock.patch.object(
            qualification_module.Catalog,
            "restore_release_boundary",
            new=faulty_boundary,
        ):
            with self.assertRaisesRegex(
                QualificationArchiveRefused,
                "durable result is incomplete",
            ):
                self.qualification(enable_restore=True).run()

        self.assertEqual([], list(self.root.rglob("evidence.json")))
        catalog_path = next(self.root.rglob("catalog.sqlite3"))
        with sqlite3.connect(catalog_path) as connection:
            self.assertEqual(
                "completed",
                connection.execute("SELECT state FROM restore_runs").fetchone()[0],
            )

    def test_restore_final_probe_must_prove_no_media_through_supervisor(self) -> None:
        for returncode in (0, 1, None):
            with self.subTest(returncode=returncode):
                with self.assertRaisesRegex(
                    QualificationArchiveRefused,
                    "did not complete qualification",
                ):
                    self.qualification(
                        enable_restore=True,
                        restore_final_probe_returncode=returncode,
                    ).run()

                self.assertEqual([], list(self.root.rglob("evidence.json")))
                catalog_path = next(self.root.rglob("catalog.sqlite3"))
                with sqlite3.connect(catalog_path) as connection:
                    state = connection.execute(
                        "SELECT state FROM restore_runs"
                    ).fetchone()[0]
                    operation_state = connection.execute(
                        "SELECT state FROM daemon_operations WHERE "
                        "kind='restore.cassette'"
                    ).fetchone()[0]
                    commands = connection.execute(
                        "SELECT command_kind,terminal_exit_code FROM "
                        "hardware_command_executions WHERE operation_id LIKE "
                        "'qualification-restore-%' ORDER BY created_at,id"
                    ).fetchall()
                self.assertEqual("recovery_required", state)
                self.assertEqual("recovery_required", operation_state)
                expected_tail = (
                    [("unload", 0)]
                    if returncode is None
                    else [("unload", 0), ("probe_media", returncode)]
                )
                self.assertEqual(expected_tail, commands[-len(expected_tail):])
                shutil.rmtree(self.root)
                self.root.mkdir(mode=0o700)
                self.tape_root.mkdir(mode=0o700)

    def test_committed_identity_keeps_physical_and_ltfs_labels_distinct(self) -> None:
        identity = MediaIdentity(
            "DRIVE-QUALIFICATION",
            "PHYSICAL-01",
            "SERIAL-01",
            "LTFS-VOLUME-01",
            "22222222-2222-4222-8222-222222222222",
        )
        now = datetime.now().astimezone()
        committed = qualification_module._CommittedArchiveProof(
            "block",
            "tape",
            "PHYSICAL-01",
            "LTFS-VOLUME-01",
            "SERIAL-01",
            "22222222-2222-4222-8222-222222222222",
            media_identity_sha256(identity.canonical_fields()),
            now,
            now,
        )

        self.qualification()._require_identity(identity, committed)

        mismatched = qualification_module._CommittedArchiveProof(
            "block",
            "tape",
            "PHYSICAL-01",
            "OTHER-LTFS",
            "SERIAL-01",
            "22222222-2222-4222-8222-222222222222",
            media_identity_sha256(identity.canonical_fields()),
            now,
            now,
        )
        with self.assertRaisesRegex(
            QualificationArchiveRefused, "committed archive identity"
        ):
            self.qualification()._require_identity(identity, mismatched)

    def test_archive_operation_starts_after_cutover_authorization(self) -> None:
        prepared = self.qualification()._prepare()

        with sqlite3.connect(prepared.catalog_path) as connection:
            created_at, started_at = connection.execute(
                "SELECT authorization.created_at,operation.started_at "
                "FROM cutover_authorizations AS authorization "
                "JOIN daemon_operations AS operation "
                "ON operation.id=authorization.consumed_by_operation_id "
                "WHERE operation.kind='archive.resume'"
            ).fetchone()

        self.assertLessEqual(created_at, started_at)

    def test_stale_prior_qualification_uuid_is_rejected_and_released(self) -> None:
        with self.assertRaisesRegex(
            QualificationArchiveRefused, "committed archive identity"
        ):
            self.qualification(stale_uuid=True).run()

        self.assertNotIn("readback.mount.True", self.events)
        self.assertEqual("readback.unload", self.events[-1])

    def test_wrong_block_tape_id_is_rejected_and_released(self) -> None:
        with self.assertRaisesRegex(
            QualificationArchiveRefused, "qualification block manifest is invalid"
        ):
            self.qualification(wrong_block_tape_id=True).run()

        self.assertEqual("readback.unmount", self.events[-2])
        self.assertEqual("readback.unload", self.events[-1])

    def test_changed_payload_mtime_is_rejected_and_released(self) -> None:
        with self.assertRaisesRegex(
            QualificationArchiveRefused, "qualification payload metadata mismatch"
        ):
            self.qualification(changed_payload_mtime=True).run()

        self.assertEqual("readback.unmount", self.events[-2])
        self.assertEqual("readback.unload", self.events[-1])

    def test_payload_hash_mismatch_fails_closed_but_releases_mounted_media(
        self,
    ) -> None:
        with self.assertRaisesRegex(
            QualificationArchiveRefused, "qualification payload digest mismatch"
        ):
            self.qualification(tamper_payload=True).run()

        self.assertEqual("readback.unmount", self.events[-2])
        self.assertEqual("readback.unload", self.events[-1])
        self.assertEqual(
            [], list((self.root / "qualification-state").rglob("evidence.json"))
        )

    def test_production_catalog_or_state_namespace_is_refused_before_factory_calls(
        self,
    ) -> None:
        calls: list[str] = []
        qualification = ArchiveRunnerPhysicalQualification(
            state_root=Path("/var/lib/lto-archiver"),
            expected_label="TAPE04",
            target_factory=lambda _expected: calls.append("target"),
            backend_factory=lambda **_kwargs: calls.append("backend"),
        )

        with self.assertRaisesRegex(
            QualificationArchiveRefused, "production catalog namespace"
        ):
            qualification.run()

        self.assertEqual([], calls)

    def test_existing_shared_state_root_is_refused_before_factory_calls(self) -> None:
        state_root = self.root / "shared-state"
        state_root.mkdir(mode=0o755)
        calls: list[str] = []
        qualification = ArchiveRunnerPhysicalQualification(
            state_root=state_root,
            expected_label="TAPE04",
            target_factory=lambda _expected: calls.append("target"),
            backend_factory=lambda **_kwargs: calls.append("backend"),
        )

        with self.assertRaisesRegex(
            QualificationArchiveRefused, "qualification state root is not private"
        ):
            qualification.run()

        self.assertEqual([], calls)

    def test_qualification_backend_pins_approved_mam_serial_before_format(
        self,
    ) -> None:
        identity = MediaIdentity(
            drive_serial="DRIVE-QUALIFICATION",
            mam_barcode="TAPE04",
            mam_volume_serial="WRONG-SERIAL",
            ltfs_volume_label=None,
            ltfs_volume_uuid=None,
        )
        backend = object.__new__(qualification_module._QualificationLinuxLtfsBackend)
        backend._preformat_media_snapshot = (identity, "0" * 64)
        expected = ExpectedMedia(
            "archive.resume", "QUAL-ARCHIVE-RUNNER", 4, "TAPE04", None, None
        )

        with (
            mock.patch.object(
                LinuxLtfsBackend,
                "identify_preformat",
                return_value=identity,
            ),
            self.assertRaises(MediaIdentityError),
        ):
            backend.identify_preformat()
        self.assertIsNone(backend._preformat_media_snapshot)

        with (
            mock.patch.object(LinuxLtfsBackend, "format") as format_call,
            self.assertRaises(MediaIdentityError),
        ):
            backend.format(expected)
        format_call.assert_not_called()

    def test_backend_leaves_exact_eject_probe_to_archive_runner(self) -> None:
        backend = object.__new__(qualification_module._QualificationLinuxLtfsBackend)
        backend._physical_unload_complete = False
        terminal_events: list[str] = []

        no_medium = mock.Mock(side_effect=AssertionError("probe consumed early"))
        backend.media_identity_probe = SimpleNamespace(identify_unmounted=no_medium)

        completed = CompletedCommand(0, "", "")
        with mock.patch.object(
            LinuxLtfsBackend,
            "unload",
            side_effect=lambda: (terminal_events.append("eject"), completed)[1],
        ) as unload:
            observed = backend.unload()

        unload.assert_called_once_with()
        no_medium.assert_not_called()
        self.assertEqual(["eject"], terminal_events)
        self.assertFalse(backend._physical_unload_complete)
        self.assertIs(completed, observed)

    def test_module_main_composes_installed_brokered_runtime(self) -> None:
        evidence = QualificationArchiveEvidence(
            "11111111-1111-4111-8111-111111111111",
            "TAPE04",
            "22222222-2222-4222-8222-222222222222",
            2,
            (("alpha.txt", "a" * 64), ("nested/pattern.bin", "b" * 64)),
            "c" * 64,
            "d" * 64,
            "e" * 64,
            "f" * 64,
            self.root / "qualification-state" / "catalog.sqlite3",
            self.root / "qualification-state" / "evidence.json",
            "g" * 64,
        )
        settings = SimpleNamespace(buffer_bytes=4096, validate=lambda: None)
        broker = SimpleNamespace(assert_ready=mock.Mock())
        privilege = SimpleNamespace(validate_supervisor=mock.Mock())
        runtime = SimpleNamespace(run=mock.Mock(return_value=evidence))
        output = io.StringIO()
        operational_events = []
        operational_sink = SimpleNamespace(emit=operational_events.append)
        with (
            mock.patch(
                "ltobackup.qualification.archive_runner.pwd.getpwnam",
                return_value=SimpleNamespace(pw_uid=0, pw_gid=0),
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.os.geteuid", return_value=0
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.os.getegid", return_value=0
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner._require_enforced_selinux_domain"
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.load_linux_settings",
                return_value=settings,
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.load_broker_capability",
                return_value="capability",
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.UnixBrokeredCgroupScopeApi",
                return_value=broker,
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.BrokeredCgroupExecutionScopeManager",
                return_value="scope-manager",
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.ReadOnlyCgroupPrivilegeBoundary",
                return_value=privilege,
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.BrokeredLinuxArchiveQualification",
                return_value=runtime,
            ) as runtime_class,
            mock.patch(
                "ltobackup.qualification.archive_runner.JournalOperationalEventSink",
                return_value=operational_sink,
            ) as journal_sink_type,
            redirect_stdout(output),
        ):
            exit_code = main(
                [
                    "--state-root",
                    str(self.root / "qualification-state"),
                    "--config",
                    str(self.root / "config.toml"),
                    "--broker-capability-file",
                    str(self.root / "broker-capability"),
                ]
            )

        self.assertEqual(0, exit_code)
        broker.assert_ready.assert_called_once_with()
        privilege.validate_supervisor.assert_called_once_with()
        runtime_class.assert_called_once()
        journal_sink_type.assert_called_once_with(
            syslog_identifier="lto-archiver-archive-runner-qualification"
        )
        self.assertIs(runtime_class.call_args.kwargs["event_sink"], operational_sink)
        self.assertEqual(
            ["archive_qualification.started", "archive_qualification.succeeded"],
            [event.code for event in operational_events],
        )
        self.assertEqual("TAPE04", json.loads(output.getvalue())["physical_label"])

    def test_module_main_requires_configured_daemon_identity(self) -> None:
        daemon = SimpleNamespace(pw_uid=991, pw_gid=991)
        with (
            mock.patch(
                "ltobackup.qualification.archive_runner.pwd.getpwnam",
                return_value=daemon,
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.os.geteuid", return_value=0
            ),
            mock.patch(
                "ltobackup.qualification.archive_runner.os.getegid", return_value=0
            ),
            self.assertRaisesRegex(SystemExit, "configured lto-archiver identity"),
        ):
            main([])

    def test_selinux_permissive_mode_is_refused(self) -> None:
        enforce = self.root / "enforce"
        current = self.root / "current"
        enforce.write_bytes(b"0\n")
        current.write_bytes(b"system_u:system_r:lto_archiver_t:s0\n")

        with self.assertRaisesRegex(
            QualificationArchiveRefused, "SELinux execution boundary"
        ):
            qualification_module._require_enforced_selinux_domain(enforce, current)

    def test_wrong_selinux_domain_is_refused(self) -> None:
        enforce = self.root / "enforce"
        current = self.root / "current"
        enforce.write_bytes(b"1\n")
        current.write_bytes(b"system_u:system_r:unconfined_t:s0\n")

        with self.assertRaisesRegex(
            QualificationArchiveRefused, "SELinux execution boundary"
        ):
            qualification_module._require_enforced_selinux_domain(enforce, current)

    def test_enforced_selinux_archiver_domain_is_accepted(self) -> None:
        enforce = self.root / "enforce"
        current = self.root / "current"
        enforce.write_bytes(b"1\n")
        current.write_bytes(b"system_u:system_r:lto_archiver_t:s0")

        qualification_module._require_enforced_selinux_domain(enforce, current)

    def test_enforced_selinux_archiver_domain_with_supported_terminator_is_accepted(
        self,
    ) -> None:
        enforce = self.root / "enforce"
        current = self.root / "current"
        enforce.write_bytes(b"1\n")

        for terminator in (b"\n", b"\0", b"\n\0"):
            with self.subTest(terminator=terminator):
                current.write_bytes(
                    b"system_u:system_r:lto_archiver_t:s0" + terminator
                )
                qualification_module._require_enforced_selinux_domain(
                    enforce, current
                )

    def test_selinux_domain_rejects_noncanonical_terminators_and_controls(
        self,
    ) -> None:
        enforce = self.root / "enforce"
        current = self.root / "current"
        enforce.write_bytes(b"1\n")
        invalid_contexts = (
            b"system_u:\0system_r:lto_archiver_t:s0",
            b"system_u:system_r:lto_archiver_t:s0\0\0",
            b"system_u:system_r:lto_archiver_t:s0\n\n",
            b"system_u:system_r:lto_archiver_t:s0\r\n",
            b"system_u:system_r:lto_archiver_t:s0\0\n",
            b"system_u:system_r:lto_archiver_t:s0\0garbage",
            b"system_u:system_r:lto_archiver_t:\x01s0",
            b"system_u:system_r:lto_archiver_t:s0 ",
        )

        for context in invalid_contexts:
            with self.subTest(context=context), self.assertRaisesRegex(
                QualificationArchiveRefused, "SELinux execution boundary"
            ):
                current.write_bytes(context)
                qualification_module._require_enforced_selinux_domain(
                    enforce, current
                )


if __name__ == "__main__":
    unittest.main()
