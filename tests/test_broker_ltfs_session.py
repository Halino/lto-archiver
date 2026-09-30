from __future__ import annotations

import inspect
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import ltobackup.broker.ltfs_session as ltfs_session_module
from ltobackup.broker.ltfs_session import (
    LtfsPinningError,
    LtfsSessionPins,
    derive_receipt_operation_uuid,
    device_fd_identity_sha256,
    mount_path_identity_sha256,
)
from ltobackup.daemon.models import HardwareTargetBinding, media_identity_sha256
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupScopeReceipt,
    LtfsSessionRequest,
)


def _stat_view(
    value: os.stat_result,
    *,
    mode: int | None = None,
    uid: int = 0,
    gid: int = 0,
    rdev: int | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        st_dev=value.st_dev,
        st_ino=value.st_ino,
        st_mode=value.st_mode if mode is None else mode,
        st_nlink=value.st_nlink,
        st_uid=uid,
        st_gid=gid,
        st_rdev=value.st_rdev if rdev is None else rdev,
        st_size=value.st_size,
        st_mtime_ns=value.st_mtime_ns,
    )


class LtfsSessionPinningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.ltfs = self._tool("ltfs", b"ltfs-v1\n")
        self.fusermount = self._tool("fusermount", b"fusermount-v1\n", mode=0o4755)
        self.mount = self.root / "mount"
        self.mount.mkdir(mode=0o755)
        self._mount_inode = self.mount.stat().st_ino
        self._mount_owner = (0, 0)
        self.device_root = self.root / "dev"
        self.tape_by_id = self.device_root / "tape" / "by-id"
        self.tape_by_id.mkdir(parents=True)
        self.device_nodes = self.root / "device-nodes"
        self.device_nodes.mkdir()
        self.tape = self.device_nodes / "nst0"
        self.scsi = self.device_nodes / "sg0"
        self.tape.write_bytes(b"tape-anchor")
        self.scsi.write_bytes(b"scsi-anchor")
        self.tape_path = self.tape_by_id / "drive-tape"
        self.scsi_path = self.device_root / "lto-archiver-scsi-drive-scsi"
        self.tape_path.symlink_to(self.tape)
        self.scsi_path.symlink_to(self.scsi)
        self.sys_class = self.root / "sys" / "class"
        self.scsi_unit = self.root / "sys" / "devices" / "unit-17"
        self.scsi_unit.mkdir(parents=True)
        (self.scsi_unit / "serial").write_text("DRIVE-A\n", encoding="ascii")
        for class_name, device_name in (("scsi_tape", "nst0"), ("scsi_generic", "sg0")):
            device_class = self.sys_class / class_name / device_name
            device_class.mkdir(parents=True)
            (device_class / "device").symlink_to(
                self.scsi_unit, target_is_directory=True
            )
        self._device_inodes = {
            self.tape.stat().st_ino,
            self.scsi.stat().st_ino,
        }
        self._device_rdev = {
            self.tape.stat().st_ino: os.makedev(9, 0),
            self.scsi.stat().st_ino: os.makedev(21, 0),
        }
        self._non_device_inodes: set[int] = set()
        self._bad_owner_paths: set[Path] = set()

        def rooted_fstat(fd: int):
            value = os.fstat(fd)
            if value.st_ino == self._mount_inode:
                return _stat_view(
                    value, uid=self._mount_owner[0], gid=self._mount_owner[1]
                )
            if (
                value.st_ino in self._device_inodes
                and value.st_ino not in self._non_device_inodes
            ):
                return _stat_view(
                    value,
                    mode=stat.S_IFCHR | 0o660,
                    rdev=self._device_rdev[value.st_ino],
                )
            return _stat_view(value)

        def rooted_stat_path(path: Path):
            value = os.stat(path, follow_symlinks=False)
            if value.st_ino == self._mount_inode:
                return _stat_view(
                    value, uid=self._mount_owner[0], gid=self._mount_owner[1]
                )
            uid = 1234 if Path(path) in self._bad_owner_paths else 0
            return _stat_view(value, uid=uid)

        fstat_patcher = patch.object(
            ltfs_session_module, "_fstat", side_effect=rooted_fstat
        )
        stat_patcher = patch.object(
            ltfs_session_module, "_stat_path", side_effect=rooted_stat_path
        )
        fstat_patcher.start()
        stat_patcher.start()
        self.addCleanup(fstat_patcher.stop)
        self.addCleanup(stat_patcher.stop)

        self.tape_fd = os.open(self.tape, os.O_RDONLY | os.O_CLOEXEC)
        self.scsi_fd = os.open(self.scsi, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(self._close_fd, self.scsi_fd)
        self.addCleanup(self._close_fd, self.tape_fd)
        self.tape_fd_digest = device_fd_identity_sha256(self.tape_fd, "tape")
        self.scsi_fd_digest = device_fd_identity_sha256(self.scsi_fd, "scsi")
        target = HardwareTargetBinding.from_verified_inputs(
            self.mount,
            '{"by_id":"drive-tape","serial":"DRIVE-A"}',
            '{"by_id":"lto-archiver-scsi-drive-scsi","serial":"DRIVE-A"}',
            ("archive", "job-17", "1", "TAPE017", "", ""),
        )
        self.tape_target = target.tape_device_identity_sha256
        self.scsi_target = target.scsi_device_identity_sha256

    @staticmethod
    def _close_fd(fd: int) -> None:
        try:
            os.close(fd)
        except OSError:
            pass

    def _tool(self, name: str, content: bytes, *, mode: int = 0o755) -> Path:
        path = self.root / name
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def _request(self, **changes: object) -> LtfsSessionRequest:
        values: dict[str, object] = {
            "protocol_version": 1,
            "operation_id": "operation-17",
            "owner_generation": 9,
            "mount_path_sha256": mount_path_identity_sha256(self.mount),
            "tape_device_identity_sha256": self.tape_target,
            "scsi_device_identity_sha256": self.scsi_target,
            "expected_media_scope_sha256": "4" * 64,
            "observed_media_identity_sha256": "5" * 64,
            "expected_volume_uuid": "22222222-2222-4222-8222-222222222222",
            "expected_prior_generation": 7,
            "read_only": False,
            "tape_fd_identity_sha256": self.tape_fd_digest,
            "scsi_fd_identity_sha256": self.scsi_fd_digest,
            "cgroup_scope_receipt": BrokeredCgroupScopeReceipt(
                protocol_version=1,
                command_id="command-17",
                owner_generation=9,
                request_nonce=b"r" * 32,
                scope_id="scope-17",
                scope_path_sha256="a" * 64,
                broker_nonce=b"n" * 32,
                broker_proof=b"p" * 32,
                recursive_population=True,
                recursive_members=True,
                cgroup_kill=True,
            ),
            "request_nonce": b"l" * 32,
        }
        values.update(changes)
        return LtfsSessionRequest(**values)  # type: ignore[arg-type]

    def _pins(self) -> LtfsSessionPins:
        pins = LtfsSessionPins.open(
            ltfs_path=self.ltfs,
            fusermount_path=self.fusermount,
            mount_path=self.mount,
            tape_device_path=self.tape_path,
            scsi_device_path=self.scsi_path,
            device_root=self.device_root,
            sys_class=self.sys_class,
        )
        self.addCleanup(pins.close)
        return pins

    def test_receipt_root_issues_only_identity_bound_root_owned_targets(self) -> None:
        receipt_root_type = getattr(
            ltfs_session_module, "LtfsStandaloneReceiptRoot", None
        )
        self.assertIsNotNone(receipt_root_type)
        receipt_dir = self.root / "standalone-receipts"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = receipt_root_type.open(receipt_dir)
        self.addCleanup(receipt_root.close)

        target = receipt_root.target_path(
            operation_id="11111111-1111-4111-8111-111111111111",
            owner_generation=9,
            request_sha256="a" * 64,
        )
        self.assertEqual(
            target,
            receipt_dir
            / "e3f1bb11f744b8c3f314562875f6f4192ed789ca20cc71a6024817f46d936e35.json",
        )
        self.assertFalse(target.exists())
        self.assertFalse(Path(f"{target}.ready").exists())
        self.assertFalse(Path(f"{target}.pending").exists())

        target.write_text("occupied", encoding="ascii")
        target.chmod(0o600)
        with self.assertRaises(LtfsPinningError):
            receipt_root.target_path(
                operation_id="11111111-1111-4111-8111-111111111111",
                owner_generation=9,
                request_sha256="a" * 64,
            )
        target.unlink()
        Path(f"{target}.tmp").write_text("occupied", encoding="ascii")
        with self.assertRaises(LtfsPinningError):
            receipt_root.target_path(
                operation_id="11111111-1111-4111-8111-111111111111",
                owner_generation=9,
                request_sha256="a" * 64,
            )

    def test_receipt_operation_uuid_is_domain_separated_and_identity_bound(
        self,
    ) -> None:
        base = derive_receipt_operation_uuid(
            operation_id="operation-0123456789abcdef0123456789abcdef",
            owner_generation=9,
            request_sha256="a" * 64,
        )
        self.assertEqual(
            base,
            derive_receipt_operation_uuid(
                operation_id="operation-0123456789abcdef0123456789abcdef",
                owner_generation=9,
                request_sha256="a" * 64,
            ),
        )
        self.assertRegex(
            base,
            r"^[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
        )
        self.assertNotEqual(
            base,
            derive_receipt_operation_uuid(
                operation_id="operation-0123456789abcdef0123456789abcdee",
                owner_generation=9,
                request_sha256="a" * 64,
            ),
        )
        self.assertNotEqual(
            base,
            derive_receipt_operation_uuid(
                operation_id="operation-0123456789abcdef0123456789abcdef",
                owner_generation=10,
                request_sha256="a" * 64,
            ),
        )
        self.assertNotEqual(
            base,
            derive_receipt_operation_uuid(
                operation_id="operation-0123456789abcdef0123456789abcdef",
                owner_generation=9,
                request_sha256="b" * 64,
            ),
        )

    def test_ready_receipt_matches_frozen_c_fixture_and_is_identity_bound(self) -> None:
        receipt_dir = self.root / "ready-receipts"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = ltfs_session_module.LtfsStandaloneReceiptRoot.open(receipt_dir)
        self.addCleanup(receipt_root.close)
        operation_uuid = "11111111-1111-4111-8111-111111111111"
        target = receipt_root.target_path(
            operation_id=operation_uuid,
            owner_generation=9,
            request_sha256="a" * 64,
        )
        Path(f"{target}.ready").write_bytes(
            b'{"schema":1,"stage":"ready","operation_id":"11111111-1111-4111-8111-111111111111","volume_uuid":"22222222-2222-4222-8222-222222222222","prior_generation":7,"read_only":false,"drive_serial":"DRIVE-TEST-01","mam_barcode":"TEST01","mam_volume_serial":"SERIAL-TEST-01","ltfs_volume_label":"TEST VOLUME"}\n'
        )
        Path(f"{target}.ready").chmod(0o600)
        ready = receipt_root.wait_ready(
            operation_id=operation_uuid,
            owner_generation=9,
            request_sha256="a" * 64,
            expected_media_identity_sha256=media_identity_sha256(
                (
                    "DRIVE-TEST-01",
                    "TEST01",
                    "SERIAL-TEST-01",
                    "TEST VOLUME",
                    "22222222-2222-4222-8222-222222222222",
                )
            ),
            expected_read_only=False,
            timeout=0.1,
        )
        self.assertEqual(ready.volume_uuid, "22222222-2222-4222-8222-222222222222")
        self.assertEqual(ready.prior_generation, 7)

        Path(f"{target}.ready").write_bytes(
            b'{"schema":1,"stage":"ready","operation_id":"11111111-1111-4111-8111-111111111111","volume_uuid":"22222222-2222-4222-8222-222222222222","prior_generation":7,"read_only":false,"drive_serial":"DRIVE-TEST-01","mam_barcode":"TEST01","mam_volume_serial":"SERIAL-TEST-02","ltfs_volume_label":"TEST VOLUME"}\n'
        )
        with self.assertRaises(LtfsPinningError):
            receipt_root.wait_ready(
                operation_id=operation_uuid,
                owner_generation=9,
                request_sha256="a" * 64,
                expected_media_identity_sha256=media_identity_sha256(
                    (
                        "DRIVE-TEST-01",
                        "TEST01",
                        "SERIAL-TEST-01",
                        "TEST VOLUME",
                        "22222222-2222-4222-8222-222222222222",
                    )
                ),
                expected_read_only=False,
                timeout=0.1,
            )

    def test_ready_waits_for_atomic_writer_to_remove_linked_temporary(self) -> None:
        receipt_dir = self.root / "ready-publication"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = ltfs_session_module.LtfsStandaloneReceiptRoot.open(receipt_dir)
        self.addCleanup(receipt_root.close)
        operation_uuid = "11111111-1111-4111-8111-111111111111"
        target = receipt_root.target_path(
            operation_id=operation_uuid,
            owner_generation=9,
            request_sha256="a" * 64,
        )
        temporary = Path(f"{target}.ready.tmp")
        ready_path = Path(f"{target}.ready")
        temporary.write_bytes(
            b'{"schema":1,"stage":"ready","operation_id":"11111111-1111-4111-8111-111111111111","volume_uuid":"22222222-2222-4222-8222-222222222222","prior_generation":7,"read_only":false,"drive_serial":"DRIVE-TEST-01","mam_barcode":"TEST01","mam_volume_serial":"SERIAL-TEST-01","ltfs_volume_label":"TEST VOLUME"}\n'
        )
        temporary.chmod(0o600)
        os.link(temporary, ready_path)

        def finish_publication() -> None:
            time.sleep(0.05)
            temporary.unlink()

        publisher = threading.Thread(target=finish_publication)
        publisher.start()
        self.addCleanup(publisher.join)
        ready = receipt_root.wait_ready(
            operation_id=operation_uuid,
            owner_generation=9,
            request_sha256="a" * 64,
            expected_media_identity_sha256=media_identity_sha256(
                (
                    "DRIVE-TEST-01",
                    "TEST01",
                    "SERIAL-TEST-01",
                    "TEST VOLUME",
                    "22222222-2222-4222-8222-222222222222",
                )
            ),
            expected_read_only=False,
            timeout=0.5,
        )
        publisher.join()
        self.assertEqual(ready.prior_generation, 7)

    def test_ready_wait_aborts_before_sleep_when_child_is_no_longer_running(
        self,
    ) -> None:
        receipt_dir = self.root / "ready-child-exited"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = ltfs_session_module.LtfsStandaloneReceiptRoot.open(receipt_dir)
        self.addCleanup(receipt_root.close)
        checks = []

        def child_running() -> bool:
            checks.append(True)
            return False

        with (
            patch.object(
                ltfs_session_module.time,
                "sleep",
                side_effect=AssertionError("wait slept after child exit"),
            ),
            self.assertRaises(LtfsPinningError),
        ):
            receipt_root.wait_ready(
                operation_id="11111111-1111-4111-8111-111111111111",
                owner_generation=9,
                request_sha256="a" * 64,
                expected_media_identity_sha256="b" * 64,
                expected_read_only=True,
                timeout=86_400.0,
                child_running=child_running,
            )
        self.assertEqual(checks, [True])

    def test_ready_identity_accepts_json_escaped_slash_and_backslash_as_data(
        self,
    ) -> None:
        receipt_dir = self.root / "ready-data-characters"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = ltfs_session_module.LtfsStandaloneReceiptRoot.open(receipt_dir)
        self.addCleanup(receipt_root.close)
        operation_uuid = "11111111-1111-4111-8111-111111111111"
        volume_uuid = "22222222-2222-4222-8222-222222222222"
        identity = (
            "DRIVE/TEST\\01",
            "BAR/CODE\\01",
            "SERIAL/TEST\\01",
            "LABEL/TEST\\01",
            volume_uuid,
        )
        payload = {
            "schema": 1,
            "stage": "ready",
            "operation_id": operation_uuid,
            "volume_uuid": volume_uuid,
            "prior_generation": 7,
            "read_only": False,
            "drive_serial": identity[0],
            "mam_barcode": identity[1],
            "mam_volume_serial": identity[2],
            "ltfs_volume_label": identity[3],
        }
        target = receipt_root.target_path(
            operation_id=operation_uuid,
            owner_generation=9,
            request_sha256="a" * 64,
        )
        Path(f"{target}.ready").write_bytes(
            (
                json.dumps(payload, ensure_ascii=True, separators=(",", ":")) + "\n"
            ).encode("ascii")
        )
        Path(f"{target}.ready").chmod(0o600)
        ready = receipt_root.wait_ready(
            operation_id=operation_uuid,
            owner_generation=9,
            request_sha256="a" * 64,
            expected_media_identity_sha256=media_identity_sha256(identity),
            expected_read_only=False,
            timeout=0.1,
        )
        self.assertEqual("LABEL/TEST\\01", ready.ltfs_volume_label)

        Path(f"{target}.ready").write_bytes(
            b'{"schema":1,"stage":"ready","operation_id":"11111111-1111-4111-8111-111111111111","volume_uuid":"22222222-2222-4222-8222-222222222222","prior_generation":0,"read_only":false,"drive_serial":"DRIVE-TEST-01","mam_barcode":"TEST01","mam_volume_serial":"SERIAL-TEST-01","ltfs_volume_label":"TEST VOLUME"}\n'
        )
        with self.assertRaises(LtfsPinningError):
            receipt_root.wait_ready(
                operation_id=operation_uuid,
                owner_generation=9,
                request_sha256="a" * 64,
                expected_media_identity_sha256=media_identity_sha256(
                    (
                        "DRIVE-TEST-01",
                        "TEST01",
                        "SERIAL-TEST-01",
                        "TEST VOLUME",
                        "22222222-2222-4222-8222-222222222222",
                    )
                ),
                expected_read_only=False,
                timeout=0.1,
            )

    def test_receipt_uuids_are_canonical_lowercase(self) -> None:
        for value in (
            "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
            "11111111111141118111111111111111",
            "11111111-1111-4111-8111-11111111111g",
        ):
            with self.subTest(value=value), self.assertRaises(LtfsPinningError):
                ltfs_session_module._validate_receipt_uuid(value)

    def test_receipt_root_rejects_nonprivate_or_nonroot_directories(self) -> None:
        receipt_root_type = ltfs_session_module.LtfsStandaloneReceiptRoot
        receipt_dir = self.root / "unsafe-receipts"
        receipt_dir.mkdir(mode=0o750)
        with self.assertRaises(LtfsPinningError):
            receipt_root_type.open(receipt_dir)
        receipt_dir.chmod(0o700)
        self._bad_owner_paths.add(receipt_dir)
        with self.assertRaises(LtfsPinningError):
            receipt_root_type.open(receipt_dir)

    def test_terminal_receipt_parser_mirrors_the_exact_c_fixture(self) -> None:
        receipt_dir = self.root / "terminal-receipts"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = ltfs_session_module.LtfsStandaloneReceiptRoot.open(receipt_dir)
        self.addCleanup(receipt_root.close)
        operation_id = "11111111-1111-4111-8111-111111111111"
        target = receipt_root.target_path(
            operation_id=operation_id,
            owner_generation=9,
            request_sha256="a" * 64,
        )
        target.write_bytes(
            b'{"schema":1,"stage":"terminal",'
            b'"operation_id":"11111111-1111-4111-8111-111111111111",'
            b'"volume_uuid":"22222222-2222-4222-8222-222222222222",'
            b'"prior_generation":7,"new_generation":8,'
            b'"bytes_valid":true,"bytes":1234,'
            b'"files_valid":true,"files":4,'
            b'"phase_duration_ns":[0,0,0,0,0,0,0,0,0,0,0],'
            b'"capture_duration_ns":0,"device_close_duration_ns":0,'
            b'"device_close_result_valid":true,"device_close_result":0,'
            b'"catalog_ack_duration_ns":0,"media_committed":true,'
            b'"catalog_acknowledged":true,"cleanup_failed":false,'
            b'"result":0}\n'
        )
        target.chmod(0o600)
        self.assertTrue(hasattr(receipt_root, "read_terminal"))

        receipt = receipt_root.read_terminal(
            operation_id=operation_id,
            owner_generation=9,
            request_sha256="a" * 64,
        )
        self.assertEqual(receipt.operation_id, operation_id)
        self.assertEqual(receipt.volume_uuid, "22222222-2222-4222-8222-222222222222")
        self.assertEqual((receipt.prior_generation, receipt.new_generation), (7, 8))
        self.assertEqual((receipt.bytes_valid, receipt.bytes), (True, 1234))
        self.assertEqual((receipt.files_valid, receipt.files), (True, 4))
        self.assertEqual(receipt.phase_duration_ns, (0,) * 11)
        self.assertTrue(receipt.media_committed)
        self.assertTrue(receipt.catalog_acknowledged)
        self.assertTrue(receipt.device_close_result_valid)
        self.assertFalse(receipt.cleanup_failed)
        self.assertEqual((receipt.device_close_result, receipt.result), (0, 0))

    def test_terminal_receipt_rejects_partial_foreign_and_failed_evidence(self) -> None:
        receipt_dir = self.root / "invalid-terminal-receipts"
        receipt_dir.mkdir(mode=0o700)
        receipt_root = ltfs_session_module.LtfsStandaloneReceiptRoot.open(receipt_dir)
        self.addCleanup(receipt_root.close)
        operation_id = "11111111-1111-4111-8111-111111111111"
        cases = (
            "missing_result",
            "foreign_operation",
            "invalid_volume",
            "generation_regression",
            "short_phases",
            "invalid_bytes",
            "prepared_stage",
            "unacknowledged",
            "close_unverified",
            "nonzero_result",
        )
        for index, case in enumerate(cases, 1):
            source = {
                "schema": 1,
                "stage": "terminal",
                "operation_id": operation_id,
                "volume_uuid": "22222222-2222-4222-8222-222222222222",
                "prior_generation": 7,
                "new_generation": 8,
                "bytes_valid": True,
                "bytes": 1234,
                "files_valid": True,
                "files": 4,
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
            if case == "missing_result":
                source.pop("result")
            elif case == "foreign_operation":
                source["operation_id"] = "33333333-3333-4333-8333-333333333333"
            elif case == "invalid_volume":
                source["volume_uuid"] = "not-a-volume-uuid"
            elif case == "generation_regression":
                source["new_generation"] = 6
            elif case == "short_phases":
                source["phase_duration_ns"] = [0] * 10
            elif case == "invalid_bytes":
                source["bytes_valid"] = False
            elif case == "prepared_stage":
                source["stage"] = "prepared"
            elif case == "unacknowledged":
                source["catalog_acknowledged"] = False
            elif case == "close_unverified":
                source["device_close_result_valid"] = False
            elif case == "nonzero_result":
                source["cleanup_failed"] = True
                source["result"] = -5
            request_sha256 = f"{index:064x}"
            target = receipt_root.target_path(
                operation_id=operation_id,
                owner_generation=index,
                request_sha256=request_sha256,
            )
            target.write_text(
                json.dumps(source, separators=(",", ":")) + "\n",
                encoding="ascii",
            )
            target.chmod(0o600)
            with self.subTest(case=case), self.assertRaises(LtfsPinningError):
                receipt_root.read_terminal(
                    operation_id=operation_id,
                    owner_generation=index,
                    request_sha256=request_sha256,
                )

    def test_startup_pins_exact_tools_and_mount_for_fd_only_execution(self) -> None:
        pins = self._pins()
        validated = pins.validate_request(
            self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
        )
        self.addCleanup(validated.close)

        self.assertEqual(validated.mount_path, self.mount)
        self.assertEqual(
            validated.ltfs_exec_path, Path(f"/proc/self/fd/{validated.ltfs_fd}")
        )
        self.assertEqual(
            validated.fusermount_exec_path,
            Path(f"/proc/self/fd/{validated.fusermount_fd}"),
        )
        self.assertNotEqual(validated.tape_fd, self.tape_fd)
        self.assertNotEqual(validated.scsi_fd, self.scsi_fd)
        self.assertEqual(
            os.fstat(validated.tape_fd).st_ino, os.fstat(self.tape_fd).st_ino
        )
        self.assertEqual(
            os.fstat(validated.scsi_fd).st_ino, os.fstat(self.scsi_fd).st_ino
        )
        self.assertFalse(hasattr(pins, "ltfs"))
        self.assertEqual(len(pins.ltfs_tool_identity_sha256), 64)
        self.assertNotEqual(
            pins.ltfs_tool_identity_sha256,
            pins.fusermount_tool_identity_sha256,
        )

        validated.close()
        self.assertEqual(
            (
                validated._ltfs_fd,
                validated._fusermount_fd,
                validated.tape_fd,
                validated.scsi_fd,
            ),
            (-1, -1, -1, -1),
        )
        with self.assertRaises(LtfsPinningError):
            _ = validated.ltfs_fd

    def test_finalization_anchor_allows_expected_mounted_root_replacement(self) -> None:
        pins = self._pins()
        validated = pins.validate_request(
            self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
        )
        self.addCleanup(validated.close)
        mounted_root = self.root / "mounted-root"
        mounted_root.mkdir()
        mounted_status = os.stat(mounted_root, follow_symlinks=False)
        original_stat = ltfs_session_module._stat_path

        def mounted_stat(path: Path):
            if path == self.mount:
                return mounted_status
            return original_stat(path)

        with patch.object(ltfs_session_module, "_stat_path", side_effect=mounted_stat):
            with self.assertRaises(LtfsPinningError):
                validated.assert_launch_anchors()
            validated.assert_finalization_anchors()

    def test_fuse2_finalizer_has_a_narrow_setuid_policy(self) -> None:
        default = (
            inspect.signature(LtfsSessionPins.open)
            .parameters["fusermount_path"]
            .default
        )
        self.assertEqual(default, Path("/usr/bin/fusermount"))

        self.fusermount.chmod(0o755)
        with self.assertRaises(LtfsPinningError):
            self._pins()

        self.fusermount.chmod(0o4755)
        self.ltfs.chmod(0o4755)
        with self.assertRaises(LtfsPinningError):
            self._pins()

        for role in ("unexpected-role", None):
            pinned = None
            try:
                with self.subTest(role=role), self.assertRaises(LtfsPinningError):
                    pinned = LtfsSessionPins._pin_tool(role, self.fusermount)
            finally:
                if pinned is not None:
                    os.close(pinned.fd)

    def test_scsi_pin_rejects_the_legacy_nested_by_id_namespace(self) -> None:
        legacy_parent = self.device_root / "disk" / "by-id"
        legacy_parent.mkdir(parents=True)
        legacy_path = legacy_parent / "drive-scsi"
        legacy_path.symlink_to(self.scsi)

        with self.assertRaises(LtfsPinningError):
            LtfsSessionPins.open(
                ltfs_path=self.ltfs,
                fusermount_path=self.fusermount,
                mount_path=self.mount,
                tape_device_path=self.tape_path,
                scsi_device_path=legacy_path,
                device_root=self.device_root,
                sys_class=self.sys_class,
            )

    def test_mount_digest_matches_the_existing_hardware_target_contract(self) -> None:
        target = HardwareTargetBinding.from_verified_inputs(
            self.mount,
            "stable-tape",
            "stable-scsi",
            ("archive", "job-17", "1", "TAPE017", "", ""),
        )
        self.assertEqual(
            mount_path_identity_sha256(self.mount), target.mount_path_sha256
        )

    def test_startup_rejects_symlink_hardlink_and_nonexact_tool_mode(self) -> None:
        cases: list[tuple[str, callable]] = []
        symlink = self.root / "ltfs-link"
        symlink.symlink_to(self.ltfs)
        cases.append(("symlink", lambda: symlink))
        hardlink = self.root / "ltfs-hard"
        os.link(self.ltfs, hardlink)
        cases.append(("hardlink", lambda: hardlink))
        wrong_mode = self._tool("ltfs-wrong-mode", b"wrong-mode\n")
        wrong_mode.chmod(0o750)
        cases.append(("mode", lambda: wrong_mode))

        for name, path in cases:
            with self.subTest(name=name), self.assertRaises(LtfsPinningError):
                LtfsSessionPins.open(
                    ltfs_path=path(),
                    fusermount_path=self.fusermount,
                    mount_path=self.mount,
                    tape_device_path=self.tape_path,
                    scsi_device_path=self.scsi_path,
                    device_root=self.device_root,
                    sys_class=self.sys_class,
                )

    def test_tool_path_replacement_or_symlink_after_pinning_fails_closed(self) -> None:
        for replacement_kind in ("file", "symlink"):
            with self.subTest(replacement_kind=replacement_kind):
                pins = self._pins()
                original = self.root / f"ltfs-original-{replacement_kind}"
                self.ltfs.rename(original)
                if replacement_kind == "file":
                    self.ltfs = self._tool("ltfs", b"replacement\n")
                else:
                    self.ltfs.symlink_to(self.fusermount)
                with self.assertRaises(LtfsPinningError):
                    pins.validate_request(
                        self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
                    )
                self.ltfs.unlink()
                original.rename(self.ltfs)

    def test_in_place_tool_mutation_and_metadata_mutation_fail_closed(self) -> None:
        cases = ("content", "mode", "owner")
        for mutation in cases:
            with self.subTest(mutation=mutation):
                pins = self._pins()
                if mutation == "content":
                    self.ltfs.write_bytes(b"mutated-in-place\n")
                    self.ltfs.chmod(0o755)
                elif mutation == "mode":
                    self.ltfs.chmod(0o750)
                else:
                    self._bad_owner_paths.add(self.ltfs)
                with self.assertRaises(LtfsPinningError):
                    pins.validate_request(
                        self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
                    )
                self._bad_owner_paths.discard(self.ltfs)
                self.ltfs.write_bytes(b"ltfs-v1\n")
                self.ltfs.chmod(0o755)

    def test_mount_root_swap_or_symlink_fails_closed(self) -> None:
        for replacement_kind in ("directory", "symlink"):
            with self.subTest(replacement_kind=replacement_kind):
                pins = self._pins()
                original = self.root / f"mount-original-{replacement_kind}"
                self.mount.rename(original)
                if replacement_kind == "directory":
                    self.mount.mkdir(mode=0o755)
                else:
                    self.mount.symlink_to(original, target_is_directory=True)
                with self.assertRaises(LtfsPinningError):
                    pins.validate_request(
                        self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
                    )
                if self.mount.is_symlink():
                    self.mount.unlink()
                else:
                    self.mount.rmdir()
                original.rename(self.mount)

    def test_configured_mount_accepts_daemon_ownership_and_seals_it(self) -> None:
        self.mount.chmod(0o750)
        self._mount_owner = (1200, 1200)
        pins = self._pins()

        self._mount_owner = (1201, 1200)
        with self.assertRaises(LtfsPinningError):
            pins.validate_request(
                self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
            )

    def test_swapped_or_non_device_descriptors_fail_before_validation(self) -> None:
        pins = self._pins()
        with self.assertRaises(LtfsPinningError):
            pins.validate_request(
                self._request(), tape_fd=self.scsi_fd, scsi_fd=self.tape_fd
            )

        self._non_device_inodes.add(os.fstat(self.tape_fd).st_ino)
        with self.assertRaises(LtfsPinningError):
            pins.validate_request(
                self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
            )

    def test_configured_by_id_swap_and_cross_unit_pair_fail_closed(self) -> None:
        pins = self._pins()
        replacement = self.device_nodes / "nst1"
        replacement.write_bytes(b"other-tape")
        replacement_inode = replacement.stat().st_ino
        self._device_inodes.add(replacement_inode)
        self._device_rdev[replacement_inode] = os.makedev(9, 1)
        self.tape_path.unlink()
        self.tape_path.symlink_to(replacement)
        with self.assertRaises(LtfsPinningError):
            pins.validate_request(
                self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
            )

        self.tape_path.unlink()
        self.tape_path.symlink_to(self.tape)
        other_unit = self.root / "sys" / "devices" / "unit-other"
        other_unit.mkdir()
        (other_unit / "serial").write_text("DRIVE-B\n", encoding="ascii")
        scsi_device_link = self.sys_class / "scsi_generic" / "sg0" / "device"
        scsi_device_link.unlink()
        scsi_device_link.symlink_to(other_unit, target_is_directory=True)
        with self.assertRaises(LtfsPinningError):
            LtfsSessionPins.open(
                ltfs_path=self.ltfs,
                fusermount_path=self.fusermount,
                mount_path=self.mount,
                tape_device_path=self.tape_path,
                scsi_device_path=self.scsi_path,
                device_root=self.device_root,
                sys_class=self.sys_class,
            )

    def test_target_fd_and_mount_digest_mismatches_fail_closed(self) -> None:
        pins = self._pins()
        cases = (
            {"mount_path_sha256": "8" * 64},
            {"tape_device_identity_sha256": "8" * 64},
            {"scsi_device_identity_sha256": "8" * 64},
            {"tape_fd_identity_sha256": "8" * 64},
            {"scsi_fd_identity_sha256": "8" * 64},
        )
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(LtfsPinningError):
                pins.validate_request(
                    self._request(**changes),
                    tape_fd=self.tape_fd,
                    scsi_fd=self.scsi_fd,
                )

    def test_closed_api_accepts_no_daemon_path_or_argv(self) -> None:
        pins = self._pins()
        signature = inspect.signature(pins.validate_request)
        self.assertEqual(tuple(signature.parameters), ("request", "tape_fd", "scsi_fd"))
        with self.assertRaises(TypeError):
            pins.validate_request(
                self._request(),
                tape_fd=self.tape_fd,
                scsi_fd=self.scsi_fd,
                mount_path=Path("/tmp/attacker"),
            )
        with self.assertRaises(TypeError):
            pins.validate_request(
                self._request(),
                tape_fd=self.tape_fd,
                scsi_fd=self.scsi_fd,
                argv=("/bin/sh",),
            )

        with self.assertRaises(TypeError):
            LtfsSessionPins(
                ltfs=pins._ltfs,
                fusermount=pins._fusermount,
                mount=pins._mount,
                tape_target=pins._tape_target,
                scsi_target=pins._scsi_target,
            )

    def test_exec_lease_revalidates_and_survives_pinset_close_without_fd_reuse(
        self,
    ) -> None:
        pins = self._pins()
        validated = pins.validate_request(
            self._request(), tape_fd=self.tape_fd, scsi_fd=self.scsi_fd
        )
        self.addCleanup(validated.close)
        lease_fd = validated.ltfs_fd
        pins.close()

        replacement = self._tool("post-close-replacement", b"replacement\n")
        replacement_fd = os.open(replacement, os.O_PATH | os.O_CLOEXEC)
        self.addCleanup(self._close_fd, replacement_fd)
        self.assertNotEqual(replacement_fd, lease_fd)
        self.assertEqual(validated.ltfs_exec_path, Path(f"/proc/self/fd/{lease_fd}"))

        self.ltfs.write_bytes(b"mutated-after-validation\n")
        self.ltfs.chmod(0o755)
        with self.assertRaises(LtfsPinningError):
            _ = validated.ltfs_exec_path

    def test_validation_failure_closes_any_partially_duplicated_descriptors(
        self,
    ) -> None:
        pins = self._pins()
        duplicated: list[int] = []
        real_duplicate = ltfs_session_module._duplicate_fd

        def observe_duplicate(fd: int) -> int:
            if duplicated:
                raise LtfsPinningError
            duplicate = real_duplicate(fd)
            duplicated.append(duplicate)
            return duplicate

        with (
            patch.object(
                ltfs_session_module, "_duplicate_fd", side_effect=observe_duplicate
            ),
            self.assertRaises(LtfsPinningError),
        ):
            pins.validate_request(
                self._request(),
                tape_fd=self.tape_fd,
                scsi_fd=self.scsi_fd,
            )

        self.assertTrue(duplicated)
        for fd in duplicated:
            with self.assertRaises(OSError):
                os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
