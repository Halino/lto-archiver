from __future__ import annotations

import errno
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from ltobackup.application import LtoApplication
from ltobackup.catalog import Catalog
from ltobackup.daemon.management import ManagementService
from ltobackup.daemon.restore_destination import (
    RestoreDestinationAdmissionError,
    RestoreDestinationNotWritable,
    RestoreDestinationVerifier,
)
from ltobackup.share_broker.protocol import ShareMountReceiptV1
from ltobackup.share_broker.systemd import mount_unit_name


class FakeManagement:
    def __init__(self, receipt: ShareMountReceiptV1) -> None:
        self.receipt = receipt
        self.inspected: list[str] = []

    def inspect_managed_share_mount(self, share_id: str) -> ShareMountReceiptV1:
        self.inspected.append(share_id)
        return self.receipt


class ReceiptManagement(ManagementService):
    def __init__(self, application: LtoApplication, receipt: ShareMountReceiptV1) -> None:
        super().__init__(application)
        self.receipt = receipt
        self.observed_share_id: str | None = None

    @staticmethod
    def _share_config(row):
        return object()

    def _inspect_actual_mount(self, share, _config):
        self.observed_share_id = str(share["share_id"])
        return self.receipt


class RestoreDestinationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.anchor = self.root / "configured-restore"
        self.destination = self.anchor / "selection"
        self.destination.mkdir(parents=True)
        self.anchor.chmod(0o700)
        self.destination.chmod(0o700)

    def local_plan(self, **destination_changes: object) -> dict[str, object]:
        destination: dict[str, object] = {
            "kind": "local",
            "root": str(self.destination),
            "anchor": str(self.anchor),
        }
        destination.update(destination_changes)
        return {
            "destination_root": str(self.destination),
            "destination": destination,
        }

    def mounted_receipt(self, **changes: object) -> ShareMountReceiptV1:
        mount_target = self.anchor
        values: dict[str, object] = {
            "schema": 1,
            "action": "mount.inspect",
            "share_id": "archive",
            "request_sha256": "1" * 64,
            "config_revision": 3,
            "credential_generation": 2,
            "unit_name": mount_unit_name(mount_target),
            "mount_identity_sha256": "2" * 64,
            "read_only": True,
            "result": "mounted",
            "safe_error_code": None,
            "broker_nonce": b"n" * 32,
            "broker_proof": b"p" * 32,
            "endpoint_server": "nas.example",
            "admitted_addresses": ("192.0.2.10",),
            "filesystem_type": "cifs",
            "source_sha256": "3" * 64,
        }
        values.update(changes)
        return ShareMountReceiptV1(**values)  # type: ignore[arg-type]

    def managed_plan(self, **destination_changes: object) -> dict[str, object]:
        destination: dict[str, object] = {
            "kind": "managed_share",
            "root": str(self.destination),
            "anchor": str(self.anchor),
            "share_id": "archive",
            "config_revision": 3,
            "credential_generation": 2,
            "mount_target": str(self.anchor),
            "filesystem_type": "cifs",
            "source_sha256": "3" * 64,
            "read_only": True,
            "mount_identity_sha256": "2" * 64,
        }
        destination.update(destination_changes)
        return {
            "destination_root": str(self.destination),
            "destination": destination,
        }

    def test_local_root_beneath_anchor_returns_owned_idempotent_lease(self) -> None:
        verifier = RestoreDestinationVerifier()

        lease = verifier.admit(self.local_plan())

        self.assertEqual(self.destination.resolve(), lease.canonical_root)
        self.assertEqual("local", lease.destination_kind)
        self.assertIsNone(lease.managed_share_identity)
        self.assertTrue(os.fstat(lease.root_fd).st_ino)
        descriptor = lease.root_fd
        lease.close()
        lease.close()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_context_manager_closes_local_root_descriptor(self) -> None:
        verifier = RestoreDestinationVerifier()
        with verifier.admit(self.local_plan()) as lease:
            descriptor = lease.root_fd
            self.assertTrue(os.fstat(descriptor).st_ino)
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_local_root_rejects_group_or_other_writable_permissions(self) -> None:
        self.destination.chmod(0o777)

        with self.assertRaises(RestoreDestinationAdmissionError):
            RestoreDestinationVerifier().admit(self.local_plan())

    def test_second_lease_for_same_root_fails_closed(self) -> None:
        first = RestoreDestinationVerifier().admit(self.local_plan())
        self.addCleanup(first.close)

        with self.assertRaises(RestoreDestinationAdmissionError):
            RestoreDestinationVerifier().admit(self.local_plan())

        first.close()
        replacement = RestoreDestinationVerifier().admit(self.local_plan())
        replacement.close()

    def test_unsupported_destination_lock_fails_closed(self) -> None:
        with patch(
            "ltobackup.daemon.restore_destination.fcntl.flock",
            side_effect=OSError(errno.EOPNOTSUPP, "unsupported"),
        ), self.assertRaisesRegex(
            RestoreDestinationAdmissionError, "exclusive lock is unavailable"
        ):
            RestoreDestinationVerifier().admit(self.local_plan())

    def test_close_cannot_race_the_copy_root_descriptor_duplication(self) -> None:
        lease = RestoreDestinationVerifier().admit(self.local_plan())
        duplicate_started = threading.Event()
        permit_duplicate = threading.Event()
        close_finished = threading.Event()
        acquired: list[int] = []
        original_dup = os.dup

        def delayed_dup(descriptor: int) -> int:
            duplicate_started.set()
            self.assertTrue(permit_duplicate.wait(2.0))
            return original_dup(descriptor)

        def acquire() -> None:
            acquired.append(lease.acquire_copy_root())

        def close() -> None:
            lease.close()
            close_finished.set()

        with patch(
            "ltobackup.daemon.restore_destination.os.dup", side_effect=delayed_dup
        ):
            borrower = threading.Thread(target=acquire)
            borrower.start()
            self.assertTrue(duplicate_started.wait(2.0))
            closer = threading.Thread(target=close)
            closer.start()
            self.assertFalse(close_finished.wait(0.05))
            permit_duplicate.set()
            borrower.join(2.0)
            closer.join(2.0)

        self.assertEqual(1, len(acquired))
        lease.release_copy_root(acquired[0])
        self.assertTrue(close_finished.is_set())

    def test_local_root_must_be_exact_canonical_beneath_anchor_without_symlinks(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        symlink = self.anchor / "link"
        symlink.symlink_to(outside, target_is_directory=True)
        cases = (
            self.local_plan(root=str(symlink)),
            self.local_plan(anchor=str(self.destination / "child")),
            self.local_plan(root=str(self.destination) + "/."),
            {
                "destination_root": str(self.destination),
                "destination": {
                    "kind": "local",
                    "root": str(self.destination),
                    "anchor": str(self.anchor),
                    "unexpected": True,
                },
            },
        )
        for plan in cases:
            with self.subTest(plan=plan), self.assertRaises(
                RestoreDestinationAdmissionError
            ):
                RestoreDestinationVerifier().admit(plan)

    def test_root_must_equal_frozen_plan_destination(self) -> None:
        plan = self.local_plan()
        plan["destination_root"] = str(self.anchor)
        with self.assertRaises(RestoreDestinationAdmissionError):
            RestoreDestinationVerifier().admit(plan)

    def test_managed_share_is_inspected_but_read_only_receipt_is_not_writable(self) -> None:
        management = FakeManagement(self.mounted_receipt())
        verifier = RestoreDestinationVerifier(management_service=management)

        with self.assertRaises(RestoreDestinationNotWritable):
            verifier.admit(self.managed_plan())

        self.assertEqual(["archive"], management.inspected)

    def test_management_public_inspection_uses_persisted_normalized_share(self) -> None:
        application = LtoApplication(self.root / "state")
        application.ensure_initialized(min_age_seconds=0)
        receipt = self.mounted_receipt()
        with Catalog(application.paths.catalog_file) as catalog:
            catalog.initialize()
            catalog.create_managed_share(
                "archive",
                "Archive",
                "nfs",
                json.dumps(
                    {
                        "kind": "nfs",
                        "server": "nas.example",
                        "export": "/archive",
                        "version": "4.2",
                        "retransmissions": 2,
                        "timeout_seconds": 30,
                    },
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                actor="admin-1",
                idempotency_key="create-archive",
                request_fingerprint_sha256="a" * 64,
            )
        management = ReceiptManagement(application, receipt)

        observed = management.inspect_managed_share_mount("ARCHIVE")

        self.assertIs(receipt, observed)
        self.assertEqual("archive", management.observed_share_id)

    def test_managed_share_receipt_mismatch_fails_before_root_open(self) -> None:
        receipt_changes = {
            "unmounted": {"result": "unmounted"},
            "wrong_share": {"share_id": "other"},
            "stale_config": {"config_revision": 2},
            "stale_credential": {"credential_generation": 1},
            "wrong_target": {"unit_name": "wrong.mount"},
            "wrong_filesystem": {"filesystem_type": "nfs"},
            "wrong_source": {"source_sha256": "4" * 64},
            "writable": {"read_only": False},
            "wrong_identity": {"mount_identity_sha256": "5" * 64},
        }
        for name, changes in receipt_changes.items():
            with self.subTest(name=name):
                management = FakeManagement(self.mounted_receipt(**changes))
                with self.assertRaises(RestoreDestinationAdmissionError):
                    RestoreDestinationVerifier(
                        management_service=management
                    ).admit(self.managed_plan())

    def test_failed_admission_does_not_leak_descriptors(self) -> None:
        before = len(os.listdir("/proc/self/fd"))
        for _ in range(20):
            with self.assertRaises(RestoreDestinationAdmissionError):
                RestoreDestinationVerifier().admit(
                    self.local_plan(root=str(self.anchor / "missing"))
                )
        self.assertEqual(before, len(os.listdir("/proc/self/fd")))


if __name__ == "__main__":
    unittest.main()
