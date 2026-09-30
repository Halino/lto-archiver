from __future__ import annotations

import hashlib
import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

import ltobackup.daemon.restore_copy as restore_copy_module
from ltobackup.daemon.restore_copy import (
    RestoreCopyCancelled,
    RestoreCopyConflict,
    RestoreCopyError,
    RestoreCopyRequest,
    RestoreCopyVerificationError,
    RestorePathError,
    RestoreReplacementAuthorization,
    copy_selected_restore_item,
)
from ltobackup.daemon.restore_destination import RestoreDestinationVerifier

DATA = b"restore-data"
DATA_SHA256 = "497b7040a3f1d3f697bac4882019a0615f2f3a5435f540fc1e897357f240a1bf"


class RestoreCopyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tape = self.root / "tape"
        self.restore = self.root / "restore"
        self.source_relative = Path(
            ".lto-backup/libraries/FILM/blocks/b1/files/Movies/title.mkv"
        )
        source = self.tape / self.source_relative
        source.parent.mkdir(parents=True)
        source.write_bytes(DATA)
        self.restore.mkdir()
        self.restore.chmod(0o700)
        self.destination_lease = RestoreDestinationVerifier().admit(
            {
                "destination_root": str(self.restore),
                "destination": {
                    "kind": "local",
                    "root": str(self.restore),
                    "anchor": str(self.restore),
                },
            }
        )
        self.addCleanup(self.destination_lease.close)

    def request(self, **changes: object) -> RestoreCopyRequest:
        values: dict[str, object] = {
            "tape_root": self.tape,
            "destination_lease": self.destination_lease,
            "library_id": "FILM",
            "relative_path": "Movies/title.mkv",
            "tape_relative_path": self.source_relative.as_posix(),
            "expected_size": len(DATA),
            "expected_sha256": DATA_SHA256,
            "replacement_authorization": None,
            "buffer_bytes": 4,
            "stop_requested": lambda: False,
            "progress": lambda _count: None,
        }
        values.update(changes)
        return RestoreCopyRequest(**values)  # type: ignore[arg-type]

    def write_destination(self, payload: bytes) -> Path:
        destination = self.restore / "FILM/Movies/title.mkv"
        destination.parent.mkdir(parents=True, exist_ok=True)
        (self.restore / "FILM").chmod(0o700)
        destination.parent.chmod(0o700)
        destination.write_bytes(payload)
        destination.chmod(0o600)
        return destination

    def consumed_authorization(self, **changes: object) -> RestoreReplacementAuthorization:
        destination = self.restore / "FILM/Movies/title.mkv"
        existing = destination.read_bytes()
        values: dict[str, object] = {
            "authorization_id": "RESTORE-AUTH-1234",
            "run_id": "RESTORE-RUN-1234",
            "item_sequence": 1,
            "file_version_id": 99,
            "canonical_destination": str(destination.resolve(strict=True)),
            "observed_size": len(existing),
            "observed_sha256": hashlib.sha256(existing).hexdigest(),
            "library_id": "FILM",
            "relative_path": "Movies/title.mkv",
            "tape_relative_path": self.source_relative.as_posix(),
            "expected_size": len(DATA),
            "expected_sha256": DATA_SHA256,
            "state": "consumed",
            "consumed_by_operation_id": "operation-1234",
        }
        values.update(changes)
        return RestoreReplacementAuthorization(**values)  # type: ignore[arg-type]

    def test_copy_streams_to_verified_atomic_destination(self) -> None:
        # Removing streaming progress, verification, or the final replace breaks this.
        observed: list[int] = []

        result = copy_selected_restore_item(self.request(progress=observed.append))

        self.assertEqual(self.restore / "FILM/Movies/title.mkv", result.destination)
        self.assertEqual("restored", result.state)
        self.assertEqual(len(DATA), result.bytes_copied)
        self.assertEqual(DATA_SHA256, result.sha256)
        self.assertEqual([4, 4, 4], observed)
        self.assertEqual(DATA, result.destination.read_bytes())
        self.assertEqual([], list(result.destination.parent.glob(".*.partial-*")))

    def test_fence_check_runs_before_every_source_buffer(self) -> None:
        checks = 0

        def fence_check() -> None:
            nonlocal checks
            checks += 1
            if checks == 3:
                raise RuntimeError("operation fence became stale")

        with self.assertRaisesRegex(RuntimeError, "stale"):
            copy_selected_restore_item(self.request(fence_check=fence_check))

        self.assertEqual(3, checks)
        self.assertFalse((self.restore / "FILM/Movies/title.mkv").exists())

    def test_long_valid_basenames_restore_and_leave_no_partial_file(self) -> None:
        for name in ("a" * 214, "b" * 255, "é" * 127):
            with self.subTest(name_bytes=len(os.fsencode(name))):
                result = copy_selected_restore_item(
                    self.request(relative_path="Movies/" + name)
                )
                self.assertEqual(DATA, result.destination.read_bytes())
                self.assertEqual(name, result.destination.name)
                self.assertFalse(any(
                    entry.name.startswith(".")
                    for entry in result.destination.parent.iterdir()
                ))

    def test_matching_existing_file_is_skipped_after_independent_verification(self) -> None:
        self.write_destination(DATA)

        result = copy_selected_restore_item(self.request())

        self.assertEqual("skipped_verified", result.state)
        self.assertEqual(0, result.bytes_copied)
        self.assertEqual(DATA_SHA256, result.sha256)

    def test_differing_existing_file_returns_exact_conflict_evidence(self) -> None:
        destination = self.write_destination(b"old")

        with self.assertRaises(RestoreCopyConflict) as raised:
            copy_selected_restore_item(self.request())

        evidence = raised.exception.evidence
        self.assertEqual(str(destination.resolve(strict=True)), evidence.canonical_destination)
        self.assertEqual(3, evidence.observed_size)
        self.assertEqual(
            "cba06b5736faf67e54b07b561eae94395e774c517a7d910a54369e1263ccfbd4",
            evidence.observed_sha256,
        )
        self.assertEqual(b"old", destination.read_bytes())

    def test_consumed_exact_authorization_replaces_only_bound_existing_file(self) -> None:
        destination = self.write_destination(b"old")
        authorization = self.consumed_authorization()

        result = copy_selected_restore_item(
            self.request(replacement_authorization=authorization)
        )

        self.assertEqual("restored", result.state)
        self.assertEqual(DATA, destination.read_bytes())

    def test_no_callback_runs_between_final_binding_check_and_atomic_replace(self) -> None:
        destination = self.write_destination(b"old")
        authorization = self.consumed_authorization()
        calls = 0

        def stop_requested() -> bool:
            nonlocal calls
            calls += 1
            if calls > 5:
                raise RuntimeError("callback ran inside sealed replacement window")
            return False

        result = copy_selected_restore_item(
            self.request(
                stop_requested=stop_requested,
                replacement_authorization=authorization,
            )
        )

        self.assertEqual("restored", result.state)
        self.assertEqual(5, calls)
        self.assertEqual(DATA, destination.read_bytes())

    def test_atomic_publish_does_not_clobber_concurrently_created_destination(self) -> None:
        destination = self.restore / "FILM/Movies/title.mkv"
        original_noreplace = restore_copy_module._rename_noreplace

        def create_competitor_then_rename(parent_fd, src, dst):
            descriptor = os.open(
                dst,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=parent_fd,
            )
            try:
                os.write(descriptor, b"concurrent")
            finally:
                os.close(descriptor)
            return original_noreplace(parent_fd, src, dst)

        with patch(
            "ltobackup.daemon.restore_copy._rename_noreplace",
            side_effect=create_competitor_then_rename,
        ), self.assertRaises(RestoreCopyConflict):
            copy_selected_restore_item(self.request())

        self.assertEqual(b"concurrent", destination.read_bytes())

    def test_authorized_replace_revalidates_changed_destination_under_lease(self) -> None:
        destination = self.write_destination(b"old")
        authorization = self.consumed_authorization()
        original_inspect = restore_copy_module._inspect_existing
        inspections = 0

        def change_before_final_inspection(*args, **kwargs):
            nonlocal inspections
            inspections += 1
            if inspections == 2:
                destination.write_bytes(b"changed-before-publish")
                destination.chmod(0o600)
            return original_inspect(*args, **kwargs)

        with patch(
            "ltobackup.daemon.restore_copy._inspect_existing",
            side_effect=change_before_final_inspection,
        ), self.assertRaises(RestoreCopyConflict):
            copy_selected_restore_item(
                self.request(replacement_authorization=authorization)
            )

        self.assertEqual(b"changed-before-publish", destination.read_bytes())

    def test_consumed_replacement_capability_is_single_use_in_memory(self) -> None:
        destination = self.write_destination(b"old")
        authorization = self.consumed_authorization()
        request = self.request(replacement_authorization=authorization)

        first = copy_selected_restore_item(request)
        destination.write_bytes(b"old")
        destination.chmod(0o600)
        with self.assertRaisesRegex(RestoreCopyError, "spent"):
            copy_selected_restore_item(request)

        self.assertEqual("restored", first.state)
        self.assertEqual(b"old", destination.read_bytes())

    def test_consumed_replacement_capability_claim_is_atomic(self) -> None:
        self.write_destination(b"old")
        authorization = self.consumed_authorization()
        start = threading.Barrier(3)
        outcomes: list[str] = []

        def claim() -> None:
            start.wait()
            try:
                authorization.claim_once()
            except RestoreCopyError:
                outcomes.append("rejected")
            else:
                outcomes.append("claimed")

        workers = [threading.Thread(target=claim) for _ in range(2)]
        for worker in workers:
            worker.start()
        start.wait()
        for worker in workers:
            worker.join(2.0)

        self.assertEqual(["claimed", "rejected"], sorted(outcomes))

    def test_path_only_request_is_not_a_supported_copier_boundary(self) -> None:
        values = dict(self.request().__dict__)
        values.pop("destination_lease")
        values["destination_root"] = self.restore

        with self.assertRaises(TypeError):
            RestoreCopyRequest(**values)

    def test_unavailable_atomic_noreplace_fails_closed_and_cleans_partial(self) -> None:
        class LibcWithoutRenameAt2:
            pass

        with patch(
            "ltobackup.daemon.restore_copy.ctypes.CDLL",
            return_value=LibcWithoutRenameAt2(),
        ), self.assertRaisesRegex(OSError, "renameat2 is unavailable"):
            copy_selected_restore_item(self.request())

        destination = self.restore / "FILM/Movies/title.mkv"
        self.assertFalse(destination.exists())
        self.assertEqual([], list(destination.parent.glob(".*.partial-*")))

    def test_copy_uses_admitted_root_descriptor_after_pathname_replacement(self) -> None:
        admitted_root = self.root / "admitted-root"
        self.restore.rename(admitted_root)
        self.restore.mkdir()

        result = copy_selected_restore_item(self.request())

        self.assertEqual("restored", result.state)
        self.assertEqual(DATA, (admitted_root / "FILM/Movies/title.mkv").read_bytes())
        self.assertFalse((self.restore / "FILM/Movies/title.mkv").exists())

    def test_second_concurrent_copy_on_same_lease_fails_closed(self) -> None:
        copy_started = threading.Event()
        release_copy = threading.Event()
        outcome: dict[str, object] = {}

        def progress(_count: int) -> None:
            copy_started.set()
            self.assertTrue(release_copy.wait(2.0))

        def run_first() -> None:
            try:
                outcome["result"] = copy_selected_restore_item(
                    self.request(progress=progress)
                )
            except Exception as exc:  # noqa: BLE001 - retain worker failure for assertion
                outcome["error"] = exc

        worker = threading.Thread(target=run_first)
        worker.start()
        self.assertTrue(copy_started.wait(2.0))
        try:
            with self.assertRaisesRegex(RestorePathError, "busy"):
                copy_selected_restore_item(self.request())
        finally:
            release_copy.set()
            worker.join(2.0)

        self.assertNotIn("error", outcome)
        self.assertEqual("restored", outcome["result"].state)

    def test_matching_skip_rejects_pathname_swap_after_hash(self) -> None:
        destination = self.write_destination(DATA)
        verified = destination.with_name("verified-old")
        original_hash = restore_copy_module._hash_open_file
        swap_armed = True

        def swap_after_hash(descriptor: int, buffer_bytes: int):
            nonlocal swap_armed
            result = original_hash(descriptor, buffer_bytes)
            if swap_armed:
                swap_armed = False
                destination.rename(verified)
                destination.write_bytes(b"different")
                destination.chmod(0o600)
            return result

        with patch(
            "ltobackup.daemon.restore_copy._hash_open_file",
            side_effect=swap_after_hash,
        ), self.assertRaises(RestoreCopyConflict):
            copy_selected_restore_item(self.request())

        self.assertEqual(b"different", destination.read_bytes())
        self.assertEqual(DATA, verified.read_bytes())

    def test_replacement_binding_mismatch_and_unconsumed_authority_fail_closed(self) -> None:
        destination = self.write_destination(b"old")
        cases = {
            "state": {"state": "authorized"},
            "operation": {"consumed_by_operation_id": ""},
            "destination": {"canonical_destination": str(self.restore / "other")},
            "observed_size": {"observed_size": 4},
            "observed_digest": {"observed_sha256": "1" * 64},
            "library": {"library_id": "ANIME"},
            "relative_path": {"relative_path": "Movies/other.mkv"},
            "tape_path": {"tape_relative_path": "other"},
            "expected_size": {"expected_size": 1},
            "expected_digest": {"expected_sha256": "2" * 64},
        }
        for name, change in cases.items():
            with self.subTest(name=name), self.assertRaises(RestoreCopyConflict):
                copy_selected_restore_item(
                    self.request(
                        replacement_authorization=self.consumed_authorization(**change)
                    )
                )
            self.assertEqual(b"old", destination.read_bytes())

    def test_destination_swapped_to_symlink_after_authorization_is_rejected(self) -> None:
        destination = self.write_destination(b"old")
        authorization = self.consumed_authorization()
        replacement_target = self.root / "outside"
        replacement_target.write_bytes(b"outside")
        destination.unlink()
        destination.symlink_to(replacement_target)

        with self.assertRaises(RestorePathError):
            copy_selected_restore_item(
                self.request(replacement_authorization=authorization)
            )
        self.assertEqual(b"outside", replacement_target.read_bytes())

    def test_invalid_catalog_and_tape_paths_are_rejected(self) -> None:
        cases = (
            ("relative_path", ""),
            ("relative_path", "."),
            ("relative_path", "../escape"),
            ("relative_path", "/absolute"),
            ("relative_path", "Movies//title.mkv"),
            ("relative_path", "Movies\\title.mkv"),
            ("relative_path", "Movies/ti\x00tle.mkv"),
            ("relative_path", "Movies/ti\ntle.mkv"),
            ("library_id", "A/B"),
            ("tape_relative_path", "../escape"),
            ("tape_relative_path", "/absolute"),
        )
        for field, value in cases:
            with self.subTest(
                field=field, value=repr(value)
            ), self.assertRaises(RestorePathError):
                copy_selected_restore_item(self.request(**{field: value}))

    def test_source_symlink_and_destination_parent_symlink_are_rejected(self) -> None:
        source = self.tape / self.source_relative
        outside_source = self.root / "outside-source"
        outside_source.write_bytes(DATA)
        source.unlink()
        source.symlink_to(outside_source)
        with self.assertRaises(RestorePathError):
            copy_selected_restore_item(self.request())

        source.unlink()
        source.write_bytes(DATA)
        outside_destination = self.root / "outside-destination"
        outside_destination.mkdir()
        (self.restore / "FILM").symlink_to(outside_destination, target_is_directory=True)
        with self.assertRaises(RestorePathError):
            copy_selected_restore_item(self.request())
        self.assertEqual([], list(outside_destination.iterdir()))

    def test_source_and_destination_type_mismatches_are_rejected(self) -> None:
        source = self.tape / self.source_relative
        source.unlink()
        source.mkdir()
        with self.assertRaises(RestorePathError):
            copy_selected_restore_item(self.request())

        source.rmdir()
        source.write_bytes(DATA)
        destination = self.restore / "FILM/Movies/title.mkv"
        destination.mkdir(parents=True)
        with self.assertRaises(RestorePathError):
            copy_selected_restore_item(self.request())

    def test_group_writable_destination_component_is_rejected(self) -> None:
        component = self.restore / "FILM"
        component.mkdir()
        component.chmod(0o777)

        with self.assertRaises(RestorePathError):
            copy_selected_restore_item(self.request())

    def test_size_and_digest_mismatch_remove_partial_destination(self) -> None:
        cases = (
            {"expected_size": len(DATA) + 1},
            {"expected_sha256": "0" * 64},
        )
        for change in cases:
            with self.subTest(change=change), self.assertRaises(
                RestoreCopyVerificationError
            ):
                copy_selected_restore_item(self.request(**change))
            destination = self.restore / "FILM/Movies/title.mkv"
            self.assertFalse(destination.exists())
            if destination.parent.exists():
                self.assertEqual([], list(destination.parent.glob(".*.partial-*")))

    def test_cancellation_removes_partial_and_preserves_existing_destination(self) -> None:
        destination = self.write_destination(b"old")
        authorization = self.consumed_authorization()
        calls = 0

        def stop_requested() -> bool:
            nonlocal calls
            calls += 1
            return calls > 2

        with self.assertRaises(RestoreCopyCancelled):
            copy_selected_restore_item(
                self.request(
                    buffer_bytes=2,
                    stop_requested=stop_requested,
                    replacement_authorization=authorization,
                )
            )
        self.assertEqual(b"old", destination.read_bytes())
        self.assertEqual([], list(destination.parent.glob(".*.partial-*")))

    def test_partial_collision_does_not_overwrite_unrelated_partial(self) -> None:
        destination = self.restore / "FILM/Movies/title.mkv"
        destination.parent.mkdir(parents=True)
        (self.restore / "FILM").chmod(0o700)
        destination.parent.chmod(0o700)
        collision = destination.parent / ".restore.partial-fixed"
        collision.write_bytes(b"keep")
        collision.chmod(0o600)
        with patch(
            "ltobackup.daemon.restore_copy.secrets.token_hex", return_value="fixed"
        ), self.assertRaises(FileExistsError):
            copy_selected_restore_item(self.request())
        self.assertEqual(b"keep", collision.read_bytes())
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
