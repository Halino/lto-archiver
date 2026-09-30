from __future__ import annotations

import hashlib
import inspect
import json
import multiprocessing
import os
import sqlite3
import stat
import tempfile
import threading
import unittest
from collections.abc import Callable
from pathlib import Path
from unittest.mock import patch

import ltobackup.broker.store as broker_store_module
from ltobackup.broker.ltfs_session import derive_receipt_operation_uuid
from ltobackup.broker.protocol import ltfs_request_sha256
from ltobackup.broker.store import (
    BrokerStateConflict,
    BrokerStateStore,
    BrokerStateUnavailable,
    PermitTransition,
    permit_sha256,
)
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupReleasePermit,
    BrokeredCgroupScopeReceipt,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)

BOOT_ID = "11111111-2222-4333-8444-555555555555"
OTHER_BOOT_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
NOW = "2026-08-22T12:34:56.000000Z"
EARLIER = "2026-08-21T12:34:56.000000Z"


def _clock() -> str:
    return NOW


def _as_root_owned(status: os.stat_result) -> os.stat_result:
    fields = list(status)
    fields[4] = 0
    fields[5] = 0
    return os.stat_result(fields)


def _root_owned_fstat(fd: int) -> os.stat_result:
    return _as_root_owned(os.fstat(fd))


def _root_owned_stat_at(name: str, *, dir_fd: int) -> os.stat_result:
    return _as_root_owned(os.stat(name, dir_fd=dir_fd, follow_symlinks=False))


def _open_store(
    path: Path,
    *,
    boot_id: str = BOOT_ID,
    clock: Callable[[], str] = _clock,
) -> BrokerStateStore:
    with (
        patch("ltobackup.broker.store._effective_ids", return_value=(0, 0)),
        patch("ltobackup.broker.store._fstat", side_effect=_root_owned_fstat),
        patch("ltobackup.broker.store._stat_at", side_effect=_root_owned_stat_at),
    ):
        return BrokerStateStore.open(path, boot_id=boot_id, clock=clock)


def _receipt(
    *,
    command_id: str = "command-17",
    owner_generation: int = 9,
    scope_id: str = "scope-17",
    scope_path_sha256: str = "a" * 64,
    request_nonce: bytes = b"r" * 32,
    broker_nonce: bytes = b"n" * 32,
    broker_proof: bytes = b"p" * 32,
) -> BrokeredCgroupScopeReceipt:
    return BrokeredCgroupScopeReceipt(
        protocol_version=1,
        command_id=command_id,
        owner_generation=owner_generation,
        request_nonce=request_nonce,
        scope_id=scope_id,
        scope_path_sha256=scope_path_sha256,
        broker_nonce=broker_nonce,
        broker_proof=broker_proof,
        recursive_population=True,
        recursive_members=True,
        cgroup_kill=True,
    )


def _permit(
    receipt: BrokeredCgroupScopeReceipt,
    *,
    pid: int = 4711,
    request_nonce: bytes = b"q" * 32,
    permit_nonce: bytes = b"m" * 32,
    broker_proof: bytes = b"z" * 32,
) -> BrokeredCgroupReleasePermit:
    return BrokeredCgroupReleasePermit(
        protocol_version=1,
        receipt=receipt,
        pid=pid,
        request_nonce=request_nonce,
        permit_nonce=permit_nonce,
        broker_proof=broker_proof,
    )


def _fresh_receipt(
    receipt: BrokeredCgroupScopeReceipt, *, variant: int = 1
) -> BrokeredCgroupScopeReceipt:
    opaque = {
        1: (b"s", b"o", b"f"),
        2: (b"t", b"u", b"v"),
    }[variant]
    return _receipt(
        command_id=receipt.command_id,
        owner_generation=receipt.owner_generation,
        scope_id=receipt.scope_id,
        scope_path_sha256=receipt.scope_path_sha256,
        request_nonce=opaque[0] * 32,
        broker_nonce=opaque[1] * 32,
        broker_proof=opaque[2] * 32,
    )


def _ltfs_request(
    *,
    operation_id: str = "operation-17",
    owner_generation: int = 9,
    request_nonce: bytes = b"l" * 32,
    mount_path_sha256: str = "1" * 64,
    cgroup_scope_receipt: BrokeredCgroupScopeReceipt | None = None,
) -> LtfsSessionRequest:
    return LtfsSessionRequest(
        protocol_version=1,
        operation_id=operation_id,
        owner_generation=owner_generation,
        mount_path_sha256=mount_path_sha256,
        tape_device_identity_sha256="2" * 64,
        scsi_device_identity_sha256="3" * 64,
        expected_media_scope_sha256="4" * 64,
        observed_media_identity_sha256="5" * 64,
        expected_volume_uuid="22222222-2222-4222-8222-222222222222",
        expected_prior_generation=7,
        read_only=False,
        tape_fd_identity_sha256="6" * 64,
        scsi_fd_identity_sha256="7" * 64,
        cgroup_scope_receipt=(
            _receipt() if cgroup_scope_receipt is None else cgroup_scope_receipt
        ),
        request_nonce=request_nonce,
    )


def _ltfs_receipt(
    request: LtfsSessionRequest,
    *,
    session_id: str = "session-17",
    child_pid: int = 4711,
    child_start_ticks: int = 8822,
    mount_namespace_sha256: str = "9" * 64,
    broker_nonce: bytes = b"b" * 32,
    broker_proof: bytes = b"e" * 32,
) -> LtfsSessionReceipt:
    request_sha256 = ltfs_request_sha256(request)
    return LtfsSessionReceipt(
        protocol_version=1,
        operation_id=request.operation_id,
        receipt_operation_uuid=derive_receipt_operation_uuid(
            operation_id=request.operation_id,
            owner_generation=request.owner_generation,
            request_sha256=request_sha256,
        ),
        observed_volume_uuid=request.expected_volume_uuid
        or "22222222-2222-4222-8222-222222222222",
        observed_prior_generation=7,
        read_only=request.read_only,
        owner_generation=request.owner_generation,
        request_nonce=request.request_nonce,
        session_id=session_id,
        request_sha256=request_sha256,
        child_pid=child_pid,
        child_start_ticks=child_start_ticks,
        mount_namespace_sha256=mount_namespace_sha256,
        broker_nonce=broker_nonce,
        broker_proof=broker_proof,
        mounted=True,
        observed_volume_label="TEST VOLUME",
        observed_media_identity_sha256=request.observed_media_identity_sha256,
    )


def _ltfs_finalization(
    receipt: LtfsSessionReceipt,
    *,
    request_nonce: bytes = b"f" * 32,
    finalization_nonce: bytes = b"u" * 32,
    broker_proof: bytes = b"v" * 32,
) -> LtfsFinalizationReceipt:
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
    terminal_sha256 = hashlib.sha256(
        (json.dumps(fields, separators=(",", ":")) + "\n").encode("ascii")
    ).hexdigest()
    standalone = LtfsStandaloneReceipt(
        **{**fields, "phase_duration_ns": tuple(fields["phase_duration_ns"])},
        terminal_sha256=terminal_sha256,
    )
    return LtfsFinalizationReceipt(
        protocol_version=1,
        session_receipt=receipt,
        standalone_receipt=standalone,
        request_nonce=request_nonce,
        finalization_nonce=finalization_nonce,
        broker_proof=broker_proof,
        unmounted=True,
        child_quiesced=True,
    )


def _issue_ltfs_scope(
    store: BrokerStateStore,
    request: LtfsSessionRequest,
    *,
    device: int = 41,
    inode: int = 73,
) -> None:
    scope = store.create_scope(request.cgroup_scope_receipt)
    store.bind_cgroup(scope, device=device, inode=inode)


def _logical_dump(path: Path) -> bytes:
    connection = sqlite3.connect(path)
    try:
        return "\n".join(connection.iterdump()).encode("utf-8")
    finally:
        connection.close()


def _process_transition(
    path: str,
    receipt: BrokeredCgroupScopeReceipt,
    permit: BrokeredCgroupReleasePermit,
    digest: str,
    operation: str,
    start_event,
    results,
) -> None:
    store = _open_store(Path(path))
    try:
        start_event.wait()
        if operation == "release":
            transition = store.commit_release(permit, digest)
        else:
            transition = store.claim_or_observe(receipt, permit.pid, digest)
        results.put(("ok", transition.record.state, transition.transitioned))
    except BrokerStateConflict:
        results.put(("conflict", None, False))
    finally:
        store.close()


def _commit_and_crash(
    path: str,
    permit: BrokeredCgroupReleasePermit,
    digest: str,
) -> None:
    store = _open_store(Path(path))
    store.commit_release(permit, digest)
    os._exit(91)


class BrokerStoreStartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.path = self.root / "state.db"

    def _open(self, *, boot_id: str = BOOT_ID) -> BrokerStateStore:
        store = _open_store(self.path, boot_id=boot_id)
        self.addCleanup(store.close)
        return store

    def test_production_default_rejects_nonroot_process_and_ownership(self):
        with (
            patch("ltobackup.broker.store.os.geteuid", return_value=1234),
            patch("ltobackup.broker.store.os.getegid", return_value=1234),
            self.assertRaisesRegex(
                BrokerStateUnavailable, r"^command broker state unavailable$"
            ),
        ):
            BrokerStateStore.open(self.path, boot_id=BOOT_ID, clock=_clock)

        with (
            patch("ltobackup.broker.store._effective_ids", return_value=(0, 0)),
            self.assertRaisesRegex(
                BrokerStateUnavailable, r"^command broker state unavailable$"
            ),
        ):
            BrokerStateStore.open(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_open_signature_has_no_credential_override_or_uid1000_bypass(self):
        signature = inspect.signature(BrokerStateStore.open)
        bound = signature.bind(self.path, boot_id=BOOT_ID, clock=_clock)
        self.assertEqual(tuple(bound.arguments), ("path", "boot_id", "clock"))
        self.assertEqual(
            tuple(parameter.kind for parameter in signature.parameters.values()),
            (
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
                inspect.Parameter.KEYWORD_ONLY,
                inspect.Parameter.KEYWORD_ONLY,
            ),
        )
        with self.assertRaises(TypeError):
            signature.bind(
                self.path,
                boot_id=BOOT_ID,
                clock=_clock,
                _credential_provider=lambda: (1000, 1000),
            )

        try:
            bypassed = BrokerStateStore.open(
                self.path,
                boot_id=BOOT_ID,
                clock=_clock,
                _credential_provider=lambda: (1000, 1000),
            )
        except TypeError:
            return
        bypassed.close()
        self.fail("credential override admitted a non-root broker state database")

    def test_new_database_has_exact_durable_sqlite_contract(self):
        real_fsync = os.fsync
        fsynced_directories = 0

        def observe_fsync(fd: int) -> None:
            nonlocal fsynced_directories
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                fsynced_directories += 1
            real_fsync(fd)

        with patch("ltobackup.broker.store.os.fsync", side_effect=observe_fsync):
            store = self._open()

        mode = stat.S_IMODE(self.path.stat().st_mode)
        self.assertEqual(mode, 0o600)
        self.assertEqual(store.pragma("foreign_keys"), 1)
        self.assertEqual(store.pragma("journal_mode"), "delete")
        self.assertEqual(store.pragma("synchronous"), 2)
        self.assertEqual(store.pragma("integrity_check"), "ok")
        self.assertEqual(store.pragma("user_version"), 10)
        self.assertEqual(fsynced_directories, 1)

    def test_every_ready_database_fsyncs_its_parent_directory(self):
        self._open().close()
        with patch("ltobackup.broker.store.os.fsync") as fsync:
            store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
            store.close()
        fsync.assert_called_once()

    def test_parent_traversal_uses_opath_and_returns_fsyncable_final_directory(self):
        self.assertTrue(hasattr(os, "O_PATH"))
        real_open = os.open
        calls: list[tuple[str, int, int | None]] = []

        def observe_open(
            path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
            flags: int,
            *args: object,
            **kwargs: object,
        ) -> int:
            dir_fd = kwargs.get("dir_fd")
            calls.append(
                (
                    os.fsdecode(path),
                    flags,
                    dir_fd if isinstance(dir_fd, int) else None,
                )
            )
            return real_open(path, flags, *args, **kwargs)

        with patch.object(broker_store_module.os, "open", side_effect=observe_open):
            parent_fd = BrokerStateStore._open_parent(self.root)
        try:
            os.fsync(parent_fd)
            self.assertGreater(len(calls), 1)
            for _, flags, _ in calls[:-1]:
                self.assertTrue(flags & os.O_PATH)
            self.assertFalse(calls[-1][1] & os.O_PATH)
            for _, flags, _ in calls:
                self.assertTrue(flags & os.O_DIRECTORY)
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_CLOEXEC)
        finally:
            os.close(parent_fd)

    def test_parent_fsync_failure_is_unavailable_and_retry_fsyncs_before_ready(self):
        with (
            patch(
                "ltobackup.broker.store.os.fsync",
                side_effect=OSError("injected parent fsync failure"),
            ),
            self.assertRaisesRegex(
                BrokerStateUnavailable, r"^command broker state unavailable$"
            ),
        ):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

        with patch("ltobackup.broker.store.os.fsync") as fsync:
            store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
            store.close()
        fsync.assert_called_once()

    def test_symlink_non_regular_and_insecure_mode_are_rejected_redacted(self):
        target = self.root / "target.db"
        target.write_bytes(b"")
        link = self.root / "link.db"
        link.symlink_to(target)
        directory = self.root / "directory.db"
        directory.mkdir()

        valid = self._open()
        valid.close()
        os.chmod(self.path, 0o644)

        for path in (link, directory, self.path):
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(
                    BrokerStateUnavailable, r"^command broker state unavailable$"
                ) as caught,
            ):
                _open_store(path, boot_id=BOOT_ID, clock=_clock)
            self.assertNotIn(str(path), str(caught.exception))

    def test_unexpected_schema_object_is_rejected(self):
        store = self._open()
        store.close()
        connection = sqlite3.connect(self.path)
        connection.execute(
            "CREATE TRIGGER unexpected AFTER INSERT ON scopes BEGIN SELECT 1; END"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(BrokerStateUnavailable):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_parent_symlink_and_hardlinked_database_are_rejected(self):
        real_parent = self.root / "real"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(BrokerStateUnavailable):
            _open_store(linked_parent / "state.db", boot_id=BOOT_ID, clock=_clock)

        store = self._open()
        store.close()
        hardlink = self.root / "hardlink.db"
        os.link(self.path, hardlink)
        for path in (self.path, hardlink):
            with self.subTest(path=path), self.assertRaises(BrokerStateUnavailable):
                _open_store(path, boot_id=BOOT_ID, clock=_clock)

    def test_future_or_partial_schema_is_rejected_without_repair(self):
        for name, setup in (
            (
                "future.db",
                ("PRAGMA user_version=8",),
            ),
            (
                "partial.db",
                (
                    "CREATE TABLE scopes(scope_id TEXT PRIMARY KEY)",
                    "PRAGMA user_version=1",
                ),
            ),
        ):
            path = self.root / name
            connection = sqlite3.connect(path)
            for statement in setup:
                connection.execute(statement)
            connection.commit()
            connection.close()
            os.chmod(path, 0o600)

            with (
                self.subTest(name=name),
                self.assertRaisesRegex(
                    BrokerStateUnavailable, r"^command broker state unavailable$"
                ),
            ):
                _open_store(path, boot_id=BOOT_ID, clock=_clock)

    def test_failed_integrity_check_is_rejected(self):
        self.path.write_bytes(b"not a sqlite database")
        os.chmod(self.path, 0o600)

        with self.assertRaisesRegex(
            BrokerStateUnavailable, r"^command broker state unavailable$"
        ):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_wrong_boot_durably_breaks_active_scope_for_reconciliation(self):
        receipt = _receipt()
        store = self._open()
        store.create_scope(receipt)
        store.close()

        reopened = _open_store(self.path, boot_id=OTHER_BOOT_ID, clock=_clock)
        self.addCleanup(reopened.close)
        self.assertEqual(reopened.open_scope(receipt).state, "BROKEN")

    def test_malformed_dynamic_sqlite_rows_fail_startup_validation(self):
        store = self._open()
        receipt = _receipt()
        store.create_scope(receipt)
        store.close()

        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "UPDATE scopes SET owner_generation='not-an-integer' WHERE scope_id=?",
            (receipt.scope_id,),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            BrokerStateUnavailable, r"^command broker state unavailable$"
        ):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_malformed_persisted_cgroup_inode_binding_fails_startup(self):
        store = self._open()
        receipt = _receipt()
        store.create_scope(receipt)
        store.close()
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA ignore_check_constraints=ON")
        connection.execute(
            "INSERT INTO cgroup_bindings(scope_id,device,inode) VALUES(?,?,?)",
            (receipt.scope_id, "not-an-integer", 71),
        )
        connection.commit()
        connection.close()

        with self.assertRaisesRegex(
            BrokerStateUnavailable, r"^command broker state unavailable$"
        ):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_public_errors_never_include_inputs_or_sqlite_exception_text(self):
        secret = "-".join(("scope", "SERIAL", "PRIVATE", "123"))
        store = self._open()
        store.create_scope(_receipt(scope_id=secret))

        with self.assertRaises(BrokerStateConflict) as caught:
            store.create_scope(_receipt(scope_id=secret, scope_path_sha256="b" * 64))
        message = str(caught.exception)
        self.assertEqual(message, "command broker state conflict")
        self.assertNotIn(secret, message)
        self.assertNotIn("UNIQUE", message)

    def test_repeated_open_close_does_not_leak_database_or_anchor_fds(self):
        before = len(tuple(Path("/proc/self/fd").iterdir()))
        for _iteration in range(100):
            store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
            store.close()
        self.assertEqual(len(tuple(Path("/proc/self/fd").iterdir())), before)


class BrokerStoreSchemaMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.db"

    def test_exact_version_one_database_migrates_binding_columns_transactionally(self):
        connection = sqlite3.connect(self.path)
        connection.executescript(
            """
            CREATE TABLE scopes(
                scope_id TEXT PRIMARY KEY,
                command_id TEXT NOT NULL,
                owner_generation INTEGER NOT NULL,
                scope_path_sha256 TEXT NOT NULL,
                boot_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('ACTIVE','CLOSED','BROKEN')),
                pid INTEGER,
                process_start_ticks INTEGER,
                created_at TEXT NOT NULL,
                UNIQUE(command_id, owner_generation)
            );
            CREATE TABLE permits(
                permit_sha256 TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES scopes(scope_id),
                pid INTEGER NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('PREPARED','RELEASE_COMMITTED','REVOKED')),
                permit_json TEXT NOT NULL,
                prepared_at TEXT NOT NULL,
                terminal_at TEXT
            );
            CREATE TABLE replay_nonces(
                domain TEXT NOT NULL,
                nonce_sha256 TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                PRIMARY KEY(domain, nonce_sha256)
            );
            PRAGMA user_version=1;
            """
        )
        connection.commit()
        connection.close()
        os.chmod(self.path, 0o600)

        store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(store.close)
        self.assertEqual(store.pragma("user_version"), 10)
        receipt = _receipt()
        created = store.create_scope(receipt)
        self.assertEqual((created.cgroup_device, created.cgroup_inode), (None, None))
        bound = store.bind_cgroup(created, device=11, inode=29)
        self.assertEqual((bound.cgroup_device, bound.cgroup_inode), (11, 29))

    def test_populated_version_one_database_preserves_every_row(self):
        store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        receipt = _receipt()
        store.create_scope(receipt)
        store.attach_process(receipt, 4711, 88001)
        permit = _permit(receipt)
        prepared = store.prepare_permit(permit)
        nonce_digest = store.record_nonce("attach", b"w" * 32)
        store.close()

        connection = sqlite3.connect(self.path)
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute("DROP TABLE ltfs_child_exit_receipts")
        connection.execute("DROP TABLE ltfs_observations")
        connection.execute("DROP TABLE ltfs_sessions")
        connection.execute("DROP TABLE cgroup_bindings")
        connection.execute("PRAGMA user_version=1")
        connection.commit()
        connection.close()

        migrated = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(migrated.close)
        scope = migrated.open_scope(receipt)
        self.assertEqual((scope.pid, scope.process_start_ticks), (4711, 88001))
        self.assertEqual((scope.cgroup_device, scope.cgroup_inode), (None, None))
        self.assertEqual(
            migrated.permit_for_reconciliation(prepared.permit_sha256), prepared
        )
        with self.assertRaises(BrokerStateConflict):
            migrated.record_nonce("attach", b"w" * 32)
        self.assertEqual(len(nonce_digest), 64)

    def test_version_one_migration_failure_rolls_back_without_partial_schema(self):
        store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        store.close()
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute("DROP TABLE ltfs_child_exit_receipts")
        connection.execute("DROP TABLE ltfs_observations")
        connection.execute("DROP TABLE ltfs_sessions")
        connection.execute("DROP TABLE cgroup_bindings")
        connection.execute("PRAGMA user_version=1")
        connection.commit()
        connection.close()

        real_execute = broker_store_module._migration_execute

        def fail_version_update(connection, statement):
            if statement.startswith("PRAGMA user_version="):
                raise sqlite3.OperationalError("injected migration failure")
            return real_execute(connection, statement)

        with (
            patch(
                "ltobackup.broker.store._migration_execute",
                side_effect=fail_version_update,
            ),
            self.assertRaises(BrokerStateUnavailable),
        ):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

        connection = sqlite3.connect(self.path)
        self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
        self.assertIsNone(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='cgroup_bindings'"
            ).fetchone()
        )
        self.assertIsNone(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='ltfs_sessions'"
            ).fetchone()
        )
        self.assertIsNone(
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='ltfs_observations'"
            ).fetchone()
        )
        connection.close()

    def test_exact_version_two_database_adds_ltfs_lifecycle_tables(self):
        store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        receipt = _receipt()
        store.create_scope(receipt)
        store.close()
        connection = sqlite3.connect(self.path)
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute("DROP TABLE ltfs_child_exit_receipts")
        connection.execute("DROP TABLE ltfs_observations")
        connection.execute("DROP TABLE ltfs_sessions")
        connection.execute("PRAGMA user_version=2")
        connection.commit()
        connection.close()

        migrated = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(migrated.close)
        self.assertEqual(migrated.pragma("user_version"), 10)
        self.assertEqual(migrated.open_scope(receipt).scope_id, receipt.scope_id)
        self.assertEqual(migrated.ltfs_sessions_for_reconciliation(), ())
        self.assertEqual(migrated.ltfs_observations_for_reconciliation(), ())

    def test_populated_version_three_database_is_sealed_and_linked(self):
        store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        request = _ltfs_request()
        _issue_ltfs_scope(store, request)
        started = store.begin_ltfs_session(
            request,
            ltfs_tool_identity_sha256="a" * 64,
            fusermount_tool_identity_sha256="c" * 64,
        ).record
        store.close()

        connection = sqlite3.connect(self.path)
        old_row = connection.execute(
            broker_store_module._LTFS_SESSION_SELECT_V3
        ).fetchone()
        self.assertIsNotNone(old_row)
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute("DROP TABLE ltfs_child_exit_receipts")
        connection.execute("DROP TABLE ltfs_observations")
        connection.execute("DROP TABLE ltfs_sessions")
        connection.execute(broker_store_module._LTFS_SESSIONS_V3_SQL)
        connection.execute(
            "INSERT INTO ltfs_sessions VALUES("
            + ",".join("?" for _ in range(30))
            + ")",
            old_row,
        )
        connection.execute("PRAGMA user_version=3")
        connection.commit()
        connection.close()

        migrated = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(migrated.close)
        recovered = migrated.ltfs_session(
            request.operation_id, request.owner_generation
        )
        self.assertEqual(migrated.pragma("user_version"), 10)
        self.assertEqual(recovered.request_sha256, started.request_sha256)
        self.assertEqual(len(recovered.immutable_sha256), 64)
        self.assertEqual(migrated.ltfs_observations_for_reconciliation(), ())

    def test_populated_version_four_database_upgrades_legacy_seal(self):
        store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        request = _ltfs_request()
        _issue_ltfs_scope(store, request)
        started = store.begin_ltfs_session(
            request,
            ltfs_tool_identity_sha256="a" * 64,
            fusermount_tool_identity_sha256="c" * 64,
        ).record
        store.close()

        legacy_seal = broker_store_module._ltfs_legacy_sha256(started)
        connection = sqlite3.connect(self.path)
        old_row = list(
            connection.execute(broker_store_module._LTFS_SESSION_SELECT_V5).fetchone()
        )
        old_row[5] = legacy_seal
        connection.execute("DROP TABLE ltfs_qualification_stages")
        connection.execute("DROP TABLE ltfs_child_exit_receipts")
        connection.execute("DROP TABLE ltfs_observations")
        connection.execute("DROP TABLE ltfs_sessions")
        connection.execute(broker_store_module._LTFS_SESSIONS_V5_SQL)
        connection.execute(
            "INSERT INTO ltfs_sessions VALUES("
            + ",".join("?" for _ in range(31))
            + ")",
            old_row,
        )
        connection.execute(broker_store_module._LTFS_OBSERVATIONS_SQL)
        connection.execute("PRAGMA user_version=4")
        connection.commit()
        connection.close()

        migrated = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(migrated.close)
        recovered = migrated.ltfs_session(
            request.operation_id, request.owner_generation
        )
        self.assertEqual(migrated.pragma("user_version"), 10)
        self.assertEqual(recovered.state, "BROKEN")
        self.assertNotEqual(recovered.immutable_sha256, legacy_seal)
        self.assertNotEqual(recovered.immutable_sha256, started.immutable_sha256)


class BrokerStoreTransitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.db"
        self.store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        self.receipt = _receipt()
        self.store.create_scope(self.receipt)

    def test_scope_identity_lookup_ignores_unrelated_malformed_history(self):
        self.store._connection.execute(
            "INSERT INTO scopes SELECT 'old-scope','old-command',1,"
            "scope_path_sha256,boot_id,'CLOSED',NULL,NULL,'malformed' "
            "FROM scopes WHERE scope_id=?",
            (self.receipt.scope_id,),
        )
        expected = self.store.bind_cgroup(
            self.store.open_scope(self.receipt), device=41, inode=73
        )
        self.assertEqual(
            expected,
            self.store.scope_for_identity("command-17", 9),
        )
        with self.assertRaises(BrokerStateUnavailable):
            self.store.scope_for_identity("old-command", 1)

    def test_scope_identity_lookup_has_bounded_database_work(self):
        self.store._connection.executemany(
            "INSERT INTO scopes SELECT ?,?,1,scope_path_sha256,boot_id,"
            "'CLOSED',NULL,NULL,created_at FROM scopes WHERE scope_id=?",
            ((f"old-scope-{i}", f"old-command-{i}", self.receipt.scope_id)
             for i in range(512)),
        )
        expected = self.store.open_scope(self.receipt)
        # Abort a history scan by SQLite VM work, independent of wall-clock speed.
        self.store._connection.set_progress_handler(lambda: 1, 1000)
        try:
            self.assertEqual(expected, self.store.scope_for_identity("command-17", 9))
        finally:
            self.store._connection.set_progress_handler(None, 0)

    def test_scope_identity_lookup_rejects_missing_and_invalid_identity(self):
        for command_id, generation in (
            ("missing", 9), ("command-17", 8), ("command-17", True),
            ("command-17", -1), ("command-17", 1 << 63), ("", 9),
        ):
            with self.subTest(command_id=command_id, generation=generation):
                with self.assertRaises(BrokerStateConflict):
                    self.store.scope_for_identity(command_id, generation)

    def test_scope_create_open_attach_and_terminal_transitions_are_exact(self):
        created_again = self.store.create_scope(self.receipt)
        self.assertEqual(created_again, self.store.open_scope(self.receipt))

        attached = self.store.attach_process(self.receipt, 4711, 88_001)
        self.assertEqual((attached.pid, attached.process_start_ticks), (4711, 88_001))
        self.assertEqual(
            self.store.attach_process(self.receipt, 4711, 88_001), attached
        )

        for mutation in (
            _receipt(command_id="command-substitution"),
            _receipt(owner_generation=10),
            _receipt(scope_path_sha256="b" * 64),
        ):
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(BrokerStateConflict),
            ):
                self.store.open_scope(mutation)
        with self.assertRaises(BrokerStateConflict):
            self.store.attach_process(self.receipt, 4712, 88_001)
        with self.assertRaises(BrokerStateConflict):
            self.store.attach_process(self.receipt, 4711, 88_002)

        closed = self.store.mark_scope(self.receipt, "CLOSED")
        self.assertEqual(closed.state, "CLOSED")
        self.assertEqual(self.store.mark_scope(self.receipt, "CLOSED"), closed)
        with self.assertRaises(BrokerStateConflict):
            self.store.mark_scope(self.receipt, "BROKEN")
        with self.assertRaises(BrokerStateConflict):
            self.store.attach_process(self.receipt, 4711, 88_001)

    def test_cgroup_inode_binding_is_set_once_idempotent_and_survives_restart(self):
        unbound = self.store.open_scope(self.receipt)
        self.assertEqual((unbound.cgroup_device, unbound.cgroup_inode), (None, None))

        bound = self.store.bind_cgroup(unbound, device=41, inode=73)
        self.assertEqual((bound.cgroup_device, bound.cgroup_inode), (41, 73))
        self.assertEqual(self.store.bind_cgroup(bound, device=41, inode=73), bound)

        with self.assertRaises(BrokerStateConflict):
            self.store.bind_cgroup(bound, device=41, inode=74)
        with self.assertRaises(BrokerStateConflict):
            self.store.bind_cgroup(self.receipt, device=41, inode=73)

        self.store.close()
        reopened = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(reopened.close)
        persisted = reopened.open_scope(self.receipt)
        self.assertEqual((persisted.cgroup_device, persisted.cgroup_inode), (41, 73))

    def test_cgroup_process_binding_and_broken_transition_are_atomic_and_exact(self):
        bound = self.store.bind_cgroup(
            self.store.open_scope(self.receipt), device=41, inode=73
        )
        self.assertEqual(self.store.require_cgroup_scope(bound), bound)

        attached = self.store.attach_cgroup_process(bound, pid=4711, start_ticks=88001)
        self.assertEqual((attached.pid, attached.process_start_ticks), (4711, 88001))
        self.assertEqual(self.store.require_cgroup_scope(bound), attached)
        self.assertEqual(
            self.store.attach_cgroup_process(attached, pid=4711, start_ticks=88001),
            attached,
        )
        with self.assertRaises(BrokerStateConflict):
            self.store.attach_cgroup_process(attached, pid=4712, start_ticks=88001)

        broken = self.store.break_cgroup_scope(bound)
        self.assertEqual(broken.state, "BROKEN")
        self.assertEqual((broken.pid, broken.process_start_ticks), (4711, 88001))
        self.assertEqual(self.store.break_cgroup_scope(broken), broken)

    def test_cgroup_binding_values_are_redacted_from_record_representation(self):
        bound = self.store.bind_cgroup(
            self.store.open_scope(self.receipt), device=417171, inode=739393
        )
        representation = repr(bound)
        self.assertNotIn("417171", representation)
        self.assertNotIn("739393", representation)

    def test_permit_digest_matches_existing_supervisor_contract(self):
        permit = _permit(self.receipt)
        self.assertEqual(
            permit_sha256(permit),
            "2e1f6aa5f4486264e500ab25acb0a07d8f545317ad2d2de0d3164ca63e986dde",
        )

    def test_prepare_release_restart_and_exact_commit_are_idempotent(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        permit = _permit(self.receipt)
        prepared = self.store.prepare_permit(permit)
        self.assertEqual(prepared.state, "PREPARED")
        self.assertEqual(self.store.prepare_permit(permit), prepared)

        self.store.close()
        self.store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        committed = self.store.commit_release(permit, prepared.permit_sha256)
        self.assertTrue(committed.transitioned)
        self.assertEqual(committed.record.state, "RELEASE_COMMITTED")
        observed = self.store.commit_release(permit, prepared.permit_sha256)
        self.assertFalse(observed.transitioned)
        self.assertEqual(observed.record.state, "RELEASE_COMMITTED")

        self.store.close()
        self.store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        claim = self.store.claim_or_observe(self.receipt, 4711, prepared.permit_sha256)
        self.assertFalse(claim.transitioned)
        self.assertEqual(claim.record.state, "RELEASE_COMMITTED")

    def test_state_record_representations_do_not_expose_identity_or_proofs(self):
        secret_scope = "-".join(("scope", "SERIAL", "PRIVATE", "123"))
        secret_proof = b"SECRET-BROKER-PROOF-MATERIAL-000"
        self.assertEqual(len(secret_proof), 32)
        receipt = _receipt(
            command_id="command-private",
            owner_generation=10,
            scope_id=secret_scope,
            broker_proof=secret_proof,
        )
        self.store.create_scope(receipt)
        self.store.attach_process(receipt, 4712, 88_002)
        permit = self.store.prepare_permit(_permit(receipt, pid=4712))
        representation = repr(permit)
        self.assertNotIn(secret_scope, representation)
        self.assertNotIn(secret_proof.hex(), representation)

    def test_negative_claim_is_durable_idempotent_and_blocks_release(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        permit = _permit(self.receipt)
        prepared = self.store.prepare_permit(permit)

        claimed = self.store.claim_or_observe(
            self.receipt, 4711, prepared.permit_sha256
        )
        self.assertTrue(claimed.transitioned)
        self.assertEqual(claimed.record.state, "REVOKED")
        repeated = self.store.claim_or_observe(
            self.receipt, 4711, prepared.permit_sha256
        )
        self.assertFalse(repeated.transitioned)
        self.assertEqual(repeated.record.state, "REVOKED")
        with self.assertRaises(BrokerStateConflict):
            self.store.commit_release(permit, prepared.permit_sha256)

        self.store.mark_scope(self.receipt, "CLOSED")
        self.store.close()
        self.store = _open_store(self.path, boot_id=OTHER_BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        tombstone = self.store.claim_or_observe(
            self.receipt, 4711, prepared.permit_sha256
        )
        self.assertEqual(tombstone.record.state, "REVOKED")

    def test_fresh_open_receipt_can_claim_or_observe_every_permit_state(self):
        for target_state in ("PREPARED", "RELEASE_COMMITTED", "REVOKED"):
            with self.subTest(target_state=target_state):
                self.store.close()
                state_path = Path(self.temporary.name) / f"fresh-{target_state}.db"
                store = _open_store(state_path, boot_id=BOOT_ID, clock=_clock)
                receipt = _receipt(scope_id=f"scope-{target_state}")
                store.create_scope(receipt)
                store.attach_process(receipt, 4711, 88_001)
                permit = _permit(receipt)
                prepared = store.prepare_permit(permit)
                if target_state == "RELEASE_COMMITTED":
                    store.commit_release(permit, prepared.permit_sha256)
                elif target_state == "REVOKED":
                    store.claim_or_observe(receipt, 4711, prepared.permit_sha256)
                store.close()

                reopened = _open_store(state_path, boot_id=BOOT_ID, clock=_clock)
                self.addCleanup(reopened.close)
                fresh = _fresh_receipt(receipt)
                self.assertEqual(reopened.open_scope(fresh).scope_id, receipt.scope_id)
                observed = reopened.claim_or_observe(
                    fresh, 4711, prepared.permit_sha256
                )
                expected = "REVOKED" if target_state == "PREPARED" else target_state
                self.assertEqual(observed.record.state, expected)
                self.assertEqual(observed.transitioned, target_state == "PREPARED")
                repeated = reopened.claim_or_observe(
                    _fresh_receipt(receipt, variant=2),
                    4711,
                    prepared.permit_sha256,
                )
                self.assertFalse(repeated.transitioned)
                self.assertEqual(repeated.record.state, expected)

    def test_prepared_permit_blocks_close_and_broken_scope_blocks_release(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        permit = _permit(self.receipt)
        prepared = self.store.prepare_permit(permit)
        with self.assertRaises(BrokerStateConflict):
            self.store.mark_scope(self.receipt, "CLOSED")

        broken = self.store.mark_scope(self.receipt, "BROKEN")
        self.assertEqual(broken.state, "BROKEN")
        with self.assertRaises(BrokerStateConflict):
            self.store.commit_release(permit, prepared.permit_sha256)
        revoked = self.store.claim_or_observe(
            self.receipt, 4711, prepared.permit_sha256
        )
        self.assertEqual(revoked.record.state, "REVOKED")

    def test_receipt_pid_and_permit_substitution_fail_without_mutation(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        permit = _permit(self.receipt)
        prepared = self.store.prepare_permit(permit)
        substitutions = (
            lambda: self.store.commit_release(
                _permit(self.receipt, broker_proof=b"x" * 32),
                prepared.permit_sha256,
            ),
            lambda: self.store.commit_release(permit, "f" * 64),
            lambda: self.store.claim_or_observe(
                _receipt(scope_path_sha256="b" * 64),
                4711,
                prepared.permit_sha256,
            ),
            lambda: self.store.claim_or_observe(
                self.receipt, 4712, prepared.permit_sha256
            ),
        )
        for invoke in substitutions:
            with self.subTest(invoke=invoke), self.assertRaises(BrokerStateConflict):
                invoke()
            self.assertEqual(
                self.store.permit_for_reconciliation(prepared.permit_sha256).state,
                "PREPARED",
            )

    def test_nonce_domains_are_closed_hashed_and_survive_restart(self):
        digest = self.store.record_nonce("prepare_release", b"fresh" * 8)
        self.assertEqual(len(digest), 64)
        self.assertNotIn("fresh", digest)
        with self.assertRaises(BrokerStateConflict):
            self.store.record_nonce("prepare_release", b"fresh" * 8)
        with self.assertRaises(BrokerStateConflict):
            self.store.record_nonce("not-a-method", b"other" * 8)

        self.store.close()
        self.store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        with self.assertRaises(BrokerStateConflict):
            self.store.record_nonce("prepare_release", b"fresh" * 8)

    def test_failed_sqlite_transition_rolls_back_to_identical_logical_dump(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        permit = _permit(self.receipt)
        prepared = self.store.prepare_permit(permit)
        before = _logical_dump(self.path)
        injector = sqlite3.connect(self.path)
        injector.execute(
            "CREATE TRIGGER fail_release BEFORE UPDATE OF state ON permits "
            "WHEN NEW.state='RELEASE_COMMITTED' "
            "BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
        injector.commit()
        injector.close()
        with self.assertRaisesRegex(
            BrokerStateUnavailable, r"^command broker state unavailable$"
        ):
            self.store.commit_release(permit, prepared.permit_sha256)
        injector = sqlite3.connect(self.path)
        injector.execute("DROP TRIGGER fail_release")
        injector.commit()
        injector.close()
        self.assertEqual(_logical_dump(self.path), before)
        self.assertEqual(
            self.store.permit_for_reconciliation(prepared.permit_sha256).state,
            "PREPARED",
        )

    def test_clock_regression_rolls_back_terminal_transition_and_restart_is_valid(self):
        for operation in ("release", "claim"):
            with self.subTest(operation=operation):
                self.store.close()
                state_path = Path(self.temporary.name) / f"clock-{operation}.db"
                setup = _open_store(state_path, boot_id=BOOT_ID, clock=_clock)
                receipt = _receipt(scope_id=f"scope-clock-{operation}")
                setup.create_scope(receipt)
                setup.attach_process(receipt, 4711, 88_001)
                permit = _permit(receipt)
                prepared = setup.prepare_permit(permit)
                setup.close()
                before = _logical_dump(state_path)

                regressed = _open_store(
                    state_path, boot_id=BOOT_ID, clock=lambda: EARLIER
                )
                with self.assertRaises(BrokerStateUnavailable):
                    if operation == "release":
                        regressed.commit_release(permit, prepared.permit_sha256)
                    else:
                        regressed.claim_or_observe(
                            receipt, 4711, prepared.permit_sha256
                        )
                regressed.close()
                self.assertEqual(_logical_dump(state_path), before)

                reopened = _open_store(state_path, boot_id=BOOT_ID, clock=_clock)
                self.addCleanup(reopened.close)
                self.assertEqual(
                    reopened.permit_for_reconciliation(prepared.permit_sha256).state,
                    "PREPARED",
                )

    def test_release_and_claim_race_has_exactly_one_durable_winner(self):
        self.store.close()
        for iteration in range(100):
            with self.subTest(iteration=iteration):
                self._assert_race(iteration)

    def test_multiprocess_release_claim_serialization_and_postcommit_crash(self):
        self.store.close()
        context = multiprocessing.get_context("fork")
        for iteration in range(20):
            with self.subTest(iteration=iteration):
                state_path = Path(self.temporary.name) / f"process-{iteration}.db"
                setup = _open_store(state_path)
                receipt = _receipt(scope_id=f"scope-process-{iteration}")
                setup.create_scope(receipt)
                setup.attach_process(receipt, 4711, 88_001)
                permit = _permit(receipt)
                prepared = setup.prepare_permit(permit)
                setup.close()

                start_event = context.Event()
                results = context.Queue()
                processes = (
                    context.Process(
                        target=_process_transition,
                        args=(
                            str(state_path),
                            receipt,
                            permit,
                            prepared.permit_sha256,
                            "release",
                            start_event,
                            results,
                        ),
                    ),
                    context.Process(
                        target=_process_transition,
                        args=(
                            str(state_path),
                            receipt,
                            permit,
                            prepared.permit_sha256,
                            "claim",
                            start_event,
                            results,
                        ),
                    ),
                )
                for process in processes:
                    process.start()
                start_event.set()
                for process in processes:
                    process.join(timeout=5.0)
                    self.assertFalse(process.is_alive())
                    self.assertEqual(process.exitcode, 0)
                outcomes = (results.get(timeout=2.0), results.get(timeout=2.0))
                results.close()
                results.join_thread()
                states = {outcome[1] for outcome in outcomes if outcome[0] == "ok"}
                self.assertEqual(len(states), 1)
                self.assertIn(states.pop(), {"RELEASE_COMMITTED", "REVOKED"})
                self.assertEqual(sum(outcome[2] for outcome in outcomes), 1)

        crash_path = Path(self.temporary.name) / "postcommit-crash.db"
        setup = _open_store(crash_path)
        receipt = _receipt(scope_id="scope-postcommit-crash")
        setup.create_scope(receipt)
        setup.attach_process(receipt, 4711, 88_001)
        permit = _permit(receipt)
        prepared = setup.prepare_permit(permit)
        setup.close()
        crashing = context.Process(
            target=_commit_and_crash,
            args=(str(crash_path), permit, prepared.permit_sha256),
        )
        crashing.start()
        crashing.join(timeout=5.0)
        self.assertFalse(crashing.is_alive())
        self.assertEqual(crashing.exitcode, 91)
        reopened = _open_store(crash_path)
        self.addCleanup(reopened.close)
        self.assertEqual(
            reopened.claim_or_observe(
                _fresh_receipt(receipt), 4711, prepared.permit_sha256
            ).record.state,
            "RELEASE_COMMITTED",
        )

    def _assert_race(self, iteration: int) -> None:
        release_first = iteration % 2 == 0
        race_path = Path(self.temporary.name) / f"race-{iteration}.db"
        setup = _open_store(race_path, boot_id=BOOT_ID, clock=_clock)
        receipt = _receipt(scope_id=f"scope-{iteration}")
        setup.create_scope(receipt)
        setup.attach_process(receipt, 4711, 88_001)
        permit = _permit(receipt)
        prepared = setup.prepare_permit(permit)
        setup.close()

        entered = threading.Event()
        resume = threading.Event()

        def blocking_clock() -> str:
            entered.set()
            if not resume.wait(timeout=3.0):
                raise AssertionError("controlled transaction did not resume")
            return NOW

        first = _open_store(race_path, boot_id=BOOT_ID, clock=blocking_clock)
        second = _open_store(race_path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        outcomes: list[PermitTransition] = []
        failures: list[BaseException] = []

        if release_first:
            first_call = lambda: first.commit_release(permit, prepared.permit_sha256)
            second_call = lambda: second.claim_or_observe(
                receipt, 4711, prepared.permit_sha256
            )
        else:
            first_call = lambda: first.claim_or_observe(
                receipt, 4711, prepared.permit_sha256
            )
            second_call = lambda: second.commit_release(permit, prepared.permit_sha256)

        def invoke(call: Callable[[], PermitTransition]) -> None:
            try:
                outcomes.append(call())
            except BaseException as error:  # noqa: BLE001 - captured across thread
                failures.append(error)

        first_thread = threading.Thread(target=invoke, args=(first_call,))
        second_thread = threading.Thread(target=invoke, args=(second_call,))
        first_thread.start()
        self.assertTrue(entered.wait(timeout=2.0))
        second_thread.start()
        resume.set()
        first_thread.join(timeout=3.0)
        second_thread.join(timeout=3.0)
        self.assertFalse(first_thread.is_alive())
        self.assertFalse(second_thread.is_alive())

        expected = "RELEASE_COMMITTED" if release_first else "REVOKED"
        self.assertEqual(sum(result.transitioned for result in outcomes), 1)
        self.assertTrue(all(result.record.state == expected for result in outcomes))
        if release_first:
            self.assertEqual((len(outcomes), len(failures)), (2, 0))
        else:
            self.assertEqual((len(outcomes), len(failures)), (1, 1))
            self.assertIsInstance(failures[0], BrokerStateConflict)
        self.assertEqual(
            second.permit_for_reconciliation(prepared.permit_sha256).state,
            expected,
        )
        first.close()
        second.close()

    def test_reconciliation_queries_are_sorted_immutable_snapshots(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        prepared = self.store.prepare_permit(_permit(self.receipt))
        scopes = self.store.scopes_for_reconciliation()
        permits = self.store.permits_for_reconciliation()
        self.assertIsInstance(scopes, tuple)
        self.assertIsInstance(permits, tuple)
        self.assertEqual(scopes, (self.store.open_scope(self.receipt),))
        self.assertEqual(permits, (prepared,))

    def test_malformed_permit_tombstone_fails_restart_validation(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        prepared = self.store.prepare_permit(_permit(self.receipt))
        self.store.close()
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE permits SET permit_json='{}' WHERE permit_sha256=?",
            (prepared.permit_sha256,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(BrokerStateUnavailable):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_startup_rejects_self_consistent_permit_json_with_reused_proofs(self):
        for duplicate_field, source_field in (
            ("scope_broker_nonce", "scope_request_nonce"),
            ("permit_nonce", "request_nonce"),
        ):
            with self.subTest(duplicate_field=duplicate_field):
                self.store.close()
                state_path = (
                    Path(self.temporary.name) / f"duplicate-{duplicate_field}.db"
                )
                store = _open_store(state_path)
                receipt = _receipt(scope_id=f"scope-{duplicate_field}")
                store.create_scope(receipt)
                store.attach_process(receipt, 4711, 88_001)
                prepared = store.prepare_permit(_permit(receipt))
                store.close()

                connection = sqlite3.connect(state_path)
                value = json.loads(prepared.permit_json)
                value[duplicate_field] = value[source_field]
                malformed_json = json.dumps(
                    value, separators=(",", ":"), sort_keys=True
                )
                malformed_digest = hashlib.sha256(
                    b"lto-broker-release-v1\0" + malformed_json.encode("ascii")
                ).hexdigest()
                connection.execute(
                    "UPDATE permits SET permit_sha256=?,permit_json=? "
                    "WHERE permit_sha256=?",
                    (malformed_digest, malformed_json, prepared.permit_sha256),
                )
                connection.commit()
                connection.close()
                with self.assertRaises(BrokerStateUnavailable):
                    _open_store(state_path)

    def test_contradictory_prepared_permit_and_terminal_scope_fail_restart(self):
        self.store.attach_process(self.receipt, 4711, 88_001)
        self.store.prepare_permit(_permit(self.receipt))
        self.store.close()
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE scopes SET state='CLOSED' WHERE scope_id=?",
            (self.receipt.scope_id,),
        )
        connection.commit()
        connection.close()
        with self.assertRaises(BrokerStateUnavailable):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_nonce_plaintext_is_not_persisted(self):
        nonce = b"SECRET-NONCE-DO-NOT-PERSIST-RAW!"
        self.assertEqual(len(nonce), 32)
        self.store.record_nonce("release_child", nonce)
        self.store.close()
        self.assertNotIn(nonce, self.path.read_bytes())


class BrokerStoreLtfsSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.db"
        self.store = _open_store(self.path, boot_id=BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        self.request = _ltfs_request()
        self.receipt = _ltfs_receipt(self.request)
        self.finalization = _ltfs_finalization(self.receipt)
        _issue_ltfs_scope(self.store, self.request)

    def _begin(self, request: LtfsSessionRequest | None = None):
        return self.store.begin_ltfs_session(
            self.request if request is None else request,
            ltfs_tool_identity_sha256="a" * 64,
            fusermount_tool_identity_sha256="c" * 64,
        )

    def _reopen(self, *, boot_id: str = BOOT_ID) -> None:
        self.store.close()
        self.store = _open_store(self.path, boot_id=boot_id, clock=_clock)
        self.addCleanup(self.store.close)

    def test_restart_recovers_every_lifecycle_transition_and_exact_proofs(self):
        self.assertTrue(hasattr(self.store, "begin_ltfs_session"))
        started = self._begin()
        self.assertTrue(started.transitioned)
        self.assertEqual(started.record.state, "STARTING")
        self.assertTrue(self.store.ltfs_sessions_ready())

        self._reopen()
        starting = self.store.ltfs_session("operation-17", 9)
        self.assertEqual(starting.state, "STARTING")
        self.assertEqual(starting.request_sha256, ltfs_request_sha256(self.request))
        self.assertEqual(starting.cgroup_scope_id, "scope-17")
        self.assertEqual(starting.child_pid, None)

        child = self.store.bind_ltfs_child(
            self.request,
            child_pid=4711,
            child_start_ticks=8822,
            mount_namespace_sha256="9" * 64,
        )
        self.assertTrue(child.transitioned)
        self.assertEqual(child.record.state, "STARTING")
        self._reopen()
        self.assertEqual(
            (
                self.store.ltfs_session("operation-17", 9).child_pid,
                self.store.ltfs_session("operation-17", 9).child_start_ticks,
            ),
            (4711, 8822),
        )

        mounted = self.store.mark_ltfs_mounted(self.receipt)
        self.assertTrue(mounted.transitioned)
        self.assertEqual(mounted.record.state, "MOUNTED")
        self._reopen()
        recovered_mount = self.store.ltfs_session("operation-17", 9)
        self.assertEqual(recovered_mount.session_id, "session-17")
        self.assertEqual(recovered_mount.session_broker_nonce, b"b" * 32)
        self.assertEqual(recovered_mount.session_broker_proof, b"e" * 32)

        finalizing = self.store.begin_ltfs_finalization(
            self.receipt, self.finalization.request_nonce
        )
        self.assertTrue(finalizing.transitioned)
        self.assertEqual(finalizing.record.state, "FINALIZING")
        self._reopen()
        self.assertEqual(
            self.store.ltfs_session("operation-17", 9).finalization_request_nonce,
            b"f" * 32,
        )

        self.store.bind_ltfs_terminal_receipt(
            self.receipt, self.finalization.standalone_receipt
        )
        unmounted = self.store.mark_ltfs_unmounted(self.finalization)
        self.assertTrue(unmounted.transitioned)
        self.assertEqual(unmounted.record.state, "UNMOUNTED")
        self._reopen(boot_id=OTHER_BOOT_ID)
        terminal = self.store.ltfs_session("operation-17", 9)
        self.assertEqual(terminal.state, "UNMOUNTED")
        self.assertEqual(terminal.finalization_nonce, b"u" * 32)
        self.assertEqual(terminal.finalization_broker_proof, b"v" * 32)
        self.assertTrue(self.store.ltfs_sessions_ready())

    def test_identical_deliveries_are_observationally_idempotent(self):
        first = self._begin()
        repeated = self._begin()
        self.assertFalse(repeated.transitioned)
        self.assertEqual(repeated.record, first.record)

        child = self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
        self.assertFalse(
            self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64).transitioned
        )
        mounted = self.store.mark_ltfs_mounted(self.receipt)
        self.assertFalse(self.store.mark_ltfs_mounted(self.receipt).transitioned)
        finalizing = self.store.begin_ltfs_finalization(
            self.receipt, self.finalization.request_nonce
        )
        self.assertFalse(
            self.store.begin_ltfs_finalization(
                self.receipt, self.finalization.request_nonce
            ).transitioned
        )
        self.store.bind_ltfs_terminal_receipt(
            self.receipt, self.finalization.standalone_receipt
        )
        terminal = self.store.mark_ltfs_unmounted(self.finalization)
        self.assertFalse(self.store.mark_ltfs_unmounted(self.finalization).transitioned)
        self.assertEqual(
            (child.record.state, mounted.record.state, finalizing.record.state),
            ("STARTING", "MOUNTED", "FINALIZING"),
        )
        self.assertEqual(terminal.record.state, "UNMOUNTED")

    def test_conflicting_duplicate_is_durably_broken_and_fails_readiness(self):
        self._begin()
        conflict = _ltfs_request(request_nonce=b"x" * 32)
        with self.assertRaises(BrokerStateConflict):
            self._begin(conflict)
        broken = self.store.ltfs_session("operation-17", 9)
        self.assertEqual(broken.state, "BROKEN")
        self.assertFalse(self.store.ltfs_sessions_ready())

        self._reopen()
        self.assertEqual(self.store.ltfs_session("operation-17", 9).state, "BROKEN")
        with self.assertRaises(BrokerStateConflict):
            self._begin()

    def test_only_one_active_session_and_cross_lifecycle_nonce_replay_is_rejected(self):
        self._begin()
        second_scope = _receipt(
            command_id="command-18",
            owner_generation=10,
            scope_id="scope-18",
            request_nonce=b"d" * 32,
            broker_nonce=b"g" * 32,
            broker_proof=b"k" * 32,
        )
        second = _ltfs_request(
            operation_id="operation-18",
            owner_generation=10,
            request_nonce=b"x" * 32,
            cgroup_scope_receipt=second_scope,
        )
        _issue_ltfs_scope(self.store, second, device=42, inode=74)
        with self.assertRaises(BrokerStateConflict):
            self._begin(second)
        with self.assertRaises(BrokerStateConflict):
            self.store.ltfs_session("operation-18", 10)

        self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
        self.store.mark_ltfs_mounted(self.receipt)
        self.store.begin_ltfs_finalization(
            self.receipt, self.finalization.request_nonce
        )
        self.store.bind_ltfs_terminal_receipt(
            self.receipt, self.finalization.standalone_receipt
        )
        self.store.mark_ltfs_unmounted(self.finalization)
        self.assertTrue(
            self.store.begin_ltfs_session(
                second,
                ltfs_tool_identity_sha256="a" * 64,
                fusermount_tool_identity_sha256="c" * 64,
            ).transitioned
        )

        third_scope = _receipt(
            command_id="command-19",
            owner_generation=11,
            scope_id="scope-19",
            request_nonce=b"d" * 32,
            broker_nonce=b"g" * 32,
            broker_proof=b"k" * 32,
        )
        replay = _ltfs_request(
            operation_id="operation-19",
            owner_generation=11,
            request_nonce=self.request.request_nonce,
            cgroup_scope_receipt=third_scope,
        )
        _issue_ltfs_scope(self.store, replay, device=43, inode=75)
        second_receipt = _ltfs_receipt(
            second,
            session_id="session-18",
            broker_nonce=b"y" * 32,
            broker_proof=b"z" * 32,
        )
        second_finalization = _ltfs_finalization(
            second_receipt,
            request_nonce=b"q" * 32,
            finalization_nonce=b"r" * 32,
            broker_proof=b"s" * 32,
        )
        self.store.bind_ltfs_child(second, 4711, 8822, "9" * 64)
        self.store.mark_ltfs_mounted(second_receipt)
        self.store.begin_ltfs_finalization(
            second_receipt, second_finalization.request_nonce
        )
        self.store.bind_ltfs_terminal_receipt(
            second_receipt, second_finalization.standalone_receipt
        )
        self.store.mark_ltfs_unmounted(second_finalization)
        with self.assertRaises(BrokerStateConflict):
            self.store.begin_ltfs_session(
                replay,
                ltfs_tool_identity_sha256="a" * 64,
                fusermount_tool_identity_sha256="c" * 64,
            )

    def test_ambiguous_transition_is_broken_instead_of_reinterpreted(self):
        self._begin()
        self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
        self.store.mark_ltfs_mounted(self.receipt)
        tampered = _ltfs_receipt(self.request, broker_proof=b"x" * 32)
        with self.assertRaises(BrokerStateConflict):
            self.store.mark_ltfs_mounted(tampered)
        self.assertEqual(self.store.ltfs_session("operation-17", 9).state, "BROKEN")
        self.assertFalse(self.store.ltfs_sessions_ready())

    def test_boot_change_breaks_inflight_session_but_terminal_survives(self):
        self._begin()
        self.store.close()
        self.store = _open_store(self.path, boot_id=OTHER_BOOT_ID, clock=_clock)
        self.addCleanup(self.store.close)
        self.assertEqual(self.store.ltfs_session("operation-17", 9).state, "BROKEN")
        self.assertFalse(self.store.ltfs_sessions_ready())
        self.assertEqual(
            self.store.open_scope(self.request.cgroup_scope_receipt).state,
            "BROKEN",
        )

    def test_session_requires_exact_current_bound_cgroup_scope(self):
        for name in ("missing", "unbound", "closed"):
            with self.subTest(name=name):
                path = Path(self.temporary.name) / f"scope-{name}.db"
                store = _open_store(path, boot_id=BOOT_ID, clock=_clock)
                request = _ltfs_request(operation_id=f"operation-{name}")
                if name == "unbound":
                    store.create_scope(request.cgroup_scope_receipt)
                elif name == "closed":
                    _issue_ltfs_scope(store, request)
                    store.mark_scope(request.cgroup_scope_receipt, "CLOSED")
                with self.assertRaises(BrokerStateConflict):
                    store.begin_ltfs_session(
                        request,
                        ltfs_tool_identity_sha256="a" * 64,
                        fusermount_tool_identity_sha256="c" * 64,
                    )
                self.assertEqual(store.ltfs_sessions_for_reconciliation(), ())
                store.close()

        self._begin()
        with self.assertRaises(BrokerStateConflict):
            self.store.mark_scope(self.request.cgroup_scope_receipt, "CLOSED")
        self.assertEqual(
            self.store.open_scope(self.request.cgroup_scope_receipt).state,
            "ACTIVE",
        )

    def test_scope_permit_retirement_rejects_every_active_ltfs_phase(self):
        self._begin()
        for phase in ("STARTING", "MOUNTED", "FINALIZING"):
            if phase == "MOUNTED":
                self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
                self.store.mark_ltfs_mounted(self.receipt)
            elif phase == "FINALIZING":
                self.store.begin_ltfs_finalization(
                    self.receipt, self.finalization.request_nonce,
                )
            with self.subTest(phase=phase):
                with self.assertRaises(BrokerStateConflict):
                    self.store.revoke_scope_prepared_permits(
                        self.request.cgroup_scope_receipt,
                    )
                self.assertEqual(self.store.ltfs_session("operation-17", 9).state, phase)
                self.assertEqual(self.store.open_scope(
                    self.request.cgroup_scope_receipt,
                ).state, "ACTIVE")

    def test_breaking_scope_atomically_breaks_linked_ltfs_and_survives_restart(self):
        for index, mutation in enumerate(("mark", "cgroup")):
            with self.subTest(mutation=mutation):
                path = Path(self.temporary.name) / f"scope-break-{index}.db"
                store = _open_store(path, boot_id=BOOT_ID, clock=_clock)
                request = _ltfs_request(operation_id=f"operation-break-{index}")
                _issue_ltfs_scope(store, request, device=51 + index, inode=81 + index)
                store.begin_ltfs_session(
                    request,
                    ltfs_tool_identity_sha256="a" * 64,
                    fusermount_tool_identity_sha256="c" * 64,
                )
                if mutation == "mark":
                    scope = store.mark_scope(request.cgroup_scope_receipt, "BROKEN")
                else:
                    scope = store.break_cgroup_scope(
                        store.open_scope(request.cgroup_scope_receipt)
                    )
                self.assertEqual(scope.state, "BROKEN")
                self.assertEqual(
                    store.ltfs_session(
                        request.operation_id, request.owner_generation
                    ).state,
                    "BROKEN",
                )
                self.assertFalse(store.ltfs_sessions_ready())
                store.close()

                restarted = _open_store(path, boot_id=BOOT_ID, clock=_clock)
                self.assertEqual(
                    restarted.ltfs_session(
                        request.operation_id, request.owner_generation
                    ).state,
                    "BROKEN",
                )
                self.assertFalse(restarted.ltfs_sessions_ready())
                restarted.close()

    def test_ltfs_request_domains_and_observation_proofs_are_durable(self):
        for index, domain in enumerate(
            (
                "start_ltfs_session",
                "observe_ltfs_session",
                "finalize_ltfs_session",
            )
        ):
            nonce = bytes([65 + index]) * 32
            self.assertEqual(len(self.store.record_nonce(domain, nonce)), 64)
            with self.assertRaises(BrokerStateConflict):
                self.store.record_nonce(domain, nonce)

        self._begin()
        self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
        self.store.mark_ltfs_mounted(self.receipt)
        self.assertTrue(hasattr(self.store, "record_ltfs_observation"))
        observed = self.store.record_ltfs_observation(
            self.receipt,
            challenge=b"h" * 32,
            observation_nonce=b"o" * 32,
            broker_proof=b"w" * 32,
        )
        self.assertTrue(observed.transitioned)
        self.assertEqual(observed.record.session_id, "session-17")
        repeated = self.store.record_ltfs_observation(
            self.receipt,
            challenge=b"h" * 32,
            observation_nonce=b"x" * 32,
            broker_proof=b"y" * 32,
        )
        self.assertFalse(repeated.transitioned)
        self.assertEqual(repeated.record, observed.record)
        self._reopen()
        observations = self.store.ltfs_observations_for_reconciliation()
        self.assertEqual(len(observations), 1)
        self.assertEqual(observations[0], observed.record)
        with self.assertRaises(BrokerStateConflict):
            self.store.record_ltfs_observation(
                self.receipt,
                challenge=b"i" * 32,
                observation_nonce=b"o" * 32,
                broker_proof=b"y" * 32,
            )
        self.assertEqual(self.store.ltfs_session("operation-17", 9).state, "BROKEN")

    def test_tampered_rows_fail_closed_on_restart(self):
        mutations = (
            ("request_sha256", "not-a-digest"),
            ("start_request_nonce", b"short"),
            ("state", "MOUNTED"),
        )
        for index, (column, value) in enumerate(mutations):
            with self.subTest(column=column):
                path = Path(self.temporary.name) / f"tamper-{index}.db"
                store = _open_store(path, boot_id=BOOT_ID, clock=_clock)
                _issue_ltfs_scope(store, self.request)
                store.begin_ltfs_session(
                    self.request,
                    ltfs_tool_identity_sha256="a" * 64,
                    fusermount_tool_identity_sha256="c" * 64,
                )
                store.close()
                connection = sqlite3.connect(path)
                connection.execute("PRAGMA ignore_check_constraints=ON")
                connection.execute(
                    f"UPDATE ltfs_sessions SET {column}=?",
                    (value,),
                )
                connection.commit()
                connection.close()
                with self.assertRaises(BrokerStateUnavailable):
                    _open_store(path, boot_id=BOOT_ID, clock=_clock)

    def test_valid_shaped_immutable_digest_tamper_fails_restart(self):
        for index, column in enumerate(
            ("mount_path_sha256", "ltfs_tool_identity_sha256")
        ):
            with self.subTest(column=column):
                path = Path(self.temporary.name) / f"sealed-{index}.db"
                store = _open_store(path, boot_id=BOOT_ID, clock=_clock)
                _issue_ltfs_scope(store, self.request)
                store.begin_ltfs_session(
                    self.request,
                    ltfs_tool_identity_sha256="a" * 64,
                    fusermount_tool_identity_sha256="c" * 64,
                )
                store.close()
                connection = sqlite3.connect(path)
                connection.execute(
                    f"UPDATE ltfs_sessions SET {column}=?",
                    ("d" * 64,),
                )
                connection.commit()
                connection.close()
                with self.assertRaises(BrokerStateUnavailable):
                    _open_store(path, boot_id=BOOT_ID, clock=_clock)

    def test_valid_shaped_lifecycle_and_observation_tamper_fails_restart(self):
        for index, (table, column, value) in enumerate(
            (
                ("ltfs_sessions", "session_broker_proof", b"z" * 32),
                ("ltfs_sessions", "child_start_ticks", 8823),
                ("ltfs_sessions", "created_at", EARLIER),
                ("ltfs_observations", "broker_proof", b"z" * 32),
            )
        ):
            with self.subTest(table=table, column=column):
                path = Path(self.temporary.name) / f"lifecycle-sealed-{index}.db"
                store = _open_store(path, boot_id=BOOT_ID, clock=_clock)
                _issue_ltfs_scope(store, self.request)
                store.begin_ltfs_session(
                    self.request,
                    ltfs_tool_identity_sha256="a" * 64,
                    fusermount_tool_identity_sha256="c" * 64,
                )
                store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
                store.mark_ltfs_mounted(self.receipt)
                store.record_ltfs_observation(
                    self.receipt,
                    challenge=b"h" * 32,
                    observation_nonce=b"o" * 32,
                    broker_proof=b"w" * 32,
                )
                store.close()
                connection = sqlite3.connect(path)
                connection.execute(f"UPDATE {table} SET {column}=?", (value,))
                connection.commit()
                connection.close()
                with self.assertRaises(BrokerStateUnavailable):
                    _open_store(path, boot_id=BOOT_ID, clock=_clock)

    def test_broken_tombstone_cannot_drop_its_mounted_child_identity(self):
        self._begin()
        self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
        self.store.mark_ltfs_mounted(self.receipt)
        self.store.break_ltfs_session("operation-17", 9)
        self.store.close()
        connection = sqlite3.connect(self.path)
        connection.execute(
            "UPDATE ltfs_sessions SET child_pid=NULL,child_start_ticks=NULL,"
            "mount_namespace_sha256=NULL"
        )
        connection.commit()
        connection.close()
        with self.assertRaises(BrokerStateUnavailable):
            _open_store(self.path, boot_id=BOOT_ID, clock=_clock)

    def test_failed_transition_rolls_back_and_fsync_failure_is_unavailable(self):
        self._begin()
        self.store.bind_ltfs_child(self.request, 4711, 8822, "9" * 64)
        before = _logical_dump(self.path)
        injector = sqlite3.connect(self.path)
        injector.execute(
            "CREATE TRIGGER fail_ltfs_mount BEFORE UPDATE OF state ON ltfs_sessions "
            "WHEN NEW.state='MOUNTED' BEGIN SELECT RAISE(ABORT, 'injected'); END"
        )
        injector.commit()
        injector.close()
        with self.assertRaises(BrokerStateUnavailable):
            self.store.mark_ltfs_mounted(self.receipt)
        injector = sqlite3.connect(self.path)
        injector.execute("DROP TRIGGER fail_ltfs_mount")
        injector.commit()
        injector.close()
        self.assertEqual(_logical_dump(self.path), before)

        fsync_path = Path(self.temporary.name) / "fsync.db"
        fsync_store = _open_store(fsync_path, boot_id=BOOT_ID, clock=_clock)
        _issue_ltfs_scope(fsync_store, self.request)
        with (
            patch(
                "ltobackup.broker.store.os.fsync",
                side_effect=OSError("injected fsync failure"),
            ),
            self.assertRaises(BrokerStateUnavailable),
        ):
            fsync_store.begin_ltfs_session(
                self.request,
                ltfs_tool_identity_sha256="a" * 64,
                fusermount_tool_identity_sha256="c" * 64,
            )
        with self.assertRaises(BrokerStateUnavailable):
            fsync_store.ltfs_sessions_ready()

    def test_store_surface_and_payload_never_accept_raw_media_or_paths(self):
        self._begin()
        public = inspect.signature(self.store.begin_ltfs_session)
        self.assertEqual(
            tuple(public.parameters),
            (
                "request",
                "ltfs_tool_identity_sha256",
                "fusermount_tool_identity_sha256",
            ),
        )
        connection = sqlite3.connect(self.path)
        try:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(ltfs_sessions)")
            }
        finally:
            connection.close()
        self.assertTrue({"mount_path_sha256", "cgroup_scope_id"}.issubset(columns))
        self.assertFalse({"mount_path", "serial", "label", "catalog_row"} & columns)


if __name__ == "__main__":
    unittest.main()
