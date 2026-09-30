from __future__ import annotations

import array
import base64
import dataclasses
import hashlib
import hmac
import io
import json
import os
import signal
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ltobackup.broker.cgroup import (
    CgroupBinding,
    CgroupValidation,
    ProcessIdentityProof,
)
from ltobackup.broker.ltfs_session import (
    BrokerLtfsExecutor,
    LtfsLifecycleUnavailable,
    ProcMountInfoProbe,
    ProcProcessProbe,
)
from ltobackup.broker.main import (
    _activated_socket_from_fd,
    _delegated_root_from_membership,
    _load_broker_settings,
    _read_credentials,
)
from ltobackup.broker.main import (
    main as broker_main,
)
from ltobackup.broker.protocol import (
    LtfsProtocolAuthority,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from ltobackup.broker.service import CommandBrokerService, _peer_identity
from ltobackup.broker.store import (
    BrokerStateStore,
    BrokerStateUnavailable,
    PermitRecord,
    PermitTransition,
    ScopeRecord,
    permit_sha256,
)
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupScopeReceipt,
    LtfsFinalizationReceipt,
    LtfsReadyReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)

CAPABILITY = b"c" * 32
PROOF_KEY = b"k" * 32
QUALIFICATION_CREDENTIAL = b"q" * 32
BOOT_ID = "11111111-2222-4333-8444-555555555555"
NOW = "2026-08-22T12:34:56.000000Z"


class _MemoryStore:
    def __init__(self) -> None:
        self.scopes: dict[str, ScopeRecord] = {}
        self.identities: dict[tuple[str, int], str] = {}
        self.permits: dict[str, PermitRecord] = {}
        self.nonces: set[tuple[str, bytes]] = set()

    def revoke_scope_prepared_permits(self, receipt):
        for digest, permit in tuple(self.permits.items()):
            if permit.scope_id == receipt.scope_id and permit.state == "PREPARED":
                self.permits[digest] = dataclasses.replace(
                    permit, state="REVOKED", terminal_at=NOW,
                )

    def record_nonce(self, domain: str, nonce: bytes) -> str:
        from ltobackup.broker.store import BrokerStateConflict

        key = (domain, nonce)
        if key in self.nonces:
            raise BrokerStateConflict
        self.nonces.add(key)
        return "f" * 64

    def create_scope(self, receipt):
        key = (receipt.command_id, receipt.owner_generation)
        if key in self.identities:
            from ltobackup.broker.store import BrokerStateConflict

            raise BrokerStateConflict
        record = ScopeRecord(
            receipt.scope_id,
            receipt.command_id,
            receipt.owner_generation,
            receipt.scope_path_sha256,
            BOOT_ID,
            "ACTIVE",
            None,
            None,
            7,
            11,
            NOW,
        )
        self.scopes[receipt.scope_id] = record
        self.identities[key] = receipt.scope_id
        return record

    def scope_for_identity(self, command_id: str, generation: int) -> ScopeRecord:
        from ltobackup.broker.store import BrokerStateConflict

        scope_id = self.identities.get((command_id, generation))
        if scope_id is None:
            raise BrokerStateConflict
        return self.scopes[scope_id]

    def open_scope(self, receipt):
        from ltobackup.broker.store import BrokerStateConflict

        record = self.scopes.get(receipt.scope_id)
        if record is None or (record.command_id, record.owner_generation) != (
            receipt.command_id,
            receipt.owner_generation,
        ):
            raise BrokerStateConflict
        return record

    def attach(self, scope_id: str, pid: int) -> ScopeRecord:
        record = self.scopes[scope_id]
        record = dataclasses.replace(record, pid=pid, process_start_ticks=123)
        self.scopes[scope_id] = record
        return record

    def prepare_permit(self, permit):
        digest = permit_sha256(permit)
        record = PermitRecord(
            digest, permit.receipt.scope_id, permit.pid, "PREPARED", "{}", NOW, None
        )
        self.permits[digest] = record
        return record

    def commit_release(self, permit, digest):
        from ltobackup.broker.store import BrokerStateConflict

        record = self.permits[digest]
        if record.state == "REVOKED":
            raise BrokerStateConflict
        if record.state == "RELEASE_COMMITTED":
            return PermitTransition(record, False)
        record = dataclasses.replace(record, state="RELEASE_COMMITTED", terminal_at=NOW)
        self.permits[digest] = record
        return PermitTransition(record, True)

    def claim_or_observe(self, receipt, pid, digest):
        record = self.permits[digest]
        if record.scope_id != receipt.scope_id or record.pid != pid:
            from ltobackup.broker.store import BrokerStateConflict

            raise BrokerStateConflict
        if record.state != "PREPARED":
            return PermitTransition(record, False)
        record = dataclasses.replace(record, state="REVOKED", terminal_at=NOW)
        self.permits[digest] = record
        return PermitTransition(record, True)

    def mark_scope(self, receipt, state):
        record = dataclasses.replace(self.scopes[receipt.scope_id], state=state)
        self.scopes[receipt.scope_id] = record
        return record

    def scopes_for_reconciliation(self):
        return tuple(self.scopes.values())

    def ltfs_sessions_ready(self) -> bool:
        return True


class _ReadinessPins:
    ltfs_tool_identity_sha256 = "8" * 64
    fusermount_tool_identity_sha256 = "9" * 64

    def __init__(self) -> None:
        self.valid = True
        self.validation_count = 0

    def assert_readiness_anchors(self) -> None:
        self.validation_count += 1
        if not self.valid:
            raise RuntimeError("tool anchor changed")


class _MemoryCgroup:
    def __init__(self, store: _MemoryStore) -> None:
        self.store = store
        self.calls: list[str] = []
        self.exited: set[str] = set()

    def create(self, record, store):
        self.calls.append("create_scope")
        return record

    def open(self, record):
        self.calls.append("open_scope")
        return CgroupBinding(record.scope_id, record.cgroup_device, record.cgroup_inode)

    def attach(self, record, pid, *, daemon_uid, store):
        self.calls.append("attach")
        current = self.store.attach(record.scope_id, pid)
        return ProcessIdentityProof(pid, current.process_start_ticks)

    def validate(self, record):
        self.calls.append("validate_scope")
        members = () if record.pid is None or record.scope_id in self.exited else (record.pid,)
        return CgroupValidation(record.scope_id, bool(members), members)

    def signal(self, record, signum, *, daemon_uid, store):
        self.calls.append("signal_scope")

    def kill(self, record):
        self.calls.append("kill_scope")
        self.exited.add(record.scope_id)

    def release(self, record):
        self.calls.append("release_scope")

    def validate_readiness(self) -> None:
        self.calls.append("readiness")


class _MissingCgroup(_MemoryCgroup):
    def open(self, record):
        from ltobackup.broker.cgroup import CgroupConflict

        raise CgroupConflict


class _StoreBackedCgroup:
    def __init__(self) -> None:
        self.members: dict[str, int] = {}
        self.next_inode = 100
        self.attach_uids: list[int] = []
        self.kill_count = 0
        self.released: set[str] = set()

    def create(self, record, store):
        self.next_inode += 1
        return store.bind_cgroup(record, device=7, inode=self.next_inode)

    def open(self, record):
        if record.scope_id in self.released:
            from ltobackup.broker.cgroup import CgroupConflict

            raise CgroupConflict
        return CgroupBinding(record.scope_id, record.cgroup_device, record.cgroup_inode)

    def attach(self, record, pid, *, daemon_uid, store):
        self.attach_uids.append(daemon_uid)
        self.open(record)
        current = store.require_cgroup_scope(record)
        if current.pid is None:
            current = store.attach_cgroup_process(current, pid=pid, start_ticks=123)
        if (current.pid, current.process_start_ticks) != (pid, 123):
            from ltobackup.broker.cgroup import CgroupConflict

            raise CgroupConflict
        self.members[current.scope_id] = pid
        return ProcessIdentityProof(pid, 123)

    def validate(self, record):
        self.open(record)
        pid = self.members.get(record.scope_id)
        members = () if pid is None else (pid,)
        return CgroupValidation(record.scope_id, bool(members), members)

    def signal(self, record, signum, *, daemon_uid, store):
        return None

    def kill(self, record):
        self.kill_count += 1
        self.members.pop(record.scope_id, None)

    def release(self, record):
        if record.scope_id in self.members:
            from ltobackup.broker.cgroup import CgroupConflict

            raise CgroupConflict
        self.released.add(record.scope_id)


def _send(
    service: CommandBrokerService, packet: bytes, fds: tuple[int, ...] = ()
) -> bytes:
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        if fds:
            rights = array.array("i", fds)
            client.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
        else:
            client.send(packet)
        service.handle_connection(server)
        return client.recv(65537)
    finally:
        client.close()
        server.close()


class CommandBrokerServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = _MemoryStore()
        self.cgroup = _MemoryCgroup(self.store)
        self.service = CommandBrokerService(
            self.store,
            self.cgroup,
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
            connection_timeout=0.25,
            max_connections=2,
        )
        self.counter = 0

    def readiness_service(self) -> tuple[CommandBrokerService, _ReadinessPins]:
        pins = _ReadinessPins()
        runtime = object()
        service = CommandBrokerService(
            self.store,
            self.cgroup,
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
            ltfs_pins=pins,
            ltfs_receipt_root=runtime,
            ltfs_executor=runtime,
            ltfs_mountinfo_probe=runtime,
            ltfs_process_probe=runtime,
        )
        return service, pins

    def packet(
        self, method: str, params: dict[str, object], *, capability: bytes = CAPABILITY
    ) -> bytes:
        self.counter += 1
        return encode_request(
            method,
            request_id=self.counter.to_bytes(32, "big"),
            capability=capability,
            params=params,
        )

    def ok(
        self, method: str, params: dict[str, object], fds: tuple[int, ...] = ()
    ) -> dict[str, object]:
        response = decode_response(
            _send(self.service, self.packet(method, params), fds)
        )
        self.assertIsNone(response.error_code)
        assert response.result is not None
        return response.result

    def _new_scope(self, suffix: str = "1") -> dict[str, object]:
        return self.ok(
            "create_scope",
            {
                "command_id": "command-" + suffix,
                "owner_generation": int(suffix),
                "request_nonce": ("r" + suffix).encode() * 16,
            },
        )["receipt"]

    def test_dispatches_all_ten_methods_and_writes_one_release_byte(self):
        receipt = self._new_scope()
        opened = self.ok(
            "open_scope",
            {
                "command_id": "command-1",
                "owner_generation": 1,
                "request_nonce": b"o" * 32,
            },
        )["receipt"]
        self.assertEqual(opened["scope_id"], receipt["scope_id"])
        self.ok("attach", {"receipt": receipt, "pid": 4711})
        validation = self.ok(
            "validate_scope", {"receipt": receipt, "challenge": b"v" * 32}
        )["validation"]
        self.assertEqual(validation["member_pids"], (4711,))
        permit = self.ok(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )["permit"]
        read_fd, write_fd = os.pipe()
        try:
            self.ok(
                "release_child",
                {"receipt": receipt, "permit": permit, "pid": 4711},
                (write_fd,),
            )
            self.assertEqual(os.read(read_fd, 2), b"1")
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.ok("signal_scope", {"receipt": receipt, "signum": int(signal.SIGTERM)})
        self.ok("kill_scope", {"receipt": receipt})
        self.ok("release_scope", {"receipt": receipt})

        second = self._new_scope("2")
        self.ok("attach", {"receipt": second, "pid": 4712})
        second_permit = self.ok(
            "prepare_release",
            {"receipt": second, "pid": 4712, "request_nonce": b"q" * 32},
        )["permit"]
        digest = permit_sha256_from_mapping(second_permit)
        claim = self.ok(
            "claim_unreleased",
            {
                "receipt": second,
                "pid": 4712,
                "permit_sha256": digest,
                "challenge": b"x" * 32,
            },
        )["claim"]
        self.assertFalse(claim["released"])
        self.assertTrue(claim["permit_revoked"])
        self.assertEqual(
            set(self.cgroup.calls),
            {
                "create_scope",
                "open_scope",
                "attach",
                "validate_scope",
                "signal_scope",
                "kill_scope",
                "release_scope",
            },
        )

    def test_rejects_peer_uid_gid_and_required_selinux_context_before_dispatch(self):
        packet = self.packet(
            "create_scope",
            {
                "command_id": "command-1",
                "owner_generation": 1,
                "request_nonce": b"r" * 32,
            },
        )
        for identity in (
            (99, os.getgid(), b"system_u:system_r:lto_archiver_t:s0"),
            (os.getuid(), 99, b"system_u:system_r:lto_archiver_t:s0"),
            (os.getuid(), os.getgid(), b"system_u:system_r:wrong_t:s0"),
        ):
            with (
                self.subTest(identity=identity),
                patch("ltobackup.broker.service._peer_identity", return_value=identity),
            ):
                self.service.enforcing = identity[2].endswith(b"wrong_t:s0")
                response = decode_response(_send(self.service, packet))
                self.assertEqual(response.error_code, "auth.denied")
                self.assertEqual(self.store.nonces, set())
                self.assertEqual(self.store.scopes, {})
                self.assertEqual(self.cgroup.calls, [])
        self.service.enforcing = False

    def test_peer_identity_uses_python_supported_peersec_buffer(self):
        expected_context = b"system_u:system_r:lto_archiver_t:s0\0"
        calls: list[tuple[int, int, int]] = []

        class Peer:
            @staticmethod
            def getsockopt(level: int, option: int, length: int) -> bytes:
                calls.append((level, option, length))
                if option == socket.SO_PEERCRED:
                    return struct.pack("3i", 17, 990, 990)
                if length > 1024:
                    raise OSError("getsockopt buflen out of range")
                return expected_context

        self.assertEqual((990, 990, expected_context[:-1]), _peer_identity(Peer()))
        self.assertEqual(1024, calls[-1][2])

    def test_capability_uses_constant_time_comparison_and_is_redacted(self):
        packet = self.packet(
            "create_scope",
            {
                "command_id": "command-secret",
                "owner_generation": 1,
                "request_nonce": b"s" * 32,
            },
            capability=b"w" * 32,
        )
        with patch(
            "ltobackup.broker.service.hmac.compare_digest",
            wraps=__import__("hmac").compare_digest,
        ) as compare:
            raw = _send(self.service, packet)
        response = decode_response(raw)
        self.assertEqual(response.error_code, "auth.denied")
        compare.assert_called_once_with(b"w" * 32, CAPABILITY)
        self.assertNotIn(b"command-secret", raw)
        self.assertNotIn(b"wwww", raw)

    def test_readiness_is_authenticated_replay_safe_and_scope_free(self):
        service, pins = self.readiness_service()
        unavailable = decode_response(
            _send(
                service,
                self.packet("readiness", {"nonce": b"u" * 32}),
            )
        )
        self.assertEqual("state.unavailable", unavailable.error_code)
        service.reconcile_startup()
        request_id = b"r" * 32
        nonce = b"n" * 32
        packet = encode_request(
            "readiness",
            request_id=request_id,
            capability=CAPABILITY,
            params={"nonce": nonce},
        )
        response = decode_response(_send(service, packet))
        self.assertIsNone(response.error_code)
        features = response.result["features"]
        self.assertEqual(nonce, response.result["nonce"])
        self.assertEqual(nonce, features["challenge"])
        self.assertEqual(1, features["ltfs_session_contract"])
        self.assertEqual("8" * 64, features["ltfs_tool_identity_sha256"])
        self.assertEqual("9" * 64, features["fusermount_tool_identity_sha256"])
        self.assertIs(features["reconciliation_clean"], True)
        proof_fields = {
            key: value for key, value in features.items() if key != "capability_proof"
        }
        canonical_fields = {
            key: (
                {"base64": base64.b64encode(value).decode("ascii")}
                if type(value) is bytes
                else value
            )
            for key, value in proof_fields.items()
        }
        expected = hmac.new(
            CAPABILITY,
            json.dumps(
                {
                    "domain": "readiness-capability-proof-v1",
                    "fields": canonical_fields,
                    "version": 1,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii"),
            hashlib.sha256,
        ).digest()
        self.assertTrue(hmac.compare_digest(expected, features["capability_proof"]))
        self.assertEqual({}, self.store.scopes)
        self.assertEqual(["readiness"], self.cgroup.calls)
        self.assertEqual(1, pins.validation_count)

        with patch(
            "ltobackup.broker.service.secrets.token_bytes",
            side_effect=(features["reconciliation_nonce"], b"w" * 32),
        ):
            fresh = decode_response(
                _send(
                    service,
                    self.packet("readiness", {"nonce": b"q" * 32}),
                )
            )
        self.assertIsNone(fresh.error_code)
        self.assertEqual(b"w" * 32, fresh.result["features"]["reconciliation_nonce"])
        self.assertEqual(2, pins.validation_count)

        replay = decode_response(_send(service, packet))
        self.assertEqual("scope.conflict", replay.error_code)
        self.assertEqual({}, self.store.scopes)

        mismatch = encode_request(
            "readiness",
            request_id=b"s" * 32,
            capability=b"x" * 32,
            params={"nonce": b"m" * 32},
        )
        denied = decode_response(_send(service, mismatch))
        self.assertEqual("auth.denied", denied.error_code)
        self.assertEqual({}, self.store.scopes)

        pins.valid = False
        changed = decode_response(
            _send(
                service,
                self.packet("readiness", {"nonce": b"t" * 32}),
            )
        )
        self.assertEqual("state.unavailable", changed.error_code)
        pins.valid = True
        still_invalid = decode_response(
            _send(
                service,
                self.packet("readiness", {"nonce": b"v" * 32}),
            )
        )
        self.assertEqual("state.unavailable", still_invalid.error_code)

    def test_readiness_rejects_a_broken_scope_after_clean_reconciliation(self):
        service, _pins = self.readiness_service()
        service.reconcile_startup()
        receipt = self._new_scope()
        self.store.mark_scope(SimpleNamespace(scope_id=receipt["scope_id"]), "BROKEN")

        response = decode_response(
            _send(
                service,
                self.packet("readiness", {"nonce": b"b" * 32}),
            )
        )

        self.assertEqual("state.unavailable", response.error_code)

    def test_replayed_request_id_fails_without_a_second_mutation(self):
        request_id = b"i" * 32
        packet = encode_request(
            "create_scope",
            request_id=request_id,
            capability=CAPABILITY,
            params={
                "command_id": "command-1",
                "owner_generation": 1,
                "request_nonce": b"r" * 32,
            },
        )
        self.assertIsNone(decode_response(_send(self.service, packet)).error_code)
        response = decode_response(_send(self.service, packet))
        self.assertEqual(response.error_code, "scope.conflict")
        self.assertEqual(self.cgroup.calls.count("create_scope"), 1)

    def test_replayed_semantic_request_nonce_fails_with_a_fresh_packet_id(self):
        receipt = self._new_scope()
        self.ok("attach", {"receipt": receipt, "pid": 4711})
        params = {
            "receipt": receipt,
            "pid": 4711,
            "request_nonce": b"p" * 32,
        }
        self.ok("prepare_release", params)
        response = decode_response(
            _send(self.service, self.packet("prepare_release", params))
        )
        self.assertEqual(response.error_code, "scope.conflict")

    def test_ancillary_descriptor_contract_is_exact_and_closes_received_fds(self):
        receipt = self._new_scope()
        self.ok("attach", {"receipt": receipt, "pid": 4711})
        permit = self.ok(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )["permit"]
        before = len(os.listdir("/proc/self/fd"))
        read_fd, write_fd = os.pipe()
        regular = os.open(__file__, os.O_RDONLY)
        try:
            cases = (
                (
                    "validate_scope",
                    {"receipt": receipt, "challenge": b"z" * 32},
                    (write_fd,),
                ),
                (
                    "release_child",
                    {"receipt": receipt, "permit": permit, "pid": 4711},
                    (),
                ),
                (
                    "release_child",
                    {"receipt": receipt, "permit": permit, "pid": 4711},
                    (write_fd, write_fd),
                ),
                (
                    "release_child",
                    {"receipt": receipt, "permit": permit, "pid": 4711},
                    (regular,),
                ),
                (
                    "release_child",
                    {"receipt": receipt, "permit": permit, "pid": 4711},
                    (read_fd,),
                ),
            )
            for method, params, fds in cases:
                with self.subTest(method=method, count=len(fds)):
                    response = decode_response(
                        _send(self.service, self.packet(method, params), fds)
                    )
                    self.assertEqual(response.error_code, "protocol.invalid")
        finally:
            os.close(regular)
            os.close(read_fd)
            os.close(write_fd)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_committed_release_is_not_written_twice(self):
        receipt = self._new_scope()
        self.ok("attach", {"receipt": receipt, "pid": 4711})
        permit = self.ok(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )["permit"]
        read_fd, first_write = os.pipe()
        second_read, second_write = os.pipe()
        try:
            self.ok(
                "release_child",
                {"receipt": receipt, "permit": permit, "pid": 4711},
                (first_write,),
            )
            self.assertEqual(os.read(read_fd, 1), b"1")
            response = decode_response(
                _send(
                    self.service,
                    self.packet(
                        "release_child",
                        {"receipt": receipt, "permit": permit, "pid": 4711},
                    ),
                    (second_write,),
                )
            )
            self.assertEqual(response.error_code, "state.ambiguous")
            os.set_blocking(second_read, False)
            with self.assertRaises(BlockingIOError):
                os.read(second_read, 1)
        finally:
            for fd in (read_fd, first_write, second_read, second_write):
                os.close(fd)

    def test_write_failure_after_commit_is_ambiguous_and_terminal(self):
        receipt = self._new_scope()
        self.ok("attach", {"receipt": receipt, "pid": 4711})
        permit = self.ok(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )["permit"]
        read_fd, write_fd = os.pipe()
        os.close(read_fd)
        try:
            response = decode_response(
                _send(
                    self.service,
                    self.packet(
                        "release_child",
                        {"receipt": receipt, "permit": permit, "pid": 4711},
                    ),
                    (write_fd,),
                )
            )
            self.assertEqual(response.error_code, "state.ambiguous")
            self.assertEqual(
                self.store.permits[permit_sha256_from_mapping(permit)].state,
                "RELEASE_COMMITTED",
            )
        finally:
            os.close(write_fd)

    def test_substituted_receipt_or_permit_proof_cannot_mutate_state(self):
        receipt = self._new_scope()
        forged_receipt = dict(receipt)
        forged_receipt["broker_proof"] = b"g" * 32
        response = decode_response(
            _send(
                self.service,
                self.packet("attach", {"receipt": forged_receipt, "pid": 4711}),
            )
        )
        self.assertEqual(response.error_code, "scope.conflict")
        self.assertIsNone(self.store.scopes[receipt["scope_id"]].pid)

        self.ok("attach", {"receipt": receipt, "pid": 4711})
        permit = self.ok(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )["permit"]
        forged_permit = dict(permit)
        forged_permit["broker_proof"] = b"g" * 32
        read_fd, write_fd = os.pipe()
        try:
            response = decode_response(
                _send(
                    self.service,
                    self.packet(
                        "release_child",
                        {
                            "receipt": receipt,
                            "permit": forged_permit,
                            "pid": 4711,
                        },
                    ),
                    (write_fd,),
                )
            )
            self.assertEqual(response.error_code, "scope.conflict")
            self.assertEqual(
                self.store.permits[permit_sha256_from_mapping(permit)].state,
                "PREPARED",
            )
            os.set_blocking(read_fd, False)
            with self.assertRaises(BlockingIOError):
                os.read(read_fd, 1)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_claim_proof_is_fresh_and_bound_to_each_challenge(self):
        receipt = self._new_scope()
        self.ok("attach", {"receipt": receipt, "pid": 4711})
        permit = self.ok(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )["permit"]
        digest = permit_sha256_from_mapping(permit)
        first = self.ok(
            "claim_unreleased",
            {
                "receipt": receipt,
                "pid": 4711,
                "permit_sha256": digest,
                "challenge": b"a" * 32,
            },
        )["claim"]
        second = self.ok(
            "claim_unreleased",
            {
                "receipt": receipt,
                "pid": 4711,
                "permit_sha256": digest,
                "challenge": b"b" * 32,
            },
        )["claim"]
        self.assertEqual(first["challenge"], b"a" * 32)
        self.assertEqual(second["challenge"], b"b" * 32)
        self.assertNotEqual(first["claim_nonce"], second["claim_nonce"])
        self.assertNotEqual(first["broker_proof"], second["broker_proof"])

    def test_serve_bounds_concurrency_and_shutdown_while_a_peer_stalls(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broker.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(str(path))
            listener.listen(8)
            thread = threading.Thread(target=self.service.serve, args=(listener,))
            thread.start()
            slow = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            fast = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            try:
                slow.connect(str(path))
                fast.settimeout(0.5)
                fast.connect(str(path))
                fast.send(
                    self.packet(
                        "create_scope",
                        {
                            "command_id": "command-fast",
                            "owner_generation": 1,
                            "request_nonce": b"f" * 32,
                        },
                    )
                )
                response = decode_response(fast.recv(65_537))
                self.assertIsNone(response.error_code)
            finally:
                slow.close()
                fast.close()
                self.service.shutdown()
                listener.close()
                thread.join(1.5)
        self.assertFalse(thread.is_alive())

    def test_shutdown_preserves_the_systemd_owned_listener_for_reactivation(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broker.sock"
            systemd_listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            systemd_listener.bind(str(path))
            systemd_listener.listen(8)
            service_listener = systemd_listener.dup()
            thread = threading.Thread(
                target=self.service.serve,
                args=(service_listener,),
            )
            thread.start()
            try:
                for _attempt in range(100):
                    if self.service._listener is service_listener:
                        break
                    time.sleep(0.01)
                self.assertIs(service_listener, self.service._listener)
                self.service.shutdown()
                thread.join(1.5)
                self.assertFalse(thread.is_alive())
                service_listener.close()

                client = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                client.settimeout(0.5)
                systemd_listener.settimeout(0.5)
                try:
                    client.connect(str(path))
                    accepted, _address = systemd_listener.accept()
                    accepted.close()
                finally:
                    client.close()
            finally:
                self.service.shutdown()
                service_listener.close()
                systemd_listener.close()
                thread.join(1.5)

    def test_startup_reconciliation_marks_missing_active_scope_broken_and_refuses_readiness(
        self,
    ):
        receipt = self._new_scope()
        missing = CommandBrokerService(
            self.store,
            _MissingCgroup(self.store),
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
        )
        from ltobackup.broker.store import BrokerStateUnavailable

        with self.assertRaises(BrokerStateUnavailable):
            missing.reconcile_startup()
        self.assertEqual(self.store.scopes[receipt["scope_id"]].state, "BROKEN")
        with self.assertRaises(BrokerStateUnavailable):
            missing.reconcile_startup()


class CommandBrokerStartupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_help_exits_zero_before_any_privileged_startup(self):
        output = io.StringIO()
        hostile = {
            "HOME": str(self.root / "hostile-home"),
            "PYTHONHOME": str(self.root / "hostile-python-home"),
            "PYTHONPATH": str(self.root / "attacker"),
            "PYTHONUSERBASE": str(self.root / "hostile-user-base"),
        }
        with (
            patch.dict(os.environ, hostile, clear=True),
            patch("ltobackup.broker.main.pwd.getpwnam") as getpwnam,
            patch("sys.stdout", output),
            self.assertRaises(SystemExit) as raised,
        ):
            broker_main(["--help"])

        self.assertEqual(0, raised.exception.code)
        self.assertIn("usage: lto-archiver-command-broker", output.getvalue())
        getpwnam.assert_not_called()

    def test_unknown_arguments_fail_closed_before_privileged_startup(self):
        error = io.StringIO()
        with (
            patch("ltobackup.broker.main.pwd.getpwnam") as getpwnam,
            patch("sys.stderr", error),
            self.assertRaises(SystemExit) as raised,
        ):
            broker_main(["--unexpected"])

        self.assertEqual(2, raised.exception.code)
        self.assertIn("unrecognized arguments: --unexpected", error.getvalue())
        getpwnam.assert_not_called()

    @staticmethod
    def _root_status(
        status: os.stat_result, *, mode: int | None = None, gid: int = 77
    ) -> os.stat_result:
        fields = list(status)
        if mode is not None:
            fields[0] = stat.S_IFMT(status.st_mode) | mode
        fields[4] = 0
        fields[5] = gid
        return os.stat_result(fields)

    def test_socket_activation_accepts_exact_single_seqpacket_listener(self):
        path = self.root / "control.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(listener.close)
        listener.bind(str(path))
        listener.listen(4)
        expected = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1"}

        def lstat_root(candidate):
            self.assertEqual(Path(candidate), path)
            return self._root_status(os.lstat(candidate), mode=0o660)

        def fstat_root(fd):
            return self._root_status(os.fstat(fd), gid=77)

        with (
            patch("ltobackup.broker.main._lstat", side_effect=lstat_root),
            patch("ltobackup.broker.main._fstat", side_effect=fstat_root),
        ):
            inherited = _activated_socket_from_fd(
                listener.fileno(), expected, expected_gid=77
            )
        self.addCleanup(inherited.close)
        self.assertEqual(inherited.family, socket.AF_UNIX)
        self.assertEqual(inherited.type & 0xF, socket.SOCK_SEQPACKET)
        self.assertEqual(
            inherited.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN), 1
        )
        self.assertFalse(os.get_inheritable(inherited.fileno()))

    def test_socket_activation_rejects_environment_or_inode_contract_mismatch(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        for environment in (
            {},
            {"LISTEN_PID": str(os.getpid() + 1), "LISTEN_FDS": "1"},
            {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "2"},
        ):
            with self.subTest(environment=environment), self.assertRaises(RuntimeError):
                _activated_socket_from_fd(left.fileno(), environment, expected_gid=77)

    def test_credentials_are_exact_distinct_root_owned_files(self):
        capability = self.root / "broker-capability"
        proof = self.root / "broker-proof-key"
        qualification = self.root / "qualification-credential"
        capability.write_bytes(CAPABILITY)
        proof.write_bytes(PROOF_KEY)
        qualification.write_bytes(QUALIFICATION_CREDENTIAL)
        capability.chmod(0o400)
        proof.chmod(0o400)
        qualification.chmod(0o400)

        def fstat_root(fd):
            current = os.fstat(fd)
            mode = 0o500 if stat.S_ISDIR(current.st_mode) else 0o400
            return self._root_status(current, mode=mode, gid=0)

        with patch("ltobackup.broker.main._fstat", side_effect=fstat_root):
            self.assertEqual(
                _read_credentials(self.root),
                (CAPABILITY, PROOF_KEY, QUALIFICATION_CREDENTIAL),
            )

        def fstat_writable_directory(fd):
            current = fstat_root(fd)
            if stat.S_ISDIR(current.st_mode):
                return self._root_status(current, mode=0o700, gid=0)
            return current

        with (
            patch(
                "ltobackup.broker.main._fstat",
                side_effect=fstat_writable_directory,
            ),
            self.assertRaises(RuntimeError),
        ):
            _read_credentials(self.root)
        proof.chmod(0o600)
        proof.write_bytes(CAPABILITY)
        proof.chmod(0o400)
        with (
            patch("ltobackup.broker.main._fstat", side_effect=fstat_root),
            self.assertRaises(RuntimeError),
        ):
            _read_credentials(self.root)

    def test_delegated_root_is_derived_only_from_unified_membership(self):
        self.assertEqual(
            _delegated_root_from_membership(b"0::/system.slice/lto.service\n"),
            Path("/sys/fs/cgroup/system.slice/lto.service"),
        )
        for payload in (
            b"1:name=systemd:/x\n",
            b"0::/../../escape\n",
            b"0::/one\n0::/two\n",
            b"0::/contains\\escape\n",
        ):
            with self.subTest(payload=payload), self.assertRaises(RuntimeError):
                _delegated_root_from_membership(payload)

    def test_broker_settings_are_loaded_through_one_root_owned_config_pin(self):
        config = self.root / "config.toml"
        config.write_text(
            'tape_device_path = "/dev/tape/by-id/drive-tape-nst"\n'
            'scsi_device_path = "/dev/lto-archiver-scsi-drive"\n'
            'mount_path = "/mnt/lto-archiver/tape"\n',
            encoding="utf-8",
        )
        config.chmod(0o640)
        inode = config.stat().st_ino

        def secured(status):
            return SimpleNamespace(
                st_dev=status.st_dev,
                st_ino=status.st_ino,
                st_mode=status.st_mode,
                st_nlink=status.st_nlink,
                st_uid=0,
                st_gid=77,
                st_size=status.st_size,
                st_mtime_ns=status.st_mtime_ns,
            )

        with (
            patch(
                "ltobackup.broker.main._fstat",
                side_effect=lambda fd: secured(os.fstat(fd)),
            ),
            patch(
                "ltobackup.broker.main._lstat",
                side_effect=lambda path: secured(os.lstat(path)),
            ),
        ):
            settings = _load_broker_settings(config, expected_gid=77)
        self.assertEqual(settings.tape_device_path.name, "drive-tape-nst")
        self.assertEqual(config.stat().st_ino, inode)

        link = self.root / "config-link.toml"
        link.symlink_to(config)
        with self.assertRaises(RuntimeError):
            _load_broker_settings(link, expected_gid=77)

    def test_main_holds_configured_pins_through_service_shutdown(self):
        notification = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.addCleanup(notification.close)
        notification_path = self.root / "notify.sock"
        notification.bind(str(notification_path))
        notification.settimeout(1)
        events: list[str] = []
        operational_events = []
        operational_sink = SimpleNamespace(emit=operational_events.append)
        listener = SimpleNamespace(close=lambda: events.append("listener.close"))
        store = SimpleNamespace(close=lambda: events.append("store.close"))
        cgroup = SimpleNamespace(close=lambda: events.append("cgroup.close"))
        pins = SimpleNamespace(close=lambda: events.append("pins.close"))
        receipt_root = SimpleNamespace(
            close=lambda: events.append("receipt_root.close")
        )
        service = SimpleNamespace(
            reconcile_startup=lambda: events.append("service.reconcile"),
            serve=lambda received: events.append(
                "service.serve" if received is listener else "wrong.listener"
            ),
            close=lambda: events.append("service.close"),
        )
        settings = SimpleNamespace(
            mount_path=Path("/mnt/lto-archiver/tape"),
            tape_device_path=Path("/dev/tape/by-id/drive-tape-nst"),
            scsi_device_path=Path("/dev/lto-archiver-scsi-drive"),
        )
        executor = object()
        qualification_runtime = SimpleNamespace(
            close=lambda: events.append("qualification_runtime.close")
        )
        qualification_driver = object()
        qualification_executor = object()
        mount_probe = object()
        process_probe = object()

        with (
            patch.dict(os.environ, {"NOTIFY_SOCKET": str(notification_path)}),
            patch(
                "ltobackup.broker.main.pwd.getpwnam",
                return_value=SimpleNamespace(pw_gid=77, pw_uid=55),
            ),
            patch(
                "ltobackup.broker.main.grp.getgrnam",
                return_value=SimpleNamespace(gr_gid=77),
            ),
            patch(
                "ltobackup.broker.main._activated_socket_from_fd",
                return_value=listener,
            ),
            patch(
                "ltobackup.broker.main._read_credentials",
                return_value=(CAPABILITY, PROOF_KEY, QUALIFICATION_CREDENTIAL),
            ),
            patch(
                "ltobackup.broker.main._load_broker_settings",
                return_value=settings,
            ) as load_settings,
            patch(
                "ltobackup.broker.main._read_bounded",
                side_effect=(
                    BOOT_ID.encode("ascii"),
                    b"0::/broker\n",
                    b"1\n",
                ),
            ),
            patch(
                "ltobackup.broker.main._delegated_root_from_membership",
                return_value=Path("/sys/fs/cgroup/broker"),
            ),
            patch("ltobackup.broker.main.BrokerStateStore.open", return_value=store),
            patch("ltobackup.broker.main.CgroupV2BrokerRoot.open", return_value=cgroup),
            patch(
                "ltobackup.broker.main.LtfsSessionPins.open", return_value=pins
            ) as open_pins,
            patch(
                "ltobackup.broker.main.LtfsStandaloneReceiptRoot",
                create=True,
            ) as receipt_root_type,
            patch("ltobackup.broker.main.BrokerLtfsExecutor", return_value=executor),
            patch(
                "ltobackup.broker.main.SystemPhysicalLtfsQualificationRuntime",
                return_value=qualification_runtime,
            ) as runtime_type,
            patch(
                "ltobackup.broker.main.PhysicalLtfsQualificationDriver",
                return_value=qualification_driver,
            ) as driver_type,
            patch(
                "ltobackup.broker.main.BrokerQualificationExecutor",
                return_value=qualification_executor,
            ) as qualification_executor_type,
            patch("ltobackup.broker.main.ProcMountInfoProbe", return_value=mount_probe),
            patch("ltobackup.broker.main.ProcProcessProbe", return_value=process_probe),
            patch(
                "ltobackup.broker.main.CommandBrokerService", return_value=service
            ) as service_type,
            patch(
                "ltobackup.broker.main.JournalOperationalEventSink",
                return_value=operational_sink,
            ) as journal_sink_type,
        ):
            receipt_root_type.open.return_value = receipt_root
            self.assertEqual(broker_main([]), 0)
        self.assertEqual(b"READY=1", notification.recv(128))

        load_settings.assert_called_once_with(
            Path("/etc/lto-archiver/config.toml"), expected_gid=77
        )
        open_pins.assert_called_once_with(
            mount_path=settings.mount_path,
            tape_device_path=settings.tape_device_path,
            scsi_device_path=settings.scsi_device_path,
        )
        receipt_root_type.open.assert_called_once_with(
            Path("/var/lib/lto-archiver-broker/receipts")
        )
        self.assertIs(service_type.call_args.kwargs["ltfs_receipt_root"], receipt_root)
        self.assertIs(service_type.call_args.kwargs["ltfs_pins"], pins)
        self.assertIs(service_type.call_args.kwargs["ltfs_executor"], executor)
        runtime_type.assert_called_once_with(
            settings=settings,
            receipt_root=receipt_root,
            workspace_root=Path("/var/lib/lto-archiver-broker/qualification"),
        )
        driver_type.assert_called_once_with(runtime=qualification_runtime)
        qualification_executor_type.assert_called_once_with(
            qualification_driver,
            credential=QUALIFICATION_CREDENTIAL,
        )
        self.assertIs(
            service_type.call_args.kwargs["qualification_executor"],
            qualification_executor,
        )
        self.assertIs(
            service_type.call_args.kwargs["ltfs_mountinfo_probe"], mount_probe
        )
        self.assertIs(
            service_type.call_args.kwargs["ltfs_process_probe"], process_probe
        )
        journal_sink_type.assert_called_once_with(
            syslog_identifier="lto-archiver-command-broker"
        )
        self.assertIs(service_type.call_args.kwargs["event_sink"], operational_sink)
        self.assertEqual(
            ["command_broker.started", "command_broker.stopped"],
            [event.code for event in operational_events],
        )
        self.assertEqual(
            events,
            [
                "service.reconcile",
                "service.serve",
                "service.close",
                "qualification_runtime.close",
                "pins.close",
                "receipt_root.close",
                "cgroup.close",
                "store.close",
                "listener.close",
            ],
        )


class CommandBrokerDurableRaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "state.db"

        def as_root(status: os.stat_result) -> os.stat_result:
            fields = list(status)
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)

        with (
            patch("ltobackup.broker.store._effective_ids", return_value=(0, 0)),
            patch(
                "ltobackup.broker.store._fstat",
                side_effect=lambda fd: as_root(os.fstat(fd)),
            ),
            patch(
                "ltobackup.broker.store._stat_at",
                side_effect=lambda name, *, dir_fd: as_root(
                    os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                ),
            ),
        ):
            self.store = BrokerStateStore.open(
                self.path, boot_id=BOOT_ID, clock=lambda: NOW
            )
        self.addCleanup(self.store.close)
        self.cgroup = _StoreBackedCgroup()
        self.service = CommandBrokerService(
            self.store,
            self.cgroup,
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
        )
        self.counter = 10_000

    def packet(self, method: str, params: dict[str, object]) -> bytes:
        self.counter += 1
        return encode_request(
            method,
            request_id=self.counter.to_bytes(32, "big"),
            capability=CAPABILITY,
            params=params,
        )

    def request(self, method: str, params: dict[str, object], fds=()):
        return decode_response(_send(self.service, self.packet(method, params), fds))

    def test_close_empty_scope_revokes_permit_after_lost_prepare_response(self):
        # Preparation committed, its response was lost, then the blocked
        # child exited on gate EOF. The caller has only the scope receipt.
        created = self.request(
            "create_scope",
            {"command_id": "lost-prepare", "owner_generation": 175,
             "request_nonce": b"r" * 32},
        )
        self.assertIsNone(created.error_code)
        receipt = created.result["receipt"]
        self.assertIsNone(self.request(
            "attach", {"receipt": receipt, "pid": 4711},
        ).error_code)
        prepared = self.request(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )
        self.assertIsNone(prepared.error_code)
        digest = permit_sha256_from_mapping(prepared.result["permit"])
        self.cgroup.members.pop(receipt["scope_id"])

        closed = self.request("release_scope", {"receipt": receipt})

        self.assertIsNone(closed.error_code)
        self.assertEqual(self.store.scope_for_identity("lost-prepare", 175).state,
                         "CLOSED")
        self.assertEqual(self.store.permit_for_reconciliation(digest).state,
                         "REVOKED")

    def test_close_populated_scope_does_not_revoke_pending_permit(self):
        created = self.request(
            "create_scope",
            {"command_id": "still-blocked", "owner_generation": 175,
             "request_nonce": b"r" * 32},
        )
        self.assertIsNone(created.error_code)
        receipt = created.result["receipt"]
        self.assertIsNone(self.request(
            "attach", {"receipt": receipt, "pid": 4711},
        ).error_code)
        prepared = self.request(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )
        self.assertIsNone(prepared.error_code)
        digest = permit_sha256_from_mapping(prepared.result["permit"])

        closed = self.request("release_scope", {"receipt": receipt})

        self.assertIsNotNone(closed.error_code)
        self.assertEqual(self.store.scope_for_identity("still-blocked", 175).state,
                         "ACTIVE")
        self.assertEqual(self.store.permit_for_reconciliation(digest).state,
                         "PREPARED")

    def _prepare_closure_scope(self, name="closure"):
        created = self.request(
            "create_scope",
            {"command_id": name, "owner_generation": 175,
             "request_nonce": b"r" * 32},
        )
        self.assertIsNone(created.error_code)
        receipt = created.result["receipt"]
        self.assertIsNone(self.request(
            "attach", {"receipt": receipt, "pid": 4711},
        ).error_code)
        prepared = self.request(
            "prepare_release",
            {"receipt": receipt, "pid": 4711, "request_nonce": b"p" * 32},
        )
        self.assertIsNone(prepared.error_code)
        return receipt, prepared.result["permit"]

    def test_failed_permit_revocation_retains_physical_scope(self):
        receipt, permit = self._prepare_closure_scope()
        self.cgroup.members.pop(receipt["scope_id"])
        # Fail the actual SQLite durable transition, not the method under test.
        self.store._connection.execute(
            "CREATE TEMP TRIGGER fail_revoke BEFORE UPDATE ON permits "
            "BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END"
        )
        closed = self.request("release_scope", {"receipt": receipt})
        self.assertIsNotNone(closed.error_code)
        self.assertNotIn(receipt["scope_id"], self.cgroup.released)
        # Durable failures close the store. Inspect only this private test DB.
        import sqlite3
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute(
                "SELECT state FROM scopes WHERE scope_id=?", (receipt["scope_id"],),
            ).fetchone()[0], "ACTIVE")
            self.assertEqual(db.execute(
                "SELECT state FROM permits WHERE permit_sha256=?",
                (permit_sha256_from_mapping(permit),),
            ).fetchone()[0], "PREPARED")

    def test_retry_closed_scope_uses_existing_release_proof(self):
        receipt, _permit = self._prepare_closure_scope()
        self.cgroup.members.pop(receipt["scope_id"])
        self.assertIsNone(self.request("release_scope", {"receipt": receipt}).error_code)
        retried = self.request("release_scope", {"receipt": receipt})
        self.assertIsNone(retried.error_code)
        self.assertEqual(self.store.scope_for_identity("closure", 175).state, "CLOSED")

    def test_failed_cgroup_removal_keeps_durable_revocation_without_false_closure(self):
        from ltobackup.broker.cgroup import CgroupConflict

        receipt, permit = self._prepare_closure_scope()
        self.cgroup.members.pop(receipt["scope_id"])
        with patch.object(self.cgroup, "release", side_effect=CgroupConflict):
            closed = self.request("release_scope", {"receipt": receipt})
        self.assertIsNotNone(closed.error_code)
        self.assertEqual(self.store.scope_for_identity("closure", 175).state, "ACTIVE")
        self.assertEqual(self.store.permit_for_reconciliation(
            permit_sha256_from_mapping(permit),
        ).state, "REVOKED")
        self.assertNotIn(receipt["scope_id"], self.cgroup.released)
        retried = self.request("release_scope", {"receipt": receipt})
        self.assertIsNone(retried.error_code)
        self.assertEqual(self.store.scope_for_identity("closure", 175).state, "CLOSED")

    def test_empty_scope_closure_preserves_committed_release(self):
        receipt, permit = self._prepare_closure_scope()
        read_fd, write_fd = os.pipe()
        try:
            released = self.request(
                "release_child", {"receipt": receipt, "permit": permit, "pid": 4711},
                (write_fd,),
            )
            self.assertIsNone(released.error_code)
            self.assertEqual(os.read(read_fd, 1), b"1")
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.cgroup.members.pop(receipt["scope_id"])
        self.assertIsNone(self.request("release_scope", {"receipt": receipt}).error_code)
        self.assertEqual(self.store.permit_for_reconciliation(
            permit_sha256_from_mapping(permit),
        ).state, "RELEASE_COMMITTED")

    def test_close_excludes_delayed_prepare_attach_and_gate_release(self):
        receipt, permit = self._prepare_closure_scope()
        self.cgroup.members.pop(receipt["scope_id"])
        removal_entered = threading.Event()
        allow_removal = threading.Event()
        results = {}
        original_release = self.cgroup.release

        def blocked_removal(record):
            removal_entered.set()
            if not allow_removal.wait(5):
                raise AssertionError("test did not release removal barrier")
            original_release(record)

        def request_in_thread(key, method, params, fds=()):
            results[key] = self.request(method, params, fds)

        read_fd, write_fd = os.pipe2(os.O_NONBLOCK)
        threads = []
        try:
            with patch.object(self.cgroup, "release", side_effect=blocked_removal):
                closer = threading.Thread(target=request_in_thread, args=(
                    "close", "release_scope", {"receipt": receipt},
                ))
                threads.append(closer)
                closer.start()
                self.assertTrue(removal_entered.wait(5))
                calls = (
                    ("prepare", "prepare_release",
                     {"receipt": receipt, "pid": 4711, "request_nonce": b"x" * 32}, ()),
                    ("attach", "attach", {"receipt": receipt, "pid": 4711}, ()),
                    ("release", "release_child",
                     {"receipt": receipt, "permit": permit, "pid": 4711}, (write_fd,)),
                )
                reached_dispatch = {key: threading.Event() for key, *_ in calls}
                dispatch = self.service._dispatch

                def observed_dispatch(request, descriptors):
                    for key, method, *_ in calls:
                        if request.method == method:
                            reached_dispatch[key].set()
                    return dispatch(request, descriptors)

                with patch.object(self.service, "_dispatch", side_effect=observed_dispatch):
                    for args in calls:
                        worker = threading.Thread(target=request_in_thread, args=args)
                        threads.append(worker)
                        worker.start()
                    for event in reached_dispatch.values():
                        self.assertTrue(event.wait(5))
                    allow_removal.set()
                    for worker in threads:
                        worker.join(5)
                        self.assertFalse(worker.is_alive())
            self.assertIsNone(results["close"].error_code)
            for key, *_ in calls:
                self.assertIsNotNone(results[key].error_code, key)
            with self.assertRaises(BlockingIOError):
                os.read(read_fd, 1)
            self.assertEqual(self.store.scope_for_identity("closure", 175).state, "CLOSED")
            self.assertEqual(self.store.permit_for_reconciliation(
                permit_sha256_from_mapping(permit),
            ).state, "REVOKED")
        finally:
            allow_removal.set()
            for worker in threads:
                worker.join(5)
            os.close(read_fd)
            os.close(write_fd)

    def test_open_scope_uses_exact_durable_identity_without_reconciliation_scan(self):
        created = self.request(
            "create_scope",
            {"command_id": "current-command", "owner_generation": 9,
             "request_nonce": b"r" * 32},
        )
        self.assertIsNone(created.error_code)
        receipt = BrokeredCgroupScopeReceipt(**created.result["receipt"])
        self.store._connection.execute(
            "INSERT INTO scopes SELECT 'old-scope','old-command',1,"
            "scope_path_sha256,boot_id,'CLOSED',NULL,NULL,'malformed' "
            "FROM scopes WHERE scope_id=?",
            (receipt.scope_id,),
        )
        for nonce, block_scan in ((b"s" * 32, False), (b"t" * 32, True)):
            with self.subTest(block_scan=block_scan):
                if block_scan:
                    with patch.object(
                        self.store, "scopes_for_reconciliation",
                        side_effect=AssertionError("open_scope scanned history"),
                    ):
                        opened = self.request(
                            "open_scope",
                            {"command_id": "current-command", "owner_generation": 9,
                             "request_nonce": nonce},
                        )
                else:
                    opened = self.request(
                        "open_scope",
                        {"command_id": "current-command", "owner_generation": 9,
                         "request_nonce": nonce},
                    )
                self.assertIsNone(opened.error_code)
                self.assertEqual(receipt.scope_id, opened.result["receipt"]["scope_id"])
                self.assertEqual(nonce, opened.result["receipt"]["request_nonce"])

    def test_release_and_claim_service_race_has_one_durable_meaning_and_at_most_one_byte(
        self,
    ):
        for iteration in range(100):
            created = self.request(
                "create_scope",
                {
                    "command_id": f"race-{iteration}",
                    "owner_generation": iteration,
                    "request_nonce": (iteration + 1).to_bytes(32, "big"),
                },
            )
            receipt = created.result["receipt"]
            pid = 20_000 + iteration
            self.assertIsNone(
                self.request("attach", {"receipt": receipt, "pid": pid}).error_code
            )
            prepared = self.request(
                "prepare_release",
                {
                    "receipt": receipt,
                    "pid": pid,
                    "request_nonce": (1_000 + iteration).to_bytes(32, "big"),
                },
            )
            permit = prepared.result["permit"]
            digest = permit_sha256_from_mapping(permit)
            read_fd, write_fd = os.pipe()
            release_client, release_server = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            claim_client, claim_server = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_SEQPACKET
            )
            try:
                rights = array.array("i", [write_fd])
                release_client.sendmsg(
                    [
                        self.packet(
                            "release_child",
                            {"receipt": receipt, "permit": permit, "pid": pid},
                        )
                    ],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)],
                )
                claim_client.send(
                    self.packet(
                        "claim_unreleased",
                        {
                            "receipt": receipt,
                            "pid": pid,
                            "permit_sha256": digest,
                            "challenge": (2_000 + iteration).to_bytes(32, "big"),
                        },
                    )
                )
                release_thread = threading.Thread(
                    target=self.service.handle_connection, args=(release_server,)
                )
                claim_thread = threading.Thread(
                    target=self.service.handle_connection, args=(claim_server,)
                )
                release_thread.start()
                claim_thread.start()
                release_thread.join(2)
                claim_thread.join(2)
                self.assertFalse(release_thread.is_alive())
                self.assertFalse(claim_thread.is_alive())
                release = decode_response(release_client.recv(65_537))
                claim = decode_response(claim_client.recv(65_537))
                self.assertIsNone(claim.error_code)
                released = claim.result["claim"]["released"]
                self.assertEqual(release.error_code is None, released)
                os.set_blocking(read_fd, False)
                if released:
                    self.assertEqual(os.read(read_fd, 2), b"1")
                else:
                    with self.assertRaises(BlockingIOError):
                        os.read(read_fd, 1)
            finally:
                for descriptor in (read_fd, write_fd):
                    os.close(descriptor)
                release_client.close()
                claim_client.close()


class _Task4Lease:
    def __init__(self, pins, request, tape_fd: int, scsi_fd: int) -> None:
        self.request = request
        self.mount_path = pins.mount_path
        self._ltfs_fd = os.dup(pins.tool_fd)
        self._fusermount_fd = os.dup(pins.tool_fd)
        self.tape_fd = os.dup(tape_fd)
        self.scsi_fd = os.dup(scsi_fd)
        self.closed = False
        self.launch_anchor_calls = 0
        self.finalization_anchor_calls = 0

    def _open(self) -> None:
        if self.closed:
            raise RuntimeError("closed")

    @property
    def ltfs_fd(self) -> int:
        self._open()
        return self._ltfs_fd

    @property
    def fusermount_fd(self) -> int:
        self._open()
        return self._fusermount_fd

    @property
    def ltfs_exec_path(self) -> Path:
        return Path(f"/proc/self/fd/{self.ltfs_fd}")

    @property
    def fusermount_exec_path(self) -> Path:
        return Path(f"/proc/self/fd/{self.fusermount_fd}")

    def assert_launch_anchors(self) -> None:
        self._open()
        self.launch_anchor_calls += 1
        for fd in (
            self._ltfs_fd,
            self._fusermount_fd,
            self.tape_fd,
            self.scsi_fd,
        ):
            os.fstat(fd)

    def assert_finalization_anchors(self) -> None:
        self._open()
        self.finalization_anchor_calls += 1
        for fd in (
            self._ltfs_fd,
            self._fusermount_fd,
            self.tape_fd,
            self.scsi_fd,
        ):
            os.fstat(fd)

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        for fd in (
            self._ltfs_fd,
            self._fusermount_fd,
            self.tape_fd,
            self.scsi_fd,
        ):
            os.close(fd)


class _Task4Pins:
    ltfs_tool_identity_sha256 = "8" * 64
    fusermount_tool_identity_sha256 = "9" * 64

    def __init__(self, root: Path) -> None:
        self.mount_path = root / "mount"
        self.mount_path.mkdir()
        self.tool_fd = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
        self.leases: list[_Task4Lease] = []

    def close(self) -> None:
        os.close(self.tool_fd)

    def assert_readiness_anchors(self) -> None:
        os.fstat(self.tool_fd)

    def validate_request(self, request, *, tape_fd: int, scsi_fd: int):
        if (
            request.mount_path_sha256 != "1" * 64
            or request.tape_device_identity_sha256 != "2" * 64
            or request.scsi_device_identity_sha256 != "3" * 64
        ):
            raise RuntimeError("target mismatch")
        lease = _Task4Lease(self, request, tape_fd, scsi_fd)
        self.leases.append(lease)
        return lease


class _Task4Executor:
    def __init__(self, cgroup: _StoreBackedCgroup) -> None:
        self.cgroup = cgroup
        self.pid = 24_017
        self.alive = False
        self.mounted = False
        self.leave_mounted = False
        self.calls: list[tuple[object, ...]] = []

    def spawn_blocked(self, argv, *, pass_fds):
        self.calls.append(("spawn", tuple(argv), tuple(pass_fds)))
        self.alive = True
        return SimpleNamespace(pid=self.pid)

    def release_launch(self, launch) -> None:
        if launch.pid not in self.cgroup.members.values():
            raise RuntimeError("released before cgroup attach")
        self.calls.append(("release", launch.pid))
        self.mounted = True

    def run_fusermount(self, argv, *, pass_fds) -> int:
        self.calls.append(("unmount", tuple(argv), tuple(pass_fds)))
        if not self.leave_mounted:
            self.mounted = False
        return 0

    def terminate_reap(
        self, launch, *, pid: int, start_ticks: int, timeout: float | None = None
    ) -> bool:
        del timeout
        self.calls.append(("reap", launch.pid, pid, start_ticks))
        self.alive = False
        for scope_id, member in tuple(self.cgroup.members.items()):
            if member == pid:
                self.cgroup.members.pop(scope_id)
        return True

    reap_natural = terminate_reap


class _Task4ReceiptRoot:
    def __init__(self) -> None:
        self.operation_id = ""

    def target_path(self, *, operation_id, owner_generation, request_sha256):
        del owner_generation, request_sha256
        self.operation_id = operation_id
        return Path("/var/lib/lto-archiver-broker/receipts/test.json")

    def wait_ready(
        self,
        *,
        operation_id,
        owner_generation,
        request_sha256,
        expected_media_identity_sha256,
        expected_read_only,
        timeout,
    ):
        del (
            owner_generation,
            request_sha256,
            expected_media_identity_sha256,
            timeout,
        )
        return LtfsReadyReceipt(
            1,
            "ready",
            operation_id,
            "22222222-2222-4222-8222-222222222222",
            7,
            expected_read_only,
            "stable-drive",
            "TAPE04",
            "serial",
            "TAPE04",
        )

    def read_terminal(self, *, operation_id, owner_generation, request_sha256):
        del owner_generation, request_sha256
        fields = {
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
        digest = hashlib.sha256(
            (json.dumps(fields, separators=(",", ":")) + "\n").encode("ascii")
        ).hexdigest()
        return LtfsStandaloneReceipt(
            **{**fields, "phase_duration_ns": tuple(fields["phase_duration_ns"])},
            terminal_sha256=digest,
        )


class _Task4ProcessProbe:
    def __init__(self, executor: _Task4Executor) -> None:
        self.executor = executor

    def observe(self, pid: int):
        if not self.executor.alive or pid != self.executor.pid:
            return None
        return SimpleNamespace(
            pid=pid, start_ticks=123, mount_namespace_sha256="d" * 64
        )


class _Task4MountProbe:
    def __init__(self, executor: _Task4Executor, mount_path: Path) -> None:
        self.executor = executor
        self.mount_path = mount_path
        self.wrong = False

    def await_mounted(self, path: Path):
        if path != self.mount_path or not self.executor.mounted:
            raise RuntimeError("mount absent")
        return SimpleNamespace(
            target=path,
            fs_type="ext4" if self.wrong else "fuse.ltfs",
            source="ltfs",
        )

    def await_unmounted(self, path: Path) -> bool:
        return path == self.mount_path and not self.executor.mounted


class BrokerLtfsExecutorTests(unittest.TestCase):
    def test_mount_probe_default_covers_the_physical_ltfs_lifecycle(self) -> None:
        probe = ProcMountInfoProbe()
        self.assertEqual(probe._timeout, 1_800.0)
        with self.assertRaises(LtfsLifecycleUnavailable):
            ProcMountInfoProbe(timeout=86_401.0)

    def test_mount_and_process_probes_require_exact_kernel_observations(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            mountinfo = Path(temporary) / "mountinfo"
            mountinfo.write_text(
                "36 25 0:32 / /mnt/lto rw - fuse.ltfs ltfs rw\n",
                encoding="utf-8",
            )
            probe = ProcMountInfoProbe(mountinfo, timeout=0.01, interval=0.001)
            mounted = probe.await_mounted(Path("/mnt/lto"))
            self.assertEqual((mounted.fs_type, mounted.source), ("fuse.ltfs", "ltfs"))
            mountinfo.write_text(
                "37 25 0:33 / /other rw - ext4 /dev/root rw\n",
                encoding="utf-8",
            )
            self.assertTrue(probe.await_unmounted(Path("/mnt/lto")))

        process = ProcProcessProbe.observe(os.getpid())
        self.assertEqual(process.pid, os.getpid())
        self.assertGreater(process.start_ticks, 0)
        self.assertEqual(len(process.mount_namespace_sha256), 64)

    def test_executor_rejects_unanchored_argv_before_fork(self) -> None:
        fd = os.open("/usr/bin/true", os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        executor = BrokerLtfsExecutor()
        with (
            patch("ltobackup.broker.ltfs_session.os.fork") as fork,
            self.assertRaises(LtfsLifecycleUnavailable),
        ):
            executor.spawn_blocked(("/usr/bin/true",), pass_fds=(fd,))
        fork.assert_not_called()

    def test_executor_blocks_then_reaps_one_fd_anchored_child(self) -> None:
        fd = os.open("/usr/bin/true", os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        executor = BrokerLtfsExecutor()
        argv = (f"/proc/self/fd/{fd}",)
        self.assertEqual(executor.run_fusermount(argv, pass_fds=(fd,)), 0)
        launch = executor.spawn_blocked(argv, pass_fds=(fd,))
        process = ProcProcessProbe.observe(launch.pid)
        self.assertIsNotNone(process)
        executor.release_launch(launch)
        self.assertTrue(
            executor.terminate_reap(
                launch, pid=launch.pid, start_ticks=process.start_ticks
            )
        )

    def test_executor_rejects_nonzero_ltfs_child_exit(self) -> None:
        fd = os.open("/usr/bin/sh", os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, fd)
        executor = BrokerLtfsExecutor()
        launch = executor.spawn_blocked(
            (f"/proc/self/fd/{fd}", "-c", "exit 17"), pass_fds=(fd,)
        )
        process = ProcProcessProbe.observe(launch.pid)
        self.assertIsNotNone(process)
        executor.release_launch(launch)
        with self.assertRaises(LtfsLifecycleUnavailable):
            executor.terminate_reap(
                launch, pid=launch.pid, start_ticks=process.start_ticks
            )


class BrokerLtfsLifecycleServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)

        def as_root(status: os.stat_result) -> os.stat_result:
            fields = list(status)
            fields[4] = 0
            fields[5] = 0
            return os.stat_result(fields)

        with (
            patch("ltobackup.broker.store._effective_ids", return_value=(0, 0)),
            patch(
                "ltobackup.broker.store._fstat",
                side_effect=lambda fd: as_root(os.fstat(fd)),
            ),
            patch(
                "ltobackup.broker.store._stat_at",
                side_effect=lambda name, *, dir_fd: as_root(
                    os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
                ),
            ),
        ):
            self.store = BrokerStateStore.open(
                root / "state.db", boot_id=BOOT_ID, clock=lambda: NOW
            )
        self.addCleanup(self.store.close)
        self.cgroup = _StoreBackedCgroup()
        self.pins = _Task4Pins(root)
        self.addCleanup(self.pins.close)
        self.executor = _Task4Executor(self.cgroup)
        self.process_probe = _Task4ProcessProbe(self.executor)
        self.mount_probe = _Task4MountProbe(self.executor, self.pins.mount_path)
        self.receipt_root = _Task4ReceiptRoot()
        self.operational_events = []
        self.identity_patch = patch(
            "ltobackup.broker.service.device_fd_identity_sha256",
            side_effect=lambda _fd, role: "6" * 64 if role == "tape" else "7" * 64,
        )
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)
        self.service = self._service()
        self.service.reconcile_startup()
        self.counter = 30_000
        self.tape_fd = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
        self.scsi_fd = os.open(__file__, os.O_RDONLY | os.O_CLOEXEC)
        self.addCleanup(os.close, self.scsi_fd)
        self.addCleanup(os.close, self.tape_fd)

    def _service(self) -> CommandBrokerService:
        return CommandBrokerService(
            self.store,
            self.cgroup,
            capability=CAPABILITY,
            proof_key=PROOF_KEY,
            daemon_uid=os.getuid(),
            daemon_gid=os.getgid(),
            enforcing=False,
            daemon_context="system_u:system_r:lto_archiver_t:s0",
            ltfs_pins=self.pins,
            ltfs_receipt_root=self.receipt_root,
            ltfs_executor=self.executor,
            ltfs_mountinfo_probe=self.mount_probe,
            ltfs_process_probe=self.process_probe,
            event_sink=SimpleNamespace(emit=self.operational_events.append),
        )

    def _packet(self, method: str, params: dict[str, object]) -> bytes:
        self.counter += 1
        return encode_request(
            method,
            request_id=self.counter.to_bytes(32, "big"),
            capability=CAPABILITY,
            params=params,
        )

    def _scope(self, generation: int = 17) -> BrokeredCgroupScopeReceipt:
        response = decode_response(
            _send(
                self.service,
                self._packet(
                    "create_scope",
                    {
                        "command_id": f"command-{generation}",
                        "owner_generation": generation,
                        "request_nonce": generation.to_bytes(32, "big"),
                    },
                ),
            )
        )
        return BrokeredCgroupScopeReceipt(**response.result["receipt"])

    @staticmethod
    def _request(scope: BrokeredCgroupScopeReceipt) -> LtfsSessionRequest:
        return LtfsSessionRequest(
            1,
            f"operation-{scope.owner_generation}",
            scope.owner_generation,
            "1" * 64,
            "2" * 64,
            "3" * 64,
            "4" * 64,
            "5" * 64,
            "22222222-2222-4222-8222-222222222222",
            7,
            False,
            "6" * 64,
            "7" * 64,
            scope,
            (b"lifecycle" + scope.owner_generation.to_bytes(8, "big")).ljust(32, b"x"),
        )

    def _start(self, request: LtfsSessionRequest, fds: tuple[int, ...] | None = None):
        authority = LtfsProtocolAuthority(
            request.operation_id,
            request.owner_generation,
            request.cgroup_scope_receipt,
            request.tape_fd_identity_sha256,
            request.scsi_fd_identity_sha256,
        )
        packet = self._packet("start_ltfs_session", {"request": request})
        decoded = decode_request(
            packet,
            ltfs_authority=authority,
            ancillary_fd_identities=("6" * 64, "7" * 64),
        )
        response = decode_response(
            _send(
                self.service,
                packet,
                (self.tape_fd, self.scsi_fd) if fds is None else fds,
            ),
            request=decoded,
            ltfs_authority=authority,
        )
        return authority, response

    def test_exact_start_observe_finalize_lifecycle_is_proof_bound(self) -> None:
        request = self._request(self._scope())
        authority, started = self._start(request)
        self.assertIsNone(started.error_code)
        receipt = started.result["receipt"]
        lease = self.pins.leases[0]
        spawn = self.executor.calls[0]
        self.assertEqual(spawn[0], "spawn")
        event_fd = spawn[2][2]
        self.assertEqual(
            spawn[1],
            (
                str(lease.ltfs_exec_path),
                "-f",
                f"--event-fd={event_fd}",
                "--event-schema=1",
                f"--operation-id={receipt.receipt_operation_uuid}",
                "-o",
                f"devname=/proc/self/fd/{lease.scsi_fd}",
                "-o",
                "subtype=ltfs",
                "-o",
                "fsname=ltfs",
                "-o",
                "allow_other",
                "-o",
                "default_permissions",
                "-o",
                f"uid={self.service.daemon_uid}",
                "-o",
                f"gid={self.service.daemon_gid}",
                "-o",
                "umask=027",
                "-o",
                "sync_type=unmount",
                "-o",
                "standalone_receipt=/var/lib/lto-archiver-broker/receipts/test.json",
                str(self.pins.mount_path),
            ),
        )
        self.assertEqual(spawn[2][:2], (lease.ltfs_fd, lease.scsi_fd))
        self.assertGreaterEqual(event_fd, 3)
        self.assertEqual(len(set(spawn[2])), 3)
        self.assertEqual(self.executor.calls[1], ("release", self.executor.pid))
        self.assertEqual(
            self.store.ltfs_session(request.operation_id, 17).state, "MOUNTED"
        )
        self.assertEqual(self.cgroup.attach_uids, [0])

        observe_packet = self._packet(
            "observe_ltfs_session",
            {
                "operation_id": request.operation_id,
                "owner_generation": 17,
                "receipt": receipt,
                "challenge": b"h" * 32,
            },
        )
        observe_request = decode_request(observe_packet, ltfs_authority=authority)
        observed = decode_response(
            _send(self.service, observe_packet),
            request=observe_request,
            ltfs_authority=authority,
        )
        self.assertIsNone(observed.error_code)
        self.assertTrue(observed.result["mounted"])

        fusermount_path = str(lease.fusermount_exec_path)
        fusermount_fd = lease.fusermount_fd
        finalize_packet = self._packet(
            "finalize_ltfs_session",
            {
                "operation_id": request.operation_id,
                "owner_generation": 17,
                "receipt": receipt,
                "request_nonce": b"f" * 32,
            },
        )
        finalize_request = decode_request(finalize_packet, ltfs_authority=authority)
        finalized = decode_response(
            _send(self.service, finalize_packet),
            request=finalize_request,
            ltfs_authority=authority,
        )
        self.assertIsNone(finalized.error_code)
        self.assertTrue(finalized.result["receipt"].unmounted)
        self.assertEqual(
            self.executor.calls[2],
            (
                "unmount",
                (
                    fusermount_path,
                    "-u",
                    "--",
                    str(self.pins.mount_path),
                ),
                (fusermount_fd,),
            ),
        )
        self.assertEqual(self.executor.calls[3][0], "reap")
        self.assertEqual(lease.launch_anchor_calls, 2)
        self.assertEqual(lease.finalization_anchor_calls, 1)
        self.assertTrue(lease.closed)
        self.assertEqual(
            self.store.ltfs_session(request.operation_id, 17).state, "UNMOUNTED"
        )
        self.assertEqual(
            [
                ("mount", "ltfs.phase.started"),
                ("mount", "ltfs.phase.succeeded"),
                ("finalizing_index", "ltfs.phase.started"),
                ("unmount", "ltfs.phase.started"),
                ("finalizing_index", "ltfs.phase.succeeded"),
                ("unmount", "ltfs.phase.succeeded"),
            ],
            [(event.phase, event.code) for event in self.operational_events],
        )

    def test_read_only_start_uses_distinct_daemon_identity_and_closed_options(self) -> None:
        self.service.daemon_uid = 12_345
        self.service.daemon_gid = 23_456
        with patch(
            "ltobackup.broker.service._peer_identity",
            return_value=(
                12_345,
                23_456,
                "system_u:system_r:lto_archiver_t:s0",
            ),
        ):
            request = dataclasses.replace(
                self._request(self._scope()),
                read_only=True,
            )

            _authority, started = self._start(request)

        self.assertIsNone(started.error_code)
        argv = self.executor.calls[0][1]
        options = tuple(
            argv[index + 1]
            for index, value in enumerate(argv[:-1])
            if value == "-o"
        )
        for exact in (
            "allow_other",
            "default_permissions",
            "uid=12345",
            "gid=23456",
            "umask=027",
            "ro",
        ):
            with self.subTest(option=exact):
                self.assertEqual(1, options.count(exact))
        self.assertNotIn("sync_type=unmount", options)
        self.assertEqual(self.cgroup.attach_uids, [0])

    def test_restart_finalizing_live_child_is_fenced_without_any_signal(self) -> None:
        request = self._request(self._scope())
        _authority, started = self._start(request)
        self.assertIsNone(started.error_code)
        receipt = started.result["receipt"]
        self.store.begin_ltfs_finalization(receipt, b"f" * 32)
        scope_id = request.cgroup_scope_receipt.scope_id
        self.assertEqual(self.executor.pid, self.cgroup.members[scope_id])

        restarted = self._service()
        with patch.object(restarted, "_start_finalizing_monitor") as monitor:
            restarted.reconcile_startup()

        monitor.assert_called_once()
        self.assertEqual(self.executor.pid, self.cgroup.members[scope_id])
        self.assertTrue(self.executor.alive)
        self.assertFalse(restarted._reconciliation_clean)

    def test_restart_cannot_complete_terminal_without_durable_exit_zero(self) -> None:
        request = self._request(self._scope())
        _authority, started = self._start(request)
        receipt = started.result["receipt"]
        self.store.begin_ltfs_finalization(receipt, b"f" * 32)
        self.executor.alive = False
        self.executor.mounted = False
        self.cgroup.members.pop(request.cgroup_scope_receipt.scope_id)

        restarted = self._service()
        with self.assertRaises(BrokerStateUnavailable):
            restarted.reconcile_startup()

        self.assertEqual(
            "BROKEN",
            self.store.ltfs_session(
                request.operation_id, request.owner_generation
            ).state,
        )
        self.assertEqual(0, self.cgroup.kill_count)

    def test_restart_completes_only_after_durable_exit_zero_and_terminal(self) -> None:
        request = self._request(self._scope())
        _authority, started = self._start(request)
        receipt = started.result["receipt"]
        self.store.begin_ltfs_finalization(receipt, b"f" * 32)
        self.store.bind_ltfs_child_exit_zero(receipt)
        self.executor.alive = False
        self.executor.mounted = False
        self.cgroup.members.pop(request.cgroup_scope_receipt.scope_id)

        restarted = self._service()
        restarted.reconcile_startup()

        terminal = self.store.ltfs_session(
            request.operation_id, request.owner_generation
        )
        self.assertEqual("UNMOUNTED", terminal.state)
        self.assertTrue(
            self.store.has_ltfs_child_exit_zero(
                request.operation_id, request.owner_generation
            )
        )
        self.assertEqual(0, self.cgroup.kill_count)

    def test_terminal_receipt_is_recoverable_after_response_and_broker_loss(
        self,
    ) -> None:
        request = self._request(self._scope())
        authority, started = self._start(request)
        receipt = started.result["receipt"]
        finalize_packet = self._packet(
            "finalize_ltfs_session",
            {
                "operation_id": request.operation_id,
                "owner_generation": request.owner_generation,
                "receipt": receipt,
                "request_nonce": b"f" * 32,
            },
        )
        finalize_request = decode_request(finalize_packet, ltfs_authority=authority)
        finalized = decode_response(
            _send(self.service, finalize_packet),
            request=finalize_request,
            ltfs_authority=authority,
        )
        terminal = finalized.result["receipt"]
        stored = self.store.ltfs_session(request.operation_id, request.owner_generation)
        self.assertEqual("UNMOUNTED", stored.state)
        self.assertEqual(request.mount_path_sha256, stored.mount_path_sha256)
        self.assertEqual(
            request.tape_device_identity_sha256,
            stored.tape_device_identity_sha256,
        )
        self.assertEqual(
            request.scsi_device_identity_sha256,
            stored.scsi_device_identity_sha256,
        )
        self.assertEqual(
            request.expected_media_scope_sha256,
            stored.expected_media_scope_sha256,
        )
        self.assertEqual(
            request.observed_media_identity_sha256,
            stored.observed_media_identity_sha256,
        )

        restarted = self._service()
        self.assertEqual(
            terminal.session_receipt,
            restarted._ltfs_receipt_from_record(stored),
        )
        from ltobackup.broker.protocol import _transform_ltfs_standalone_receipt

        self.assertEqual(
            terminal.standalone_receipt,
            _transform_ltfs_standalone_receipt(
                json.loads(stored.standalone_receipt_json), encode=False
            ),
        )
        self.assertEqual(
            terminal,
            LtfsFinalizationReceipt(
                1,
                restarted._ltfs_receipt_from_record(stored),
                terminal.standalone_receipt,
                stored.finalization_request_nonce,
                stored.finalization_nonce,
                stored.finalization_broker_proof,
                True,
                True,
            ),
        )
        recovery_params = {
            "operation_id": request.operation_id,
            "owner_generation": request.owner_generation,
            "mount_path_sha256": request.mount_path_sha256,
            "tape_device_identity_sha256": request.tape_device_identity_sha256,
            "scsi_device_identity_sha256": request.scsi_device_identity_sha256,
            "expected_media_scope_sha256": request.expected_media_scope_sha256,
            "observed_media_identity_sha256": (request.observed_media_identity_sha256),
            "request_nonce": b"r" * 32,
        }
        self.assertEqual(
            {"receipt": terminal},
            restarted._recover_ltfs_finalization(recovery_params),
        )
        recovered = decode_response(
            _send(
                restarted,
                self._packet(
                    "recover_ltfs_finalization",
                    recovery_params,
                ),
            )
        )
        self.assertIsNone(recovered.error_code)
        self.assertEqual(terminal, recovered.result["receipt"])

        substituted = decode_response(
            _send(
                restarted,
                self._packet(
                    "recover_ltfs_finalization",
                    {
                        "operation_id": request.operation_id,
                        "owner_generation": request.owner_generation,
                        "mount_path_sha256": request.mount_path_sha256,
                        "tape_device_identity_sha256": (
                            request.tape_device_identity_sha256
                        ),
                        "scsi_device_identity_sha256": (
                            request.scsi_device_identity_sha256
                        ),
                        "expected_media_scope_sha256": (
                            request.expected_media_scope_sha256
                        ),
                        "observed_media_identity_sha256": "8" * 64,
                        "request_nonce": b"s" * 32,
                    },
                ),
            )
        )
        self.assertEqual("scope.conflict", substituted.error_code)

    def test_ancillary_count_and_second_lifecycle_fail_before_exec(self) -> None:
        first = self._request(self._scope())
        first_authority, first_started = self._start(first)
        self.assertIsNone(first_started.error_code)
        same_scope_conflict = dataclasses.replace(
            first,
            request_nonce=b"different-lifecycle-request".ljust(32, b"x"),
        )
        self.assertEqual(
            self._start(same_scope_conflict)[1].error_code, "scope.conflict"
        )
        first_scope = next(
            record
            for record in self.store.scopes_for_reconciliation()
            if record.scope_id == first.cgroup_scope_receipt.scope_id
        )
        self.assertEqual("ACTIVE", first_scope.state)
        self.assertTrue(self.cgroup.members[first_scope.scope_id])
        second = self._request(self._scope(18))
        self.assertEqual(self._start(second)[1].error_code, "scope.conflict")
        self.assertEqual(sum(call[0] == "spawn" for call in self.executor.calls), 1)
        second_scope = next(
            record
            for record in self.store.scopes_for_reconciliation()
            if record.command_id == "command-18"
        )
        self.assertEqual("CLOSED", second_scope.state)
        self.assertNotIn(second_scope.scope_id, self.cgroup.members)

        authority = LtfsProtocolAuthority(
            second.operation_id,
            second.owner_generation,
            second.cgroup_scope_receipt,
            second.tape_fd_identity_sha256,
            second.scsi_fd_identity_sha256,
        )
        packet = self._packet("start_ltfs_session", {"request": second})
        decoded = decode_request(
            packet,
            ltfs_authority=authority,
            ancillary_fd_identities=("6" * 64, "7" * 64),
        )
        response = decode_response(
            _send(self.service, packet, (self.tape_fd,)),
            request=decoded,
            ltfs_authority=authority,
        )
        self.assertEqual(response.error_code, "protocol.invalid")

        finalize_packet = self._packet(
            "finalize_ltfs_session",
            {
                "operation_id": first.operation_id,
                "owner_generation": first.owner_generation,
                "receipt": first_started.result["receipt"],
                "request_nonce": b"f" * 32,
            },
        )
        finalize_request = decode_request(
            finalize_packet, ltfs_authority=first_authority
        )
        finalized = decode_response(
            _send(self.service, finalize_packet),
            request=finalize_request,
            ltfs_authority=first_authority,
        )
        self.assertIsNone(finalized.error_code)

        retry = decode_response(
            _send(
                self.service,
                self._packet(
                    "create_scope",
                    {
                        "command_id": "command-18",
                        "owner_generation": 18,
                        "request_nonce": b"r" * 32,
                    },
                ),
            )
        )
        self.assertEqual("scope.conflict", retry.error_code)
        restarted = self._service()
        restarted.reconcile_startup()

    def test_ambiguous_unmount_stays_fenced_without_killing_finalizer(self) -> None:
        request = self._request(self._scope())
        authority, started = self._start(request)
        self.executor.leave_mounted = True
        packet = self._packet(
            "finalize_ltfs_session",
            {
                "operation_id": request.operation_id,
                "owner_generation": 17,
                "receipt": started.result["receipt"],
                "request_nonce": b"f" * 32,
            },
        )
        decoded = decode_request(packet, ltfs_authority=authority)
        response = decode_response(
            _send(self.service, packet),
            request=decoded,
            ltfs_authority=authority,
        )
        self.assertEqual(response.error_code, "state.unavailable")
        self.assertEqual(
            self.store.ltfs_session(request.operation_id, 17).state, "FINALIZING"
        )
        self.assertEqual(0, self.cgroup.kill_count)
        self.assertFalse(self.pins.leases[0].closed)
        self.assertEqual(tuple(self.cgroup.members.values()), (self.executor.pid,))
        readiness = decode_response(
            _send(
                self.service,
                self._packet("readiness", {"nonce": b"z" * 32}),
            )
        )
        self.assertEqual("state.unavailable", readiness.error_code)
        self.assertEqual(
            ["ltfs.phase.started", "ltfs.phase.failed"],
            [
                event.code
                for event in self.operational_events
                if event.phase == "unmount"
            ],
        )

    def test_cleanup_failure_never_reclassifies_durable_ltfs_terminal(self) -> None:
        request = self._request(self._scope())
        authority, started = self._start(request)

        def fail_release(_record):
            raise RuntimeError("synthetic cleanup failure")

        self.cgroup.release = fail_release
        packet = self._packet(
            "finalize_ltfs_session",
            {
                "operation_id": request.operation_id,
                "owner_generation": 17,
                "receipt": started.result["receipt"],
                "request_nonce": b"f" * 32,
            },
        )
        decoded = decode_request(packet, ltfs_authority=authority)
        response = decode_response(
            _send(self.service, packet),
            request=decoded,
            ltfs_authority=authority,
        )

        self.assertEqual("state.unavailable", response.error_code)
        for phase in ("finalizing_index", "unmount"):
            self.assertEqual(
                ["ltfs.phase.started", "ltfs.phase.succeeded"],
                [
                    event.code
                    for event in self.operational_events
                    if event.phase == phase
                ],
            )

    def test_lost_success_response_contains_and_breaks_session(self) -> None:
        request = self._request(self._scope())
        packet = self._packet("start_ltfs_session", {"request": request})
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        try:
            rights = array.array("i", (self.tape_fd, self.scsi_fd))
            client.sendmsg([packet], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, rights)])
            client.close()
            self.service.handle_connection(server)
        finally:
            client.close()
            server.close()
        self.assertEqual(
            self.store.ltfs_session(request.operation_id, 17).state, "BROKEN"
        )
        self.assertTrue(self.pins.leases[0].closed)
        self.assertEqual(self.cgroup.members, {})

    def test_failed_success_encoding_contains_and_breaks_session(self) -> None:
        request = self._request(self._scope())

        def fail_success(method, **kwargs):
            if method == "start_ltfs_session" and kwargs.get("result") is not None:
                raise RuntimeError("injected encoding failure")
            return encode_response(method, **kwargs)

        with patch(
            "ltobackup.broker.service.encode_response", side_effect=fail_success
        ):
            _authority, response = self._start(request)
        self.assertEqual(response.error_code, "state.unavailable")
        self.assertEqual(
            self.store.ltfs_session(request.operation_id, 17).state, "BROKEN"
        )
        self.assertTrue(self.pins.leases[0].closed)
        self.assertEqual(self.cgroup.members, {})

    def test_restart_contains_inflight_session_and_refuses_readiness(self) -> None:
        request = self._request(self._scope())
        self.assertIsNone(self._start(request)[1].error_code)
        restarted = self._service()
        with self.assertRaises(BrokerStateUnavailable):
            restarted.reconcile_startup()
        self.assertEqual(
            self.store.ltfs_session(request.operation_id, 17).state, "BROKEN"
        )
        readiness = decode_response(
            _send(
                restarted,
                self._packet("readiness", {"nonce": b"z" * 32}),
            )
        )
        self.assertEqual(readiness.error_code, "state.unavailable")

    def test_restart_closes_empty_client_scope_left_before_ltfs_start(self) -> None:
        response = decode_response(
            _send(
                self.service,
                self._packet(
                    "create_scope",
                    {
                        "command_id": "ltfs-" + "a" * 64,
                        "owner_generation": 21,
                        "request_nonce": b"q" * 32,
                    },
                ),
            )
        )
        self.assertIsNone(response.error_code)
        orphan = next(
            record
            for record in self.store.scopes_for_reconciliation()
            if record.command_id == "ltfs-" + "a" * 64
        )
        self.assertEqual("ACTIVE", orphan.state)

        self._service().reconcile_startup()

        reconciled = next(
            record
            for record in self.store.scopes_for_reconciliation()
            if record.scope_id == orphan.scope_id
        )
        self.assertEqual("CLOSED", reconciled.state)


class BrokerStateStoreReadinessIntegrationTests(unittest.TestCase):
    def test_readiness_persists_nonce_without_creating_a_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "broker-state.db"
            real_fstat = os.fstat

            def root_owned_fstat(descriptor: int) -> os.stat_result:
                fields = list(real_fstat(descriptor))
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            def root_owned_stat_at(name: str, *, dir_fd: int) -> os.stat_result:
                fields = list(os.stat(name, dir_fd=dir_fd, follow_symlinks=False))
                fields[4] = 0
                fields[5] = 0
                return os.stat_result(fields)

            with (
                patch("ltobackup.broker.store._effective_ids", return_value=(0, 0)),
                patch("ltobackup.broker.store._fstat", side_effect=root_owned_fstat),
                patch(
                    "ltobackup.broker.store._stat_at",
                    side_effect=root_owned_stat_at,
                ),
            ):
                store = BrokerStateStore.open(
                    path,
                    boot_id=BOOT_ID,
                    clock=lambda: NOW,
                )
            self.addCleanup(store.close)
            cgroup = _MemoryCgroup(store)
            pins = _ReadinessPins()
            runtime = object()
            service = CommandBrokerService(
                store,
                cgroup,
                capability=CAPABILITY,
                proof_key=PROOF_KEY,
                daemon_uid=os.getuid(),
                daemon_gid=os.getgid(),
                enforcing=False,
                daemon_context="system_u:system_r:lto_archiver_t:s0",
                connection_timeout=0.25,
                max_connections=2,
                ltfs_pins=pins,
                ltfs_receipt_root=runtime,
                ltfs_executor=runtime,
                ltfs_mountinfo_probe=runtime,
                ltfs_process_probe=runtime,
            )
            service.reconcile_startup()

            first = encode_request(
                "readiness",
                request_id=b"a" * 32,
                capability=CAPABILITY,
                params={"nonce": b"n" * 32},
            )
            response = decode_response(_send(service, first))
            self.assertIsNone(response.error_code)
            self.assertEqual(b"n" * 32, response.result["nonce"])
            self.assertEqual((), store.scopes_for_reconciliation())
            self.assertEqual(["readiness"], cgroup.calls)

            semantic_replay = encode_request(
                "readiness",
                request_id=b"b" * 32,
                capability=CAPABILITY,
                params={"nonce": b"n" * 32},
            )
            self.assertEqual(
                "scope.conflict",
                decode_response(_send(service, semantic_replay)).error_code,
            )
            self.assertEqual((), store.scopes_for_reconciliation())

            denied = encode_request(
                "readiness",
                request_id=b"c" * 32,
                capability=b"x" * 32,
                params={"nonce": b"m" * 32},
            )
            self.assertEqual(
                "auth.denied", decode_response(_send(service, denied)).error_code
            )
            self.assertEqual((), store.scopes_for_reconciliation())


def permit_sha256_from_mapping(value: dict[str, object]) -> str:
    from ltobackup.tape.command_supervisor import (
        BrokeredCgroupReleasePermit,
        BrokeredCgroupScopeReceipt,
    )

    source = dict(value)
    source["receipt"] = BrokeredCgroupScopeReceipt(**source["receipt"])
    return permit_sha256(BrokeredCgroupReleasePermit(**source))


if __name__ == "__main__":
    unittest.main()
