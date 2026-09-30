from __future__ import annotations

import array
import base64
import copy
import gc
import hashlib
import hmac
import json
import os
import pickle
import signal
import socket
import tempfile
import threading
import time
import unittest
import weakref
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Self
from unittest.mock import MagicMock, patch

from ltobackup.broker import client as broker_client_module
from ltobackup.broker.client import (
    BrokerUnavailable,
    LtfsSessionAdmission,
    LtfsSessionHandle,
    LtfsSessionRecoveryAdmission,
    UnixBrokeredCgroupScopeApi,
)
from ltobackup.broker.ltfs_session import derive_receipt_operation_uuid
from ltobackup.broker.protocol import (
    MAX_PACKET_BYTES,
    BrokerRequest,
    _decode_request_structure,
    decode_request,
    encode_response,
    ltfs_request_sha256,
)
from ltobackup.daemon.models import OperationFence, RecoveryCommandFence
from ltobackup.tape.command_supervisor import (
    BrokeredCgroupReleaseClaim,
    BrokeredCgroupReleasePermit,
    BrokeredCgroupScopeReceipt,
    BrokeredCgroupScopeToken,
    BrokeredCgroupScopeValidation,
    ExecutionScopeIdentity,
    LtfsFinalizationReceipt,
    LtfsSessionReceipt,
    LtfsSessionRequest,
    LtfsStandaloneReceipt,
)

TOKEN = BrokeredCgroupScopeToken(b"c" * 32)
IDENTITY = ExecutionScopeIdentity("command-17", 9)


def _ltfs_admission() -> LtfsSessionAdmission:
    return LtfsSessionAdmission(
        operation_id="operation-17",
        owner_generation=9,
        mount_path_sha256="1" * 64,
        tape_device_identity_sha256="2" * 64,
        scsi_device_identity_sha256="3" * 64,
        expected_media_scope_sha256="4" * 64,
        observed_media_identity_sha256="5" * 64,
        expected_volume_uuid="22222222-2222-4222-8222-222222222222",
        expected_prior_generation=7,
        read_only=False,
    )


def _ltfs_recovery_admission() -> LtfsSessionRecoveryAdmission:
    admission = _ltfs_admission()
    return LtfsSessionRecoveryAdmission(
        fence=RecoveryCommandFence(admission.operation_id, 10),
        original_owner_generation=admission.owner_generation,
        mount_path_sha256=admission.mount_path_sha256,
        tape_device_identity_sha256=admission.tape_device_identity_sha256,
        scsi_device_identity_sha256=admission.scsi_device_identity_sha256,
        expected_media_scope_sha256=admission.expected_media_scope_sha256,
        observed_media_identity_sha256=admission.observed_media_identity_sha256,
    )


def _ltfs_same_generation_admission() -> LtfsSessionRecoveryAdmission:
    admission = _ltfs_admission()
    return LtfsSessionRecoveryAdmission(
        fence=OperationFence(admission.operation_id, admission.owner_generation),
        original_owner_generation=admission.owner_generation,
        mount_path_sha256=admission.mount_path_sha256,
        tape_device_identity_sha256=admission.tape_device_identity_sha256,
        scsi_device_identity_sha256=admission.scsi_device_identity_sha256,
        expected_media_scope_sha256=admission.expected_media_scope_sha256,
        observed_media_identity_sha256=admission.observed_media_identity_sha256,
    )


def _receipt(request_nonce: bytes = b"r" * 32) -> BrokeredCgroupScopeReceipt:
    return BrokeredCgroupScopeReceipt(
        protocol_version=1,
        command_id=IDENTITY.command_id,
        owner_generation=IDENTITY.owner_generation,
        request_nonce=request_nonce,
        scope_id="scope-17",
        scope_path_sha256="a" * 64,
        broker_nonce=b"n" * 32,
        broker_proof=b"p" * 32,
        recursive_population=True,
        recursive_members=True,
        cgroup_kill=True,
    )


def _permit(
    receipt: BrokeredCgroupScopeReceipt,
    request_nonce: bytes = b"q" * 32,
) -> BrokeredCgroupReleasePermit:
    return BrokeredCgroupReleasePermit(
        protocol_version=1,
        receipt=receipt,
        pid=4711,
        request_nonce=request_nonce,
        permit_nonce=b"m" * 32,
        broker_proof=b"z" * 32,
    )


def _receipt_wire(receipt: BrokeredCgroupScopeReceipt) -> dict[str, object]:
    return {
        "protocol_version": receipt.protocol_version,
        "command_id": receipt.command_id,
        "owner_generation": receipt.owner_generation,
        "request_nonce": receipt.request_nonce,
        "scope_id": receipt.scope_id,
        "scope_path_sha256": receipt.scope_path_sha256,
        "broker_nonce": receipt.broker_nonce,
        "broker_proof": receipt.broker_proof,
        "recursive_population": receipt.recursive_population,
        "recursive_members": receipt.recursive_members,
        "cgroup_kill": receipt.cgroup_kill,
    }


def _permit_wire(permit: BrokeredCgroupReleasePermit) -> dict[str, object]:
    return {
        "protocol_version": permit.protocol_version,
        "receipt": _receipt_wire(permit.receipt),
        "pid": permit.pid,
        "request_nonce": permit.request_nonce,
        "permit_nonce": permit.permit_nonce,
        "broker_proof": permit.broker_proof,
    }


def _success_result(request: BrokerRequest) -> dict[str, object]:
    receipt = request.params.get("receipt")
    if request.method == "readiness":
        fields: dict[str, object] = {
            "broker_state": True,
            "delegated_cgroup": True,
            "recursive_population": True,
            "cgroup_kill": True,
            "ltfs_session_contract": 1,
            "challenge": request.params["nonce"],
            "reconciliation_nonce": b"r" * 32,
            "ltfs_tool_identity_sha256": "8" * 64,
            "fusermount_tool_identity_sha256": "9" * 64,
            "reconciliation_clean": True,
        }
        canonical_fields = {
            key: (
                {"base64": base64.b64encode(value).decode("ascii")}
                if type(value) is bytes
                else value
            )
            for key, value in fields.items()
        }
        payload = json.dumps(
            {
                "domain": "readiness-capability-proof-v1",
                "fields": canonical_fields,
                "version": 1,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        fields["capability_proof"] = hmac.new(
            request.capability, payload, hashlib.sha256
        ).digest()
        return {
            "nonce": request.params["nonce"],
            "features": fields,
        }
    if request.method in {"create_scope", "open_scope"}:
        scope_receipt = BrokeredCgroupScopeReceipt(
            protocol_version=1,
            command_id=request.params["command_id"],
            owner_generation=request.params["owner_generation"],
            request_nonce=request.params["request_nonce"],
            scope_id="scope-17",
            scope_path_sha256="a" * 64,
            broker_nonce=b"n" * 32,
            broker_proof=b"p" * 32,
            recursive_population=True,
            recursive_members=True,
            cgroup_kill=True,
        )
        receipt = _receipt_wire(scope_receipt)
        return {"receipt": receipt}
    if request.method == "start_ltfs_session":
        session_request = request.params["request"]
        assert type(session_request) is LtfsSessionRequest
        request_sha256 = ltfs_request_sha256(session_request)
        return {
            "receipt": LtfsSessionReceipt(
                protocol_version=1,
                operation_id=session_request.operation_id,
                receipt_operation_uuid=derive_receipt_operation_uuid(
                    operation_id=session_request.operation_id,
                    owner_generation=session_request.owner_generation,
                    request_sha256=request_sha256,
                ),
                observed_volume_uuid=session_request.expected_volume_uuid
                or "22222222-2222-4222-8222-222222222222",
                observed_prior_generation=7,
                read_only=session_request.read_only,
                owner_generation=session_request.owner_generation,
                request_nonce=session_request.request_nonce,
                session_id="ltfs-session-17",
                request_sha256=request_sha256,
                child_pid=4711,
                child_start_ticks=8123,
                mount_namespace_sha256="d" * 64,
                broker_nonce=b"u" * 32,
                broker_proof=b"v" * 32,
                mounted=True,
                observed_volume_label="TEST VOLUME",
                observed_media_identity_sha256=(
                    session_request.observed_media_identity_sha256
                ),
            )
        }
    if request.method == "observe_ltfs_session":
        return {
            "receipt": request.params["receipt"],
            "challenge": request.params["challenge"],
            "observation_nonce": b"w" * 32,
            "broker_proof": b"x" * 32,
            "mounted": True,
        }
    if request.method == "finalize_ltfs_session":
        session = request.params["receipt"]
        assert type(session) is LtfsSessionReceipt
        terminal_fields = {
            "schema": 1,
            "stage": "terminal",
            "operation_id": session.receipt_operation_uuid,
            "volume_uuid": session.observed_volume_uuid,
            "prior_generation": session.observed_prior_generation,
            "new_generation": session.observed_prior_generation + 1,
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
            (json.dumps(terminal_fields, separators=(",", ":")) + "\n").encode("ascii")
        ).hexdigest()
        return {
            "receipt": LtfsFinalizationReceipt(
                protocol_version=1,
                session_receipt=session,
                standalone_receipt=LtfsStandaloneReceipt(
                    **{
                        **terminal_fields,
                        "phase_duration_ns": tuple(
                            terminal_fields["phase_duration_ns"]
                        ),
                    },
                    terminal_sha256=terminal_sha256,
                ),
                request_nonce=request.params["request_nonce"],
                finalization_nonce=b"y" * 32,
                broker_proof=b"z" * 32,
                unmounted=True,
                child_quiesced=True,
            )
        }
    if request.method == "validate_scope":
        return {
            "validation": {
                "protocol_version": 1,
                "receipt": receipt,
                "challenge": request.params["challenge"],
                "validation_nonce": b"v" * 32,
                "broker_proof": b"w" * 32,
                "populated": True,
                "member_pids": (4711,),
            }
        }
    if request.method == "prepare_release":
        return {
            "permit": {
                "protocol_version": 1,
                "receipt": receipt,
                "pid": request.params["pid"],
                "request_nonce": request.params["request_nonce"],
                "permit_nonce": b"m" * 32,
                "broker_proof": b"z" * 32,
            }
        }
    if request.method == "claim_unreleased":
        return {
            "claim": {
                "protocol_version": 1,
                "receipt": receipt,
                "pid": request.params["pid"],
                "permit_sha256": request.params["permit_sha256"],
                "challenge": request.params["challenge"],
                "claim_nonce": b"l" * 32,
                "broker_proof": b"y" * 32,
                "released": False,
                "permit_revoked": True,
            }
        }
    return {}


def _received_fds(ancillary: list[tuple[int, int, bytes]]) -> list[int]:
    result: list[int] = []
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            values = array.array("i")
            values.frombytes(data[: len(data) - (len(data) % values.itemsize)])
            result.extend(values)
    return result


class _Peer:
    def __init__(
        self,
        server: socket.socket,
        responder: Callable[[socket.socket, BrokerRequest], None] | None = None,
    ) -> None:
        self.server = server
        self.responder = responder or self._respond_success
        self.request: BrokerRequest | None = None
        self.fds: list[int] = []
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run)

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.thread.join(timeout=2.0)
        self.server.close()
        for fd in self.fds:
            os.close(fd)
        if self.thread.is_alive():
            self.fail("fake broker peer did not stop")
        if self.error is not None:
            raise self.error

    def fail(self, message: str) -> None:
        raise AssertionError(message)

    def _run(self) -> None:
        try:
            packet, ancillary, flags, _address = self.server.recvmsg(
                MAX_PACKET_BYTES + 1, socket.CMSG_SPACE(16 * array.array("i").itemsize)
            )
            if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                self.fail("client request was truncated")
            self.fds = _received_fds(ancillary)
            self.request = _decode_request_structure(packet)
            self.responder(self.server, self.request)
        except BaseException as error:  # noqa: BLE001 - re-raised in test thread owner
            self.error = error

    @staticmethod
    def _respond_success(server: socket.socket, request: BrokerRequest) -> None:
        server.send(
            encode_response(
                request.method,
                request_id=request.request_id,
                result=_success_result(request),
            )
        )


def _fd_count() -> int:
    return len(tuple(Path("/proc/self/fd").iterdir()))


class _PathPeer:
    def __init__(self, listener: socket.socket) -> None:
        self.listener = listener
        self.request: BrokerRequest | None = None
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self._run)

    def __enter__(self) -> Self:
        self.listener.settimeout(0.2)
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.thread.join(timeout=2.0)
        self.listener.close()
        if self.thread.is_alive():
            raise AssertionError("pathname broker peer did not stop")
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        try:
            connection, _address = self.listener.accept()
        except TimeoutError:
            return
        try:
            packet = connection.recv(MAX_PACKET_BYTES)
            self.request = decode_request(packet)
            connection.send(
                encode_response(
                    self.request.method,
                    request_id=self.request.request_id,
                    result=_success_result(self.request),
                )
            )
        except BaseException as error:  # noqa: BLE001 - re-raised by thread owner
            self.error = error
        finally:
            connection.close()


class BrokerClientTests(unittest.TestCase):
    def test_ltfs_outcome_admission_keeps_recovery_lineage_strict(self) -> None:
        same_generation = _ltfs_same_generation_admission()
        self.assertIs(type(same_generation.fence), OperationFence)
        self.assertEqual(
            same_generation.fence.owner_generation,
            same_generation.original_owner_generation,
        )
        with self.assertRaisesRegex(ValueError, "recovery fence"):
            replace(
                _ltfs_recovery_admission(),
                fence=RecoveryCommandFence("operation-a", 7),
                original_owner_generation=7,
            )

    def _connected_api(self) -> tuple[UnixBrokeredCgroupScopeApi, socket.socket]:
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        return (
            UnixBrokeredCgroupScopeApi.from_connected_socket(
                client, TOKEN, expected_peer_uid=os.getuid()
            ),
            server,
        )

    def test_readiness_accepts_an_authenticated_local_seqpacket_peer(self) -> None:
        api, server = self._connected_api()
        try:
            with _Peer(server):
                self.assertIsNone(api.assert_ready())
        finally:
            server.close()

    def test_readiness_rejects_legacy_extra_and_missing_feature_shapes(self) -> None:
        def responder_for(mutation):
            def respond(server: socket.socket, request: BrokerRequest) -> None:
                raw = json.loads(
                    encode_response(
                        request.method,
                        request_id=request.request_id,
                        result=_success_result(request),
                    )
                )
                mutation(raw["result"]["features"])
                server.send(
                    json.dumps(raw, sort_keys=True, separators=(",", ":")).encode(
                        "ascii"
                    )
                )

            return respond

        def legacy(features: dict[str, object]) -> None:
            for key in tuple(features):
                if key not in {
                    "broker_state",
                    "delegated_cgroup",
                    "recursive_population",
                    "cgroup_kill",
                }:
                    del features[key]

        mutations = (
            legacy,
            lambda features: features.__setitem__("extra", True),
            lambda features: features.pop("reconciliation_clean"),
        )
        for mutation in mutations:
            api, server = self._connected_api()
            try:
                with (
                    self.subTest(mutation=mutation),
                    _Peer(server, responder_for(mutation)),
                    self.assertRaises(BrokerUnavailable),
                ):
                    api.assert_ready()
            finally:
                server.close()

    def test_readiness_rejects_tampered_proof_and_replayed_reconciliation_nonce(
        self,
    ) -> None:
        def tampered(server: socket.socket, request: BrokerRequest) -> None:
            result = _success_result(request)
            result["features"]["ltfs_tool_identity_sha256"] = "7" * 64
            server.send(
                encode_response(
                    request.method, request_id=request.request_id, result=result
                )
            )

        api, server = self._connected_api()
        try:
            with _Peer(server, tampered), self.assertRaises(BrokerUnavailable):
                api.assert_ready()
        finally:
            server.close()

        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        for _ in range(2):
            client, peer = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            clients.append(client)
            peers.append(_Peer(peer))
        api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
        api._expected_peer_uid = os.getuid()
        try:
            with (
                peers[0],
                peers[1],
                patch.object(api, "_take_socket", side_effect=clients),
            ):
                api.assert_ready()
                with self.assertRaises(BrokerUnavailable):
                    api.assert_ready()
        finally:
            for connection in clients:
                connection.close()

    def test_all_ten_api_methods_use_the_closed_contract(self):
        receipt = _receipt()
        permit = _permit(receipt)
        challenge = b"h" * 32
        request_nonce = b"q" * 32
        receipt_payload = _receipt_wire(receipt)
        cases = (
            (
                "create_scope",
                lambda api: api.create_scope(IDENTITY, b"r" * 32, TOKEN),
                {
                    "command_id": "command-17",
                    "owner_generation": 9,
                    "request_nonce": b"r" * 32,
                },
                _receipt(b"r" * 32),
            ),
            (
                "open_scope",
                lambda api: api.open_scope(IDENTITY, b"r" * 32, TOKEN),
                {
                    "command_id": "command-17",
                    "owner_generation": 9,
                    "request_nonce": b"r" * 32,
                },
                _receipt(b"r" * 32),
            ),
            (
                "attach",
                lambda api: api.attach(receipt, 4711, TOKEN),
                {"receipt": receipt_payload, "pid": 4711},
                None,
            ),
            (
                "validate_scope",
                lambda api: api.validate_scope(receipt, challenge, TOKEN),
                {"receipt": receipt_payload, "challenge": b"h" * 32},
                BrokeredCgroupScopeValidation(
                    protocol_version=1,
                    receipt=receipt,
                    challenge=b"h" * 32,
                    validation_nonce=b"v" * 32,
                    broker_proof=b"w" * 32,
                    populated=True,
                    member_pids=(4711,),
                ),
            ),
            (
                "prepare_release",
                lambda api: api.prepare_release(receipt, 4711, request_nonce, TOKEN),
                {
                    "receipt": receipt_payload,
                    "pid": 4711,
                    "request_nonce": b"q" * 32,
                },
                permit,
            ),
            (
                "claim_unreleased",
                lambda api: api.claim_unreleased(
                    receipt, 4711, "b" * 64, challenge, TOKEN
                ),
                {
                    "receipt": receipt_payload,
                    "pid": 4711,
                    "permit_sha256": "b" * 64,
                    "challenge": b"h" * 32,
                },
                BrokeredCgroupReleaseClaim(
                    protocol_version=1,
                    receipt=receipt,
                    pid=4711,
                    permit_sha256="b" * 64,
                    challenge=b"h" * 32,
                    claim_nonce=b"l" * 32,
                    broker_proof=b"y" * 32,
                    released=False,
                    permit_revoked=True,
                ),
            ),
            (
                "signal_scope",
                lambda api: api.signal_scope(receipt, signal.SIGTERM, TOKEN),
                {"receipt": receipt_payload, "signum": 15},
                None,
            ),
            (
                "kill_scope",
                lambda api: api.kill_scope(receipt, TOKEN),
                {"receipt": receipt_payload},
                None,
            ),
            (
                "release_scope",
                lambda api: api.release_scope(receipt, TOKEN),
                {"receipt": receipt_payload},
                None,
            ),
        )

        for method, invoke, expected_params, expected_result in cases:
            before = _fd_count()
            api, server = self._connected_api()
            with self.subTest(method=method), _Peer(server) as peer:
                result = invoke(api)
            self.assertIsNotNone(peer.request)
            self.assertEqual(peer.request.method, method)
            self.assertEqual(peer.request.capability, TOKEN.value)
            self.assertEqual(peer.request.params, expected_params)
            self.assertEqual(peer.fds, [])
            self.assertEqual(result, expected_result)
            self.assertEqual(_fd_count(), before)

        before = _fd_count()
        read_fd, write_fd = os.pipe()
        try:
            api, server = self._connected_api()
            with _Peer(server) as peer:
                result = api.release_child(receipt, permit, 4711, write_fd, TOKEN)
            self.assertIsNone(result)
            self.assertEqual(peer.request.method, "release_child")
            self.assertEqual(
                peer.request.params,
                {
                    "receipt": receipt_payload,
                    "permit": _permit_wire(permit),
                    "pid": 4711,
                },
            )
            self.assertEqual(len(peer.fds), 1)
            self.assertNotEqual(peer.fds[0], write_fd)
            os.write(write_fd, b"x")
            self.assertEqual(os.read(read_fd, 1), b"x")
        finally:
            os.close(read_fd)
            os.close(write_fd)
        self.assertEqual(_fd_count(), before)

    def test_ltfs_start_sends_exact_ordered_fds_without_taking_ownership(self) -> None:
        tape_read, tape_write = os.pipe()
        scsi_read, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        observed_payloads: list[bytes] = []

        def record_start(server: socket.socket, request: BrokerRequest) -> None:
            peer = peers[1]
            observed_payloads.extend(os.read(fd, 1) for fd in peer.fds)
            server.send(
                encode_response(
                    request.method,
                    request_id=request.request_id,
                    result=_success_result(request),
                )
            )

        try:
            os.write(tape_write, b"T")
            os.write(scsi_write, b"S")
            for responder in (None, record_start):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server, responder))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda fd, role: (
                        "6" * 64 if (fd, role) == (tape_read, "tape") else "7" * 64
                    ),
                ) as identity,
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_read, scsi_fd=scsi_read
                )

            self.assertEqual([b"T", b"S"], observed_payloads)
            self.assertEqual(2, len(peers[1].fds))
            self.assertEqual("operation-17", handle.receipt.operation_id)
            self.assertEqual(
                [
                    (tape_read, "tape"),
                    (scsi_read, "scsi"),
                    (tape_read, "tape"),
                    (scsi_read, "scsi"),
                ],
                [call.args for call in identity.call_args_list],
            )
            os.fstat(tape_read)
            os.fstat(scsi_read)
        finally:
            for fd in (tape_read, tape_write, scsi_read, scsi_write):
                os.close(fd)

    def test_ltfs_handle_is_client_bound_and_finalize_is_one_shot(self) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for _index in range(4):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                peers[2],
                peers[3],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
                restarted = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
                with self.assertRaises(BrokerUnavailable):
                    restarted.observe_ltfs_session(handle)
                api.observe_ltfs_session(handle)
                terminal = api.finalize_ltfs_session(handle)
                with self.assertRaises(BrokerUnavailable):
                    api.finalize_ltfs_session(handle)

            self.assertTrue(terminal.unmounted)
            self.assertTrue(terminal.child_quiesced)
            self.assertEqual(
                [
                    "create_scope",
                    "start_ltfs_session",
                    "observe_ltfs_session",
                    "finalize_ltfs_session",
                ],
                [peer.request.method for peer in peers if peer.request is not None],
            )
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_handle_is_opaque_nonconstructible_and_nonserializable(self) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for _index in range(2):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )

            self.assertFalse(hasattr(handle, "__dict__"))
            for field_name in ("_request", "_authority", "_client_binding", "_state"):
                self.assertFalse(hasattr(handle, field_name))
            with self.assertRaises(TypeError):
                LtfsSessionHandle(handle.receipt)  # type: ignore[call-arg]
            with self.assertRaises(TypeError):
                replace(handle, receipt=handle.receipt)
            with self.assertRaises(TypeError):
                copy.copy(handle)
            with self.assertRaises(TypeError):
                copy.deepcopy(handle)
            with self.assertRaises(TypeError):
                pickle.dumps(handle)
            forged = object.__new__(LtfsSessionHandle)
            with (
                patch.object(
                    api,
                    "_take_socket",
                    side_effect=AssertionError("forged handle reached dispatch"),
                ) as take_socket,
                self.assertRaises(BrokerUnavailable),
            ):
                api.observe_ltfs_session(forged)
            take_socket.assert_not_called()
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_terminal_handle_registry_and_tombstones_are_gc_bounded(self) -> None:
        api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
        receipt = LtfsSessionReceipt(
            1,
            "operation-17",
            "11111111-1111-5111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            7,
            False,
            9,
            b"r" * 32,
            "session-17",
            "a" * 64,
            4711,
            8123,
            "b" * 64,
            b"n" * 32,
            b"p" * 32,
            True,
            "TEST VOLUME",
            "5" * 64,
        )
        references: list[weakref.ReferenceType[object]] = []
        for _index in range(1_000):
            handle = broker_client_module._issue_ltfs_session_handle(receipt)
            api._ltfs_sessions[handle] = MagicMock()
            api._tombstone_ltfs_handle(handle)
            references.append(weakref.ref(handle))
        del handle
        gc.collect()

        self.assertEqual(0, len(api._ltfs_sessions))
        self.assertEqual(0, len(api._ltfs_pending))
        self.assertEqual(0, len(api._ltfs_tombstones))
        self.assertTrue(all(reference() is None for reference in references))

    def test_ltfs_partial_observe_send_poisons_handle_without_closing_callers_fds(
        self,
    ) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for _index in range(3):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(
                    _Peer(
                        server,
                        (lambda _server, _request: None) if _index == 2 else None,
                    )
                )
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )

                original_send = socket.socket.send
                observe_client_fd = clients[2].fileno()

                def partial_send(connection: socket.socket, packet: bytes) -> int:
                    sent = original_send(connection, packet)
                    return (
                        sent - 1 if connection.fileno() == observe_client_fd else sent
                    )

                with (
                    peers[2],
                    patch.object(socket.socket, "send", new=partial_send),
                    self.assertRaises(BrokerUnavailable),
                ):
                    api.observe_ltfs_session(handle)

                with (
                    patch.object(
                        api,
                        "_take_socket",
                        side_effect=AssertionError("poisoned handle was reused"),
                    ) as take_socket,
                    self.assertRaises(BrokerUnavailable),
                ):
                    api.finalize_ltfs_session(handle)
                take_socket.assert_not_called()
            os.fstat(tape_fd)
            os.fstat(scsi_fd)
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_presend_observe_and_finalize_failures_keep_handle_retryable(
        self,
    ) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for _index in range(4):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                peers[2],
                peers[3],
                patch.object(
                    api,
                    "_take_socket",
                    side_effect=(
                        clients[0],
                        clients[1],
                        OSError("observe pre-send"),
                        clients[2],
                        OSError("finalize pre-send"),
                        clients[3],
                    ),
                ),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
                with self.assertRaises(BrokerUnavailable) as observe_error:
                    api.observe_ltfs_session(handle)
                self.assertIs(type(observe_error.exception), BrokerUnavailable)
                self.assertEqual(handle.receipt, api.observe_ltfs_session(handle))
                with self.assertRaises(BrokerUnavailable) as finalize_error:
                    api.finalize_ltfs_session(handle)
                self.assertIs(type(finalize_error.exception), BrokerUnavailable)
                terminal = api.finalize_ltfs_session(handle)

            self.assertTrue(terminal.unmounted)
            self.assertEqual(
                [
                    "create_scope",
                    "start_ltfs_session",
                    "observe_ltfs_session",
                    "finalize_ltfs_session",
                ],
                [peer.request.method for peer in peers if peer.request is not None],
            )
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_partial_finalize_send_poisons_handle(self) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for index in range(3):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(
                    _Peer(
                        server,
                        (lambda _server, _request: None) if index == 2 else None,
                    )
                )
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            original_send = socket.socket.send
            finalize_client_fd = clients[2].fileno()

            def partial_send(connection: socket.socket, packet: bytes) -> int:
                sent = original_send(connection, packet)
                return sent - 1 if connection.fileno() == finalize_client_fd else sent

            with (
                peers[0],
                peers[1],
                peers[2],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(socket.socket, "send", new=partial_send),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
                with self.assertRaises(BrokerUnavailable):
                    api.finalize_ltfs_session(handle)
                with (
                    patch.object(
                        api,
                        "_take_socket",
                        side_effect=AssertionError("poisoned handle was reused"),
                    ) as take_socket,
                    self.assertRaises(BrokerUnavailable),
                ):
                    api.finalize_ltfs_session(handle)
                take_socket.assert_not_called()
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_pending_cleanup_is_shared_and_recovered_without_raw_handle(
        self,
    ) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for _index in range(3):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                peers[2],
                patch.object(
                    api,
                    "_take_socket",
                    side_effect=(
                        clients[0],
                        clients[1],
                        OSError("finalize pre-send"),
                        clients[2],
                    ),
                ) as take_socket,
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
                with self.assertRaises(BrokerUnavailable):
                    api.finalize_ltfs_session(handle)
                before_blocked_start = take_socket.call_count
                with self.assertRaises(BrokerUnavailable):
                    api.start_ltfs_session(
                        _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                    )
                self.assertEqual(before_blocked_start, take_socket.call_count)
                mismatch = replace(
                    _ltfs_recovery_admission(),
                    observed_media_identity_sha256="8" * 64,
                )
                self.assertIsNone(api.recover_pending_ltfs_session(mismatch))
                terminal = api.recover_pending_ltfs_session(_ltfs_recovery_admission())

            self.assertIsNotNone(terminal)
            self.assertTrue(terminal.unmounted)
            self.assertEqual(0, len(api._ltfs_sessions))
            self.assertEqual(0, len(api._ltfs_pending))
            self.assertEqual(
                ["create_scope", "start_ltfs_session", "finalize_ltfs_session"],
                [peer.request.method for peer in peers if peer.request is not None],
            )
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_partial_start_sendmsg_is_not_retried_and_fds_remain_owned(
        self,
    ) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []
        try:
            for index in range(2):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(
                    _Peer(
                        server,
                        (lambda _server, _request: None) if index == 1 else None,
                    )
                )
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            original_sendmsg = socket.socket.sendmsg
            start_client_fd = clients[1].fileno()

            def partial_sendmsg(connection, buffers, ancillary=(), *args):
                sent = original_sendmsg(connection, buffers, ancillary, *args)
                return sent - 1 if connection.fileno() == start_client_fd else sent

            with (
                peers[0],
                peers[1],
                patch.object(api, "_take_socket", side_effect=clients) as take_socket,
                patch.object(socket.socket, "sendmsg", new=partial_sendmsg),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
                self.assertRaises(BrokerUnavailable),
            ):
                api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )

            self.assertEqual(2, take_socket.call_count)
            self.assertEqual(
                ["create_scope", "start_ltfs_session"],
                [peer.request.method for peer in peers if peer.request is not None],
            )
            os.fstat(tape_fd)
            os.fstat(scsi_fd)
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_same_descriptor_is_rejected_before_scope_creation(self) -> None:
        read_fd, write_fd = os.pipe()
        try:
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            with (
                patch.object(
                    api,
                    "_take_socket",
                    side_effect=AssertionError("invalid FDs reached broker dispatch"),
                ) as take_socket,
                self.assertRaises(BrokerUnavailable),
            ):
                api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=read_fd, scsi_fd=read_fd
                )
            take_socket.assert_not_called()
            os.fstat(read_fd)
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_ltfs_tampered_start_proof_is_rejected_without_leaking_details(
        self,
    ) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []

        def tampered(server: socket.socket, request: BrokerRequest) -> None:
            result = _success_result(request)
            receipt = result["receipt"]
            assert type(receipt) is LtfsSessionReceipt
            result["receipt"] = LtfsSessionReceipt(
                receipt.protocol_version,
                receipt.operation_id,
                receipt.receipt_operation_uuid,
                receipt.observed_volume_uuid,
                receipt.observed_prior_generation,
                receipt.read_only,
                receipt.owner_generation,
                receipt.request_nonce,
                receipt.session_id,
                "0" * 64,
                receipt.child_pid,
                receipt.child_start_ticks,
                receipt.mount_namespace_sha256,
                receipt.broker_nonce,
                receipt.broker_proof,
                receipt.mounted,
                receipt.observed_volume_label,
                receipt.observed_media_identity_sha256,
            )
            server.send(
                encode_response(
                    request.method,
                    request_id=request.request_id,
                    result=result,
                )
            )

        try:
            for responder in (None, tampered):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server, responder))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ) as raised,
            ):
                api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
            self.assertNotIn("operation-17", str(raised.exception))
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_definite_start_rejection_releases_the_empty_scope(self) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        scope = MagicMock()
        scope.receipt = _receipt()

        def rejected(server: socket.socket, request: BrokerRequest) -> None:
            server.send(
                encode_response(
                    request.method,
                    request_id=request.request_id,
                    error_code="scope.conflict",
                )
            )

        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        api = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client, TOKEN, expected_peer_uid=os.getuid()
        )
        try:
            with (
                _Peer(server, rejected),
                patch.object(
                    broker_client_module,
                    "BrokeredCgroupExecutionScopeManager",
                ) as manager,
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
                self.assertRaises(BrokerUnavailable) as caught,
            ):
                manager.return_value.create.return_value = scope
                api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
            self.assertIs(type(caught.exception), BrokerUnavailable)
            scope.close.assert_called_once_with()
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_restart_readopts_only_the_exact_deterministic_empty_scope(
        self,
    ) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        clients: list[socket.socket] = []
        peers: list[_Peer] = []

        def already_exists(server: socket.socket, request: BrokerRequest) -> None:
            server.send(
                encode_response(
                    request.method,
                    request_id=request.request_id,
                    error_code="scope.conflict",
                )
            )

        try:
            for responder in (already_exists, None, None):
                client, server = socket.socketpair(
                    socket.AF_UNIX, socket.SOCK_SEQPACKET
                )
                clients.append(client)
                peers.append(_Peer(server, responder))
            api = UnixBrokeredCgroupScopeApi(Path("/run/broker.sock"), TOKEN)
            api._expected_peer_uid = os.getuid()
            with (
                peers[0],
                peers[1],
                peers[2],
                patch.object(api, "_take_socket", side_effect=clients),
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=lambda _fd, role: (
                        "6" * 64 if role == "tape" else "7" * 64
                    ),
                ),
            ):
                handle = api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )

            self.assertEqual("operation-17", handle.receipt.operation_id)
            self.assertEqual(
                ["create_scope", "open_scope", "start_ltfs_session"],
                [peer.request.method for peer in peers if peer.request is not None],
            )
            create = peers[0].request
            opened = peers[1].request
            self.assertIsNotNone(create)
            self.assertIsNotNone(opened)
            self.assertEqual(create.params["command_id"], opened.params["command_id"])
            self.assertEqual(
                create.params["owner_generation"],
                opened.params["owner_generation"],
            )
        finally:
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_ltfs_fd_swap_before_send_releases_scope_without_dispatch(self) -> None:
        tape_fd, tape_write = os.pipe()
        scsi_fd, scsi_write = os.pipe()
        scope = MagicMock()
        scope.receipt = _receipt()
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        api = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client, TOKEN, expected_peer_uid=os.getuid()
        )
        try:
            with (
                patch.object(
                    broker_client_module,
                    "BrokeredCgroupExecutionScopeManager",
                ) as manager,
                patch.object(
                    broker_client_module,
                    "device_fd_identity_sha256",
                    side_effect=("6" * 64, "7" * 64, "8" * 64, "7" * 64),
                ),
                self.assertRaises(BrokerUnavailable),
            ):
                manager.return_value.create.return_value = scope
                api.start_ltfs_session(
                    _ltfs_admission(), tape_fd=tape_fd, scsi_fd=scsi_fd
                )
            scope.close.assert_called_once_with()
            self.assertEqual(b"", server.recv(1))
        finally:
            server.close()
            for fd in (tape_fd, tape_write, scsi_fd, scsi_write):
                os.close(fd)

    def test_response_identity_mismatch_and_remote_errors_are_redacted(self):
        def mismatched(server: socket.socket, request: BrokerRequest) -> None:
            server.send(
                encode_response(
                    request.method,
                    request_id=b"x" * 32,
                    result=_success_result(request),
                )
            )

        def denied(server: socket.socket, request: BrokerRequest) -> None:
            server.send(
                encode_response(
                    request.method,
                    request_id=request.request_id,
                    error_code="auth.denied",
                )
            )

        for responder, reason in ((mismatched, "protocol"), (denied, "rejected")):
            before = _fd_count()
            api, server = self._connected_api()
            with (
                self.subTest(responder=responder.__name__),
                _Peer(server, responder),
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ) as caught,
            ):
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            self.assertIs(type(caught.exception), BrokerUnavailable)
            self.assertEqual(reason, caught.exception.reason)
            self.assertNotIn("auth.denied", str(caught.exception))
            self.assertNotIn("command-17", str(caught.exception))
            self.assertEqual(_fd_count(), before)

    def test_timeout_eof_oversized_and_unknown_responses_are_redacted(self):
        def timeout(server: socket.socket, _request: BrokerRequest) -> None:
            time.sleep(0.1)

        def eof(server: socket.socket, _request: BrokerRequest) -> None:
            server.close()

        def oversized(server: socket.socket, _request: BrokerRequest) -> None:
            server.send(b"x" * (MAX_PACKET_BYTES + 1))

        def unknown(server: socket.socket, _request: BrokerRequest) -> None:
            server.send(b'{"status":"raw-internal-error"}')

        for responder, reason in (
            (timeout, "timeout"),
            (eof, "eof"),
            (oversized, "protocol"),
            (unknown, "protocol"),
        ):
            before = _fd_count()
            client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            api = UnixBrokeredCgroupScopeApi.from_connected_socket(
                client, TOKEN, timeout=0.02, expected_peer_uid=os.getuid()
            )
            with (
                self.subTest(responder=responder.__name__),
                _Peer(server, responder),
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ) as caught,
            ):
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            self.assertEqual(reason, caught.exception.reason)
            self.assertEqual(_fd_count(), before)

    def test_scope_connection_failure_has_safe_pre_dispatch_reason(self):
        api = UnixBrokeredCgroupScopeApi(Path("/run/broker/control.sock"), TOKEN)
        with (
            patch.object(
                api, "_open_socket_anchor", side_effect=OSError("secret-path-token")
            ),
            self.assertRaises(BrokerUnavailable) as caught,
        ):
            api.open_scope(IDENTITY, b"r" * 32, TOKEN)
        self.assertEqual("pre_dispatch", caught.exception.reason)
        self.assertEqual(("command broker unavailable",), caught.exception.args)
        self.assertNotIn("secret-path-token", repr(caught.exception))

    def test_broker_failure_reason_normalizes_untrusted_values(self):
        for value in ("secret-path-token", object(), None):
            with self.subTest(value=type(value).__name__):
                failure = BrokerUnavailable(reason=value)
                self.assertEqual("unavailable", failure.reason)
                self.assertEqual(("command broker unavailable",), failure.args)
                self.assertNotIn("secret-path-token", repr(failure))

    def test_unexpected_received_descriptor_is_closed_on_failure(self):
        def response_with_fd(server: socket.socket, request: BrokerRequest) -> None:
            read_fd, write_fd = os.pipe()
            try:
                descriptor = array.array("i", [read_fd])
                server.sendmsg(
                    [
                        encode_response(
                            request.method,
                            request_id=request.request_id,
                            result=_success_result(request),
                        )
                    ],
                    [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptor)],
                )
            finally:
                os.close(read_fd)
                os.close(write_fd)

        before = _fd_count()
        api, server = self._connected_api()
        with _Peer(server, response_with_fd), self.assertRaises(BrokerUnavailable):
            api.create_scope(IDENTITY, b"r" * 32, TOKEN)
        self.assertEqual(_fd_count(), before)

    def test_release_fd_duplicate_is_closed_when_send_fails(self):
        read_fd, write_fd = os.pipe()
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        api = UnixBrokeredCgroupScopeApi.from_connected_socket(
            client, TOKEN, expected_peer_uid=os.getuid()
        )
        server.close()
        before = _fd_count()
        try:
            with self.assertRaises(BrokerUnavailable):
                api.release_child(
                    _receipt(), _permit(_receipt()), 4711, write_fd, TOKEN
                )
            self.assertEqual(_fd_count(), before - 1)
            os.write(write_fd, b"x")
            self.assertEqual(os.read(read_fd, 1), b"x")
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_capability_substitution_is_rejected_without_sending(self):
        api, server = self._connected_api()
        with self.assertRaisesRegex(BrokerUnavailable, "^command broker unavailable$"):
            api.create_scope(
                IDENTITY,
                b"r" * 32,
                BrokeredCgroupScopeToken(b"d" * 32),
            )
        self.assertEqual(server.recv(1), b"")
        server.close()

    def test_invalid_local_dataclass_is_redacted_and_connected_socket_is_closed(self):
        api, server = self._connected_api()
        with self.assertRaisesRegex(BrokerUnavailable, "^command broker unavailable$"):
            api.attach(object(), 4711, TOKEN)  # type: ignore[arg-type]
        self.assertEqual(server.recv(1), b"")
        server.close()

    def test_invalid_identity_is_redacted_and_connected_socket_is_closed(self):
        api, server = self._connected_api()
        server.settimeout(0.1)
        with self.assertRaisesRegex(BrokerUnavailable, "^command broker unavailable$"):
            api.create_scope(object(), b"r" * 32, TOKEN)  # type: ignore[arg-type]
        self.assertEqual(server.recv(1), b"")
        server.close()

    def test_connected_socket_is_one_shot_without_path_fallback(self):
        api, server = self._connected_api()
        with _Peer(server):
            api.create_scope(IDENTITY, b"r" * 32, TOKEN)

        with (
            patch.object(
                api,
                "_connect",
                side_effect=AssertionError("one-shot client attempted path fallback"),
            ) as connect,
            self.assertRaisesRegex(BrokerUnavailable, "^command broker unavailable$"),
        ):
            api.open_scope(IDENTITY, b"s" * 32, TOKEN)
        connect.assert_not_called()

    def test_rogue_nonroot_peer_never_receives_the_capability(self):
        if os.getuid() == 0:
            self.skipTest("requires a non-root peer identity")
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        api = UnixBrokeredCgroupScopeApi.from_connected_socket(client, TOKEN)
        received: list[bytes] = []

        def receive() -> None:
            try:
                received.append(server.recv(MAX_PACKET_BYTES))
            finally:
                server.close()

        receiver = threading.Thread(target=receive)
        receiver.start()
        try:
            with self.assertRaisesRegex(
                BrokerUnavailable, "^command broker unavailable$"
            ):
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            receiver.join(timeout=2.0)
            self.assertFalse(receiver.is_alive())
            self.assertEqual(received, [b""])
        finally:
            server.close()

    def test_client_does_not_query_peersec_on_systemd_activated_listener(self):
        original_getsockopt = socket.socket.getsockopt
        observed_options: list[int] = []

        def forbid_peersec(
            connection: socket.socket, level: int, option: int, *args: int
        ) -> int | bytes:
            observed_options.append(option)
            if level == socket.SOL_SOCKET and option == socket.SO_PEERSEC:
                raise AssertionError("client queried listener SO_PEERSEC")
            return original_getsockopt(connection, level, option, *args)

        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o750)
            socket_path = runtime / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            with (
                patch.object(broker_client_module, "_BROKER_SOCKET_UID", os.getuid()),
                patch.object(broker_client_module, "_BROKER_PEER_UID", os.getuid()),
                patch.object(
                    broker_client_module,
                    "_selinux_is_enforcing",
                    return_value=True,
                    create=True,
                ),
                patch.object(socket.socket, "getsockopt", new=forbid_peersec),
                _PathPeer(listener),
            ):
                api = UnixBrokeredCgroupScopeApi(socket_path, TOKEN)
                self.assertEqual(
                    api.create_scope(IDENTITY, b"r" * 32, TOKEN), _receipt()
                )
        self.assertIn(socket.SO_PEERCRED, observed_options)
        self.assertNotIn(socket.SO_PEERSEC, observed_options)

    def test_socket_group_may_be_a_supplementary_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o750)
            socket_path = runtime / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            socket_group = socket_path.stat().st_gid
            different_effective_group = socket_group + 1
            with (
                patch.object(broker_client_module, "_BROKER_SOCKET_UID", os.getuid()),
                patch.object(broker_client_module, "_BROKER_PEER_UID", os.getuid()),
                patch.object(os, "getegid", return_value=different_effective_group),
                patch.object(os, "getgroups", return_value=[socket_group]),
                _PathPeer(listener),
            ):
                api = UnixBrokeredCgroupScopeApi(socket_path, TOKEN)
                self.assertEqual(
                    api.create_scope(IDENTITY, b"r" * 32, TOKEN), _receipt()
                )

    def test_directory_and_socket_must_share_the_same_admitted_group(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o750)
            socket_path = runtime / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            runtime_status = runtime.stat()
            socket_status = socket_path.stat()
            effective_group = 41_001
            supplementary_group = 41_002
            runtime_fields = list(runtime_status)
            runtime_fields[5] = effective_group
            socket_fields = list(socket_status)
            socket_fields[5] = supplementary_group
            with (
                patch.object(broker_client_module, "_BROKER_SOCKET_UID", os.getuid()),
                patch.object(os, "getegid", return_value=effective_group),
                patch.object(os, "getgroups", return_value=[supplementary_group]),
                patch.object(
                    os,
                    "fstat",
                    side_effect=(
                        os.stat_result(runtime_fields),
                        os.stat_result(socket_fields),
                    ),
                ),
                _PathPeer(listener) as peer,
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ),
            ):
                api = UnixBrokeredCgroupScopeApi(socket_path, TOKEN)
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            self.assertIsNone(peer.request)

    def test_common_socket_group_must_belong_to_the_process(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o750)
            socket_path = runtime / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            socket_group = socket_path.stat().st_gid
            with (
                patch.object(broker_client_module, "_BROKER_SOCKET_UID", os.getuid()),
                patch.object(os, "getegid", return_value=socket_group + 1),
                patch.object(os, "getgroups", return_value=[socket_group + 2]),
                _PathPeer(listener) as peer,
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ),
            ):
                api = UnixBrokeredCgroupScopeApi(socket_path, TOKEN)
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            self.assertIsNone(peer.request)

    def test_production_path_must_be_absolute_bounded_socket_not_symlink(self):
        with self.assertRaises(ValueError):
            UnixBrokeredCgroupScopeApi(Path("relative.sock"), TOKEN)
        with self.assertRaises(ValueError):
            UnixBrokeredCgroupScopeApi(Path("/" + "x" * 108), TOKEN)

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.sock"
            alias = Path(directory) / "alias.sock"
            target.touch()
            alias.symlink_to(target)
            api = UnixBrokeredCgroupScopeApi(alias, TOKEN)
            with self.assertRaisesRegex(
                BrokerUnavailable, "^command broker unavailable$"
            ):
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)

    def test_ancestor_symlink_is_rejected_before_capability_is_sent(self):
        before = _fd_count()
        with tempfile.TemporaryDirectory() as directory:
            real_runtime = Path(directory) / "runtime"
            real_runtime.mkdir(mode=0o750)
            socket_path = real_runtime / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o660)
            listener.listen(1)
            alias = Path(directory) / "alias"
            alias.symlink_to(real_runtime, target_is_directory=True)

            with (
                patch.object(
                    broker_client_module,
                    "_BROKER_SOCKET_UID",
                    os.getuid(),
                    create=True,
                ),
                patch.object(broker_client_module, "_BROKER_PEER_UID", os.getuid()),
                _PathPeer(listener) as peer,
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ),
            ):
                api = UnixBrokeredCgroupScopeApi(alias / "control.sock", TOKEN)
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            self.assertIsNone(peer.request)
        self.assertEqual(_fd_count(), before)

    def test_socket_swap_connects_only_to_the_anchored_inode(self):
        before = _fd_count()
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o750)
            socket_path = runtime / "control.sock"
            anchored_path = runtime / "anchored.sock"
            legitimate = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            legitimate.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o660)
            legitimate.listen(1)
            rogue = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            original_connect = socket.socket.connect
            swapped = False

            def swap_before_connect(
                connection: socket.socket, address: str | bytes
            ) -> None:
                nonlocal swapped
                if not swapped:
                    swapped = True
                    socket_path.rename(anchored_path)
                    rogue.bind(os.fspath(socket_path))
                    os.chmod(socket_path, 0o660)
                    rogue.listen(1)
                original_connect(connection, address)

            try:
                with (
                    patch.object(
                        broker_client_module,
                        "_BROKER_SOCKET_UID",
                        os.getuid(),
                        create=True,
                    ),
                    patch.object(broker_client_module, "_BROKER_PEER_UID", os.getuid()),
                    patch.object(socket.socket, "connect", new=swap_before_connect),
                    _PathPeer(legitimate) as peer,
                ):
                    api = UnixBrokeredCgroupScopeApi(socket_path, TOKEN)
                    receipt = api.create_scope(IDENTITY, b"r" * 32, TOKEN)
                self.assertEqual(receipt, _receipt())
                self.assertIsNotNone(peer.request)
                rogue.settimeout(0.05)
                with self.assertRaises(TimeoutError):
                    rogue.accept()
            finally:
                rogue.close()
        self.assertEqual(_fd_count(), before)

    def test_socket_mode_contract_is_checked_before_capability_is_sent(self):
        before = _fd_count()
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime"
            runtime.mkdir(mode=0o750)
            socket_path = runtime / "control.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            listener.bind(os.fspath(socket_path))
            os.chmod(socket_path, 0o666)
            listener.listen(1)
            with (
                patch.object(
                    broker_client_module,
                    "_BROKER_SOCKET_UID",
                    os.getuid(),
                    create=True,
                ),
                patch.object(broker_client_module, "_BROKER_PEER_UID", os.getuid()),
                _PathPeer(listener) as peer,
                self.assertRaisesRegex(
                    BrokerUnavailable, "^command broker unavailable$"
                ),
            ):
                api = UnixBrokeredCgroupScopeApi(socket_path, TOKEN)
                api.create_scope(IDENTITY, b"r" * 32, TOKEN)
            self.assertIsNone(peer.request)
        self.assertEqual(_fd_count(), before)


if __name__ == "__main__":
    unittest.main()
