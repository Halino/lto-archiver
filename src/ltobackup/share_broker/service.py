from __future__ import annotations

import hmac
import secrets
import socket
import struct
import threading
from collections import deque
from collections.abc import Callable, Sequence
from ipaddress import IPv4Address, IPv6Address

from ltobackup.shares import (
    EndpointPolicy,
    NfsShareConfig,
    SmbShareConfig,
)

from .protocol import (
    MAX_FRAME_BYTES,
    ShareBrokerProtocolError,
    ShareBrokerRequest,
    decode_request,
    encode_response,
    issue_mount_receipt,
)
from .store import CredentialConflict, CredentialStore, CredentialStoreError
from .systemd import (
    SystemdMountAdapter,
    SystemdMountError,
    source_identity_sha256,
)

_MAX_REPLAY_NONCES = 16_384


class ShareBrokerService:
    """Authenticated closed broker service for one trusted daemon identity."""

    def __init__(
        self,
        store: CredentialStore,
        mounts: SystemdMountAdapter,
        *,
        capability: bytes,
        proof_key: bytes,
        daemon_uid: int,
        daemon_gid: int,
        endpoint_policy: EndpointPolicy,
        resolver: Callable[[str], Sequence[IPv4Address | IPv6Address]],
        connection_timeout: float = 30.0,
    ) -> None:
        if (
            type(capability) is not bytes
            or len(capability) != 32
            or type(proof_key) is not bytes
            or len(proof_key) != 32
            or hmac.compare_digest(capability, proof_key)
            or type(daemon_uid) is not int
            or type(daemon_gid) is not int
            or not 0 <= daemon_uid < 1 << 32
            or not 0 <= daemon_gid < 1 << 32
            or type(connection_timeout) not in {int, float}
            or type(connection_timeout) is bool
            or not 0 < float(connection_timeout) <= 600
            or not isinstance(endpoint_policy, EndpointPolicy)
            or not callable(resolver)
        ):
            raise ValueError("invalid share broker policy")
        self.store = store
        self.mounts = mounts
        self._capability = bytes(capability)
        self._proof_key = bytes(proof_key)
        self.daemon_uid = daemon_uid
        self.daemon_gid = daemon_gid
        self.connection_timeout = float(connection_timeout)
        self.endpoint_policy = endpoint_policy
        self._resolver = resolver
        self._seen: set[tuple[bytes, bytes]] = set()
        self._seen_order: deque[tuple[bytes, bytes]] = deque()
        self._lock = threading.Lock()

    def fence_all(self) -> int:
        """Unmount durable bindings, reconcile the store, then fence orphans."""

        fenced = 0
        for binding in self.store.mount_bindings():
            if not binding.mounted:
                continue
            self.mounts.unmount(binding.share_id)
            self.store.mark_unmounted(
                binding.share_id,
                expected_mount_identity_sha256=binding.mount_identity_sha256,
            )
            fenced += 1
        return fenced + self.mounts.fence_unknown_units(())

    def handle_packet(self, packet: bytes, *, peer_uid: int, peer_gid: int) -> bytes:
        if peer_uid != self.daemon_uid or peer_gid != self.daemon_gid:
            raise PermissionError("share broker authentication denied")
        request = decode_request(packet, capability=self._capability)
        self._consume_nonce(request)
        try:
            result = self._dispatch(request)
            return encode_response(
                request.action,
                request_id=request.request_id,
                proof_key=self._proof_key,
                result=result,
            )
        except CredentialConflict:
            return encode_response(
                request.action,
                request_id=request.request_id,
                proof_key=self._proof_key,
                error_code="share_state_conflict",
            )
        except CredentialStoreError:
            return encode_response(
                request.action,
                request_id=request.request_id,
                proof_key=self._proof_key,
                error_code="share_broker_unavailable",
            )
        except SystemdMountError as exc:
            return encode_response(
                request.action,
                request_id=request.request_id,
                proof_key=self._proof_key,
                error_code=exc.safe_error_code,
            )

    def handle_connection(self, connection: socket.socket) -> None:
        if (
            type(connection) is not socket.socket
            or connection.family != socket.AF_UNIX
            or connection.type & 0xF != socket.SOCK_SEQPACKET
        ):
            raise PermissionError("share broker authentication denied")
        connection.settimeout(self.connection_timeout)
        size = struct.calcsize("3i")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        if type(raw) is not bytes or len(raw) != size:
            raise PermissionError("share broker authentication denied")
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0:
            raise PermissionError("share broker authentication denied")
        packet, ancillary, flags, _address = connection.recvmsg(MAX_FRAME_BYTES + 5, 1)
        if (
            not packet
            or ancillary
            or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or len(packet) > MAX_FRAME_BYTES + 4
        ):
            raise ShareBrokerProtocolError
        response = self.handle_packet(packet, peer_uid=uid, peer_gid=gid)
        if connection.send(response) != len(response):
            raise ShareBrokerProtocolError

    def serve(self, listener: socket.socket, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                connection, _address = listener.accept()
            except TimeoutError:
                continue
            with connection:
                try:
                    self.handle_connection(connection)
                except Exception:  # noqa: BLE001,S112 - redact peer boundary
                    # No unauthenticated diagnostic crosses the root boundary.
                    continue

    def _consume_nonce(self, request: ShareBrokerRequest) -> None:
        key = (request.request_id, request.nonce)
        with self._lock:
            if key in self._seen or any(
                hmac.compare_digest(request.request_id, request_id)
                or hmac.compare_digest(request.nonce, nonce)
                for request_id, nonce in self._seen
            ):
                raise PermissionError("share broker authentication denied")
            self._seen.add(key)
            self._seen_order.append(key)
            while len(self._seen_order) > _MAX_REPLAY_NONCES:
                self._seen.discard(self._seen_order.popleft())

    def _dispatch(self, request: ShareBrokerRequest) -> dict[str, object]:
        params = request.params
        if request.action == "broker.ready":
            self.mounts.assert_ready()
            return {"schema": 1, "ready": True}
        if request.action == "credential.install":
            state = self.store.install(
                params["share_id"],
                params["credential_generation"],
                username=params["username"],
                domain=params["domain"],
                password=params["password"],
            )
            return {
                "share_id": state.share_id,
                "generation": state.generation,
                "configured": state.configured,
            }
        if request.action == "credential.delete":
            state = self.store.delete(
                params["share_id"], params["credential_generation"]
            )
            return {
                "share_id": state.share_id,
                "generation": state.generation,
                "configured": state.configured,
            }
        if request.action == "credential.inspect":
            state = self.store.state(params["share_id"])
            return {
                "share_id": params["share_id"],
                "generation": 0 if state is None else state.generation,
                "configured": False if state is None else state.configured,
            }
        if request.action == "mount.fence":
            return {
                "fenced_count": self.mounts.fence_unknown_units(
                    params["known_share_ids"]
                )
            }
        return {"receipt": self._mount_action(request)}

    def _mount_action(self, request: ShareBrokerRequest):
        params = request.params
        share_id = params["share_id"]
        unit_name = self.mounts.unit_name(share_id)
        binding = self.store.mount_binding(share_id)
        if request.action != "mount.start":
            candidate_inspect = request.action == "mount.inspect" and "config" in params
            if binding is None and candidate_inspect:
                config = params["config"]
                config_revision = params["config_revision"]
                credential_generation = params["credential_generation"]
            elif binding is None:
                raise CredentialConflict
            else:
                config = binding.config
                config_revision = binding.config_revision
                credential_generation = binding.credential_generation
                if candidate_inspect and (
                    params["config"] != config
                    or params["config_revision"] != config_revision
                    or params["credential_generation"] != credential_generation
                ):
                    if (
                        binding.mounted
                        or params["config_revision"] < binding.config_revision
                        or params["credential_generation"]
                        < binding.credential_generation
                        or (
                            params["config_revision"] == binding.config_revision
                            and params["config"] != binding.config
                        )
                    ):
                        raise CredentialConflict
                    config = params["config"]
                    config_revision = params["config_revision"]
                    credential_generation = params["credential_generation"]
        else:
            config = params["config"]
            config_revision = params["config_revision"]
            credential_generation = params["credential_generation"]
        if request.action == "mount.stop":
            admitted_addresses: tuple[str, ...] = ()
        else:
            admitted_addresses = self._admit_endpoint(
                config,
                presented=(
                    params["admitted_addresses"]
                    if request.action == "mount.start" or "admitted_addresses" in params
                    else None
                ),
            )
        admitted_address = admitted_addresses[0] if admitted_addresses else None
        try:
            if request.action == "mount.stop":
                if binding is not None and binding.mounted:
                    self.mounts.unmount(share_id)
                    binding = self.store.mark_unmounted(
                        share_id,
                        expected_mount_identity_sha256=binding.mount_identity_sha256,
                    )
                elif self.mounts.inspect(share_id, config) is not None:
                    raise SystemdMountError("share_identity_changed")
                return issue_mount_receipt(
                    action=request.action,
                    share_id=share_id,
                    request_sha256=request.request_sha256,
                    config_revision=config_revision,
                    credential_generation=credential_generation,
                    unit_name=unit_name,
                    mount_identity_sha256=None,
                    read_only=False,
                    result="unmounted",
                    safe_error_code=None,
                    broker_nonce=secrets.token_bytes(32),
                    proof_key=self._proof_key,
                    endpoint_server=config.server,
                    admitted_addresses=admitted_addresses,
                    filesystem_type=None,
                    source_sha256=None,
                )
            if request.action == "mount.inspect":
                evidence = self.mounts.inspect(
                    share_id, config, admitted_address=admitted_address
                )
                if binding is not None and binding.mounted:
                    if evidence is None:
                        binding = self.store.mark_unmounted(
                            share_id,
                            expected_mount_identity_sha256=(
                                binding.mount_identity_sha256
                            ),
                        )
                        result = "unmounted"
                    elif evidence.identity_sha256 != binding.mount_identity_sha256:
                        raise SystemdMountError("share_identity_changed")
                    else:
                        result = "mounted"
                elif binding is not None:
                    if evidence is not None:
                        raise SystemdMountError("share_identity_changed")
                    result = "unmounted"
                else:
                    if evidence is not None:
                        raise SystemdMountError("share_identity_changed")
                    result = "unmounted"
            else:
                if binding is not None and binding.mounted:
                    if (
                        binding.config != config
                        or binding.config_revision != config_revision
                        or binding.credential_generation != credential_generation
                    ):
                        raise CredentialConflict
                    evidence = self.mounts.inspect(
                        share_id,
                        binding.config,
                        admitted_address=admitted_address,
                    )
                    if (
                        evidence is None
                        or evidence.identity_sha256 != binding.mount_identity_sha256
                    ):
                        raise SystemdMountError("share_identity_changed")
                else:
                    credential_path = None
                    if type(config) is SmbShareConfig:
                        try:
                            credential_path = self.store.credential_path(
                                share_id, credential_generation
                            )
                        except CredentialConflict:
                            raise SystemdMountError(
                                "share_credentials_required"
                            ) from None
                    elif type(config) is NfsShareConfig and credential_generation != 0:
                        raise SystemdMountError("share_identity_changed")
                    evidence = self.mounts.mount(
                        share_id,
                        config,
                        credential_path=credential_path,
                        admitted_address=admitted_address,
                    )
                    try:
                        binding = self.store.record_mount(
                            share_id,
                            config,
                            config_revision=config_revision,
                            credential_generation=credential_generation,
                            mount_identity_sha256=evidence.identity_sha256,
                        )
                    except (CredentialConflict, CredentialStoreError):
                        self.mounts.unmount(share_id)
                        raise
                result = "mounted"
            return issue_mount_receipt(
                action=request.action,
                share_id=share_id,
                request_sha256=request.request_sha256,
                config_revision=config_revision,
                credential_generation=credential_generation,
                unit_name=unit_name,
                mount_identity_sha256=(
                    None if evidence is None else evidence.identity_sha256
                ),
                read_only=evidence is not None,
                result=result,
                safe_error_code=None,
                broker_nonce=secrets.token_bytes(32),
                proof_key=self._proof_key,
                endpoint_server=config.server,
                admitted_addresses=admitted_addresses,
                filesystem_type=(
                    None if evidence is None else evidence.filesystem_type
                ),
                source_sha256=(
                    None
                    if evidence is None
                    else source_identity_sha256(evidence.source)
                ),
            )
        except SystemdMountError as exc:
            safe_error = exc.safe_error_code
        return issue_mount_receipt(
            action=request.action,
            share_id=share_id,
            request_sha256=request.request_sha256,
            config_revision=config_revision,
            credential_generation=credential_generation,
            unit_name=unit_name,
            mount_identity_sha256=None,
            read_only=False,
            result="failed",
            safe_error_code=safe_error,
            broker_nonce=secrets.token_bytes(32),
            proof_key=self._proof_key,
            endpoint_server=config.server,
            admitted_addresses=admitted_addresses,
            filesystem_type=None,
            source_sha256=None,
        )

    def _admit_endpoint(
        self,
        config: NfsShareConfig | SmbShareConfig,
        *,
        presented: tuple[str, ...] | None,
    ) -> tuple[str, ...]:
        try:
            admitted = tuple(
                sorted(
                    self.endpoint_policy.admit(
                        config.server, self._resolver(config.server)
                    )
                )
            )
        except Exception:  # noqa: BLE001 - redact DNS/policy diagnostics
            raise SystemdMountError("share_endpoint_not_allowed") from None
        if presented is not None and tuple(sorted(presented)) != admitted:
            raise SystemdMountError("share_endpoint_not_allowed")
        return admitted
