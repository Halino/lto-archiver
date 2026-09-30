from __future__ import annotations

import hmac
import secrets
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from ltobackup.shares import ShareConfig

from .protocol import (
    MAX_FRAME_BYTES,
    ShareBrokerProtocolError,
    ShareMountReceiptV1,
    decode_request,
    decode_response,
    encode_request,
)


class ShareBrokerUnavailable(RuntimeError):
    def __init__(self, safe_error_code: str = "share_broker_unavailable") -> None:
        self.safe_error_code = safe_error_code
        super().__init__(safe_error_code)


@dataclass(frozen=True)
class CredentialStatus:
    share_id: str
    generation: int
    configured: bool


class ShareBrokerClient:
    """Typed daemon client for the closed privileged share broker."""

    def __init__(
        self,
        socket_path: Path,
        *,
        capability: bytes,
        proof_key: bytes,
        timeout: float = 90.0,
        expected_peer_uid: int = 0,
        expected_peer_gid: int = 0,
    ) -> None:
        self.socket_path = Path(socket_path)
        if (
            not self.socket_path.is_absolute()
            or len(str(self.socket_path).encode()) > 107
            or type(capability) is not bytes
            or len(capability) != 32
            or type(proof_key) is not bytes
            or len(proof_key) != 32
            or hmac.compare_digest(capability, proof_key)
            or type(timeout) not in {int, float}
            or type(timeout) is bool
            or not 0 < float(timeout) <= 600
            or type(expected_peer_uid) is not int
            or not 0 <= expected_peer_uid < 1 << 32
            or type(expected_peer_gid) is not int
            or not 0 <= expected_peer_gid < 1 << 32
        ):
            raise ValueError("invalid share broker client policy")
        self._capability = bytes(capability)
        self._proof_key = bytes(proof_key)
        self.timeout = float(timeout)
        self.expected_peer_uid = expected_peer_uid
        self.expected_peer_gid = expected_peer_gid

    def install_smb_credential(
        self,
        share_id: str,
        credential_generation: int,
        *,
        username: str,
        password: str,
        domain: str | None = None,
    ) -> CredentialStatus:
        result = self._exchange(
            "credential.install",
            {
                "share_id": share_id,
                "credential_generation": credential_generation,
                "username": username,
                "domain": domain,
                "password": password,
            },
        )
        return CredentialStatus(
            result["share_id"], result["generation"], result["configured"]
        )

    def assert_ready(self) -> None:
        result = self._exchange("broker.ready", {})
        if (
            frozenset(result) != {"schema", "ready"}
            or type(result["schema"]) is not int
            or result["schema"] != 1
            or result["ready"] is not True
        ):
            raise ShareBrokerUnavailable

    def delete_smb_credential(
        self, share_id: str, credential_generation: int
    ) -> CredentialStatus:
        result = self._exchange(
            "credential.delete",
            {
                "share_id": share_id,
                "credential_generation": credential_generation,
            },
        )
        return CredentialStatus(
            result["share_id"], result["generation"], result["configured"]
        )

    def inspect_credential(self, share_id: str) -> CredentialStatus:
        result = self._exchange("credential.inspect", {"share_id": share_id})
        return CredentialStatus(
            result["share_id"], result["generation"], result["configured"]
        )

    def mount(
        self,
        share_id: str,
        config: ShareConfig,
        *,
        config_revision: int,
        credential_generation: int,
        admitted_addresses: tuple[str, ...],
    ) -> ShareMountReceiptV1:
        return self._receipt_exchange(
            "mount.start",
            {
                "share_id": share_id,
                "config": config,
                "config_revision": config_revision,
                "credential_generation": credential_generation,
                "admitted_addresses": admitted_addresses,
            },
        )

    def unmount(
        self,
        share_id: str,
    ) -> ShareMountReceiptV1:
        return self._receipt_exchange(
            "mount.stop",
            {"share_id": share_id},
        )

    def inspect(
        self,
        share_id: str,
        config: ShareConfig | None = None,
        *,
        config_revision: int | None = None,
        credential_generation: int | None = None,
        admitted_addresses: tuple[str, ...] | None = None,
    ) -> ShareMountReceiptV1:
        params: dict[str, object] = {"share_id": share_id}
        candidates = (
            config,
            config_revision,
            credential_generation,
            admitted_addresses,
        )
        if any(value is not None for value in candidates):
            if any(value is None for value in candidates):
                raise ShareBrokerUnavailable
            params.update(
                config=config,
                config_revision=config_revision,
                credential_generation=credential_generation,
                admitted_addresses=admitted_addresses,
            )
        return self._receipt_exchange(
            "mount.inspect",
            params,
        )

    def fence_unknown_mounts(self, known_share_ids: tuple[str, ...]) -> int:
        result = self._exchange("mount.fence", {"known_share_ids": known_share_ids})
        count = result.get("fenced_count")
        if type(count) is not int or count < 0:
            raise ShareBrokerUnavailable
        return count

    def _receipt_exchange(
        self, action: str, params: dict[str, object]
    ) -> ShareMountReceiptV1:
        result = self._exchange(action, params)
        receipt = result.get("receipt")
        if type(receipt) is not ShareMountReceiptV1:
            raise ShareBrokerUnavailable
        return receipt

    def _exchange(self, action: str, params: dict[str, object]) -> dict[str, object]:
        request_id = secrets.token_bytes(32)
        nonce = secrets.token_bytes(32)
        try:
            packet = encode_request(
                action,
                request_id=request_id,
                nonce=nonce,
                capability=self._capability,
                params=params,
            )
            semantic = decode_request(packet, capability=self._capability)
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.socket_path))
                self._verify_peer(connection)
                if connection.send(packet) != len(packet):
                    raise ShareBrokerProtocolError
                response_packet, ancillary, flags, _address = connection.recvmsg(
                    MAX_FRAME_BYTES + 5, 1
                )
                if (
                    not response_packet
                    or ancillary
                    or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                    or len(response_packet) > MAX_FRAME_BYTES + 4
                ):
                    raise ShareBrokerProtocolError
            response = decode_response(response_packet, proof_key=self._proof_key)
            if response.action != action or not hmac.compare_digest(
                response.request_id, request_id
            ):
                raise ShareBrokerProtocolError
            if response.error_code is not None:
                raise ShareBrokerUnavailable(response.error_code)
            if response.result is None:
                raise ShareBrokerProtocolError
            receipt = response.result.get("receipt")
            if type(receipt) is ShareMountReceiptV1 and not hmac.compare_digest(
                receipt.request_sha256, semantic.request_sha256
            ):
                raise ShareBrokerProtocolError
            return response.result
        except ShareBrokerUnavailable:
            raise
        except Exception:  # noqa: BLE001 - redact the complete local IPC boundary
            raise ShareBrokerUnavailable from None

    def _verify_peer(self, connection: socket.socket) -> None:
        size = struct.calcsize("3i")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ShareBrokerProtocolError
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0 or uid != self.expected_peer_uid or gid != self.expected_peer_gid:
            raise ShareBrokerProtocolError
