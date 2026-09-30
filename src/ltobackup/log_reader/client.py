from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

from .protocol import (
    MAX_FRAME_BYTES,
    JournalPage,
    JournalQuery,
    ProtocolError,
    decode_response,
    encode_request,
)


class JournalReaderUnavailable(RuntimeError):
    """A closed error at the daemon-to-reader trust boundary."""

    def __init__(self) -> None:
        super().__init__("journal reader unavailable")


class UnixJournalReaderClient:
    """The daemon's fixed-timeout client for the root journal reader."""

    def __init__(
        self,
        socket_path: Path,
        *,
        expected_peer_uid: int = 0,
        expected_peer_gid: int = 0,
        timeout: float = 6.0,
    ) -> None:
        path = Path(socket_path)
        if (
            not path.is_absolute()
            or "\0" in str(path)
            or len(str(path).encode()) > 107
            or type(expected_peer_uid) is not int
            or type(expected_peer_gid) is not int
            or min(expected_peer_uid, expected_peer_gid) < 0
            or type(timeout) not in (int, float)
            or type(timeout) is bool
            or float(timeout) != 6.0
        ):
            raise ValueError("invalid journal reader client policy")
        self.socket_path = path
        self.expected_peer_uid = expected_peer_uid
        self.expected_peer_gid = expected_peer_gid
        self.timeout = 6.0

    def query(self, request: JournalQuery) -> JournalPage:
        try:
            packet = encode_request(request)
            deadline = time.monotonic() + self.timeout
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                _set_remaining_timeout(connection, deadline)
                connection.connect(str(self.socket_path))
                self._verify_peer(connection)
                _set_remaining_timeout(connection, deadline)
                connection.sendall(packet)
                connection.shutdown(socket.SHUT_WR)
                response = _read_frame(connection, deadline)
                _set_remaining_timeout(connection, deadline)
                if connection.recv(1):
                    raise ProtocolError
            return decode_response(response)
        except Exception:  # noqa: BLE001 - redact the complete local IPC boundary
            raise JournalReaderUnavailable from None

    def _verify_peer(self, connection: socket.socket) -> None:
        size = struct.calcsize("3i")
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, size)
        if type(raw) is not bytes or len(raw) != size:
            raise ProtocolError
        pid, uid, gid = struct.unpack("3i", raw)
        if pid <= 0 or uid != self.expected_peer_uid or gid != self.expected_peer_gid:
            raise ProtocolError


def _read_frame(connection: socket.socket, deadline: float) -> bytes:
    header = _read_exact(connection, 4, deadline)
    length = int.from_bytes(header, "big")
    if not 0 < length <= MAX_FRAME_BYTES:
        raise ProtocolError
    return header + _read_exact(connection, length, deadline)


def _read_exact(connection: socket.socket, length: int, deadline: float) -> bytes:
    parts: list[bytes] = []
    remaining = length
    while remaining:
        _set_remaining_timeout(connection, deadline)
        chunk = connection.recv(remaining)
        if not chunk:
            raise ProtocolError
        parts.append(chunk)
        remaining -= len(chunk)
    return b"".join(parts)


def _set_remaining_timeout(connection: socket.socket, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    connection.settimeout(remaining)
