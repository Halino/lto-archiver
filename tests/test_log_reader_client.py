from __future__ import annotations

import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from ltobackup.log_reader.client import (
    JournalReaderUnavailable,
    UnixJournalReaderClient,
)
from ltobackup.log_reader.main import activated_listener, build_parser
from ltobackup.log_reader.protocol import (
    JournalEntry,
    JournalPage,
    JournalQuery,
    LogDirection,
    LogRange,
    LogSource,
    Severity,
    decode_request,
    encode_response,
)


def query() -> JournalQuery:
    return JournalQuery(
        LogSource.DAEMON, Severity.INFO, LogRange.ONE_HOUR, LogDirection.OLDER, None, 50
    )


def page() -> JournalPage:
    return JournalPage(
        entries=(
            JournalEntry(
                "cursor-1",
                "2026-09-04T10:11:12Z",
                LogSource.DAEMON,
                Severity.INFO,
                "lto-archiverd.service",
                "safe",
            ),
        ),
        older_cursor="cursor-1",
        newer_cursor=None,
        cursor_rotated=False,
    )


class UnixJournalReaderClientTests(unittest.TestCase):
    def test_reader_cli_accepts_only_the_inherited_socket_descriptor(self) -> None:
        self.assertEqual(3, build_parser().parse_args([]).socket_fd)
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--socket", "3"])
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--socket-fd", "4"])
        with self.assertRaises(RuntimeError):
            activated_listener(
                3,
                {
                    "LISTEN_PID": str(os.getpid()),
                    "LISTEN_FDS": "1",
                    "LISTEN_FDNAMES": "wrong-name",
                },
            )
        with self.assertRaises(RuntimeError):
            activated_listener(
                4,
                {
                    "LISTEN_PID": str(os.getpid()),
                    "LISTEN_FDS": "1",
                    "LISTEN_FDNAMES": "log-reader",
                },
            )

    def test_client_preserves_rotated_page_and_rejects_wrong_peer_identity(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)

            def server() -> None:
                with listener.accept()[0] as connection:
                    connection.recv(4096)
                    connection.sendall(
                        encode_response(JournalPage((), None, None, True))
                    )
                    connection.shutdown(socket.SHUT_WR)

            thread = threading.Thread(target=server)
            thread.start()
            client = UnixJournalReaderClient(
                path, expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid()
            )
            self.assertTrue(client.query(query()).cursor_rotated)
            thread.join()
            listener.close()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)
            thread = threading.Thread(target=lambda: listener.accept()[0].close())
            thread.start()
            client = UnixJournalReaderClient(
                path, expected_peer_uid=os.getuid() + 1, expected_peer_gid=os.getgid()
            )
            with self.assertRaises(JournalReaderUnavailable):
                client.query(query())
            thread.join()
            listener.close()

    def test_client_preserves_partial_source_unavailability_from_wire(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)

            def server() -> None:
                with listener.accept()[0] as connection:
                    connection.recv(4096)
                    connection.sendall(
                        encode_response(
                            JournalPage(
                                (),
                                None,
                                None,
                                False,
                                unavailable_sources=(LogSource.LTFS,),
                            )
                        )
                    )
                    connection.shutdown(socket.SHUT_WR)

            thread = threading.Thread(target=server)
            thread.start()
            client = UnixJournalReaderClient(
                path, expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid()
            )
            self.assertEqual(
                (LogSource.LTFS,), client.query(query()).unavailable_sources
            )
            thread.join()
            listener.close()

    def test_queries_real_unix_stream_and_validates_one_response(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "reader.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(str(path))
            listener.listen(1)
            errors: list[BaseException] = []

            def server() -> None:
                try:
                    with listener.accept()[0] as connection:
                        header = connection.recv(4)
                        request = connection.recv(int.from_bytes(header, "big"))
                        self.assertEqual(query(), decode_request(header + request))
                        self.assertEqual(b"", connection.recv(1))
                        connection.sendall(encode_response(page()))
                        connection.shutdown(socket.SHUT_WR)
                except BaseException as exc:  # noqa: BLE001 - capture test thread failure
                    errors.append(exc)

            thread = threading.Thread(target=server)
            thread.start()
            client = UnixJournalReaderClient(
                path, expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid()
            )
            self.assertEqual(page(), client.query(query()))
            thread.join()
            listener.close()
            self.assertEqual([], errors)

    def test_rejects_truncated_or_extra_frames_without_accepting_a_page(self) -> None:
        for payload in (b"\x00\x00", encode_response(page()) + encode_response(page())):
            with (
                self.subTest(payload=payload),
                tempfile.TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "reader.sock"
                listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                listener.bind(str(path))
                listener.listen(1)

                def server(
                    current_listener: socket.socket = listener,
                    current_payload: bytes = payload,
                ) -> None:
                    with current_listener.accept()[0] as connection:
                        connection.recv(4096)
                        connection.sendall(current_payload)
                        connection.shutdown(socket.SHUT_WR)

                thread = threading.Thread(target=server)
                thread.start()
                client = UnixJournalReaderClient(
                    path, expected_peer_uid=os.getuid(), expected_peer_gid=os.getgid()
                )
                with self.assertRaises(JournalReaderUnavailable):
                    client.query(query())
                thread.join()
                listener.close()


if __name__ == "__main__":
    unittest.main()
