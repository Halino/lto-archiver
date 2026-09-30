from __future__ import annotations

import argparse
import os
import pwd
import socket
import stat
import threading
from collections.abc import Callable, Mapping, Sequence
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path

from ltobackup.linux_settings import LinuxSettings, load_linux_settings
from ltobackup.operational_log import (
    JournalOperationalEventSink,
    OperationalEvent,
    OperationalSeverity,
    OperationalSource,
)
from ltobackup.shares import EndpointPolicy
from ltobackup.systemd_activation import activated_unix_listener

from .linux_systemd import LinuxSystemdManager
from .service import ShareBrokerService
from .store import CredentialStore
from .systemd import ProcMountInfoProbe, SystemdMountAdapter

_SYSTEMD_LISTEN_FD = 3
DEFAULT_SOCKET_PATH = Path("/run/lto-archiver-share-broker/control.sock")
DEFAULT_STATE_ROOT = Path("/var/lib/lto-archiver-share-broker")
DEFAULT_CREDENTIAL_ROOT = Path("/etc/lto-archiver/share-credentials")
_CREDENTIAL_DIRECTORY = Path("/run/credentials/lto-archiver-share-broker.service")


def load_systemd_credential(path: Path) -> bytes:
    descriptor: int | None = None
    try:
        candidate = Path(path)
        if not candidate.is_absolute():
            raise RuntimeError
        descriptor = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        status = os.fstat(descriptor)
        value = os.read(descriptor, 33)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or stat.S_IMODE(status.st_mode) != 0o400
            or len(value) != 32
            or os.read(descriptor, 1)
        ):
            raise RuntimeError
        return value
    except (OSError, RuntimeError, TypeError, ValueError):
        raise RuntimeError("share broker credential unavailable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def activated_listener(
    environ: Mapping[str, str] | None = None,
    *,
    expected_gid: int,
    fd: int = _SYSTEMD_LISTEN_FD,
) -> socket.socket:
    if not _trusted_socket_parent(DEFAULT_SOCKET_PATH.parent, expected_gid):
        raise RuntimeError("share broker activation unavailable")
    return activated_unix_listener(
        fd,
        os.environ if environ is None else environ,
        socket_type=socket.SOCK_SEQPACKET,
        fd_name="share-broker",
        expected_uid=0,
        expected_gid=expected_gid,
        expected_mode=0o660,
        expected_path=DEFAULT_SOCKET_PATH,
    )


def _trusted_socket_parent(path: Path, expected_gid: int) -> bool:
    try:
        status = os.stat(path, follow_symlinks=False)
        return (
            path.is_absolute()
            and stat.S_ISDIR(status.st_mode)
            and status.st_uid == 0
            and status.st_gid == expected_gid
            and stat.S_IMODE(status.st_mode) == 0o750
        )
    except (OSError, TypeError, ValueError):
        return False


def serve_activated(
    service: ShareBrokerService,
    *,
    daemon_gid: int,
    stop: threading.Event | None = None,
    environ: Mapping[str, str] | None = None,
) -> None:
    if type(service) is not ShareBrokerService:
        raise RuntimeError("share broker service unavailable")
    stop_event = stop or threading.Event()
    with activated_listener(environ, expected_gid=daemon_gid) as listener:
        listener.settimeout(1.0)
        service.serve(listener, stop_event)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lto-archiver-share-broker")
    parser.add_argument(
        "--config", type=Path, default=Path("/etc/lto-archiver/config.toml")
    )
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET_PATH)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    parser.add_argument("--credential-root", type=Path, default=DEFAULT_CREDENTIAL_ROOT)
    parser.add_argument(
        "--capability-file",
        type=Path,
        default=_CREDENTIAL_DIRECTORY / "share-broker-capability",
    )
    parser.add_argument(
        "--proof-key-file",
        type=Path,
        default=_CREDENTIAL_DIRECTORY / "share-broker-proof-key",
    )
    parser.add_argument(
        "--store-request-key-file",
        type=Path,
        default=_CREDENTIAL_DIRECTORY / "share-store-request-key",
    )
    parser.add_argument("--daemon-user", default="lto-archiver")
    parser.add_argument("--fence-all", action="store_true")
    return parser


def _resolve_endpoint(server: str) -> tuple[IPv4Address | IPv6Address, ...]:
    return tuple(
        sorted(
            {
                ip_address(result[4][0])
                for result in socket.getaddrinfo(
                    server,
                    None,
                    type=socket.SOCK_STREAM,
                )
            },
            key=str,
        )
    )


def build_service(
    args: argparse.Namespace,
    *,
    settings: LinuxSettings | None = None,
    credential_loader: Callable[[Path], bytes] = load_systemd_credential,
    resolver: Callable[[str], Sequence[IPv4Address | IPv6Address]] = _resolve_endpoint,
) -> ShareBrokerService:
    if Path(args.socket) != DEFAULT_SOCKET_PATH:
        raise RuntimeError("share broker runtime unavailable")
    configured = settings or load_linux_settings(args.config)
    configured.validate()
    identity = pwd.getpwnam(args.daemon_user)
    capability = credential_loader(args.capability_file)
    proof_key = credential_loader(args.proof_key_file)
    store_request_key = credential_loader(args.store_request_key_file)
    if len({capability, proof_key, store_request_key}) != 3:
        raise RuntimeError("share broker credential unavailable")
    store = CredentialStore(
        args.state_root,
        credential_root=args.credential_root,
        request_key=store_request_key,
    )
    manager = LinuxSystemdManager()
    mounts = SystemdMountAdapter(
        manager,
        ProcMountInfoProbe(),
        managed_root=configured.managed_source_mount_root,
        service_uid=identity.pw_uid,
        service_gid=identity.pw_gid,
    )
    return ShareBrokerService(
        store,
        mounts,
        capability=capability,
        proof_key=proof_key,
        daemon_uid=identity.pw_uid,
        daemon_gid=identity.pw_gid,
        endpoint_policy=EndpointPolicy(
            tuple(configured.share_endpoint_cidrs),
            tuple(configured.share_endpoint_dns_suffixes),
        ),
        resolver=resolver,
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    events = JournalOperationalEventSink(
        syslog_identifier="lto-archiver-share-broker"
    )
    if os.geteuid() != 0:
        raise RuntimeError("share broker runtime unavailable")
    try:
        events.emit(
            OperationalEvent(
                OperationalSource.SHARE_BROKER,
                OperationalSeverity.INFO,
                "share_broker.started",
                "Share broker started.",
            )
        )
        identity = pwd.getpwnam(args.daemon_user)
        service = build_service(args)
        if args.fence_all:
            service.fence_all()
        else:
            serve_activated(service, daemon_gid=identity.pw_gid)
    except (KeyError, OSError, RuntimeError, TypeError, ValueError):
        events.emit(
            OperationalEvent(
                OperationalSource.SHARE_BROKER,
                OperationalSeverity.ERROR,
                "share_broker.failed",
                "Share broker failed.",
            )
        )
        raise RuntimeError("share broker runtime unavailable") from None
    events.emit(
        OperationalEvent(
            OperationalSource.SHARE_BROKER,
            OperationalSeverity.INFO,
            "share_broker.stopped",
            "Share broker stopped.",
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
