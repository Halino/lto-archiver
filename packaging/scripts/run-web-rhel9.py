#!/usr/bin/python3.11
from __future__ import annotations

import argparse
import contextlib
import ipaddress
import os
import re
import stat
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

WEB_LAUNCHER = "/usr/bin/lto-archiver-web"
WEB_CONFIG = Path("/etc/lto-archiver/web.toml")
TLS_ROOT = Path("/etc/lto-archiver/tls")
AUTH_DATABASE = "/var/lib/lto-archiver-web/auth.sqlite3"
DAEMON_SOCKET = "/run/lto-archiver/daemon.sock"
EXACT_CIDRS = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
_EXPECTED_KEYS = frozenset(
    {
        "listen_host",
        "listen_port",
        "tls_certfile",
        "tls_keyfile",
        "firewall_zone",
        "allowed_ipv4_cidrs",
    }
)
_ZONE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}\Z")
_MAX_CONFIG_BYTES = 64 * 1024


@dataclass(frozen=True)
class WebRhel9Config:
    listen_host: ipaddress.IPv4Address
    listen_port: Literal[8443]
    tls_certfile: Path
    tls_keyfile: Path
    firewall_zone: str
    allowed_ipv4_cidrs: tuple[
        ipaddress.IPv4Network,
        ipaddress.IPv4Network,
        ipaddress.IPv4Network,
    ]


def _read_regular_no_follow(
    path: Path, *, max_bytes: int
) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RuntimeError
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(8192, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise RuntimeError
        return b"".join(chunks), metadata
    finally:
        os.close(descriptor)


def _lto_web_gid() -> int:
    gid = os.getegid()
    if isinstance(gid, bool) or not isinstance(gid, int) or gid <= 0:
        raise RuntimeError
    return gid


def _require_metadata(
    metadata: os.stat_result,
    *,
    mode: int,
    uid: int,
    gid: int,
    directory: bool = False,
) -> None:
    expected_kind = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_kind(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_uid != uid
        or metadata.st_gid != gid
    ):
        raise RuntimeError


def _validate_config_file(path: Path, web_gid: int) -> None:
    _, metadata = _read_regular_no_follow(path, max_bytes=_MAX_CONFIG_BYTES)
    _require_metadata(metadata, mode=0o640, uid=0, gid=web_gid)


def _validate_tls_files(certificate: Path, private_key: Path, web_gid: int) -> None:
    directory = os.open(
        TLS_ROOT,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY,
    )
    try:
        _require_metadata(
            os.fstat(directory), mode=0o750, uid=0, gid=web_gid, directory=True
        )
    finally:
        os.close(directory)
    for path, mode, gid in (
        (certificate, 0o644, 0),
        (private_key, 0o640, web_gid),
    ):
        _, metadata = _read_regular_no_follow(path, max_bytes=16 * 1024 * 1024)
        _require_metadata(metadata, mode=mode, uid=0, gid=gid)


def _tls_path(value: object) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise RuntimeError
    path = Path(value)
    if not path.is_absolute() or path != Path(os.path.normpath(value)):
        raise RuntimeError
    try:
        relative = path.relative_to(TLS_ROOT)
    except ValueError as exc:
        raise RuntimeError from exc
    if relative == Path("."):
        raise RuntimeError
    if len(relative.parts) != 1:
        raise RuntimeError
    return path


def load_web_config(
    path: Path,
    *,
    expected_web_gid: int | None = None,
) -> WebRhel9Config:
    if not isinstance(path, Path) or not path.is_absolute():
        # Absolute production paths are mandatory. Tests use an absolute
        # TemporaryDirectory path and exercise the identical parser.
        raise RuntimeError
    web_gid = _lto_web_gid() if expected_web_gid is None else expected_web_gid
    if isinstance(web_gid, bool) or not isinstance(web_gid, int) or web_gid <= 0:
        raise RuntimeError
    try:
        _validate_config_file(path, web_gid)
        payload, _ = _read_regular_no_follow(path, max_bytes=_MAX_CONFIG_BYTES)
        decoded = tomllib.loads(payload.decode("utf-8", errors="strict"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise RuntimeError from exc
    if set(decoded) != _EXPECTED_KEYS:
        raise RuntimeError
    raw_host = decoded["listen_host"]
    if not isinstance(raw_host, str) or not raw_host:
        raise RuntimeError
    try:
        listen_host = ipaddress.IPv4Address(raw_host)
    except ipaddress.AddressValueError as exc:
        raise RuntimeError from exc
    if (
        listen_host.is_unspecified
        or listen_host.is_loopback
        or listen_host.is_multicast
        or listen_host.is_link_local
        or listen_host.is_reserved
    ):
        raise RuntimeError
    listen_port = decoded["listen_port"]
    if isinstance(listen_port, bool) or listen_port != 8443:
        raise RuntimeError
    zone = decoded["firewall_zone"]
    if not isinstance(zone, str) or _ZONE.fullmatch(zone) is None:
        raise RuntimeError
    raw_cidrs = decoded["allowed_ipv4_cidrs"]
    if not isinstance(raw_cidrs, list) or not all(
        isinstance(value, str) for value in raw_cidrs
    ):
        raise RuntimeError
    try:
        cidrs = tuple(ipaddress.IPv4Network(value, strict=True) for value in raw_cidrs)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise RuntimeError from exc
    if cidrs != EXACT_CIDRS:
        raise RuntimeError
    certificate = _tls_path(decoded["tls_certfile"])
    private_key = _tls_path(decoded["tls_keyfile"])
    if certificate == private_key:
        raise RuntimeError
    _validate_tls_files(certificate, private_key, web_gid)
    return WebRhel9Config(
        listen_host=listen_host,
        listen_port=8443,
        tls_certfile=certificate,
        tls_keyfile=private_key,
        firewall_zone=zone,
        allowed_ipv4_cidrs=cidrs,
    )


def web_argv(config: WebRhel9Config) -> tuple[str, ...]:
    if not isinstance(config, WebRhel9Config):
        raise TypeError
    return (
        WEB_LAUNCHER,
        "serve",
        "--host",
        str(config.listen_host),
        "--port",
        "8443",
        "--auth-db",
        AUTH_DATABASE,
        "--daemon-socket",
        DAEMON_SOCKET,
        "--tls-certfile",
        str(config.tls_certfile),
        "--tls-keyfile",
        str(config.tls_keyfile),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", type=Path, default=WEB_CONFIG)
    try:
        arguments = parser.parse_args(argv)
        config = load_web_config(arguments.config)
        command = web_argv(config)
        os.execve(command[0], command, {"LANG": "C.UTF-8"})
        raise RuntimeError
    except (OSError, RuntimeError, ValueError, TypeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("WebUI activation failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
