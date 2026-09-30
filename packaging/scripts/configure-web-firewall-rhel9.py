#!/usr/bin/python3.11
from __future__ import annotations

import argparse
import contextlib
import fcntl
import grp
import importlib.util
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

FIREWALL_CMD = "/usr/bin/firewall-cmd"
WEB_CONFIG = Path("/etc/lto-archiver/web.toml")
_SIOCGIFADDR = 0x8915
_RICH_TCP_PORT = re.compile(
    r'\bport\s+port="(?P<port>[0-9]+(?:-[0-9]+)?)"\s+protocol="tcp"'
)


def _load_web_runner():
    path = Path(__file__).with_name("run-web-rhel9.py")
    name = "_lto_archiver_run_web_rhel9"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_web_runner = _load_web_runner()
WebRhel9Config = _web_runner.WebRhel9Config
load_web_config = _web_runner.load_web_config
EXACT_CIDRS = _web_runner.EXACT_CIDRS


class FirewallHost(Protocol):
    def interface_for_address(self, address: ipaddress.IPv4Address) -> str | None: ...

    def zone_for_interface(self, interface: str) -> str | None: ...

    def rich_rules(self, permanent: bool) -> tuple[str, ...]: ...

    def open_ports(self, permanent: bool) -> tuple[str, ...]: ...

    def services_exposing_port(self, permanent: bool, port: int) -> tuple[str, ...]: ...

    def add_rich_rule(self, permanent: bool, rule: str) -> None: ...

    def remove_rich_rule(self, permanent: bool, rule: str) -> None: ...


@dataclass(frozen=True)
class FirewallReceipt:
    allowed_ipv4_cidrs: tuple[str, str, str]
    listen_port: int
    added_permanent: tuple[str, ...]
    added_runtime: tuple[str, ...]


def _rule(network: ipaddress.IPv4Network) -> str:
    return (
        'rule family="ipv4" source address="'
        f'{network}" port port="8443" protocol="tcp" accept'
    )


EXACT_RULES = tuple(_rule(network) for network in EXACT_CIDRS)


def _lto_web_gid() -> int:
    try:
        gid = grp.getgrnam("lto-web").gr_gid
    except KeyError as exc:
        raise RuntimeError from exc
    if isinstance(gid, bool) or not isinstance(gid, int) or gid <= 0:
        raise RuntimeError
    return gid


def _port_range_contains(value: str, target: int) -> bool:
    parts = value.split("-", 1)
    if not all(part.isascii() and part.isdecimal() for part in parts):
        raise RuntimeError
    lower = int(parts[0])
    upper = int(parts[-1])
    if not 1 <= lower <= upper <= 65535:
        raise RuntimeError
    return lower <= target <= upper


def _tcp_port_token_contains(token: str, target: int) -> bool:
    port, separator, protocol = token.rpartition("/")
    if not separator or not port or not protocol:
        raise RuntimeError
    if protocol != "tcp":
        return False
    return _port_range_contains(port, target)


class FirewalldHost:
    def __init__(
        self,
        zone: str,
        *,
        run_command: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self.zone = zone
        self._run_command = run_command

    def _firewall(self, *arguments: str) -> str:
        completed = self._run_command(
            (FIREWALL_CMD, *arguments),
            check=True,
            capture_output=True,
            text=True,
        )
        return completed.stdout.strip()

    def interface_for_address(self, address: ipaddress.IPv4Address) -> str | None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            for _index, interface in socket.if_nameindex():
                encoded = interface.encode("ascii", errors="strict")
                if len(encoded) > 15:
                    continue
                request = struct.pack("256s", encoded)
                try:
                    response = fcntl.ioctl(probe.fileno(), _SIOCGIFADDR, request)
                except OSError:
                    continue
                candidate = ipaddress.IPv4Address(socket.inet_ntoa(response[20:24]))
                if candidate == address:
                    return interface
        return None

    def zone_for_interface(self, interface: str) -> str | None:
        zone = self._firewall(f"--get-zone-of-interface={interface}")
        return zone or None

    def rich_rules(self, permanent: bool) -> tuple[str, ...]:
        arguments = [f"--zone={self.zone}"]
        if permanent:
            arguments.append("--permanent")
        arguments.append("--list-rich-rules")
        return tuple(
            sorted(
                line.strip()
                for line in self._firewall(*arguments).splitlines()
                if line.strip()
            )
        )

    def open_ports(self, permanent: bool) -> tuple[str, ...]:
        arguments = [f"--zone={self.zone}"]
        if permanent:
            arguments.append("--permanent")
        arguments.append("--list-ports")
        return tuple(sorted(self._firewall(*arguments).split()))

    def services_exposing_port(self, permanent: bool, port: int) -> tuple[str, ...]:
        arguments = [f"--zone={self.zone}"]
        if permanent:
            arguments.append("--permanent")
        services = self._firewall(*arguments, "--list-services").split()
        exposing: list[str] = []
        for service in services:
            detail_arguments: list[str] = []
            if permanent:
                detail_arguments.append("--permanent")
            detail_arguments.append(f"--info-service={service}")
            details = self._firewall(*detail_arguments)
            ports = next(
                (
                    line.partition(":")[2].split()
                    for line in details.splitlines()
                    if line.strip().startswith("ports:")
                ),
                [],
            )
            if any(_tcp_port_token_contains(token, port) for token in ports):
                exposing.append(service)
        return tuple(sorted(exposing))

    def _change(self, operation: str, permanent: bool, rule: str) -> None:
        arguments = [f"--zone={self.zone}"]
        if permanent:
            arguments.append("--permanent")
        arguments.append(f"--{operation}-rich-rule={rule}")
        self._firewall(*arguments)

    def add_rich_rule(self, permanent: bool, rule: str) -> None:
        self._change("add", permanent, rule)

    def remove_rich_rule(self, permanent: bool, rule: str) -> None:
        self._change("remove", permanent, rule)


def _validate_config(config: WebRhel9Config) -> None:
    if (
        not isinstance(config, WebRhel9Config)
        or config.listen_port != 8443
        or config.allowed_ipv4_cidrs != EXACT_CIDRS
        or config.listen_host.is_unspecified
        or config.listen_host.is_loopback
        or config.listen_host.is_multicast
    ):
        raise RuntimeError


def verify_firewall(config: WebRhel9Config, host: FirewallHost) -> None:
    _validate_config(config)
    interface = host.interface_for_address(config.listen_host)
    if interface is None or host.zone_for_interface(interface) != config.firewall_zone:
        raise RuntimeError
    expected = set(EXACT_RULES)
    for permanent in (True, False):
        if any(
            _tcp_port_token_contains(token, 8443)
            for token in host.open_ports(permanent)
        ):
            raise RuntimeError
        if host.services_exposing_port(permanent, 8443):
            raise RuntimeError
        for rule in host.rich_rules(permanent):
            if rule in expected:
                continue
            match = _RICH_TCP_PORT.search(rule)
            if match is not None and _port_range_contains(match.group("port"), 8443):
                raise RuntimeError


def apply_firewall(config: WebRhel9Config, host: FirewallHost) -> FirewallReceipt:
    additions: list[tuple[bool, str]] = []
    try:
        verify_firewall(config, host)
        for permanent in (True, False):
            present = set(host.rich_rules(permanent))
            for rule in EXACT_RULES:
                if rule not in present:
                    host.add_rich_rule(permanent, rule)
                    additions.append((permanent, rule))
        verify_firewall(config, host)
        for permanent in (True, False):
            if not set(host.rich_rules(permanent)).issuperset(EXACT_RULES):
                raise RuntimeError
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, TypeError):
        rollback_failed = False
        for permanent, rule in reversed(additions):
            try:
                host.remove_rich_rule(permanent, rule)
            except (
                OSError,
                subprocess.SubprocessError,
                RuntimeError,
                ValueError,
                TypeError,
            ):
                rollback_failed = True
        if rollback_failed:
            raise RuntimeError("firewall apply and rollback failed") from None
        raise RuntimeError from None
    return FirewallReceipt(
        allowed_ipv4_cidrs=tuple(str(network) for network in EXACT_CIDRS),
        listen_port=8443,
        added_permanent=tuple(rule for permanent, rule in additions if permanent),
        added_runtime=tuple(rule for permanent, rule in additions if not permanent),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--config", type=Path, default=WEB_CONFIG)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--verify-only", action="store_true")
    action.add_argument("--apply", action="store_true")
    try:
        arguments = parser.parse_args(argv)
        config = load_web_config(
            arguments.config,
            expected_web_gid=_lto_web_gid(),
        )
        host = FirewalldHost(config.firewall_zone)
        if arguments.apply:
            if os.geteuid() != 0:
                raise RuntimeError
            receipt = apply_firewall(config, host)
            sys.stdout.write(
                f"port={receipt.listen_port} sources={','.join(receipt.allowed_ipv4_cidrs)}\n"
            )
        else:
            verify_firewall(config, host)
        return 0
    except (OSError, subprocess.SubprocessError, RuntimeError, ValueError, TypeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("WebUI firewall configuration failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
