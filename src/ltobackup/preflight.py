from __future__ import annotations

import argparse
import grp
import json
import os
import pwd
import secrets
import stat
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TextIO

from .broker.client import UnixBrokeredCgroupScopeApi
from .daemon.archive_runtime import load_broker_capability
from .errors import LtoBackupError
from .linux_settings import (
    MANAGED_SOURCE_MOUNT_ROOT,
    LinuxSettings,
    load_linux_settings,
)
from .share_broker.client import ShareBrokerClient
from .share_broker.main import load_systemd_credential
from .tape.command_supervisor import BrokeredCgroupScopeToken

_DEFAULT_BROKER_SOCKET = Path("/run/lto-archiver-broker/control.sock")
_DEFAULT_BROKER_CAPABILITY = Path(
    "/run/credentials/lto-archiverd.service/broker-capability"
)
_DEFAULT_SHARE_BROKER_SOCKET = Path("/run/lto-archiver-share-broker/control.sock")
_DEFAULT_SHARE_BROKER_CAPABILITY = Path(
    "/run/credentials/lto-archiverd.service/share-broker-capability"
)
_DEFAULT_SHARE_BROKER_PROOF_KEY = Path(
    "/run/credentials/lto-archiverd.service/share-broker-proof-key"
)
_FUSERMOUNT_PATH = Path("/usr/bin/fusermount")
_STANDARD_EXECUTABLE_MODES = frozenset({0o750, 0o755})
_FUSERMOUNT_EXECUTABLE_MODES = frozenset({0o4755})


class _BrokerReadinessApi(Protocol):
    def assert_ready(self) -> None: ...


@dataclass(frozen=True)
class AccountIdentity:
    uid: int
    gids: tuple[int, ...]
    primary_gid: int | None = None


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    ok: bool


@dataclass(frozen=True)
class PreflightResult:
    checks: tuple[PreflightCheck, ...]

    @property
    def ok(self) -> bool:
        return all(check.ok for check in self.checks)

    def json_value(self) -> dict[str, object]:
        return {
            "schema": 1,
            "ok": self.ok,
            "checks": [{"name": check.name, "ok": check.ok} for check in self.checks],
        }


class PreflightHost:
    """Read-only host probes used by the production preflight."""

    _TOOLS = (
        Path("/usr/bin/sg_inq"),
        Path("/usr/bin/mkltfs"),
        Path("/usr/bin/ltfs"),
        _FUSERMOUNT_PATH,
        Path("/usr/bin/mt"),
        Path("/usr/bin/ltfs-info"),
    )
    _SHARE_HELPER_CONTRACTS = (
        (Path("/usr/sbin/mount.nfs"), frozenset({0o4755})),
        (Path("/usr/sbin/mount.cifs"), frozenset({0o755})),
    )
    _SHARE_HELPERS = tuple(path for path, _modes in _SHARE_HELPER_CONTRACTS)

    def __init__(
        self,
        *,
        broker_capability_loader: Callable[
            [Path], BrokeredCgroupScopeToken
        ] = load_broker_capability,
        broker_api_factory: Callable[
            [Path, BrokeredCgroupScopeToken], _BrokerReadinessApi
        ] = UnixBrokeredCgroupScopeApi,
        share_credential_loader: Callable[[Path], bytes] = load_systemd_credential,
        share_broker_factory: Callable[..., ShareBrokerClient] = ShareBrokerClient,
    ) -> None:
        self._broker_capability_loader = broker_capability_loader
        self._broker_api_factory = broker_api_factory
        self._share_credential_loader = share_credential_loader
        self._share_broker_factory = share_broker_factory

    def is_rhel_major_9(self) -> bool:
        try:
            release = Path("/etc/redhat-release").read_text().strip()
            prefix = "Red Hat Enterprise Linux release "
            if not release.startswith(prefix):
                return False
            version = release.removeprefix(prefix).partition(" ")[0]
            components = version.split(".")
            return (
                bool(components)
                and components[0] == "9"
                and all(component.isdigit() for component in components)
            )
        except OSError:
            return False

    def is_selinux_enforcing(self) -> bool:
        try:
            return Path("/sys/fs/selinux/enforce").read_bytes() in {b"1", b"1\n"}
        except OSError:
            return False

    def account(self, name: str) -> AccountIdentity | None:
        try:
            record = pwd.getpwnam(name)
            gids = {record.pw_gid}
            gids.update(
                group.gr_gid for group in grp.getgrall() if name in group.gr_mem
            )
            return AccountIdentity(record.pw_uid, tuple(sorted(gids)), record.pw_gid)
        except (KeyError, OSError):
            return None

    def stable_devices_ready(self, settings: LinuxSettings) -> bool:
        try:
            settings.validate()
            return self._stable_character_device(
                settings.tape_device_path
            ) and self._stable_character_device(settings.scsi_device_path)
        except (OSError, RuntimeError, ValueError, TypeError):
            return False

    @staticmethod
    def _stable_character_device(path: Path) -> bool:
        link = path.lstat()
        target = path.stat()
        return stat.S_ISLNK(link.st_mode) and stat.S_ISCHR(target.st_mode)

    def tools_ready(self) -> bool:
        return all(
            _trusted_executable(
                path,
                accepted_modes=(
                    _FUSERMOUNT_EXECUTABLE_MODES
                    if path == _FUSERMOUNT_PATH
                    else _STANDARD_EXECUTABLE_MODES
                ),
                required_nlink=1 if path == _FUSERMOUNT_PATH else None,
            )
            for path in self._TOOLS
        )

    def share_helpers_ready(self) -> bool:
        return all(
            _trusted_executable(path, accepted_modes=modes, required_nlink=1)
            for path, modes in self._SHARE_HELPER_CONTRACTS
        )

    def share_broker_boundary_ready(
        self,
        *,
        socket_path: Path,
        capability_path: Path,
        proof_key_path: Path,
    ) -> bool:
        try:
            capability = self._share_credential_loader(capability_path)
            proof_key = self._share_credential_loader(proof_key_path)
            if (
                type(capability) is not bytes
                or len(capability) != 32
                or type(proof_key) is not bytes
                or len(proof_key) != 32
                or secrets.compare_digest(capability, proof_key)
            ):
                return False
            broker = self._share_broker_factory(
                socket_path, capability=capability, proof_key=proof_key
            )
            return broker.assert_ready() is None
        except Exception:  # noqa: BLE001 - redact local trust-boundary errors
            return False

    def share_paths_ready(
        self, settings: LinuxSettings, daemon: AccountIdentity
    ) -> bool:
        if settings.managed_source_mount_root != MANAGED_SOURCE_MOUNT_ROOT:
            return False
        primary_gid = (
            daemon.primary_gid
            if daemon.primary_gid is not None
            else daemon.gids[0]
            if daemon.gids
            else -1
        )
        return (
            _owned_directory(Path("/var/lib/lto-archiver-share-broker"), 0, 0, 0o700)
            and _owned_directory(
                Path("/etc/lto-archiver/share-credentials"), 0, 0, 0o700
            )
            and _owned_directory(
                Path("/run/lto-archiver-share-broker"), 0, primary_gid, 0o750
            )
            and _owned_directory(
                settings.managed_source_mount_root, 0, primary_gid, 0o750
            )
        )

    def ltfs_provenance_ready(self) -> bool:
        vendor = Path("/opt/hp/StoreOpen_Standalone/bin/ltfs")
        own = Path("/usr/share/licenses/lto-ltfs/upstream.json")
        return _trusted_executable(vendor) or _trusted_regular_file(own)

    def fuse_session_boundary_ready(
        self,
        *,
        broker_socket_path: Path,
        broker_capability_path: Path,
    ) -> bool:
        """Accept only a fresh authenticated proof from the exact broker peer."""

        try:
            capability = self._broker_capability_loader(broker_capability_path)
            broker = self._broker_api_factory(broker_socket_path, capability)
            return broker.assert_ready() is None
        except Exception:  # noqa: BLE001 - redact every local trust-boundary error
            return False

    def sources_readable(
        self, settings: LinuxSettings, account: AccountIdentity
    ) -> bool:
        return all(
            _account_can_access(path, account, read=True, write=False)
            for path in settings.source_roots
        )

    def managed_mount_ready(self, settings: LinuxSettings) -> bool:
        try:
            target = str(settings.mount_path.resolve(strict=True))
            mounted = target in _mount_targets(Path("/proc/1/mountinfo").read_text())
            empty = next(settings.mount_path.iterdir(), None) is None
            return settings.mount_path.is_dir() and not mounted and empty
        except (OSError, RuntimeError, ValueError):
            return False

    def state_paths_ready(
        self,
        settings: LinuxSettings,
        daemon: AccountIdentity,
        web: AccountIdentity,
    ) -> bool:
        daemon_paths = (
            settings.state_dir,
            settings.state_dir / "backups",
            settings.state_dir / "migrations",
        )
        return (
            all(
                _owned_directory(path, daemon.uid, daemon.gids, 0o750)
                for path in daemon_paths
            )
            and _owned_directory(Path("/var/lib/lto-archiver-broker"), 0, 0, 0o700)
            and _owned_directory(
                Path("/var/lib/lto-archiver-web"), web.uid, web.gids, 0o700
            )
            and all(
                _account_can_access(path, daemon, read=True, write=True)
                for path in (*daemon_paths, *settings.restore_roots)
            )
        )

    def windows_owner_inactive(self) -> bool:
        return not Path("/etc/lto-archiver/windows-authority-active").exists()


def run_preflight(
    settings: LinuxSettings,
    host: PreflightHost,
    *,
    broker_socket_path: Path = _DEFAULT_BROKER_SOCKET,
    broker_capability_path: Path = _DEFAULT_BROKER_CAPABILITY,
    share_broker_socket_path: Path = _DEFAULT_SHARE_BROKER_SOCKET,
    share_broker_capability_path: Path = _DEFAULT_SHARE_BROKER_CAPABILITY,
    share_broker_proof_key_path: Path = _DEFAULT_SHARE_BROKER_PROOF_KEY,
) -> PreflightResult:
    daemon = _safe_probe(lambda: host.account("lto-archiver"), None)
    web = _safe_probe(lambda: host.account("lto-web"), None)
    checks = (
        PreflightCheck("platform.rhel9", _safe_bool(host.is_rhel_major_9)),
        PreflightCheck("selinux.enforcing", _safe_bool(host.is_selinux_enforcing)),
        PreflightCheck("accounts.present", daemon is not None and web is not None),
        PreflightCheck(
            "devices.stable", _safe_bool(lambda: host.stable_devices_ready(settings))
        ),
        PreflightCheck("ltfs.tools", _safe_bool(host.tools_ready)),
        PreflightCheck("ltfs.provenance", _safe_bool(host.ltfs_provenance_ready)),
        PreflightCheck(
            "ltfs.fuse_boundary",
            _safe_bool(
                lambda: host.fuse_session_boundary_ready(
                    broker_socket_path=broker_socket_path,
                    broker_capability_path=broker_capability_path,
                )
            ),
        ),
        PreflightCheck("shares.helpers", _safe_bool(host.share_helpers_ready)),
        PreflightCheck(
            "shares.broker_boundary",
            _safe_bool(
                lambda: host.share_broker_boundary_ready(
                    socket_path=share_broker_socket_path,
                    capability_path=share_broker_capability_path,
                    proof_key_path=share_broker_proof_key_path,
                )
            ),
        ),
        PreflightCheck(
            "shares.permissions",
            daemon is not None
            and _safe_bool(lambda: host.share_paths_ready(settings, daemon)),
        ),
        PreflightCheck(
            "sources.readable",
            daemon is not None
            and _safe_bool(lambda: host.sources_readable(settings, daemon)),
        ),
        PreflightCheck(
            "mount.empty_unmounted",
            _safe_bool(lambda: host.managed_mount_ready(settings)),
        ),
        PreflightCheck(
            "state.permissions",
            daemon is not None
            and web is not None
            and _safe_bool(lambda: host.state_paths_ready(settings, daemon, web)),
        ),
        PreflightCheck("windows.inactive", _safe_bool(host.windows_owner_inactive)),
    )
    return PreflightResult(checks)


def _safe_probe(operation: Callable[[], object], fallback: object) -> object:
    try:
        return operation()
    except (LtoBackupError, OSError, RuntimeError, ValueError, TypeError):
        return fallback


def _safe_bool(operation: Callable[[], object]) -> bool:
    return _safe_probe(operation, False) is True


def _trusted_executable(
    path: Path,
    *,
    accepted_modes: frozenset[int] = _STANDARD_EXECUTABLE_MODES,
    required_nlink: int | None = None,
) -> bool:
    try:
        status = path.stat(follow_symlinks=False)
        return (
            path.is_absolute()
            and not path.is_symlink()
            and stat.S_ISREG(status.st_mode)
            and status.st_uid == 0
            and stat.S_IMODE(status.st_mode) in accepted_modes
            and (required_nlink is None or status.st_nlink == required_nlink)
        )
    except OSError:
        return False


def _trusted_regular_file(path: Path) -> bool:
    try:
        status = path.stat(follow_symlinks=False)
        return (
            not path.is_symlink()
            and stat.S_ISREG(status.st_mode)
            and status.st_uid == 0
            and stat.S_IMODE(status.st_mode) & 0o022 == 0
        )
    except OSError:
        return False


def _owned_directory(
    path: Path, uid: int, gids: int | tuple[int, ...], mode: int
) -> bool:
    try:
        status = path.stat(follow_symlinks=False)
        return (
            not path.is_symlink()
            and stat.S_ISDIR(status.st_mode)
            and status.st_uid == uid
            and status.st_gid in ((gids,) if type(gids) is int else gids)
            and stat.S_IMODE(status.st_mode) == mode
        )
    except OSError:
        return False


def _account_can_access(
    path: Path,
    account: AccountIdentity,
    *,
    read: bool,
    write: bool,
) -> bool:
    try:
        status = path.stat()
        required = 0o1 | (0o4 if read else 0) | (0o2 if write else 0)
        if (
            not stat.S_ISDIR(status.st_mode)
            or _account_bits(status, account) & required != required
        ):
            return False
        ancestor = path.parent
        while True:
            ancestor_status = ancestor.stat()
            if (
                not stat.S_ISDIR(ancestor_status.st_mode)
                or _account_bits(ancestor_status, account) & 0o1 != 0o1
            ):
                return False
            parent = ancestor.parent
            if parent == ancestor:
                return True
            ancestor = parent
    except OSError:
        return False


def _account_bits(status: os.stat_result, account: AccountIdentity) -> int:
    shift = (
        6 if status.st_uid == account.uid else 3 if status.st_gid in account.gids else 0
    )
    return stat.S_IMODE(status.st_mode) >> shift


def _mount_targets(payload: str) -> frozenset[str]:
    lines = [line for line in payload.splitlines() if line.strip()]
    if not lines:
        raise ValueError("empty mountinfo")
    targets: set[str] = set()
    for line in lines:
        fields = line.split()
        try:
            separator = fields.index("-", 6)
        except (ValueError, IndexError) as error:
            raise ValueError("invalid mountinfo separator") from error
        major, colon, minor = (
            fields[2].partition(":")
            if len(fields) >= 3
            else (
                "",
                "",
                "",
            )
        )
        if (
            len(fields) < 10
            or separator < 6
            or len(fields) < separator + 4
            or not fields[0].isdigit()
            or not fields[1].isdigit()
            or colon != ":"
            or not major.isdigit()
            or not minor.isdigit()
            or not fields[3].startswith("/")
            or not fields[4].startswith("/")
        ):
            raise ValueError("invalid mountinfo record")
        targets.add(_decode_mount_path(fields[4]))
    return frozenset(targets)


def _decode_mount_path(value: str) -> str:
    for escaped, decoded in (
        ("\\040", " "),
        ("\\011", "\t"),
        ("\\012", "\n"),
        ("\\134", "\\"),
    ):
        value = value.replace(escaped, decoded)
    return value


def main(
    argv: list[str] | None = None,
    *,
    stdout: TextIO | None = None,
    settings_loader: Callable[[Path], LinuxSettings] = load_linux_settings,
    host_factory: Callable[[], PreflightHost] = PreflightHost,
) -> int:
    parser = argparse.ArgumentParser(prog="preflight-rhel9.sh")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--json", action="store_true", required=True)
    parser.add_argument("--broker-socket", type=Path, default=_DEFAULT_BROKER_SOCKET)
    parser.add_argument(
        "--broker-capability-file",
        type=Path,
        default=_DEFAULT_BROKER_CAPABILITY,
    )
    parser.add_argument(
        "--share-broker-socket",
        type=Path,
        default=_DEFAULT_SHARE_BROKER_SOCKET,
    )
    parser.add_argument(
        "--share-broker-capability-file",
        type=Path,
        default=_DEFAULT_SHARE_BROKER_CAPABILITY,
    )
    parser.add_argument(
        "--share-broker-proof-key-file",
        type=Path,
        default=_DEFAULT_SHARE_BROKER_PROOF_KEY,
    )
    output = stdout or sys.stdout
    try:
        args = parser.parse_args(argv)
        checked = run_preflight(
            settings_loader(args.config),
            host_factory(),
            broker_socket_path=args.broker_socket,
            broker_capability_path=args.broker_capability_file,
            share_broker_socket_path=args.share_broker_socket,
            share_broker_capability_path=args.share_broker_capability_file,
            share_broker_proof_key_path=args.share_broker_proof_key_file,
        )
    except (LtoBackupError, OSError, RuntimeError, ValueError, TypeError):
        checked = PreflightResult((PreflightCheck("config.valid", False),))
    json.dump(checked.json_value(), output, sort_keys=True, separators=(",", ":"))
    output.write("\n")
    return 0 if checked.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
