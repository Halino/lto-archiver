#!/usr/bin/python3.11
"""Create, verify, and restore an offline RHEL 9 rollback bundle.

All host interaction is deliberately behind ``RollbackHost``.  This keeps the
transaction testable and prevents bundle verification from growing implicit
network, package-cache, or tape dependencies.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import types
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Protocol

REQUIRED_STATE_CHECKS = frozenset(
    {
        "catalog",
        "protected_catalog_backup",
        "command_broker",
        "share_broker_state",
        "web_auth",
    }
)
_LEGACY_SNAPSHOTS = (
    "configuration",
    "application_state",
    "command_broker_state",
    "share_broker_state",
    "web_auth_state",
    "custom_web_unit",
    "systemd_dropins",
)
_LTFS_SNAPSHOT_ROOTS = {
    "ltfs_device_configuration": Path("/etc/lto-ltfs"),
    "ltfs_configuration": Path("/etc/ltfs.conf"),
    "ltfs_configuration_rpmnew": Path("/etc/ltfs.conf.rpmnew"),
    "ltfs_configuration_rpmsave": Path("/etc/ltfs.conf.rpmsave"),
    "ltfs_local_configuration": Path("/etc/ltfs.conf.local"),
    "ltfs_local_configuration_rpmnew": Path("/etc/ltfs.conf.local.rpmnew"),
    "ltfs_local_configuration_rpmsave": Path("/etc/ltfs.conf.local.rpmsave"),
}
REQUIRED_SNAPSHOTS = (*_LEGACY_SNAPSHOTS, *_LTFS_SNAPSHOT_ROOTS)
_FILE_SNAPSHOTS = frozenset(
    {"custom_web_unit", *(_LTFS_SNAPSHOT_ROOTS.keys() - {"ltfs_device_configuration"})}
)
STOP_UNITS = (
    "lto-archiver-web.service",
    "lto-archiverd.socket",
    "lto-archiverd.service",
    "lto-archiver-log-reader.socket",
    "lto-archiver-log-reader.service",
    "lto-archiver-share-broker.socket",
    "lto-archiver-share-broker.service",
    "lto-archiver-command-broker.socket",
    "lto-archiver-command-broker.service",
)
START_UNITS = (
    "lto-archiver-command-broker.socket",
    "lto-archiver-share-broker.socket",
    "lto-archiver-log-reader.socket",
    "lto-archiverd.socket",
    "lto-archiver-command-broker.service",
    "lto-archiver-share-broker.service",
    "lto-archiverd.service",
    "lto-archiver-web.service",
)
_LOG_READER_UNITS = frozenset(
    {
        "lto-archiver-log-reader.socket",
        "lto-archiver-log-reader.service",
    }
)
_PRE_LOG_READER_STOP_UNITS = tuple(
    unit for unit in STOP_UNITS if unit not in _LOG_READER_UNITS
)
_UNIT_ENABLEMENT_CLOSURES = frozenset(
    {
        frozenset(STOP_UNITS),
        frozenset(_PRE_LOG_READER_STOP_UNITS),
    }
)
_RESTORE_STAGE_IDS = frozenset(
    {
        "platform_state",
        "protected_catalog",
        "revalidate",
        "activation",
        "health",
    }
)
_TARGETS = frozenset({"application", "runtime", "driver-evidence"})
_PACKAGE_FOR_TARGET = {
    "application": "lto-archiver",
    "runtime": "lto-archiver-python-runtime",
    "driver-evidence": "lto-ltfs",
}
_LEGACY_NEVRAS = frozenset(
    {
        "lto-archiver-0.11.27-100.el9.noarch",
        "lto-archiver-python-runtime-0.11.27-2.el9.x86_64",
        "lto-ltfs-0.1.0-16.el9.x86_64",
    }
)
_LEGACY_PREDECESSOR_NEVRAS = {
    "lto-archiver": "lto-archiver-0.11.27-127.el9.noarch",
    "lto-archiver-python-runtime": (
        "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
    ),
    "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
}
_LEGACY_DEPLOYED_NEVRAS = {
    **_LEGACY_PREDECESSOR_NEVRAS,
    "lto-archiver": "lto-archiver-0.11.27-129.el9.noarch",
}
_PREDECESSOR_NEVRAS = {
    **_LEGACY_DEPLOYED_NEVRAS,
    "lto-archiver": "lto-archiver-0.11.27-141.el9.noarch",
    "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
}
_DEPLOYED_NEVRAS = {
    **_PREDECESSOR_NEVRAS,
    "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
}


def _coordinated_package_state_known(installed: Mapping[str, str]) -> bool:
    return set(installed) == set(_PREDECESSOR_NEVRAS) and all(
        installed[name] in {_PREDECESSOR_NEVRAS[name], _DEPLOYED_NEVRAS[name]}
        for name in _PREDECESSOR_NEVRAS
    )


def _daemon_quiescent_for_maintenance(status: Mapping[str, object]) -> bool:
    """Accept persisted media waits, but never active or recovery work."""
    required = {
        "job",
        "operation",
        "admission_blocker",
        "critical_recovery",
    }
    if not required.issubset(status):
        return False
    if (
        status["operation"] is not None
        or status["admission_blocker"] is not None
        or status["critical_recovery"] is not None
    ):
        return False
    job = status["job"]
    if job is None:
        return True
    return bool(
        isinstance(job, Mapping)
        and job.get("state") in {"waiting_media", "paused"}
    )


_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_RPM_VERIFY = re.compile(
    r"^(?P<flags>[SM5DLUGTP.]{9})[ \t]+(?P<marker>[a-z]?)[ \t]+(?P<path>/[^\n\r]+)$"
)
_DRIVER_RPM_VERIFY_POLICY_SHA256 = (
    "c00c446b14fdf8daa42094874cbe91ce2aa1f7ed5976a2c01c86eaff7fced4c5"
)
_DRIVER_RPM_VERIFY_ROW = "S.5....T.  c /etc/lto-ltfs/device.json"
_PREDECESSOR_CATALOG_SCHEMA = "40"
_MANIFEST_KEYS = frozenset(
    {
        "available_capacity_bytes",
        "bundle_id",
        "created_at",
        "custom_web_unit_sha256",
        "driver_input_sha256",
        "firewall_observation_sha256",
        "host_binding_sha256",
        "installed_nevras",
        "old_journal_policy_sha256",
        "old_live_contract_sha256",
        "old_rpm_policy_sha256",
        "protected_backup_relative_path",
        "protected_backup_sha256",
        "required_capacity_bytes",
        "rpms",
        "schema",
        "snapshots",
        "state_checks",
        "source_catalog_schema",
        "source_catalog_sha256",
        "tool_hashes",
        "tool_versions",
        "unit_enablement",
    }
)
_SNAPSHOT_ROOTS = {
    "configuration": Path("/etc/lto-archiver"),
    "application_state": Path("/var/lib/lto-archiver"),
    "command_broker_state": Path("/var/lib/lto-archiver-broker"),
    "share_broker_state": Path("/var/lib/lto-archiver-share-broker"),
    "web_auth_state": Path("/var/lib/lto-archiver-web"),
    "custom_web_unit": Path("/etc/systemd/system/lto-archiver-web.service"),
    "systemd_dropins": Path("/etc/systemd/system"),
    **_LTFS_SNAPSHOT_ROOTS,
}
_PROTECTED_BACKUP_RELATIVE = Path("backups")
_PROTECTED_BACKUP_ROOT = (
    _SNAPSHOT_ROOTS["application_state"] / _PROTECTED_BACKUP_RELATIVE
)
_LIVE_CATALOG = _SNAPSHOT_ROOTS["application_state"] / "catalog.db"
_ROLLBACK_RECOVERY_ROOT = Path("/var/lib/lto-archiver-rollback-recovery")
_PROTECTED_BACKUP_NAME = re.compile(
    r"^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{12}-p-v(?P<version>[0-9]+)-"
    r"[0-9a-f]{16}\.sqlite3$"
)
_MIN_PROTECTED_CATALOG_SCHEMA = 13
_MAX_PROTECTED_CATALOG_SCHEMA = int(_PREDECESSOR_CATALOG_SCHEMA)
_ROOT_UID = 0
_ROOT_GID = 0
_SYSTEMCTL = Path("/usr/bin/systemctl")
_RPM = Path("/usr/bin/rpm")
_RPMKEYS = Path("/usr/bin/rpmkeys")
_DNF = Path("/usr/bin/dnf-3")
_FIREWALL = Path("/usr/bin/firewall-cmd")
_PYTHON = Path("/usr/bin/python3.11")
_FINDMNT = Path("/usr/bin/findmnt")
_RESTORECON = Path("/usr/sbin/restorecon")


class RollbackError(RuntimeError):
    """Closed rollback validation or transaction failure."""


def _predecessor_https_login_ok(probe: Mapping[str, object]) -> bool:
    try:
        if set(probe) != {"ca_certificate", "url"}:
            return False
        certificate = Path(str(probe["ca_certificate"]))
        url = probe["url"]
        if not isinstance(url, str):
            return False
        parsed = urllib.parse.urlsplit(url)
        if (
            not certificate.is_absolute()
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.port != 8443
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path != "/login"
            or parsed.query
            or parsed.fragment
        ):
            return False
        context = ssl.create_default_context(cafile=certificate)
        request = urllib.request.Request(
            url, headers={"Accept": "text/html"}, method="GET"
        )
        with urllib.request.urlopen(request, context=context, timeout=10) as response:
            body = response.read(1024 * 1024 + 1)
            content_type = response.headers.get("Content-Type", "")
            cache_control = response.headers.get("Cache-Control", "")
            return (
                response.status == 200
                and response.geturl() == url
                and len(body) <= 1024 * 1024
                and content_type.split(";", 1)[0].strip().lower() == "text/html"
                and "no-store"
                in {value.strip().lower() for value in cache_control.split(",")}
                and b'action="/login"' in body
            )
    except (KeyError, OSError, TypeError, ValueError, ssl.SSLError):
        return False


def _canonical_unit_enablement(
    result: subprocess.CompletedProcess[str],
) -> str:
    if result.stderr or "\r" in result.stdout:
        raise RollbackError("unit enablement observation is invalid")
    stdout = (
        result.stdout[:-1] if result.stdout.endswith("\n") else result.stdout
    )
    if "\n" in stdout:
        raise RollbackError("unit enablement observation is invalid")
    states = {
        (0, "enabled"): "enabled",
        (1, "disabled"): "disabled",
        (0, "static"): "static",
    }
    try:
        return states[(result.returncode, stdout)]
    except KeyError:
        raise RollbackError("unit enablement observation is invalid") from None


def _reader_unit_is_exactly_absent(
    result: subprocess.CompletedProcess[str], expected_unit: str
) -> bool:
    if expected_unit not in _LOG_READER_UNITS:
        return False
    return (
        result.returncode == 1
        and result.stdout == "not-found\n"
        and not result.stderr
    ) or (
        result.returncode == 1
        and not result.stdout
        and result.stderr
        == (
            "Failed to get unit file state for "
            f"{expected_unit}: No such file or directory\n"
        )
    )


def _valid_unit_enablement(enablement: Mapping[str, str]) -> bool:
    return (
        frozenset(enablement) in _UNIT_ENABLEMENT_CLOSURES
        and all(
            state in {"enabled", "disabled", "static"}
            for state in enablement.values()
        )
    )


def _required_active_units(enablement: Mapping[str, str]) -> tuple[str, ...]:
    return tuple(
        unit
        for unit in STOP_UNITS
        if unit in enablement and unit != "lto-archiver-log-reader.service"
    )


def _legacy_rpm_rows_expected_only(package: str, rows: list[str]) -> bool:
    if package == "lto-archiver-python-runtime":
        return not rows
    if package == "lto-ltfs":
        return rows == [_DRIVER_RPM_VERIFY_ROW]
    if package != "lto-archiver":
        return False
    allowed = {
        "/etc/lto-archiver/config.toml",
        "/etc/lto-archiver/web.toml",
    }
    seen: set[str] = set()
    for row in rows:
        match = _RPM_VERIFY.fullmatch(row)
        if match is None or match.group("marker") != "c":
            return False
        path = match.group("path")
        if path not in allowed or path in seen:
            return False
        seen.add(path)
        if any(
            actual not in {".", canonical}
            for canonical, actual in zip("SM5DLUGTP", match.group("flags"))
        ):
            return False
        changed = {
            canonical
            for canonical, actual in zip("SM5DLUGTP", match.group("flags"))
            if actual != "."
        }
        if changed - {"S", "5", "T"}:
            return False
    return True


def _legacy_rpm_verification_expected_only(
    package: str, result: subprocess.CompletedProcess[str]
) -> bool:
    if result.stderr:
        return False
    if package == "lto-ltfs":
        return (
            result.returncode == 1
            and result.stdout == _DRIVER_RPM_VERIFY_ROW + "\n"
        )
    if package == "lto-archiver-python-runtime":
        return result.returncode == 0 and result.stdout == ""
    if package != "lto-archiver":
        return False
    rows = list(filter(None, result.stdout.splitlines()))
    return (
        result.returncode == (1 if rows else 0)
        and result.stdout == ("" if not rows else "\n".join(rows) + "\n")
        and _legacy_rpm_rows_expected_only(package, rows)
    )


@dataclass(frozen=True)
class SnapshotSource:
    identity: str
    logical_bytes: int


@dataclass(frozen=True)
class FileEvidence:
    relative_path: str
    sha256: str
    size: int
    mode: int
    uid: int
    gid: int
    acl_sha256: str
    xattr_sha256: str
    selinux_sha256: str


@dataclass(frozen=True)
class DirectoryEvidence:
    relative_path: str
    mode: int
    uid: int
    gid: int
    acl_sha256: str
    xattr_sha256: str
    selinux_sha256: str


@dataclass(frozen=True)
class SnapshotEvidence:
    identity: str
    logical_bytes: int
    files: tuple[FileEvidence, ...]
    directories: tuple[DirectoryEvidence, ...]


@dataclass(frozen=True)
class StateCheck:
    identity: str
    integrity_ok: bool
    foreign_keys_ok: bool
    schema_ok: bool


@dataclass(frozen=True)
class RpmEvidence:
    target: str
    filename: str
    nevra: str
    sha256: str
    size: int
    signature_status: str
    signing_key_id: str
    header_sha256: str
    payload_sha256: str


@dataclass(frozen=True)
class CreateBundleRequest:
    bundle_dir: Path
    rollback_rpm_dir: Path
    expected_custom_web_unit_sha256: str
    driver_input_contract: Path
    expected_driver_input_sha256: str
    predecessor_web_probe: Mapping[str, str]
    candidate_driver_input_contract: Path
    expected_candidate_driver_input_sha256: str


@dataclass(frozen=True)
class PreparedSourceBackup:
    path: Path
    source_schema: int
    catalog_sha256: str
    backup_sha256: str


@dataclass(frozen=True)
class BundleManifest:
    bundle_id: str
    created_at: str
    host_binding_sha256: str
    installed_nevras: Mapping[str, str]
    rpms: tuple[RpmEvidence, ...]
    snapshots: tuple[SnapshotEvidence, ...]
    state_checks: tuple[StateCheck, ...]
    custom_web_unit_sha256: str
    unit_enablement: Mapping[str, str]
    firewall_observation_sha256: str
    available_capacity_bytes: int
    required_capacity_bytes: int
    tool_hashes: Mapping[str, str]
    old_live_contract_sha256: str
    old_rpm_policy_sha256: str
    old_journal_policy_sha256: str
    driver_input_sha256: str
    tool_versions: Mapping[str, str]
    protected_backup_relative_path: str
    protected_backup_sha256: str
    source_catalog_schema: int
    source_catalog_sha256: str
    candidate_driver_input_sha256: str = ""
    schema: int = 4


@dataclass(frozen=True)
class RestoreResult:
    status: str
    bundle_id: str
    failed_new_state_dir: Path
    detail: str


@dataclass(frozen=True)
class StagedSwap:
    items: tuple[tuple[Path, Path | None], ...]
    guard_directories: tuple[Path, ...] = ()


class RollbackHost(Protocol):
    def is_root(self) -> bool: ...
    def parent_is_secure(self, parent: Path) -> bool: ...
    def available_bytes(self, parent: Path) -> int: ...
    def artifact_lease(self, bundle: Path) -> AbstractContextManager: ...
    def host_binding_material(self) -> bytes: ...
    def installed_nevras(self) -> Mapping[str, str]: ...
    def driver_package_state_matches(self, contract: Mapping[str, object]) -> bool: ...
    def install_local_rollback(
        self, runtime_rpm: Path, app_rpm: Path, driver_rpm: Path | None = None
    ) -> None: ...
    def captured_installed_package_state(self) -> Mapping[str, object]: ...
    def inspect_rollback_rpms(self, directory: Path) -> tuple[RpmEvidence, ...]: ...
    def rollback_rpm_authority_ok(
        self, directory: Path, filenames: tuple[str, ...]
    ) -> bool: ...
    def snapshot_sources(self) -> tuple[SnapshotSource, ...]: ...
    def verify_restore_capacity(self, bundle: Path, manifest: BundleManifest) -> None: ...
    def prepare_source_catalog_backup(self, parent: Path) -> PreparedSourceBackup: ...
    def validate_prepared_source(self, prepared: object) -> bool: ...
    def copy_prepared_source(
        self, prepared: PreparedSourceBackup, destination: Path
    ) -> None: ...
    def verify_protected_source(
        self, bundle: Path, manifest: BundleManifest
    ) -> bool: ...
    def copy_snapshot(self, source: SnapshotSource, destination: Path) -> SnapshotEvidence: ...
    def check_copied_state(self, snapshots: Path) -> tuple[StateCheck, ...]: ...
    def custom_web_unit_sha256(self) -> str: ...
    def captured_enablement(self) -> Mapping[str, str]: ...
    def firewall_observation_digest(self) -> str: ...
    def copy_bundle_tools(self, destination: Path) -> Mapping[str, str]: ...
    def tool_versions(self) -> Mapping[str, str]: ...
    def verify_bundle_security(self, bundle: Path) -> bool: ...
    def verify_rpm_evidence(self, evidence: tuple[RpmEvidence, ...]) -> bool: ...
    def verify_snapshot_evidence(self, bundle: Path, evidence: tuple[SnapshotEvidence, ...]) -> bool: ...
    def verify_copied_state(self, bundle: Path, checks: tuple[StateCheck, ...]) -> bool: ...
    def fsync_tree(self, root: Path) -> None: ...
    def publish_noreplace(self, staging: Path, final: Path) -> None: ...
    def remask_stop_and_prove_idle(self, units: tuple[str, ...]) -> None: ...
    def verify_restored_ltfs_configuration(self, manifest: BundleManifest) -> bool: ...
    def restore_protected_catalog(
        self, manifest: BundleManifest, recovery: Path
    ) -> None: ...
    def all_units_active(self, units: tuple[str, ...]) -> bool: ...
    def begin_restore_health_window(self, recovery: Path) -> None: ...


class SystemRollbackHost:
    """Concrete, local-only RHEL 9 adapter used by the executable CLI."""

    def __init__(self) -> None:
        self._script_dir = Path(__file__).resolve().parent
        sibling_policies = tuple(
            self._script_dir / name
            for name in ("rpm-verify-policy.json", "journal-policy.json")
        )
        self._deployment_dir = (
            self._script_dir
            if all(path.is_file() and not path.is_symlink() for path in sibling_policies)
            else Path("/usr/share/lto-archiver/deployment")
        )

    @staticmethod
    def _run(
        argv: Sequence[str | Path], *, accepted: tuple[int, ...] = (0,)
    ) -> subprocess.CompletedProcess[str]:
        command = [str(item) for item in argv]
        if not command or not Path(command[0]).is_absolute():
            raise RollbackError("host command is not absolute")
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
            )
        except (OSError, subprocess.SubprocessError):
            raise RollbackError("host command failed") from None
        if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 64 * 1024:
            raise RollbackError("host command output exceeded its bound")
        if result.returncode not in accepted:
            raise RollbackError("host command failed")
        return result

    @staticmethod
    def _require_tool(path: Path) -> None:
        try:
            entry = path.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry.st_mode):
                if entry.st_uid != 0:
                    raise RollbackError(
                        "required RHEL tool failed ownership checks"
                    )
                resolved = path.resolve(strict=True)
                for ancestor in (*path.parents, *resolved.parents):
                    parent = ancestor.stat(follow_symlinks=False)
                    if (
                        not stat.S_ISDIR(parent.st_mode)
                        or parent.st_uid != 0
                        or parent.st_mode & 0o022
                    ):
                        raise RollbackError(
                            "required RHEL tool failed ownership checks"
                        )
                details = resolved.stat(follow_symlinks=False)
            else:
                details = entry
        except (OSError, RuntimeError):
            raise RollbackError("required RHEL tool is unavailable") from None
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
        ):
            raise RollbackError("required RHEL tool failed ownership checks")

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def parent_is_secure(self, parent: Path) -> bool:
        try:
            details = parent.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            stat.S_ISDIR(details.st_mode)
            and details.st_uid == 0
            and stat.S_IMODE(details.st_mode) == 0o700
            and not parent.is_symlink()
        )

    def available_bytes(self, parent: Path) -> int:
        details = os.statvfs(parent)
        return details.f_bavail * details.f_frsize

    def _deployment_artifact_registry(self):
        registry = getattr(self, "_artifact_registry", None)
        if registry is not None:
            return registry
        # The deployer injects its signature-verified helper. Standalone restore
        # uses the root-owned bundled/installed sibling, never ambient imports.
        path = self._script_dir / "deployment_artifacts.py"
        for ancestor in path.parents:
            details = ancestor.stat(follow_symlinks=False)
            if not stat.S_ISDIR(details.st_mode) or details.st_uid != 0:
                raise RollbackError("artifact helper ancestor authority failed")
            if details.st_mode & 0o022:
                # Root-owned sticky temporary roots are safe only below an
                # immediate root-private stage, never as a blanket exception
                # for arbitrary writable ancestors or direct helper placement.
                private = ancestor / path.relative_to(ancestor).parts[0]
                private_details = private.stat(follow_symlinks=False)
                if (ancestor not in (Path("/tmp"), Path("/var/tmp"))
                        or not details.st_mode & stat.S_ISVTX
                        or not stat.S_ISDIR(private_details.st_mode)
                        or private_details.st_uid != 0
                        or stat.S_IMODE(private_details.st_mode) != 0o700):
                    raise RollbackError("artifact helper ancestor authority failed")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_nlink != 1 or before.st_mode & 0o022 or before.st_size > 4 * 1024 * 1024):
                raise RollbackError("artifact helper authority failed")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                data = stream.read(4 * 1024 * 1024 + 1)
            after = os.fstat(descriptor)
            current = path.stat(follow_symlinks=False)
            def identity(row):
                return (row.st_dev, row.st_ino, row.st_mode, row.st_uid,
                        row.st_gid, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
            if len(data) != before.st_size or identity(before) != identity(after) or identity(before) != identity(current):
                raise RollbackError("artifact helper changed")
        finally:
            os.close(descriptor)
        module = types.ModuleType("_lto_rollback_artifacts")
        module.__file__, module.__package__ = str(path), ""
        exec(compile(data, str(path), "exec"), module.__dict__)
        self._artifact_registry = module.DeploymentArtifactRegistry()
        return self._artifact_registry

    @contextmanager
    def artifact_lease(self, bundle: Path):
        active = getattr(self, "_artifact_lease_bundle", None)
        if active is not None:
            if active != bundle:
                raise RollbackError("another rollback artifact lease is active")
            yield
            return
        with self._deployment_artifact_registry().lease_if_registered(bundle):
            self._artifact_lease_bundle = bundle
            try:
                yield
            finally:
                self._artifact_lease_bundle = None

    @staticmethod
    def _artifact_path_reference(value: str, bundle: Path) -> bool:
        value = value.removesuffix(" (deleted)")
        return value == str(bundle) or value.startswith(str(bundle) + "/")

    def _artifact_task_clear(self, task: Path, *, inodes: set[tuple[int, int]], bundle: Path) -> None:
        """Inspect one thread's FD table, mappings and executable/cwd references."""
        own = task == Path(f"/proc/{os.getpid()}/task/{os.getpid()}")

        def read(name: str) -> bytes:
            with (task / name).open("rb") as stream:
                data = stream.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise RollbackError("artifact reference observation exceeded bound")
            return data

        def identity(data: bytes):
            end = data.rfind(b") ")
            values = data[end + 2:].split()
            if end < 0 or len(values) < 20 or int(data.split(b" ", 1)[0]) != int(task.name):
                raise RollbackError("artifact process reference identity is invalid")
            return values[0], int(values[6]), tuple(values[1:4]), values[19]

        def referenced(details, target: str) -> None:
            if ((details.st_dev, details.st_ino) in inodes
                    or self._artifact_path_reference(target, bundle)):
                raise RollbackError("artifact has an active process reference")

        def descriptor_snapshot():
            result = {}
            for name in os.listdir(task / "fd"):
                if not name.isdigit():
                    raise RollbackError("artifact descriptor observation is invalid")
                path = task / "fd" / name
                try:
                    details = path.stat()
                    target = os.readlink(path)
                except FileNotFoundError:
                    # listdir itself briefly opens an FD in this single-threaded
                    # helper. No disappearing FD in another task is exempted.
                    if own:
                        continue
                    raise
                referenced(details, target)
                result[name] = (details.st_dev, details.st_ino, details.st_mode, target)
            return result

        try:
            before = identity(read("stat"))
            cmdline = read("cmdline")
            inactive = before[0] == b"Z" or bool(before[1] & 0x200000)
            links = {}
            if not inactive:
                for name in ("cwd", "root", "exe"):
                    details = (task / name).stat()
                    target = os.readlink(task / name)
                    referenced(details, target)
                    links[name] = (details.st_dev, details.st_ino, target)
                for value in cmdline.decode(errors="surrogateescape").split("\0"):
                    argument = value.partition("=")[2] if "=" in value else value
                    if self._artifact_path_reference(argument, bundle):
                        raise RollbackError("artifact has a pending process reference")
                    if not own and Path(value).name in {"deploy-rhel9.py", "rollback-rhel9.py"}:
                        raise RollbackError("external deployment or restore lease reference remains")
            descriptors = descriptor_snapshot()
            mappings = read("maps")
            for line in mappings.decode(errors="surrogateescape").splitlines():
                fields = line.split(None, 5)
                if len(fields) < 5 or not re.fullmatch(r"[0-9a-f]+:[0-9a-f]+", fields[3]) or not fields[4].isdigit():
                    raise RollbackError("artifact mapping reference observation is invalid")
                major, minor = (int(value, 16) for value in fields[3].split(":"))
                path = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[5]) if len(fields) == 6 else ""
                if ((os.makedev(major, minor), int(fields[4])) in inodes
                        or self._artifact_path_reference(path, bundle)):
                    raise RollbackError("artifact has an active mapping reference")
            # Our own observer allocates memory while reading maps. It cannot
            # acquire an old-bundle mapping between these synchronous checks;
            # public admission requires this helper to be single-threaded.
            if (descriptors != descriptor_snapshot() or (not own and mappings != read("maps"))
                    or cmdline != read("cmdline") or before != identity(read("stat"))):
                raise RollbackError("artifact process reference observation changed")
            for name, expected in links.items():
                details = (task / name).stat()
                if (details.st_dev, details.st_ino, os.readlink(task / name)) != expected:
                    raise RollbackError("artifact process reference identity changed")
        except (OSError, ValueError, IndexError) as error:
            raise RollbackError("artifact reference observation is incomplete") from error

    def prove_artifact_prunable(self, bundle: Path) -> None:
        """Fail closed on references and external users; never stop or signal them.

        Registry EX excludes cooperating leases. This observation also refuses
        other deployment/restore processes, every thread's open files/mappings,
        kernel locks and mount-root aliases in each observed mount namespace.
        Registry revalidates the exact artifact inventory after this callback.
        """
        def tasks():
            return {Path(f"/proc/{pid}/task/{tid}")
                    for pid in os.listdir("/proc") if pid.isdigit()
                    for tid in os.listdir(f"/proc/{pid}/task") if tid.isdigit()}

        def inventory():
            paths = (bundle, *self._walk_directories(bundle), *self._walk_files(bundle))
            return {(row.st_dev, row.st_ino) for path in paths
                    for row in (path.stat(follow_symlinks=False),)}

        try:
            if not self.is_root() or bundle.resolve(strict=True) != bundle:
                raise RollbackError("artifact reference proof requires an authoritative root path")
            for name in ("pid", "mnt"):
                if os.stat(f"/proc/self/ns/{name}").st_ino != os.stat(f"/proc/1/ns/{name}").st_ino:
                    raise RollbackError("artifact reference proof requires host namespaces")
            before = tasks()
            own_tasks = {path.name for path in before if path.parent.parent.name == str(os.getpid())}
            if own_tasks != {str(os.getpid())}:
                raise RollbackError("artifact reference observer must be single-threaded")
            inodes = inventory()
            namespaces = {}
            for task in sorted(before):
                self._artifact_task_clear(task, inodes=inodes, bundle=bundle)
                try:
                    namespace = (task / "ns/mnt").stat().st_ino
                except FileNotFoundError:
                    # Kernel threads/zombies have no mount namespace and no
                    # user references; the task inspector still checked FDs/maps.
                    text = (task / "stat").read_text()
                    values = text[text.rfind(") ") + 2:].split()
                    if not (values[0] == "Z" or int(values[6]) & 0x200000):
                        raise
                else:
                    namespaces.setdefault(namespace, task)
            for namespace, task in namespaces.items():
                mountinfo = (task / "mountinfo").read_bytes()
                for line in mountinfo.decode().splitlines():
                    fields = line.split()
                    if len(fields) < 10 or "-" not in fields:
                        raise RollbackError("artifact mount reference observation is invalid")
                    mount = re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), fields[4])
                    details = (task / "root" / mount.lstrip("/")).stat()
                    if ((details.st_dev, details.st_ino) in inodes
                            or self._artifact_path_reference(mount, bundle)):
                        raise RollbackError("artifact has an active mount reference")
                if (task / "ns/mnt").stat().st_ino != namespace or (task / "mountinfo").read_bytes() != mountinfo:
                    raise RollbackError("artifact mount reference observation changed")
            locks = Path("/proc/locks").read_text()
            for line in locks.splitlines():
                identities = [field for field in line.split() if re.fullmatch(r"[0-9a-fA-F]+:[0-9a-fA-F]+:[0-9]+", field)]
                if len(identities) != 1:
                    raise RollbackError("artifact external lease observation is invalid")
                major, minor, inode = identities[0].split(":")
                if (os.makedev(int(major, 16), int(minor, 16)), int(inode)) in inodes:
                    raise RollbackError("artifact has an external lock or lease reference")
            if before != tasks() or inodes != inventory() or Path("/proc/locks").read_text() != locks:
                raise RollbackError("artifact reference proof changed")
        except (OSError, ValueError, IndexError) as error:
            raise RollbackError("artifact reference proof is incomplete") from error

    def verify_deployment_capacity(
        self, parent: Path, sources: Sequence[SnapshotSource], rpms: Sequence[RpmEvidence],
        *, prove_absent_web_unit: Callable[[Path], None] | None = None,
    ) -> None:
        """Budget persistent copies, validation scratch, and future restore together.

        This is the initial deployment gate, before any catalog validation copy.
        Existing files are already excluded from available bytes. New bundle and
        prepared-source copies remain allocated during a rollback; old live
        trees are retained by rename while replacement snapshots are copied.

        Retained recovery may project its historically absent local WebUI unit
        after releasing an authenticated owned mask. Its proof must remain valid
        across this entire check. This does not authorize any restore operation
        or exempt other paths, destination parents, or filesystems from checks.
        """
        if (
            tuple(row.identity for row in sources) != REQUIRED_SNAPSHOTS
            or any(row.logical_bytes < 0 for row in sources)
            or any(row.size < 0 for row in rpms)
        ):
            raise RollbackError("deployment capacity inputs are invalid")
        if prove_absent_web_unit is not None:
            if not callable(prove_absent_web_unit) or next(
                row.logical_bytes for row in sources if row.identity == "custom_web_unit"
            ) != 0:
                raise RollbackError("absent WebUI projection requires a proof and empty snapshot")
            if prove_absent_web_unit(_SNAPSHOT_ROOTS["custom_web_unit"]) is not None:
                raise RollbackError("absent WebUI projection proof did not succeed")
        catalog_size = _LIVE_CATALOG.stat().st_size
        wal = _LIVE_CATALOG.with_name(_LIVE_CATALOG.name + "-wal")
        if wal.exists():
            catalog_size += wal.stat().st_size
        self._verify_catalog_capacity(parent, sources, rpms, catalog_size=catalog_size,
                                      prove_absent_web_unit=prove_absent_web_unit)
        if prove_absent_web_unit is not None and prove_absent_web_unit(_SNAPSHOT_ROOTS["custom_web_unit"]) is not None:
            raise RollbackError("absent WebUI projection proof did not succeed")

    def verify_compacted_deployment_capacity(
        self, parent: Path, sources: Sequence[SnapshotSource], rpms: Sequence[RpmEvidence],
        *, original_bytes: int, candidate_bytes: int,
    ) -> None:
        """Check future deployment before installing a verified compact catalog.

        The caller binds the original size to its stopped standalone catalog and
        the candidate size to its verified standalone output. Snapshot sizes are
        still those of the original tree. Only its catalog contribution changes;
        retained backups and every other snapshot remain in the copy closure.
        Existing candidate and backup files are already charged to free space.
        No original-file blocks are credited as reclaimable, even for sparse or
        shared extents. Charge the future installed copy on the live filesystem.
        """
        if (
            type(original_bytes) is not int or original_bytes <= 0
            or type(candidate_bytes) is not int or candidate_bytes <= 0
            or tuple(row.identity for row in sources) != REQUIRED_SNAPSHOTS
            or any(type(row.logical_bytes) is not int or row.logical_bytes < 0 for row in sources)
            or any(type(row.size) is not int or row.size < 0 for row in rpms)
        ):
            raise RollbackError("compacted deployment capacity inputs are invalid")
        application = next(row for row in sources if row.identity == "application_state")
        if application.logical_bytes < original_bytes:
            raise RollbackError("original catalog exceeds application snapshot capacity")
        projected = tuple(
            SnapshotSource(row.identity, row.logical_bytes - original_bytes + candidate_bytes)
            if row.identity == "application_state" else row
            for row in sources
        )
        self._verify_catalog_capacity(
            parent, projected, rpms, catalog_size=candidate_bytes,
            installation_bytes=candidate_bytes,
        )

    def _verify_catalog_capacity(
        self, parent: Path, sources: Sequence[SnapshotSource], rpms: Sequence[RpmEvidence],
        *, catalog_size: int, installation_bytes: int = 0,
        prove_absent_web_unit: Callable[[Path], None] | None = None,
    ) -> None:
        """Aggregate the same copy lifetimes for measured or projected catalogs."""
        self._verify_restore_topology(tuple(row.identity for row in sources),
                                      prove_absent_web_unit=prove_absent_web_unit)
        scratch_size = max(
            catalog_size,
            *(row.logical_bytes for row in sources if row.identity != "application_state"),
        )
        # Service-owned protected backups still use descriptor isolation followed
        # by a SQLite backup. Both copies coexist during their validation.
        for path in self._walk_files(_PROTECTED_BACKUP_ROOT):
            if _PROTECTED_BACKUP_NAME.fullmatch(path.name):
                scratch_size = max(scratch_size, 2 * path.stat().st_size)

        demands = [
            (parent, sum(row.logical_bytes for row in sources)
             + sum(row.size for row in rpms) + 2 * catalog_size),
            (_LIVE_CATALOG.parent, catalog_size + installation_bytes),
            (Path(tempfile.gettempdir()), scratch_size),
        ]
        for row in sources:
            target = _SNAPSHOT_ROOTS[row.identity]
            # stage_snapshot places dropin guards inside the systemd directory;
            # every other snapshot guard is beside its destination.
            destination = target if row.identity == "systemd_dropins" else target.parent
            demands.append((destination, row.logical_bytes))
        self._verify_capacity_demands(demands)

    def verify_restore_capacity(self, bundle: Path, manifest: BundleManifest) -> None:
        """Admit only future restore allocations from an already verified bundle.

        Bundle, RPM, prepared-source and failed live bytes already reduce free
        space. Current state is retained by rename, not copied or reclaimed.
        The snapshot closure and validation sizes belong to the saved state,
        not to the potentially different failed installation being replaced.
        """
        snapshots = manifest.snapshots
        identities = _LEGACY_SNAPSHOTS if manifest.schema == 2 else REQUIRED_SNAPSHOTS
        if (
            manifest.schema not in (2, 3, 4)
            or tuple(row.identity for row in snapshots) != identities
            or any(type(row.logical_bytes) is not int or row.logical_bytes < 0 for row in snapshots)
            or any(type(record.size) is not int or record.size < 0
                   for row in snapshots for record in row.files)
        ):
            raise RollbackError("restore capacity inputs are invalid")
        relative = Path(manifest.protected_backup_relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise RollbackError("restore capacity protected source is invalid")
        selected = bundle / relative
        details = selected.stat(follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode) or details.st_size <= 0:
            raise RollbackError("restore capacity protected source is invalid")
        catalog_size = details.st_size
        application = next(row for row in snapshots if row.identity == "application_state")
        catalog_family_size = sum(
            record.size for record in application.files
            if record.relative_path in ("catalog.db", "catalog.db-wal")
        )
        scratch_size = max(
            catalog_size, catalog_family_size,
            *(row.logical_bytes for row in snapshots if row.identity != "application_state"),
        )
        for record in application.files:
            path = Path(record.relative_path)
            if path.is_relative_to(_PROTECTED_BACKUP_RELATIVE) and _PROTECTED_BACKUP_NAME.fullmatch(path.name):
                scratch_size = max(scratch_size, 2 * record.size)
        self._verify_restore_topology(identities)
        demands = [
            # The application directory may be absent after a failed swap;
            # its same-filesystem parent is also where its staging is allocated.
            (_SNAPSHOT_ROOTS["application_state"].parent, catalog_size),
            (Path(tempfile.gettempdir()), scratch_size),
        ]
        for row in snapshots:
            target = _SNAPSHOT_ROOTS[row.identity]
            destination = target if row.identity == "systemd_dropins" else target.parent
            demands.append((destination, row.logical_bytes))
        self._verify_capacity_demands(demands)

    def _verify_restore_topology(
        self, identities: Sequence[str], *, prove_absent_web_unit: Callable[[Path], None] | None = None,
    ) -> None:
        """All saved-current renames must reach the single recovery filesystem.

        No directory is created here. Refuse mounted roots or descendants on
        another device rather than discovering EXDEV after package installation.
        Only managed dropins are inspected, not unrelated systemd symlinks.
        """
        recovery_parent = _ROLLBACK_RECOVERY_ROOT
        while True:
            try:
                recovery_details = recovery_parent.stat(follow_symlinks=False)
                break
            except FileNotFoundError:
                if recovery_parent == recovery_parent.parent:
                    raise RollbackError("restore filesystem topology is unavailable") from None
                recovery_parent = recovery_parent.parent
        if not stat.S_ISDIR(recovery_details.st_mode):
            raise RollbackError("restore filesystem topology is invalid")
        recovery_device = recovery_details.st_dev

        def check_entry(path: Path) -> None:
            details = path.stat(follow_symlinks=False)
            if details.st_dev != recovery_device or not (
                stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)
            ):
                raise RollbackError("restore filesystem topology does not support atomic rename")

        def walk_error(error: OSError) -> None:
            raise RollbackError("restore filesystem topology could not be inspected") from error

        for identity in identities:
            target = _SNAPSHOT_ROOTS[identity]
            destination = target if identity == "systemd_dropins" else target.parent
            check_entry(destination)
            if identity == "custom_web_unit" and prove_absent_web_unit is not None:
                if prove_absent_web_unit(target) is not None:
                    raise RollbackError("absent WebUI projection proof did not succeed")
                continue
            targets = self._dropin_paths() if identity == "systemd_dropins" else (target,)
            for root in targets:
                try:
                    check_entry(root)
                except FileNotFoundError:
                    continue
                if not root.is_dir():
                    continue
                for current, directories, files in os.walk(root, followlinks=False, onerror=walk_error):
                    for name in (*directories, *files):
                        check_entry(Path(current) / name)

    def _verify_capacity_demands(self, demands: Sequence[tuple[Path, int]]) -> None:
        """Apply one reserve after summing simultaneous demand per filesystem."""
        grouped: dict[int, tuple[Path, int]] = {}
        for path, size in demands:
            if not size:
                continue
            device = path.stat().st_dev
            previous = grouped.get(device)
            grouped[device] = (path, size + (previous[1] if previous else 0))
        for path, subtotal in grouped.values():
            required = subtotal + max((subtotal + 4) // 5, 10 * 1024**3)
            if self.available_bytes(path) < required:
                raise RollbackError("deployment or restore capacity is insufficient")

    def host_binding_material(self) -> bytes:
        return Path("/etc/machine-id").read_bytes().strip()

    def installed_nevras(self) -> Mapping[str, str]:
        self._require_tool(_RPM)
        result: dict[str, str] = {}
        for package in _PACKAGE_FOR_TARGET.values():
            query = self._run(
                (
                    _RPM,
                    "-q",
                    "--qf",
                    "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}",
                    package,
                )
            ).stdout
            if "\n" in query or not query.startswith(package + "-"):
                raise RollbackError("installed package identity is invalid")
            result[package] = query
        return result

    def captured_installed_package_state(self) -> Mapping[str, object]:
        self._require_tool(_RPM)
        packages: dict[str, object] = {}
        for package, nevra in self.installed_nevras().items():
            metadata = self._run(
                (_RPM, "-ql", "--dump", package)
            )
            verification = self._run(
                (_RPM, "-V", package), accepted=(0, 1)
            )
            verification_rows = list(
                filter(None, verification.stdout.splitlines())
            )
            if metadata.stderr or not metadata.stdout.endswith("\n"):
                raise RollbackError("installed package state is not closed")
            if not _legacy_rpm_verification_expected_only(package, verification):
                raise RollbackError("installed rpm-V state exceeds rollback policy")
            packages[package] = {
                "installed_file_metadata_sha256": _digest(
                    metadata.stdout.encode()
                ),
                "nevra": nevra,
                "rpm_verify_exit": verification.returncode,
                "rpm_verify_stdout_sha256": _digest(
                    verification.stdout.encode()
                ),
                "rpm_verify_rows": verification_rows,
            }
        return {"packages": packages, "schema": 1}

    def inspect_rollback_rpms(self, directory: Path) -> tuple[RpmEvidence, ...]:
        self._require_tool(_RPM)
        self._require_tool(_RPMKEYS)
        rows: list[RpmEvidence] = []
        by_package = {value: key for key, value in _PACKAGE_FOR_TARGET.items()}
        for path in sorted(directory.iterdir()):
            if path.suffix != ".rpm" or not path.is_file() or path.is_symlink():
                continue
            metadata = self._run(
                (
                    _RPM,
                    "-qp",
                    "--qf",
                    "%{NAME}\n%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n%{PAYLOADDIGEST}\n",
                    path,
                )
            ).stdout.splitlines()
            if len(metadata) != 3 or metadata[0] not in by_package:
                if metadata and metadata[0].startswith("lto-"):
                    raise RollbackError("unexpected target package in rollback closure")
                continue
            signature = self._run(
                (_RPMKEYS, "--verbose", "--checksig", path), accepted=(0, 1)
            )
            lines = [line.strip() for line in signature.stdout.splitlines()]
            digest_lines = {
                "Header SHA256 digest: OK", "Header SHA1 digest: OK",
                "Payload SHA256 digest: OK", "MD5 digest: OK",
            }
            if (
                signature.returncode != 0 or signature.stderr
                or not lines or lines[0] != f"{path}:"
                or not {"Header SHA256 digest: OK", "Payload SHA256 digest: OK"}.issubset(lines[1:])
            ):
                raise RollbackError("rollback RPM signature verification failed")
            signing_keys: set[str] = set()
            for line in lines[1:]:
                if line in digest_lines:
                    continue
                match = re.fullmatch(
                    r"(?:Header )?V4 RSA/SHA256 Signature, key ID ([0-9a-f]{8}|[0-9a-f]{16}): OK",
                    line, re.IGNORECASE,
                )
                if match is None:
                    raise RollbackError("rollback RPM signature evidence is invalid")
                signing_keys.add(match.group(1).lower())
            if signing_keys:
                signing_key = max(signing_keys, key=len)
                if not all(signing_key.endswith(key) for key in signing_keys):
                    raise RollbackError("rollback RPM signature identities disagree")
                status = "verified"
            elif metadata[1] in _LEGACY_NEVRAS:
                status, signing_key = "legacy-unsigned", "absent"
            else:
                raise RollbackError("unsigned RPM is not an admitted legacy rollback input")
            raw = path.read_bytes()
            header_material = (
                metadata[0] + "\n" + metadata[1] + "\n" + metadata[2] + "\n"
            ).encode()
            payload_digest = metadata[2]
            if not re.fullmatch(r"[0-9a-fA-F]{64}", payload_digest):
                payload_digest = _digest(payload_digest.encode())
            rows.append(
                RpmEvidence(
                    target=by_package[metadata[0]],
                    filename=path.name,
                    nevra=metadata[1],
                    sha256=_digest(raw),
                    size=len(raw),
                    signature_status=status,
                    signing_key_id=signing_key,
                    header_sha256=_digest(header_material),
                    payload_sha256=payload_digest.lower(),
                )
            )
        return tuple(rows)

    @staticmethod
    def rollback_rpm_authority_ok(
        directory: Path, filenames: tuple[str, ...]
    ) -> bool:
        if (
            not directory.is_absolute()
            or len(filenames) != 3
            or len(set(filenames)) != 3
            or any(Path(name).name != name for name in filenames)
        ):
            return False
        directory_descriptor: int | None = None
        try:
            directory_descriptor = os.open(
                directory,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            )
            directory_details = os.fstat(directory_descriptor)
            if (
                not stat.S_ISDIR(directory_details.st_mode)
                or directory_details.st_uid != 0
                or stat.S_IMODE(directory_details.st_mode) != 0o700
            ):
                return False
            for filename in filenames:
                descriptor = os.open(
                    filename,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_descriptor,
                )
                try:
                    details = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(details.st_mode)
                        or details.st_uid != 0
                        or details.st_nlink != 1
                        or details.st_mode & 0o022
                    ):
                        return False
                finally:
                    os.close(descriptor)
        except OSError:
            return False
        finally:
            if directory_descriptor is not None:
                os.close(directory_descriptor)
        return True

    @staticmethod
    def _dropin_paths() -> tuple[Path, ...]:
        root = _SNAPSHOT_ROOTS["systemd_dropins"]
        return tuple(sorted(path for path in root.glob("lto-archiver*.d") if path.is_dir()))

    @staticmethod
    def _walk_files(root: Path) -> tuple[Path, ...]:
        if not root.exists():
            return ()
        if root.is_symlink():
            raise RollbackError("snapshot source contains a symlink")
        if root.is_file():
            return (root,)
        paths: list[Path] = []
        for current, directories, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            for name in directories:
                if (current_path / name).is_symlink():
                    raise RollbackError("snapshot source contains a symlink")
            for name in files:
                path = current_path / name
                if path.is_symlink() or not path.is_file():
                    raise RollbackError("snapshot source is not a regular tree")
                paths.append(path)
        return tuple(sorted(paths))

    def snapshot_sources(self) -> tuple[SnapshotSource, ...]:
        return tuple(self.snapshot_source(identity) for identity in REQUIRED_SNAPSHOTS)

    def snapshot_source(self, identity: str) -> SnapshotSource:
        """Inventory one required root with the normal no-symlink policy."""
        if identity not in REQUIRED_SNAPSHOTS:
            raise RollbackError("unknown snapshot source")
        if identity in _LTFS_SNAPSHOT_ROOTS:
            self._ltfs_source_present(identity)
        roots = (self._dropin_paths() if identity == "systemd_dropins"
                 else (_SNAPSHOT_ROOTS[identity],))
        size = sum(path.stat().st_size for root in roots for path in self._walk_files(root))
        return SnapshotSource(identity, size)

    @staticmethod
    def _ltfs_source_present(identity: str) -> bool:
        path = _SNAPSHOT_ROOTS[identity]
        try:
            details = path.lstat()
        except FileNotFoundError:
            return False
        expected_type = (
            stat.S_ISDIR if identity == "ltfs_device_configuration" else stat.S_ISREG
        )
        if not expected_type(details.st_mode) or (
            stat.S_ISREG(details.st_mode) and details.st_nlink != 1
        ):
            raise RollbackError("LTFS configuration source has an unsafe type")
        return True

    @staticmethod
    def _secure_regular_digest(
        path: Path,
        *,
        uid: int | None,
        gid: int | None,
        mode: int,
    ) -> str:
        descriptor: int | None = None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or stat.S_IMODE(before.st_mode) != mode
                or (uid is not None and before.st_uid != uid)
                or (gid is not None and before.st_gid != gid)
                or before.st_size <= 0
            ):
                raise RollbackError("secure regular file policy failed")
            digest = hashlib.sha256()
            while chunk := os.read(descriptor, 1024 * 1024):
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            ):
                raise RollbackError("secure regular file drifted while reading")
            return digest.hexdigest()
        except OSError:
            raise RollbackError("secure regular file is unreadable") from None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _protected_source_values(
        self, path: Path, *, expected_name: str | None = None
    ) -> tuple[int, str] | None:
        name = expected_name if expected_name is not None else path.name
        match = _PROTECTED_BACKUP_NAME.fullmatch(name)
        if match is None or int(match["version"]) != int(_PREDECESSOR_CATALOG_SCHEMA):
            return None
        descriptor: int | None = None
        try:
            root = path.parent
            root_details = root.stat(follow_symlinks=False)
            if (
                root.is_symlink()
                or not stat.S_ISDIR(root_details.st_mode)
                or root_details.st_uid != _ROOT_UID
                or root_details.st_gid != _ROOT_GID
                or stat.S_IMODE(root_details.st_mode) != 0o700
            ):
                return None
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_uid != _ROOT_UID
                or details.st_gid != _ROOT_GID
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_size <= 0
            ):
                return None
            digest = hashlib.sha256()
            with tempfile.TemporaryDirectory(
                prefix="lto-protected-source-"
            ) as temporary:
                isolated = Path(temporary) / name
                output = os.open(
                    isolated,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    while chunk := os.read(descriptor, 1024 * 1024):
                        digest.update(chunk)
                        os.write(output, chunk)
                    os.fsync(output)
                finally:
                    os.close(output)
                after = os.fstat(descriptor)
                if (
                    details.st_dev,
                    details.st_ino,
                    details.st_size,
                    details.st_mtime_ns,
                    details.st_ctime_ns,
                ) != (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    return None
                if not self._validate_isolated_sqlite(
                    isolated,
                    catalog=True,
                    catalog_schema=_PREDECESSOR_CATALOG_SCHEMA,
                ):
                    return None
            return int(match["version"]), digest.hexdigest()
        except OSError:
            return None
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def validate_prepared_source(self, prepared: object) -> bool:
        if not isinstance(prepared, PreparedSourceBackup):
            return False
        observed = self._protected_source_values(prepared.path)
        try:
            catalog_digest = self._secure_regular_digest(
                _LIVE_CATALOG, uid=None, gid=None, mode=0o600
            )
        except RollbackError:
            return False
        return (
            observed == (prepared.source_schema, prepared.backup_sha256)
            and prepared.source_schema == int(_PREDECESSOR_CATALOG_SCHEMA)
            and prepared.catalog_sha256 == catalog_digest
            and _HEX64.fullmatch(prepared.catalog_sha256) is not None
        )

    def prepare_source_catalog_backup(self, parent: Path) -> PreparedSourceBackup:
        if not self._sqlite_check(
            _LIVE_CATALOG,
            catalog=True,
            catalog_schema=_PREDECESSOR_CATALOG_SCHEMA,
        ):
            raise RollbackError(
                "predecessor catalog is not schema "
                f"{_PREDECESSOR_CATALOG_SCHEMA} and clean"
            )
        catalog_digest = self._secure_regular_digest(
            _LIVE_CATALOG, uid=None, gid=None, mode=0o600
        )
        root: Path | None = None
        temporary: Path | None = None
        try:
            root = Path(tempfile.mkdtemp(prefix=".release-recovery-", dir=parent))
            os.chown(root, _ROOT_UID, _ROOT_GID)
            os.chmod(root, 0o700)
            stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
            name = (
                f"{stamp}-{uuid.uuid4().hex[:12]}-p-v{_PREDECESSOR_CATALOG_SCHEMA}-"
                f"{uuid.uuid4().hex[:16]}.sqlite3"
            )
            final = root / name
            temporary = root / f".{name}.tmp-{uuid.uuid4().hex}"
            _write(temporary, b"", mode=0o600)
            os.chown(temporary, _ROOT_UID, _ROOT_GID)
            source = sqlite3.connect(f"file:{_LIVE_CATALOG}?mode=ro", uri=True)
            destination = sqlite3.connect(temporary)
            try:
                source.backup(destination)
                destination.commit()
            finally:
                destination.close()
                source.close()
            os.chmod(temporary, 0o600)
            os.chown(temporary, _ROOT_UID, _ROOT_GID)
            observed = self._protected_source_values(temporary, expected_name=name)
            if observed is None:
                raise RollbackError("fresh protected backup failed validation")
            descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, final)
            directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            prepared = PreparedSourceBackup(
                path=final,
                source_schema=observed[0],
                catalog_sha256=catalog_digest,
                backup_sha256=observed[1],
            )
            if not self.validate_prepared_source(prepared):
                raise RollbackError("fresh protected backup source binding failed")
            return prepared
        except RollbackError:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            if root is not None:
                shutil.rmtree(root, ignore_errors=True)
            raise
        except (OSError, sqlite3.Error):
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            if root is not None:
                shutil.rmtree(root, ignore_errors=True)
            raise RollbackError("fresh protected backup creation failed") from None

    def copy_prepared_source(
        self, prepared: PreparedSourceBackup, destination: Path
    ) -> None:
        if not self.validate_prepared_source(prepared):
            raise RollbackError("prepared protected source is invalid")
        source_descriptor: int | None = None
        destination_descriptor: int | None = None
        try:
            destination.parent.mkdir(mode=0o700)
            os.chown(destination.parent, _ROOT_UID, _ROOT_GID)
            source_descriptor = os.open(
                prepared.path, os.O_RDONLY | os.O_NOFOLLOW
            )
            destination_descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            os.fchown(destination_descriptor, _ROOT_UID, _ROOT_GID)
            while chunk := os.read(source_descriptor, 1024 * 1024):
                os.write(destination_descriptor, chunk)
            os.fchmod(destination_descriptor, 0o600)
            os.fsync(destination_descriptor)
        except OSError:
            destination.unlink(missing_ok=True)
            raise RollbackError("prepared protected source copy failed") from None
        finally:
            if source_descriptor is not None:
                os.close(source_descriptor)
            if destination_descriptor is not None:
                os.close(destination_descriptor)
        directory = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def verify_protected_source(
        self, bundle: Path, manifest: BundleManifest
    ) -> bool:
        try:
            relative_value = manifest.protected_backup_relative_path
            relative = PurePosixPath(relative_value)
            if (
                relative_value != relative.as_posix()
                or relative.is_absolute()
                or len(relative.parts) != 2
                or relative.parts[0] != "release-recovery"
                or ".." in relative.parts
                or _PROTECTED_BACKUP_NAME.fullmatch(relative.name) is None
                or manifest.source_catalog_schema
                != int(_PREDECESSOR_CATALOG_SCHEMA)
                or not _HEX64.fullmatch(manifest.source_catalog_sha256)
                or not _HEX64.fullmatch(manifest.protected_backup_sha256)
            ):
                return False
            selected = bundle.joinpath(*relative.parts)
            observed = self._protected_source_values(selected)
            application = tuple(
                row
                for row in manifest.snapshots
                if row.identity == "application_state"
            )
            catalog = tuple(
                row
                for row in application[0].files
                if row.relative_path == "catalog.db"
            )
            return (
                len(application) == 1
                and len(catalog) == 1
                and catalog[0].sha256 == manifest.source_catalog_sha256
                and observed
                == (
                    manifest.source_catalog_schema,
                    manifest.protected_backup_sha256,
                )
            )
        except (IndexError, OSError, TypeError, ValueError):
            return False

    @staticmethod
    def _metadata_hashes(path: Path) -> tuple[str, str, str]:
        names = sorted(os.listxattr(path, follow_symlinks=False))
        xattrs = b"".join(
            name.encode()
            + b"\0"
            + os.getxattr(path, name, follow_symlinks=False)
            + b"\0"
            for name in names
        )
        acl = (
            os.getxattr(path, "system.posix_acl_access", follow_symlinks=False)
            if "system.posix_acl_access" in names
            else b""
        )
        selinux = (
            os.getxattr(path, "security.selinux", follow_symlinks=False)
            if "security.selinux" in names
            else b""
        )
        return _digest(acl), _digest(xattrs), _digest(selinux)

    @classmethod
    def _file_evidence(cls, path: Path, relative: Path) -> FileEvidence:
        details = path.stat(follow_symlinks=False)
        acl, xattrs, selinux = cls._metadata_hashes(path)
        digest, size = _file_digest(path)
        return FileEvidence(
            relative_path=relative.as_posix(),
            sha256=digest,
            size=size,
            mode=stat.S_IMODE(details.st_mode),
            uid=details.st_uid,
            gid=details.st_gid,
            acl_sha256=acl,
            xattr_sha256=xattrs,
            selinux_sha256=selinux,
        )

    @classmethod
    def _directory_evidence(
        cls, path: Path, relative: Path
    ) -> DirectoryEvidence:
        details = path.stat(follow_symlinks=False)
        acl, xattrs, selinux = cls._metadata_hashes(path)
        return DirectoryEvidence(
            relative_path=relative.as_posix(),
            mode=stat.S_IMODE(details.st_mode),
            uid=details.st_uid,
            gid=details.st_gid,
            acl_sha256=acl,
            xattr_sha256=xattrs,
            selinux_sha256=selinux,
        )

    @staticmethod
    def _walk_directories(root: Path) -> tuple[Path, ...]:
        if not root.is_dir() or root.is_symlink():
            return ()
        rows = [root]
        for current, directories, _files in os.walk(root, followlinks=False):
            current_path = Path(current)
            for name in directories:
                path = current_path / name
                if path.is_symlink():
                    raise RollbackError("snapshot source contains a symlink")
                rows.append(path)
        return tuple(sorted(rows, key=lambda path: (len(path.parts), path.as_posix())))

    def copy_snapshot(self, source: SnapshotSource, destination: Path) -> SnapshotEvidence:
        if source.identity in _LTFS_SNAPSHOT_ROOTS:
            self._ltfs_source_present(source.identity)
        destination.mkdir(parents=True, mode=0o700)
        roots = self._dropin_paths() if source.identity == "systemd_dropins" else (_SNAPSHOT_ROOTS[source.identity],)
        evidence: list[FileEvidence] = []
        directory_evidence: list[DirectoryEvidence] = []
        for root in roots:
            if not root.exists():
                continue
            prefix = Path(root.name) if source.identity == "systemd_dropins" else Path(".")
            if root.is_file():
                target = destination / root.name
                expected = self._file_evidence(root, Path(root.name))
                shutil.copy2(root, target, follow_symlinks=False)
                source_stat = root.stat(follow_symlinks=False)
                os.chown(
                    target,
                    source_stat.st_uid,
                    source_stat.st_gid,
                    follow_symlinks=False,
                )
                measured = self._file_evidence(target, Path(root.name))
                if measured != expected:
                    raise RollbackError("snapshot file metadata copy degraded")
                evidence.append(measured)
                continue
            directory_rows: list[tuple[Path, Path, Path]] = []
            for path in self._walk_directories(root):
                relative = (
                    Path(root.name) / path.relative_to(root)
                    if source.identity == "systemd_dropins"
                    else path.relative_to(root)
                )
                relative = Path(".") if not relative.parts else relative
                target = destination if relative == Path(".") else destination / relative
                target.mkdir(parents=True, exist_ok=True)
                directory_rows.append((path, target, relative))
            for path in self._walk_files(root):
                relative = prefix / path.relative_to(root)
                target = destination / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                expected = self._file_evidence(path, relative)
                shutil.copy2(path, target, follow_symlinks=False)
                source_stat = path.stat(follow_symlinks=False)
                os.chown(
                    target,
                    source_stat.st_uid,
                    source_stat.st_gid,
                    follow_symlinks=False,
                )
                measured = self._file_evidence(target, relative)
                if measured != expected:
                    raise RollbackError("snapshot file metadata copy degraded")
                evidence.append(measured)
            for path, target, relative in reversed(directory_rows):
                expected = self._directory_evidence(path, relative)
                shutil.copystat(path, target, follow_symlinks=False)
                details = path.stat(follow_symlinks=False)
                os.chown(
                    target, details.st_uid, details.st_gid, follow_symlinks=False
                )
                measured = self._directory_evidence(target, relative)
                if measured != expected:
                    raise RollbackError("snapshot directory metadata copy degraded")
                directory_evidence.append(measured)
        return SnapshotEvidence(
            source.identity,
            source.logical_bytes,
            tuple(sorted(evidence, key=lambda row: row.relative_path)),
            tuple(sorted(directory_evidence, key=lambda row: row.relative_path)),
        )

    @staticmethod
    def _sqlite_check(
        path: Path,
        *,
        auth: bool = False,
        catalog: bool = False,
        broker: bool = False,
        catalog_schema: str = _PREDECESSOR_CATALOG_SCHEMA,
        deployment_quiescent: bool = False,
        frozen: bool = False,
    ) -> bool:
        if not path.is_file() or path.is_symlink():
            return False
        try:
            for suffix in ("-wal", "-shm"):
                sidecar = path.with_name(path.name + suffix)
                if sidecar.is_symlink() or (sidecar.exists() and not sidecar.is_file()):
                    return False
            with tempfile.TemporaryDirectory(prefix="lto-rollback-sqlite-") as temporary:
                isolated = Path(temporary) / "state.sqlite3"
                if frozen:
                    # A SQLite read-only connection may still write WAL shared
                    # memory. Never open sealed rollback originals with SQLite.
                    SystemRollbackHost._copy_frozen_sqlite(path, isolated)
                    return SystemRollbackHost._validate_isolated_sqlite(
                        isolated, auth=auth, catalog=catalog, broker=broker,
                        catalog_schema=catalog_schema,
                        deployment_quiescent=deployment_quiescent,
                    )
                _write(isolated, b"", mode=0o600)
                # DB and WAL must belong to one SQLite snapshot, including when
                # the waiting-media daemon is still publishing catalog scans.
                deadline = time.monotonic() + 300.0

                def bounded_backup(_status: int, _remaining: int, _total: int) -> None:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("validation snapshot deadline exceeded")

                source = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
                try:
                    destination = sqlite3.connect(isolated)
                    try:
                        source.backup(destination, pages=1024, progress=bounded_backup, sleep=0.05)
                    finally:
                        destination.close()
                finally:
                    source.close()
                return SystemRollbackHost._validate_isolated_sqlite(
                    isolated, auth=auth, catalog=catalog, broker=broker,
                    catalog_schema=catalog_schema,
                    deployment_quiescent=deployment_quiescent,
                )
        except (sqlite3.Error, OSError, TypeError):
            return False

    @staticmethod
    def _copy_frozen_sqlite(path: Path, isolated: Path) -> None:
        """Copy a stopped, leased DB/WAL family without touching SQLite locks.

        SHM is disposable and rebuilt only in the private directory. Pin every
        original family member (including absent sidecars) across all copying;
        live databases must use the coherent SQLite backup path instead.
        """
        def identity(details):
            return (details.st_dev, details.st_ino, details.st_mode,
                    details.st_uid, details.st_gid, details.st_nlink,
                    details.st_size, details.st_mtime_ns, details.st_ctime_ns)

        def inventory():
            result = {}
            for suffix in ("", "-wal", "-shm"):
                member = path.with_name(path.name + suffix)
                try:
                    details = member.lstat()
                except FileNotFoundError:
                    if not suffix:
                        raise
                    result[suffix] = None
                    continue
                if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                    raise OSError("frozen SQLite family is not private regular files")
                result[suffix] = identity(details)
            return result

        before = inventory()
        # One raw DB+WAL copy, not a second SQLite backup. Reserve also covers
        # regenerated WAL-index pages; charge conservatively before allocating.
        database_bytes = before[""][6]
        wal_bytes = before["-wal"][6] if before["-wal"] else 0
        demand = database_bytes + 2 * wal_bytes + 1024**2
        usage = os.statvfs(isolated.parent)
        if usage.f_bavail * usage.f_frsize < demand + max((demand + 4) // 5, 10 * 1024**3):
            raise OSError("frozen SQLite validation scratch capacity is insufficient")
        for suffix in ("", "-wal"):
            expected = before[suffix]
            if expected is None:
                continue
            descriptor = os.open(path.with_name(path.name + suffix),
                                 os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                if identity(os.fstat(descriptor)) != expected:
                    raise OSError("frozen SQLite source identity changed")
                target = isolated.with_name(isolated.name + suffix)
                output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(output, "wb") as stream:
                    remaining = expected[6]
                    while remaining:
                        chunk = os.read(descriptor, min(1024**2, remaining))
                        if not chunk:
                            raise OSError("frozen SQLite source was truncated")
                        stream.write(chunk)
                        remaining -= len(chunk)
                if identity(os.fstat(descriptor)) != expected:
                    raise OSError("frozen SQLite source changed while copying")
            finally:
                os.close(descriptor)
        if inventory() != before:
            raise OSError("frozen SQLite family changed while copying")

    @staticmethod
    def _validate_isolated_sqlite(
        isolated: Path,
        *,
        auth: bool = False,
        catalog: bool = False,
        broker: bool = False,
        catalog_schema: str = _PREDECESSOR_CATALOG_SCHEMA,
        deployment_quiescent: bool = False,
    ) -> bool:
        """Validate only a private snapshot already owned by the calling helper.

        Live/WAL sources must go through _sqlite_check's coherent backup.
        Protected sources have already been descriptor-copied into a private
        directory and identity/hash checked, so duplicating that copy wastes a
        full catalog's worth of scratch space without adding isolation.
        """
        try:
            connection = sqlite3.connect(isolated.resolve().as_uri() + "?mode=ro", uri=True)
            try:
                integrity = connection.execute("PRAGMA integrity_check").fetchall()
                foreign = connection.execute("PRAGMA foreign_key_check").fetchall()
                if catalog:
                    row = connection.execute(
                        "SELECT value FROM metadata WHERE key='schema_version'"
                    ).fetchone()
                    schema_ok = row == (catalog_schema,)
                    if deployment_quiescent:
                        active_jobs = connection.execute(
                            "SELECT status FROM automatic_jobs "
                            "WHERE status NOT IN ('completed','failed') "
                            "ORDER BY id"
                        ).fetchall()
                        active_operations = connection.execute(
                            "SELECT COUNT(*) FROM daemon_operations "
                            "WHERE state IN ('running','recovery_required')"
                        ).fetchone()
                        quiescence_ok = bool(
                            len(active_jobs) <= 1
                            and all(
                                state in {"paused", "waiting_media"}
                                for (state,) in active_jobs
                            )
                            and active_operations == (0,)
                        )
                    else:
                        quiescence_ok = True
                elif auth:
                    version = connection.execute("PRAGMA user_version").fetchone()[0]
                    tables = {
                        row[0]
                        for row in connection.execute(
                            "SELECT name FROM sqlite_schema WHERE type='table'"
                        )
                    }
                    expected = {
                        "web_users",
                        "web_sessions",
                        "web_auth_audit",
                        "web_idempotency",
                    }
                    schema_ok = version == 2 and {
                        name for name in tables if not name.startswith("sqlite_")
                    } == expected
                elif broker:
                    schema_ok = connection.execute("PRAGMA user_version").fetchone()[0] == 10
                else:
                    schema_ok = False
            finally:
                connection.close()
        except (sqlite3.Error, OSError, TypeError):
            return False
        return (
            integrity == [("ok",)]
            and not foreign
            and schema_ok
            and (not catalog or quiescence_ok)
        )

    def _protected_backup_check(
        self, path: Path, *, expected_name: str | None = None
    ) -> bool:
        match = _PROTECTED_BACKUP_NAME.fullmatch(
            expected_name if expected_name is not None else path.name
        )
        if match is None:
            return False
        version = int(match["version"])
        if not (
            _MIN_PROTECTED_CATALOG_SCHEMA
            <= version
            <= _MAX_PROTECTED_CATALOG_SCHEMA
        ):
            return False
        try:
            root = path.parent
            root_details = root.stat(follow_symlinks=False)
            if (
                root.is_symlink()
                or not stat.S_ISDIR(root_details.st_mode)
                or stat.S_IMODE(root_details.st_mode) != 0o750
            ):
                return False
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                details = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(details.st_mode)
                    or details.st_nlink != 1
                    or details.st_uid != root_details.st_uid
                    or details.st_gid != root_details.st_gid
                    or stat.S_IMODE(details.st_mode) != 0o600
                    or details.st_size <= 0
                ):
                    return False
                with tempfile.TemporaryDirectory(
                    prefix="lto-service-backup-"
                ) as temporary:
                    isolated = Path(temporary) / path.name
                    output = os.open(
                        isolated,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                    )
                    try:
                        while chunk := os.read(descriptor, 1024 * 1024):
                            os.write(output, chunk)
                        os.fsync(output)
                    finally:
                        os.close(output)
                    after = os.fstat(descriptor)
                    if (
                        details.st_dev,
                        details.st_ino,
                        details.st_size,
                        details.st_mtime_ns,
                        details.st_ctime_ns,
                    ) != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    ):
                        return False
                    return self._sqlite_check(
                        isolated,
                        catalog=True,
                        catalog_schema=str(version),
                    )
            finally:
                os.close(descriptor)
        except OSError:
            return False

    def check_copied_state(self, snapshots: Path) -> tuple[StateCheck, ...]:
        catalog = snapshots / "application_state/catalog.db"
        broker = snapshots / "command_broker_state/state.db"
        auth = snapshots / "web_auth_state/auth.sqlite3"
        backups = tuple(
            (
                snapshots
                / "application_state"
                / _PROTECTED_BACKUP_RELATIVE
            ).glob("*-p-*.sqlite3")
        )
        protected_ok = bool(backups) and all(
            self._protected_backup_check(path)
            and int(_PROTECTED_BACKUP_NAME.fullmatch(path.name)["version"])
            <= int(_PREDECESSOR_CATALOG_SCHEMA)
            for path in backups
        )
        share_ok = self._share_state_check(
            snapshots / "share_broker_state",
            snapshots / "configuration/share-credentials",
        )
        checks = {
            "catalog": self._sqlite_check(catalog, catalog=True, frozen=True),
            "protected_catalog_backup": protected_ok,
            "command_broker": self._sqlite_check(broker, broker=True, frozen=True),
            "share_broker_state": share_ok,
            "web_auth": self._sqlite_check(auth, auth=True, frozen=True),
        }
        return tuple(StateCheck(name, ok, ok, ok) for name, ok in sorted(checks.items()))

    @staticmethod
    def _share_state_check(state_root: Path, credential_root: Path) -> bool:
        if not state_root.is_dir() or state_root.is_symlink():
            return False
        states: dict[str, dict[str, object]] = {}
        try:
            for path in sorted(state_root.iterdir()):
                if (
                    path.is_symlink()
                    or not path.is_file()
                    or not path.name.endswith((".state", ".mount-state"))
                ):
                    return False
                raw = path.read_bytes()
                value = json.loads(
                    raw.decode("ascii"), object_pairs_hook=_closed_object
                )
                if not isinstance(value, dict) or raw != json.dumps(
                    value, sort_keys=True, separators=(",", ":")
                ).encode("ascii"):
                    return False
                if path.name.endswith(".mount-state"):
                    share_id = path.name[: -len(".mount-state")]
                    if (
                        set(value)
                        != {
                            "version",
                            "share_id",
                            "config",
                            "config_revision",
                            "credential_generation",
                            "mounted",
                            "mount_identity_sha256",
                        }
                        or value.get("version") != 1
                        or value.get("share_id") != share_id
                        or type(value.get("config_revision")) is not int
                        or type(value.get("credential_generation")) is not int
                        or type(value.get("mounted")) is not bool
                        or (
                            value.get("mount_identity_sha256") is not None
                            and not _HEX64.fullmatch(
                                str(value["mount_identity_sha256"])
                            )
                        )
                        or value["mounted"]
                        != (value.get("mount_identity_sha256") is not None)
                    ):
                        return False
                else:
                    share_id = path.name[: -len(".state")]
                    cleanup = value.get("cleanup_generations")
                    if (
                        set(value)
                        != {
                            "version",
                            "share_id",
                            "generation",
                            "configured",
                            "request_hmac",
                            "cleanup_generations",
                        }
                        or value.get("version") != 2
                        or value.get("share_id") != share_id
                        or type(value.get("generation")) is not int
                        or int(value["generation"]) < 1
                        or type(value.get("configured")) is not bool
                        or not _HEX64.fullmatch(str(value.get("request_hmac")))
                        or not isinstance(cleanup, list)
                        or any(type(item) is not int or item < 1 for item in cleanup)
                        or cleanup != sorted(set(cleanup))
                    ):
                        return False
                    states[share_id] = value
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            RollbackError,
            TypeError,
            ValueError,
        ):
            return False
        for share_id, value in states.items():
            if value["configured"]:
                credential = (
                    credential_root
                    / f"{share_id}.g{value['generation']}.credentials"
                )
                if not credential.is_file() or credential.is_symlink():
                    return False
        return True

    def custom_web_unit_sha256(self) -> str:
        path = _SNAPSHOT_ROOTS["custom_web_unit"]
        return _digest(path.read_bytes()) if path.is_file() and not path.is_symlink() else "ABSENT"

    def captured_enablement(self) -> Mapping[str, str]:
        captured = getattr(self, "_pre_mask_enablement", None)
        if isinstance(captured, dict) and _valid_unit_enablement(captured):
            return dict(captured)
        self._require_tool(_SYSTEMCTL)
        enablement: dict[str, str] = {}
        absent_reader_units: set[str] = set()
        for unit in STOP_UNITS:
            result = self._run((_SYSTEMCTL, "is-enabled", unit), accepted=(0, 1))
            try:
                enablement[unit] = _canonical_unit_enablement(result)
            except RollbackError:
                if (
                    unit in _LOG_READER_UNITS
                    and _reader_unit_is_exactly_absent(result, unit)
                ):
                    absent_reader_units.add(unit)
                    continue
                raise
        if absent_reader_units and absent_reader_units != _LOG_READER_UNITS:
            raise RollbackError("reader unit presence is inconsistent")
        if not _valid_unit_enablement(enablement):
            raise RollbackError("captured unit enablement is invalid")
        return enablement

    def firewall_observation_digest(self) -> str:
        self._require_tool(_FIREWALL)
        return _digest(_canonical(self.captured_firewall_policy()))

    def _firewall_zone(self) -> str:
        configured = getattr(self, "_deployment_firewall_zone", None)
        if isinstance(configured, str) and re.fullmatch(
            r"[A-Za-z0-9_-]{1,32}", configured
        ):
            return configured
        try:
            value = tomllib.loads(Path("/etc/lto-archiver/web.toml").read_text())
            zone = value["firewall_zone"]
        except (OSError, UnicodeError, tomllib.TOMLDecodeError, KeyError, TypeError):
            raise RollbackError("WebUI firewall zone is unavailable") from None
        if not isinstance(zone, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", zone):
            raise RollbackError("WebUI firewall zone is invalid")
        return zone

    def captured_firewall_policy(self) -> Mapping[str, object]:
        self._require_tool(_FIREWALL)
        zone = self._firewall_zone()
        result: dict[str, object] = {"schema": 1, "zone": zone}
        for permanent, suffix in ((False, "runtime"), (True, "permanent")):
            prefix: tuple[str, ...] = ("--permanent",) if permanent else ()
            result[f"rich_rules_{suffix}"] = sorted(
                filter(
                    None,
                    self._run(
                        (_FIREWALL, f"--zone={zone}", *prefix, "--list-rich-rules")
                    ).stdout.splitlines(),
                )
            )
            result[f"ports_{suffix}"] = sorted(
                self._run(
                    (_FIREWALL, f"--zone={zone}", *prefix, "--list-ports")
                ).stdout.split()
            )
            result[f"services_{suffix}"] = sorted(
                self._run(
                    (_FIREWALL, f"--zone={zone}", *prefix, "--list-services")
                ).stdout.split()
            )
        return result

    def copy_bundle_tools(self, destination: Path) -> Mapping[str, str]:
        destination.mkdir(parents=True, mode=0o700)
        sources = {
            "rollback-rhel9.py": self._script_dir / "rollback-rhel9.py",
            "deployment_artifacts.py": self._script_dir / "deployment_artifacts.py",
            "verify-deployment-rhel9.py": self._script_dir / "verify-deployment-rhel9.py",
            "rpm-verify-policy.json": self._deployment_dir / "rpm-verify-policy.json",
            "journal-policy.json": self._deployment_dir / "journal-policy.json",
        }
        result: dict[str, str] = {}
        for name, source in sources.items():
            if not source.is_file() or source.is_symlink():
                raise RollbackError("bundle tool authority is missing")
            target = destination / name
            shutil.copyfile(source, target)
            os.chmod(target, 0o700 if name.endswith(".py") else 0o600)
            result[name] = _digest(target.read_bytes())
        return result

    def tool_versions(self) -> Mapping[str, str]:
        return {
            "python": sys.version.split()[0],
            "rpm": self._run((_RPM, "--version")).stdout.strip(),
        }

    def verify_bundle_security(self, bundle: Path) -> bool:
        try:
            for path in (bundle, *bundle.rglob("*")):
                details = path.stat(follow_symlinks=False)
                if not self._bundle_security_entry_ok(bundle, path, details):
                    return False
        except OSError:
            return False
        return stat.S_IMODE(bundle.stat().st_mode) == 0o700

    @staticmethod
    def _bundle_security_entry_ok(bundle: Path, path: Path, details: os.stat_result) -> bool:
        if stat.S_ISLNK(details.st_mode) or not (
            stat.S_ISDIR(details.st_mode) or stat.S_ISREG(details.st_mode)
        ):
            return False
        try:
            relative = path.relative_to(bundle)
        except ValueError:
            return False
        # Snapshot descendants deliberately retain the source owner and mode so
        # rollback can restore them exactly.  The root-owned snapshots container
        # remains sealed; verify_snapshot_evidence binds every retained file's
        # owner, group, mode, size and digest into the signed manifest.
        if len(relative.parts) >= 2 and relative.parts[0] == "snapshots":
            return True
        return details.st_uid == 0 and not details.st_mode & 0o022

    def verify_rpm_evidence(self, evidence: tuple[RpmEvidence, ...]) -> bool:
        directory = getattr(self, "_verified_bundle", None)
        if not isinstance(directory, Path):
            return all(row.signature_status in {"verified", "legacy-unsigned"} for row in evidence)
        observed = tuple(self.inspect_rollback_rpms(directory / "rpms"))
        if observed == evidence:
            return True
        # Old schema-2/3 inspectors recorded successful nonverbose checks without
        # a key ID. Reverify the actual signatures; only that historical field
        # may differ, within the exact legacy predecessor closure.
        try:
            value, raw = _read_json(directory / "bundle-manifest.json")
            manifest = _parse_manifest(value, raw)
        except RollbackError:
            return False
        if (
            manifest.schema not in {2, 3}
            or dict(manifest.installed_nevras) != _LEGACY_PREDECESSOR_NEVRAS
            or manifest.rpms != evidence or len(observed) != len(evidence)
        ):
            return False
        return all(
            actual == recorded or (
                recorded.target in {"application", "runtime"}
                and recorded.signature_status == actual.signature_status == "verified"
                and recorded.signing_key_id == "absent"
                and actual.signing_key_id != "absent"
                and replace(actual, signing_key_id="absent") == recorded
            )
            for actual, recorded in zip(observed, evidence)
        )

    def begin_bundle_verification(self, bundle: Path) -> None:
        self._verified_bundle = bundle

    def _ltfs_snapshot_contents_ok(self, root: Path, snapshot: SnapshotEvidence) -> bool:
        if not root.is_dir() or root.is_symlink():
            return False
        files = tuple(row.relative_path for row in snapshot.files)
        directories = tuple(row.relative_path for row in snapshot.directories)
        if len(set(files)) != len(files) or len(set(directories)) != len(directories):
            return False
        if snapshot.identity in _FILE_SNAPSHOTS:
            if directories or files not in ((), (_SNAPSHOT_ROOTS[snapshot.identity].name,)):
                return False
        elif (files or directories) and "." not in directories:
            return False
        actual_files = {
            path.relative_to(root).as_posix() for path in self._walk_files(root)
        }
        actual_directories = {
            path.relative_to(root).as_posix()
            for path in self._walk_directories(root)
            if path != root or "." in directories
        }
        return actual_files == set(files) and actual_directories == set(directories)

    def verify_snapshot_evidence(self, bundle: Path, evidence: tuple[SnapshotEvidence, ...]) -> bool:
        self._verified_bundle = bundle
        try:
            for snapshot in evidence:
                root = bundle / "snapshots" / snapshot.identity
                if snapshot.identity in _LTFS_SNAPSHOT_ROOTS and not self._ltfs_snapshot_contents_ok(root, snapshot):
                    return False
                if tuple(sorted(record.relative_path for record in snapshot.files)) != tuple(record.relative_path for record in snapshot.files):
                    return False
                for record in snapshot.files:
                    path = root / record.relative_path
                    if not path.is_file() or path.is_symlink():
                        return False
                    measured = self._file_evidence(path, Path(record.relative_path))
                    if measured != record:
                        return False
                expected_directories = {
                    record.relative_path for record in snapshot.directories
                }
                actual_directories = {
                    path.relative_to(root).as_posix()
                    for path in root.rglob("*")
                    if path.is_dir() and not path.is_symlink()
                }
                if "." in expected_directories:
                    actual_directories.add(".")
                if actual_directories != expected_directories:
                    return False
                for record in snapshot.directories:
                    path = (
                        root
                        if record.relative_path == "."
                        else root / record.relative_path
                    )
                    if (
                        not path.is_dir()
                        or path.is_symlink()
                        or self._directory_evidence(
                            path, Path(record.relative_path)
                        )
                        != record
                    ):
                        return False
        except (OSError, RollbackError):
            return False
        return True

    def verify_copied_state(self, bundle: Path, checks: tuple[StateCheck, ...]) -> bool:
        return self.check_copied_state(bundle / "snapshots") == checks

    def fsync_tree(self, root: Path) -> None:
        for path in sorted(root.rglob("*"), reverse=True):
            flags = os.O_RDONLY | (os.O_DIRECTORY if path.is_dir() else 0)
            descriptor = os.open(path, flags)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def publish_noreplace(self, staging: Path, final: Path) -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = getattr(libc, "renameat2", None)
        if renameat2 is None:
            raise RollbackError("atomic no-replace rename is unavailable")
        result = renameat2(-100, os.fsencode(staging), -100, os.fsencode(final), 1)
        if result != 0:
            raise RollbackError("atomic no-replace publication failed")
        descriptor = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def mask_stop_and_prove_idle(self, units: tuple[str, ...]) -> None:
        self._require_tool(_SYSTEMCTL)
        self._require_tool(_FINDMNT)
        if units != STOP_UNITS:
            raise RollbackError("service stop closure is invalid")
        enablement = dict(self.captured_enablement())
        if not _valid_unit_enablement(enablement):
            raise RollbackError("captured unit enablement is invalid")
        self._pre_mask_enablement = enablement
        self._mask_stop_and_prove_idle(units)

    def remask_stop_and_prove_idle(self, units: tuple[str, ...]) -> None:
        self._require_tool(_SYSTEMCTL)
        self._require_tool(_FINDMNT)
        if units != STOP_UNITS:
            raise RollbackError("service stop closure is invalid")
        self._mask_stop_and_prove_idle(units)

    def _mask_stop_and_prove_idle(self, units: tuple[str, ...]) -> None:
        self._run((_SYSTEMCTL, "mask", "--runtime", *units))
        for unit in units:
            self._run((_SYSTEMCTL, "stop", unit), accepted=(0, 5))
            if self._run((_SYSTEMCTL, "is-active", unit), accepted=(0, 3, 4)).returncode == 0:
                raise RollbackError("service did not stop")
        if self._run((_FINDMNT, "--mountpoint", "/mnt/lto-archiver/tape"), accepted=(0, 1)).returncode == 0:
            raise RollbackError("tape remains mounted")
        forbidden = ("/usr/bin/ltfs", "/usr/bin/mkltfs", "/usr/bin/ltfsck", "lto-archiver-qualify")
        for process in Path("/proc").glob("[0-9]*/cmdline"):
            try:
                command = process.read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if any(marker in command for marker in forbidden):
                raise RollbackError("LTFS or qualification process remains active")

    def install_local_rollback(
        self, runtime_rpm: Path, app_rpm: Path, driver_rpm: Path | None = None
    ) -> None:
        self._require_tool(_DNF)
        installed = dict(self.installed_nevras())
        predecessor = _PREDECESSOR_NEVRAS if driver_rpm is not None else _LEGACY_PREDECESSOR_NEVRAS
        if installed == predecessor:
            return
        admitted = (
            _coordinated_package_state_known(installed)
            if driver_rpm is not None else installed == _LEGACY_DEPLOYED_NEVRAS
        )
        if not admitted:
            raise RollbackError("installed package closure cannot be rolled back")
        self._run(
            (
                _DNF,
                "--disablerepo=*",
                "--setopt=install_weak_deps=False",
                "--assumeyes",
                "downgrade",
                runtime_rpm,
                app_rpm,
                *((driver_rpm,) if driver_rpm is not None else ()),
            )
        )
        if dict(self.installed_nevras()) != predecessor:
            raise RollbackError("rollback package closure is not exact")

    def driver_package_state_matches(self, contract: Mapping[str, object]) -> bool:
        self._require_tool(_RPM)
        header = self._run((
            _RPM, "-q", "--qf",
            "%{NAME}\n%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n%{PAYLOADDIGEST}\n",
            "lto-ltfs",
        ))
        metadata = self._run((_RPM, "-ql", "--dump", "lto-ltfs"))
        return (
            header.returncode == 0 and metadata.returncode == 0
            and not header.stderr and not metadata.stderr
            and header.stdout.endswith("\n") and metadata.stdout.endswith("\n")
            and _digest(header.stdout.encode()) == contract["rpm_header_sha256"]
            and _digest(metadata.stdout.encode()) == contract["installed_file_metadata_sha256"]
        )

    def verify_untouched_driver(self, manifest: BundleManifest) -> bool:
        bundle = getattr(self, "_verified_bundle", None)
        if not isinstance(bundle, Path):
            return False
        try:
            contract_bytes = _validate_driver_contract(
                bundle / "contracts/driver-input.json",
                manifest.driver_input_sha256,
                legacy=manifest.schema < 4,
            )
            contract = json.loads(
                contract_bytes.decode(), object_pairs_hook=_closed_object
            )
            old_live, _raw = _read_json(
                bundle / "contracts/old-live-contract.json"
            )
            authority = old_live.get("driver_authority")
            expected_authority = {
                key: contract[key]
                for key in (
                    "rpm_public_key_sha256",
                    "rpm_signing_policy_sha256",
                    "rpm_verify_policy_sha256",
                    "source_provenance_evidence_sha256",
                    "source_provenance_status",
                )
            }
            current = self.captured_installed_package_state()
            packages = current.get("packages")
            driver_state = (
                packages.get("lto-ltfs") if isinstance(packages, dict) else None
            )
            driver_rpm = next(
                row for row in manifest.rpms if row.target == "driver-evidence"
            )
            supplied = tuple(
                row
                for row in self.inspect_rollback_rpms(bundle / "rpms")
                if row.target == "driver-evidence"
            )
            signature_ok = (
                (
                    driver_rpm.signature_status == "verified"
                    and bool(driver_rpm.signing_key_id)
                    and driver_rpm.signing_key_id != "absent"
                )
                or (
                    contract["package_nevra"] == "lto-ltfs-0.1.0-16.el9.x86_64"
                    and contract["source_provenance_status"] == "local-build-identity-only"
                    and driver_rpm.signature_status == "legacy-unsigned"
                    and driver_rpm.signing_key_id == "absent"
                )
            )
            return (
                authority == expected_authority
                and isinstance(driver_state, dict)
                and driver_state.get("nevra") == contract["package_nevra"]
                and driver_state.get("installed_file_metadata_sha256")
                == contract["installed_file_metadata_sha256"]
                and driver_state.get("rpm_verify_exit") == 1
                and driver_state.get("rpm_verify_stdout_sha256")
                == _digest((_DRIVER_RPM_VERIFY_ROW + "\n").encode())
                and driver_state.get("rpm_verify_rows")
                == [_DRIVER_RPM_VERIFY_ROW]
                and driver_rpm.nevra == contract["package_nevra"]
                and driver_rpm.sha256 == contract["rpm_raw_sha256"]
                and driver_rpm.header_sha256 == contract["rpm_header_sha256"]
                and driver_rpm.payload_sha256
                == contract["rpm_payload_sha256"]
                and supplied == (driver_rpm,)
                and signature_ok
            )
        except (KeyError, OSError, RollbackError, StopIteration, TypeError):
            return False

    def create_recovery_directory(self, bundle_id: str) -> Path:
        root = _ROLLBACK_RECOVERY_ROOT
        root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(root, 0o700)
        target = root / bundle_id
        target.mkdir(mode=0o700)
        return target

    def begin_restore_health_window(self, recovery: Path) -> None:
        """Durably mark this activation, without rewriting prior incident evidence."""
        self._restore_health_window = None
        bundle = getattr(self, "_verified_bundle", None)
        if (
            not isinstance(bundle, Path)
            or not recovery.is_absolute()
            or recovery.resolve() != recovery
            or not self.parent_is_secure(recovery)
        ):
            raise RollbackError("restore health window requires verified private state")
        payload = {
            "schema": 1,
            "bundle_manifest_sha256": _digest((bundle / "bundle-manifest.json").read_bytes()),
            "restoration_started_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        path = recovery / "restore-health-window.json"
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(_canonical(payload))
            handle.flush()
            os.fsync(handle.fileno())
        for directory in (recovery, recovery.parent):
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        self._restore_health_window = (path, _canonical(payload))

    @staticmethod
    def _staged_relative(relative_path: str, prefix: Path) -> Path | None:
        relative = Path(relative_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise RollbackError("snapshot evidence path is unsafe")
        if prefix == Path("."):
            return relative
        try:
            return relative.relative_to(prefix)
        except ValueError:
            return None

    def _apply_staged_tree_metadata(
        self,
        source_root: Path,
        staged_root: Path,
        snapshot: SnapshotEvidence,
        prefix: Path,
    ) -> None:
        files = tuple(
            (record, relative)
            for record in snapshot.files
            if (relative := self._staged_relative(record.relative_path, prefix))
            is not None
        )
        directories = tuple(
            (record, relative)
            for record in snapshot.directories
            if (relative := self._staged_relative(record.relative_path, prefix))
            is not None
        )
        for record, relative in files:
            source = source_root / record.relative_path
            staged = staged_root / relative
            if (
                not source.is_file()
                or source.is_symlink()
                or not staged.is_file()
                or staged.is_symlink()
            ):
                raise RollbackError("staged snapshot file is invalid")
            os.chown(staged, record.uid, record.gid, follow_symlinks=False)
            shutil.copystat(source, staged, follow_symlinks=False)
            os.chmod(staged, record.mode, follow_symlinks=False)
        for record, relative in sorted(
            directories,
            key=lambda row: (len(row[1].parts), row[1].as_posix()),
            reverse=True,
        ):
            source = source_root / record.relative_path
            staged = staged_root if relative == Path(".") else staged_root / relative
            if (
                not source.is_dir()
                or source.is_symlink()
                or not staged.is_dir()
                or staged.is_symlink()
            ):
                raise RollbackError("staged snapshot directory is invalid")
            os.chown(staged, record.uid, record.gid, follow_symlinks=False)
            shutil.copystat(source, staged, follow_symlinks=False)
            os.chmod(staged, record.mode, follow_symlinks=False)

    def _verify_staged_tree(
        self,
        staged_root: Path,
        snapshot: SnapshotEvidence,
        prefix: Path,
    ) -> bool:
        try:
            expected_files = {
                relative: record
                for record in snapshot.files
                if (
                    relative := self._staged_relative(record.relative_path, prefix)
                )
                is not None
            }
            expected_directories = {
                relative: record
                for record in snapshot.directories
                if (
                    relative := self._staged_relative(record.relative_path, prefix)
                )
                is not None
            }
            actual_files = {
                path.relative_to(staged_root): path
                for path in self._walk_files(staged_root)
            }
            actual_directories = {
                (
                    Path(".")
                    if path == staged_root
                    else path.relative_to(staged_root)
                ): path
                for path in self._walk_directories(staged_root)
            }
            if (
                set(actual_files) != set(expected_files)
                or set(actual_directories) != set(expected_directories)
            ):
                return False
            return all(
                self._file_evidence(actual_files[relative], Path(record.relative_path))
                == record
                for relative, record in expected_files.items()
            ) and all(
                self._directory_evidence(
                    actual_directories[relative], Path(record.relative_path)
                )
                == record
                for relative, record in expected_directories.items()
            )
        except (OSError, RollbackError, ValueError):
            return False

    def _apply_and_verify_staged_file(
        self,
        source: Path,
        staged: Path,
        snapshot: SnapshotEvidence,
        relative_path: Path,
    ) -> None:
        records = tuple(
            record
            for record in snapshot.files
            if record.relative_path == relative_path.as_posix()
        )
        if len(records) != 1 or snapshot.directories:
            raise RollbackError("staged snapshot file evidence is invalid")
        record = records[0]
        if (
            set(row.relative_path for row in snapshot.files)
            != {relative_path.as_posix()}
            or not source.is_file()
            or source.is_symlink()
            or not staged.is_file()
            or staged.is_symlink()
        ):
            raise RollbackError("staged snapshot file is invalid")
        os.chown(staged, record.uid, record.gid, follow_symlinks=False)
        shutil.copystat(source, staged, follow_symlinks=False)
        os.chmod(staged, record.mode, follow_symlinks=False)
        if self._file_evidence(staged, relative_path) != record:
            raise RollbackError("staged snapshot file metadata degraded")

    @staticmethod
    def _stage_guard_is_secure(path: Path) -> bool:
        try:
            details = path.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            not path.is_symlink()
            and stat.S_ISDIR(details.st_mode)
            and details.st_uid == 0
            and stat.S_IMODE(details.st_mode) == 0o700
        )

    def _new_stage_guard(self, parent: Path, prefix: str) -> Path:
        guard = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
        try:
            os.chown(guard, 0, 0)
            os.chmod(guard, 0o700)
            if not self._stage_guard_is_secure(guard):
                raise RollbackError("staged snapshot guard is insecure")
        except (OSError, RollbackError) as error:
            shutil.rmtree(guard, ignore_errors=True)
            raise RollbackError("staged snapshot guard creation failed") from error
        return guard

    def stage_snapshot(self, bundle: Path, snapshot: SnapshotEvidence) -> object:
        target = _SNAPSHOT_ROOTS[snapshot.identity]
        source = bundle / "snapshots" / snapshot.identity
        if snapshot.identity in _LTFS_SNAPSHOT_ROOTS:
            if not self._ltfs_snapshot_contents_ok(source, snapshot):
                raise RollbackError("LTFS snapshot contents or shape are invalid")
            self._ltfs_source_present(snapshot.identity)
            if not snapshot.files and not snapshot.directories:
                if tuple(source.iterdir()):
                    raise RollbackError("absent LTFS snapshot contains files")
                return StagedSwap(((target, None),))
            if snapshot.identity == "ltfs_device_configuration" and not any(
                row.relative_path == "." for row in snapshot.directories
            ):
                raise RollbackError("LTFS directory snapshot has no root evidence")
        if snapshot.identity == "systemd_dropins":
            items: list[tuple[Path, Path | None]] = []
            guard = self._new_stage_guard(
                target, ".lto-archiver-dropins.restore-"
            )
            try:
                saved_names = {
                    path.name for path in source.iterdir() if path.is_dir()
                }
                live_names = {path.name for path in self._dropin_paths()}
                for name in sorted(saved_names | live_names):
                    live = target / name
                    saved = source / name
                    staged: Path | None = None
                    if saved.is_dir():
                        staged = guard / name
                        shutil.copytree(saved, staged, copy_function=shutil.copy2)
                        self._apply_staged_tree_metadata(
                            source, staged, snapshot, Path(name)
                        )
                        if not self._verify_staged_tree(
                            staged, snapshot, Path(name)
                        ):
                            raise RollbackError("staged snapshot metadata degraded")
                    items.append((live, staged))
            except Exception:
                shutil.rmtree(guard, ignore_errors=True)
                raise
            return StagedSwap(tuple(items), (guard,))
        if snapshot.identity in _FILE_SNAPSHOTS:
            saved = source / target.name
            if not saved.exists():
                if snapshot.identity in _LTFS_SNAPSHOT_ROOTS:
                    raise RollbackError("LTFS file snapshot evidence is missing")
                return StagedSwap(((target, None),))
            guard = self._new_stage_guard(
                target.parent, f".{target.name}.restore-"
            )
            staged = guard / target.name
            try:
                shutil.copy2(saved, staged, follow_symlinks=False)
                self._apply_and_verify_staged_file(
                    saved, staged, snapshot, Path(target.name)
                )
            except Exception:
                shutil.rmtree(guard, ignore_errors=True)
                raise
            return StagedSwap(((target, staged),), (guard,))
        guard = self._new_stage_guard(
            target.parent, f".{target.name}.restore-"
        )
        staged = guard / target.name
        try:
            shutil.copytree(source, staged, copy_function=shutil.copy2)
            self._apply_staged_tree_metadata(source, staged, snapshot, Path("."))
            if not self._verify_staged_tree(staged, snapshot, Path(".")):
                raise RollbackError("staged snapshot metadata degraded")
        except Exception:
            shutil.rmtree(guard, ignore_errors=True)
            raise
        return StagedSwap(((target, staged),), (guard,))

    def swap_snapshot(self, identity: str, staged: object, recovery: Path) -> None:
        if not isinstance(staged, StagedSwap):
            raise RollbackError("invalid staged snapshot")
        try:
            if any(
                not self._stage_guard_is_secure(path)
                for path in staged.guard_directories
            ):
                raise RollbackError("staged snapshot guard drifted")
            guarded_replacements = {
                replacement
                for _target, replacement in staged.items
                if replacement is not None
            }
            if staged.guard_directories and any(
                replacement.parent not in staged.guard_directories
                for replacement in guarded_replacements
            ):
                raise RollbackError("staged snapshot escaped its guard")
            completed: list[tuple[Path, Path]] = []
            recovery_root = recovery / identity
            recovery_root.mkdir(mode=0o700)
            try:
                for target, replacement in staged.items:
                    saved = recovery_root / target.name
                    moved_current = False
                    if target.exists():
                        os.replace(target, saved)
                        moved_current = True
                    try:
                        if replacement is not None:
                            os.replace(replacement, target)
                    except Exception:
                        if moved_current and not target.exists() and saved.exists():
                            os.replace(saved, target)
                        raise
                    completed.append((target, saved))
            except Exception:
                for target, saved in reversed(completed):
                    if target.exists():
                        os.replace(target, recovery_root / f"failed-{target.name}")
                    if saved.exists():
                        os.replace(saved, target)
                raise
        finally:
            for guard in reversed(staged.guard_directories):
                shutil.rmtree(guard, ignore_errors=True)

    def reverse_snapshot_swap(self, identity: str, recovery: Path) -> None:
        recovery_root = recovery / identity
        targets = self._dropin_paths() if identity == "systemd_dropins" else (_SNAPSHOT_ROOTS[identity],)
        saved_names = {path.name for path in recovery_root.iterdir()} if recovery_root.is_dir() else set()
        by_name = {path.name: path for path in targets}
        for name in sorted(saved_names | set(by_name), reverse=True):
            target = by_name.get(name, _SNAPSHOT_ROOTS["systemd_dropins"] / name)
            saved = recovery_root / name
            if target.exists():
                os.replace(target, recovery_root / f"failed-restore-{name}")
            if saved.exists():
                os.replace(saved, target)

    def restore_platform_state(self, manifest: BundleManifest) -> None:
        self._require_tool(_RESTORECON)
        for snapshot in manifest.snapshots:
            root = _SNAPSHOT_ROOTS[snapshot.identity]
            if root.exists():
                self._run((_RESTORECON, "-RF", root))
        self._run((_SYSTEMCTL, "daemon-reload"))
        bundle = getattr(self, "_verified_bundle", None)
        if not isinstance(bundle, Path):
            raise RollbackError("verified rollback bundle is unavailable")
        value, _raw = _read_json(bundle / "contracts/old-live-contract.json")
        firewall = value.get("firewall_policy")
        firewall_keys = {
            "ports_permanent",
            "ports_runtime",
            "rich_rules_permanent",
            "rich_rules_runtime",
            "schema",
            "services_permanent",
            "services_runtime",
            "zone",
        }
        if not isinstance(firewall, dict) or set(firewall) != firewall_keys or firewall.get("schema") != 1:
            raise RollbackError("captured firewall policy is unavailable")
        zone = firewall.get("zone")
        if not isinstance(zone, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", zone):
            raise RollbackError("captured firewall zone is invalid")
        for permanent, suffix in ((False, "runtime"), (True, "permanent")):
            prefix: tuple[str, ...] = ("--permanent",) if permanent else ()
            current = set(
                filter(
                    None,
                    self._run(
                        (_FIREWALL, f"--zone={zone}", *prefix, "--list-rich-rules")
                    ).stdout.splitlines(),
                )
            )
            desired_value = firewall[f"rich_rules_{suffix}"]
            if not isinstance(desired_value, list) or any(
                not isinstance(item, str) for item in desired_value
            ):
                raise RollbackError("captured firewall rule is invalid")
            desired = set(desired_value)
            for rule in sorted(current - desired):
                self._run(
                    (
                        _FIREWALL,
                        f"--zone={zone}",
                        *prefix,
                        f"--remove-rich-rule={rule}",
                    )
                )
            for rule in sorted(desired - current):
                self._run(
                    (
                        _FIREWALL,
                        f"--zone={zone}",
                        *prefix,
                        f"--add-rich-rule={rule}",
                    )
                )
            ports = sorted(
                self._run(
                    (_FIREWALL, f"--zone={zone}", *prefix, "--list-ports")
                ).stdout.split()
            )
            services = sorted(
                self._run(
                    (_FIREWALL, f"--zone={zone}", *prefix, "--list-services")
                ).stdout.split()
            )
            if ports != firewall[f"ports_{suffix}"] or services != firewall[f"services_{suffix}"]:
                raise RollbackError("firewall port or service policy drifted")

    def revalidate_restored_state(self, manifest: BundleManifest) -> None:
        catalog = Path("/var/lib/lto-archiver/catalog.db")
        broker = Path("/var/lib/lto-archiver-broker/state.db")
        auth = Path("/var/lib/lto-archiver-web/auth.sqlite3")
        backups = tuple(
            _PROTECTED_BACKUP_ROOT.glob("*-p-*.sqlite3")
        )
        share_ok = self._share_state_check(
            Path("/var/lib/lto-archiver-share-broker"),
            Path("/etc/lto-archiver/share-credentials"),
        )
        protected_ok = bool(backups) and all(
            self._protected_backup_check(path)
            and int(_PROTECTED_BACKUP_NAME.fullmatch(path.name)["version"])
            <= int(_PREDECESSOR_CATALOG_SCHEMA)
            for path in backups
        )
        if not all(
            (
                self._sqlite_check(catalog, catalog=True),
                self._sqlite_check(broker, broker=True),
                self._sqlite_check(auth, auth=True),
                protected_ok,
                share_ok,
            )
        ):
            raise RollbackError("restored catalog failed validation")

    def verify_restored_ltfs_configuration(self, manifest: BundleManifest) -> bool:
        try:
            for snapshot in manifest.snapshots:
                if snapshot.identity not in _LTFS_SNAPSHOT_ROOTS:
                    continue
                present = self._ltfs_source_present(snapshot.identity)
                if not snapshot.files and not snapshot.directories:
                    if present:
                        return False
                    continue
                if not present:
                    return False
                target = _SNAPSHOT_ROOTS[snapshot.identity]
                if snapshot.identity in _FILE_SNAPSHOTS:
                    if snapshot.directories or len(snapshot.files) != 1:
                        return False
                    if self._file_evidence(target, Path(target.name)) != snapshot.files[0]:
                        return False
                elif not self._verify_staged_tree(target, snapshot, Path(".")):
                    return False
            return True
        except (OSError, RollbackError, ValueError):
            return False

    def restore_protected_catalog(
        self, manifest: BundleManifest, recovery: Path
    ) -> None:
        bundle = getattr(self, "_verified_bundle", None)
        if not isinstance(bundle, Path):
            raise RollbackError("verified bundle is unavailable")
        selected = bundle / manifest.protected_backup_relative_path
        observed = self._protected_source_values(selected)
        if observed != (
            manifest.source_catalog_schema,
            manifest.protected_backup_sha256,
        ):
            raise RollbackError("selected protected source is invalid")
        try:
            live_details = _LIVE_CATALOG.stat(follow_symlinks=False)
            if (
                _LIVE_CATALOG.is_symlink()
                or not stat.S_ISREG(live_details.st_mode)
                or live_details.st_nlink != 1
            ):
                raise RollbackError("restored catalog target is insecure")
            temporary = _LIVE_CATALOG.with_name(
                f".{_LIVE_CATALOG.name}.protected-restore-{uuid.uuid4().hex}"
            )
            descriptor = os.open(
                temporary,
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            os.fchown(descriptor, live_details.st_uid, live_details.st_gid)
            os.fchmod(descriptor, 0o600)
            os.close(descriptor)
            source_path = urllib.parse.quote(os.fspath(selected), safe="/")
            source = sqlite3.connect(
                f"file:{source_path}?mode=ro&immutable=1", uri=True
            )
            destination = sqlite3.connect(temporary)
            try:
                source.backup(destination)
                destination.commit()
            finally:
                destination.close()
                source.close()
            os.chown(temporary, live_details.st_uid, live_details.st_gid)
            os.chmod(temporary, 0o600)
            if not self._sqlite_check(
                temporary,
                catalog=True,
                catalog_schema=_PREDECESSOR_CATALOG_SCHEMA,
            ):
                raise RollbackError("selected catalog restore failed validation")
            descriptor = os.open(temporary, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            quarantine = recovery / "catalog-sidecars"
            quarantine.mkdir(mode=0o700)
            for suffix in ("-wal", "-shm"):
                sidecar = _LIVE_CATALOG.with_name(_LIVE_CATALOG.name + suffix)
                if not sidecar.exists():
                    continue
                details = sidecar.stat(follow_symlinks=False)
                if sidecar.is_symlink() or not stat.S_ISREG(details.st_mode):
                    raise RollbackError("catalog sidecar is insecure")
                os.replace(sidecar, quarantine / sidecar.name)
            os.replace(temporary, _LIVE_CATALOG)
            for directory_path in (
                quarantine,
                recovery,
                _LIVE_CATALOG.parent,
            ):
                directory = os.open(
                    directory_path, os.O_RDONLY | os.O_DIRECTORY
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except RollbackError:
            if "temporary" in locals():
                temporary.unlink(missing_ok=True)
            raise
        except (OSError, sqlite3.Error):
            if "temporary" in locals():
                temporary.unlink(missing_ok=True)
            raise RollbackError("protected catalog restore failed") from None

    def activate_old_stack(self, manifest: BundleManifest) -> None:
        self._run((_SYSTEMCTL, "unmask", "--runtime", *STOP_UNITS))
        enablement_by_unit = dict(manifest.unit_enablement)
        if not _valid_unit_enablement(enablement_by_unit):
            raise RollbackError("restored unit enablement is invalid")
        for unit, enablement in enablement_by_unit.items():
            if enablement in {"enabled", "disabled"}:
                self._run(
                    (
                        _SYSTEMCTL,
                        "enable" if enablement == "enabled" else "disable",
                        unit,
                    ),
                )
            observed = _canonical_unit_enablement(
                self._run((_SYSTEMCTL, "is-enabled", unit), accepted=(0, 1))
            )
            if observed != enablement:
                raise RollbackError("restored unit enablement drifted")
        for unit in START_UNITS:
            if unit not in enablement_by_unit:
                continue
            self._run((_SYSTEMCTL, "start", unit))

    def all_units_active(self, units: tuple[str, ...]) -> bool:
        if units != STOP_UNITS:
            return False
        try:
            enablement = self.captured_enablement()
            return all(
                self._run(
                    (_SYSTEMCTL, "is-active", unit), accepted=(0, 3, 4)
                ).returncode
                == 0
                for unit in _required_active_units(enablement)
            )
        except RollbackError:
            return False

    def _basic_old_health(
        self,
        manifest: BundleManifest,
        predecessor_web_probe: Mapping[str, object],
    ) -> bool:
        enablement = dict(manifest.unit_enablement)
        if not _valid_unit_enablement(enablement) or not all(
            self._run(
                (_SYSTEMCTL, "is-active", unit), accepted=(0, 3, 4)
            ).returncode
            == 0
            for unit in _required_active_units(enablement)
        ):
            return False
        try:
            request = (
                b"GET /api/v1/status HTTP/1.1\r\nHost: localhost\r\n"
                b"Connection: close\r\n\r\n"
            )
            response = bytearray()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(10)
                connection.connect("/run/lto-archiver/daemon.sock")
                connection.sendall(request)
                while chunk := connection.recv(65536):
                    response.extend(chunk)
                    if len(response) > 1024 * 1024:
                        return False
            head, separator, body = bytes(response).partition(b"\r\n\r\n")
            status = json.loads(body, object_pairs_hook=_closed_object)
            if (
                not separator
                or not head.startswith(b"HTTP/1.1 200 ")
                or not isinstance(status, dict)
                or status.get("api_version") != 1
                or not _daemon_quiescent_for_maintenance(status)
                or status.get("accepting_mutations") is not True
            ):
                return False
            return _predecessor_https_login_ok(predecessor_web_probe)
        except (
            OSError,
            KeyError,
            TypeError,
            ValueError,
            ssl.SSLError,
            json.JSONDecodeError,
            RollbackError,
            tomllib.TOMLDecodeError,
        ):
            return False

    def verify_old_health(self, manifest: BundleManifest) -> bool:
        bundle = getattr(self, "_verified_bundle", None)
        if not isinstance(bundle, Path):
            return False
        try:
            restoration_args: tuple[str, ...] = ()
            if manifest.schema >= 4:
                window = getattr(self, "_restore_health_window", None)
                if not isinstance(window, tuple) or len(window) != 2:
                    return False
                path, expected = window
                if not self.parent_is_secure(path.parent):
                    return False
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                with os.fdopen(descriptor, "rb") as handle:
                    details = os.fstat(handle.fileno())
                    if (
                        not stat.S_ISREG(details.st_mode)
                        or details.st_uid != os.geteuid()
                        or details.st_nlink != 1
                        or stat.S_IMODE(details.st_mode) != 0o600
                        or details.st_size > 1024
                        or handle.read(1025) != expected
                    ):
                        return False
                payload = json.loads(expected)
                if payload["bundle_manifest_sha256"] != _digest(
                    (bundle / "bundle-manifest.json").read_bytes()
                ):
                    return False
                restoration_args = (
                    "--restoration-started-at", payload["restoration_started_at"]
                )
            old_live, raw = _read_json(
                bundle / "contracts/old-live-contract.json"
            )
            if raw != _canonical(old_live):
                return False
            predecessor_web_probe = old_live.get("predecessor_web_probe")
            if not isinstance(predecessor_web_probe, dict) or not self._basic_old_health(
                manifest, predecessor_web_probe
            ):
                return False
            expected_state = old_live.get("installed_package_state")
            if self.captured_installed_package_state() != expected_state:
                return False
            verifier = bundle / "tools/verify-deployment-rhel9.py"
            expected_hash = manifest.tool_hashes.get(
                "verify-deployment-rhel9.py"
            )
            if (
                not verifier.is_file()
                or verifier.is_symlink()
                or _digest(verifier.read_bytes()) != expected_hash
            ):
                return False
            self._require_tool(_PYTHON)
            with tempfile.TemporaryDirectory() as temporary:
                report = Path(temporary) / "legacy-live-report.json"
                result = self._run(
                    (
                        _PYTHON,
                        "-I",
                        verifier,
                        "--legacy-old-contract",
                        bundle / "contracts/old-live-contract.json",
                        "--legacy-bundle",
                        bundle,
                        *restoration_args,
                        "--json-output",
                        report,
                    ),
                    accepted=(0, 2),
                )
                if result.returncode != 0 or not report.is_file():
                    return False
                value, report_raw = _read_json(report)
                return (
                    report_raw == _canonical(value)
                    and value
                    == {"schema": 1, "status": "green"}
                )
        except (OSError, RollbackError, TypeError):
            return False

    def keep_runtime_masked(self) -> None:
        self._run((_SYSTEMCTL, "mask", "--runtime", *STOP_UNITS))
        for unit in STOP_UNITS:
            self._run((_SYSTEMCTL, "stop", unit), accepted=(0, 5))

    def append_restore_journal(self, recovery: Path, event: str) -> None:
        path = recovery / "restore.journal"
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(descriptor, (event + "\n").encode())
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file_digest(path: Path) -> tuple[str, int]:
    """Hash catalog-sized inputs without allocating their entire contents."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _closed_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RollbackError("duplicate JSON key")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, object], bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data.decode(), object_pairs_hook=_closed_object)
    except (OSError, UnicodeError, json.JSONDecodeError, RollbackError):
        raise RollbackError("invalid bundle JSON") from None
    if not isinstance(value, dict):
        raise RollbackError("bundle JSON must be an object")
    return value, data


def _validate_driver_contract(
    path: Path, expected: str, *, candidate: bool = False, legacy: bool = False
) -> bytes:
    if not path.is_absolute() or not _HEX64.fullmatch(expected):
        raise RollbackError("invalid driver input authority")
    value, data = _read_json(path)
    required = {
        "installed_file_metadata_sha256",
        "package_nevra",
        "rpm_header_sha256",
        "rpm_payload_sha256",
        "rpm_public_key_sha256",
        "rpm_raw_sha256",
        "rpm_signing_policy_sha256",
        "rpm_verify_policy_sha256",
        "schema",
        "source_provenance_evidence_sha256",
        "source_provenance_status",
    }
    if set(value) != required or type(value.get("schema")) is not int or value.get("schema") != 1 or data != _canonical(value):
        raise RollbackError("driver input contract is not canonical and closed")
    if candidate and legacy:
        raise RollbackError("legacy rollback has no candidate driver authority")
    nevra = (
        _LEGACY_PREDECESSOR_NEVRAS["lto-ltfs"] if legacy
        else _DEPLOYED_NEVRAS["lto-ltfs"] if candidate
        else _PREDECESSOR_NEVRAS["lto-ltfs"]
    )
    policy_digest = (
        _DRIVER_RPM_VERIFY_POLICY_SHA256 if legacy
        else "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
    )
    if _digest(data) != expected or value.get("package_nevra") != nevra:
        raise RollbackError("driver input contract does not match authority")
    if value.get("rpm_verify_policy_sha256") != policy_digest:
        raise RollbackError("driver RPM verification policy authority mismatch")
    if value.get("source_provenance_status") not in {
        "authenticated-release",
        "local-build-identity-only",
    }:
        raise RollbackError("invalid driver provenance status")
    for key, item in value.items():
        if key.endswith("sha256") and (not isinstance(item, str) or not _HEX64.fullmatch(item)):
            raise RollbackError("invalid driver digest")
    return data


def _validate_rpms(
    evidence: tuple[RpmEvidence, ...],
    installed: Mapping[str, str],
    directory: Path,
    *,
    legacy: bool = False,
) -> None:
    if {row.target for row in evidence} != _TARGETS or len(evidence) != len(_TARGETS):
        raise RollbackError("rollback RPM closure is not exact")
    for row in evidence:
        package = _PACKAGE_FOR_TARGET[row.target]
        path = directory / row.filename
        if (
            Path(row.filename).name != row.filename
            or row.nevra != installed.get(package)
            or not path.is_file()
            or path.is_symlink()
            or path.stat().st_size != row.size
            or _digest(path.read_bytes()) != row.sha256
            or not _HEX64.fullmatch(row.header_sha256)
            or not _HEX64.fullmatch(row.payload_sha256)
        ):
            raise RollbackError("rollback RPM evidence mismatch")
        if row.signature_status == "legacy-unsigned":
            if row.nevra not in _LEGACY_NEVRAS or row.signing_key_id != "absent":
                raise RollbackError("unsigned RPM is not an admitted legacy rollback input")
        elif (
            row.signature_status != "verified" or not row.signing_key_id
            or (
                row.signing_key_id == "absent"
                and not (
                    legacy and dict(installed) == _LEGACY_PREDECESSOR_NEVRAS
                    and row.target in {"application", "runtime"}
                )
            )
        ):
            raise RollbackError("rollback RPM signature policy failed")


def _manifest_value(manifest: BundleManifest) -> dict[str, object]:
    value = asdict(manifest)
    if manifest.schema < 4:
        value.pop("candidate_driver_input_sha256")
    return value


def _parse_manifest(value: dict[str, object], raw: bytes) -> BundleManifest:
    if (
        set(value) != (_MANIFEST_KEYS | {"candidate_driver_input_sha256"} if value.get("schema") == 4 else _MANIFEST_KEYS)
        or type(value.get("schema")) is not int
        or value["schema"] not in {2, 3, 4}
        or raw != _canonical(value)
    ):
        raise RollbackError("bundle manifest is not canonical and closed")
    try:
        rpms = tuple(RpmEvidence(**row) for row in value["rpms"])
        snapshots = tuple(
            SnapshotEvidence(
                identity=row["identity"],
                logical_bytes=row["logical_bytes"],
                files=tuple(FileEvidence(**record) for record in row["files"]),
                directories=tuple(
                    DirectoryEvidence(**record) for record in row["directories"]
                ),
            )
            for row in value["snapshots"]
        )
        checks = tuple(StateCheck(**row) for row in value["state_checks"])
        expected_snapshots = _LEGACY_SNAPSHOTS if value["schema"] == 2 else REQUIRED_SNAPSHOTS
        if tuple(row.identity for row in snapshots) != expected_snapshots:
            raise RollbackError("bundle snapshot closure is invalid")
        enablement = dict(value["unit_enablement"])
        if not _valid_unit_enablement(enablement):
            raise RollbackError("bundle unit enablement is invalid")
        return BundleManifest(
            bundle_id=str(value["bundle_id"]),
            created_at=str(value["created_at"]),
            host_binding_sha256=str(value["host_binding_sha256"]),
            installed_nevras=dict(value["installed_nevras"]),
            rpms=rpms,
            snapshots=snapshots,
            state_checks=checks,
            custom_web_unit_sha256=str(value["custom_web_unit_sha256"]),
            unit_enablement=enablement,
            firewall_observation_sha256=str(value["firewall_observation_sha256"]),
            available_capacity_bytes=int(value["available_capacity_bytes"]),
            required_capacity_bytes=int(value["required_capacity_bytes"]),
            tool_hashes=dict(value["tool_hashes"]),
            old_live_contract_sha256=str(value["old_live_contract_sha256"]),
            old_rpm_policy_sha256=str(value["old_rpm_policy_sha256"]),
            old_journal_policy_sha256=str(value["old_journal_policy_sha256"]),
            driver_input_sha256=str(value["driver_input_sha256"]),
            tool_versions=dict(value["tool_versions"]),
            protected_backup_relative_path=str(
                value["protected_backup_relative_path"]
            ),
            protected_backup_sha256=str(value["protected_backup_sha256"]),
            source_catalog_schema=int(value["source_catalog_schema"]),
            source_catalog_sha256=str(value["source_catalog_sha256"]),
            schema=value["schema"],
            candidate_driver_input_sha256=str(value.get("candidate_driver_input_sha256", "")),
        )
    except (KeyError, TypeError, ValueError):
        raise RollbackError("bundle manifest has invalid field types") from None


def _write(path: Path, data: bytes, mode: int = 0o600) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _checksum_rows(root: Path) -> list[str]:
    rows: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise RollbackError("bundle may not contain symlinks")
        if path.is_file() and path.name != "rollback-SHA256SUMS":
            relative = path.relative_to(root).as_posix()
            rows.append(f"{_file_digest(path)[0]}  {relative}")
    return rows


def _verify_checksums(bundle: Path) -> None:
    try:
        actual = (bundle / "rollback-SHA256SUMS").read_text(encoding="utf-8").splitlines()
    except OSError:
        raise RollbackError("rollback checksum manifest is missing") from None
    expected = sorted(_checksum_rows(bundle))
    if actual != sorted(actual) or actual != expected:
        raise RollbackError("rollback checksum manifest mismatch")


def create_bundle(
    request: CreateBundleRequest,
    host: RollbackHost,
    prepared_source: object | None = None,
) -> BundleManifest:
    final = request.bundle_dir
    if not host.is_root():
        raise RollbackError("rollback operation requires root")
    if not final.is_absolute() or final.exists() or final.is_symlink():
        raise RollbackError("bundle path must be absolute and new")
    parent = final.parent.resolve(strict=True)
    if parent != final.parent or not host.parent_is_secure(parent):
        raise RollbackError("bundle parent is not a secure root-owned 0700 directory")
    if not request.rollback_rpm_dir.is_absolute() or not request.rollback_rpm_dir.is_dir():
        raise RollbackError("rollback RPM directory is invalid")
    probe = request.predecessor_web_probe
    try:
        probe_url = urllib.parse.urlsplit(probe["url"])
        probe_port = probe_url.port
        probe_ca = Path(probe["ca_certificate"])
    except (KeyError, TypeError, ValueError):
        raise RollbackError("predecessor Web probe is invalid") from None
    if (
        set(probe) != {"ca_certificate", "url"}
        or not all(isinstance(item, str) for item in probe.values())
        or probe_url.scheme != "https"
        or not probe_url.hostname
        or probe_port != 8443
        or probe_url.username is not None
        or probe_url.password is not None
        or probe_url.path != "/login"
        or probe_url.query
        or probe_url.fragment
        or not probe_ca.is_absolute()
        or not probe_ca.is_file()
        or probe_ca.is_symlink()
    ):
        raise RollbackError("predecessor Web probe is invalid")
    driver_data = _validate_driver_contract(
        request.driver_input_contract, request.expected_driver_input_sha256
    )
    candidate_driver_data = _validate_driver_contract(
        request.candidate_driver_input_contract,
        request.expected_candidate_driver_input_sha256, candidate=True,
    )
    # Both roles are independently closed above to the unchanged driver21
    # authority. Preserve both contract copies for coordinated recovery.
    installed = dict(host.installed_nevras())
    if installed != _PREDECESSOR_NEVRAS:
        raise RollbackError("installed package closure is not exact")
    expected_rpm_filenames = tuple(f"{nevra}.rpm" for nevra in installed.values())
    if not host.rollback_rpm_authority_ok(
        request.rollback_rpm_dir, expected_rpm_filenames
    ):
        raise RollbackError("rollback RPM directory authority is invalid")
    rpms = tuple(host.inspect_rollback_rpms(request.rollback_rpm_dir))
    _validate_rpms(rpms, installed, request.rollback_rpm_dir)
    driver_contract = json.loads(
        driver_data.decode(), object_pairs_hook=_closed_object
    )
    driver_rpm = next(row for row in rpms if row.target == "driver-evidence")
    if (
        driver_rpm.nevra != driver_contract["package_nevra"]
        or driver_rpm.sha256 != driver_contract["rpm_raw_sha256"]
        or driver_rpm.header_sha256 != driver_contract["rpm_header_sha256"]
        or driver_rpm.payload_sha256 != driver_contract["rpm_payload_sha256"]
    ):
        raise RollbackError("driver RPM evidence does not match its input contract")
    prepared = (
        host.prepare_source_catalog_backup(parent)
        if prepared_source is None
        else prepared_source
    )
    if not isinstance(prepared, PreparedSourceBackup) or not host.validate_prepared_source(
        prepared
    ):
        raise RollbackError("prepared protected source is invalid")
    sources = tuple(host.snapshot_sources())
    if tuple(row.identity for row in sources) != REQUIRED_SNAPSHOTS:
        raise RollbackError("snapshot source closure is not exact")
    if any(row.logical_bytes < 0 for row in sources):
        raise RollbackError("snapshot size is invalid")
    protected_size = prepared.path.stat().st_size
    subtotal = (
        sum(row.logical_bytes for row in sources)
        + sum(row.size for row in rpms)
        + protected_size
    )
    required = subtotal + max((subtotal + 4) // 5, 10 * 1024**3)
    available = host.available_bytes(parent)
    if available < required:
        raise RollbackError("rollback capacity is insufficient")
    if host.custom_web_unit_sha256() != request.expected_custom_web_unit_sha256:
        raise RollbackError("custom WebUI unit authority mismatch")

    staging = Path(tempfile.mkdtemp(prefix=f".{final.name}.tmp-", dir=parent))
    os.chmod(staging, 0o700)
    try:
        rpm_destination = staging / "rpms"
        rpm_destination.mkdir(mode=0o700)
        for row in rpms:
            shutil.copyfile(request.rollback_rpm_dir / row.filename, rpm_destination / row.filename)
            os.chmod(rpm_destination / row.filename, 0o600)
        contracts = staging / "contracts"
        contracts.mkdir(mode=0o700)
        _write(contracts / "driver-input.json", driver_data)
        _write(contracts / "candidate-driver-input.json", candidate_driver_data)
        enablement = dict(host.captured_enablement())
        if not _valid_unit_enablement(enablement):
            raise RollbackError("captured unit enablement is invalid")
        firewall_digest = host.firewall_observation_digest()
        created_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        capture_firewall = getattr(host, "captured_firewall_policy", None)
        firewall_policy = capture_firewall() if callable(capture_firewall) else None
        old_live = _canonical(
            {
                "installed_nevras": installed,
                "installed_package_state": host.captured_installed_package_state(),
                "captured_at": created_at,
                "protected_backup_relative_path": (
                    f"release-recovery/{prepared.path.name}"
                ),
                "protected_backup_sha256": prepared.backup_sha256,
                "schema": 2,
                "source_catalog_schema": prepared.source_schema,
                "source_catalog_sha256": prepared.catalog_sha256,
                "unit_enablement": enablement,
                "custom_web_unit_sha256": request.expected_custom_web_unit_sha256,
                "firewall_observation_sha256": firewall_digest,
                "firewall_policy": firewall_policy,
                "predecessor_web_probe": dict(request.predecessor_web_probe),
                "driver_authority": {
                    key: driver_contract[key]
                    for key in (
                        "rpm_public_key_sha256",
                        "rpm_signing_policy_sha256",
                        "rpm_verify_policy_sha256",
                        "source_provenance_evidence_sha256",
                        "source_provenance_status",
                    )
                },
            }
        )
        old_rpm_policy = _canonical(
            {"schema": 1, "legacy_hash_bound_nevras": sorted(_LEGACY_NEVRAS)}
        )
        old_journal_policy = _canonical({"schema": 1, "allowlist": []})
        _write(contracts / "old-live-contract.json", old_live)
        _write(contracts / "old-rpm-policy.json", old_rpm_policy)
        _write(contracts / "old-journal-policy.json", old_journal_policy)
        snapshot_root = staging / "snapshots"
        snapshot_root.mkdir(mode=0o700)
        snapshots = tuple(
            host.copy_snapshot(source, snapshot_root / source.identity) for source in sources
        )
        if tuple(row.identity for row in snapshots) != REQUIRED_SNAPSHOTS:
            raise RollbackError("copied snapshot evidence is not exact")
        application = next(
            row for row in snapshots if row.identity == "application_state"
        )
        catalog_rows = tuple(
            row for row in application.files if row.relative_path == "catalog.db"
        )
        if (
            len(catalog_rows) != 1
            or catalog_rows[0].sha256 != prepared.catalog_sha256
        ):
            raise RollbackError("stopped catalog snapshot binding failed")
        protected_relative = f"release-recovery/{prepared.path.name}"
        protected_destination = staging / protected_relative
        host.copy_prepared_source(prepared, protected_destination)
        copied_values = getattr(host, "_protected_source_values", lambda _path: None)(
            protected_destination
        )
        if copied_values is not None and copied_values != (
            prepared.source_schema,
            prepared.backup_sha256,
        ):
            raise RollbackError("copied protected source binding failed")
        checks = tuple(host.check_copied_state(snapshot_root))
        if (
            {row.identity for row in checks} != REQUIRED_STATE_CHECKS
            or len(checks) != len(REQUIRED_STATE_CHECKS)
            or not all(row.integrity_ok and row.foreign_keys_ok and row.schema_ok for row in checks)
        ):
            raise RollbackError("copied state verification failed")
        tools = dict(host.copy_bundle_tools(staging / "tools"))
        manifest = BundleManifest(
            bundle_id=uuid.uuid4().hex,
            created_at=created_at,
            host_binding_sha256=_digest(host.host_binding_material()),
            installed_nevras=installed,
            rpms=rpms,
            snapshots=snapshots,
            state_checks=checks,
            custom_web_unit_sha256=request.expected_custom_web_unit_sha256,
            unit_enablement=enablement,
            firewall_observation_sha256=firewall_digest,
            available_capacity_bytes=available,
            required_capacity_bytes=required,
            tool_hashes=tools,
            old_live_contract_sha256=_digest(old_live),
            old_rpm_policy_sha256=_digest(old_rpm_policy),
            old_journal_policy_sha256=_digest(old_journal_policy),
            driver_input_sha256=request.expected_driver_input_sha256,
            candidate_driver_input_sha256=request.expected_candidate_driver_input_sha256,
            tool_versions=dict(host.tool_versions()),
            protected_backup_relative_path=protected_relative,
            protected_backup_sha256=prepared.backup_sha256,
            source_catalog_schema=prepared.source_schema,
            source_catalog_sha256=prepared.catalog_sha256,
        )
        _write(staging / "bundle-manifest.json", _canonical(_manifest_value(manifest)))
        _write(
            staging / "rollback-SHA256SUMS",
            ("\n".join(sorted(_checksum_rows(staging))) + "\n").encode(),
        )
        verify_bundle(staging, host)
        host.fsync_tree(staging)
        host.publish_noreplace(staging, final)
        return verify_bundle(final, host)
    except RollbackError:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    except Exception as error:
        shutil.rmtree(staging, ignore_errors=True)
        raise RollbackError("rollback bundle creation failed") from error


def _verify_bundle(
    bundle: Path, host: RollbackHost, *, require_predeploy_state: bool,
    retained_catalog_manifest_sha256: str | None = None,
) -> BundleManifest:
    if not host.is_root() or not bundle.is_absolute() or not bundle.is_dir():
        raise RollbackError("bundle verification requires root and an absolute directory")
    if not host.verify_bundle_security(bundle):
        raise RollbackError("bundle ownership or mode verification failed")
    _verify_checksums(bundle)
    value, raw = _read_json(bundle / "bundle-manifest.json")
    if retained_catalog_manifest_sha256 is not None and _digest(raw) != retained_catalog_manifest_sha256:
        raise RollbackError("retained catalog rollback manifest differs from authenticated evidence")
    manifest = _parse_manifest(value, raw)
    begin_verification = getattr(host, "begin_bundle_verification", None)
    if callable(begin_verification):
        begin_verification(bundle)
    if manifest.host_binding_sha256 != _digest(host.host_binding_material()):
        raise RollbackError("bundle host binding mismatch")
    expected_predecessor = _PREDECESSOR_NEVRAS if manifest.schema == 4 else _LEGACY_PREDECESSOR_NEVRAS
    if retained_catalog_manifest_sha256 is not None:
        if require_predeploy_state or manifest.schema != 4:
            raise RollbackError("retained catalog rollback is not a deployment admission")
        # One explicit retained recovery transition, not arbitrary historic
        # package acceptance. Normal verify/restore paths retain their policy.
        expected_predecessor = {
            "lto-archiver": "lto-archiver-0.11.27-140.el9.noarch",
            "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
    if dict(manifest.installed_nevras) != expected_predecessor:
        raise RollbackError("bundle predecessor package closure is invalid")
    installed = dict(host.installed_nevras())
    if retained_catalog_manifest_sha256 is not None and installed != {
        **expected_predecessor, "lto-archiver": "lto-archiver-0.11.27-141.el9.noarch",
    }:
        raise RollbackError("installed package closure is not the retained catalog recovery baseline")
    if require_predeploy_state and dict(manifest.installed_nevras) != installed:
        raise RollbackError("installed package closure drifted")
    if not require_predeploy_state and manifest.schema < 4 and installed.get("lto-ltfs") != manifest.installed_nevras.get("lto-ltfs"):
        raise RollbackError("installed driver drifted")
    if manifest.schema == 4 and not _coordinated_package_state_known(installed):
        raise RollbackError("installed package state is not a bound recovery state")
    _validate_rpms(
        manifest.rpms, manifest.installed_nevras, bundle / "rpms",
        legacy=manifest.schema < 4,
    )
    if not host.verify_rpm_evidence(manifest.rpms):
        raise RollbackError("rollback RPM policy verification failed")
    driver_bytes = _validate_driver_contract(
        bundle / "contracts/driver-input.json", manifest.driver_input_sha256,
        legacy=manifest.schema < 4,
    )
    driver_contract = json.loads(
        driver_bytes.decode(), object_pairs_hook=_closed_object
    )
    if manifest.schema == 4:
        candidate_bytes = _validate_driver_contract(
            bundle / "contracts/candidate-driver-input.json",
            manifest.candidate_driver_input_sha256, candidate=True,
        )
        candidate = json.loads(candidate_bytes, object_pairs_hook=_closed_object)
        current_driver = (
            driver_contract if installed["lto-ltfs"] == driver_contract["package_nevra"]
            else candidate
        )
        if not host.driver_package_state_matches(current_driver):
            raise RollbackError("installed driver metadata is not bound to the transition")
    driver_rpm = next(row for row in manifest.rpms if row.target == "driver-evidence")
    if (
        driver_rpm.nevra != driver_contract["package_nevra"]
        or driver_rpm.sha256 != driver_contract["rpm_raw_sha256"]
        or driver_rpm.header_sha256 != driver_contract["rpm_header_sha256"]
        or driver_rpm.payload_sha256 != driver_contract["rpm_payload_sha256"]
    ):
        raise RollbackError("driver input contract drifted")
    if not host.verify_snapshot_evidence(bundle, manifest.snapshots):
        raise RollbackError("snapshot metadata or content drifted")
    if not host.verify_protected_source(bundle, manifest):
        raise RollbackError("protected source binding is invalid")
    if not host.verify_copied_state(bundle, manifest.state_checks):
        raise RollbackError("copied state verification failed")
    if (
        require_predeploy_state
        and manifest.custom_web_unit_sha256 != host.custom_web_unit_sha256()
    ):
        raise RollbackError("custom WebUI authority drifted")
    for name, expected in manifest.tool_hashes.items():
        path = bundle / "tools" / name
        if Path(name).name != name or not path.is_file() or _digest(path.read_bytes()) != expected:
            raise RollbackError("bundle-local tool drifted")
    contract_hashes = {
        "old-live-contract.json": manifest.old_live_contract_sha256,
        "old-rpm-policy.json": manifest.old_rpm_policy_sha256,
        "old-journal-policy.json": manifest.old_journal_policy_sha256,
    }
    for name, expected in contract_hashes.items():
        if _digest((bundle / "contracts" / name).read_bytes()) != expected:
            raise RollbackError("synthesized rollback policy drifted")
    old_live, old_live_raw = _read_json(
        bundle / "contracts/old-live-contract.json"
    )
    if (
        old_live_raw != _canonical(old_live)
        or set(old_live)
        != {
            "custom_web_unit_sha256",
            "captured_at",
            "driver_authority",
            "firewall_observation_sha256",
            "firewall_policy",
            "installed_nevras",
            "installed_package_state",
            "predecessor_web_probe",
            "protected_backup_relative_path",
            "protected_backup_sha256",
            "schema",
            "source_catalog_schema",
            "source_catalog_sha256",
            "unit_enablement",
        }
        or old_live.get("schema") != 2
        or old_live.get("installed_nevras") != dict(manifest.installed_nevras)
        or old_live.get("unit_enablement") != dict(manifest.unit_enablement)
        or old_live.get("protected_backup_relative_path")
        != manifest.protected_backup_relative_path
        or old_live.get("protected_backup_sha256")
        != manifest.protected_backup_sha256
        or old_live.get("source_catalog_schema")
        != manifest.source_catalog_schema
        or old_live.get("source_catalog_sha256")
        != manifest.source_catalog_sha256
    ):
        raise RollbackError("old live contract is not closed")
    if (
        require_predeploy_state
        and host.captured_installed_package_state()
        != old_live.get("installed_package_state")
    ):
        raise RollbackError("installed package metadata or rpm-V state drifted")
    return manifest


def verify_bundle(bundle: Path, host: RollbackHost) -> BundleManifest:
    with host.artifact_lease(bundle):
        return _verify_bundle(bundle, host, require_predeploy_state=True)


def verify_retained_catalog_rollback(
    bundle: Path, host: RollbackHost, *, expected_manifest_sha256: str
) -> BundleManifest:
    """Verify the authenticated retained 140 bundle with 141 still installed.

    Evidence only: no restore-capacity admission, package install, service action
    or restore. The caller independently binds the complete current runtime and
    owns stopped-host exclusion. Other verify/restore contracts are unchanged.
    """
    if not isinstance(expected_manifest_sha256, str) or not _HEX64.fullmatch(expected_manifest_sha256):
        raise RollbackError("invalid retained catalog manifest digest")
    with host.artifact_lease(bundle):
        manifest = _verify_bundle(bundle, host, require_predeploy_state=False,
            retained_catalog_manifest_sha256=expected_manifest_sha256)
        if _digest((bundle / "bundle-manifest.json").read_bytes()) != expected_manifest_sha256:
            raise RollbackError("retained catalog manifest changed during verification")
        return manifest


def restore_bundle(bundle: Path, host: RollbackHost) -> RestoreResult:
    with host.artifact_lease(bundle):
        return _restore_leased_bundle(bundle, host)


def _restore_leased_bundle(bundle: Path, host: RollbackHost) -> RestoreResult:
    manifest = _verify_bundle(bundle, host, require_predeploy_state=False)
    # Admission failure must not stop services, install packages, create a
    # recovery directory or enter the mutating failure/masking path below.
    host.verify_restore_capacity(bundle, manifest)
    recovery: Path | None = None
    completed: list[str] = []
    swapping = False
    restore_stage: str | None = None
    try:
        host.remask_stop_and_prove_idle(STOP_UNITS)
        runtime = next(row for row in manifest.rpms if row.target == "runtime")
        application = next(row for row in manifest.rpms if row.target == "application")
        if manifest.schema == 4:
            driver = next(row for row in manifest.rpms if row.target == "driver-evidence")
            host.install_local_rollback(
                bundle / "rpms" / runtime.filename, bundle / "rpms" / application.filename,
                bundle / "rpms" / driver.filename,
            )
        else:
            host.install_local_rollback(bundle / "rpms" / runtime.filename, bundle / "rpms" / application.filename)
        if manifest.schema == 2 and not host.verify_untouched_driver(manifest):
            raise RollbackError("unchanged driver verification failed")
        recovery = host.create_recovery_directory(manifest.bundle_id)
        host.append_restore_journal(recovery, "restore-started")
        swapping = True
        for snapshot in manifest.snapshots:
            staged = host.stage_snapshot(bundle, snapshot)
            host.swap_snapshot(snapshot.identity, staged, recovery)
            completed.append(snapshot.identity)
            host.append_restore_journal(recovery, f"swapped:{snapshot.identity}")
        swapping = False
        restore_stage = "platform_state"
        host.append_restore_journal(recovery, f"stage-started:{restore_stage}")
        host.restore_platform_state(manifest)
        host.append_restore_journal(recovery, f"stage-complete:{restore_stage}")
        restore_stage = "protected_catalog"
        host.append_restore_journal(recovery, f"stage-started:{restore_stage}")
        host.restore_protected_catalog(manifest, recovery)
        host.append_restore_journal(recovery, f"stage-complete:{restore_stage}")
        restore_stage = "revalidate"
        host.append_restore_journal(recovery, f"stage-started:{restore_stage}")
        host.revalidate_restored_state(manifest)
        if manifest.schema >= 3 and (
            not host.verify_restored_ltfs_configuration(manifest)
            or not host.verify_untouched_driver(manifest)
        ):
            raise RollbackError("restored LTFS configuration or driver verification failed")
        host.append_restore_journal(recovery, f"stage-complete:{restore_stage}")
        restore_stage = "activation"
        host.append_restore_journal(recovery, f"stage-started:{restore_stage}")
        if manifest.schema >= 4:
            host.begin_restore_health_window(recovery)
        host.activate_old_stack(manifest)
        host.append_restore_journal(recovery, f"stage-complete:{restore_stage}")
        restore_stage = "health"
        host.append_restore_journal(recovery, f"stage-started:{restore_stage}")
        if not host.verify_old_health(manifest):
            raise RollbackError("restored old stack failed its live gate")
        host.append_restore_journal(recovery, f"stage-complete:{restore_stage}")
        restore_stage = None
        host.append_restore_journal(recovery, "restore-complete")
        return RestoreResult("restored", manifest.bundle_id, recovery, "verified old stack restored")
    except Exception as error:
        if recovery is None:
            recovery = host.create_recovery_directory(manifest.bundle_id)
        if swapping:
            for identity in reversed(completed):
                try:
                    host.reverse_snapshot_swap(identity, recovery)
                    host.append_restore_journal(recovery, f"reversed:{identity}")
                except Exception:
                    pass
        host.keep_runtime_masked()
        blocked_event = "restore-blocked"
        detail = type(error).__name__
        if restore_stage in _RESTORE_STAGE_IDS:
            blocked_event = f"{blocked_event}:{restore_stage}"
            detail = f"stage={restore_stage}"
        try:
            host.append_restore_journal(recovery, blocked_event)
        except Exception:
            pass
        return RestoreResult("blocked", manifest.bundle_id, recovery, detail)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("create", "verify", "restore"))
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--rollback-rpm-dir", type=Path)
    parser.add_argument("--expected-custom-web-unit-sha256")
    parser.add_argument("--driver-input-contract", type=Path)
    parser.add_argument("--expected-driver-input-sha256")
    parser.add_argument("--candidate-driver-input-contract", type=Path)
    parser.add_argument("--expected-candidate-driver-input-sha256")
    parser.add_argument("--predecessor-https-login-url")
    parser.add_argument("--predecessor-https-ca-certificate", type=Path)
    parser.add_argument("--firewall-zone")
    parser.add_argument("--json-output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    host = SystemRollbackHost()
    try:
        if arguments.command == "create":
            if any(
                value is None
                for value in (
                    arguments.rollback_rpm_dir,
                    arguments.expected_custom_web_unit_sha256,
                    arguments.driver_input_contract,
                    arguments.expected_driver_input_sha256,
                    arguments.candidate_driver_input_contract,
                    arguments.expected_candidate_driver_input_sha256,
                    arguments.predecessor_https_login_url,
                    arguments.predecessor_https_ca_certificate,
                    arguments.firewall_zone,
                )
            ):
                raise RollbackError("create inputs are incomplete")
            host._deployment_firewall_zone = arguments.firewall_zone
            manifest = create_bundle(
                CreateBundleRequest(
                    bundle_dir=arguments.bundle_dir,
                    rollback_rpm_dir=arguments.rollback_rpm_dir,
                    expected_custom_web_unit_sha256=arguments.expected_custom_web_unit_sha256,
                    driver_input_contract=arguments.driver_input_contract,
                    expected_driver_input_sha256=arguments.expected_driver_input_sha256,
                    candidate_driver_input_contract=arguments.candidate_driver_input_contract,
                    expected_candidate_driver_input_sha256=arguments.expected_candidate_driver_input_sha256,
                    predecessor_web_probe={
                        "url": arguments.predecessor_https_login_url,
                        "ca_certificate": os.fspath(
                            arguments.predecessor_https_ca_certificate
                        ),
                    },
                ),
                host,
            )
            status = "created"
        elif arguments.command == "verify":
            manifest = verify_bundle(arguments.bundle_dir, host)
            status = "verified"
        else:
            with host.artifact_lease(arguments.bundle_dir):
                restored = restore_bundle(arguments.bundle_dir, host)
                manifest = _verify_bundle(
                    arguments.bundle_dir, host, require_predeploy_state=False
                )
            status = restored.status
        result = _canonical(
            {"bundle_id": manifest.bundle_id, "schema": 1, "status": status}
        )
        if arguments.json_output is None:
            sys.stdout.buffer.write(result)
        else:
            output = arguments.json_output
            if not output.is_absolute() or output.exists():
                raise RollbackError("JSON output path must be absolute and new")
            _write(output, result)
        return 0 if status in {"created", "verified", "restored"} else 2
    except (RollbackError, OSError, ValueError):
        print("rollback failed: closed host validation error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
