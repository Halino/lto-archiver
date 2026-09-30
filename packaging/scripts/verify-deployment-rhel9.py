#!/usr/bin/python3.11
from __future__ import annotations

import argparse
import grp
import hashlib
import json
import os
import re
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from typing import Protocol

REQUIRED_ACTIVE_UNITS = frozenset(
    {
        "lto-archiver-command-broker.service",
        "lto-archiver-command-broker.socket",
        "lto-archiver-share-broker.service",
        "lto-archiver-share-broker.socket",
        "lto-archiver-log-reader.socket",
        "lto-archiver-log-reader.service",
        "lto-archiver-web.service",
        "lto-archiverd.service",
        "lto-archiverd.socket",
    }
)
SECURITY_JOURNAL_UNITS = frozenset({"setroubleshootd.service"})
REQUIRED_ENABLED_UNITS = frozenset(
    {
        "lto-archiver-command-broker.socket",
        "lto-archiver-share-broker.socket",
        "lto-archiver-log-reader.socket",
        "lto-archiver-web.service",
        "lto-archiverd.socket",
    }
)
REQUIRED_STATIC_UNITS = frozenset(
    {
        "lto-archiver-log-reader.service",
        "lto-archiver-share-broker.service",
    }
)
PRESERVED_ENABLEMENT_UNITS = (
    REQUIRED_ACTIVE_UNITS - REQUIRED_ENABLED_UNITS - REQUIRED_STATIC_UNITS
)
REQUIRED_DATABASES = frozenset(
    {
        "catalog",
        "command_broker",
        "protected_catalog_backup",
        "share_broker_state",
        "web_auth",
    }
)
REQUIRED_FIREWALL_RULES = frozenset(
    {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
)
_APPLICATION_NEVRA = "lto-archiver-0.11.27-144.el9.noarch"
_RUNTIME_NEVRA = "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
_DRIVER_NEVRA = "lto-ltfs-0.1.0-21.el9.x86_64"


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


_LEGACY_PREDECESSOR_NEVRAS = {
    "lto-archiver": "lto-archiver-0.11.27-101.el9.noarch",
    "lto-archiver-python-runtime": _RUNTIME_NEVRA,
    "lto-ltfs": "lto-ltfs-0.1.0-16.el9.x86_64",
}
_DRIVER_RPM_VERIFY_POLICY_SHA256 = (
    "39c26ec18c7d8eadaad0c9b1b3d89fc133e5f60fb63f94ed427dbb8839fbadb0"
)
_DRIVER_RPM_VERIFY_ROW = "S.5....T.  c /etc/lto-ltfs/device.json"
_DRIVER_DIGEST_AUTHORITY_SHA256 = (
    "60b3da198aec3a49ccb45f0856f01601fe2949fdc9a7dc9b6f5b2cb97ae86d7b"
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_UTC = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_RPM_VERIFY = re.compile(r"^(?P<flags>[SM5DLUGTP.]{9})[ \t]+(?P<marker>[a-z]?)[ \t]+(?P<path>/[^\n\r]+)$")
_MESSAGE_ID = re.compile(r"^[0-9a-f]{32}$")
_DRIVER_KEYS = frozenset(
    {
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
)
_RPM = Path("/usr/bin/rpm")
_RPMKEYS = Path("/usr/bin/rpmkeys")
_GPG = Path("/usr/bin/gpg")
_SYSTEMCTL = Path("/usr/bin/systemctl")
_FINDMNT = Path("/usr/bin/findmnt")
_FIREWALL = Path("/usr/bin/firewall-cmd")
_JOURNALCTL = Path("/usr/bin/journalctl")
_MATCHPATHCON = Path("/usr/sbin/matchpathcon")
_PROTECTED_BACKUP_ROOT = Path("/var/lib/lto-archiver/backups")
_PROTECTED_BACKUP_NAME = re.compile(
    r"^[0-9]{8}T[0-9]{12}Z-[0-9a-f]{12}-p-v(?P<version>[0-9]+)-"
    r"[0-9a-f]{16}\.sqlite3$"
)
_MIN_PROTECTED_CATALOG_SCHEMA = 13
_MAX_PROTECTED_CATALOG_SCHEMA = 40
_ROOT_UID = 0
_ROOT_GID = 0
_LOG_READER_EXEC_START = (
    "/usr/bin/lto-archiver-log-reader --socket-fd 3"
)
_LOG_READER_EMPTY_PATH_PROPERTIES = (
    "ReadWritePaths",
    "StateDirectory",
    "RuntimeDirectory",
    "CacheDirectory",
    "LogsDirectory",
    "ConfigurationDirectory",
)
_LOG_READER_EFFECTIVE_SERVICE_GROUPS = {
    "lto-archiverd.service": frozenset(
        {"tape", "lto-admin", "lto-web", "lto-log-read"}
    ),
    "lto-archiver-web.service": frozenset({"lto-archiver"}),
    "lto-archiver-command-broker.service": frozenset({"lto-archiver"}),
    "lto-archiver-share-broker.service": frozenset({"lto-archiver"}),
    "lto-archiver-ltfs-qualification.service": frozenset({"lto-archiver"}),
    "lto-archiver-archive-runner-qualification.service": frozenset(
        {"tape", "lto-admin", "lto-web"}
    ),
    "lto-archiver-log-reader.service": frozenset(),
}


class ContractError(RuntimeError):
    pass


def _systemd_show_values(output: str) -> list[str]:
    """Keep empty systemd --value rows: they are part of the contract."""
    if output.endswith("\n"):
        return output.split("\n")[:-1]
    return output.split("\n")


def _duplicate_free_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _load_json(path: Path) -> tuple[dict[str, object], bytes]:
    if not isinstance(path, Path) or not path.is_absolute() or not path.is_file():
        raise ContractError("contract path must be an absolute regular file")
    data = path.read_bytes()
    try:
        text = data.decode("utf-8")
        value = json.loads(text, object_pairs_hook=_duplicate_free_object)
    except (OSError, UnicodeError, json.JSONDecodeError, ContractError):
        raise ContractError("invalid JSON contract") from None
    if not isinstance(value, dict):
        raise ContractError("contract root must be an object")
    return value, data


def _canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n"
    ).encode("utf-8")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class DriverInputContract:
    package_nevra: str
    rpm_raw_sha256: str
    rpm_header_sha256: str
    rpm_payload_sha256: str
    rpm_signing_policy_sha256: str
    rpm_public_key_sha256: str
    rpm_verify_policy_sha256: str
    installed_file_metadata_sha256: str
    source_provenance_status: str
    source_provenance_evidence_sha256: str

    @property
    def upstream_lineage_verified(self) -> bool:
        return self.source_provenance_status == "authenticated-release"


def _driver_artifact_identity_ok(
    contract: DriverInputContract,
    rpm_bytes: bytes,
    query: subprocess.CompletedProcess[str],
) -> bool:
    rows = query.stdout.splitlines()
    return (
        query.returncode == 0
        and not query.stderr
        and query.stdout.endswith("\n")
        and len(rows) == 3
        and rows[0] == "lto-ltfs"
        and rows[1] == contract.package_nevra
        and rows[2].lower() == contract.rpm_payload_sha256
        and _digest(query.stdout.encode()) == contract.rpm_header_sha256
        and _digest(rpm_bytes) == contract.rpm_raw_sha256
    )


def _local_unsigned_driver_signature_ok(
    result: subprocess.CompletedProcess[str],
) -> bool:
    return (
        result.returncode == 0
        and not result.stderr
        and "digests OK" in result.stdout
        and "signatures OK" not in result.stdout
        and "key ID" not in result.stdout
    )


def _signing_key_listing_authorized(
    output: str, policy: Mapping[str, object]
) -> bool:
    primary = policy.get("primary_fingerprint")
    signing_subkey = policy.get("signing_subkey_fingerprint")
    minimum_bits = policy.get("minimum_rsa_bits")
    if (
        not isinstance(primary, str)
        or not isinstance(signing_subkey, str)
        or type(minimum_bits) is not int
    ):
        return False
    keys: list[tuple[str, int, str, int, str]] = []
    pending: tuple[str, int, str, int] | None = None
    for line in output.splitlines():
        fields = line.split(":")
        if fields[0] in {"pub", "sub"}:
            try:
                expires = int(fields[6]) if fields[6] else 0
                pending = (fields[0], int(fields[2]), fields[1], expires)
            except (IndexError, ValueError):
                return False
            if (
                len(fields) < 7
                or fields[3] != "1"
                or fields[1] in {"d", "e", "r"}
            ):
                return False
        elif fields[0] == "fpr" and pending is not None:
            if len(fields) < 10:
                return False
            kind, bits, validity, expires = pending
            keys.append((kind, bits, validity, expires, fields[9].upper()))
            pending = None
    now = int(time.time())
    return (
        pending is None
        and sum(
            kind == "pub" and fingerprint == primary
            for kind, _, _, _, fingerprint in keys
        )
        == 1
        and sum(
            kind == "sub" and fingerprint == signing_subkey
            for kind, _, _, _, fingerprint in keys
        )
        == 1
        and all(bits >= minimum_bits for _, bits, _, _, _ in keys)
        and all(
            expires == 0 or expires > now
            for _, _, _, expires, _ in keys
        )
    )


def _closed_signing_policy(
    policy: Mapping[str, object], *, exact_package_names: list[str]
) -> bool:
    return (
        set(policy)
        == {
            "accepted_digest_algorithms",
            "accepted_public_key_algorithm",
            "exact_package_names",
            "minimum_rsa_bits",
            "primary_fingerprint",
            "public_key_path",
            "public_key_sha256",
            "schema_version",
            "signing_subkey_fingerprint",
        }
        and type(policy.get("schema_version")) is int
        and policy.get("schema_version") == 1
        and policy.get("exact_package_names") == exact_package_names
        and policy.get("accepted_digest_algorithms") == ["SHA256"]
        and policy.get("accepted_public_key_algorithm") == "RSA"
        and policy.get("minimum_rsa_bits") == 3072
        and re.fullmatch(
            r"[0-9A-F]{40}", str(policy.get("primary_fingerprint"))
        )
        is not None
        and re.fullmatch(
            r"[0-9A-F]{40}", str(policy.get("signing_subkey_fingerprint"))
        )
        is not None
        and _HEX64.fullmatch(str(policy.get("public_key_sha256"))) is not None
        and isinstance(policy.get("public_key_path"), str)
        and bool(policy.get("public_key_path"))
    )


def _rpm_signature_authorized(
    result: subprocess.CompletedProcess[str], policy: Mapping[str, object]
) -> bool:
    fingerprint = policy.get("signing_subkey_fingerprint")
    if not isinstance(fingerprint, str) or len(fingerprint) != 40:
        return False
    key_ids = (fingerprint[-16:].lower(), fingerprint[-8:].lower())
    signature = re.compile(
        r"^(?:Header )?V4 RSA/SHA256 Signature, key ID "
        + r"(?:"
        + "|".join(re.escape(value) for value in key_ids)
        + r")"
        + r": OK$",
        re.IGNORECASE,
    )
    detail_lines = [line.strip() for line in result.stdout.splitlines()]
    signature_lines = [line for line in detail_lines if "Signature" in line]
    return (
        result.returncode == 0
        and not result.stderr
        and "NOT OK" not in result.stdout
        and "NOKEY" not in result.stdout
        and bool(signature_lines)
        and all(signature.fullmatch(line) for line in signature_lines)
        and "Header SHA256 digest: OK" in detail_lines
        and "Payload SHA256 digest: OK" in detail_lines
    )


def _tcp_port_specs_expose_web_range(specifications: str) -> bool:
    for token in specifications.split():
        match = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?/tcp", token)
        if match is None:
            continue
        start = int(match.group(1))
        end = int(match.group(2) or match.group(1))
        if start <= 9000 and end >= 8000:
            return True
    return False


def _rich_rule_exposes_web_range(rule: str) -> bool:
    match = re.search(
        r'\bport port="([0-9]{1,5}(?:-[0-9]{1,5})?)" protocol="tcp"',
        rule,
    )
    return match is not None and _tcp_port_specs_expose_web_range(
        match.group(1) + "/tcp"
    )


def _healthy_api_v1(value: object) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"api_version", "status"}
        and value.get("api_version") == 1
        and value.get("status") in {"ok", "healthy"}
    )


def _driver_rpm_verify_result_ok(
    result: subprocess.CompletedProcess[str],
) -> bool:
    return (
        result.returncode == 1
        and result.stdout == _DRIVER_RPM_VERIFY_ROW + "\n"
        and result.stderr == ""
    )


def _driver_rpm_verify_policy_ok(
    policy: Mapping[str, object], raw: bytes
) -> bool:
    return (
        raw == _canonical_bytes(dict(policy))
        and set(policy)
        == {
            "command",
            "package_nevra",
            "permitted_rows",
            "schema",
            "stderr",
            "success_exit_codes",
        }
        and policy.get("schema") == 1
        and policy.get("command") == ["/usr/bin/rpm", "-V", "lto-ltfs"]
        and policy.get("package_nevra") == _DRIVER_NEVRA
        and policy.get("permitted_rows") == [_DRIVER_RPM_VERIFY_ROW]
        and policy.get("stderr") == ""
        and policy.get("success_exit_codes") == [1]
    )


def _legacy_https_login_ok(probe: Mapping[str, object]) -> bool:
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
            if (
                response.status != 200
                or response.geturl() != url
                or len(body) > 1024 * 1024
                or content_type.split(";", 1)[0].strip().lower() != "text/html"
                or "no-store" not in {
                    value.strip().lower() for value in cache_control.split(",")
                }
                or b'action="/login"' not in body
            ):
                return False
        return True
    except (
        ContractError,
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        ssl.SSLError,
        tomllib.TOMLDecodeError,
    ):
        return False


def load_driver_input_contract(
    path: Path, *, expected_sha256: str
) -> DriverInputContract:
    value, data = _load_json(path)
    if set(value) != _DRIVER_KEYS or type(value.get("schema")) is not int or value.get("schema") != 1:
        raise ContractError("closed driver contract keys mismatch")
    if data != _canonical_bytes(value):
        raise ContractError("driver contract is not canonical JSON")
    if not _HEX64.fullmatch(expected_sha256) or hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ContractError("driver contract digest mismatch")
    if value.get("package_nevra") != _DRIVER_NEVRA:
        raise ContractError("driver NEVRA mismatch")
    if value.get("rpm_verify_policy_sha256") != _DRIVER_RPM_VERIFY_POLICY_SHA256:
        raise ContractError("driver RPM verification policy authority mismatch")
    digest_keys = _DRIVER_KEYS - {
        "package_nevra",
        "schema",
        "source_provenance_status",
    }
    if any(
        not isinstance(value.get(key), str)
        or not _HEX64.fullmatch(str(value[key]))
        for key in digest_keys
    ):
        raise ContractError("driver digest field is invalid")
    provenance = value.get("source_provenance_status")
    if provenance not in {"local-build-identity-only", "authenticated-release"}:
        raise ContractError("driver provenance status is invalid")
    return DriverInputContract(
        package_nevra=str(value["package_nevra"]),
        rpm_raw_sha256=str(value["rpm_raw_sha256"]),
        rpm_header_sha256=str(value["rpm_header_sha256"]),
        rpm_payload_sha256=str(value["rpm_payload_sha256"]),
        rpm_signing_policy_sha256=str(value["rpm_signing_policy_sha256"]),
        rpm_public_key_sha256=str(value["rpm_public_key_sha256"]),
        rpm_verify_policy_sha256=str(value["rpm_verify_policy_sha256"]),
        installed_file_metadata_sha256=str(value["installed_file_metadata_sha256"]),
        source_provenance_status=str(provenance),
        source_provenance_evidence_sha256=str(
            value["source_provenance_evidence_sha256"]
        ),
    )


@dataclass(frozen=True)
class UnitObservation:
    enablement: str
    active: bool


def _canonical_unit_enablement(
    result: subprocess.CompletedProcess[str],
) -> str:
    if result.stderr or "\r" in result.stdout:
        raise ContractError("unit enablement observation is invalid")
    stdout = (
        result.stdout[:-1] if result.stdout.endswith("\n") else result.stdout
    )
    if "\n" in stdout:
        raise ContractError("unit enablement observation is invalid")
    states = {
        (0, "enabled"): "enabled",
        (1, "disabled"): "disabled",
        (0, "static"): "static",
    }
    try:
        return states[(result.returncode, stdout)]
    except KeyError:
        raise ContractError("unit enablement observation is invalid") from None


@dataclass(frozen=True)
class DaemonObservation:
    health_ok: bool
    api_v1: bool
    idle: bool
    accepting_mutations: bool
    admission_blocker_count: int
    critical_recovery_count: int


@dataclass(frozen=True)
class DatabaseObservation:
    integrity_ok: bool
    foreign_keys_ok: bool
    schema_ok: bool


@dataclass(frozen=True)
class InventoryObservation:
    library_count: int
    share_count: int
    mount_count: int
    digest: str
    reconciled: bool
    no_unmanaged_test_mount: bool


@dataclass(frozen=True)
class FirewallObservation:
    listener_exact: bool
    lan_only: bool
    source_rules: frozenset[str]
    broad_port_open: bool
    broad_service_open: bool


@dataclass(frozen=True)
class JournalEvent:
    unit: str
    message_id: str
    priority: int


@dataclass(frozen=True)
class LiveObservation:
    installed_nevras: Mapping[str, str]
    app_runtime_signatures_ok: bool
    driver_contract_ok: bool
    driver_installed_equivalent: bool
    units: Mapping[str, UnitObservation]
    failed_unit_count: int
    daemon: DaemonObservation
    https_ok: bool
    databases: Mapping[str, DatabaseObservation]
    inventory: InventoryObservation
    firewall: FirewallObservation
    rpm_verify: Mapping[str, tuple[str, ...]]
    driver_rpm_verify_ok: bool
    priority_journal_events: tuple[JournalEvent, ...]


class LiveHost(Protocol):
    def observe(self, request: VerifyDeploymentRequest) -> LiveObservation: ...


@dataclass(frozen=True)
class VerifyDeploymentRequest:
    expected_nevras: Mapping[str, str]
    rpm_verify_policy: Path
    journal_policy: Path
    driver_input_contract: Path
    expected_driver_input_sha256: str
    maintenance_started_at: str
    artifact_manifest_sha256: str
    rollback_manifest_sha256: str


@dataclass(frozen=True)
class SystemLiveConfig:
    daemon_socket: Path
    https_health_url: str
    https_ca_certificate: Path
    firewall_zone: str
    expected_listen_address: str
    managed_sources_root: Path
    application_rpm: Path
    runtime_rpm: Path
    signing_public_key: Path
    signing_policy: Path
    driver_rpm: Path
    driver_rpm_verify_policy: Path
    driver_signing_policy: Path
    driver_public_key: Path
    driver_source_provenance_evidence: Path
    driver_digest_authority: Path


class CommandRunner(Protocol):
    def __call__(
        self, argv: tuple[str, ...], accepted: tuple[int, ...] = (0,)
    ) -> subprocess.CompletedProcess[str]: ...


@dataclass(frozen=True)
class VerificationReport:
    status: str
    expected_nevras: Mapping[str, str]
    observed_nevras: Mapping[str, str]
    package_identity_ok: bool
    signatures_ok: bool
    units_ok: bool
    failed_units_ok: bool
    daemon_ok: bool
    https_ok: bool
    databases_ok: bool
    inventory_ok: bool
    inventory_counts: Mapping[str, int]
    inventory_digest: str
    listener_firewall_ok: bool
    rpm_verify_ok: bool
    rpm_difference_count: int
    journal_ok: bool
    priority_journal_count: int
    artifact_manifest_sha256: str
    rollback_manifest_sha256: str
    driver_input_sha256: str
    upstream_driver_lineage_verified: bool

    def to_json(self) -> str:
        return json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":")
        ) + "\n"


class SystemLiveHost:
    """Observation-only local RHEL 9 collector for the executable verifier."""

    def __init__(
        self,
        config: SystemLiveConfig,
        *,
        runner: CommandRunner | None = None,
    ) -> None:
        self._config = config
        self._runner = runner or self._run

    @staticmethod
    def _run(
        argv: tuple[str, ...], accepted: tuple[int, ...] = (0,)
    ) -> subprocess.CompletedProcess[str]:
        if not argv or not Path(argv[0]).is_absolute():
            raise ContractError("live command is not absolute")
        try:
            result = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=True,
                timeout=60,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
            )
        except (OSError, subprocess.SubprocessError):
            raise ContractError("live command failed") from None
        if result.returncode not in accepted:
            raise ContractError("live command failed")
        if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 64 * 1024:
            raise ContractError("live command output exceeded its bound")
        return result

    @staticmethod
    def _require_root_tool(path: Path) -> None:
        try:
            details = path.stat(follow_symlinks=False)
        except OSError:
            raise ContractError("required live tool is unavailable") from None
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
        ):
            raise ContractError("required live tool failed ownership checks")

    @staticmethod
    def _root_authority(path: Path) -> bool:
        try:
            details = path.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            path.is_absolute()
            and stat.S_ISREG(details.st_mode)
            and not path.is_symlink()
            and details.st_uid == 0
            and not details.st_mode & 0o022
        )

    def _command(self, *argv: str | Path, accepted: tuple[int, ...] = (0,)) -> str:
        path = Path(argv[0])
        self._require_root_tool(path)
        return self._runner(tuple(str(value) for value in argv), accepted).stdout

    def _command_result(
        self, *argv: str | Path, accepted: tuple[int, ...] = (0,)
    ) -> subprocess.CompletedProcess[str]:
        path = Path(argv[0])
        self._require_root_tool(path)
        return self._runner(tuple(str(value) for value in argv), accepted)

    @staticmethod
    def _json_bytes(data: bytes) -> object:
        if len(data) > 4 * 1024 * 1024:
            raise ContractError("live JSON exceeded its bound")
        try:
            return json.loads(data.decode(), object_pairs_hook=_duplicate_free_object)
        except (UnicodeError, json.JSONDecodeError, ContractError):
            raise ContractError("live JSON is invalid") from None

    def _daemon_get(
        self, endpoint: str, *, deadline: float | None = None
    ) -> object:
        path = self._config.daemon_socket
        if not path.is_absolute():
            raise ContractError("daemon socket path is invalid")

        def remaining_timeout() -> float:
            if deadline is None:
                return 10.0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ContractError("daemon observation timed out")
            return min(10.0, remaining)

        request = (
            f"GET {endpoint} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        ).encode()
        response = bytearray()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(remaining_timeout())
                connection.connect(str(path))
                connection.settimeout(remaining_timeout())
                connection.sendall(request)
                while True:
                    connection.settimeout(remaining_timeout())
                    chunk = connection.recv(65536)
                    if not chunk:
                        break
                    response.extend(chunk)
                    if len(response) > 4 * 1024 * 1024:
                        raise ContractError("daemon response exceeded its bound")
        except OSError:
            raise ContractError("daemon observation failed") from None
        head, separator, body = bytes(response).partition(b"\r\n\r\n")
        if not separator or not head.startswith(b"HTTP/1.1 200 "):
            raise ContractError("daemon response failed")
        return self._json_bytes(body)

    def _log_reader_boundary_ok(self) -> bool:
        """Verify the reader's DAC, systemd, SELinux, and API boundaries."""
        socket_path = Path("/run/lto-archiver-log-reader/control.sock")
        runtime_path = socket_path.parent

        def unit_properties(unit: str, names: tuple[str, ...]) -> dict[str, str]:
            values: dict[str, str] = {}
            for name in names:
                rows = _systemd_show_values(
                    self._command(
                        _SYSTEMCTL,
                        "show",
                        f"--property={name}",
                        "--value",
                        unit,
                    )
                )
                if len(rows) != 1:
                    raise ContractError("systemd property observation is invalid")
                values[name] = rows[0]
            return values

        try:
            runtime_details = runtime_path.stat(follow_symlinks=False)
            socket_details = socket_path.stat(follow_symlinks=False)
            reader_group = grp.getgrnam("lto-log-read")
        except (KeyError, OSError):
            return False
        if (
            not stat.S_ISDIR(runtime_details.st_mode)
            or runtime_details.st_uid != 0
            or runtime_details.st_gid != reader_group.gr_gid
            or stat.S_IMODE(runtime_details.st_mode) != 0o750
            or not stat.S_ISSOCK(socket_details.st_mode)
            or socket_details.st_uid != 0
            or socket_details.st_gid != reader_group.gr_gid
            or stat.S_IMODE(socket_details.st_mode) != 0o660
            or reader_group.gr_mem != ["lto-archiver"]
        ):
            return False
        try:
            effective_groups = {
                unit: _systemd_show_values(
                    self._command(
                        _SYSTEMCTL,
                        "show",
                        "--property=SupplementaryGroups",
                        "--value",
                        unit,
                    )
                )
                for unit in _LOG_READER_EFFECTIVE_SERVICE_GROUPS
            }
            socket_properties = unit_properties(
                "lto-archiver-log-reader.socket",
                ("SocketUser", "SocketGroup", "SocketMode", "FileDescriptorName"),
            )
            service_properties = unit_properties(
                "lto-archiver-log-reader.service",
                (
                    "User",
                    "Group",
                    "ExecStart",
                    "CapabilityBoundingSet",
                    "AmbientCapabilities",
                    "NoNewPrivileges",
                    "ProtectSystem",
                    "ProtectHome",
                    "PrivateDevices",
                    "ProtectKernelLogs",
                    "RestrictAddressFamilies",
                    "DevicePolicy",
                    *_LOG_READER_EMPTY_PATH_PROPERTIES,
                ),
            )
            runtime_label = self._command(_MATCHPATHCON, "-n", runtime_path).strip()
            actual_runtime_label = os.getxattr(
                runtime_path, "security.selinux"
            ).decode("ascii").rstrip("\0")
            socket_label = self._command(_MATCHPATHCON, "-n", socket_path).strip()
            actual_socket_label = os.getxattr(socket_path, "security.selinux").decode(
                "ascii"
            ).rstrip("\0")
            page = self._daemon_get("/api/v1/system-logs?limit=1")
        except (ContractError, OSError, UnicodeError):
            return False
        return (
            all(
                len(values) == 1
                and frozenset(filter(None, values[0].split(" ")))
                == expected_groups
                for unit, expected_groups in _LOG_READER_EFFECTIVE_SERVICE_GROUPS.items()
                for values in (effective_groups[unit],)
            )
            and socket_properties
            == {
                "SocketUser": "root",
                "SocketGroup": "lto-log-read",
                "SocketMode": "0660",
                "FileDescriptorName": "log-reader",
            }
            and service_properties["User"] == "root"
            and service_properties["Group"] == "root"
            and service_properties["ExecStart"].startswith(
                "{ path=/usr/bin/lto-archiver-log-reader ; argv[]="
                + _LOG_READER_EXEC_START
                + " ;"
            )
            and service_properties["ExecStart"].count(
                "path=/usr/bin/lto-archiver-log-reader"
            )
            == 1
            and {
                name: service_properties[name]
                for name in (
                    "CapabilityBoundingSet",
                    "AmbientCapabilities",
                    "NoNewPrivileges",
                    "ProtectSystem",
                    "ProtectHome",
                    "PrivateDevices",
                    "ProtectKernelLogs",
                    "RestrictAddressFamilies",
                    "DevicePolicy",
                )
            }
            == {
                "CapabilityBoundingSet": "",
                "AmbientCapabilities": "",
                "NoNewPrivileges": "yes",
                "ProtectSystem": "strict",
                "ProtectHome": "yes",
                "PrivateDevices": "yes",
                "ProtectKernelLogs": "no",
                "RestrictAddressFamilies": "AF_UNIX",
                "DevicePolicy": "closed",
            }
            and all(
                service_properties[name] == ""
                for name in _LOG_READER_EMPTY_PATH_PROPERTIES
            )
            and runtime_label
            == "system_u:object_r:lto_archiver_log_reader_runtime_t:s0"
            and actual_runtime_label
            == "system_u:object_r:lto_archiver_log_reader_runtime_t:s0"
            and socket_label
            == "system_u:object_r:lto_archiver_log_reader_runtime_t:s0"
            and actual_socket_label
            == "system_u:object_r:lto_archiver_log_reader_runtime_t:s0"
            and isinstance(page, dict)
            and isinstance(page.get("items"), list)
        )

    def _https_ok(self) -> bool:
        url = self._config.https_health_url
        if not url.startswith("https://") or not self._config.https_ca_certificate.is_absolute():
            return False
        try:
            context = ssl.create_default_context(cafile=self._config.https_ca_certificate)
            request = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(request, context=context, timeout=10) as response:
                data = response.read(1024 * 1024 + 1)
                if response.status != 200 or len(data) > 1024 * 1024:
                    return False
            value = self._json_bytes(data)
        except (OSError, ValueError, ssl.SSLError, ContractError):
            return False
        return _healthy_api_v1(value)

    def _installed_nevras(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for package in ("lto-archiver", "lto-archiver-python-runtime", "lto-ltfs"):
            value = self._command(
                _RPM,
                "-q",
                "--qf",
                "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}",
                package,
            )
            if "\n" in value or not value.startswith(package + "-"):
                raise ContractError("installed package response is invalid")
            result[package] = value
        return result

    def _isolated_signatures_ok(self, rpms: tuple[Path, ...]) -> bool:
        policy, _raw = _load_json(self._config.signing_policy)
        if not _closed_signing_policy(
            policy,
            exact_package_names=["lto-archiver", "lto-archiver-python-runtime"],
        ):
            return False
        package_names = tuple(
            self._command(_RPM, "-qp", "--qf", "%{NAME}", rpm) for rpm in rpms
        )
        if package_names != ("lto-archiver", "lto-archiver-python-runtime"):
            return False
        key = self._config.signing_public_key
        if (
            not self._root_authority(self._config.signing_policy)
            or not self._root_authority(key)
            or _digest(key.read_bytes()) != policy.get("public_key_sha256")
        ):
            return False
        with tempfile.TemporaryDirectory() as temporary:
            gnupg = Path(temporary) / "gnupg"
            rpmdb = Path(temporary) / "rpmdb"
            gnupg.mkdir(mode=0o700)
            rpmdb.mkdir(mode=0o700)
            key_listing = self._command(
                _GPG,
                "--no-options",
                "--homedir",
                gnupg,
                "--batch",
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                key,
            )
            if not _signing_key_listing_authorized(key_listing, policy):
                return False
            self._command(_RPMKEYS, "--dbpath", rpmdb, "--import", key)
            for rpm in rpms:
                result = self._command_result(
                    _RPMKEYS,
                    "--dbpath",
                    rpmdb,
                    "--checksig",
                    "--verbose",
                    rpm,
                )
                if not _rpm_signature_authorized(result, policy):
                    return False
        return True

    def _driver_ok(self, request: VerifyDeploymentRequest) -> tuple[bool, bool]:
        return self._inspect_driver(request, include_installed=True)

    def _driver_artifact_ok(self, request: VerifyDeploymentRequest) -> bool:
        artifact_ok, _installed_unverified = self._inspect_driver(
            request, include_installed=False
        )
        return artifact_ok

    def _inspect_driver(
        self, request: VerifyDeploymentRequest, *, include_installed: bool
    ) -> tuple[bool, bool]:
        contract = load_driver_input_contract(
            request.driver_input_contract,
            expected_sha256=request.expected_driver_input_sha256,
        )
        config = self._config
        if (
            not all(
                self._root_authority(path)
                for path in (
                    request.driver_input_contract,
                    config.driver_rpm,
                    config.driver_rpm_verify_policy,
                    config.driver_signing_policy,
                    config.driver_public_key,
                    config.driver_source_provenance_evidence,
                    config.driver_digest_authority,
                )
            )
            or not config.driver_rpm.is_absolute()
            or not config.driver_rpm.is_file()
            or not config.driver_rpm_verify_policy.is_file()
            or _digest(config.driver_rpm_verify_policy.read_bytes())
            != contract.rpm_verify_policy_sha256
            or not config.driver_signing_policy.is_file()
            or _digest(config.driver_signing_policy.read_bytes())
            != contract.rpm_signing_policy_sha256
            or not config.driver_public_key.is_file()
            or _digest(config.driver_public_key.read_bytes())
            != contract.rpm_public_key_sha256
            or not config.driver_source_provenance_evidence.is_file()
            or _digest(config.driver_source_provenance_evidence.read_bytes())
            != contract.source_provenance_evidence_sha256
            or not config.driver_digest_authority.is_file()
            or _digest(config.driver_digest_authority.read_bytes())
            != _DRIVER_DIGEST_AUTHORITY_SHA256
        ):
            return False, False
        policy, policy_raw = _load_json(config.driver_rpm_verify_policy)
        if not _driver_rpm_verify_policy_ok(policy, policy_raw):
            return False, False
        query_result = self._command_result(
            _RPM,
            "-qp",
            "--qf",
            "%{NAME}\n%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n%{PAYLOADDIGEST}\n",
            config.driver_rpm,
        )
        if not _driver_artifact_identity_ok(
            contract, config.driver_rpm.read_bytes(), query_result
        ):
            return False, False
        installed_ok = False
        if include_installed:
            metadata_result = self._command_result(
                _RPM, "-ql", "--dump", "lto-ltfs"
            )
            metadata = metadata_result.stdout
            installed_ok = (
                not metadata_result.stderr
                and metadata.endswith("\n")
                and _digest(metadata.encode()) == contract.installed_file_metadata_sha256
            )
        signing_policy, _raw = _load_json(config.driver_signing_policy)
        # Downstream package signing does not authenticate inherited source
        # lineage. The hash-bound signing policy selects the verification path.
        if _closed_signing_policy(
            signing_policy, exact_package_names=["lto-ltfs"]
        ):
            if signing_policy["public_key_sha256"] != contract.rpm_public_key_sha256:
                return False, installed_ok
            with tempfile.TemporaryDirectory() as temporary:
                gnupg = Path(temporary) / "gnupg"
                rpmdb = Path(temporary) / "rpmdb"
                gnupg.mkdir(mode=0o700)
                rpmdb.mkdir(mode=0o700)
                key_listing = self._command(
                    _GPG,
                    "--no-options",
                    "--homedir",
                    gnupg,
                    "--batch",
                    "--with-colons",
                    "--import-options",
                    "show-only",
                    "--import",
                    config.driver_public_key,
                )
                if not _signing_key_listing_authorized(
                    key_listing, signing_policy
                ):
                    return False, installed_ok
                self._command(
                    _RPMKEYS,
                    "--dbpath",
                    rpmdb,
                    "--import",
                    config.driver_public_key,
                )
                signature = self._command_result(
                    _RPMKEYS,
                    "--dbpath",
                    rpmdb,
                    "--checksig",
                    "--verbose",
                    config.driver_rpm,
                )
                return (
                    _rpm_signature_authorized(signature, signing_policy),
                    installed_ok,
                )
        if (
            contract.package_nevra != "lto-ltfs-0.1.0-16.el9.x86_64"
            or contract.source_provenance_status != "local-build-identity-only"
            or type(signing_policy.get("schema")) is not int
            or signing_policy != {
                "package_names": ["lto-ltfs"],
                "schema": 1,
                "status": "unsigned-local-build",
            }
        ):
            return False, installed_ok
        signature = self._command_result(
            _RPMKEYS, "--checksig", config.driver_rpm, accepted=(0, 1)
        )
        return _local_unsigned_driver_signature_ok(signature), installed_ok

    @staticmethod
    def _database(
        path: Path,
        *,
        auth: bool = False,
        catalog: bool = False,
        broker: bool = False,
        catalog_schema: str = "40",
        protected_catalog: bool = False,
    ) -> DatabaseObservation:
        integrity_ok = foreign_ok = schema_ok = False
        try:
            connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
            integrity_ok = connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
            foreign_ok = not connection.execute("PRAGMA foreign_key_check").fetchall()
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if catalog:
                row = connection.execute(
                    "SELECT value FROM metadata WHERE key='schema_version'"
                ).fetchone()
                protected_schema = (
                    int(catalog_schema)
                    if catalog_schema.isascii() and catalog_schema.isdecimal()
                    else -1
                )
                schema_ok = (
                    (
                        _MIN_PROTECTED_CATALOG_SCHEMA
                        <= protected_schema
                        <= _MAX_PROTECTED_CATALOG_SCHEMA
                        if protected_catalog
                        else catalog_schema in {"32", "35", "38", "39", "40", "41"}
                    )
                    and row == (catalog_schema,)
                )
                if schema_ok and not protected_catalog and catalog_schema in {"38", "39", "40", "41"}:
                    from ltobackup.migration.validator import (
                        validate_catalog_contract,
                    )

                    schema_ok = validate_catalog_contract(
                        connection, int(catalog_schema)
                    ).valid
            elif auth:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_schema WHERE type='table'"
                    )
                }
                expected_tables = {
                    "web_users",
                    "web_sessions",
                    "web_auth_audit",
                    "web_idempotency",
                }
                schema_ok = version == 2 and {
                    name for name in tables if not name.startswith("sqlite_")
                } == expected_tables
            elif broker:
                schema_ok = version == 10
            else:
                schema_ok = False
            connection.close()
        except (OSError, sqlite3.Error, TypeError):
            pass
        return DatabaseObservation(integrity_ok, foreign_ok, schema_ok)

    @staticmethod
    def _protected_backup(path: Path) -> DatabaseObservation:
        match = _PROTECTED_BACKUP_NAME.fullmatch(path.name)
        if match is None:
            return DatabaseObservation(False, False, False)
        version = int(match["version"])
        if not (
            _MIN_PROTECTED_CATALOG_SCHEMA
            <= version
            <= _MAX_PROTECTED_CATALOG_SCHEMA
        ):
            return DatabaseObservation(False, False, False)
        descriptor: int | None = None
        try:
            root = path.parent
            root_details = root.stat(follow_symlinks=False)
            if (
                root.is_symlink()
                or not stat.S_ISDIR(root_details.st_mode)
                or stat.S_IMODE(root_details.st_mode) != 0o750
            ):
                return DatabaseObservation(False, False, False)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            details = os.fstat(descriptor)
            if (
                not stat.S_ISREG(details.st_mode)
                or details.st_nlink != 1
                or details.st_uid != root_details.st_uid
                or details.st_gid != root_details.st_gid
                or stat.S_IMODE(details.st_mode) != 0o600
                or details.st_size <= 0
            ):
                return DatabaseObservation(False, False, False)
            with tempfile.TemporaryDirectory(
                prefix="lto-live-protected-backup-"
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
                    return DatabaseObservation(False, False, False)
                return SystemLiveHost._database(
                    isolated,
                    catalog=True,
                    catalog_schema=str(version),
                    protected_catalog=True,
                )
        except (OSError, TypeError):
            return DatabaseObservation(False, False, False)
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def _databases(
        self,
        *,
        catalog_schema: str = "40",
        protected_backup_required: bool = True,
    ) -> Mapping[str, DatabaseObservation]:
        backups = tuple(
            _PROTECTED_BACKUP_ROOT.glob("*-p-*.sqlite3")
        )
        parameters_ok = (
            (catalog_schema, protected_backup_required)
            in {
                ("32", False),
                ("35", False),
                ("35", True),
                ("38", True),
                ("39", True),
                ("40", True),
                ("40", False),
            }
            and type(protected_backup_required) is bool
        )
        backup_ok = parameters_ok and (
            bool(backups) or not protected_backup_required
        ) and all(
            all(
                asdict(
                    self._protected_backup(path)
                ).values()
            )
            for path in backups
        ) and (
            catalog_schema != "35"
            or not protected_backup_required
            or (
                all(
                    int(_PROTECTED_BACKUP_NAME.fullmatch(path.name)["version"])
                    <= int(catalog_schema)
                    for path in backups
                )
                and any(
                    (match := _PROTECTED_BACKUP_NAME.fullmatch(path.name)) is not None
                    and match["version"] == catalog_schema
                    for path in backups
                )
            )
        )
        share_ok = self._share_state_ok(
            Path("/var/lib/lto-archiver-share-broker"),
            Path("/etc/lto-archiver/share-credentials"),
        )
        return {
            "catalog": self._database(
                Path("/var/lib/lto-archiver/catalog.db"),
                catalog=True,
                catalog_schema=catalog_schema,
            ),
            "command_broker": self._database(
                Path("/var/lib/lto-archiver-broker/state.db"), broker=True
            ),
            "protected_catalog_backup": DatabaseObservation(backup_ok, backup_ok, backup_ok),
            "share_broker_state": DatabaseObservation(share_ok, share_ok, share_ok),
            "web_auth": self._database(Path("/var/lib/lto-archiver-web/auth.sqlite3"), auth=True),
        }

    @staticmethod
    def _share_state_ok(state_root: Path, credential_root: Path) -> bool:
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
                    raw.decode("ascii"), object_pairs_hook=_duplicate_free_object
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
            ContractError,
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

    def _inventory(self, libraries: object, shares: object) -> InventoryObservation:
        library_rows = (
            libraries
            if isinstance(libraries, list)
            else libraries.get("libraries")
            if isinstance(libraries, dict)
            else None
        )
        share_rows = (
            shares
            if isinstance(shares, list)
            else shares.get("shares")
            if isinstance(shares, dict)
            else None
        )
        if not isinstance(library_rows, list) or not isinstance(share_rows, list):
            return InventoryObservation(0, 0, 0, "0" * 64, False, False)
        mounts_raw = self._command(
            _FINDMNT,
            "--json",
            "--list",
            "--output",
            "TARGET",
        )
        try:
            mounts = json.loads(mounts_raw, object_pairs_hook=_duplicate_free_object)
        except (json.JSONDecodeError, ContractError):
            mounts = {}
        filesystems = mounts.get("filesystems", []) if isinstance(mounts, dict) else []

        def mount_targets(rows: object) -> list[str]:
            if not isinstance(rows, list):
                return []
            result: list[str] = []
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("target"), str):
                    continue
                result.append(row["target"])
                result.extend(mount_targets(row.get("children", [])))
            return result

        targets = mount_targets(filesystems)
        managed_root = self._config.managed_sources_root
        managed_targets = [
            target
            for target in targets
            if Path(target) != managed_root
            and managed_root in Path(target).parents
        ]
        active_shares = [
            row
            for row in share_rows
            if isinstance(row, dict)
            and row.get("lifecycle") == "active"
            and row.get("desired_state") == "connected"
            and row.get("observed_state") == "connected"
        ]
        expected_targets = [
            str(managed_root / str(row.get("share_id"))) for row in active_shares
        ]
        managed_share_ids = {str(row.get("share_id")) for row in active_shares}
        libraries_ok = all(
            isinstance(row, dict)
            and (
                not isinstance(row.get("source"), dict)
                or row["source"].get("kind") != "managed_share"
                or row["source"].get("share_id") in managed_share_ids
            )
            for row in library_rows
        )
        no_test = "test" not in json.dumps(mounts, sort_keys=True).lower()
        reconciled = (
            sorted(managed_targets) == sorted(expected_targets)
            and len(managed_targets) == len(set(managed_targets))
            and libraries_ok
        )
        mount_count = len(managed_targets)
        digest = _digest(
            _canonical_bytes(
                {"libraries": library_rows, "mounts": mounts, "shares": share_rows}
            )
        )
        return InventoryObservation(
            len(library_rows), len(active_shares), mount_count, digest, reconciled, no_test
        )

    def _listener_exact(self) -> bool:
        try:
            octets = [int(item) for item in self._config.expected_listen_address.split(".")]
            if len(octets) != 4 or any(not 0 <= item <= 255 for item in octets):
                return False
            expected = "".join(f"{item:02X}" for item in reversed(octets)) + ":20FB"
            listeners: list[str] = []
            for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
                for line in table.read_text().splitlines()[1:]:
                    fields = line.split()
                    if len(fields) > 3 and fields[3] == "0A" and fields[1].endswith(":20FB"):
                        listeners.append(fields[1])
            return listeners == [expected]
        except (OSError, ValueError):
            return False

    def _firewall(self) -> FirewallObservation:
        zone = self._config.firewall_zone
        rich = self._command(_FIREWALL, f"--zone={zone}", "--list-rich-rules")
        ports = self._command(_FIREWALL, f"--zone={zone}", "--list-ports")
        services = self._command(_FIREWALL, f"--zone={zone}", "--list-services")
        permanent_rich = self._command(
            _FIREWALL, f"--zone={zone}", "--permanent", "--list-rich-rules"
        )
        permanent_ports = self._command(
            _FIREWALL, f"--zone={zone}", "--permanent", "--list-ports"
        )
        permanent_services = self._command(
            _FIREWALL, f"--zone={zone}", "--permanent", "--list-services"
        )
        sources: set[str] = set()
        valid = True
        for line in filter(None, rich.splitlines()):
            match = re.fullmatch(
                r'rule family="ipv4" source address="([^"]+)" port port="8443" protocol="tcp" accept',
                line,
            )
            if match is None:
                if _rich_rule_exposes_web_range(line):
                    valid = False
                continue
            sources.add(match.group(1))
        service_exposes_8443 = False
        for permanent, service_rows in (
            (False, services.split()),
            (True, permanent_services.split()),
        ):
            prefix: tuple[str, ...] = ("--permanent",) if permanent else ()
            for service in sorted(service_rows):
                if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", service):
                    service_exposes_8443 = True
                    continue
                detail = self._command(
                    _FIREWALL, *prefix, f"--info-service={service}"
                )
                for line in detail.splitlines():
                    if line.strip().startswith("ports:") and (
                        _tcp_port_specs_expose_web_range(
                            line.partition(":")[2]
                        )
                    ):
                        service_exposes_8443 = True
        return FirewallObservation(
            listener_exact=self._listener_exact(),
            lan_only=(
                valid
                and sources == REQUIRED_FIREWALL_RULES
                and sorted(filter(None, rich.splitlines()))
                == sorted(filter(None, permanent_rich.splitlines()))
            ),
            source_rules=frozenset(sources),
            broad_port_open=(
                _tcp_port_specs_expose_web_range(ports)
                or _tcp_port_specs_expose_web_range(permanent_ports)
            ),
            broad_service_open=service_exposes_8443,
        )

    def _journal(self, started_at: str) -> tuple[JournalEvent, ...]:
        try:
            started = datetime.strptime(
                started_at, "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=UTC)
        except (TypeError, ValueError):
            raise ContractError("journal start time is invalid") from None
        output = self._command(
            _JOURNALCTL,
            "--output=json",
            "--priority=0..3",
            f"--since=@{int(started.timestamp())}",
            *(
                value
                for unit in sorted(REQUIRED_ACTIVE_UNITS | SECURITY_JOURNAL_UNITS)
                for value in ("--unit", unit)
            ),
        )
        events: list[JournalEvent] = []
        for line in filter(None, output.splitlines()):
            try:
                row = json.loads(line, object_pairs_hook=_duplicate_free_object)
                message_id = row.get("MESSAGE_ID", "")
                if not isinstance(message_id, str):
                    raise ContractError("journal message ID is invalid")
                events.append(
                    JournalEvent(
                        unit=str(row["_SYSTEMD_UNIT"]),
                        message_id=message_id.lower(),
                        priority=int(row["PRIORITY"]),
                    )
                )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError, ContractError):
                raise ContractError("journal observation is invalid") from None
        return tuple(events)

    def observe(self, request: VerifyDeploymentRequest) -> LiveObservation:
        status = self._daemon_get("/api/v1/status")
        health = self._daemon_get("/api/v1/health")
        libraries = self._daemon_get("/api/v1/libraries")
        shares = self._daemon_get("/api/v1/network-shares")
        if not self._log_reader_boundary_ok():
            raise ContractError("journal log reader boundary verification failed")
        if not isinstance(status, dict) or not isinstance(health, dict):
            raise ContractError("daemon observation is not an object")
        units = {}
        for unit in REQUIRED_ACTIVE_UNITS:
            enablement = _canonical_unit_enablement(
                self._command_result(
                    _SYSTEMCTL, "is-enabled", unit, accepted=(0, 1)
                )
            )
            allowed_enablement = (
                {"enabled"}
                if unit in REQUIRED_ENABLED_UNITS
                else (
                    {"static"}
                    if unit in REQUIRED_STATIC_UNITS
                    else {"enabled", "disabled"}
                )
            )
            if enablement not in allowed_enablement:
                raise ContractError(
                    "unit enablement does not match activation contract"
                )
            units[unit] = UnitObservation(
                enablement=enablement,
                active=self._command(
                    _SYSTEMCTL, "is-active", unit, accepted=(0, 3, 4)
                ).strip()
                == "active",
            )
        failed = self._command(_SYSTEMCTL, "--failed", "--plain", "--no-legend")
        driver_contract_ok, driver_installed_ok = self._driver_ok(request)
        rpm_verify: dict[str, tuple[str, ...]] = {}
        for package in ("lto-archiver", "lto-archiver-python-runtime"):
            result = self._command_result(_RPM, "-V", package, accepted=(0, 1))
            lines = tuple(filter(None, result.stdout.splitlines()))
            if result.stderr:
                lines = (*lines, "invalid-rpm-verify-stderr")
            rpm_verify[package] = lines
        driver_verify = self._command_result(
            _RPM, "-V", "lto-ltfs", accepted=(0, 1)
        )
        return LiveObservation(
            installed_nevras=self._installed_nevras(),
            app_runtime_signatures_ok=self._isolated_signatures_ok(
                (self._config.application_rpm, self._config.runtime_rpm)
            ),
            driver_contract_ok=driver_contract_ok,
            driver_installed_equivalent=driver_installed_ok,
            units=units,
            failed_unit_count=len(tuple(filter(None, failed.splitlines()))),
            daemon=DaemonObservation(
                health_ok=health.get("status") in {"ok", "healthy"},
                api_v1=health.get("api_version") == 1 and status.get("api_version") == 1,
                idle=_daemon_quiescent_for_maintenance(status),
                accepting_mutations=status.get("accepting_mutations") is True,
                admission_blocker_count=int(status.get("admission_blocker") is not None),
                critical_recovery_count=int(status.get("critical_recovery") is not None),
            ),
            https_ok=self._https_ok(),
            databases=self._databases(),
            inventory=self._inventory(libraries, shares),
            firewall=self._firewall(),
            rpm_verify=rpm_verify,
            driver_rpm_verify_ok=_driver_rpm_verify_result_ok(driver_verify),
            priority_journal_events=self._journal(request.maintenance_started_at),
        )


def _load_rpm_policy(path: Path) -> dict[str, dict[str, frozenset[str]]]:
    value, _data = _load_json(path)
    if set(value) != {"packages", "schema"} or value.get("schema") != 1:
        raise ContractError("RPM policy schema mismatch")
    packages = value.get("packages")
    expected = {"lto-archiver", "lto-archiver-python-runtime"}
    if not isinstance(packages, dict) or set(packages) != expected:
        raise ContractError("RPM policy package set mismatch")
    result: dict[str, dict[str, frozenset[str]]] = {}
    for package, rule in packages.items():
        if not isinstance(rule, dict) or set(rule) != {"allowed_config_paths"}:
            raise ContractError("RPM policy rule mismatch")
        paths = rule["allowed_config_paths"]
        if not isinstance(paths, dict):
            raise ContractError("RPM policy path map mismatch")
        normalized: dict[str, frozenset[str]] = {}
        for name, flags in paths.items():
            if (
                not isinstance(name, str)
                or not name.startswith("/")
                or not isinstance(flags, list)
                or any(flag not in {"S", "5", "T"} for flag in flags)
                or len(flags) != len(set(flags))
            ):
                raise ContractError("RPM policy path rule is invalid")
            normalized[name] = frozenset(flags)
        result[str(package)] = normalized
    return result


def _load_journal_policy(path: Path) -> frozenset[tuple[str, str, int]]:
    value, _data = _load_json(path)
    if set(value) != {"allowlist", "schema"} or value.get("schema") != 1:
        raise ContractError("journal policy schema mismatch")
    rows = value.get("allowlist")
    if not isinstance(rows, list):
        raise ContractError("journal allowlist is invalid")
    allowed: set[tuple[str, str, int]] = set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
            "message_id",
            "priority",
            "unit",
        }:
            raise ContractError("journal policy row mismatch")
        unit = row["unit"]
        message_id = row["message_id"]
        priority = row["priority"]
        item = (str(unit), str(message_id), int(priority))
        if (
            unit not in REQUIRED_ACTIVE_UNITS
            or not isinstance(message_id, str)
            or not _MESSAGE_ID.fullmatch(message_id)
            or isinstance(priority, bool)
            or not isinstance(priority, int)
            or not 0 <= priority <= 3
            or item in allowed
        ):
            raise ContractError("journal policy row is invalid")
        allowed.add(item)
    return frozenset(allowed)


def _rpm_verify_ok(
    observed: Mapping[str, tuple[str, ...]],
    policy: Mapping[str, Mapping[str, frozenset[str]]],
) -> tuple[bool, int]:
    if set(observed) != set(policy):
        return False, sum(len(value) for value in observed.values())
    seen: set[tuple[str, str]] = set()
    difference_count = 0
    for package, lines in observed.items():
        for line in lines:
            difference_count += 1
            match = _RPM_VERIFY.fullmatch(line)
            if match is None:
                return False, difference_count
            marker = match.group("marker")
            path = match.group("path")
            identity = (package, path)
            if identity in seen or marker != "c" or path not in policy[package]:
                return False, difference_count
            seen.add(identity)
            if any(
                actual not in {".", canonical}
                for canonical, actual in zip(
                    "SM5DLUGTP", match.group("flags")
                )
            ):
                return False, difference_count
            changed = {
                canonical
                for canonical, actual in zip("SM5DLUGTP", match.group("flags"))
                if actual != "."
            }
            if changed - policy[package][path]:
                return False, difference_count
    return True, difference_count


def verify_deployment(
    request: VerifyDeploymentRequest, host: LiveHost
) -> VerificationReport:
    if (
        set(request.expected_nevras)
        != {"lto-archiver", "lto-archiver-python-runtime", "lto-ltfs"}
        or request.expected_nevras.get("lto-archiver") != _APPLICATION_NEVRA
        or request.expected_nevras.get("lto-archiver-python-runtime")
        != _RUNTIME_NEVRA
        or request.expected_nevras.get("lto-ltfs") != _DRIVER_NEVRA
        or not _UTC.fullmatch(request.maintenance_started_at)
        or any(
            not _HEX64.fullmatch(value)
            for value in (
                request.artifact_manifest_sha256,
                request.rollback_manifest_sha256,
            )
        )
    ):
        raise ContractError("verification request is invalid")
    driver = load_driver_input_contract(
        request.driver_input_contract,
        expected_sha256=request.expected_driver_input_sha256,
    )
    rpm_policy = _load_rpm_policy(request.rpm_verify_policy)
    journal_policy = _load_journal_policy(request.journal_policy)
    observation = host.observe(request)

    package_identity_ok = dict(observation.installed_nevras) == dict(
        request.expected_nevras
    )
    signatures_ok = all(
        (
            observation.app_runtime_signatures_ok,
            observation.driver_contract_ok,
            observation.driver_installed_equivalent,
            observation.driver_rpm_verify_ok,
        )
    )
    units_ok = set(observation.units) == REQUIRED_ACTIVE_UNITS and all(
        state.active
        and (
            (unit in REQUIRED_ENABLED_UNITS and state.enablement == "enabled")
            or (unit in REQUIRED_STATIC_UNITS and state.enablement == "static")
            or (
                unit in PRESERVED_ENABLEMENT_UNITS
                and state.enablement in {"enabled", "disabled"}
            )
        )
        for unit, state in observation.units.items()
    )
    failed_units_ok = observation.failed_unit_count == 0
    daemon = observation.daemon
    daemon_ok = all(
        (daemon.health_ok, daemon.api_v1, daemon.idle, daemon.accepting_mutations)
    ) and daemon.admission_blocker_count == daemon.critical_recovery_count == 0
    databases_ok = set(observation.databases) == REQUIRED_DATABASES and all(
        all((state.integrity_ok, state.foreign_keys_ok, state.schema_ok))
        for state in observation.databases.values()
    )
    inventory = observation.inventory
    inventory_ok = all(
        (
            inventory.reconciled,
            inventory.no_unmanaged_test_mount,
            isinstance(inventory.library_count, int),
            isinstance(inventory.share_count, int),
            isinstance(inventory.mount_count, int),
            inventory.library_count >= 0,
            inventory.share_count >= 0,
            inventory.mount_count == inventory.share_count,
            bool(_HEX64.fullmatch(inventory.digest)),
        )
    )
    firewall = observation.firewall
    listener_firewall_ok = all(
        (
            firewall.listener_exact,
            firewall.lan_only,
            firewall.source_rules == REQUIRED_FIREWALL_RULES,
            not firewall.broad_port_open,
            not firewall.broad_service_open,
        )
    )
    rpm_ok, difference_count = _rpm_verify_ok(observation.rpm_verify, rpm_policy)
    journal_ok = all(
        (event.unit, event.message_id, event.priority) in journal_policy
        for event in observation.priority_journal_events
    )
    checks = (
        package_identity_ok,
        signatures_ok,
        units_ok,
        failed_units_ok,
        daemon_ok,
        observation.https_ok,
        databases_ok,
        inventory_ok,
        listener_firewall_ok,
        rpm_ok,
        journal_ok,
    )
    return VerificationReport(
        status="green" if all(checks) else "failed",
        expected_nevras=dict(sorted(request.expected_nevras.items())),
        observed_nevras=dict(sorted(observation.installed_nevras.items())),
        package_identity_ok=package_identity_ok,
        signatures_ok=signatures_ok,
        units_ok=units_ok,
        failed_units_ok=failed_units_ok,
        daemon_ok=daemon_ok,
        https_ok=observation.https_ok,
        databases_ok=databases_ok,
        inventory_ok=inventory_ok,
        inventory_counts={
            "libraries": inventory.library_count,
            "mounts": inventory.mount_count,
            "shares": inventory.share_count,
        },
        inventory_digest=inventory.digest,
        listener_firewall_ok=listener_firewall_ok,
        rpm_verify_ok=rpm_ok,
        rpm_difference_count=difference_count,
        journal_ok=journal_ok,
        priority_journal_count=len(observation.priority_journal_events),
        artifact_manifest_sha256=request.artifact_manifest_sha256,
        rollback_manifest_sha256=request.rollback_manifest_sha256,
        driver_input_sha256=request.expected_driver_input_sha256,
        upstream_driver_lineage_verified=driver.upstream_lineage_verified,
    )


def _request_from_file(path: Path) -> VerifyDeploymentRequest:
    value, raw = _load_json(path)
    expected_keys = {
        "artifact_manifest_sha256",
        "driver_input_contract",
        "expected_driver_input_sha256",
        "expected_nevras",
        "journal_policy",
        "maintenance_started_at",
        "rollback_manifest_sha256",
        "rpm_verify_policy",
        "schema",
    }
    if set(value) != expected_keys or value.get("schema") != 1 or raw != _canonical_bytes(value):
        raise ContractError("verification request is not canonical and closed")
    try:
        return VerifyDeploymentRequest(
            expected_nevras=dict(value["expected_nevras"]),
            rpm_verify_policy=Path(str(value["rpm_verify_policy"])),
            journal_policy=Path(str(value["journal_policy"])),
            driver_input_contract=Path(str(value["driver_input_contract"])),
            expected_driver_input_sha256=str(value["expected_driver_input_sha256"]),
            maintenance_started_at=str(value["maintenance_started_at"]),
            artifact_manifest_sha256=str(value["artifact_manifest_sha256"]),
            rollback_manifest_sha256=str(value["rollback_manifest_sha256"]),
        )
    except (TypeError, ValueError):
        raise ContractError("verification request field is invalid") from None


def _system_config_from_file(path: Path) -> SystemLiveConfig:
    value, _raw = _load_json(path)
    expected_keys = {
        "application_rpm",
        "daemon_socket",
        "driver_rpm",
        "driver_rpm_verify_policy",
        "driver_signing_policy",
        "driver_public_key",
        "driver_source_provenance_evidence",
        "driver_digest_authority",
        "expected_listen_address",
        "firewall_zone",
        "https_ca_certificate",
        "https_health_url",
        "managed_sources_root",
        "runtime_rpm",
        "schema",
        "signing_policy",
        "signing_public_key",
    }
    if set(value) != expected_keys or value.get("schema") != 1:
        raise ContractError("private live config is not closed")
    path_keys = expected_keys - {
        "expected_listen_address",
        "firewall_zone",
        "https_health_url",
        "schema",
    }
    paths = {key: Path(str(value[key])) for key in path_keys}
    if any(not item.is_absolute() for item in paths.values()):
        raise ContractError("private live config path is not absolute")
    return SystemLiveConfig(
        daemon_socket=paths["daemon_socket"],
        https_health_url=str(value["https_health_url"]),
        https_ca_certificate=paths["https_ca_certificate"],
        firewall_zone=str(value["firewall_zone"]),
        expected_listen_address=str(value["expected_listen_address"]),
        managed_sources_root=paths["managed_sources_root"],
        application_rpm=paths["application_rpm"],
        runtime_rpm=paths["runtime_rpm"],
        signing_public_key=paths["signing_public_key"],
        signing_policy=paths["signing_policy"],
        driver_rpm=paths["driver_rpm"],
        driver_rpm_verify_policy=paths["driver_rpm_verify_policy"],
        driver_signing_policy=paths["driver_signing_policy"],
        driver_public_key=paths["driver_public_key"],
        driver_source_provenance_evidence=paths[
            "driver_source_provenance_evidence"
        ],
        driver_digest_authority=paths["driver_digest_authority"],
    )


def _publish_report(path: Path, data: bytes) -> None:
    if not path.is_absolute() or path.exists() or path.parent.is_symlink():
        raise ContractError("report path must be absolute and new")
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path)
        temporary.unlink()
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _rollback_predecessor_schema(contract: Mapping[str, object]) -> int | None:
    schema = contract.get("source_catalog_schema")
    if type(schema) is not int:
        return None
    for application_release, catalog_schema, driver_release in (
        (101, 35, 16), (129, 40, 16), (130, 40, 17), (131, 40, 17),
        (132, 40, 18), (133, 40, 19), (134, 40, 20), (135, 40, 21),
        (136, 40, 21), (137, 40, 21), (138, 40, 21), (139, 40, 21),
        (140, 40, 21), (141, 40, 21),
    ):
        expected = {
            "lto-archiver": f"lto-archiver-0.11.27-{application_release}.el9.noarch",
            "lto-archiver-python-runtime": (
                "lto-archiver-python-runtime-0.11.27-3.el9.x86_64"
            ),
            "lto-ltfs": f"lto-ltfs-0.1.0-{driver_release}.el9.x86_64",
        }
        if schema == catalog_schema and contract.get("installed_nevras") == expected:
            return catalog_schema
    return None


def _legacy_protected_source_ok(bundle: Path, contract: Mapping[str, object]) -> bool:
    descriptor: int | None = None
    try:
        catalog_schema = _rollback_predecessor_schema(contract)
        if catalog_schema is None:
            return False
        relative_value = contract.get("protected_backup_relative_path")
        if not isinstance(relative_value, str):
            return False
        relative = PurePosixPath(relative_value)
        if (
            relative_value != relative.as_posix()
            or relative.is_absolute()
            or len(relative.parts) != 2
            or relative.parts[0] != "release-recovery"
            or ".." in relative.parts
        ):
            return False
        path = bundle.joinpath(*relative.parts)
        match = _PROTECTED_BACKUP_NAME.fullmatch(path.name)
        root = path.parent
        root_details = root.stat(follow_symlinks=False)
        if (
            match is None
            or match["version"] != str(catalog_schema)
            or root.is_symlink()
            or not stat.S_ISDIR(root_details.st_mode)
            or root_details.st_uid != _ROOT_UID
            or root_details.st_gid != _ROOT_GID
            or stat.S_IMODE(root_details.st_mode) != 0o700
        ):
            return False
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != _ROOT_UID
            or details.st_gid != _ROOT_GID
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o600
            or details.st_size <= 0
        ):
            return False
        digest = hashlib.sha256()
        with tempfile.TemporaryDirectory(prefix="lto-legacy-source-") as temporary:
            isolated = Path(temporary) / path.name
            output = os.open(
                isolated, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
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
                return False
            observed = SystemLiveHost._database(
                isolated,
                catalog=True,
                catalog_schema=str(catalog_schema),
                protected_catalog=True,
            )
        return (
            digest.hexdigest() == contract.get("protected_backup_sha256")
            and isinstance(contract.get("source_catalog_sha256"), str)
            and _HEX64.fullmatch(str(contract["source_catalog_sha256"])) is not None
            and all(asdict(observed).values())
        )
    except (OSError, TypeError, ValueError):
        return False
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _legacy_rollback_gate(
    contract_path: Path, bundle: Path, *, restoration_started_at: str | None = None
) -> bool:
    expected_contract_keys = {
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
    try:
        contract, raw = _load_json(contract_path)
        if (
            raw != _canonical_bytes(contract)
            or set(contract) != expected_contract_keys
            or type(contract.get("schema")) is not int
            or contract.get("schema") != 2
            or not bundle.is_absolute()
            or contract_path.resolve()
            != (bundle / "contracts/old-live-contract.json").resolve()
        ):
            return False
        catalog_schema = _rollback_predecessor_schema(contract)
        captured_at = contract.get("captured_at")
        if (
            catalog_schema is None
            or not isinstance(captured_at, str)
            or not _UTC.fullmatch(captured_at)
        ):
            return False
        captured = datetime.strptime(captured_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
        if catalog_schema == 40:
            if not isinstance(restoration_started_at, str) or not _UTC.fullmatch(restoration_started_at):
                return False
            restored = datetime.strptime(restoration_started_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
            if not captured <= restored <= datetime.now(UTC):
                return False
            journal_start = restoration_started_at
        else:
            if restoration_started_at is not None:
                return False
            journal_start = captured_at
        if not _legacy_protected_source_ok(bundle, contract):
            return False
        manifest_rows = (bundle / "rollback-SHA256SUMS").read_text(
            encoding="ascii"
        ).splitlines()
        measured: list[str] = []
        for path in sorted(bundle.rglob("*")):
            if path.is_symlink():
                return False
            if path.is_file() and path.name != "rollback-SHA256SUMS":
                measured.append(
                    f"{_digest(path.read_bytes())}  {path.relative_to(bundle).as_posix()}"
                )
        if manifest_rows != sorted(measured):
            return False
        state = contract.get("installed_package_state")
        packages = state.get("packages") if isinstance(state, dict) else None
        if (
            not isinstance(packages, dict)
            or set(packages)
            != {"lto-archiver", "lto-archiver-python-runtime", "lto-ltfs"}
        ):
            return False
        observed_rpm_verify: dict[str, tuple[str, ...]] = {}
        for package, expected in packages.items():
            if not isinstance(expected, dict):
                return False
            SystemLiveHost._require_root_tool(_RPM)
            nevra = SystemLiveHost._run(
                (
                    str(_RPM),
                    "-q",
                    "--qf",
                    "%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}",
                    package,
                )
            )
            metadata = SystemLiveHost._run(
                (str(_RPM), "-ql", "--dump", package)
            )
            verification = SystemLiveHost._run(
                (str(_RPM), "-V", package), (0, 1)
            )
            observed = {
                "installed_file_metadata_sha256": _digest(
                    metadata.stdout.encode()
                ),
                "nevra": nevra.stdout,
                "rpm_verify_exit": verification.returncode,
                "rpm_verify_stdout_sha256": _digest(
                    verification.stdout.encode()
                ),
                "rpm_verify_rows": list(
                    filter(None, verification.stdout.splitlines())
                ),
            }
            if (
                metadata.stderr or verification.stderr or nevra.stderr
                or observed != expected
                or observed["nevra"] != contract["installed_nevras"][package]
            ):
                return False
            if package == "lto-ltfs":
                if not _driver_rpm_verify_result_ok(verification):
                    return False
            elif verification.returncode != (
                1 if observed["rpm_verify_rows"] else 0
            ):
                return False
            observed_rpm_verify[package] = tuple(observed["rpm_verify_rows"])
        rpm_policy = _load_rpm_policy(
            bundle / "tools/rpm-verify-policy.json"
        )
        rpm_policy_ok, _difference_count = _rpm_verify_ok(
            {
                package: observed_rpm_verify[package]
                for package in (
                    "lto-archiver",
                    "lto-archiver-python-runtime",
                )
            },
            rpm_policy,
        )
        if (
            rpm_policy_ok is not True
            or observed_rpm_verify["lto-ltfs"]
            != (_DRIVER_RPM_VERIFY_ROW,)
        ):
            return False
        enablement = contract.get("unit_enablement")
        if (
            not isinstance(enablement, dict)
            or set(enablement) != REQUIRED_ACTIVE_UNITS
            or any(
                value not in {"enabled", "disabled", "static"}
                for value in enablement.values()
            )
        ):
            return False
        legacy = SystemLiveHost.__new__(SystemLiveHost)
        legacy._config = SimpleNamespace(
            daemon_socket=Path("/run/lto-archiver/daemon.sock"),
            managed_sources_root=Path("/mnt/lto-archiver/sources"),
        )
        legacy._runner = SystemLiveHost._run
        if catalog_schema == 40 and not legacy._log_reader_boundary_ok():
            return False
        for unit in REQUIRED_ACTIVE_UNITS:
            SystemLiveHost._require_root_tool(_SYSTEMCTL)
            observed_enablement = _canonical_unit_enablement(
                SystemLiveHost._run(
                    (str(_SYSTEMCTL), "is-enabled", unit), (0, 1)
                )
            )
            if observed_enablement != enablement[unit]:
                return False
            active = SystemLiveHost._run(
                (str(_SYSTEMCTL), "is-active", unit), (0, 3, 4)
            )
            on_demand_inactive = (
                catalog_schema == 40
                and unit == "lto-archiver-log-reader.service"
                and active.returncode == 3
                and active.stdout.strip() == "inactive"
                and not active.stderr
            )
            if active.returncode != 0 and not on_demand_inactive:
                return False
        if SystemLiveHost._run(
            (str(_SYSTEMCTL), "--failed", "--plain", "--no-legend")
        ).stdout:
            return False
        firewall = contract.get("firewall_policy")
        if not isinstance(firewall, dict):
            return False
        zone = firewall.get("zone")
        if not isinstance(zone, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,32}", zone
        ):
            return False
        SystemLiveHost._require_root_tool(_FIREWALL)
        for permanent, suffix in ((False, "runtime"), (True, "permanent")):
            prefix = ("--permanent",) if permanent else ()
            rich = sorted(
                filter(
                    None,
                    SystemLiveHost._run(
                        (
                            str(_FIREWALL),
                            f"--zone={zone}",
                            *prefix,
                            "--list-rich-rules",
                        )
                    ).stdout.splitlines(),
                )
            )
            ports = sorted(
                SystemLiveHost._run(
                    (
                        str(_FIREWALL),
                        f"--zone={zone}",
                        *prefix,
                        "--list-ports",
                    )
                ).stdout.split()
            )
            services = sorted(
                SystemLiveHost._run(
                    (
                        str(_FIREWALL),
                        f"--zone={zone}",
                        *prefix,
                        "--list-services",
                    )
                ).stdout.split()
            )
            if (
                rich != firewall.get(f"rich_rules_{suffix}")
                or ports != firewall.get(f"ports_{suffix}")
                or services != firewall.get(f"services_{suffix}")
            ):
                return False
        status = legacy._daemon_get("/api/v1/status")
        health = legacy._daemon_get("/api/v1/health")
        libraries = legacy._daemon_get("/api/v1/libraries")
        shares = legacy._daemon_get("/api/v1/network-shares")
        if (
            not isinstance(status, dict)
            or status.get("api_version") != 1
            or not _daemon_quiescent_for_maintenance(status)
            or status.get("accepting_mutations") is not True
            or not _healthy_api_v1(health)
        ):
            return False
        databases = legacy._databases(
            catalog_schema=str(catalog_schema),
            protected_backup_required=False,
        )
        if not all(
            all(asdict(observation).values())
            for observation in databases.values()
        ):
            return False
        inventory = legacy._inventory(libraries, shares)
        if not inventory.reconciled or not inventory.no_unmanaged_test_mount:
            return False
        if legacy._journal(journal_start):
            return False
        probe = contract.get("predecessor_web_probe")
        return isinstance(probe, dict) and _legacy_https_login_ok(probe)
    except (
        ContractError,
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
        ssl.SSLError,
        tomllib.TOMLDecodeError,
    ):
        return False


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path)
    parser.add_argument("--private-config", type=Path)
    parser.add_argument("--legacy-old-contract", type=Path)
    parser.add_argument("--legacy-bundle", type=Path)
    parser.add_argument("--restoration-started-at")
    parser.add_argument("--json-output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise ContractError("live verification requires root")
        legacy = arguments.legacy_old_contract is not None
        if legacy:
            if (
                arguments.request is not None
                or arguments.private_config is not None
                or arguments.legacy_bundle is None
            ):
                raise ContractError("legacy live inputs are incomplete")
            green = _legacy_rollback_gate(
                arguments.legacy_old_contract, arguments.legacy_bundle,
                restoration_started_at=arguments.restoration_started_at,
            )
            _publish_report(
                arguments.json_output,
                _canonical_bytes(
                    {"schema": 1, "status": "green" if green else "failed"}
                ),
            )
            return 0 if green else 2
        if (
            arguments.request is None
            or arguments.private_config is None
            or arguments.legacy_bundle is not None
            or arguments.restoration_started_at is not None
        ):
            raise ContractError("live verification inputs are incomplete")
        request = _request_from_file(arguments.request)
        config = _system_config_from_file(arguments.private_config)
        report = verify_deployment(request, SystemLiveHost(config))
        _publish_report(arguments.json_output, report.to_json().encode())
        return 0 if report.status == "green" else 2
    except (ContractError, OSError, ValueError):
        sys.stderr.write("live verification failed: closed host validation error\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
