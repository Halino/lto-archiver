#!/usr/bin/python3.11
"""Fail-closed local RHEL 9 deployment transaction.

The orchestration owns ordering and evidence binding; privileged host effects
are injected through ``DeploymentHost`` so the core has no hidden network,
hardware, package-cache, or tape behavior.
"""

from __future__ import annotations

import argparse
import grp
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import types
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager, ExitStack
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

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
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PYTHON = Path("/usr/bin/python3.11")
_DNF = Path("/usr/bin/dnf-3")
_SYSTEMCTL = Path("/usr/bin/systemctl")
_GPG = Path("/usr/bin/gpg")
_OPENSSL = Path("/usr/bin/openssl")
_LTFS_EXECUTABLES = frozenset(
    {
        b"ltfs",
        b"mkltfs",
        b"ltfsck",
        b"unltfs",
        b"fusermount",
        b"fusermount3",
    }
)
_QUALIFICATION_EXECUTABLES = frozenset(
    {b"lto-archiver-qualify-ltfs", b"lto-archiver-qualify-archive-runner"}
)
_SCRIPT_INTERPRETERS = frozenset(
    {b"python", b"python3", b"python3.11", b"sh", b"bash"}
)
_BOOTSTRAP_MEMBER_MAX = 512 * 1024 * 1024
_DAEMON_READINESS_TIMEOUT_SECONDS = 120
_RELEASE_AUTHORITY_MODES = frozenset({0o444, 0o600, 0o644, 0o755})
_ACTIVATION_STAGES = frozenset(
    {
        "input_validation",
        "quiescence_check",
        "enablement_snapshot",
        "device_policy_apply",
        "web_firewall_verify",
        "restore_contexts",
        "systemd_reload",
        "device_policy_verify",
        "application_import_verify",
        "unit_enable",
        "unit_start",
        "web_firewall_apply",
    }
)
_ACTIVATION_DIAGNOSTIC = re.compile(
    r"\ARHEL activation failed stage=([a-z0-9_]+)( cleanup=failed)?\n\Z"
)


def _is_active_ltfs_commandline(commandline: bytes, executable_path: str) -> bool:
    argv = tuple(value for value in commandline.split(b"\0") if value)
    if not argv:
        return False
    executable = os.fsencode(executable_path).rsplit(b"/", 1)[-1]
    if executable in _LTFS_EXECUTABLES:
        return True
    invoked = argv[0].rsplit(b"/", 1)[-1]
    if invoked in _LTFS_EXECUTABLES or invoked in _QUALIFICATION_EXECUTABLES:
        return True
    if executable not in _SCRIPT_INTERPRETERS and invoked not in _SCRIPT_INTERPRETERS:
        return False
    for argument in argv[1:] if invoked in _SCRIPT_INTERPRETERS else argv:
        if argument.startswith(b"-"):
            continue
        return argument.rsplit(b"/", 1)[-1] in _QUALIFICATION_EXECUTABLES
    return False


def _daemon_quiescent_for_deployment(status: Mapping[str, object]) -> bool:
    """Allow persisted media waits, but never an active/recovery operation."""
    if not {"job", "operation", "admission_blocker"}.issubset(status):
        return False
    if status["operation"] is not None or status["admission_blocker"] is not None:
        return False
    job = status["job"]
    if job is None:
        return True
    return bool(
        isinstance(job, Mapping)
        and job.get("state") in {"waiting_media", "paused"}
    )


class DeploymentError(RuntimeError):
    """Closed deployment admission or transaction failure."""


class ActivationDeploymentError(DeploymentError):
    """Closed activation stage propagated through the deployment transaction."""

    def __init__(self, stage: str, *, cleanup_failed: bool = False) -> None:
        if stage not in _ACTIVATION_STAGES or type(cleanup_failed) is not bool:
            raise ValueError("invalid activation diagnostic")
        self.stage = stage
        self.cleanup_failed = cleanup_failed
        detail = f"activation_stage={stage}"
        if cleanup_failed:
            detail += " cleanup=failed"
        super().__init__(detail)


@dataclass(frozen=True)
class RollbackRequest:
    bundle_dir: Path
    rollback_rpm_dir: Path
    expected_custom_web_unit_sha256: str
    driver_input_contract: Path
    expected_driver_input_sha256: str
    predecessor_web_probe: Mapping[str, str]
    candidate_driver_input_contract: Path
    expected_candidate_driver_input_sha256: str


@dataclass(frozen=True)
class DeploymentRequest:
    repository_commit: str
    deployment_commit: str
    application_rpm: Path
    runtime_rpm: Path
    driver_rpm: Path
    application_manifest: Path
    application_manifest_signature: Path
    runtime_manifest: Path
    runtime_manifest_signature: Path
    app_runtime_signing_policy: Path
    driver_input_contract: Path
    expected_driver_input_sha256: str
    rollback_request: RollbackRequest
    web_config_candidate: Path
    expected_web_config_sha256: str
    tls_certificate_candidate: Path
    tls_private_key_candidate: Path
    expected_tls_certificate_sha256: str
    expected_tls_private_key_sha256: str
    maintenance_started_at: str


@dataclass(frozen=True)
class ArtifactEvidence:
    verified: bool
    source_commit: str
    application_rpm_sha256: str
    runtime_rpm_sha256: str
    application_manifest_sha256: str
    runtime_manifest_sha256: str
    application_signed: bool
    runtime_signed: bool


@dataclass(frozen=True)
class AdmissionObservation:
    daemon_idle: bool
    daemon_reconciled: bool
    broker_idle: bool
    qualification_idle: bool
    no_ltfs_process: bool
    no_tape_mount: bool
    no_unmanaged_share_mount: bool
    no_failed_unit: bool
    no_priority_error: bool
    web_tls_firewall_ok: bool


@dataclass(frozen=True)
class RollbackEvidence:
    bundle_dir: Path
    bundle_id: str
    manifest_sha256: str


@dataclass(frozen=True)
class LiveEvidence:
    status: str
    report_sha256: str


@dataclass(frozen=True)
class RollbackOutcome:
    status: str
    old_health_verified: bool


@dataclass(frozen=True)
class DeploymentResult:
    status: str
    repository_commit: str
    application_rpm_sha256: str
    runtime_rpm_sha256: str
    application_manifest_sha256: str
    runtime_manifest_sha256: str
    driver_input_sha256: str
    rollback_manifest_sha256: str
    live_report_sha256: str
    evidence_sha256: str
    detail: str
    retention: Mapping[str, object] | None = None


_QUALIFICATION_OWNER = 0
_QUALIFICATION_ATTESTATION = Path("/etc/lto-archiver/qualification-artifacts.json")
_QUALIFICATION_TOOLS = {
    name: Path("/usr/bin") / name
    for name in ("ltfs", "mkltfs", "ltfsck", "ltfs-info", "fusermount", "mt")
}


def _qualification_driver_tools(raw: str) -> dict[str, str]:
    if not isinstance(raw, str) or len(raw) > 4 * 1024 * 1024 or not raw.endswith("\n"):
        raise DeploymentError("qualification RPM metadata is invalid")
    seen: set[str] = set()
    tools: dict[str, str] = {}
    required = {"ltfs", "mkltfs", "ltfsck", "ltfs-info"}
    for row in raw.splitlines():
        fields = row.split("\t")
        if len(fields) != 5:
            raise DeploymentError("qualification RPM metadata row is invalid")
        path, digest, mode, user, group = fields
        if (
            not path.startswith("/") or str(Path(path)) != path
            or ".." in Path(path).parts or path in seen
            or any(ord(character) < 32 for character in path)
        ):
            raise DeploymentError("qualification RPM metadata path is invalid")
        seen.add(path)
        name = Path(path).name
        if path not in {str(_QUALIFICATION_TOOLS[item]) for item in required}:
            continue
        expected_mode = 0o100750 if name == "mkltfs" else 0o100755
        if (
            not _HEX64.fullmatch(digest) or not re.fullmatch(r"0?[0-7]{6}", mode)
            or int(mode, 8) != expected_mode or user != "root"
            or group != ("lto-admin" if name == "mkltfs" else "root")
        ):
            raise DeploymentError("qualification RPM tool metadata is invalid")
        tools[name] = digest
    if set(tools) != required:
        raise DeploymentError("qualification RPM tools are incomplete")
    return tools


def _qualification_file(
    path: Path, *, mode: int, gid: int, expected: str | None = None
) -> bytes:
    descriptor = -1
    try:
        if not path.is_absolute() or ".." in path.parts:
            raise DeploymentError("qualification file path is unsafe")
        parents = tuple((parent, parent.lstat()) for parent in path.parents)
        for _parent, details in parents:
            if (
                not stat.S_ISDIR(details.st_mode)
                or details.st_uid not in (0, _QUALIFICATION_OWNER)
                or details.st_mode & 0o022
            ):
                raise DeploymentError("qualification file ancestor is unsafe")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode) or before.st_uid != _QUALIFICATION_OWNER
            or before.st_gid != gid or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != mode
            or not 0 < before.st_size <= 64 * 1024 * 1024
        ):
            raise DeploymentError("qualification file metadata is unsafe")
        data = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            data.extend(chunk)
            if len(data) > before.st_size:
                raise DeploymentError("qualification file grew")
        after = os.fstat(descriptor)
        current = path.lstat()
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                    value.st_gid, value.st_nlink, value.st_size,
                    value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(after) or identity(before) != identity(current):
            raise DeploymentError("qualification file changed")
        for parent, details in parents:
            current_parent = parent.lstat()
            if any(
                getattr(details, field) != getattr(current_parent, field)
                for field in ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
            ):
                raise DeploymentError("qualification file ancestor changed")
        if len(data) != before.st_size or (
            expected is not None and hashlib.sha256(data).hexdigest() != expected
        ):
            raise DeploymentError("qualification file hash is invalid")
        return bytes(data)
    except OSError:
        raise DeploymentError("qualification file is unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


class DeploymentHost(Protocol):
    def is_root(self) -> bool: ...
    def verify_release_artifacts(self, request: DeploymentRequest) -> ArtifactEvidence: ...
    def verify_driver_input(self, request: DeploymentRequest) -> bool: ...
    def observe_admission(self, request: DeploymentRequest) -> AdmissionObservation: ...
    def verify_rollback_preflight(self, request: RollbackRequest) -> bool: ...
    def verify_remaining_capacity(self, rollback: RollbackEvidence) -> bool: ...
    def register_rollback_artifact(self, rollback: RollbackEvidence) -> None: ...
    def rollback_artifact_lease(self, rollback: RollbackEvidence) -> AbstractContextManager: ...
    def finalize_rollback_artifacts(self, rollback: RollbackEvidence, evidence_hash: str) -> Mapping[str, object]: ...
    def validate_predecessor_source(self, request: RollbackRequest) -> bool: ...
    def verify_tls_candidates(self, request: DeploymentRequest) -> bool: ...
    def stop_stack(self, units: tuple[str, ...]) -> None: ...
    def prepare_predecessor_recovery(self, request: RollbackRequest) -> object: ...
    def create_verified_rollback(
        self, request: RollbackRequest, prepared_source: object
    ) -> RollbackEvidence: ...
    def resume_unchanged_predecessor(
        self, request: DeploymentRequest, prepared_source: object
    ) -> bool: ...
    def migrate_custom_web_unit(self, expected_hash: str) -> None: ...
    def install_web_candidate(self, candidate: Path) -> None: ...
    def install_tls_candidates(self, certificate: Path, private_key: Path) -> None: ...
    def install_release_packages(
        self, runtime: Path, application: Path, driver: Path | None = None
    ) -> None: ...
    def verify_installed_driver(self, request: DeploymentRequest) -> bool: ...
    def install_qualification_attestation(self, request: DeploymentRequest) -> None: ...
    def authenticated_preflight(self) -> None: ...
    def activate_complete_stack(self) -> None: ...
    def verify_live(self, request: DeploymentRequest) -> LiveEvidence: ...
    def restore_verified_rollback(self, rollback: RollbackEvidence) -> RollbackOutcome: ...
    def keep_stack_masked(self) -> None: ...
    def write_deployment_evidence(self, evidence: bytes) -> str: ...


@dataclass(frozen=True)
class SystemDeploymentConfig:
    artifact_source_commit_file: Path
    clean_source_root: Path
    main_rpm_verifier: Path
    main_rpm_contract: Path
    activation_script: Path
    activation_config: Path
    live_private_config: Path
    rpm_verify_policy: Path
    journal_policy: Path
    live_report_output: Path
    deployment_evidence_output: Path


def _load_sibling(
    name: str, filename: str, authorities: Mapping[Path, str]
):
    path = Path(__file__).resolve().with_name(filename)
    expected = authorities.get(path)
    if expected is None:
        raise DeploymentError("deployment helper lacks signed authority")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
        data = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            data.extend(chunk)
            if len(data) > 4 * 1024 * 1024:
                raise DeploymentError("deployment helper exceeded its bound")
    except OSError:
        raise DeploymentError("deployment helper is unavailable") from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != 0
        or details.st_mode & 0o022
        or hashlib.sha256(data).hexdigest() != expected
    ):
        raise DeploymentError("deployment helper authority drifted")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    module.__package__ = ""
    sys.modules[name] = module
    try:
        exec(compile(bytes(data), str(path), "exec"), module.__dict__)
    except Exception:
        sys.modules.pop(name, None)
        raise DeploymentError("deployment helper import failed") from None
    return module


def _validsig_authorized(status: str, policy: Mapping[str, object]) -> bool:
    bad_statuses = {
        "BADSIG",
        "ERRSIG",
        "EXPKEYSIG",
        "EXPSIG",
        "KEYEXPIRED",
        "NO_PUBKEY",
        "REVKEYSIG",
        "SIGEXPIRED",
    }
    allowed_statuses = {
        "GOODSIG",
        "KEY_CONSIDERED",
        "NEWSIG",
        "SIG_ID",
        "TRUST_FULLY",
        "TRUST_MARGINAL",
        "TRUST_NEVER",
        "TRUST_ULTIMATE",
        "TRUST_UNDEFINED",
        "VALIDSIG",
    }
    status_rows = [
        line.split()
        for line in status.splitlines()
        if line.startswith("[GNUPG:] ")
    ]
    if any(
        len(row) < 2
        or row[1] in bad_statuses
        or row[1] not in allowed_statuses
        for row in status_rows
    ):
        return False
    primary = policy.get("primary_fingerprint")
    subkey = policy.get("signing_subkey_fingerprint")
    if any(
        row[1] == "KEY_CONSIDERED"
        and (len(row) < 3 or row[2].upper() != primary)
        for row in status_rows
    ) or any(
        row[1] == "GOODSIG"
        and (len(row) < 3 or row[2].upper() != str(subkey)[-16:])
        for row in status_rows
    ):
        return False
    rows = [
        row for row in status_rows if row[1] == "VALIDSIG"
    ]
    return (
        len(rows) == 1
        and len(rows[0]) == 12
        and rows[0][2].upper() == subkey
        and rows[0][8] == "1"
        and rows[0][9] == "8"
        and rows[0][11].upper() == primary
    )


def _bootstrap_secure_file(path: Path) -> bool:
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


def _bootstrap_read(path: Path, maximum: int = 4 * 1024 * 1024) -> bytes:
    if not path.is_absolute():
        raise DeploymentError("bootstrap input is not absolute")
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != 0
            or details.st_mode & 0o022
        ):
            raise DeploymentError("bootstrap input is unsafe")
        data = bytearray()
        while chunk := os.read(descriptor, 1024 * 1024):
            data.extend(chunk)
            if len(data) > maximum:
                raise DeploymentError("bootstrap input exceeded its bound")
        return bytes(data)
    except OSError:
        raise DeploymentError("bootstrap input is unreadable") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _bootstrap_manifest(manifest: Path) -> tuple[dict[Path, str], bytes]:
    rows: dict[Path, str] = {}
    seen: set[str] = set()
    try:
        raw = _bootstrap_read(manifest)
        lines = raw.decode("ascii").splitlines()
        if not lines or not raw.endswith(b"\n") or b"\r" in raw:
            raise DeploymentError("artifact manifest is not canonical")
        ordered_paths: list[str] = []
        for line in lines:
            match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
            if match is None:
                raise DeploymentError("artifact manifest row is invalid")
            relative = match.group(2)
            relative_path = Path(relative)
            if (
                relative in seen
                or relative_path.is_absolute()
                or ".." in relative_path.parts
                or "\\" in relative
            ):
                raise DeploymentError("artifact manifest path is invalid")
            seen.add(relative)
            ordered_paths.append(relative)
            path = manifest.parent / relative_path
            digest = hashlib.sha256(
                _bootstrap_read(path, maximum=_BOOTSTRAP_MEMBER_MAX)
            ).hexdigest()
            if digest != match.group(1):
                raise DeploymentError("artifact manifest member drifted")
            rows[path.resolve()] = digest
        if ordered_paths != sorted(ordered_paths):
            raise DeploymentError("artifact manifest is not canonical")
    except (OSError, UnicodeError):
        raise DeploymentError("artifact manifest is unreadable") from None
    return rows, raw


def _bootstrap_run(argv: tuple[Path | str, ...]) -> subprocess.CompletedProcess[str]:
    tool = Path(argv[0])
    if not _bootstrap_secure_file(tool):
        raise DeploymentError("bootstrap tool is unsafe")
    try:
        result = subprocess.run(
            tuple(str(item) for item in argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
        )
    except (OSError, subprocess.SubprocessError):
        raise DeploymentError("bootstrap signature verification failed") from None
    if (
        result.returncode != 0
        or len(result.stdout) > 1024 * 1024
        or len(result.stderr) > 64 * 1024
    ):
        raise DeploymentError("bootstrap signature verification failed")
    return result


def _bootstrap_authorities(
    request: DeploymentRequest, config: SystemDeploymentConfig
) -> dict[Path, str]:
    application, application_manifest_bytes = _bootstrap_manifest(
        request.application_manifest
    )
    runtime, runtime_manifest_bytes = _bootstrap_manifest(
        request.runtime_manifest
    )
    try:
        policy_bytes = _bootstrap_read(request.app_runtime_signing_policy)
        contract_bytes = _bootstrap_read(config.main_rpm_contract)
        live_bytes = _bootstrap_read(config.live_private_config)
        policy = json.loads(
            policy_bytes.decode("utf-8"),
            object_pairs_hook=_duplicate_free_object,
        )
        contract = json.loads(
            contract_bytes.decode("utf-8"),
            object_pairs_hook=_duplicate_free_object,
        )
        live = json.loads(
            live_bytes.decode("utf-8"),
            object_pairs_hook=_duplicate_free_object,
        )
        if not all(isinstance(value, dict) for value in (policy, contract, live)):
            raise DeploymentError("bootstrap authority is invalid")
        public_key = Path(str(live["signing_public_key"]))
        public_key_bytes = _bootstrap_read(public_key)
        if (
            hashlib.sha256(policy_bytes).hexdigest()
            != contract.get("signing_policy_sha256")
            or hashlib.sha256(public_key_bytes).hexdigest()
            != contract.get("public_key_sha256")
        ):
            raise DeploymentError("bootstrap signing authority drifted")
        required_application = {
            Path(__file__).resolve(),
            Path(__file__).resolve().with_name("rollback-rhel9.py"),
            Path(__file__).resolve().with_name("deployment_artifacts.py"),
            Path(__file__).resolve().with_name("verify-deployment-rhel9.py"),
            request.application_rpm.resolve(),
            request.app_runtime_signing_policy.resolve(),
            config.main_rpm_verifier.resolve(),
            config.main_rpm_contract.resolve(),
            config.rpm_verify_policy.resolve(),
            config.journal_policy.resolve(),
            Path(str(live["driver_rpm_verify_policy"])).resolve(),
            Path(str(live["driver_digest_authority"])).resolve(),
        }
        if not required_application.issubset(application) or request.runtime_rpm.resolve() not in runtime:
            raise DeploymentError("bootstrap signed closure is incomplete")
        signature_bytes = (
            _bootstrap_read(request.application_manifest_signature),
            _bootstrap_read(request.runtime_manifest_signature),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / "gnupg"
            home.mkdir(mode=0o700)
            key_copy = root / "authority.asc"
            key_copy.write_bytes(public_key_bytes)
            key_copy.chmod(0o600)
            _bootstrap_run(
                (
                    _GPG,
                    "--no-options",
                    "--homedir",
                    home,
                    "--batch",
                    "--no-auto-key-retrieve",
                    "--import",
                    key_copy,
                )
            )
            for index, (signature_data, manifest_data) in enumerate(
                zip(
                    signature_bytes,
                    (application_manifest_bytes, runtime_manifest_bytes),
                    strict=True,
                )
            ):
                signature = root / f"manifest-{index}.asc"
                manifest = root / f"manifest-{index}.txt"
                signature.write_bytes(signature_data)
                manifest.write_bytes(manifest_data)
                signature.chmod(0o600)
                manifest.chmod(0o600)
                status = _bootstrap_run(
                    (
                        _GPG,
                        "--no-options",
                        "--homedir",
                        home,
                        "--batch",
                        "--no-auto-key-retrieve",
                        "--status-fd=1",
                        "--verify",
                        signature,
                        manifest,
                    )
                )
                if not _validsig_authorized(status.stdout, policy):
                    raise DeploymentError("bootstrap manifest signature is unauthorized")
    except (KeyError, OSError, UnicodeError, json.JSONDecodeError):
        raise DeploymentError("bootstrap authority is invalid") from None
    return application


class SystemDeploymentHost:
    """Concrete privileged adapter for the local, offline deployment CLI."""

    def __init__(
        self, config: SystemDeploymentConfig, authorities: Mapping[Path, str]
    ) -> None:
        self._config = config
        self._rollback = _load_sibling(
            "_lto_task9_rollback", "rollback-rhel9.py", authorities
        )
        self._live = _load_sibling(
            "_lto_task9_live", "verify-deployment-rhel9.py", authorities
        )
        live_config = self._live._system_config_from_file(config.live_private_config)
        self._live_host = self._live.SystemLiveHost(live_config)
        self._rollback_host = self._rollback.SystemRollbackHost()
        artifacts = _load_sibling("_lto_deployment_artifacts", "deployment_artifacts.py", authorities)
        self._artifact_registry = artifacts.DeploymentArtifactRegistry()
        self._rollback_host._artifact_registry = self._artifact_registry

    @staticmethod
    def _run(
        argv: tuple[str | Path, ...],
        *,
        accepted: tuple[int, ...] = (0,),
        activation_diagnostics: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = tuple(str(value) for value in argv)
        if not command or not Path(command[0]).is_absolute():
            raise DeploymentError("deployment command is not absolute")
        try:
            tool = Path(command[0]).stat(follow_symlinks=False)
        except OSError:
            raise DeploymentError("deployment tool is unavailable") from None
        if (
            not stat.S_ISREG(tool.st_mode)
            or tool.st_uid != 0
            or tool.st_mode & 0o022
        ):
            raise DeploymentError("deployment tool failed ownership checks")
        try:
            result = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
                env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/usr/sbin"},
            )
        except (OSError, subprocess.SubprocessError):
            raise DeploymentError("deployment command failed") from None
        if len(result.stdout) > 4 * 1024 * 1024 or len(result.stderr) > 64 * 1024:
            raise DeploymentError("deployment command output exceeded its bound")
        if result.returncode not in accepted:
            if activation_diagnostics:
                diagnostic = _ACTIVATION_DIAGNOSTIC.fullmatch(result.stderr)
                if diagnostic is not None and diagnostic.group(1) in _ACTIVATION_STAGES:
                    raise ActivationDeploymentError(
                        diagnostic.group(1),
                        cleanup_failed=diagnostic.group(2) is not None,
                    )
            raise DeploymentError("deployment command failed")
        return result

    @staticmethod
    def _secure_file(path: Path, modes: frozenset[int]) -> bool:
        try:
            details = path.stat(follow_symlinks=False)
        except OSError:
            return False
        return (
            path.is_absolute()
            and stat.S_ISREG(details.st_mode)
            and not path.is_symlink()
            and details.st_uid == 0
            and stat.S_IMODE(details.st_mode) in modes
        )

    @staticmethod
    def _manifest_ok(manifest: Path, required: Path) -> bool:
        if not manifest.is_absolute() or not required.is_absolute():
            return False
        root = manifest.parent
        seen: set[str] = set()
        required_seen = False
        try:
            raw = manifest.read_bytes()
            lines = raw.decode("ascii").splitlines()
            if not lines or not raw.endswith(b"\n") or b"\r" in raw:
                return False
            ordered_paths: list[str] = []
            for line in lines:
                match = re.fullmatch(r"([0-9a-f]{64})  ([^\r\n]+)", line)
                if match is None:
                    return False
                relative = match.group(2)
                if relative in seen or Path(relative).is_absolute() or ".." in Path(relative).parts:
                    return False
                seen.add(relative)
                ordered_paths.append(relative)
                path = root / relative
                if not path.is_file() or path.is_symlink() or _digest(path) != match.group(1):
                    return False
                required_seen = required_seen or path.resolve() == required.resolve()
            if ordered_paths != sorted(ordered_paths):
                return False
        except (OSError, UnicodeError):
            return False
        return required_seen

    def is_root(self) -> bool:
        return os.geteuid() == 0

    def _detached_manifests_authorized(
        self, request: DeploymentRequest, policy: Mapping[str, object]
    ) -> bool:
        key = self._live_host._config.signing_public_key
        pairs = (
            (request.application_manifest_signature, request.application_manifest),
            (request.runtime_manifest_signature, request.runtime_manifest),
        )
        if any(
            not self._secure_file(path, frozenset({0o600, 0o644}))
            for pair in pairs
            for path in pair
        ):
            return False
        try:
            with tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary) / "gnupg"
                home.mkdir(mode=0o700)
                self._run(
                    (
                        _GPG,
                        "--no-options",
                        "--homedir",
                        home,
                        "--batch",
                        "--no-auto-key-retrieve",
                        "--import",
                        key,
                    )
                )
                for signature, manifest in pairs:
                    verified = self._run(
                        (
                            _GPG,
                            "--no-options",
                            "--homedir",
                            home,
                            "--batch",
                            "--no-auto-key-retrieve",
                            "--status-fd=1",
                            "--verify",
                            signature,
                            manifest,
                        )
                    )
                    if not _validsig_authorized(verified.stdout, policy):
                        return False
        except (DeploymentError, OSError):
            return False
        return True

    def verify_release_artifacts(self, request: DeploymentRequest) -> ArtifactEvidence:
        source_commit = self._config.artifact_source_commit_file.read_text().strip()
        authorities_ok = all(
            self._secure_file(path, _RELEASE_AUTHORITY_MODES)
            for path in (
                self._config.artifact_source_commit_file,
                self._config.main_rpm_verifier,
                self._config.main_rpm_contract,
            )
        )
        manifests_ok = all(
            self._manifest_ok(request.application_manifest, authority)
            for authority in (
                request.application_rpm,
                self._config.rpm_verify_policy,
                self._config.journal_policy,
                self._config.main_rpm_contract,
                self._live_host._config.driver_rpm_verify_policy,
                self._live_host._config.driver_digest_authority,
            )
        ) and self._manifest_ok(request.runtime_manifest, request.runtime_rpm)
        verifier_ok = False
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "main-rpm.json"
            result = self._run(
                (
                    _PYTHON,
                    self._config.main_rpm_verifier,
                    "--rpm",
                    request.application_rpm,
                    "--source-root",
                    self._config.clean_source_root,
                    "--contract",
                    self._config.main_rpm_contract,
                    "--json-output",
                    report,
                ),
                accepted=(0, 2),
            )
            verifier_ok = result.returncode == 0 and report.is_file()
        signatures_ok = self._live_host._isolated_signatures_ok(
            (request.application_rpm, request.runtime_rpm)
        )
        try:
            contract = json.loads(
                self._config.main_rpm_contract.read_text(encoding="utf-8"),
                object_pairs_hook=_duplicate_free_object,
            )
            signing_policy_bound = (
                isinstance(contract, dict)
                and request.app_runtime_signing_policy.is_file()
                and _digest(request.app_runtime_signing_policy)
                == _digest(self._live_host._config.signing_policy)
                == contract.get("signing_policy_sha256")
                and _digest(self._live_host._config.signing_public_key)
                == contract.get("public_key_sha256")
            )
            manifests_signed = self._detached_manifests_authorized(
                request,
                json.loads(
                    request.app_runtime_signing_policy.read_text(encoding="utf-8"),
                    object_pairs_hook=_duplicate_free_object,
                ),
            )
        except (OSError, UnicodeError, json.JSONDecodeError, DeploymentError):
            signing_policy_bound = False
            manifests_signed = False
        evidence = ArtifactEvidence(
            verified=(
                authorities_ok
                and manifests_ok
                and verifier_ok
                and signatures_ok
                and signing_policy_bound
                and manifests_signed
            ),
            source_commit=source_commit,
            application_rpm_sha256=_digest(request.application_rpm),
            runtime_rpm_sha256=_digest(request.runtime_rpm),
            application_manifest_sha256=_digest(request.application_manifest),
            runtime_manifest_sha256=_digest(request.runtime_manifest),
            application_signed=signatures_ok,
            runtime_signed=signatures_ok,
        )
        self._qualification_manifest = (
            (request.application_manifest, evidence.application_manifest_sha256)
            if evidence.verified else None
        )
        return evidence

    def verify_driver_input(self, request: DeploymentRequest) -> bool:
        return (
            self._live_host._config.driver_rpm == request.driver_rpm
            and self._live_host._driver_artifact_ok(self._driver_request(request))
        )

    def _driver_request(self, request: DeploymentRequest):
        return self._live.VerifyDeploymentRequest(
            expected_nevras={
                "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
                "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
                "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
            },
            rpm_verify_policy=self._config.rpm_verify_policy,
            journal_policy=self._config.journal_policy,
            driver_input_contract=request.driver_input_contract,
            expected_driver_input_sha256=request.expected_driver_input_sha256,
            maintenance_started_at=request.maintenance_started_at,
            artifact_manifest_sha256=_digest(request.application_manifest),
            rollback_manifest_sha256="0" * 64,
        )

    def observe_admission(self, request: DeploymentRequest) -> AdmissionObservation:
        try:
            status = self._live_host._daemon_get("/api/v1/status")
            libraries = self._live_host._daemon_get("/api/v1/libraries")
            shares = self._live_host._daemon_get("/api/v1/network-shares")
            inventory = self._live_host._inventory(libraries, shares)
            failed = self._run(
                (_SYSTEMCTL, "--failed", "--plain", "--no-legend")
            ).stdout.strip()
            qualification = all(
                self._run(
                    (_SYSTEMCTL, "is-active", unit), accepted=(0, 3, 4)
                ).returncode != 0
                for unit in (
                    "lto-archiver-ltfs-qualification.service",
                    "lto-archiver-archive-runner-qualification.service",
                )
            )
            tape = self._run(
                (Path("/usr/bin/findmnt"), "--mountpoint", "/mnt/lto-archiver/tape"),
                accepted=(0, 1),
            ).returncode != 0
            no_process = True
            for process in Path("/proc").glob("[0-9]*/cmdline"):
                try:
                    commandline = process.read_bytes()
                    executable = os.readlink(process.parent / "exe")
                except FileNotFoundError:
                    continue
                except OSError:
                    no_process = False
                    continue
                if _is_active_ltfs_commandline(commandline, executable):
                    no_process = False
            priority = self._live_host._journal(request.maintenance_started_at)
            firewall = self._live_host._firewall()
            successor_health_url = self._live_host._config.https_health_url
            suffix = "/api/v1/health"
            expected_login_url = (
                successor_health_url[: -len(suffix)] + "/login"
                if successor_health_url.endswith(suffix)
                else ""
            )
            predecessor_probe = request.rollback_request.predecessor_web_probe
            if not isinstance(status, dict):
                raise DeploymentError("daemon admission is invalid")
            idle = _daemon_quiescent_for_deployment(status)
            broker_idle = status.get("broker_operation") is None
            return AdmissionObservation(
                daemon_idle=idle and status.get("accepting_mutations") is True,
                daemon_reconciled=inventory.reconciled,
                broker_idle=broker_idle,
                qualification_idle=qualification,
                no_ltfs_process=no_process,
                no_tape_mount=tape,
                no_unmanaged_share_mount=inventory.no_unmanaged_test_mount,
                no_failed_unit=not failed,
                no_priority_error=not priority,
                web_tls_firewall_ok=(
                    predecessor_probe.get("url") == expected_login_url
                    and self._live._legacy_https_login_ok(predecessor_probe)
                    and firewall.listener_exact
                    and firewall.lan_only
                    and not firewall.broad_port_open
                    and not firewall.broad_service_open
                ),
            )
        except Exception:
            return AdmissionObservation(*(False for _ in range(10)))

    def verify_rollback_preflight(self, request: RollbackRequest) -> bool:
        try:
            parent = request.bundle_dir.parent.resolve(strict=True)
            installed = self._rollback_host.installed_nevras()
            rpms = self._rollback_host.inspect_rollback_rpms(request.rollback_rpm_dir)
            self._rollback._validate_rpms(rpms, installed, request.rollback_rpm_dir)
            driver_contract = json.loads(self._rollback._validate_driver_contract(
                request.driver_input_contract, request.expected_driver_input_sha256,
            ))
            driver_rpm = next(row for row in rpms if row.target == "driver-evidence")
            if (
                driver_rpm.nevra != driver_contract["package_nevra"]
                or driver_rpm.sha256 != driver_contract["rpm_raw_sha256"]
                or driver_rpm.header_sha256 != driver_contract["rpm_header_sha256"]
                or driver_rpm.payload_sha256 != driver_contract["rpm_payload_sha256"]
                or not self._rollback_host.driver_package_state_matches(driver_contract)
            ):
                return False
            self._rollback._validate_driver_contract(
                request.candidate_driver_input_contract,
                request.expected_candidate_driver_input_sha256, candidate=True,
            )
            sources = self._rollback_host.snapshot_sources()
            self._rollback_host.verify_deployment_capacity(parent, sources, rpms)
            return (
                not request.bundle_dir.exists()
                and self._rollback_host.parent_is_secure(parent)
                and self._rollback_host.custom_web_unit_sha256()
                == request.expected_custom_web_unit_sha256
            )
        except Exception:
            return False

    def validate_predecessor_source(self, request: RollbackRequest) -> bool:
        try:
            return (
                dict(self._rollback_host.installed_nevras())
                == self._rollback._PREDECESSOR_NEVRAS
                and self._rollback_host._sqlite_check(
                    Path("/var/lib/lto-archiver/catalog.db"),
                    catalog=True,
                    catalog_schema=self._rollback._PREDECESSOR_CATALOG_SCHEMA,
                    deployment_quiescent=True,
                )
            )
        except Exception:
            return False

    def verify_tls_candidates(self, request: DeploymentRequest) -> bool:
        if not (
            self._secure_file(
                request.tls_certificate_candidate, frozenset({0o600, 0o644})
            )
            and self._secure_file(
                request.tls_private_key_candidate, frozenset({0o600, 0o640})
            )
        ):
            return False
        try:
            certificate_public_key = self._run(
                (
                    _OPENSSL,
                    "x509",
                    "-in",
                    request.tls_certificate_candidate,
                    "-pubkey",
                    "-noout",
                )
            ).stdout
            private_public_key = self._run(
                (
                    _OPENSSL,
                    "pkey",
                    "-in",
                    request.tls_private_key_candidate,
                    "-pubout",
                    "-passin",
                    "pass:",
                )
            ).stdout
        except DeploymentError:
            return False
        return bool(certificate_public_key) and hmac.compare_digest(
            certificate_public_key,
            private_public_key,
        )

    def stop_stack(self, units: tuple[str, ...]) -> None:
        self._rollback_host.mask_stop_and_prove_idle(units)

    def prepare_predecessor_recovery(self, request: RollbackRequest) -> object:
        return self._rollback_host.prepare_source_catalog_backup(
            request.bundle_dir.parent.resolve(strict=True)
        )

    def create_verified_rollback(
        self, request: RollbackRequest, prepared_source: object
    ) -> RollbackEvidence:
        self._rollback_host._deployment_firewall_zone = (
            self._live_host._config.firewall_zone
        )
        manifest = self._rollback.create_bundle(
            self._rollback.CreateBundleRequest(
                bundle_dir=request.bundle_dir,
                rollback_rpm_dir=request.rollback_rpm_dir,
                expected_custom_web_unit_sha256=request.expected_custom_web_unit_sha256,
                driver_input_contract=request.driver_input_contract,
                expected_driver_input_sha256=request.expected_driver_input_sha256,
                predecessor_web_probe=request.predecessor_web_probe,
                candidate_driver_input_contract=request.candidate_driver_input_contract,
                expected_candidate_driver_input_sha256=request.expected_candidate_driver_input_sha256,
            ),
            self._rollback_host,
            prepared_source,
        )
        self._rollback.verify_bundle(request.bundle_dir, self._rollback_host)
        return RollbackEvidence(
            request.bundle_dir,
            manifest.bundle_id,
            _digest(request.bundle_dir / "bundle-manifest.json"),
        )

    def verify_remaining_capacity(self, rollback: RollbackEvidence) -> bool:
        try:
            path = rollback.bundle_dir / "bundle-manifest.json"
            if _digest(path) != rollback.manifest_sha256:
                return False
            manifest = self._rollback.verify_bundle(rollback.bundle_dir, self._rollback_host)
            if manifest.bundle_id != rollback.bundle_id or _digest(path) != rollback.manifest_sha256:
                return False
            self._rollback_host.verify_restore_capacity(rollback.bundle_dir, manifest)
            return True
        except Exception:
            return False

    def register_rollback_artifact(self, rollback: RollbackEvidence) -> None:
        def verify(path: Path) -> None:
            # Registry holds EX: use the internal verifier, without nested SH.
            manifest = self._rollback._verify_bundle(path, self._rollback_host, require_predeploy_state=True)
            if manifest.bundle_id != rollback.bundle_id:
                raise DeploymentError("registered rollback identity differs")

        self._artifact_registry.register_verified_bundle(
            rollback.bundle_dir, rollback.manifest_sha256, verify_bundle=verify,
        )

    def rollback_artifact_lease(self, rollback: RollbackEvidence) -> AbstractContextManager:
        return self._rollback_host.artifact_lease(rollback.bundle_dir)

    def finalize_rollback_artifacts(self, rollback: RollbackEvidence, evidence_hash: str) -> Mapping[str, object]:
        def verify(path: Path) -> None:
            # Successful installation is now the candidate, not the predecessor.
            manifest = self._rollback._verify_bundle(path, self._rollback_host, require_predeploy_state=False)
            if manifest.bundle_id != rollback.bundle_id:
                raise DeploymentError("promoted rollback identity differs")

        return self._artifact_registry.promote_after_success(
            rollback.bundle_dir, evidence_path=self._config.deployment_evidence_output,
            evidence_sha256=evidence_hash, verify_bundle=verify,
            prove_prunable=self._rollback_host.prove_artifact_prunable,
        )

    def resume_unchanged_predecessor(
        self, request: DeploymentRequest, prepared_source: object
    ) -> bool:
        try:
            enablement = getattr(self._rollback_host, "_pre_mask_enablement", None)
            if not isinstance(enablement, dict):
                return False
            # This binding describes stopped catalog bytes. Startup may perform
            # normal housekeeping, so prove it before admitting service writers.
            if not self._rollback_host.validate_prepared_source(prepared_source):
                return False
            self._rollback_host.activate_old_stack(
                types.SimpleNamespace(unit_enablement=dict(enablement))
            )
            return self.validate_predecessor_source(
                request.rollback_request
            ) and self._rollback_host.all_units_active(
                STOP_UNITS
            ) and _admitted(self.observe_admission(request))
        except Exception:
            return False

    def migrate_custom_web_unit(self, expected_hash: str) -> None:
        source = Path("/etc/systemd/system/lto-archiver-web.service")
        target = source.with_name(source.name + ".lto-archiver-pre-task9")
        if expected_hash == "ABSENT":
            if source.exists():
                raise DeploymentError("unexpected custom WebUI unit")
            return
        if (
            not self._secure_file(source, frozenset({0o644}))
            or _digest(source) != expected_hash
            or target.exists()
        ):
            raise DeploymentError("custom WebUI unit migration is not authorized")
        os.link(source, target, follow_symlinks=False)
        source.unlink()
        directory = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    @staticmethod
    def _atomic_install(source: Path, target: Path, mode: int, gid: int) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(f".{target.name}.task9-{os.getpid()}")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        source_descriptor: int | None = None
        copied = False
        try:
            source_descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            while chunk := os.read(source_descriptor, 1024 * 1024):
                os.write(descriptor, chunk)
            os.fchmod(descriptor, mode)
            os.fchown(descriptor, 0, gid)
            os.fsync(descriptor)
            copied = True
        finally:
            if source_descriptor is not None:
                os.close(source_descriptor)
            os.close(descriptor)
            if not copied:
                temporary.unlink(missing_ok=True)
        try:
            os.replace(temporary, target)
            directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    def install_web_candidate(self, candidate: Path) -> None:
        gid = grp.getgrnam("lto-web").gr_gid
        self._atomic_install(candidate, Path("/etc/lto-archiver/web.toml"), 0o640, gid)

    def install_tls_candidates(self, certificate: Path, private_key: Path) -> None:
        gid = grp.getgrnam("lto-web").gr_gid
        directory = Path("/etc/lto-archiver/tls")
        directory.mkdir(parents=True, exist_ok=True)
        details = directory.stat(follow_symlinks=False)
        if not stat.S_ISDIR(details.st_mode) or directory.is_symlink() or details.st_uid != 0:
            raise DeploymentError("TLS target directory is unsafe")
        os.chown(directory, 0, gid)
        os.chmod(directory, 0o750)
        self._atomic_install(certificate, directory / "server.crt", 0o644, 0)
        self._atomic_install(private_key, directory / "server.key", 0o640, gid)

    def install_release_packages(
        self, runtime: Path, application: Path, driver: Path | None = None
    ) -> None:
        packages = (runtime, application, *((driver,) if driver is not None else ()))
        if len(set(packages)) != len(packages) or not all(
            path.is_absolute()
            and path.suffix == ".rpm"
            and path.is_file()
            and not path.is_symlink()
            for path in packages
        ):
            raise DeploymentError("release RPM paths are not a closed local set")
        self._run(
            (
                _DNF,
                "--disablerepo=*",
                "--setopt=install_weak_deps=False",
                "--assumeyes",
                "install",
                *packages,
            )
        )

    def verify_installed_driver(self, request: DeploymentRequest) -> bool:
        artifact_ok, installed_ok = self._live_host._driver_ok(self._driver_request(request))
        verified = artifact_ok and installed_ok
        self._qualification_driver = (
            (request.driver_rpm, request.driver_input_contract,
             request.expected_driver_input_sha256) if verified else None
        )
        return verified

    def install_qualification_attestation(self, request: DeploymentRequest) -> None:
        manifest_pin = getattr(self, "_qualification_manifest", None)
        driver_pin = getattr(self, "_qualification_driver", None)
        if (
            manifest_pin != (request.application_manifest, _digest(request.application_manifest))
            or driver_pin is None
            or driver_pin != (request.driver_rpm, request.driver_input_contract,
                              request.expected_driver_input_sha256)
        ):
            raise DeploymentError("qualification inputs were not verified")
        rows, _raw = _bootstrap_manifest(request.application_manifest)
        source = request.application_manifest.parent / "SOURCES/lto-archiver-0.11.27.tar.gz"
        if source.resolve() not in rows:
            raise DeploymentError("qualification application Source0 is not authenticated")
        contract = self._live.load_driver_input_contract(
            request.driver_input_contract,
            expected_sha256=request.expected_driver_input_sha256,
        )
        if _digest(request.driver_rpm) != contract.rpm_raw_sha256:
            raise DeploymentError("qualification driver RPM changed")
        provenance_raw = _bootstrap_read(
            self._live_host._config.driver_source_provenance_evidence
        )
        if hashlib.sha256(provenance_raw).hexdigest() != contract.source_provenance_evidence_sha256:
            raise DeploymentError("qualification driver provenance changed")
        try:
            provenance = json.loads(provenance_raw, object_pairs_hook=_duplicate_free_object)
            driver_source = provenance["source_archive_sha256"]
        except (ValueError, KeyError, TypeError):
            raise DeploymentError("qualification driver Source0 is invalid") from None
        if not isinstance(driver_source, str) or not _HEX64.fullmatch(driver_source):
            raise DeploymentError("qualification driver Source0 digest is invalid")
        result = self._run((
            Path("/usr/bin/rpm"), "-qp", "--qf",
            "[%{FILENAMES}\\t%{FILEDIGESTS}\\t%{FILEMODES:octal}\\t%{FILEUSERNAME}\\t%{FILEGROUPNAME}\\n]",
            request.driver_rpm,
        ))
        if result.stderr or _digest(request.driver_rpm) != contract.rpm_raw_sha256:
            raise DeploymentError("qualification RPM metadata is not bound")
        tools = _qualification_driver_tools(result.stdout)
        target = _QUALIFICATION_ATTESTATION
        old_raw = _qualification_file(target, mode=0o400, gid=0)
        try:
            old = json.loads(old_raw, object_pairs_hook=_duplicate_free_object)
        except ValueError:
            raise DeploymentError("qualification existing authority is invalid") from None
        if (
            not isinstance(old, dict)
            or set(old) != {"schema", "linux_tree_sha256", "ltfs_tree_sha256",
                            "ltfs_rpm_sha256", "tool_sha256"}
            or type(old.get("schema")) is not int
            or old.get("schema") != 2 or _canonical(old) != old_raw
            or not isinstance(old.get("tool_sha256"), dict)
            or set(old["tool_sha256"]) != set(_QUALIFICATION_TOOLS)
            or any(not isinstance(value, str) or not _HEX64.fullmatch(value)
                   for value in (*old["tool_sha256"].values(), old["linux_tree_sha256"],
                                 old["ltfs_tree_sha256"], old["ltfs_rpm_sha256"]))
        ):
            raise DeploymentError("qualification existing authority is not closed")
        tools.update({name: old["tool_sha256"][name] for name in ("fusermount", "mt")})
        for name, path in _QUALIFICATION_TOOLS.items():
            _qualification_file(
                path, mode=0o4755 if name == "fusermount" else 0o750 if name == "mkltfs" else 0o755,
                gid=grp.getgrnam("lto-admin").gr_gid if name == "mkltfs" else 0,
                expected=tools[name],
            )
        authority = _canonical({
            "schema": 2, "linux_tree_sha256": rows[source.resolve()],
            "ltfs_tree_sha256": driver_source,
            "ltfs_rpm_sha256": contract.rpm_raw_sha256, "tool_sha256": tools,
        })
        parent = target.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
            raise DeploymentError("qualification publication directory is unsafe")
        with tempfile.TemporaryDirectory(prefix=".qualification-", dir=target.parent) as temporary:
            staged = Path(temporary) / "authority.json"
            with staged.open("xb") as stream:
                stream.write(authority)
                stream.flush()
                os.fsync(stream.fileno())
            staged.chmod(0o400)
            if _qualification_file(target, mode=0o400, gid=0) != old_raw:
                raise DeploymentError("qualification authority changed before publication")
            self._atomic_install(staged, target, 0o400, 0)
        if _qualification_file(target, mode=0o400, gid=0) != authority:
            raise DeploymentError("qualification authority readback failed")

    def authenticated_preflight(self) -> None:
        installed = self._rollback_host.installed_nevras()
        expected = {
            "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
            "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
            "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
        }
        if dict(installed) != expected:
            raise DeploymentError("installed deployment closure is not exact")

    def activate_complete_stack(self) -> None:
        self._run((_SYSTEMCTL, "unmask", "--runtime", *STOP_UNITS))
        self._run(
            (
                _PYTHON,
                self._config.activation_script,
                "--config",
                self._config.activation_config,
                "--web-config",
                "/etc/lto-archiver/web.toml",
            ),
            activation_diagnostics=True,
        )
        deadline = time.monotonic() + _DAEMON_READINESS_TIMEOUT_SECONDS
        while True:
            try:
                health = self._live_host._daemon_get(
                    "/api/v1/health", deadline=deadline
                )
                if self._live._healthy_api_v1(health):
                    return
            except self._live.ContractError:
                pass
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeploymentError("daemon readiness timed out")
            time.sleep(min(1.0, remaining))

    def verify_live(self, request: DeploymentRequest) -> LiveEvidence:
        rollback_hash = _digest(request.rollback_request.bundle_dir / "bundle-manifest.json")
        verify_request = self._live.VerifyDeploymentRequest(
            expected_nevras={
                "lto-archiver": "lto-archiver-0.11.27-144.el9.noarch",
                "lto-archiver-python-runtime": "lto-archiver-python-runtime-0.11.27-3.el9.x86_64",
                "lto-ltfs": "lto-ltfs-0.1.0-21.el9.x86_64",
            },
            rpm_verify_policy=self._config.rpm_verify_policy,
            journal_policy=self._config.journal_policy,
            driver_input_contract=request.driver_input_contract,
            expected_driver_input_sha256=request.expected_driver_input_sha256,
            maintenance_started_at=request.maintenance_started_at,
            artifact_manifest_sha256=_digest(request.application_manifest),
            rollback_manifest_sha256=rollback_hash,
        )
        report = self._live.verify_deployment(verify_request, self._live_host)
        data = report.to_json().encode()
        self._live._publish_report(self._config.live_report_output, data)
        return LiveEvidence(
            "verified" if report.status == "green" else "failed", hashlib.sha256(data).hexdigest()
        )

    def restore_verified_rollback(self, rollback: RollbackEvidence) -> RollbackOutcome:
        result = self._rollback.restore_bundle(rollback.bundle_dir, self._rollback_host)
        return RollbackOutcome(result.status, result.status == "restored")

    def keep_stack_masked(self) -> None:
        self._rollback_host.keep_runtime_masked()

    def write_deployment_evidence(self, evidence: bytes) -> str:
        self._live._publish_report(self._config.deployment_evidence_output, evidence)
        return hashlib.sha256(evidence).hexdigest()


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _empty_result(status: str, request: DeploymentRequest, detail: str) -> DeploymentResult:
    return DeploymentResult(
        status=status,
        repository_commit=request.repository_commit,
        application_rpm_sha256="",
        runtime_rpm_sha256="",
        application_manifest_sha256="",
        runtime_manifest_sha256="",
        driver_input_sha256=request.expected_driver_input_sha256,
        rollback_manifest_sha256="",
        live_report_sha256="",
        evidence_sha256="",
        detail=detail,
    )


def _failure_detail(error: Exception) -> str:
    if isinstance(error, ActivationDeploymentError):
        return str(error)
    return type(error).__name__


def _bounded_error_class(error: BaseException) -> str:
    name = type(error).__name__
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,47}", name) else "Exception"


def _path_inputs_are_closed(request: DeploymentRequest) -> bool:
    predecessor_ca = Path(
        str(request.rollback_request.predecessor_web_probe.get("ca_certificate", ""))
    )
    files = (
        request.application_rpm,
        request.runtime_rpm,
        request.driver_rpm,
        request.application_manifest,
        request.application_manifest_signature,
        request.runtime_manifest,
        request.runtime_manifest_signature,
        request.app_runtime_signing_policy,
        request.driver_input_contract,
        request.rollback_request.driver_input_contract,
        request.rollback_request.candidate_driver_input_contract,
        request.web_config_candidate,
        request.tls_certificate_candidate,
        request.tls_private_key_candidate,
        predecessor_ca,
    )
    return all(
        isinstance(path, Path)
        and path.is_absolute()
        and path.is_file()
        and not path.is_symlink()
        for path in files
    ) and request.rollback_request.bundle_dir.is_absolute()


def _artifacts_match(request: DeploymentRequest, evidence: ArtifactEvidence) -> bool:
    return (
        evidence.verified
        and evidence.source_commit == request.repository_commit
        and evidence.application_signed
        and evidence.runtime_signed
        and evidence.application_rpm_sha256 == _digest(request.application_rpm)
        and evidence.runtime_rpm_sha256 == _digest(request.runtime_rpm)
        and evidence.application_manifest_sha256 == _digest(request.application_manifest)
        and evidence.runtime_manifest_sha256 == _digest(request.runtime_manifest)
        and all(
            _HEX64.fullmatch(value)
            for value in (
                evidence.application_rpm_sha256,
                evidence.runtime_rpm_sha256,
                evidence.application_manifest_sha256,
                evidence.runtime_manifest_sha256,
            )
        )
    )


def _admitted(observation: AdmissionObservation) -> bool:
    return all(asdict(observation).values())


def _success_evidence(
    request: DeploymentRequest,
    artifacts: ArtifactEvidence,
    rollback: RollbackEvidence,
    live: LiveEvidence,
) -> bytes:
    value = {
        "application_manifest_sha256": artifacts.application_manifest_sha256,
        "application_rpm_sha256": artifacts.application_rpm_sha256,
        "driver_input_sha256": request.expected_driver_input_sha256,
        "live_report_sha256": live.report_sha256,
        "repository_commit": request.repository_commit,
        "rollback_manifest_sha256": rollback.manifest_sha256,
        "runtime_manifest_sha256": artifacts.runtime_manifest_sha256,
        "runtime_rpm_sha256": artifacts.runtime_rpm_sha256,
        "schema": 1,
        "status": "deployed",
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def deploy(request: DeploymentRequest, host: DeploymentHost) -> DeploymentResult:
    """Run preflight, a recoverable mutation, activation, and the live gate."""
    try:
        if not host.is_root():
            raise DeploymentError("deployment requires root")
        if (
            not _HEX40.fullmatch(request.repository_commit)
            or request.repository_commit != request.deployment_commit
            or not _HEX64.fullmatch(request.expected_driver_input_sha256)
            or not _path_inputs_are_closed(request)
            or _digest(request.driver_input_contract) != request.expected_driver_input_sha256
            or request.rollback_request.candidate_driver_input_contract
            != request.driver_input_contract
            or request.rollback_request.expected_candidate_driver_input_sha256
            != request.expected_driver_input_sha256
            or request.rollback_request.driver_input_contract == request.driver_input_contract
            or not _HEX64.fullmatch(request.rollback_request.expected_driver_input_sha256)
            or _digest(request.rollback_request.driver_input_contract)
            != request.rollback_request.expected_driver_input_sha256
            or set(request.rollback_request.predecessor_web_probe)
            != {"ca_certificate", "url"}
            or _digest(
                Path(request.rollback_request.predecessor_web_probe["ca_certificate"])
            )
            != request.expected_tls_certificate_sha256
            or not _HEX64.fullmatch(request.expected_tls_certificate_sha256)
            or not _HEX64.fullmatch(request.expected_tls_private_key_sha256)
            or not _HEX64.fullmatch(request.expected_web_config_sha256)
            or _digest(request.web_config_candidate)
            != request.expected_web_config_sha256
            or _digest(request.tls_certificate_candidate)
            != request.expected_tls_certificate_sha256
            or _digest(request.tls_private_key_candidate)
            != request.expected_tls_private_key_sha256
        ):
            raise DeploymentError("deployment input binding is invalid")
        artifacts = host.verify_release_artifacts(request)
        if not _artifacts_match(request, artifacts):
            raise DeploymentError("release artifact verification failed")
        if not host.verify_driver_input(request):
            raise DeploymentError("driver input verification failed")
        if not _admitted(host.observe_admission(request)):
            raise DeploymentError("pre-mutation admission failed")
        if not host.verify_rollback_preflight(request.rollback_request):
            raise DeploymentError("rollback closure or capacity failed")
        if not host.validate_predecessor_source(request.rollback_request):
            raise DeploymentError("predecessor package or schema validation failed")
        if not host.verify_tls_candidates(request):
            raise DeploymentError("TLS candidate verification failed")
    except Exception as error:
        return _empty_result("refused", request, type(error).__name__)

    rollback: RollbackEvidence | None = None
    prepared_source: object | None = None
    mutation_started = False
    rollback_use = ExitStack()
    phase = "stop_stack"
    try:
        host.stop_stack(STOP_UNITS)
        phase = "prepare_source"
        prepared_source = host.prepare_predecessor_recovery(
            request.rollback_request
        )
        phase = "validate_source"
        if not host.validate_predecessor_source(request.rollback_request):
            raise DeploymentError("stopped predecessor source drifted")
        phase = "create_rollback"
        rollback = host.create_verified_rollback(
            request.rollback_request, prepared_source
        )
        if not _HEX64.fullmatch(rollback.manifest_sha256):
            raise DeploymentError("rollback manifest binding is invalid")
        phase = "register_rollback"
        host.register_rollback_artifact(rollback)
        phase = "lease_rollback"
        rollback_use.enter_context(host.rollback_artifact_lease(rollback))
        phase = "remaining_capacity"
        if not host.verify_remaining_capacity(rollback):
            raise DeploymentError("remaining rollback capacity or topology failed")
        mutation_started = True
        host.migrate_custom_web_unit(
            request.rollback_request.expected_custom_web_unit_sha256
        )
        host.install_web_candidate(request.web_config_candidate)
        host.install_tls_candidates(
            request.tls_certificate_candidate, request.tls_private_key_candidate
        )
        host.install_release_packages(request.runtime_rpm, request.application_rpm, request.driver_rpm)
        if not host.verify_installed_driver(request):
            raise DeploymentError("installed candidate driver verification failed")
        host.install_qualification_attestation(request)
        host.authenticated_preflight()
        host.activate_complete_stack()
        live = host.verify_live(request)
        if live.status != "verified" or not _HEX64.fullmatch(live.report_sha256):
            raise DeploymentError("new live gate failed")
        evidence_hash = host.write_deployment_evidence(
            _success_evidence(request, artifacts, rollback, live)
        )
        if not _HEX64.fullmatch(evidence_hash):
            raise DeploymentError("deployment evidence publication failed")
        try:
            # EX promotion must not run under our SH use/restore lease. Nothing
            # after durable success can request rollback of the healthy release.
            rollback_use.close()
            retention = host.finalize_rollback_artifacts(rollback, evidence_hash)
            if not isinstance(retention, Mapping) or retention.get("status") not in {"promoted", "refused"}:
                raise DeploymentError("invalid retention outcome")
        except Exception:
            retention = {"status": "refused", "pruned": [], "deferred": [], "error": "artifact_retention_failed"}
        return DeploymentResult(
            status="deployed",
            repository_commit=request.repository_commit,
            application_rpm_sha256=artifacts.application_rpm_sha256,
            runtime_rpm_sha256=artifacts.runtime_rpm_sha256,
            application_manifest_sha256=artifacts.application_manifest_sha256,
            runtime_manifest_sha256=artifacts.runtime_manifest_sha256,
            driver_input_sha256=request.expected_driver_input_sha256,
            rollback_manifest_sha256=rollback.manifest_sha256,
            live_report_sha256=live.report_sha256,
            evidence_sha256=evidence_hash,
            detail="verified deployment",
            retention=retention,
        )
    except Exception as error:
        primary_detail = _failure_detail(error)
        if not mutation_started:
            try:
                resumed = (
                    prepared_source is not None
                    and host.resume_unchanged_predecessor(
                        request, prepared_source
                    )
                )
            except Exception:
                resumed = False
            if resumed:
                return _empty_result("refused", request, primary_detail)
            host.keep_stack_masked()
            detail = f"phase={phase} error={_bounded_error_class(error)}"
            if error.__cause__ is not None:
                detail += f" cause={_bounded_error_class(error.__cause__)}"
            return _empty_result(
                "blocked", request, f"{detail}; rollback bundle unavailable"
            )
        rollback_detail = "health_gate_failed"
        try:
            outcome = host.restore_verified_rollback(rollback)
        except Exception:
            outcome = RollbackOutcome("blocked", False)
            rollback_detail = "failed"
        if outcome.status == "restored" and outcome.old_health_verified:
            result = _empty_result("rolled_back", request, primary_detail)
            return DeploymentResult(
                **{
                    **asdict(result),
                    "rollback_manifest_sha256": rollback.manifest_sha256,
                }
            )
        host.keep_stack_masked()
        result = _empty_result(
            "blocked",
            request,
            f"{primary_detail}; rollback={rollback_detail}",
        )
        return DeploymentResult(
            **{
                **asdict(result),
                "rollback_manifest_sha256": rollback.manifest_sha256,
            }
        )
    finally:
        rollback_use.close()


def _duplicate_free_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise DeploymentError("duplicate JSON key")
        result[key] = value
    return result


def _load_json(path: Path) -> tuple[dict[str, object], bytes]:
    if not path.is_absolute() or not path.is_file():
        raise DeploymentError("deployment JSON path is invalid")
    try:
        raw = path.read_bytes()
        value = json.loads(raw.decode(), object_pairs_hook=_duplicate_free_object)
    except (OSError, UnicodeError, json.JSONDecodeError, DeploymentError):
        raise DeploymentError("deployment JSON is invalid") from None
    if not isinstance(value, dict):
        raise DeploymentError("deployment JSON must be an object")
    return value, raw


def _canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _deployment_request_from_file(path: Path) -> DeploymentRequest:
    value, raw = _load_json(path)
    keys = {
        "app_runtime_signing_policy",
        "application_manifest",
        "application_manifest_signature",
        "application_rpm",
        "deployment_commit",
        "driver_input_contract",
        "driver_rpm",
        "expected_driver_input_sha256",
        "expected_tls_certificate_sha256",
        "expected_tls_private_key_sha256",
        "expected_web_config_sha256",
        "maintenance_started_at",
        "repository_commit",
        "rollback_request",
        "runtime_manifest",
        "runtime_manifest_signature",
        "runtime_rpm",
        "schema",
        "tls_certificate_candidate",
        "tls_private_key_candidate",
        "web_config_candidate",
    }
    if set(value) != keys or type(value.get("schema")) is not int or value.get("schema") != 2 or raw != _canonical(value):
        raise DeploymentError("deployment request is not canonical and closed")
    rollback = value.get("rollback_request")
    rollback_keys = {
        "candidate_driver_input_contract",
        "expected_candidate_driver_input_sha256",
        "bundle_dir",
        "driver_input_contract",
        "expected_custom_web_unit_sha256",
        "expected_driver_input_sha256",
        "predecessor_web_probe",
        "rollback_rpm_dir",
    }
    if not isinstance(rollback, dict) or set(rollback) != rollback_keys:
        raise DeploymentError("rollback request is not closed")
    predecessor_web_probe = rollback.get("predecessor_web_probe")
    if (
        not isinstance(predecessor_web_probe, dict)
        or set(predecessor_web_probe) != {"ca_certificate", "url"}
        or not all(
            isinstance(item, str) for item in predecessor_web_probe.values()
        )
    ):
        raise DeploymentError("predecessor Web probe is not closed")
    try:
        rollback_request = RollbackRequest(
            bundle_dir=Path(str(rollback["bundle_dir"])),
            rollback_rpm_dir=Path(str(rollback["rollback_rpm_dir"])),
            expected_custom_web_unit_sha256=str(
                rollback["expected_custom_web_unit_sha256"]
            ),
            driver_input_contract=Path(str(rollback["driver_input_contract"])),
            expected_driver_input_sha256=str(
                rollback["expected_driver_input_sha256"]
            ),
            predecessor_web_probe=dict(predecessor_web_probe),
            candidate_driver_input_contract=Path(str(rollback["candidate_driver_input_contract"])),
            expected_candidate_driver_input_sha256=str(rollback["expected_candidate_driver_input_sha256"]),
        )
        return DeploymentRequest(
            repository_commit=str(value["repository_commit"]),
            deployment_commit=str(value["deployment_commit"]),
            application_rpm=Path(str(value["application_rpm"])),
            runtime_rpm=Path(str(value["runtime_rpm"])),
            driver_rpm=Path(str(value["driver_rpm"])),
            application_manifest=Path(str(value["application_manifest"])),
            application_manifest_signature=Path(
                str(value["application_manifest_signature"])
            ),
            runtime_manifest=Path(str(value["runtime_manifest"])),
            runtime_manifest_signature=Path(
                str(value["runtime_manifest_signature"])
            ),
            app_runtime_signing_policy=Path(
                str(value["app_runtime_signing_policy"])
            ),
            driver_input_contract=Path(str(value["driver_input_contract"])),
            expected_driver_input_sha256=str(
                value["expected_driver_input_sha256"]
            ),
            rollback_request=rollback_request,
            web_config_candidate=Path(str(value["web_config_candidate"])),
            expected_web_config_sha256=str(value["expected_web_config_sha256"]),
            tls_certificate_candidate=Path(
                str(value["tls_certificate_candidate"])
            ),
            tls_private_key_candidate=Path(
                str(value["tls_private_key_candidate"])
            ),
            expected_tls_certificate_sha256=str(
                value["expected_tls_certificate_sha256"]
            ),
            expected_tls_private_key_sha256=str(
                value["expected_tls_private_key_sha256"]
            ),
            maintenance_started_at=str(value["maintenance_started_at"]),
        )
    except (KeyError, TypeError, ValueError):
        raise DeploymentError("deployment request field is invalid") from None


def _system_config_from_file(path: Path) -> SystemDeploymentConfig:
    value, _raw = _load_json(path)
    keys = {
        "activation_config",
        "activation_script",
        "artifact_source_commit_file",
        "clean_source_root",
        "deployment_evidence_output",
        "journal_policy",
        "live_private_config",
        "live_report_output",
        "main_rpm_contract",
        "main_rpm_verifier",
        "rpm_verify_policy",
        "schema",
    }
    if set(value) != keys or value.get("schema") != 1:
        raise DeploymentError("deployment host config is not closed")
    paths = {key: Path(str(value[key])) for key in keys - {"schema"}}
    if any(not item.is_absolute() for item in paths.values()):
        raise DeploymentError("deployment host config path is not absolute")
    return SystemDeploymentConfig(**paths)


def _publish_cli_result(path: Path, result: DeploymentResult) -> None:
    if not path.is_absolute() or path.exists():
        raise DeploymentError("deployment result path must be absolute and new")
    data = _canonical(asdict(result))
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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--host-config", type=Path, required=True)
    parser.add_argument("--json-output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        request = _deployment_request_from_file(arguments.request)
        config = _system_config_from_file(arguments.host_config)
        authorities = _bootstrap_authorities(request, config)
        result = deploy(request, SystemDeploymentHost(config, authorities))
        _publish_cli_result(arguments.json_output, result)
        return 0 if result.status == "deployed" else 2
    except (DeploymentError, OSError, ValueError):
        print("deployment failed: closed host validation error", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
