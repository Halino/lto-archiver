"""Inspect and validate the security-sensitive main RPM release contract."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PRIVATE_RUNTIME_ROOT = "/usr/lib64/lto-archiver/python-runtime/3.11/site-packages"
GLOBAL_SITE_ROOT = "/usr/lib/python3.11/site-packages/"
APPLICATION_DIST_INFO = "lto_archiver-0.11.28.dist-info"
DEVICE_RELABELER = "/usr/libexec/lto-archiver/relabel-device-aliases.py"
HISTORICAL_RUNNER_NAMES = frozenset(
    {"deploy-rhel9.py", "rollback-rhel9.py", "verify-deployment-rhel9.py"}
)
HISTORICAL_RUNNER_PATHS = frozenset(
    f"/usr/libexec/lto-archiver/{name}" for name in HISTORICAL_RUNNER_NAMES
)
WEB_FORMS_MACRO = (
    "/usr/lib/python3.11/site-packages/ltobackup/web/templates/macros/forms.html"
)
SHARE_ASSET_PATHS = {
    "lto-archiver-share-broker.service": (
        "/usr/lib/systemd/system/lto-archiver-share-broker.service"
    ),
    "lto-archiver-share-broker.socket": (
        "/usr/lib/systemd/system/lto-archiver-share-broker.socket"
    ),
    "lto-archiver.tmpfiles": "/usr/lib/tmpfiles.d/lto-archiver.conf",
}
REQUIRED_SHARE_PAYLOAD_METADATA = {
    "/usr/lib/systemd/system/lto-archiver-share-broker.service": (
        "-rw-r--r--",
        "root",
        "root",
    ),
    "/usr/lib/systemd/system/lto-archiver-share-broker.socket": (
        "-rw-r--r--",
        "root",
        "root",
    ),
    "/usr/lib/tmpfiles.d/lto-archiver.conf": ("-rw-r--r--", "root", "root"),
    "/etc/lto-archiver/share-credentials": ("drwx------", "root", "root"),
}
REQUIRED_LOG_READER_PAYLOAD_METADATA = {
    "/usr/lib/systemd/system/lto-archiver-log-reader.service": (
        "-rw-r--r--",
        "root",
        "root",
    ),
    "/usr/lib/systemd/system/lto-archiver-log-reader.socket": (
        "-rw-r--r--",
        "root",
        "root",
    ),
}
LAUNCHER_CONTEXTS = {
    "lto-archiver-admin": "lto_archiver_exec_t",
    "lto-archiver-command-broker": "lto_archiver_broker_exec_t",
    "lto-archiver-share-broker": "lto_archiver_share_broker_exec_t",
    "lto-archiver-log-reader": "lto_archiver_log_reader_exec_t",
    "lto-archiverd": "lto_archiver_exec_t",
    "lto-archiver-migrate": "lto_archiver_exec_t",
    "lto-archiver-qualify-archive-runner": "lto_archiver_exec_t",
    "lto-archiver-qualify-ltfs": "lto_archiver_exec_t",
    "lto-archiver-web": "lto_archiver_web_exec_t",
}
RUNTIME_REQUIREMENT_TOKEN = re.compile(
    r"(?<![A-Za-z0-9_.+-])lto-archiver-python-runtime(?![A-Za-z0-9_.+-])"
)
LTFS_REQUIREMENT_TOKEN = re.compile(r"(?<![A-Za-z0-9_.+-])lto-ltfs(?![A-Za-z0-9_.+-])")
RUNTIME_CONTEXTS = {
    "/var/lib/lto-archiver-share-broker(/.*)?": (
        "lto_archiver_share_broker_state_t"
    ),
    "/etc/lto-archiver/share-credentials(/.*)?": (
        "lto_archiver_share_credential_t"
    ),
    "/mnt/lto-archiver/sources(/.*)?": "lto_archiver_share_source_t",
    "/var/run/lto-archiver(/.*)?": "lto_archiver_runtime_t",
    "/var/run/lto-archiver-broker(/.*)?": "lto_archiver_broker_runtime_t",
    "/var/run/lto-archiver-share-broker(/.*)?": ("lto_archiver_share_broker_runtime_t"),
    "/var/run/lto-archiver-log-reader(/.*)?": ("lto_archiver_log_reader_runtime_t"),
    "/var/lock/lto-ltfs(/.*)?": "lto_archiver_ltfs_lock_t",
    "/var/run/credentials/lto-archiverd\\.service(/.*)?": ("lto_archiver_credential_t"),
    "/var/run/credentials/lto-archiver-command-broker\\.service(/.*)?": (
        "lto_archiver_credential_t"
    ),
    "/var/run/credentials/lto-archiver-ltfs-qualification\\.service(/.*)?": (
        "lto_archiver_credential_t"
    ),
    "/var/run/credentials/lto-archiver-archive-runner-qualification\\.service(/.*)?": (
        "lto_archiver_credential_t"
    ),
    "/var/run/credentials/lto-archiver-preflight\\.service(/.*)?": (
        "lto_archiver_credential_t"
    ),
    "/var/run/credentials/lto-archiver-share-broker\\.service(/.*)?": (
        "lto_archiver_credential_t"
    ),
}
DEVICE_CONTEXTS = {
    "/dev/lto-archiver-scsi-[^/]+": "lto_archiver_device_t",
}


class ContractError(ValueError):
    """The built main RPM does not satisfy its closed runtime contract."""


@dataclass(frozen=True)
class RpmTools:
    rpm: Path = Path("/usr/bin/rpm")
    rpm2cpio: Path = Path("/usr/bin/rpm2cpio")
    cpio: Path = Path("/usr/bin/cpio")
    semodule_unpackage: Path = Path("/usr/bin/semodule_unpackage")
    matchpathcon: Path = Path("/usr/sbin/matchpathcon")


@dataclass(frozen=True)
class RpmSnapshot:
    name: str
    architecture: str
    version_release: str
    project_url: str
    requirements: frozenset[str]
    provides: frozenset[str]
    payload_metadata: Mapping[str, tuple[str, str, str]]
    extracted_root: Path


_CONTRACT_KEYS = frozenset(
    {
        "allowed_config_paths",
        "architecture",
        "driver_requirement",
        "forbidden_payload_prefixes",
        "forbidden_payload_suffixes",
        "name",
        "project_url",
        "public_key_sha256",
        "release",
        "required_payload_metadata",
        "required_selinux_contexts",
        "required_source_authorities",
        "runtime_requirement",
        "schema_version",
        "security_sensitive_prefixes",
        "signing_policy_sha256",
        "version",
    }
)
_MODE_PATTERN = re.compile(r"^[bcdlps-][rwxStTs-]{9}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FINGERPRINT_SAFE_ENV = {"LANG": "C", "LC_ALL": "C"}
_MAX_TOOL_OUTPUT = 16 * 1024 * 1024


class _ClosedParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ValueError


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError("duplicate JSON key")
        result[key] = value
    return result


def _load_contract(path: Path) -> dict[str, Any]:
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise ContractError("invalid contract authority")
    try:
        raw = path.read_bytes()
        if len(raw) > 1024 * 1024:
            raise ContractError("contract is too large")
        contract = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_strict_json_object
        )
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError) as error:
        raise ContractError("invalid contract authority") from error
    if type(contract) is not dict or set(contract) != _CONTRACT_KEYS:
        raise ContractError("contract schema is not closed")
    if type(contract["schema_version"]) is not int or contract["schema_version"] != 1:
        raise ContractError("unsupported contract schema")
    for key in (
        "architecture",
        "driver_requirement",
        "name",
        "project_url",
        "release",
        "runtime_requirement",
        "version",
    ):
        if type(contract[key]) is not str or not contract[key]:
            raise ContractError("invalid contract scalar")
    if contract["project_url"] != "https://github.com/Halino/lto-archiver":
        raise ContractError("project URL differs from approved public destination")
    for key in ("public_key_sha256", "signing_policy_sha256"):
        if type(contract[key]) is not str or _SHA256_PATTERN.fullmatch(contract[key]) is None:
            raise ContractError("invalid signing authority digest")
    for key in (
        "allowed_config_paths",
        "forbidden_payload_prefixes",
        "forbidden_payload_suffixes",
        "security_sensitive_prefixes",
    ):
        values = contract[key]
        if (
            type(values) is not list
            or not values
            or any(type(value) is not str or not value for value in values)
            or len(set(values)) != len(values)
        ):
            raise ContractError("invalid contract list")
    if type(contract["required_payload_metadata"]) is not dict:
        raise ContractError("invalid payload metadata authority")
    for path_name, metadata in contract["required_payload_metadata"].items():
        if (
            type(path_name) is not str
            or not _normal_payload_path(path_name)
            or type(metadata) is not list
            or len(metadata) != 3
            or any(type(item) is not str or not item for item in metadata)
            or _MODE_PATTERN.fullmatch(metadata[0]) is None
        ):
            raise ContractError("invalid payload metadata authority")
    if type(contract["required_source_authorities"]) is not dict:
        raise ContractError("invalid source authority")
    required_authority_keys = {"group", "mode", "source", "user"}
    for path_name, authority in contract["required_source_authorities"].items():
        if (
            type(path_name) is not str
            or not _normal_payload_path(path_name)
            or type(authority) is not dict
            or set(authority) != required_authority_keys
            or any(type(value) is not str or not value for value in authority.values())
            or _MODE_PATTERN.fullmatch(authority["mode"]) is None
        ):
            raise ContractError("invalid source authority")
        source = Path(authority["source"])
        if source.is_absolute() or any(part in ("", ".", "..") for part in source.parts):
            raise ContractError("source authority must be relative and normalized")
    contexts = contract["required_selinux_contexts"]
    if (
        type(contexts) is not dict
        or not contexts
        or any(
            type(path_name) is not str
            or not _normal_payload_path(path_name)
            or type(context_type) is not str
            or re.fullmatch(r"[a-z0-9_]+_t", context_type) is None
            for path_name, context_type in contexts.items()
        )
    ):
        raise ContractError("invalid SELinux context authority")
    return contract


def _normal_payload_path(path: str) -> bool:
    return (
        bool(path)
        and path.startswith("/")
        and "\\" not in path
        and "\0" not in path
        and posixpath.normpath(path) == path
        and path != "/"
    )


def _validated_tool(path: Path) -> str:
    if not path.is_absolute() or path.is_symlink():
        raise ContractError("invalid RPM inspection tool")
    try:
        status = path.stat()
    except OSError as error:
        raise ContractError("invalid RPM inspection tool") from error
    if (
        not stat.S_ISREG(status.st_mode)
        or not status.st_mode & stat.S_IXUSR
        or status.st_mode & 0o022
        or status.st_uid not in (0, os.getuid())
    ):
        raise ContractError("invalid RPM inspection tool")
    return os.fspath(path)


def _run_tool(arguments: list[str], *, input_bytes: bytes | None = None, cwd: Path | None = None) -> bytes:
    try:
        completed = subprocess.run(
            arguments,
            input=input_bytes,
            cwd=cwd,
            env=_FINGERPRINT_SAFE_ENV,
            stdin=subprocess.DEVNULL if input_bytes is None else None,
            capture_output=True,
            check=False,
            close_fds=True,
        )
    except OSError as error:
        raise ContractError("RPM inspection tool failed") from error
    if (
        completed.returncode != 0
        or len(completed.stdout) > _MAX_TOOL_OUTPUT
        or len(completed.stderr) > 64 * 1024
    ):
        raise ContractError("RPM inspection tool failed")
    return completed.stdout


def _query_lines(tool: str, rpm: Path, *query: str) -> list[str]:
    output = _run_tool([tool, "-qp", *query, os.fspath(rpm)])
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ContractError("RPM query is not UTF-8") from error
    if "\0" in text or "\r" in text:
        raise ContractError("RPM query is malformed")
    return text.splitlines()


def _extract_rpm_payload(rpm2cpio_tool: str, cpio_tool: str, rpm: Path, root: Path) -> None:
    """Stream an RPM payload to cpio without retaining the archive in RAM."""
    try:
        with tempfile.TemporaryFile() as converter_errors:
            with subprocess.Popen(
                [rpm2cpio_tool, os.fspath(rpm)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=converter_errors,
                env=_FINGERPRINT_SAFE_ENV,
                close_fds=True,
            ) as converter:
                if converter.stdout is None:
                    raise ContractError("RPM payload stream is unavailable")
                try:
                    extracted = subprocess.run(
                        [cpio_tool, "-idm", "--quiet", "--no-absolute-filenames"],
                        stdin=converter.stdout,
                        cwd=root,
                        env=_FINGERPRINT_SAFE_ENV,
                        capture_output=True,
                        check=False,
                        close_fds=True,
                    )
                except OSError as error:
                    converter.kill()
                    converter.wait()
                    raise ContractError("RPM inspection tool failed") from error
                finally:
                    converter.stdout.close()
                converter_status = converter.wait()
            converter_errors.seek(0)
            converter_error = converter_errors.read(64 * 1024 + 1)
    except OSError as error:
        raise ContractError("RPM inspection tool failed") from error
    if (
        converter_status != 0
        or extracted.returncode != 0
        or len(converter_error) > 64 * 1024
        or len(extracted.stderr) > 64 * 1024
        or len(extracted.stdout) > _MAX_TOOL_OUTPUT
    ):
        raise ContractError("RPM inspection tool failed")


def _validate_extracted_tree(root: Path, metadata: Mapping[str, tuple[str, str, str]]) -> None:
    expected_files = {path.removeprefix("/") for path, details in metadata.items() if details[0][0] != "d"}
    found_files: set[str] = set()
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        directory_path = Path(directory)
        for name in list(names):
            candidate = directory_path / name
            status = candidate.lstat()
            if stat.S_ISLNK(status.st_mode) or not stat.S_ISDIR(status.st_mode):
                raise ContractError("extracted RPM tree is unsafe")
        for name in files:
            candidate = directory_path / name
            status = candidate.lstat()
            if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
                raise ContractError("extracted RPM payload is unsafe")
            found_files.add(candidate.relative_to(root).as_posix())
    # RPM %ghost entries are owned in header metadata but intentionally absent
    # from the cpio payload.  Every extracted file must still be declared; the
    # closed contract below verifies all security-sensitive authorities.
    if not found_files.issubset(expected_files):
        raise ContractError("extracted RPM payload differs from header")


def inspect_rpm(rpm: Path, *, tools: RpmTools | None = None) -> RpmSnapshot:
    rpm = Path(rpm)
    if tools is None:
        tools = RpmTools()
    if not rpm.is_absolute() or rpm.is_symlink() or not rpm.is_file():
        raise ContractError("RPM input is not an absolute regular file")
    rpm_tool = _validated_tool(Path(tools.rpm))
    rpm2cpio_tool = _validated_tool(Path(tools.rpm2cpio))
    cpio_tool = _validated_tool(Path(tools.cpio))
    _validated_tool(Path(tools.semodule_unpackage))
    _validated_tool(Path(tools.matchpathcon))
    header = _query_lines(
        rpm_tool,
        rpm,
        "--qf",
        "%{NAME}\\n%{ARCH}\\n%{VERSION}-%{RELEASE}\\n%{URL}\\n",
    )
    if len(header) != 4 or any(not value for value in header):
        raise ContractError("RPM identity query is malformed")
    requirements = frozenset(_query_lines(rpm_tool, rpm, "--requires"))
    provides = frozenset(_query_lines(rpm_tool, rpm, "--provides"))
    if "" in requirements or "" in provides:
        raise ContractError("RPM dependency query is malformed")
    metadata_rows = _query_lines(
        rpm_tool,
        rpm,
        "--qf",
        "[%{FILENAMES}\\t%{FILEMODES:perms}\\t%{FILEUSERNAME}\\t%{FILEGROUPNAME}\\n]",
    )
    metadata = payload_metadata_from_rows(metadata_rows)
    if not metadata:
        raise ContractError("RPM payload is empty")
    for path_name, (mode, user, group) in metadata.items():
        if (
            not _normal_payload_path(path_name)
            or _MODE_PATTERN.fullmatch(mode) is None
            or not user
            or not group
        ):
            raise ContractError("RPM payload metadata is malformed")
    extracted_root = Path(tempfile.mkdtemp(prefix="lto-main-rpm-inspect-"))
    extracted_root.chmod(0o700)
    try:
        _extract_rpm_payload(rpm2cpio_tool, cpio_tool, rpm, extracted_root)
        _validate_extracted_tree(extracted_root, metadata)
        return RpmSnapshot(
            name=header[0],
            architecture=header[1],
            version_release=header[2],
            project_url=header[3],
            requirements=requirements,
            provides=provides,
            payload_metadata=metadata,
            extracted_root=extracted_root,
        )
    except BaseException:
        shutil.rmtree(extracted_root, ignore_errors=True)
        raise


def payload_metadata_from_rows(
    rows: Iterable[str],
) -> dict[str, tuple[str, str, str]]:
    """Parse RPM file metadata without collapsing duplicate payload paths."""

    metadata: dict[str, tuple[str, str, str]] = {}
    for row in rows:
        fields = row.split("\t")
        if len(fields) != 4 or not all(fields):
            raise ContractError("malformed RPM payload metadata")
        path, mode, user, group = fields
        if path in metadata:
            raise ContractError(f"duplicate RPM payload path: {path}")
        metadata[path] = (mode, user, group)
    return metadata


def _reject_global_runtime_payload(
    payload_metadata: Mapping[str, tuple[str, str, str]],
) -> None:
    for path in payload_metadata:
        if path == PRIVATE_RUNTIME_ROOT or path.startswith(f"{PRIVATE_RUNTIME_ROOT}/"):
            raise ContractError("main RPM owns private runtime payload")
        if not path.startswith(GLOBAL_SITE_ROOT):
            continue
        relative = path.removeprefix(GLOBAL_SITE_ROOT)
        if relative in {"ltobackup", ""}:
            continue
        if relative.startswith("ltobackup/"):
            continue
        first = relative.split("/", 1)[0]
        if first == APPLICATION_DIST_INFO:
            continue
        raise ContractError(f"main RPM owns global dependency payload: {path}")


def _verify_selinux_contexts(contexts: str) -> None:
    for name, context_type in LAUNCHER_CONTEXTS.items():
        source_context = rf"system_u:object_r:{context_type},s0"
        compiled_context = rf"system_u:object_r:{context_type}:s0"
        pattern = re.compile(
            rf"(?m)^/usr/bin/{re.escape(name)}\s+--\s+"
            rf"(?:gen_context\({source_context}\)|{compiled_context})$"
        )
        if pattern.search(contexts) is None:
            raise ContractError(f"missing SELinux context for {name}")
    if re.search(r"(?m)^/run/(?:credentials|lock|lto-archiver)", contexts):
        raise ContractError("SELinux runtime authority is not canonical")
    device_authorities = set(re.findall(r"(?m)^(/dev/lto-archiver\S*)\s+", contexts))
    if device_authorities != set(DEVICE_CONTEXTS):
        raise ContractError("SELinux device authority is not exact")
    for path, context_type in {**RUNTIME_CONTEXTS, **DEVICE_CONTEXTS}.items():
        source_context = rf"system_u:object_r:{context_type},s0"
        compiled_context = rf"system_u:object_r:{context_type}:s0"
        pattern = re.compile(
            rf"(?m)^{re.escape(path)}\s+"
            rf"(?:gen_context\({source_context}\)|{compiled_context})$"
        )
        if pattern.search(contexts) is None:
            raise ContractError(f"missing SELinux context for {path}")


def verify_contract(
    *,
    architecture: str,
    version_release: str,
    expected_version_release: str,
    requirements: AbstractSet[str],
    provides: AbstractSet[str],
    payload_metadata: Mapping[str, tuple[str, str, str]],
    launcher_payloads: Mapping[str, bytes],
    expected_launcher_payloads: Mapping[str, bytes],
    share_asset_payloads: Mapping[str, bytes],
    expected_share_asset_payloads: Mapping[str, bytes],
    selinux_contexts: str,
) -> None:
    """Reject any RPM snapshot outside the exact application/runtime boundary."""

    if architecture != "noarch":
        raise ContractError("main RPM must remain noarch")
    if version_release != expected_version_release:
        raise ContractError("unexpected main RPM version-release")

    exact_runtime = "lto-archiver-python-runtime = 0.11.27-3.el9"
    runtime_requirements = {
        requirement
        for requirement in requirements
        if RUNTIME_REQUIREMENT_TOKEN.search(requirement) is not None
    }
    if runtime_requirements != {exact_runtime}:
        raise ContractError("runtime dependency is not exact")
    exact_ltfs = "lto-ltfs = 0.1.0-22.el9"
    ltfs_requirements = {
        requirement
        for requirement in requirements
        if LTFS_REQUIREMENT_TOKEN.search(requirement) is not None
    }
    if ltfs_requirements != {exact_ltfs}:
        raise ContractError("LTFS dependency is not exact")
    if any(
        capability in requirement
        for requirement in requirements
        for capability in ("python3dist(", "python3.11dist(")
    ):
        raise ContractError("main RPM has a global Python distribution dependency")
    if any(
        marker in capability
        for capability in provides
        for marker in ("python3dist(", "python3.11dist(")
    ):
        raise ContractError("main RPM publishes a false Python capability")
    required_share_runtime = {"nfs-utils", "cifs-utils", "systemd-libs"}
    if not required_share_runtime.issubset(requirements):
        raise ContractError("network share runtime dependency is missing")

    _reject_global_runtime_payload(payload_metadata)
    if payload_metadata.get(DEVICE_RELABELER) != (
        "-rwxr-xr-x",
        "root",
        "root",
    ):
        raise ContractError("device relabeler metadata is mutable or untrusted")
    if payload_metadata.get(WEB_FORMS_MACRO) != (
        "-rw-r--r--",
        "root",
        "root",
    ):
        raise ContractError("shared WebUI forms macro is missing or untrusted")
    for path, expected_metadata in REQUIRED_SHARE_PAYLOAD_METADATA.items():
        if payload_metadata.get(path) != expected_metadata:
            raise ContractError(
                f"network share runtime metadata is missing or untrusted: {path}"
            )
    for path, expected_metadata in REQUIRED_LOG_READER_PAYLOAD_METADATA.items():
        if payload_metadata.get(path) != expected_metadata:
            raise ContractError(
                f"journal reader runtime metadata is missing or untrusted: {path}"
            )
    expected_share_names = set(SHARE_ASSET_PATHS)
    if set(share_asset_payloads) != expected_share_names:
        raise ContractError("network share asset payload set is not exact")
    if set(expected_share_asset_payloads) != expected_share_names:
        raise ContractError("expected network share asset authority set is not exact")
    for name in sorted(expected_share_names):
        if (
            type(share_asset_payloads[name]) is not bytes
            or type(expected_share_asset_payloads[name]) is not bytes
            or share_asset_payloads[name] != expected_share_asset_payloads[name]
        ):
            raise ContractError(
                f"network share asset differs from authority: "
                f"{SHARE_ASSET_PATHS[name]}"
            )
    expected_names = set(LAUNCHER_CONTEXTS)
    if set(launcher_payloads) != expected_names:
        raise ContractError("launcher payload set is not exact")
    if set(expected_launcher_payloads) != expected_names:
        raise ContractError("expected launcher authority set is not exact")
    for name in sorted(expected_names):
        path = f"/usr/bin/{name}"
        if payload_metadata.get(path) != ("-rwxr-xr-x", "root", "root"):
            raise ContractError(f"launcher metadata is mutable or untrusted: {name}")
        if launcher_payloads[name] != expected_launcher_payloads[name]:
            raise ContractError(f"launcher dispatch differs from authority: {name}")

    _verify_selinux_contexts(selinux_contexts)


def _sha256_file(path: Path) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ContractError("authority file is unavailable") from error
    try:
        status = os.fstat(descriptor)
        if (
            not stat.S_ISREG(status.st_mode)
            or status.st_nlink != 1
            or status.st_mode & 0o022
            or status.st_uid not in (0, os.getuid())
        ):
            raise ContractError("authority file is unsafe")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)
    finally:
        os.close(descriptor)


def _read_regular(path: Path, *, maximum: int = 16 * 1024 * 1024) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ContractError("payload authority is unavailable") from error
    try:
        status = os.fstat(descriptor)
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1 or status.st_size > maximum:
            raise ContractError("payload authority is unsafe")
        content = bytearray()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                return bytes(content)
            content.extend(chunk)
    finally:
        os.close(descriptor)


def _verify_signing_authority(source_root: Path, contract: Mapping[str, Any]) -> None:
    authorities = (
        (
            source_root / "packaging/signing/lto-archiver-task9-rpm-public.asc",
            contract["public_key_sha256"],
        ),
        (
            source_root / "packaging/deployment/app-runtime-signing-policy.json",
            contract["signing_policy_sha256"],
        ),
    )
    for path, expected_digest in authorities:
        if _sha256_file(path) != expected_digest:
            raise ContractError("signing authority digest mismatch")


def _verify_dependencies(snapshot: RpmSnapshot, contract: Mapping[str, Any]) -> None:
    runtime = contract["runtime_requirement"]
    driver = contract["driver_requirement"]
    runtime_matches = {
        value
        for value in snapshot.requirements
        if RUNTIME_REQUIREMENT_TOKEN.search(value) is not None
    }
    driver_matches = {
        value
        for value in snapshot.requirements
        if LTFS_REQUIREMENT_TOKEN.search(value) is not None
    }
    if runtime_matches != {runtime} or driver_matches != {driver}:
        raise ContractError("external RPM dependency is not exact")
    if any(
        marker in capability
        for capability in (*snapshot.requirements, *snapshot.provides)
        for marker in ("python3dist(", "python3.11dist(")
    ):
        raise ContractError("global Python capability is forbidden")


def _verify_payload_classes(snapshot: RpmSnapshot, contract: Mapping[str, Any]) -> None:
    paths = set(snapshot.payload_metadata)
    if paths & HISTORICAL_RUNNER_PATHS:
        raise ContractError("historical deployment runner in current RPM")
    for path in paths:
        lowered = path.casefold()
        if any(
            path == prefix.rstrip("/") or path.startswith(prefix)
            for prefix in contract["forbidden_payload_prefixes"]
        ) or any(lowered.endswith(suffix.casefold()) for suffix in contract["forbidden_payload_suffixes"]):
            raise ContractError("forbidden operational payload class")
    allowed_config = set(contract["allowed_config_paths"])
    for path in paths:
        if path.startswith("/etc/lto-archiver/") and path not in allowed_config:
            raise ContractError("unapproved configuration payload")
    expected_metadata = {
        path: tuple(metadata)
        for path, metadata in contract["required_payload_metadata"].items()
    }
    for path, metadata in expected_metadata.items():
        if snapshot.payload_metadata.get(path) != metadata:
            raise ContractError("required payload metadata mismatch")
    source_authorities = contract["required_source_authorities"]
    authorized_sensitive = set(source_authorities) | set(expected_metadata)
    for path in paths:
        if any(
            path.startswith(prefix)
            for prefix in contract["security_sensitive_prefixes"]
        ) and path not in authorized_sensitive:
            raise ContractError("extra security-sensitive payload")


def _reject_historical_runner_bytes(snapshot: RpmSnapshot, source_root: Path) -> None:
    historical_hashes: dict[int, set[str]] = {}
    for name in HISTORICAL_RUNNER_NAMES:
        content = _read_regular(source_root / "packaging/scripts" / name)
        historical_hashes.setdefault(len(content), set()).add(
            hashlib.sha256(content).hexdigest()
        )
    for directory, _subdirs, files in os.walk(snapshot.extracted_root):
        for name in files:
            extracted = Path(directory) / name
            try:
                size = extracted.lstat().st_size
            except OSError as error:
                raise ContractError("RPM payload cannot be inspected") from error
            if size in historical_hashes:
                content = _read_regular(extracted)
                if hashlib.sha256(content).hexdigest() in historical_hashes[size]:
                    raise ContractError("historical deployment runner bytes in current RPM")


def _verify_source_authorities(
    snapshot: RpmSnapshot,
    source_root: Path,
    contract: Mapping[str, Any],
) -> None:
    for rpm_path, authority in contract["required_source_authorities"].items():
        expected_metadata = (
            authority["mode"],
            authority["user"],
            authority["group"],
        )
        if snapshot.payload_metadata.get(rpm_path) != expected_metadata:
            raise ContractError("source-bound payload metadata mismatch")
        extracted = snapshot.extracted_root / rpm_path.removeprefix("/")
        source = source_root / authority["source"]
        if _read_regular(extracted) != _read_regular(source):
            raise ContractError("source-bound payload differs from authority")


def _compiled_selinux_contexts(
    snapshot: RpmSnapshot,
    tools: RpmTools,
    contract: Mapping[str, Any],
) -> str:
    policy = snapshot.extracted_root / "usr/share/selinux/packages/lto_archiver.pp"
    if snapshot.payload_metadata.get(
        "/usr/share/selinux/packages/lto_archiver.pp"
    ) != ("-rw-r--r--", "root", "root"):
        raise ContractError("SELinux package metadata mismatch")
    _read_regular(policy)
    output_root = Path(tempfile.mkdtemp(prefix="lto-main-rpm-selinux-"))
    output_root.chmod(0o700)
    try:
        module = output_root / "lto_archiver.mod"
        contexts = output_root / "lto_archiver.fc"
        _run_tool(
            [
                _validated_tool(Path(tools.semodule_unpackage)),
                os.fspath(policy),
                os.fspath(module),
                os.fspath(contexts),
            ]
        )
        _read_regular(module)
        try:
            context_text = _read_regular(contexts).decode("utf-8")
        except UnicodeDecodeError as error:
            raise ContractError("SELinux contexts are not UTF-8") from error
        matcher = _validated_tool(Path(tools.matchpathcon))
        for path, context_type in contract["required_selinux_contexts"].items():
            output = _run_tool(
                [matcher, "-N", "-n", "-f", os.fspath(contexts), path]
            )
            try:
                actual = output.decode("utf-8").strip()
            except UnicodeDecodeError as error:
                raise ContractError("SELinux matcher output is not UTF-8") from error
            if actual != f"system_u:object_r:{context_type}:s0":
                raise ContractError("SELinux matcher result differs from contract")
        return context_text
    finally:
        shutil.rmtree(output_root, ignore_errors=True)


def _verify_required_contexts(contexts: str, contract: Mapping[str, Any]) -> None:
    for path, context_type in contract["required_selinux_contexts"].items():
        matched = False
        for line in contexts.splitlines():
            fields = line.split()
            if len(fields) not in (2, 3):
                continue
            path_pattern = fields[0]
            context = fields[-1]
            if fields[-2] == "--" or len(fields) == 2:
                try:
                    path_matches = re.fullmatch(path_pattern, path) is not None
                except re.error as error:
                    raise ContractError("SELinux context pattern is malformed") from error
                expected = {
                    f"gen_context(system_u:object_r:{context_type},s0)",
                    f"system_u:object_r:{context_type}:s0",
                }
                if path_matches and context in expected:
                    matched = True
                    break
        if not matched:
            raise ContractError("required SELinux context is missing")


def verify_rpm(
    rpm: Path,
    *,
    source_root: Path,
    contract_file: Path,
    tools: RpmTools | None = None,
) -> dict[str, object]:
    rpm = Path(rpm)
    source_root = Path(source_root)
    contract_file = Path(contract_file)
    if tools is None:
        tools = RpmTools()
    if (
        not source_root.is_absolute()
        or source_root.is_symlink()
        or not source_root.is_dir()
    ):
        raise ContractError("source root is not an absolute directory")
    contract = _load_contract(contract_file)
    _verify_signing_authority(source_root, contract)
    snapshot = inspect_rpm(rpm, tools=tools)
    try:
        expected_version_release = f"{contract['version']}-{contract['release']}"
        if (
            snapshot.name != contract["name"]
            or snapshot.architecture != contract["architecture"]
            or snapshot.version_release != expected_version_release
            or snapshot.project_url != contract["project_url"]
        ):
            raise ContractError("RPM identity differs from contract")
        exact_provide = f"{contract['name']} = {expected_version_release}"
        application_provides = {
            value
            for value in snapshot.provides
            if value.startswith(f"{contract['name']} = ")
        }
        if application_provides != {exact_provide}:
            raise ContractError("application provide is not exact")
        _verify_dependencies(snapshot, contract)
        _verify_payload_classes(snapshot, contract)
        _reject_historical_runner_bytes(snapshot, source_root)
        _verify_source_authorities(snapshot, source_root, contract)
        contexts = _compiled_selinux_contexts(snapshot, tools, contract)
        _verify_required_contexts(contexts, contract)
        return {
            "architecture": snapshot.architecture,
            "contract_sha256": _sha256_file(contract_file),
            "dependency_count": len(snapshot.requirements),
            "name": snapshot.name,
            "payload_count": len(snapshot.payload_metadata),
            "rpm_sha256": _sha256_file(rpm),
            "schema_version": 1,
            "status": "verified",
            "version_release": snapshot.version_release,
        }
    finally:
        shutil.rmtree(snapshot.extracted_root, ignore_errors=True)


def _publish_json(path: Path, result: Mapping[str, object]) -> None:
    if not path.is_absolute() or path.name in ("", ".", "..") or path.exists() or path.is_symlink():
        raise ContractError("JSON output must be a new absolute path")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise ContractError("JSON output parent is unsafe")
    content = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    published = False
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(content):
            written = os.write(descriptor, content[offset:])
            if written <= 0:
                raise ContractError("JSON output write failed")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        published = True
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if published:
            with contextlib.suppress(OSError):
                path.unlink()
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _ClosedParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--rpm", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--json-output", required=True, type=Path)
    try:
        arguments = parser.parse_args(argv)
        if any(
            not value.is_absolute()
            for value in (
                arguments.rpm,
                arguments.source_root,
                arguments.contract,
                arguments.json_output,
            )
        ):
            raise ContractError("all CLI paths must be absolute")
        result = verify_rpm(
            arguments.rpm,
            source_root=arguments.source_root,
            contract_file=arguments.contract,
        )
        _publish_json(arguments.json_output, result)
        return 0
    except (ContractError, OSError, ValueError, TypeError, UnicodeError):
        with contextlib.suppress(OSError):
            sys.stderr.write("main RPM verification failed\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
