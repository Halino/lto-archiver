from __future__ import annotations

import argparse
import hashlib
import ipaddress
import io
import json
import os
import re
import resource
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath


DEFAULT_MAX_FILE_SIZE = 32 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_MEMBERS = 10_000
DEFAULT_MAX_COMMIT_COUNT = 5_000
DEFAULT_MAX_COMPRESSION_RATIO = 200
DEFAULT_MAX_ARCHIVE_DEPTH = 5

_SENSITIVE_EXTENSIONS = frozenset(
    {
        ".db",
        ".db-shm",
        ".db-wal",
        ".dmp",
        ".etl",
        ".evtx",
        ".log",
        ".lzt",
        ".reg",
        ".sqlite",
        ".sqlite3",
    }
)
_PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |EC |DSA |OPEN" + rb"SSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_PRIVATE_KEY_PATH_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPEN" + r"SSH )?PRIVATE KEY-----",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_PATH_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
_UNC_RE = re.compile(
    r"(?:^|[\s=:'\"(])\\\\(?P<host>[A-Za-z0-9](?:[A-Za-z0-9.-]{0,252}))\\(?=[^\\\s])",
    re.MULTILINE,
)
_WINDOWS_PROFILE_RE = re.compile(r"\b[A-Za-z]:\\Users\\([^\\\r\n]+)", re.IGNORECASE)
_INTERNAL_HOST_RE = re.compile(
    r"\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)*\.(?:corp|internal|lan|local)\b",
    re.IGNORECASE,
)
_CREDENTIAL_RE = re.compile(
    r"(?im)\b(?P<key>pass" + r"word|passwd|pwd|credential|user(?:name)?|account|"
    r"api[_-]?key|access[_-]?key|client[_-]?secret|secret|token)"
    r"\s*[:=]\s*(?P<value>[^\s,;#}]+)"
)
_TOKEN_PATTERNS = (
    re.compile(r"\bgh(?:p|o|u|s|r)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)
_SYNTHETIC_CREDENTIAL_VALUES = frozenset(
    {
        "<account>",
        "<password>",
        "<redacted>",
        "<secret>",
        "<token>",
        "<user>",
        "<username>",
        "example",
        "placeholder",
        "redacted",
        "none",
        "null",
        "$null",
        "true",
        "false",
        "not-a-real-token",
    }
)
_SYNTHETIC_PROFILE_NAMES = frozenset(
    {
        "<user>",
        "<username>",
        "default",
        "example",
        "public",
        "user",
        "username",
        "%username%",
        "$env:username",
    }
)


@dataclass(frozen=True, slots=True)
class AuditFinding:
    path: str
    rule: str
    detail: str


def _ipv4_network(
    octets: tuple[int, int, int, int], prefix: int
) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network((int.from_bytes(bytes(octets), "big"), prefix))


_RFC5737_DOCUMENTATION_NETWORKS = (
    _ipv4_network((192, 0, 2, 0), 24),
    _ipv4_network((198, 51, 100, 0), 24),
    _ipv4_network((203, 0, 113, 0), 24),
)
_IANA_SPECIAL_PURPOSE_NETWORKS = (
    _ipv4_network((0, 0, 0, 0), 8),
    _ipv4_network((0, 0, 0, 0), 32),
    _ipv4_network((10, 0, 0, 0), 8),
    _ipv4_network((100, 64, 0, 0), 10),
    _ipv4_network((127, 0, 0, 0), 8),
    _ipv4_network((169, 254, 0, 0), 16),
    _ipv4_network((172, 16, 0, 0), 12),
    _ipv4_network((192, 0, 0, 0), 24),
    _ipv4_network((192, 0, 0, 0), 29),
    _ipv4_network((192, 0, 0, 8), 32),
    _ipv4_network((192, 0, 0, 9), 32),
    _ipv4_network((192, 0, 0, 10), 32),
    _ipv4_network((192, 0, 0, 170), 32),
    _ipv4_network((192, 0, 0, 171), 32),
    _ipv4_network((192, 31, 196, 0), 24),
    _ipv4_network((192, 52, 193, 0), 24),
    _ipv4_network((192, 88, 99, 0), 24),
    _ipv4_network((192, 88, 99, 2), 32),
    _ipv4_network((192, 168, 0, 0), 16),
    _ipv4_network((192, 175, 48, 0), 24),
    _ipv4_network((198, 18, 0, 0), 15),
    _ipv4_network((224, 0, 0, 0), 4),
    _ipv4_network((240, 0, 0, 0), 4),
    _ipv4_network((255, 255, 255, 255), 32),
)
_RELEASE_FILE_VERSIONS = frozenset(
    ".".join(str(part) for part in version)
    for version in ((0, 11, 26, 0), (0, 11, 27, 0))
)


def _is_private_address(value: str) -> bool:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError:
        return False
    if any(address in network for network in _RFC5737_DOCUMENTATION_NETWORKS):
        return False
    return (
        any(address in network for network in _IANA_SPECIAL_PURPOSE_NETWORKS)
        or not address.is_global
        or address.is_link_local
        or address.is_loopback
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


def _is_synthetic_credential(value: str) -> bool:
    normalized = value.strip("\"'").casefold()
    if not normalized:
        return True
    if normalized in _SYNTHETIC_CREDENTIAL_VALUES:
        return True
    return bool(
        re.fullmatch(r"\$env:[A-Za-z_][A-Za-z0-9_]*", normalized, re.IGNORECASE)
        or re.fullmatch(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", normalized)
        or re.fullmatch(r"\{\{\s*[A-Za-z_][A-Za-z0-9_.-]*\s*\}\}", normalized)
        or re.fullmatch(r"%\([A-Za-z_][A-Za-z0-9_]*\)[a-z]", normalized)
    )


def _replace_match_group(match: re.Match[str], group: str, replacement: str) -> str:
    matched = match.group(0)
    start = match.start(group) - match.start()
    end = match.end(group) - match.start()
    return matched[:start] + replacement + matched[end:]


def _redact_path(path: str) -> str:
    redacted = _PRIVATE_KEY_PATH_RE.sub("[REDACTED-PRIVATE-KEY-HEADER]", path)
    redacted = _CREDENTIAL_RE.sub(
        lambda match: _replace_match_group(match, "value", "[REDACTED-CREDENTIAL]"),
        redacted,
    )
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub("[REDACTED-TOKEN]", redacted)
    redacted = _WINDOWS_PROFILE_RE.sub(
        lambda match: match.group(0).replace(match.group(1), "[REDACTED-USER]", 1),
        redacted,
    )
    redacted = _UNC_RE.sub(
        lambda match: match.group(0).replace(match.group("host"), "[REDACTED-HOST]", 1),
        redacted,
    )
    redacted = _INTERNAL_HOST_RE.sub("[REDACTED-HOST]", redacted)
    pieces: list[str] = []
    position = 0
    for match in _PATH_IPV4_RE.finditer(redacted):
        pieces.append(redacted[position : match.start()])
        pieces.append(
            "[REDACTED-IP]" if _is_private_address(match.group(0)) else match.group(0)
        )
        position = match.end()
    pieces.append(redacted[position:])
    redacted = "".join(pieces)
    return "".join(
        character
        if ord(character) >= 32 and ord(character) != 127
        else f"\\x{ord(character):02x}"
        for character in redacted
    )


def _finding(path: str, rule: str, detail: str) -> AuditFinding:
    return AuditFinding(path=_redact_path(path), rule=rule, detail=detail)


def _line_for_match(text: str, match: re.Match[str]) -> str:
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    return text[line_start : line_end if line_end >= 0 else len(text)]


def _is_file_version_context(text: str, match: re.Match[str]) -> bool:
    if match.group(0) not in _RELEASE_FILE_VERSIONS:
        return False
    line_start = text.rfind("\n", 0, match.start()) + 1
    prefix = text[line_start : match.start()].strip().casefold()
    return prefix.endswith(
        (
            "version",
            "file version",
            "product version",
            "file/product version",
            "versione file/prodotto",
        )
    )


def _is_allowed_unc(
    text: str, match: re.Match[str], path: str, *, path_scan: bool
) -> bool:
    host = match.group("host").rstrip(".").casefold()
    if host == "example.test" or host.endswith(".example.test"):
        return True
    if path_scan:
        return False
    line = _line_for_match(text, match).casefold()
    labeled_example = any(
        marker in line
        for marker in ("example:", "esempio:", "exemple :", "beispiel:", "ejemplo:")
    )
    if host == "nas" and labeled_example:
        return True
    return (
        path == "tests/test_util.py"
        and host == "server"
        and "for unsafe in" in line
        and "server\\share\\file" in line
    )


def _sensitive_text_findings(
    report_path: str,
    text: str,
    *,
    path_scan: bool,
) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    ipv4_pattern = _PATH_IPV4_RE if path_scan else _IPV4_RE
    for match in ipv4_pattern.finditer(text):
        if _is_private_address(match.group(0)) and not (
            not path_scan and _is_file_version_context(text, match)
        ):
            findings.append(
                _finding(
                    report_path,
                    "private-network",
                    "private or special-use IPv4 address detected; value redacted",
                )
            )
    for match in _UNC_RE.finditer(text):
        if not _is_allowed_unc(text, match, report_path, path_scan=path_scan):
            findings.append(
                _finding(
                    report_path,
                    "private-unc-host",
                    "non-example UNC host detected; value redacted",
                )
            )
    for match in _WINDOWS_PROFILE_RE.finditer(text):
        profile = match.group(1).split("\\", 1)[0].strip().casefold()
        if profile not in _SYNTHETIC_PROFILE_NAMES:
            findings.append(
                _finding(
                    report_path,
                    "windows-user-profile",
                    "real Windows user profile detected; value redacted",
                )
            )
    for match in _CREDENTIAL_RE.finditer(text):
        line = _line_for_match(text, match).strip()
        oidc_permission = "id-" + "token" + ": write"
        if (report_path, line) in {
            (".github/workflows/build-release.yml", oidc_permission),
            (
                "tests/test_public_workflow_policy.py",
                'self.assertIn("' + oidc_permission + '", source)',
            ),
        }:
            # This exact Actions OIDC permission is not a stored credential.
            continue
        if (
            report_path.endswith(".github/workflows/publish-release.yml")
            and _line_for_match(text, match).strip()
            == "github-" + "token" + ": ${{ github.token }}"
        ):
            # GitHub supplies this per-job token; no credential bytes are stored.
            continue
        if not _is_synthetic_credential(match.group("value")):
            findings.append(
                _finding(
                    report_path,
                    "credential-assignment",
                    "account or credential assignment detected; value redacted",
                )
            )
    if any(pattern.search(text) for pattern in _TOKEN_PATTERNS):
        findings.append(
            _finding(
                report_path,
                "secret-token",
                "repository or cloud token form detected; value redacted",
            )
        )
    if _INTERNAL_HOST_RE.search(text):
        findings.append(
            _finding(
                report_path,
                "internal-host",
                "internal hostname detected; value redacted",
            )
        )
    return findings


def _path_findings(path: str) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    normalized = path.replace("\\", "/")
    lower = normalized.casefold()
    filename = PurePosixPath(normalized).name.casefold()
    suffixes = PurePosixPath(normalized).suffixes
    components = tuple(
        component.casefold() for component in PurePosixPath(normalized).parts
    )
    combined_suffix = "".join(suffix.casefold() for suffix in suffixes[-2:])
    suffix = PurePosixPath(normalized).suffix.casefold()
    if (
        filename == ".env"
        or filename.startswith(".env.")
        or suffix in _SENSITIVE_EXTENSIONS
        or combined_suffix in _SENSITIVE_EXTENSIONS
    ):
        findings.append(
            _finding(
                path,
                "sensitive-extension",
                "database, log, credential, or support artifact path",
            )
        )
    if ".git" in components:
        findings.append(
            _finding(
                path, "git-metadata", "Git metadata is forbidden in release content"
            )
        )
    forbidden = (
        ".gitlab" + "-ci.yml",
        "scripts/field-tools/archive/",
        "scripts/field-tools/controlled/",
    )
    if (
        lower in forbidden
        or any(marker in lower for marker in forbidden[1:])
        or lower.startswith("scripts/deploy-")
    ):
        findings.append(
            _finding(
                path, "private-operation-path", "private server or deployment path"
            )
        )
    if _PRIVATE_KEY_PATH_RE.search(path):
        findings.append(
            _finding(
                path,
                "private-key",
                "private-key header detected in path; value redacted",
            )
        )
    findings.extend(_sensitive_text_findings(path, path, path_scan=True))
    return findings


def _audit_content_bytes(path: str, data: bytes) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    key_headers = tuple(_PRIVATE_KEY_RE.finditer(data))
    if key_headers:
        findings.append(
            _finding(path, "private-key", "private-key header detected; value redacted")
        )

    text = data.decode("utf-8", errors="replace")
    source_suffix = PurePosixPath(path.replace("\\", "/")).suffix.casefold()
    if "\ufffd" in text and b"\x00" in data:
        return findings
    findings.extend(_sensitive_text_findings(path, text, path_scan=False))

    private_identifiers = (
        ".gitlab" + "-ci.yml",
        "scripts/deploy" + "-",
        "scripts/field-tools/" + "archive/",
        "scripts/field-tools/" + "controlled/",
    )
    if source_suffix not in {".py", ".ps1"} and any(
        identifier.casefold() in text.casefold() for identifier in private_identifiers
    ):
        findings.append(
            _finding(
                path,
                "private-operation-identifier",
                "private server or deployment identifier detected",
            )
        )
    return findings


def audit_bytes(path: str, data: bytes) -> tuple[AuditFinding, ...]:
    return tuple((*_path_findings(path), *_audit_content_bytes(path, data)))


def _unsafe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        not name
        or "\\" in name
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    )


@dataclass
class _ArchiveBudget:
    max_bytes: int = DEFAULT_MAX_ARCHIVE_SIZE
    max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS
    max_depth: int = DEFAULT_MAX_ARCHIVE_DEPTH
    max_member_size: int = DEFAULT_MAX_FILE_SIZE
    bytes_seen: int = 0
    members_seen: int = 0

    def consume(self, label: str, size: int) -> AuditFinding | None:
        self.members_seen += 1
        self.bytes_seen += size
        if (
            size > self.max_member_size
            or self.members_seen > self.max_members
            or self.bytes_seen > self.max_bytes
        ):
            return _finding(
                label,
                "archive-budget",
                "recursive archive member, byte, or file limit was exceeded",
            )
        return None


def _archive_kind(label: str) -> str | None:
    lower = label.casefold()
    if lower.endswith((".tar.zst", ".tzst")):
        return "unsupported"
    if lower.endswith((".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar")):
        return "tar"
    if lower.endswith((".zip", ".whl", ".pyz")):
        return "zip"
    if lower.endswith(".rpm"):
        return "rpm"
    return None


def _expected_archive_magic(label: str) -> str | None:
    lower = label.casefold()
    if lower.endswith((".tar.gz", ".tgz")):
        return "gzip"
    if lower.endswith((".tar.xz", ".txz")):
        return "xz"
    if lower.endswith((".tar.zst", ".tzst")):
        return "zstd"
    if lower.endswith(".tar"):
        return "tar"
    if lower.endswith((".zip", ".whl", ".pyz")):
        return "zip"
    if lower.endswith(".rpm"):
        return "rpm"
    return None


def _archive_magic(data: bytes) -> str | None:
    if data.startswith(b"\x1f\x8b"):
        return "gzip"
    if data.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if data.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"\xed\xab\xee\xdb"):
        return "rpm"
    if len(data) >= 262 and data[257:262] == b"ustar":
        return "tar"
    return None


def _audit_member_data(
    label: str,
    data: bytes,
    *,
    budget: _ArchiveBudget,
    depth: int,
    ancestors: frozenset[bytes],
) -> tuple[AuditFinding, ...]:
    kind = _archive_kind(label)
    expected_magic = _expected_archive_magic(label)
    actual_magic = _archive_magic(data)
    if (expected_magic is None and actual_magic is not None) or (
        expected_magic is not None and actual_magic != expected_magic
    ):
        return (
            _finding(
                label,
                "archive-magic-mismatch",
                "archive/compression magic and filename suffix do not match",
            ),
        )
    if kind is None:
        return audit_bytes(label, data)
    if depth >= budget.max_depth:
        return (_finding(label, "archive-depth", "recursive archive depth limit was exceeded"),)
    digest = hashlib.sha256(data).digest()
    if digest in ancestors:
        return (_finding(label, "archive-cycle", "recursive archive content cycle was detected"),)
    nested_ancestors = ancestors | {digest}
    if kind == "unsupported":
        return (_finding(label, "archive-parser-unavailable", "archive parser is unavailable; release is rejected"),)
    if kind == "rpm":
        return (_finding(label, "nested-rpm-unsupported", "nested RPM cannot be inspected without a pinned filesystem input"),)
    if kind == "tar":
        return _audit_tar_bytes(label, data, budget=budget, depth=depth, ancestors=nested_ancestors)
    return _audit_zip_bytes(label, data, budget=budget, depth=depth, ancestors=nested_ancestors)


def _audit_tar_bytes(
    label: str,
    data: bytes,
    *,
    budget: _ArchiveBudget,
    depth: int,
    ancestors: frozenset[bytes],
) -> tuple[AuditFinding, ...]:
    findings: list[AuditFinding] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            for member in archive:
                member_label = f"{label}!{member.name}"
                limit = budget.consume(member_label, member.size)
                if limit is not None:
                    findings.append(limit)
                    return tuple(findings)
                if _unsafe_member(member.name):
                    findings.append(_finding(member_label, "archive-path", "unsafe archive member path"))
                    continue
                if member.isdir():
                    continue
                if not member.isfile():
                    findings.append(_finding(member_label, "archive-special-file", "non-regular archive member is forbidden"))
                    continue
                source = archive.extractfile(member)
                if source is None:
                    findings.append(_finding(member_label, "archive-read-error", "archive member cannot be read"))
                    continue
                member_data = source.read(member.size + 1)
                if len(member_data) != member.size:
                    findings.append(_finding(member_label, "archive-read-error", "archive member length is inconsistent"))
                    continue
                findings.extend(
                    _audit_member_data(
                        member_label,
                        member_data,
                        budget=budget,
                        depth=depth + 1,
                        ancestors=ancestors,
                    )
                )
    except (OSError, EOFError, tarfile.TarError):
        findings.append(_finding(label, "archive-read-error", "compressed tar cannot be inspected"))
    return tuple(findings)


def audit_tar(path: Path, *, display: str | None = None) -> tuple[AuditFinding, ...]:
    label = display or path.name
    if _archive_kind(label) == "unsupported":
        return (_finding(label, "archive-parser-unavailable", "archive parser is unavailable; release is rejected"),)
    try:
        if path.stat().st_size > DEFAULT_MAX_ARCHIVE_SIZE:
            return (_finding(label, "archive-budget", "archive exceeds bounded input size"),)
        data = path.read_bytes()
    except OSError:
        return (_finding(label, "archive-read-error", "compressed tar cannot be inspected"),)
    if len(data) > DEFAULT_MAX_ARCHIVE_SIZE:
        return (_finding(label, "archive-budget", "archive exceeds bounded input size"),)
    return _audit_member_data(
        label,
        data,
        budget=_ArchiveBudget(),
        depth=0,
        ancestors=frozenset(),
    )


def _audit_newc(
    label: str,
    data: bytes,
    *,
    budget: _ArchiveBudget | None = None,
    depth: int = 0,
    ancestors: frozenset[bytes] = frozenset(),
) -> tuple[AuditFinding, ...]:
    budget = budget or _ArchiveBudget()
    findings: list[AuditFinding] = []
    offset = 0
    members = 0
    total = 0
    while offset + 110 <= len(data):
        header = data[offset : offset + 110]
        if header[:6] not in (b"070701", b"070702"):
            return (*findings, _finding(label, "rpm-payload-invalid", "RPM cpio payload is not bounded newc"))
        try:
            mode = int(header[14:22], 16)
            size = int(header[54:62], 16)
            name_size = int(header[94:102], 16)
        except ValueError:
            return (*findings, _finding(label, "rpm-payload-invalid", "RPM cpio header is invalid"))
        offset += 110
        if name_size < 2 or offset + name_size > len(data):
            return (*findings, _finding(label, "rpm-payload-invalid", "RPM cpio name is invalid"))
        raw_name = data[offset : offset + name_size - 1]
        offset = (offset + name_size + 3) & ~3
        try:
            name = raw_name.decode("utf-8")
        except UnicodeDecodeError:
            return (*findings, _finding(label, "rpm-payload-invalid", "RPM cpio path is not UTF-8"))
        if name == "TRAILER!!!":
            return tuple(findings)
        member_label = f"{label}!{name}"
        members += 1
        total += size
        limit = budget.consume(member_label, size)
        if limit is not None:
            findings.append(limit)
            return tuple(findings)
        if _unsafe_member(name):
            findings.append(_finding(member_label, "rpm-payload-path", "unsafe RPM payload path"))
        if (mode & 0o170000) not in (0o040000, 0o100000):
            findings.append(_finding(member_label, "rpm-payload-special-file", "non-regular RPM payload member is forbidden"))
        if offset + size > len(data):
            return (*findings, _finding(member_label, "rpm-payload-invalid", "RPM payload is truncated"))
        if (mode & 0o170000) == 0o100000:
            findings.extend(
                _audit_member_data(
                    member_label,
                    data[offset : offset + size],
                    budget=budget,
                    depth=depth + 1,
                    ancestors=ancestors,
                )
            )
        offset = (offset + size + 3) & ~3
    return (*findings, _finding(label, "rpm-payload-invalid", "RPM cpio trailer is missing"))


def audit_rpm(
    path: Path,
    *,
    rpm2cpio: Path = Path("/usr/bin/rpm2cpio"),
    timeout: float = 60,
) -> tuple[AuditFinding, ...]:
    try:
        if path.stat().st_size > DEFAULT_MAX_ARCHIVE_SIZE:
            return (_finding(path.name, "archive-budget", "RPM exceeds bounded input size"),)
        with path.open("rb") as source:
            if _archive_magic(source.read(8)) != "rpm":
                return (_finding(path.name, "archive-magic-mismatch", "RPM magic and filename suffix do not match"),)
    except OSError:
        return (_finding(path.name, "rpm-parser-unavailable", "RPM input cannot be inspected"),)
    if rpm2cpio.is_symlink() or not rpm2cpio.is_file() or not os.access(rpm2cpio, os.X_OK):
        return (_finding(path.name, "rpm-parser-unavailable", "rpm2cpio is unavailable; release is rejected"),)

    def limit_converter_output() -> None:
        limit = DEFAULT_MAX_ARCHIVE_SIZE + 1
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))

    try:
        with tempfile.TemporaryFile() as output_file:
            process = subprocess.Popen(
                [os.fspath(rpm2cpio), os.fspath(path)],
                stdout=output_file,
                stderr=subprocess.DEVNULL,
                preexec_fn=limit_converter_output,
            )
            try:
                process.communicate(timeout=timeout)
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                return (_finding(path.name, "rpm-parser-timeout", "bounded RPM payload inspection timed out"),)
            output_file.seek(0, os.SEEK_END)
            output_size = output_file.tell()
            output_file.seek(0)
            output = output_file.read(DEFAULT_MAX_ARCHIVE_SIZE + 1)
    except OSError:
        return (_finding(path.name, "rpm-parser-unavailable", "bounded RPM payload inspection failed"),)
    if return_code != 0 or output_size > DEFAULT_MAX_ARCHIVE_SIZE or len(output) > DEFAULT_MAX_ARCHIVE_SIZE:
        return (_finding(path.name, "rpm-payload-invalid", "RPM payload conversion failed or exceeded bound"),)
    return _audit_newc(path.name, output)


def _sorted_scandir(directory: Path) -> list[os.DirEntry[str]]:
    with os.scandir(directory) as entries:
        return sorted(entries, key=lambda entry: os.fsencode(entry.name))


def _canonical_application_source(
    release_root: Path,
    repository: Path,
    commit: str,
) -> tuple[Path, tuple[AuditFinding, ...]]:
    contract_path = release_root / "release-contract.json"
    if contract_path.is_symlink() or not contract_path.is_file():
        raise ValueError("canonical Source0 requires a real release contract")
    try:
        contract = json.loads(contract_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("canonical Source0 release contract is invalid") from exc
    release_identity = contract.get("version")
    identity_match = (
        re.fullmatch(r"(?P<version>[0-9]+(?:[.][0-9]+){2})-(?P<release>[1-9][0-9]*)", release_identity)
        if isinstance(release_identity, str)
        else None
    )
    if (
        contract.get("kind") != "application"
        or contract.get("package_name") != "lto-archiver"
        or contract.get("source_commit") != commit
        or identity_match is None
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
    ):
        raise ValueError("canonical Source0 contract does not match the requested commit")
    version = identity_match.group("version")
    repository = repository.resolve(strict=True)
    if not repository.is_dir():
        raise ValueError("canonical Source0 repository is unavailable")
    git_environment = {
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    try:
        resolved_commit = subprocess.run(
            ["/usr/bin/git", "-C", os.fspath(repository), "rev-parse", f"{commit}^{{commit}}"],
            check=True,
            capture_output=True,
            text=True,
            env=git_environment,
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError("canonical Source0 commit is unavailable") from exc
    if resolved_commit != commit:
        raise ValueError("canonical Source0 commit did not resolve exactly")
    relative = Path("payload") / f"lto-archiver-{version}.tar.gz"
    source = release_root / relative
    if source.is_symlink() or not source.is_file():
        return relative, (
            _finding(relative.as_posix(), "source-archive-missing", "canonical application Source0 is missing"),
        )
    with tempfile.TemporaryDirectory(prefix="lto-canonical-source-") as temporary:
        expected = Path(temporary) / source.name
        try:
            subprocess.run(
                [
                    "/usr/bin/git", "-C", os.fspath(repository), "archive", "--format=tar.gz",
                    f"--prefix=lto-archiver-{version}/", f"--output={expected}",
                    commit, "--", ".", ":(exclude).superpowers/**",
                    ":(exclude)docs/superpowers/**",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=git_environment,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError("canonical Source0 could not be regenerated") from exc
        with source.open("rb") as actual_file, expected.open("rb") as expected_file:
            actual_digest = hashlib.file_digest(actual_file, "sha256").hexdigest()
            expected_digest = hashlib.file_digest(expected_file, "sha256").hexdigest()
        if source.stat().st_size != expected.stat().st_size or actual_digest != expected_digest:
            return relative, (
                _finding(
                    relative.as_posix(),
                    "source-archive-mismatch",
                    "application Source0 does not exactly match canonical git archive",
                ),
            )
    return relative, ()


def audit_directory(
    root: Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ignored_root_entry: Path | None = None,
    canonical_source_repository: Path | None = None,
    canonical_source_commit: str | None = None,
) -> tuple[AuditFinding, ...]:
    findings = _path_findings(root.name)
    if root.is_symlink():
        findings.append(
            _finding(root.name, "symlink", "audit root must not be a symlink")
        )
        return tuple(findings)
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"audit source is not a directory: {root}")
    if root.name.casefold() == ".git":
        return tuple(findings)
    if (canonical_source_repository is None) != (canonical_source_commit is None):
        raise ValueError("canonical Source0 repository and commit must be provided together")
    canonical_source: Path | None = None
    if canonical_source_repository is not None and canonical_source_commit is not None:
        canonical_source, source_findings = _canonical_application_source(
            root,
            canonical_source_repository,
            canonical_source_commit,
        )
        findings.extend(source_findings)

    def visit(directory: Path, relative_directory: Path) -> None:
        for entry in _sorted_scandir(directory):
            relative = relative_directory / entry.name
            display = relative.as_posix()
            path_findings = _path_findings(display)
            if (
                ignored_root_entry is not None
                and not relative_directory.parts
                and not entry.is_symlink()
                and _same_filesystem_entry(Path(entry.path), ignored_root_entry)
            ):
                continue
            findings.extend(path_findings)
            if entry.is_symlink():
                findings.append(
                    _finding(display, "symlink", "symbolic links are forbidden")
                )
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() == ".git":
                        continue
                    visit(Path(entry.path), relative)
                elif entry.is_file(follow_symlinks=False):
                    if canonical_source is not None and relative == canonical_source:
                        continue
                    size = entry.stat(follow_symlinks=False).st_size
                    if size > max_file_size:
                        findings.append(
                            _finding(
                                display,
                                "file-size",
                                "file exceeds the safe audit size limit",
                            )
                        )
                    else:
                        data = Path(entry.path).read_bytes()
                        if _archive_kind(display) == "rpm" and _archive_magic(data) == "rpm":
                            findings.extend(audit_rpm(Path(entry.path)))
                        else:
                            findings.extend(
                                _audit_member_data(
                                    display,
                                    data,
                                    budget=_ArchiveBudget(max_bytes=max_file_size),
                                    depth=0,
                                    ancestors=frozenset(),
                                )
                            )
                else:
                    findings.append(
                        _finding(
                            display,
                            "special-file",
                            "non-regular filesystem entry is forbidden",
                        )
                    )
            except OSError:
                findings.append(
                    _finding(
                        display, "read-error", "filesystem entry could not be audited"
                    )
                )

    visit(root, Path())
    return tuple(findings)


def _unsafe_archive_path(name: str, is_directory: bool) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return True
    candidate = name[:-1] if is_directory and name.endswith("/") else name
    if (
        not candidate
        or PurePosixPath(candidate).is_absolute()
        or PureWindowsPath(candidate).is_absolute()
    ):
        return True
    if PureWindowsPath(candidate).drive:
        return True
    components = candidate.split("/")
    return any(component in ("", ".", "..") for component in components)


def _audit_zip_bytes(
    label: str,
    data: bytes,
    *,
    budget: _ArchiveBudget,
    depth: int,
    ancestors: frozenset[bytes],
    max_compression_ratio: int = DEFAULT_MAX_COMPRESSION_RATIO,
) -> tuple[AuditFinding, ...]:
    findings: list[AuditFinding] = []
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as handle:
            members = handle.infolist()
            seen: set[str] = set()
            for member in members:
                member_label = f"{label}!{member.filename or '<empty>'}"
                limit = budget.consume(member_label, member.file_size)
                if limit is not None:
                    findings.append(limit)
                    return tuple(findings)
                findings.extend(_path_findings(member_label))
                if _unsafe_archive_path(member.filename, member.is_dir()):
                    findings.append(
                        _finding(
                            member_label,
                            "unsafe-archive-path",
                            "archive path is absolute or traverses directories",
                        )
                    )
                    continue
                canonical = member.filename.rstrip("/").casefold()
                if canonical in seen:
                    findings.append(
                        _finding(
                            member_label,
                            "duplicate-archive-path",
                            "archive contains a duplicate or case-colliding path",
                        )
                    )
                    continue
                seen.add(canonical)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    findings.append(
                        _finding(
                            member_label, "symlink", "archive symbolic links are forbidden"
                        )
                    )
                    continue
                file_type = stat.S_IFMT(mode)
                if file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR):
                    findings.append(
                        _finding(
                            member_label,
                            "archive-special-file",
                            "non-regular archive member is forbidden",
                        )
                    )
                    continue
                if member.is_dir():
                    continue
                if member.flag_bits & 0x1:
                    findings.append(
                        _finding(
                            member_label,
                            "encrypted-archive-member",
                            "encrypted archive members cannot be audited",
                        )
                    )
                    continue
                ratio = member.file_size / max(member.compress_size, 1)
                if member.file_size >= 1024 * 1024 and ratio > max_compression_ratio:
                    findings.append(
                        _finding(
                            member_label,
                            "archive-compression-ratio",
                            "archive member has an unsafe expansion ratio",
                        )
                    )
                    continue
                try:
                    with handle.open(member) as source:
                        member_data = source.read(member.file_size + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    findings.append(
                        _finding(
                            member_label,
                            "archive-read-error",
                            "archive member could not be audited",
                        )
                    )
                    continue
                if len(member_data) != member.file_size:
                    findings.append(
                        _finding(
                            member_label,
                            "archive-read-error",
                            "archive member length is inconsistent",
                        )
                    )
                    continue
                findings.extend(
                    _audit_member_data(
                        member_label,
                        member_data,
                        budget=budget,
                        depth=depth + 1,
                        ancestors=ancestors,
                    )
                )
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        findings.append(
            _finding(
                label,
                "invalid-archive",
                "ZIP archive could not be parsed safely",
            )
        )
    return tuple(findings)


def audit_zip(
    archive: Path,
    *,
    max_member_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_ARCHIVE_SIZE,
    max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS,
    max_compression_ratio: int = DEFAULT_MAX_COMPRESSION_RATIO,
) -> tuple[AuditFinding, ...]:
    try:
        if archive.stat().st_size > max_total_size:
            return (_finding(archive.name, "archive-budget", "archive exceeds bounded input size"),)
        data = archive.read_bytes()
    except OSError:
        return (_finding(archive.name, "invalid-archive", "ZIP archive could not be parsed safely"),)
    if len(data) > max_total_size:
        return (_finding(archive.name, "archive-budget", "archive exceeds bounded input size"),)
    budget = _ArchiveBudget(
        max_bytes=max_total_size,
        max_members=max_members,
        max_member_size=max_member_size,
    )
    if _expected_archive_magic(archive.name) != _archive_magic(data):
        return (_finding(archive.name, "archive-magic-mismatch", "archive/compression magic and filename suffix do not match"),)
    return _audit_zip_bytes(
        archive.name,
        data,
        budget=budget,
        depth=0,
        ancestors=frozenset({hashlib.sha256(data).digest()}),
        max_compression_ratio=max_compression_ratio,
    )


def _run_git(
    root: Path, arguments: list[str], *, text: bool = False
) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=text,
    )


def _same_filesystem_entry(left: Path, right: Path) -> bool:
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _validated_git_metadata_entry(root: Path) -> Path | None:
    try:
        resolved_root = root.resolve(strict=True)
        top_level = _run_git(
            root, ["rev-parse", "--show-toplevel"], text=True
        ).stdout.strip()
        absolute_git_dir = _run_git(
            root,
            ["rev-parse", "--absolute-git-dir"],
            text=True,
        ).stdout.strip()
        if (
            not top_level
            or not absolute_git_dir
            or Path(top_level).resolve(strict=True) != resolved_root
        ):
            return None

        git_dir = Path(absolute_git_dir).resolve(strict=True)
        metadata_entry = resolved_root / ".git"
        if metadata_entry.is_symlink():
            return None
        if metadata_entry.is_dir():
            return (
                metadata_entry
                if _same_filesystem_entry(metadata_entry, git_dir)
                else None
            )
        if not metadata_entry.is_file():
            return None

        with metadata_entry.open("rb") as source:
            gitfile = source.read(4097)
        if len(gitfile) > 4096:
            return None
        gitfile = gitfile.removesuffix(b"\n").removesuffix(b"\r")
        prefix = b"gitdir: "
        if not gitfile.startswith(prefix) or b"\n" in gitfile or b"\r" in gitfile:
            return None
        target_text = os.fsdecode(gitfile[len(prefix) :])
        if not target_text or "\x00" in target_text:
            return None
        target = Path(target_text)
        if not target.is_absolute():
            target = metadata_entry.parent / target
        return metadata_entry if _same_filesystem_entry(target, git_dir) else None
    except (OSError, ValueError, subprocess.CalledProcessError):
        return None


def audit_git_history(
    root: Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    max_commits: int = DEFAULT_MAX_COMMIT_COUNT,
) -> tuple[AuditFinding, ...]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"Git history root is not a directory: {root}")
    try:
        repository_check = _run_git(
            root, ["rev-parse", "--is-inside-work-tree"], text=True
        )
        if repository_check.stdout.strip() != "true":
            raise ValueError(f"not a Git worktree: {root}")
        commits_output = _run_git(
            root, ["rev-list", "--all", f"--max-count={max_commits + 1}"], text=True
        ).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"unable to inspect Git history at {root}") from exc
    commits = commits_output.splitlines()
    findings: list[AuditFinding] = []
    if len(commits) > max_commits:
        findings.append(
            _finding(
                "<git-history>",
                "git-commit-count",
                "history exceeds the safe audit commit limit",
            )
        )
        commits = commits[:max_commits]

    for commit in commits:
        message_path = f"{commit}:<commit-message>"
        try:
            message = _run_git(root, ["show", "-s", "--format=%B", commit]).stdout
        except (OSError, subprocess.CalledProcessError):
            findings.append(
                _finding(
                    message_path,
                    "git-read-error",
                    "Git commit message could not be audited",
                )
            )
        else:
            findings.extend(
                AuditFinding(message_path, finding.rule, finding.detail)
                for finding in audit_bytes("<commit-message>", message)
            )
        try:
            tree = _run_git(
                root, ["ls-tree", "-rz", "--full-tree", "--long", commit]
            ).stdout
        except (OSError, subprocess.CalledProcessError):
            findings.append(
                _finding(
                    f"{commit}:<tree>",
                    "git-read-error",
                    "Git tree could not be audited",
                )
            )
            continue
        for record in tree.split(b"\x00"):
            if not record:
                continue
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, _object_id, raw_size = metadata.split(b" ", 3)
                path = os.fsdecode(raw_path)
            except ValueError:
                findings.append(
                    _finding(
                        f"{commit}:<tree>",
                        "git-read-error",
                        "malformed Git tree record",
                    )
                )
                continue
            display = f"{commit}:{path}"
            findings.extend(
                AuditFinding(f"{commit}:{finding.path}", finding.rule, finding.detail)
                for finding in _path_findings(path)
            )
            if mode == b"120000":
                findings.append(
                    _finding(display, "symlink", "Git history contains a symbolic link")
                )
                continue
            if object_type != b"blob":
                findings.append(
                    _finding(
                        display,
                        "special-git-entry",
                        "Git history contains a non-file entry",
                    )
                )
                continue
            try:
                size = int(raw_size)
            except ValueError:
                findings.append(
                    _finding(
                        display, "git-read-error", "Git blob size could not be read"
                    )
                )
                continue
            if size > max_file_size:
                findings.append(
                    _finding(
                        display,
                        "file-size",
                        "Git blob exceeds the safe audit size limit",
                    )
                )
                continue
            try:
                data = _run_git(root, ["show", f"{commit}:{path}"]).stdout
            except (OSError, subprocess.CalledProcessError):
                findings.append(
                    _finding(display, "git-read-error", "Git blob could not be audited")
                )
                continue
            findings.extend(
                AuditFinding(f"{commit}:{finding.path}", finding.rule, finding.detail)
                for finding in _audit_content_bytes(path, data)
            )
    return tuple(findings)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit a private release directory or ZIP for forbidden content"
    )
    parser.add_argument(
        "source", nargs="?", type=Path, help="directory or ZIP archive to audit"
    )
    parser.add_argument(
        "--git-history",
        action="store_true",
        help="also audit every commit reachable from all refs",
    )
    parser.add_argument("--canonical-source-repository", type=Path)
    parser.add_argument("--canonical-source-commit")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.source is None:
            raise ValueError("provide a private release directory or ZIP archive")
        source = arguments.source
        if source.is_dir():
            findings = audit_directory(
                source,
                ignored_root_entry=(
                    _validated_git_metadata_entry(source)
                    if arguments.git_history
                    else None
                ),
                canonical_source_repository=arguments.canonical_source_repository,
                canonical_source_commit=arguments.canonical_source_commit,
            )
            if arguments.git_history:
                findings += audit_git_history(source)
        elif arguments.git_history or arguments.canonical_source_repository is not None or arguments.canonical_source_commit is not None:
            raise ValueError("history and canonical Source0 checks require a directory")
        else:
            findings = audit_zip(source)
    except (OSError, ValueError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2

    findings = tuple(
        sorted(
            findings,
            key=lambda item: (item.path.encode("utf-8"), item.rule, item.detail),
        )
    )
    for finding in findings:
        print(f"{finding.rule} {finding.path}: {finding.detail}")
    if findings:
        print(f"audit blocked: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("audit passed: zero findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
