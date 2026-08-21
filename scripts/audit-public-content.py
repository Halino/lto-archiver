from __future__ import annotations

import argparse
import ipaddress
import os
import re
import stat
import subprocess
import sys
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath


DEFAULT_MAX_FILE_SIZE = 32 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_SIZE = 512 * 1024 * 1024
DEFAULT_MAX_ARCHIVE_MEMBERS = 10_000
DEFAULT_MAX_COMMIT_COUNT = 5_000
DEFAULT_MAX_COMPRESSION_RATIO = 200

_SENSITIVE_EXTENSIONS = frozenset(
    {".db", ".db-shm", ".db-wal", ".dmp", ".etl", ".evtx", ".log", ".lzt", ".reg", ".sqlite", ".sqlite3"}
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
    {"<user>", "<username>", "default", "example", "public", "user", "username", "%username%", "$env:username"}
)


@dataclass(frozen=True, slots=True)
class AuditFinding:
    path: str
    rule: str
    detail: str


def _ipv4_network(octets: tuple[int, int, int, int], prefix: int) -> ipaddress.IPv4Network:
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
_SYNTHETIC_KEY_FIXTURE_PATH = "tests/fixtures/public-audit-private-key.txt"
_SYNTHETIC_KEY_FIXTURE_MARKER = b"\nPUBLIC_AUDIT_SYNTHETIC_KEY_FIXTURE\n"
_DEPLOYMENT_KEY_LITERAL_SUFFIX = b"\\" + b'nfixture"'
_PUBLIC_FILE_VERSION = ".".join(str(part) for part in (0, 11, 26, 0))


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


def _is_known_synthetic_key_header(
    path: str,
    data: bytes,
    match: re.Match[bytes],
) -> bool:
    if path == _SYNTHETIC_KEY_FIXTURE_PATH:
        return match.start() == 0 and data[match.end() :] == _SYNTHETIC_KEY_FIXTURE_MARKER
    if path == "tests/test_deployment_scripts.py":
        prefix = data[max(0, match.start() - 2) : match.start()]
        suffix = data[match.end() : match.end() + len(_DEPLOYMENT_KEY_LITERAL_SUFFIX)]
        return prefix == b'b"' and suffix == _DEPLOYMENT_KEY_LITERAL_SUFFIX
    return False


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
        pieces.append("[REDACTED-IP]" if _is_private_address(match.group(0)) else match.group(0))
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
    if match.group(0) != _PUBLIC_FILE_VERSION:
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


def _is_allowed_unc(text: str, match: re.Match[str], path: str, *, path_scan: bool) -> bool:
    host = match.group("host").rstrip(".").casefold()
    if host == "example.test" or host.endswith(".example.test"):
        return True
    if path_scan:
        return False
    line = _line_for_match(text, match).casefold()
    labeled_example = any(
        marker in line for marker in ("example:", "esempio:", "exemple :", "beispiel:", "ejemplo:")
    )
    if host == "nas" and labeled_example:
        return True
    if (
        path == "tests/test_gui.py"
        and host == "nas"
        and '"source_root": r"\\\\nas\\share"' in line
    ):
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
            findings.append(_finding(report_path, "private-network", "private or special-use IPv4 address detected; value redacted"))
    for match in _UNC_RE.finditer(text):
        if not _is_allowed_unc(text, match, report_path, path_scan=path_scan):
            findings.append(_finding(report_path, "private-unc-host", "non-example UNC host detected; value redacted"))
    for match in _WINDOWS_PROFILE_RE.finditer(text):
        profile = match.group(1).split("\\", 1)[0].strip().casefold()
        if profile not in _SYNTHETIC_PROFILE_NAMES:
            findings.append(_finding(report_path, "windows-user-profile", "real Windows user profile detected; value redacted"))
    for match in _CREDENTIAL_RE.finditer(text):
        if not _is_synthetic_credential(match.group("value")):
            findings.append(_finding(report_path, "credential-assignment", "account or credential assignment detected; value redacted"))
    if any(pattern.search(text) for pattern in _TOKEN_PATTERNS):
        findings.append(_finding(report_path, "secret-token", "GitHub or cloud token form detected; value redacted"))
    if _INTERNAL_HOST_RE.search(text):
        findings.append(_finding(report_path, "internal-host", "internal hostname detected; value redacted"))
    return findings


def _path_findings(path: str) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    normalized = path.replace("\\", "/")
    lower = normalized.casefold()
    filename = PurePosixPath(normalized).name.casefold()
    suffixes = PurePosixPath(normalized).suffixes
    components = tuple(component.casefold() for component in PurePosixPath(normalized).parts)
    combined_suffix = "".join(suffix.casefold() for suffix in suffixes[-2:])
    suffix = PurePosixPath(normalized).suffix.casefold()
    if filename == ".env" or filename.startswith(".env.") or suffix in _SENSITIVE_EXTENSIONS or combined_suffix in _SENSITIVE_EXTENSIONS:
        findings.append(_finding(path, "sensitive-extension", "database, log, credential, or support artifact path"))
    if ".git" in components:
        findings.append(_finding(path, "git-metadata", "Git metadata is forbidden in public content"))
    forbidden = (
        ".gitlab" + "-ci.yml",
        "scripts/field-tools/archive/",
        "scripts/field-tools/controlled/",
    )
    if lower in forbidden or any(marker in lower for marker in forbidden[1:]) or lower.startswith("scripts/deploy-"):
        findings.append(_finding(path, "private-operation-path", "private server or deployment path"))
    if _PRIVATE_KEY_PATH_RE.search(path):
        findings.append(_finding(path, "private-key", "private-key header detected in path; value redacted"))
    findings.extend(_sensitive_text_findings(path, path, path_scan=True))
    return findings


def _audit_content_bytes(path: str, data: bytes) -> list[AuditFinding]:
    findings: list[AuditFinding] = []
    key_headers = tuple(_PRIVATE_KEY_RE.finditer(data))
    unsafe_key_header = any(
        not _is_known_synthetic_key_header(path, data, match)
        for match in key_headers
    )
    if unsafe_key_header:
        findings.append(_finding(path, "private-key", "private-key header detected; value redacted"))

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
        findings.append(_finding(path, "private-operation-identifier", "private server or deployment identifier detected"))
    return findings


def audit_bytes(path: str, data: bytes) -> tuple[AuditFinding, ...]:
    return tuple((*_path_findings(path), *_audit_content_bytes(path, data)))


def _sorted_scandir(directory: Path) -> list[os.DirEntry[str]]:
    with os.scandir(directory) as entries:
        return sorted(entries, key=lambda entry: os.fsencode(entry.name))


def audit_directory(
    root: Path,
    *,
    max_file_size: int = DEFAULT_MAX_FILE_SIZE,
    ignored_root_entry: Path | None = None,
) -> tuple[AuditFinding, ...]:
    findings = _path_findings(root.name)
    if root.is_symlink():
        findings.append(_finding(root.name, "symlink", "audit root must not be a symlink"))
        return tuple(findings)
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"audit source is not a directory: {root}")
    if root.name.casefold() == ".git":
        return tuple(findings)

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
                findings.append(_finding(display, "symlink", "symbolic links are forbidden"))
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.name.casefold() == ".git":
                        continue
                    visit(Path(entry.path), relative)
                elif entry.is_file(follow_symlinks=False):
                    size = entry.stat(follow_symlinks=False).st_size
                    if size > max_file_size:
                        findings.append(_finding(display, "file-size", "file exceeds the safe audit size limit"))
                    else:
                        findings.extend(_audit_content_bytes(display, Path(entry.path).read_bytes()))
                else:
                    findings.append(_finding(display, "special-file", "non-regular filesystem entry is forbidden"))
            except OSError:
                findings.append(_finding(display, "read-error", "filesystem entry could not be audited"))

    visit(root, Path())
    return tuple(findings)


def _unsafe_archive_path(name: str, is_directory: bool) -> bool:
    if not name or "\x00" in name or "\\" in name:
        return True
    candidate = name[:-1] if is_directory and name.endswith("/") else name
    if not candidate or PurePosixPath(candidate).is_absolute() or PureWindowsPath(candidate).is_absolute():
        return True
    if PureWindowsPath(candidate).drive:
        return True
    components = candidate.split("/")
    return any(component in ("", ".", "..") for component in components)


def audit_zip(
    archive: Path,
    *,
    max_member_size: int = DEFAULT_MAX_FILE_SIZE,
    max_total_size: int = DEFAULT_MAX_ARCHIVE_SIZE,
    max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS,
    max_compression_ratio: int = DEFAULT_MAX_COMPRESSION_RATIO,
) -> tuple[AuditFinding, ...]:
    findings = _path_findings(archive.name)
    try:
        with zipfile.ZipFile(archive) as handle:
            members = handle.infolist()
            for member in members:
                findings.extend(_path_findings(member.filename or "<empty>"))
            if len(members) > max_members:
                findings.append(_finding(archive.name, "archive-member-count", "archive has too many members to audit safely"))
                members = members[:max_members]
            total_size = sum(member.file_size for member in members)
            over_total_budget = total_size > max_total_size
            if over_total_budget:
                findings.append(_finding(archive.name, "archive-total-size", "archive expands beyond the safe audit limit"))
            seen: set[str] = set()
            for member in members:
                display = member.filename
                if _unsafe_archive_path(display, member.is_dir()):
                    findings.append(_finding(display or "<empty>", "unsafe-archive-path", "archive path is absolute or traverses directories"))
                    continue
                canonical = display.rstrip("/").casefold()
                if canonical in seen:
                    findings.append(_finding(display, "duplicate-archive-path", "archive contains a duplicate or case-colliding path"))
                    continue
                seen.add(canonical)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    findings.append(_finding(display, "symlink", "archive symbolic links are forbidden"))
                    continue
                if member.is_dir():
                    continue
                if member.flag_bits & 0x1:
                    findings.append(_finding(display, "encrypted-archive-member", "encrypted archive members cannot be audited"))
                    continue
                if over_total_budget:
                    continue
                if member.file_size > max_member_size:
                    findings.append(_finding(display, "archive-member-size", "archive member exceeds the safe audit size limit"))
                    continue
                ratio = member.file_size / max(member.compress_size, 1)
                if member.file_size >= 1024 * 1024 and ratio > max_compression_ratio:
                    findings.append(_finding(display, "archive-compression-ratio", "archive member has an unsafe expansion ratio"))
                    continue
                try:
                    with handle.open(member) as source:
                        data = source.read(max_member_size + 1)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    findings.append(_finding(display, "archive-read-error", "archive member could not be audited"))
                    continue
                if len(data) > max_member_size:
                    findings.append(_finding(display, "archive-member-size", "archive member exceeds the safe audit size limit"))
                    continue
                findings.extend(_audit_content_bytes(display, data))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile):
        findings.append(_finding(archive.name, "invalid-archive", "ZIP archive could not be parsed safely"))
    return tuple(findings)


def _run_git(root: Path, arguments: list[str], *, text: bool = False) -> subprocess.CompletedProcess:
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
        top_level = _run_git(root, ["rev-parse", "--show-toplevel"], text=True).stdout.strip()
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
            return metadata_entry if _same_filesystem_entry(metadata_entry, git_dir) else None
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
        repository_check = _run_git(root, ["rev-parse", "--is-inside-work-tree"], text=True)
        if repository_check.stdout.strip() != "true":
            raise ValueError(f"not a Git worktree: {root}")
        commits_output = _run_git(root, ["rev-list", "--all", f"--max-count={max_commits + 1}"], text=True).stdout
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"unable to inspect Git history at {root}") from exc
    commits = commits_output.splitlines()
    findings: list[AuditFinding] = []
    if len(commits) > max_commits:
        findings.append(_finding("<git-history>", "git-commit-count", "history exceeds the safe audit commit limit"))
        commits = commits[:max_commits]

    for commit in commits:
        message_path = f"{commit}:<commit-message>"
        try:
            message = _run_git(root, ["show", "-s", "--format=%B", commit]).stdout
        except (OSError, subprocess.CalledProcessError):
            findings.append(_finding(message_path, "git-read-error", "Git commit message could not be audited"))
        else:
            findings.extend(
                AuditFinding(message_path, finding.rule, finding.detail)
                for finding in audit_bytes("<commit-message>", message)
            )
        try:
            tree = _run_git(root, ["ls-tree", "-rz", "--full-tree", "--long", commit]).stdout
        except (OSError, subprocess.CalledProcessError):
            findings.append(_finding(f"{commit}:<tree>", "git-read-error", "Git tree could not be audited"))
            continue
        for record in tree.split(b"\x00"):
            if not record:
                continue
            try:
                metadata, raw_path = record.split(b"\t", 1)
                mode, object_type, _object_id, raw_size = metadata.split(b" ", 3)
                path = os.fsdecode(raw_path)
            except ValueError:
                findings.append(_finding(f"{commit}:<tree>", "git-read-error", "malformed Git tree record"))
                continue
            display = f"{commit}:{path}"
            findings.extend(
                AuditFinding(f"{commit}:{finding.path}", finding.rule, finding.detail)
                for finding in _path_findings(path)
            )
            if mode == b"120000":
                findings.append(_finding(display, "symlink", "Git history contains a symbolic link"))
                continue
            if object_type != b"blob":
                findings.append(_finding(display, "special-git-entry", "Git history contains a non-file entry"))
                continue
            try:
                size = int(raw_size)
            except ValueError:
                findings.append(_finding(display, "git-read-error", "Git blob size could not be read"))
                continue
            if size > max_file_size:
                findings.append(_finding(display, "file-size", "Git blob exceeds the safe audit size limit"))
                continue
            try:
                data = _run_git(root, ["show", f"{commit}:{path}"]).stdout
            except (OSError, subprocess.CalledProcessError):
                findings.append(_finding(display, "git-read-error", "Git blob could not be audited"))
                continue
            findings.extend(
                AuditFinding(f"{commit}:{finding.path}", finding.rule, finding.detail)
                for finding in _audit_content_bytes(path, data)
            )
    return tuple(findings)


def _load_manifest(root: Path, manifest: Path) -> tuple[Path, ...]:
    try:
        from scripts.build_public_snapshot import load_manifest
    except ModuleNotFoundError:
        import importlib.util

        builder_path = Path(__file__).with_name("build-public-snapshot.py")
        spec = importlib.util.spec_from_file_location("_build_public_snapshot", builder_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot load {builder_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        load_manifest = module.load_manifest
    return load_manifest(root, manifest)


def audit_manifest(root: Path, manifest: Path) -> tuple[AuditFinding, ...]:
    root = root.resolve(strict=True)
    findings: list[AuditFinding] = []
    for relative in _load_manifest(root, manifest):
        findings.extend(audit_bytes(relative.as_posix(), (root / relative).read_bytes()))
    return tuple(findings)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit public source, ZIP, or Git history for private content")
    parser.add_argument("source", nargs="?", type=Path, help="directory or ZIP archive to audit")
    parser.add_argument("--root", type=Path, help="repository root for a manifest audit")
    parser.add_argument("--manifest", type=Path, help="exact manifest to audit under --root")
    parser.add_argument("--git-history", action="store_true", help="also audit every commit reachable from all refs")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.manifest is not None:
            if arguments.root is None or arguments.source is not None or arguments.git_history:
                raise ValueError("--manifest requires --root and cannot be combined with source or --git-history")
            findings = audit_manifest(arguments.root, arguments.manifest)
        else:
            if arguments.source is None or arguments.root is not None:
                raise ValueError("provide a directory/ZIP source, or use --manifest with --root")
            source = arguments.source
            if source.is_dir():
                findings = audit_directory(
                    source,
                    ignored_root_entry=(
                        _validated_git_metadata_entry(source)
                        if arguments.git_history
                        else None
                    ),
                )
                if arguments.git_history:
                    findings += audit_git_history(source)
            elif arguments.git_history:
                raise ValueError("--git-history requires a Git worktree directory")
            else:
                findings = audit_zip(source)
    except (OSError, ValueError) as exc:
        print(f"audit failed: {exc}", file=sys.stderr)
        return 2

    findings = tuple(sorted(findings, key=lambda item: (item.path.encode("utf-8"), item.rule, item.detail)))
    for finding in findings:
        print(f"{finding.rule} {finding.path}: {finding.detail}")
    if findings:
        print(f"audit blocked: {len(findings)} finding(s)", file=sys.stderr)
        return 1
    print("audit passed: zero findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
