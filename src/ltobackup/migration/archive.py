"""Deterministic canonical bundle for the Linux migration importer."""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import tempfile
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import BinaryIO

from .models import AcceptanceReport, MigrationRejected
from .validator import MigrationValidator, ReadOnlyCatalog

CANONICAL_MEMBERS = (
    "SHA256SUMS",
    "acceptance.json",
    "catalog.db",
    "provenance.json",
)
CANONICAL_PAYLOAD_MEMBERS = CANONICAL_MEMBERS[1:]

_SOURCE_HASH_MEMBERS = frozenset(
    {
        "catalog-closed-consistent.db",
        "catalog-closed-source.db",
        "catalog-export.json",
        "config.json",
        "lto-backup.log",
        "ltfs-mount.log",
    }
)
_MAX_BUNDLE_MEMBER_BYTES = {
    "SHA256SUMS": 64 * 1024,
    "acceptance.json": 1024 * 1024,
    "catalog.db": 32 * 1024 * 1024,
    "provenance.json": 1024 * 1024,
}
MAX_CANONICAL_BUNDLE_BYTES = sum(_MAX_BUNDLE_MEMBER_BYTES.values()) + 16 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_CHECKSUM_LINE_PATTERN = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def checksum_lines(members: Mapping[str, bytes]) -> bytes:
    if set(members) != set(CANONICAL_PAYLOAD_MEMBERS):
        raise MigrationRejected("bundle-members-invalid")
    return "".join(
        f"{sha256_bytes(members[name])}  {name}\n" for name in CANONICAL_PAYLOAD_MEMBERS
    ).encode("ascii")


@dataclass(frozen=True)
class VerifiedBundle:
    path: Path
    member_names: tuple[str, ...]
    bundle_sha256: str
    catalog_sha256: str
    acceptance: AcceptanceReport
    provenance: Mapping[str, object]
    _catalog_bytes: bytes

    def extract_catalog(self, destination: Path) -> Path:
        destination = Path(destination)
        try:
            with _open_exclusive_private(destination) as handle:
                handle.write(self._catalog_bytes)
        except FileExistsError as exc:
            raise MigrationRejected("destination-exists") from exc
        except OSError as exc:
            raise MigrationRejected("catalog-extraction-failed") from exc
        return destination


def write_canonical_bundle(destination: Path, members: Mapping[str, bytes]) -> Path:
    destination = Path(destination)
    if set(members) != set(CANONICAL_MEMBERS):
        raise MigrationRejected("bundle-members-invalid")
    if any(
        len(members[name]) > _MAX_BUNDLE_MEMBER_BYTES[name]
        for name in CANONICAL_MEMBERS
    ):
        raise MigrationRejected("bundle-member-too-large")
    try:
        with _open_exclusive_private(destination) as raw:
            _write_canonical_zip(raw, members)
    except FileExistsError as exc:
        raise MigrationRejected("destination-exists") from exc
    except MigrationRejected:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise MigrationRejected("bundle-write-failed") from exc
    return destination


def _write_canonical_zip(destination: BinaryIO, members: Mapping[str, bytes]) -> None:
    with zipfile.ZipFile(
        destination,
        mode="w",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
    ) as archive:
        archive.comment = b""
        for name in CANONICAL_MEMBERS:
            payload = members[name]
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            info.extra = b""
            info.comment = b""
            archive.writestr(info, payload)


def _canonical_bundle_bytes(members: Mapping[str, bytes]) -> bytes:
    output = io.BytesIO()
    _write_canonical_zip(output, members)
    return output.getvalue()


def _open_exclusive_private(path: Path) -> io.BufferedWriter:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        return os.fdopen(descriptor, "wb")
    except BaseException:
        os.close(descriptor)
        raise


def read_bundle(path: Path) -> VerifiedBundle:
    path = Path(path)
    try:
        bundle_bytes = _read_bounded_regular_file(path)
        with zipfile.ZipFile(io.BytesIO(bundle_bytes), mode="r") as archive:
            if archive.comment:
                raise MigrationRejected("bundle-metadata-invalid")
            members: dict[str, bytes] = {}
            seen: set[str] = set()
            for info in archive.infolist():
                name = info.filename
                if name in seen:
                    raise MigrationRejected("bundle-member-duplicate")
                seen.add(name)
                if name not in CANONICAL_MEMBERS or not _safe_member_name(name):
                    raise MigrationRejected("bundle-member-name-invalid")
                if info.flag_bits & 0x1:
                    raise MigrationRejected("bundle-member-encrypted")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise MigrationRejected("bundle-compression-invalid")
                mode_type = stat.S_IFMT(info.external_attr >> 16)
                if info.is_dir() or mode_type not in {0, stat.S_IFREG}:
                    raise MigrationRejected("bundle-member-type-invalid")
                if (
                    info.file_size < 0
                    or info.file_size > _MAX_BUNDLE_MEMBER_BYTES[name]
                    or info.compress_size != info.file_size
                ):
                    raise MigrationRejected("bundle-member-too-large")
                payload = archive.read(info)
                if len(payload) != info.file_size:
                    raise MigrationRejected("bundle-member-size-invalid")
                members[name] = payload
    except MigrationRejected:
        raise
    except (OSError, EOFError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise MigrationRejected("bundle-malformed") from exc

    if tuple(sorted(members)) != CANONICAL_MEMBERS:
        raise MigrationRejected("bundle-members-invalid")
    declared = _parse_checksums(
        members["SHA256SUMS"],
        frozenset(CANONICAL_PAYLOAD_MEMBERS),
        "bundle-checksums-invalid",
    )
    for name in CANONICAL_PAYLOAD_MEMBERS:
        if declared[name] != sha256_bytes(members[name]):
            raise MigrationRejected("bundle-member-sha256-mismatch")

    acceptance = _acceptance_report(members["acceptance.json"])
    provenance = _provenance(members["provenance.json"])
    catalog_sha256 = sha256_bytes(members["catalog.db"])
    if provenance["authoritative_catalog_sha256"] != catalog_sha256:
        raise MigrationRejected("bundle-catalog-provenance-mismatch")
    _validate_catalog_bytes(members["catalog.db"], acceptance)
    if bundle_bytes != _canonical_bundle_bytes(members):
        raise MigrationRejected("bundle-noncanonical")
    return VerifiedBundle(
        path=path,
        member_names=CANONICAL_MEMBERS,
        bundle_sha256=sha256_bytes(bundle_bytes),
        catalog_sha256=catalog_sha256,
        acceptance=acceptance,
        provenance=provenance,
        _catalog_bytes=members["catalog.db"],
    )


def _read_bounded_regular_file(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise MigrationRejected("bundle-not-regular") from exc
        raise MigrationRejected("bundle-unreadable") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise MigrationRejected("bundle-not-regular")
        if before.st_size > MAX_CANONICAL_BUNDLE_BYTES:
            raise MigrationRejected("bundle-size-limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(MAX_CANONICAL_BUNDLE_BYTES + 1)
        if len(payload) > MAX_CANONICAL_BUNDLE_BYTES:
            raise MigrationRejected("bundle-size-limit")
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if identity_before != identity_after or len(payload) != before.st_size:
            raise MigrationRejected("bundle-changed-during-read")
        return payload
    finally:
        os.close(descriptor)


def _safe_member_name(name: str) -> bool:
    posix = PurePosixPath(name)
    windows = PureWindowsPath(name)
    return bool(
        name
        and "\x00" not in name
        and "\\" not in name
        and not posix.is_absolute()
        and not windows.is_absolute()
        and not windows.drive
        and not windows.root
        and all(part not in {"", ".", ".."} for part in posix.parts)
    )


def _parse_checksums(
    payload: bytes, expected_names: frozenset[str], error_code: str
) -> dict[str, str]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MigrationRejected(error_code) from exc
    if not text or not text.endswith("\n"):
        raise MigrationRejected(error_code)
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = _CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            raise MigrationRejected(error_code)
        digest, name = match.groups()
        if name in result or name not in expected_names:
            raise MigrationRejected(error_code)
        result[name] = digest
    if set(result) != set(expected_names):
        raise MigrationRejected(error_code)
    return result


def _strict_json_object(payload: bytes, error_code: str) -> dict[str, object]:
    def reject_constant(value: str) -> object:
        raise ValueError(value)

    try:
        value = json.loads(payload.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationRejected(error_code) from exc
    if not isinstance(value, dict):
        raise MigrationRejected(error_code)
    return value


def _acceptance_report(payload: bytes) -> AcceptanceReport:
    value = _strict_json_object(payload, "bundle-acceptance-invalid")
    expected_keys = {
        "job_id",
        "accepted",
        "next_sequence",
        "total_cassettes",
        "completed_sequences",
        "assignment_sha256",
        "error_codes",
        "media_accesses",
    }
    if set(value) != expected_keys:
        raise MigrationRejected("bundle-acceptance-invalid")
    completed = value["completed_sequences"]
    errors = value["error_codes"]
    media = value["media_accesses"]
    if (
        not isinstance(value["job_id"], str)
        or not value["job_id"]
        or value["accepted"] is not True
        or not isinstance(value["next_sequence"], int)
        or isinstance(value["next_sequence"], bool)
        or not isinstance(value["total_cassettes"], int)
        or isinstance(value["total_cassettes"], bool)
        or not isinstance(completed, list)
        or any(
            not isinstance(item, int) or isinstance(item, bool) for item in completed
        )
        or not isinstance(value["assignment_sha256"], str)
        or _SHA256_PATTERN.fullmatch(value["assignment_sha256"]) is None
        or not isinstance(errors, list)
        or any(not isinstance(item, str) for item in errors)
        or errors
        or not isinstance(media, list)
        or any(not isinstance(item, str) for item in media)
        or media
    ):
        raise MigrationRejected("bundle-acceptance-invalid")
    return AcceptanceReport(
        job_id=value["job_id"],
        accepted=True,
        next_sequence=value["next_sequence"],
        total_cassettes=value["total_cassettes"],
        completed_sequences=tuple(completed),
        assignment_sha256=value["assignment_sha256"],
        error_codes=tuple(errors),
        media_accesses=tuple(media),
    )


def _provenance(payload: bytes) -> dict[str, object]:
    value = _strict_json_object(payload, "bundle-provenance-invalid")
    expected_keys = {
        "format_version",
        "source_archive_sha256",
        "authoritative_catalog_sha256",
        "source_catalog_sha256",
        "source_member_sha256",
        "capture_summary_sha256",
        "capture_checksums_sha256",
    }
    hashes = value.get("source_member_sha256")
    if (
        set(value) != expected_keys
        or value["format_version"] != 1
        or isinstance(value["format_version"], bool)
        or not isinstance(hashes, dict)
        or set(hashes) != _SOURCE_HASH_MEMBERS
    ):
        raise MigrationRejected("bundle-provenance-invalid")
    for key in expected_keys - {"format_version", "source_member_sha256"}:
        digest = value[key]
        if not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None:
            raise MigrationRejected("bundle-provenance-invalid")
    if any(
        not isinstance(digest, str) or _SHA256_PATTERN.fullmatch(digest) is None
        for digest in hashes.values()
    ):
        raise MigrationRejected("bundle-provenance-invalid")
    if (
        value["authoritative_catalog_sha256"] != hashes["catalog-closed-consistent.db"]
        or value["source_catalog_sha256"] != hashes["catalog-closed-source.db"]
    ):
        raise MigrationRejected("bundle-provenance-invalid")
    return value


def _validate_catalog_bytes(payload: bytes, expected: AcceptanceReport) -> None:
    with tempfile.TemporaryDirectory(prefix="lto-bundle-read-") as temporary:
        catalog_path = Path(temporary) / "catalog.db"
        catalog_path.write_bytes(payload)
        try:
            with ReadOnlyCatalog(catalog_path) as catalog:
                job_ids = tuple(
                    row[0]
                    for row in catalog.connection.execute(
                        "SELECT id FROM automatic_jobs ORDER BY id"
                    )
                )
                if job_ids != (expected.job_id,):
                    raise MigrationRejected("bundle-job-count-invalid")
                actual = MigrationValidator.inspect(catalog, expected.job_id)
        except sqlite3.DatabaseError as exc:
            raise MigrationRejected("bundle-catalog-invalid") from exc
    actual.require_valid()
    if actual != expected:
        raise MigrationRejected("bundle-acceptance-mismatch")
