"""Read-only normalization of the sealed Windows preservation capture."""

from __future__ import annotations

import io
import json
import os
import re
import sqlite3
import stat
import tarfile
import tempfile
import zlib
from dataclasses import asdict
from pathlib import Path, PurePosixPath, PureWindowsPath

from .archive import (
    VerifiedBundle,
    canonical_json,
    checksum_lines,
    read_bundle,
    sha256_bytes,
    write_canonical_bundle,
)
from .models import AcceptanceReport, MigrationRejected
from .validator import MigrationValidator, ReadOnlyCatalog

SEALED_CAPTURE_SHA256 = (
    "664c0a3a320bf789204895a552f28fcf60937dca93622cacd5a7407308b5b440"
)
CAPTURE_MEMBERS = frozenset(
    {
        "SHA256SUMS-post-close",
        "capture-summary-post-close.json",
        "catalog-closed-consistent.db",
        "catalog-closed-source.db",
        "catalog-export.json",
        "config.json",
        "lto-backup.log",
        "ltfs-mount.log",
    }
)
HASHED_CAPTURE_MEMBERS = CAPTURE_MEMBERS - {
    "SHA256SUMS-post-close",
    "capture-summary-post-close.json",
}
MAX_CAPTURE_MEMBER_BYTES = {
    "SHA256SUMS-post-close": 64 * 1024,
    "capture-summary-post-close.json": 1024 * 1024,
    "catalog-closed-consistent.db": 32 * 1024 * 1024,
    "catalog-closed-source.db": 32 * 1024 * 1024,
    "catalog-export.json": 8 * 1024 * 1024,
    "config.json": 1024 * 1024,
    "lto-backup.log": 8 * 1024 * 1024,
    "ltfs-mount.log": 8 * 1024 * 1024,
}
MAX_CAPTURE_TOTAL_BYTES = 40 * 1024 * 1024
MAX_CAPTURE_COMPRESSED_BYTES = 64 * 1024 * 1024
MAX_CAPTURE_STREAM_BYTES = MAX_CAPTURE_TOTAL_BYTES + 64 * 1024

_CHECKSUM_LINE_PATTERN = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
_SUMMARY_KEYS = {
    "captured_at_utc",
    "source_host",
    "application_version",
    "schema_version",
    "job",
    "quiescence",
    "validation",
    "catalog_files",
    "cutover_note",
}


def normalize_capture(
    source: Path,
    destination: Path,
    *,
    expected_archive_sha256: str = SEALED_CAPTURE_SHA256,
) -> VerifiedBundle:
    source = Path(source)
    destination = Path(destination)
    if destination.exists():
        raise MigrationRejected("destination-exists")
    if _SHA256_PATTERN.fullmatch(expected_archive_sha256) is None:
        raise MigrationRejected("expected-capture-sha256-invalid")

    capture_bytes = _read_source_once(source)
    archive_sha256 = sha256_bytes(capture_bytes)
    if archive_sha256 != expected_archive_sha256:
        raise MigrationRejected("capture-sha256-mismatch")
    members = _read_capture_members(capture_bytes)
    capture_hashes = _verify_capture_checksums(members)
    summary = _strict_summary_json(members["capture-summary-post-close.json"])
    acceptance = _validate_catalog_and_summary(
        members["catalog-closed-consistent.db"], summary, capture_hashes
    )

    provenance = {
        "format_version": 1,
        "source_archive_sha256": archive_sha256,
        "authoritative_catalog_sha256": capture_hashes["catalog-closed-consistent.db"],
        "source_catalog_sha256": capture_hashes["catalog-closed-source.db"],
        "source_member_sha256": {
            name: capture_hashes[name] for name in sorted(capture_hashes)
        },
        "capture_summary_sha256": sha256_bytes(
            members["capture-summary-post-close.json"]
        ),
        "capture_checksums_sha256": sha256_bytes(members["SHA256SUMS-post-close"]),
    }
    payloads = {
        "acceptance.json": canonical_json(asdict(acceptance)),
        "catalog.db": members["catalog-closed-consistent.db"],
        "provenance.json": canonical_json(provenance),
    }
    canonical_members = {"SHA256SUMS": checksum_lines(payloads), **payloads}
    write_canonical_bundle(destination, canonical_members)
    return read_bundle(destination)


def _read_source_once(source: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise MigrationRejected("capture-unreadable") from exc
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise MigrationRejected("capture-not-regular")
        if details.st_size > MAX_CAPTURE_COMPRESSED_BYTES:
            raise MigrationRejected("capture-size-limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            payload = handle.read(MAX_CAPTURE_COMPRESSED_BYTES + 1)
        if len(payload) > MAX_CAPTURE_COMPRESSED_BYTES:
            raise MigrationRejected("capture-size-limit")
        return payload
    finally:
        os.close(descriptor)


def _read_capture_members(capture_bytes: bytes) -> dict[str, bytes]:
    _validate_gzip_header(capture_bytes)
    tar_bytes = _validate_gzip_stream(capture_bytes)
    _validate_tar_layout(tar_bytes)
    members: dict[str, bytes] = {}
    total_size = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:") as archive:
            while True:
                member = archive.next()
                if member is None:
                    break
                name = member.name
                if not _safe_capture_name(name) or name not in CAPTURE_MEMBERS:
                    raise MigrationRejected("capture-member-name-invalid")
                if name in members:
                    raise MigrationRejected("capture-member-duplicate")
                if (
                    not member.isfile()
                    or member.type not in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    or member.linkname
                    or member.pax_headers
                    or member.offset_data != member.offset + tarfile.BLOCKSIZE
                ):
                    raise MigrationRejected("capture-member-type-invalid")
                if member.size < 0 or member.size > MAX_CAPTURE_MEMBER_BYTES[name]:
                    raise MigrationRejected("capture-member-too-large")
                total_size += member.size
                if total_size > MAX_CAPTURE_TOTAL_BYTES:
                    raise MigrationRejected("capture-size-limit")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise MigrationRejected("capture-member-type-invalid")
                payload = extracted.read(member.size + 1)
                if len(payload) != member.size:
                    raise MigrationRejected("capture-malformed")
                members[name] = payload
                if len(members) > len(CAPTURE_MEMBERS):
                    raise MigrationRejected("capture-members-invalid")
    except MigrationRejected:
        raise
    except (OSError, EOFError, ValueError, tarfile.TarError) as exc:
        raise MigrationRejected("capture-malformed") from exc
    if set(members) != CAPTURE_MEMBERS:
        raise MigrationRejected("capture-members-invalid")
    return members


def _validate_gzip_header(payload: bytes) -> None:
    if payload.startswith((b"-----BEGIN PGP MESSAGE-----", b"age-encryption.org/")):
        raise MigrationRejected("capture-encrypted-or-malformed")
    if len(payload) < 10 or payload[:2] != b"\x1f\x8b" or payload[2] != 8:
        raise MigrationRejected("capture-encrypted-or-malformed")
    if payload[3] & 0xE0:
        raise MigrationRejected("capture-encrypted-or-malformed")


def _validate_gzip_stream(payload: bytes) -> bytes:
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
        pending = payload
        total = 0
        chunks: list[bytes] = []
        while pending:
            room = MAX_CAPTURE_STREAM_BYTES + 1 - total
            if room <= 0:
                raise MigrationRejected("capture-size-limit")
            output = decoder.decompress(pending, room)
            chunks.append(output)
            total += len(output)
            if total > MAX_CAPTURE_STREAM_BYTES:
                raise MigrationRejected("capture-size-limit")
            if decoder.unused_data:
                raise MigrationRejected("capture-malformed")
            next_pending = decoder.unconsumed_tail
            if next_pending and len(next_pending) == len(pending) and not output:
                raise MigrationRejected("capture-malformed")
            pending = next_pending
        tail = decoder.flush(MAX_CAPTURE_STREAM_BYTES + 1 - total)
        chunks.append(tail)
    except MigrationRejected:
        raise
    except (EOFError, OSError, ValueError, zlib.error) as exc:
        raise MigrationRejected("capture-malformed") from exc
    if total + len(tail) > MAX_CAPTURE_STREAM_BYTES:
        raise MigrationRejected("capture-size-limit")
    if not decoder.eof or decoder.unused_data:
        raise MigrationRejected("capture-malformed")
    return b"".join(chunks)


def _validate_tar_layout(payload: bytes) -> None:
    zero_block = b"\0" * tarfile.BLOCKSIZE
    offset = 0
    try:
        while offset + tarfile.BLOCKSIZE <= len(payload):
            header = payload[offset : offset + tarfile.BLOCKSIZE]
            if header == zero_block:
                second_end = offset + 2 * tarfile.BLOCKSIZE
                if payload[offset + tarfile.BLOCKSIZE : second_end] != zero_block:
                    raise MigrationRejected("capture-malformed")
                trailing = payload[second_end:]
                if any(trailing):
                    first_nonzero = next(
                        index
                        for index in range(0, len(trailing), tarfile.BLOCKSIZE)
                        if trailing[index : index + tarfile.BLOCKSIZE] != zero_block
                    )
                    hidden_header = trailing[
                        first_nonzero : first_nonzero + tarfile.BLOCKSIZE
                    ]
                    if len(hidden_header) == tarfile.BLOCKSIZE:
                        hidden = tarfile.TarInfo.frombuf(
                            hidden_header, "utf-8", "surrogateescape"
                        )
                        if (
                            not _safe_capture_name(hidden.name)
                            or hidden.name not in CAPTURE_MEMBERS
                        ):
                            raise MigrationRejected("capture-member-name-invalid")
                    raise MigrationRejected("capture-malformed")
                return
            member = tarfile.TarInfo.frombuf(header, "utf-8", "surrogateescape")
            if member.size < 0:
                raise MigrationRejected("capture-member-too-large")
            if (
                member.name in MAX_CAPTURE_MEMBER_BYTES
                and member.size > MAX_CAPTURE_MEMBER_BYTES[member.name]
            ):
                raise MigrationRejected("capture-member-too-large")
            data_blocks = (member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE
            offset += tarfile.BLOCKSIZE * (1 + data_blocks)
            if offset > len(payload):
                raise MigrationRejected("capture-malformed")
    except MigrationRejected:
        raise
    except (ValueError, tarfile.TarError) as exc:
        raise MigrationRejected("capture-malformed") from exc
    raise MigrationRejected("capture-malformed")


def _safe_capture_name(name: str) -> bool:
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


def _verify_capture_checksums(members: dict[str, bytes]) -> dict[str, str]:
    payload = members["SHA256SUMS-post-close"]
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MigrationRejected("capture-checksums-invalid") from exc
    if not text or not text.endswith("\n"):
        raise MigrationRejected("capture-checksums-invalid")
    declared: dict[str, str] = {}
    for line in text.splitlines():
        match = _CHECKSUM_LINE_PATTERN.fullmatch(line)
        if match is None:
            raise MigrationRejected("capture-checksums-invalid")
        digest, name = match.groups()
        if name in declared or name not in HASHED_CAPTURE_MEMBERS:
            raise MigrationRejected("capture-checksums-invalid")
        declared[name] = digest
    if set(declared) != HASHED_CAPTURE_MEMBERS:
        raise MigrationRejected("capture-checksums-invalid")
    for name, digest in declared.items():
        if sha256_bytes(members[name]) != digest:
            raise MigrationRejected("capture-member-sha256-mismatch")
    return declared


def _strict_summary_json(payload: bytes) -> dict[str, object]:
    def reject_constant(value: str) -> object:
        raise ValueError(value)

    try:
        value = json.loads(payload.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise MigrationRejected("capture-summary-invalid") from exc
    if not isinstance(value, dict) or set(value) != _SUMMARY_KEYS:
        raise MigrationRejected("capture-summary-invalid")
    return value


def _validate_catalog_and_summary(
    catalog_bytes: bytes,
    summary: dict[str, object],
    capture_hashes: dict[str, str],
) -> AcceptanceReport:
    with tempfile.TemporaryDirectory(prefix="lto-capture-normalize-") as temporary:
        catalog_path = Path(temporary) / "catalog.db"
        catalog_path.write_bytes(catalog_bytes)
        try:
            with ReadOnlyCatalog(catalog_path) as catalog:
                connection = catalog.connection
                job_ids = tuple(
                    row[0]
                    for row in connection.execute(
                        "SELECT id FROM automatic_jobs ORDER BY id"
                    )
                )
                if len(job_ids) != 1 or not isinstance(job_ids[0], str):
                    raise MigrationRejected("capture-job-count-invalid")
                acceptance = MigrationValidator.inspect(catalog, job_ids[0])
                facts = _catalog_facts(connection, job_ids[0])
        except MigrationRejected:
            raise
        except sqlite3.DatabaseError as exc:
            raise MigrationRejected("capture-catalog-invalid") from exc
    acceptance.require_valid()
    _validate_summary(summary, facts, acceptance, capture_hashes)
    return acceptance


def _catalog_facts(connection: sqlite3.Connection, job_id: str) -> dict[str, object]:
    job = connection.execute(
        "SELECT status, current_sequence, total_cassettes, last_error "
        "FROM automatic_jobs WHERE id=?",
        (job_id,),
    ).fetchone()
    fourth = connection.execute(
        "SELECT status FROM automatic_cassettes WHERE job_id=? AND sequence=4",
        (job_id,),
    ).fetchone()
    schema = connection.execute(
        "SELECT value FROM metadata WHERE key='schema_version'"
    ).fetchone()
    completed = tuple(
        row[0]
        for row in connection.execute(
            "SELECT sequence FROM automatic_cassettes "
            "WHERE job_id=? AND status='completed' ORDER BY sequence",
            (job_id,),
        )
    )
    if schema is None or not isinstance(schema[0], str) or schema[0] != "13":
        if schema is not None and isinstance(schema[0], str) and schema[0].isdecimal():
            raise MigrationRejected("capture-schema-invalid")
        raise MigrationRejected("capture-catalog-invalid")
    return {
        "schema_version": 13,
        "job_status": job[0] if job is not None else None,
        "current_sequence": job[1] if job is not None else None,
        "total_cassettes": job[2] if job is not None else None,
        "last_error": job[3] if job is not None else None,
        "completed_sequences": completed,
        "next_cassette_status": fourth[0] if fourth is not None else None,
        "assignment_rows": connection.execute(
            "SELECT COUNT(*) FROM automatic_cassette_items WHERE job_id=?", (job_id,)
        ).fetchone()[0],
        "completed_file_versions": connection.execute(
            "SELECT COUNT(*) FROM file_versions"
        ).fetchone()[0],
        "uncommitted_blocks": connection.execute(
            "SELECT COUNT(*) FROM blocks WHERE status!='completed'"
        ).fetchone()[0],
        "foreign_key_violations": len(
            list(connection.execute("PRAGMA foreign_key_check"))
        ),
    }


def _validate_summary(
    summary: dict[str, object],
    facts: dict[str, object],
    acceptance: AcceptanceReport,
    capture_hashes: dict[str, str],
) -> None:
    job = summary.get("job")
    quiescence = summary.get("quiescence")
    validation = summary.get("validation")
    catalog_files = summary.get("catalog_files")
    if (
        not isinstance(summary.get("captured_at_utc"), str)
        or not summary["captured_at_utc"].endswith("Z")
        or not isinstance(summary.get("source_host"), str)
        or not summary["source_host"]
        or not isinstance(summary.get("application_version"), str)
        or not summary["application_version"]
        or not isinstance(summary.get("schema_version"), int)
        or isinstance(summary["schema_version"], bool)
        or not isinstance(summary.get("cutover_note"), str)
        or not summary["cutover_note"]
        or not isinstance(job, dict)
        or not isinstance(quiescence, dict)
        or not isinstance(validation, dict)
        or not isinstance(catalog_files, dict)
    ):
        raise MigrationRejected("capture-summary-invalid")
    if (
        set(job)
        != {
            "status",
            "current_sequence",
            "total_cassettes",
            "completed_sequences",
            "next_cassette_status",
            "last_error",
        }
        or set(quiescence)
        != {
            "automatic_job_lock_held",
            "gui_process_count",
            "ltfs_process_count",
            "ltfs_volume_count",
            "source_catalog_sha256",
            "source_catalog_modified_utc",
        }
        or set(validation)
        != {
            "sqlite_integrity_check",
            "foreign_key_violations",
            "uncommitted_blocks",
            "assignment_gaps",
            "duplicate_assignments",
            "completed_cassettes_match_planned_files_and_bytes",
            "next_cassette_has_no_committed_or_provisional_write",
            "assignment_rows",
            "completed_file_versions",
        }
        or set(catalog_files)
        != {
            "catalog-closed-consistent.db",
            "catalog-closed-source.db",
            "catalog-export.json",
        }
    ):
        raise MigrationRejected("capture-summary-invalid")
    if any(not isinstance(value, str) or not value for value in catalog_files.values()):
        raise MigrationRejected("capture-summary-invalid")
    if (
        not isinstance(job["status"], str)
        or not _is_integer(job["current_sequence"])
        or not _is_integer(job["total_cassettes"])
        or not isinstance(job["completed_sequences"], list)
        or any(not _is_integer(value) for value in job["completed_sequences"])
        or not isinstance(job["next_cassette_status"], str)
        or job["last_error"] is not None
        or quiescence["automatic_job_lock_held"] is not False
        or any(
            not _is_integer(quiescence[key])
            for key in (
                "gui_process_count",
                "ltfs_process_count",
                "ltfs_volume_count",
            )
        )
        or not isinstance(quiescence["source_catalog_sha256"], str)
        or _SHA256_PATTERN.fullmatch(quiescence["source_catalog_sha256"]) is None
        or not isinstance(quiescence["source_catalog_modified_utc"], str)
        or not quiescence["source_catalog_modified_utc"]
        or validation["sqlite_integrity_check"] != "ok"
        or any(
            not _is_integer(validation[key])
            for key in (
                "foreign_key_violations",
                "uncommitted_blocks",
                "assignment_gaps",
                "duplicate_assignments",
                "assignment_rows",
                "completed_file_versions",
            )
        )
        or validation["completed_cassettes_match_planned_files_and_bytes"] is not True
        or validation["next_cassette_has_no_committed_or_provisional_write"] is not True
    ):
        raise MigrationRejected("capture-summary-invalid")
    expected_job = {
        "status": facts["job_status"],
        "current_sequence": facts["current_sequence"],
        "total_cassettes": facts["total_cassettes"],
        "completed_sequences": list(facts["completed_sequences"]),
        "next_cassette_status": facts["next_cassette_status"],
        "last_error": facts["last_error"],
    }
    expected_validation = {
        "sqlite_integrity_check": "ok",
        "foreign_key_violations": facts["foreign_key_violations"],
        "uncommitted_blocks": facts["uncommitted_blocks"],
        "assignment_gaps": 0,
        "duplicate_assignments": 0,
        "completed_cassettes_match_planned_files_and_bytes": True,
        "next_cassette_has_no_committed_or_provisional_write": True,
        "assignment_rows": facts["assignment_rows"],
        "completed_file_versions": facts["completed_file_versions"],
    }
    if (
        summary["schema_version"] != facts["schema_version"]
        or job != expected_job
        or validation != expected_validation
        or acceptance.next_sequence != facts["current_sequence"]
        or acceptance.total_cassettes != facts["total_cassettes"]
        or acceptance.completed_sequences != facts["completed_sequences"]
        or quiescence["automatic_job_lock_held"] is not False
        or quiescence["gui_process_count"] != 0
        or quiescence["ltfs_process_count"] != 0
        or quiescence["ltfs_volume_count"] != 0
        or quiescence["source_catalog_sha256"]
        != capture_hashes["catalog-closed-source.db"]
        or not isinstance(quiescence["source_catalog_modified_utc"], str)
        or not quiescence["source_catalog_modified_utc"]
    ):
        raise MigrationRejected("capture-summary-mismatch")


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
